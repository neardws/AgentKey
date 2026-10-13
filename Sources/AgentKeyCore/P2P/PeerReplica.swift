import Foundation

/// A paired device as recorded in the replicated device registry.
public struct DeviceRecord: Codable, Equatable, Sendable {
    public var deviceID: String
    public var name: String
    public var publicKey: Data
    public var addedAt: Date
    public var addedBy: String
    public var revokedAt: Date?
    public var isHomeNode: Bool?
    public var fingerprint: String { DeviceIdentity.fingerprint(publicKey) }
}

/// Vault record keys, wrapped individually to each non-revoked device's static key.
/// Key versions are `(generation << 32) | random32` so concurrent rotations never collide;
/// the newest generation is used for sealing.
public struct KeyringEntry: Codable, Equatable, Sendable {
    public var version: Int
    public var createdBy: String
    public var wrapped: [String: Data]     // deviceID → KeyWrap.seal(key)
}

/// Replicated device + key state (merged as a join-semilattice: union; revocation is sticky).
public struct TrustState: Codable, Equatable, Sendable {
    public var vaultID: UUID
    public var devices: [String: DeviceRecord] = [:]
    public var keyring: [KeyringEntry] = []

    public mutating func merge(_ o: TrustState) {
        guard o.vaultID == vaultID else { return }
        for (id, d) in o.devices {
            if var mine = devices[id] {
                if mine.revokedAt == nil || (d.revokedAt != nil && d.revokedAt! < mine.revokedAt!) { mine.revokedAt = d.revokedAt ?? mine.revokedAt }
                if mine.isHomeNode == nil { mine.isHomeNode = d.isHomeNode }
                devices[id] = mine
            } else { devices[id] = d }
        }
        for e in o.keyring {
            if let i = keyring.firstIndex(where: { $0.version == e.version }) {
                keyring[i].wrapped.merge(e.wrapped) { a, _ in a }
            } else { keyring.append(e) }
        }
        keyring.sort { $0.version < $1.version }
    }

    public func isTrusted(_ pub: Data) -> Bool {
        devices.values.contains { $0.publicKey == pub && $0.revokedAt == nil }
    }
    public func device(pub: Data) -> DeviceRecord? { devices.values.first { $0.publicKey == pub } }
}

/// One device's replica of the vault for peer-to-peer sync. Any replica can act as the
/// responder ("hub") for another; the always-on Mac mini home node is just the usual hub.
///
/// Delta sync: the hub numbers every local change with a sequence number; a client remembers
/// the hub's sequence it has fully applied (`cursor[hub]`) and asks for changes after it.
/// Uploads are compare-and-set against the client's merge base for that hub; on conflict the
/// client 3-way merges (MergeEngine) and retries. Everything on the wire is AES-GCM ciphertext.
public final class PeerReplica: @unchecked Sendable {
    public struct Entry: Codable { public var item: VaultItem?; public var meta: RecordMeta; public var seq: UInt64 }
    public struct Base: Codable { public var item: VaultItem?; public var stamp: Stamp }

    public let identity: DeviceIdentity
    public var device: DeviceID { identity.deviceID }
    public private(set) var trust: TrustState
    public private(set) var keys: [Int: SymmetricKey] = [:]
    public private(set) var clock = LamportClock()
    public private(set) var records: [UUID: Entry] = [:]
    public private(set) var seq: UInt64 = 0
    public private(set) var bases: [String: [UUID: Base]] = [:]      // peer deviceID → merge bases
    public private(set) var cursors: [String: UInt64] = [:]          // peer deviceID → hub seq applied
    public private(set) var conflicts: [UUID: [MergeConflict]] = [:]
    public var lastSync: [String: Date] = [:]
    let lock = NSRecursiveLock()
    /// Serializes hub sessions so a client's final cursor is exact.
    let hubLock = NSLock()

    /// Create the first replica of a vault (home node or first device).
    public init(identity: DeviceIdentity, vaultID: UUID, isHomeNode: Bool = false) {
        self.identity = identity
        trust = TrustState(vaultID: vaultID)
        trust.devices[identity.deviceID.raw] = DeviceRecord(deviceID: identity.deviceID.raw, name: identity.name, publicKey: identity.publicKey,
                                                            addedAt: Date(), addedBy: identity.deviceID.raw, revokedAt: nil, isHomeNode: isHomeNode)
        try? rotateKey()
    }

    /// Replica created on a newly paired device from the handover.
    init(identity: DeviceIdentity, handover: PairingHandover) throws {
        self.identity = identity
        trust = handover.trust
        for (v, k) in handover.keys { keys[v] = SymmetricKey(data: k) }
    }

    public var vaultID: UUID { trust.vaultID }
    public var currentKeyVersion: Int { keys.keys.max() ?? 0 }
    public var isRevoked: Bool { trust.devices[device.raw]?.revokedAt != nil }

    // MARK: local edits

    public func item(_ id: UUID) -> VaultItem? { lock.withLock { records[id]?.item } }
    public var liveItems: [VaultItem] {
        lock.withLock { records.values.compactMap(\.item).sorted { ($0.title, $0.id.uuidString) < ($1.title, $1.id.uuidString) } }
    }

    public func write(_ item: VaultItem) {
        lock.withLock {
            let rev = (records[item.id]?.meta.revision ?? 0) + 1
            seq += 1
            records[item.id] = Entry(item: item, meta: RecordMeta(id: item.id, revision: rev, stamp: Stamp(lamport: clock.tick(), device: device),
                                                                    keyVersion: currentKeyVersion), seq: seq)
        }
    }

    public func delete(_ id: UUID) {
        lock.withLock {
            guard let r = records[id], r.item != nil else { return }
            seq += 1
            records[id] = Entry(item: nil, meta: RecordMeta(id: id, revision: r.meta.revision + 1, stamp: Stamp(lamport: clock.tick(), device: device),
                                                             deleted: true, keyVersion: currentKeyVersion), seq: seq)
        }
    }

    // MARK: keys & trust

    /// New vault record key, wrapped to every non-revoked device (including us).
    public func rotateKey() throws {
        try lock.withLock {
            let gen = (currentKeyVersion >> 32) + 1
            let version = (gen << 32) | Int(UInt32.random(in: 1...UInt32.max))
            let k = SymmetricKey(size: .bits256)
            var wrapped: [String: Data] = [:]
            for d in trust.devices.values where d.revokedAt == nil {
                wrapped[d.deviceID] = try KeyWrap.seal(k.data, to: d.publicKey, context: "\(vaultID.uuidString)|\(version)")
            }
            keys[version] = k
            trust.keyring.append(KeyringEntry(version: version, createdBy: device.raw, wrapped: wrapped))
        }
    }

    /// Revoke a device: sticky in the registry, and rotate the vault key so that records written
    /// from now on are unreadable to it. (It keeps whatever it had already decrypted.)
    public func revoke(_ deviceID: String) throws {
        try lock.withLock {
            guard var d = trust.devices[deviceID] else { throw PairingError.rejected("unknown device") }
            if d.revokedAt == nil { d.revokedAt = Date(); trust.devices[deviceID] = d }
            try rotateKey()
            // re-stamp live records so they propagate sealed under the new key
            for (id, e) in records where e.item != nil {
                seq += 1
                var m = e.meta; m.revision += 1; m.stamp = Stamp(lamport: clock.tick(), device: device); m.keyVersion = currentKeyVersion
                records[id] = Entry(item: e.item, meta: m, seq: seq)
            }
        }
    }

    func mergeTrust(_ o: TrustState) {
        lock.withLock {
            trust.merge(o)
            for e in trust.keyring where keys[e.version] == nil {
                if let w = e.wrapped[device.raw],
                   let raw = try? KeyWrap.open(w, with: identity.staticKey, context: "\(vaultID.uuidString)|\(e.version)") {
                    keys[e.version] = SymmetricKey(data: raw)
                }
            }
        }
    }

    func addDevice(_ d: DeviceRecord) throws {
        try lock.withLock {
            guard trust.devices[d.deviceID]?.revokedAt == nil else { throw PairingError.revoked }
            trust.devices[d.deviceID] = d
            // give the new device every existing key via the keyring as well
            for i in trust.keyring.indices {
                if let k = keys[trust.keyring[i].version] {
                    trust.keyring[i].wrapped[d.deviceID] = try KeyWrap.seal(k.data, to: d.publicKey, context: "\(vaultID.uuidString)|\(trust.keyring[i].version)")
                }
            }
        }
    }

    // MARK: sealing

    func seal(_ e: Entry) throws -> SyncRecord {
        var meta = e.meta
        if !meta.deleted, keys[meta.keyVersion] == nil { meta.keyVersion = currentKeyVersion }
        guard let k = keys[meta.keyVersion] ?? keys[currentKeyVersion] else { throw NoiseError.wrongState }
        return try SyncRecord.seal(e.item ?? VaultItem(id: meta.id, kind: .secureNote, title: ""), meta: meta, key: k)
    }

    func open(_ r: SyncRecord) throws -> VaultItem? {
        if r.meta.deleted { return nil }
        guard let k = keys[r.meta.keyVersion] else { throw SyncProtocolError.missingKey(r.meta.keyVersion) }
        return try r.open(key: k)
    }

    // MARK: hub side

    /// Records changed after `since` (hub sequence), sealed.
    func delta(since: UInt64, limit: Int = 500) throws -> (records: [SyncRecord], upTo: UInt64, more: Bool) {
        try lock.withLock {
            let changed = records.values.filter { $0.seq > since }.sorted { $0.seq < $1.seq }
            let page = Array(changed.prefix(limit))
            return (try page.map(seal), page.last?.seq ?? seq, changed.count > limit)
        }
    }

    /// Compare-and-set upload from a client. Idempotent: re-sending an accepted record is a no-op.
    func accept(_ r: SyncRecord, base: Stamp?) throws -> SyncRecord? {
        try lock.withLock {
            clock.observe(r.meta.stamp.lamport)
            let cur = records[r.meta.id]
            if cur?.meta.stamp == r.meta.stamp { return nil }
            guard cur?.meta.stamp == base else { return try cur.map(seal) }     // conflict → send ours
            let item = try open(r)
            seq += 1
            records[r.meta.id] = Entry(item: item, meta: r.meta, seq: seq)
            return nil
        }
    }

    // MARK: client side

    /// Apply a record received from `peer` (delta or conflict). Idempotent.
    func receive(_ r: SyncRecord, from peer: String) throws {
        try lock.withLock {
            clock.observe(r.meta.stamp.lamport)
            let id = r.meta.id
            let remoteItem = try open(r)
            let cur = records[id]
            defer { bases[peer, default: [:]][id] = Base(item: remoteItem, stamp: r.meta.stamp) }
            if cur?.meta.stamp == r.meta.stamp { return }
            let base = bases[peer]?[id]
            if cur == nil || cur!.meta.stamp == base?.stamp {
                seq += 1; records[id] = Entry(item: remoteItem, meta: r.meta, seq: seq); return   // fast-forward
            }
            let res = MergeEngine.merge(base: base?.item,
                                        local: Version(item: cur!.item, stamp: cur!.meta.stamp),
                                        remote: Version(item: remoteItem, stamp: r.meta.stamp))
            if !res.conflicts.isEmpty { conflicts[id, default: []] += res.conflicts }
            seq += 1
            if res.item == remoteItem {
                records[id] = Entry(item: remoteItem, meta: r.meta, seq: seq)
            } else {
                records[id] = Entry(item: res.item, meta: RecordMeta(id: id, revision: max(cur!.meta.revision, r.meta.revision) + 1,
                                                                     stamp: Stamp(lamport: clock.tick(), device: device),
                                                                     deleted: res.item == nil, keyVersion: currentKeyVersion), seq: seq)
            }
        }
    }

    /// Records the peer does not have yet (current stamp ≠ our merge base for that peer).
    func pending(for peer: String) throws -> [(SyncRecord, Stamp?)] {
        try lock.withLock {
            try records.values.filter { $0.meta.stamp != bases[peer]?[$0.meta.id]?.stamp }
                .sorted { $0.seq < $1.seq }
                .map { (try seal($0), bases[peer]?[$0.meta.id]?.stamp) }
        }
    }

    func didAccept(_ id: UUID, stamp: Stamp, peer: String) {
        lock.withLock {
            guard let cur = records[id], cur.meta.stamp == stamp else { return }
            bases[peer, default: [:]][id] = Base(item: cur.item, stamp: stamp)
        }
    }

    func setCursor(_ peer: String, _ v: UInt64) { lock.withLock { cursors[peer] = max(cursors[peer] ?? 0, v); lastSync[peer] = Date() } }
    public func pendingCount(for peer: String) -> Int { (try? pending(for: peer).count) ?? 0 }

    // MARK: persistence (encrypted at rest with a device-local key)

    struct Snapshot: Codable {
        var trust: TrustState; var keys: [Int: Data]; var clock: LamportClock; var records: [UUID: Entry]
        var seq: UInt64; var bases: [String: [UUID: Base]]; var cursors: [String: UInt64]; var lastSync: [String: Date]
    }

    /// Storage key derived from the device identity. TODO(mac): Keychain/Secure-Enclave-protected key instead.
    static func storageKey(_ id: DeviceIdentity) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: id.staticKey.rawRepresentation),
                               info: Data("agentkey/replica-storage/v1".utf8), outputByteCount: 32)
    }

    public func save(to url: URL) throws {
        let snap: Snapshot = lock.withLock {
            Snapshot(trust: trust, keys: keys.mapValues(\.data), clock: clock, records: records, seq: seq, bases: bases, cursors: cursors, lastSync: lastSync)
        }
        let ct = try KeyHierarchy.seal(try P2PCodec.enc.encode(snap), key: Self.storageKey(identity), aad: Data("agentkey/replica|\(device.raw)".utf8))
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let tmp = url.appendingPathExtension("tmp")
        FileManager.default.createFile(atPath: tmp.path, contents: ct, attributes: [.posixPermissions: 0o600])
        _ = try? FileManager.default.removeItem(at: url)
        try FileManager.default.moveItem(at: tmp, to: url)
    }

    public static func load(from url: URL, identity: DeviceIdentity) throws -> PeerReplica {
        let pt = try KeyHierarchy.open(try Data(contentsOf: url), key: storageKey(identity), aad: Data("agentkey/replica|\(identity.deviceID.raw)".utf8))
        let s = try P2PCodec.dec.decode(Snapshot.self, from: pt)
        let r = PeerReplica(identity: identity, vaultID: s.trust.vaultID)
        r.trust = s.trust; r.keys = s.keys.mapValues { SymmetricKey(data: $0) }; r.clock = s.clock; r.records = s.records
        r.seq = s.seq; r.bases = s.bases; r.cursors = s.cursors; r.lastSync = s.lastSync
        return r
    }

    // MARK: bridge to the local Vault file

    /// Push local vault edits into the replica (writes only items that changed; tombstones deletions).
    public func importFrom(_ items: [VaultItem]) {
        let byID = Dictionary(uniqueKeysWithValues: items.map { ($0.id, $0) })
        for i in items where item(i.id) != i { write(i) }
        for e in liveItems where byID[e.id] == nil { delete(e.id) }
    }
}

public enum SyncProtocolError: Error, Equatable, CustomStringConvertible {
    case missingKey(Int), vaultMismatch, protocolViolation(String), revoked
    public var description: String {
        switch self {
        case .missingKey(let v): return "no key for record key version \(v)"
        case .vaultMismatch: return "peer belongs to a different vault"
        case .protocolViolation(let s): return "sync protocol violation: \(s)"
        case .revoked: return "this device has been revoked"
        }
    }
}
