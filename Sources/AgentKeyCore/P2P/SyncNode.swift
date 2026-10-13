import Foundation

/// Per-device sync runtime used by `agentkeyd`: identity, replica, pairing offers, known peers,
/// and the bridge between the local vault file and the sync replica. No external services:
/// devices talk directly (LAN / Bonjour / Tailscale / WireGuard), usually via an always-on home node.
public final class SyncNode: @unchecked Sendable {
    public static let defaultPort: UInt16 = 7373
    public let dir: URL
    public let identity: DeviceIdentity
    public private(set) var replica: PeerReplica?
    public private(set) var peers = Peers()
    private var offer: PairingPayload?
    private let lock = NSRecursiveLock()

    public struct Peers: Codable {
        public var homeNode: String?                       // deviceID of the home node
        public var endpoints: [String: [String]] = [:]     // deviceID → ["host:port", …]
    }

    var identityURL: URL { dir.appendingPathComponent("identity.json") }
    var replicaURL: URL { dir.appendingPathComponent("replica.sealed") }
    var peersURL: URL { dir.appendingPathComponent("peers.json") }
    var bridgeURL: URL { dir.appendingPathComponent("bridge.json") }

    /// Loads or creates this device's Curve25519 identity.
    /// TODO(mac): store the identity in the Keychain (ThisDeviceOnly), wrapped by a Secure Enclave
    /// P-256 key (the SE cannot do X25519 itself). On Linux/dev boxes it is a 0600 file.
    public init(dir: URL, deviceName: String) throws {
        self.dir = dir
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        if let d = try? Data(contentsOf: dir.appendingPathComponent("identity.json")) {
            identity = try DeviceIdentity(stored: try JSONDecoder().decode(DeviceIdentity.Stored.self, from: d))
        } else {
            identity = DeviceIdentity(name: deviceName)
            try Self.writePrivate(try JSONEncoder().encode(identity.stored), to: dir.appendingPathComponent("identity.json"))
        }
        if FileManager.default.fileExists(atPath: replicaURL.path) { replica = try PeerReplica.load(from: replicaURL, identity: identity) }
        if let d = try? Data(contentsOf: peersURL), let p = try? JSONDecoder().decode(Peers.self, from: d) { peers = p }
    }

    static func writePrivate(_ d: Data, to url: URL) throws {
        let tmp = url.appendingPathExtension("tmp")
        FileManager.default.createFile(atPath: tmp.path, contents: d, attributes: [.posixPermissions: 0o600])
        guard rename(tmp.path, url.path) == 0 else { throw CocoaError(.fileWriteUnknown) }
    }

    public func save() throws {
        try lock.withLock {
            try replica?.save(to: replicaURL)
            try Self.writePrivate(try JSONEncoder().encode(peers), to: peersURL)
        }
    }

    /// Make this device the home node of a new sync group for `vaultID`.
    public func initHome(vaultID: UUID) throws -> PeerReplica {
        try lock.withLock {
            if let r = replica { return r }
            let r = PeerReplica(identity: identity, vaultID: vaultID, isHomeNode: true)
            replica = r; peers.homeNode = identity.deviceID.raw; try save(); return r
        }
    }

    // MARK: pairing

    /// Issue a one-time pairing payload (shown as QR / `agentkey-pair:` URI). Replaces any previous one.
    public func makeOffer(hosts: [String], port: UInt16, ttl: TimeInterval = 600) throws -> PairingPayload {
        try lock.withLock {
            guard let r = replica else { throw SyncNodeError.notInitialized }
            let p = PairingPayload(vaultID: r.vaultID, nodeName: identity.name, hosts: hosts, port: port,
                                   fingerprint: identity.fingerprint, ttl: ttl)
            offer = p; return p
        }
    }

    /// Join a sync group with a scanned payload. Tries each advertised host.
    public func join(_ payload: PairingPayload, connect: (String, UInt16) throws -> FrameTransport = { try TCPTransport.connect(host: $0, port: $1) }) throws -> PeerReplica {
        try lock.withLock {
            guard replica == nil else { throw SyncNodeError.alreadyPaired }
            var last: Error = SyncNodeError.unreachable
            for h in payload.hosts {
                do {
                    let t = try connect(h, payload.port)
                    try t.send(Data(SecureChannel.proloquePair.utf8))
                    let r = try SyncSession.pair(identity: identity, payload: payload, over: t)
                    guard let hub = r.trust.devices.values.first(where: { $0.fingerprint == payload.fingerprint }) else { throw PairingError.rejected("node missing") }
                    replica = r; peers.homeNode = hub.deviceID
                    peers.endpoints[hub.deviceID] = payload.hosts.map { "\($0):\(payload.port)" }
                    try save(); return r
                } catch let e as PairingError { throw e }
                catch { last = error }
            }
            throw last
        }
    }

    // MARK: serving

    /// Handle one inbound connection (pairing or sync). The first plaintext frame selects the mode;
    /// it is also bound into the Noise prologue, so tampering with it fails the handshake.
    public func serveConnection(_ t: FrameTransport, prepare: (() -> Void)? = nil) throws -> String {
        let mode = String(decoding: try t.receive(timeout: 10), as: UTF8.self)
        guard let r = lock.withLock({ replica }) else { t.close(); throw SyncNodeError.notInitialized }
        switch mode {
        case SecureChannel.proloquePair:
            let p: PairingPayload? = lock.withLock { let o = offer; offer = nil; return o }   // single use, even on failure
            guard let p else { t.close(); throw PairingError.secretAlreadyUsed }
            let d = try SyncSession.servePairing(r, payload: p, over: t)
            try save(); return "paired \(d.name) (\(d.fingerprint))"
        case SecureChannel.prologueSync:
            prepare?()          // e.g. pull fresh local vault edits into the replica before serving
            let st = try SyncSession.serve(r, over: t)
            try save(); return "synced with \(r.trust.devices[st.peer]?.name ?? st.peer): in \(st.received) out \(st.sent)"
        default:
            t.close(); throw SyncProtocolError.protocolViolation("unknown mode")
        }
    }

    /// Run a blocking accept loop (used by `agentkeyd --sync-node`). `after` runs after each session.
    public func runListener(_ l: TCPListener, log: @escaping (String) -> Void, before: @escaping () -> Void, after: @escaping () -> Void) {
        while true {
            guard let t = try? l.accept() else { continue }
            Thread { [self] in
                do { log(try serveConnection(t, prepare: before)); after() } catch { log("session from \(t.peerDescription) failed: \(error)") }
            }.start()
        }
    }

    // MARK: client sync

    /// Sync with the home node (or every known peer endpoint). Returns per-peer results.
    public func syncNow(connect: (String, UInt16) throws -> FrameTransport = { try TCPTransport.connect(host: $0, port: $1, timeout: 5) }) throws -> [String: Result<SyncStats, Error>] {
        guard let r = lock.withLock({ replica }) else { throw SyncNodeError.notInitialized }
        var out: [String: Result<SyncStats, Error>] = [:]
        for (peer, eps) in peers.endpoints.sorted(by: { $0.key < $1.key }) where peer != identity.deviceID.raw {
            var res: Result<SyncStats, Error> = .failure(SyncNodeError.unreachable)
            for ep in eps {
                guard let i = ep.lastIndex(of: ":"), let port = UInt16(ep[ep.index(after: i)...]) else { continue }
                do {
                    let t = try connect(String(ep[..<i]), port)
                    try t.send(Data(SecureChannel.prologueSync.utf8))
                    let fp = r.trust.devices[peer]?.fingerprint
                    res = .success(try SyncSession.runClient(r, over: t, pinnedFingerprint: fp)); break
                } catch { res = .failure(error) }
            }
            out[peer] = res
        }
        try save()
        return out
    }

    public func addEndpoint(peer: String, _ ep: String) throws {
        lock.withLock { var l = peers.endpoints[peer] ?? []; if !l.contains(ep) { l.append(ep) }; peers.endpoints[peer] = l }
        try save()
    }

    public func revoke(_ deviceID: String) throws {
        guard let r = lock.withLock({ replica }) else { throw SyncNodeError.notInitialized }
        guard deviceID != identity.deviceID.raw else { throw SyncNodeError.cannotRevokeSelf }
        try r.revoke(deviceID); lock.withLock { _ = peers.endpoints.removeValue(forKey: deviceID) }; try save()
    }

    // MARK: status

    public struct Status: Codable {
        public var deviceID: String, name: String, fingerprint: String
        public var initialized: Bool, isHomeNode: Bool, keyVersion: Int, items: Int
        public var devices: [DeviceInfo]
    }
    public struct DeviceInfo: Codable {
        public var deviceID: String, name: String, fingerprint: String, isHomeNode: Bool, revoked: Bool, isSelf: Bool
        public var endpoints: [String], lastSync: Date?, pendingOut: Int
    }

    public func status() -> Status {
        lock.withLock {
            let r = replica
            let devs = (r?.trust.devices.values.sorted { $0.addedAt < $1.addedAt } ?? []).map { d in
                DeviceInfo(deviceID: d.deviceID, name: d.name, fingerprint: d.fingerprint, isHomeNode: d.isHomeNode ?? false,
                           revoked: d.revokedAt != nil, isSelf: d.deviceID == identity.deviceID.raw,
                           endpoints: peers.endpoints[d.deviceID] ?? [], lastSync: r?.lastSync[d.deviceID],
                           pendingOut: d.deviceID == identity.deviceID.raw ? 0 : (r?.pendingCount(for: d.deviceID) ?? 0))
            }
            return Status(deviceID: identity.deviceID.raw, name: identity.name, fingerprint: identity.fingerprint,
                          initialized: r != nil, isHomeNode: peers.homeNode == identity.deviceID.raw,
                          keyVersion: r?.currentKeyVersion ?? 0, items: r?.liveItems.count ?? 0, devices: devs)
        }
    }

    // MARK: vault bridge

    /// Two-way reconcile between the local vault file and the replica, using a keyed snapshot of the
    /// last reconciled state: vault-side changes go to the replica (and out to peers); replica-side
    /// changes (from peers) are written into the vault. Snapshot stores only HMACs, never plaintext.
    @discardableResult
    public func reconcile(vault: Vault) throws -> (toReplica: Int, toVault: Int) {
        try lock.withLock {
            guard let r = replica else { throw SyncNodeError.notInitialized }
            let key = KeyHierarchy.subkey(SymmetricKey(data: identity.staticKey.rawRepresentation), purpose: "bridge")
            func h(_ i: VaultItem?) throws -> String? {
                guard let i else { return nil }
                return Data(HMAC<SHA256>.authenticationCode(for: try Vault.encoder.encode(i), using: key)).base64EncodedString()
            }
            var snap: [UUID: String] = (try? JSONDecoder().decode([UUID: String].self, from: Data(contentsOf: bridgeURL))) ?? [:]
            let v = Dictionary(uniqueKeysWithValues: try vault.items().map { ($0.id, $0) })
            let rp = Dictionary(uniqueKeysWithValues: r.liveItems.map { ($0.id, $0) })
            var toR = 0, toV = 0
            for id in Set(v.keys).union(rp.keys).union(snap.keys) {
                let hv = try h(v[id]), hr = try h(rp[id]), hs = snap[id]
                if hv == hr { snap[id] = hv; continue }
                if hv != hs {                       // vault changed locally → replica
                    if let i = v[id] { r.write(i) } else { r.delete(id) }
                    snap[id] = hv; toR += 1
                } else {                            // replica changed (from a peer) → vault
                    if let i = rp[id] { try vault.put(i) } else { try vault.delete(id: id) }
                    snap[id] = hr; toV += 1
                }
            }
            snap = snap.filter { $0.value != nil }.mapValues { $0 }
            try Self.writePrivate(try JSONEncoder().encode(snap), to: bridgeURL)
            try save()
            return (toR, toV)
        }
    }
}

public enum SyncNodeError: Error, CustomStringConvertible {
    case notInitialized, alreadyPaired, unreachable, cannotRevokeSelf
    public var description: String {
        switch self {
        case .notInitialized: return "sync not set up on this device (run `agentkeyd --sync-node` on the home node, or `agentkey device pair <code>`)"
        case .alreadyPaired: return "this device is already paired"
        case .unreachable: return "no peer endpoint reachable"
        case .cannotRevokeSelf: return "cannot revoke this device from itself"
        }
    }
}
