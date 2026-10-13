import Foundation

/// Stable per-install device identifier (random, not hardware-derived).
public struct DeviceID: Codable, Hashable, Comparable, Sendable, CustomStringConvertible {
    public let raw: String
    public init(_ raw: String) { self.raw = raw }
    public static func generate() -> DeviceID { DeviceID(UUID().uuidString.lowercased()) }
    public static func < (a: DeviceID, b: DeviceID) -> Bool { a.raw < b.raw }
    public var description: String { raw }
}

/// Lamport clock: `tick()` before every local write, `observe()` every remote record.
public struct LamportClock: Codable, Equatable, Sendable {
    public private(set) var value: UInt64
    public init(_ v: UInt64 = 0) { value = v }
    @discardableResult public mutating func tick() -> UInt64 { value += 1; return value }
    public mutating func observe(_ remote: UInt64) { value = max(value, remote) }
}

/// Total order used to pick a winner for concurrent edits: (lamport, deviceID).
public struct Stamp: Codable, Comparable, Hashable, Sendable {
    public var lamport: UInt64
    public var device: DeviceID
    public init(lamport: UInt64, device: DeviceID) { self.lamport = lamport; self.device = device }
    public static func < (a: Stamp, b: Stamp) -> Bool { (a.lamport, a.device) < (b.lamport, b.device) }
}

/// Sync metadata for one record. Maps 1:1 onto a CKRecord in the private zone:
/// recordName = id, fields: ct (ciphertext), rev, lamport, device, deleted, keyVersion.
public struct RecordMeta: Codable, Equatable, Sendable {
    public var id: UUID
    public var revision: Int          // local monotonically increasing edit counter
    public var stamp: Stamp
    public var deleted: Bool          // tombstone: kept so deletions propagate, payload dropped
    public var keyVersion: Int
    public init(id: UUID, revision: Int = 0, stamp: Stamp, deleted: Bool = false, keyVersion: Int = 1) {
        self.id = id; self.revision = revision; self.stamp = stamp; self.deleted = deleted; self.keyVersion = keyVersion
    }
}

/// What goes over the wire / into CloudKit: metadata + AES-GCM ciphertext (nil for tombstones).
public struct SyncRecord: Codable, Equatable, Sendable {
    public var meta: RecordMeta
    public var ciphertext: Data?
    public init(meta: RecordMeta, ciphertext: Data?) { self.meta = meta; self.ciphertext = ciphertext }

    /// Lossless date encoding (Double seconds) so 3-way merge equality survives a round-trip.
    static let codec: (enc: JSONEncoder, dec: JSONDecoder) = {
        let e = JSONEncoder(); e.outputFormatting = .sortedKeys; e.dateEncodingStrategy = .deferredToDate
        let d = JSONDecoder(); d.dateDecodingStrategy = .deferredToDate
        return (e, d)
    }()

    public static func aad(_ id: UUID, keyVersion: Int) -> Data { Data("agentkey/record|\(id.uuidString)|k\(keyVersion)".utf8) }

    public static func seal(_ item: VaultItem, meta: RecordMeta, key: SymmetricKey) throws -> SyncRecord {
        if meta.deleted { return SyncRecord(meta: meta, ciphertext: nil) }
        let pt = try codec.enc.encode(item)
        return SyncRecord(meta: meta, ciphertext: try KeyHierarchy.seal(pt, key: key, aad: aad(meta.id, keyVersion: meta.keyVersion)))
    }

    public func open(key: SymmetricKey) throws -> VaultItem? {
        guard !meta.deleted, let ct = ciphertext else { return nil }
        return try Self.codec.dec.decode(VaultItem.self, from: KeyHierarchy.open(ct, key: key, aad: Self.aad(meta.id, keyVersion: meta.keyVersion)))
    }
}

/// A side of a merge: nil item = tombstone.
public struct Version: Sendable {
    public var item: VaultItem?
    public var stamp: Stamp
    public init(item: VaultItem?, stamp: Stamp) { self.item = item; self.stamp = stamp }
}

public struct MergeConflict: Codable, Equatable, Sendable {
    public var path: String           // e.g. "title", "field:password", "item"
    public var winner: String         // "local" | "remote"
    public var note: String
}

public struct MergeResult: Sendable {
    public var item: VaultItem?       // nil = stays deleted
    public var stamp: Stamp
    public var conflicts: [MergeConflict]
}

/// Field-level three-way merge (base = last version both sides agreed on).
/// - A property changed on one side only → take that side.
/// - Changed on both sides to the same value → take it.
/// - Changed on both sides differently → higher (lamport, device) wins; the loser's
///   secret values are preserved in item history so nothing is lost.
/// - Sets (urls, tags, agentModes) merge as set operations: adds and removes from both sides.
/// - Delete vs edit → the edit wins (resurrect) and is reported; delete vs delete → tombstone.
public enum MergeEngine {
    public static func merge(base: VaultItem?, local: Version, remote: Version) -> MergeResult {
        let winnerIsLocal = local.stamp >= remote.stamp
        let stamp = max(local.stamp, remote.stamp)
        switch (local.item, remote.item) {
        case (nil, nil):
            return MergeResult(item: nil, stamp: stamp, conflicts: [])
        case (let l?, nil):
            if let base, l == base { return MergeResult(item: nil, stamp: stamp, conflicts: []) }  // unchanged locally → accept delete
            return MergeResult(item: l, stamp: stamp, conflicts: [MergeConflict(path: "item", winner: "local", note: "edited locally, deleted remotely; kept edit")])
        case (nil, let r?):
            if let base, r == base { return MergeResult(item: nil, stamp: stamp, conflicts: []) }
            return MergeResult(item: r, stamp: stamp, conflicts: [MergeConflict(path: "item", winner: "remote", note: "deleted locally, edited remotely; kept edit")])
        case (let l?, let r?):
            if l == r { return MergeResult(item: l, stamp: stamp, conflicts: []) }
            guard let b = base else {
                // no common ancestor (e.g. first sync of an item created on both): whole-item LWW, keep loser in history
                var w = winnerIsLocal ? l : r
                let loser = winnerIsLocal ? r : l
                w.recordHistory("sync conflict (no base)", fields: loser.fields)
                return MergeResult(item: w, stamp: stamp, conflicts: [MergeConflict(path: "item", winner: winnerIsLocal ? "local" : "remote", note: "no common base")])
            }
            var conflicts: [MergeConflict] = []
            var out = winnerIsLocal ? l : r
            func pick<T: Equatable>(_ path: String, _ kp: WritableKeyPath<VaultItem, T>) {
                let (bv, lv, rv) = (b[keyPath: kp], l[keyPath: kp], r[keyPath: kp])
                if lv == rv { out[keyPath: kp] = lv }
                else if lv == bv { out[keyPath: kp] = rv }
                else if rv == bv { out[keyPath: kp] = lv }
                else {
                    out[keyPath: kp] = winnerIsLocal ? lv : rv
                    conflicts.append(MergeConflict(path: path, winner: winnerIsLocal ? "local" : "remote", note: "both changed"))
                }
            }
            pick("kind", \.kind); pick("title", \.title); pick("username", \.username); pick("notes", \.notes)
            pick("lastUsedAt", \.lastUsedAt); pick("passwordChangedAt", \.passwordChangedAt)
            pick("archivedAt", \.archivedAt); pick("trashedAt", \.trashedAt); pick("allowedHosts", \.allowedHosts)
            out.urls = mergeList(b.urls, l.urls, r.urls)
            out.tags = mergeList(b.tags, l.tags, r.tags).sorted()
            out.agentModes = mergeList(b.agentModes, l.agentModes, r.agentModes)
            // fields by id
            var lost: [ItemField] = []
            var ids: [String] = []
            for f in b.fields + l.fields + r.fields where !ids.contains(f.id) { ids.append(f.id) }
            var fields: [ItemField] = []
            for id in ids {
                let bf = b.fields.first { $0.id == id }, lf = l.fields.first { $0.id == id }, rf = r.fields.first { $0.id == id }
                let chosen: ItemField?
                if lf == rf { chosen = lf }
                else if lf == bf { chosen = rf }
                else if rf == bf { chosen = lf }
                else {
                    chosen = winnerIsLocal ? (lf ?? rf) : (rf ?? lf)   // edit beats delete inside an item too
                    if let loser = winnerIsLocal ? rf : lf, loser != chosen { lost.append(loser) }
                    conflicts.append(MergeConflict(path: "field:\(id)", winner: winnerIsLocal ? "local" : "remote", note: "both changed"))
                }
                if let chosen { fields.append(chosen) }
            }
            out.fields = fields
            out.history = mergeHistory(l.history, r.history)
            if !lost.isEmpty { out.recordHistory("sync conflict", fields: lost) }
            out.createdAt = min(l.createdAt, r.createdAt)
            out.updatedAt = max(l.updatedAt, r.updatedAt)
            return MergeResult(item: out, stamp: stamp, conflicts: conflicts)
        }
    }

    /// Three-way merge of an ordered list treated as a set: keep order of `local`, apply remote adds/removes.
    static func mergeList<T: Equatable>(_ base: [T], _ local: [T], _ remote: [T]) -> [T] {
        let removedRemote = base.filter { !remote.contains($0) }
        let removedLocal = base.filter { !local.contains($0) }
        var out = local.filter { !removedRemote.contains($0) }
        for x in remote where !out.contains(x) && !removedLocal.contains(x) { out.append(x) }
        return out
    }

    static func mergeHistory(_ a: [ItemHistoryEntry]?, _ b: [ItemHistoryEntry]?) -> [ItemHistoryEntry]? {
        guard a != nil || b != nil else { return nil }
        var all = a ?? []
        for e in b ?? [] where !all.contains(e) { all.append(e) }
        return Array(all.sorted { $0.at < $1.at }.suffix(20))
    }
}

/// In-memory reference implementation of the sync state machine (used by tests and as the
/// contract the SQLite store + CKSyncEngine adapter must satisfy).
public final class SyncReplica: @unchecked Sendable {
    public let device: DeviceID
    public private(set) var clock = LamportClock()
    public private(set) var records: [UUID: (item: VaultItem?, meta: RecordMeta)] = [:]
    /// Last version known to be on the server for each record (the merge base).
    public private(set) var base: [UUID: (item: VaultItem?, stamp: Stamp)] = [:]
    public private(set) var pending: Set<UUID> = []
    public private(set) var conflicts: [UUID: [MergeConflict]] = [:]
    let key: SymmetricKey

    public init(device: DeviceID, key: SymmetricKey) { self.device = device; self.key = key }

    public func item(_ id: UUID) -> VaultItem? { records[id]?.item }
    public var liveItems: [VaultItem] { records.values.compactMap(\.item).sorted { ($0.title, $0.id.uuidString) < ($1.title, $1.id.uuidString) } }

    public func write(_ item: VaultItem) {
        let rev = (records[item.id]?.meta.revision ?? 0) + 1
        records[item.id] = (item, RecordMeta(id: item.id, revision: rev, stamp: Stamp(lamport: clock.tick(), device: device)))
        pending.insert(item.id)
    }

    public func delete(_ id: UUID) {
        guard let r = records[id] else { return }
        records[id] = (nil, RecordMeta(id: id, revision: r.meta.revision + 1, stamp: Stamp(lamport: clock.tick(), device: device), deleted: true))
        pending.insert(id)
    }

    /// Records to upload (encrypted).
    public func outgoing() throws -> [SyncRecord] {
        try pending.sorted { $0.uuidString < $1.uuidString }.compactMap { id in
            guard let r = records[id] else { return nil }
            return try SyncRecord.seal(r.item ?? placeholder(id), meta: r.meta, key: key)
        }
    }
    private func placeholder(_ id: UUID) -> VaultItem { VaultItem(id: id, kind: .secureNote, title: "") }

    /// Server accepted our record: it becomes the new base.
    public func didSave(_ rec: SyncRecord) throws {
        guard let r = records[rec.meta.id], r.meta.stamp == rec.meta.stamp else { return }  // edited again meanwhile
        base[rec.meta.id] = (r.item, rec.meta.stamp)
        pending.remove(rec.meta.id)
    }

    /// Apply a record fetched from the server (or a serverRecordChanged conflict payload).
    public func receive(_ rec: SyncRecord) throws {
        clock.observe(rec.meta.stamp.lamport)
        let remoteItem = try rec.open(key: key)
        let id = rec.meta.id
        guard let local = records[id], pending.contains(id) else {
            // no local unsynced edits → fast-forward
            records[id] = (remoteItem, rec.meta)
            base[id] = (remoteItem, rec.meta.stamp)
            return
        }
        let res = MergeEngine.merge(base: base[id]?.item,
                                    local: Version(item: local.item, stamp: local.meta.stamp),
                                    remote: Version(item: remoteItem, stamp: rec.meta.stamp))
        base[id] = (remoteItem, rec.meta.stamp)
        if !res.conflicts.isEmpty { conflicts[id, default: []] += res.conflicts }
        let merged = res.item
        if merged == remoteItem {
            records[id] = (remoteItem, rec.meta); pending.remove(id)
        } else {
            // merged result differs from server → new local revision to upload
            records[id] = (merged, RecordMeta(id: id, revision: max(local.meta.revision, rec.meta.revision) + 1,
                                              stamp: Stamp(lamport: clock.tick(), device: device), deleted: merged == nil))
            pending.insert(id)
        }
    }
}
