import Foundation

/// Append-only, hash-chained JSONL audit log. Each line carries `prev` (hash of the previous
/// line) and `hash` = SHA256(prev || canonical JSON of the entry without `hash`).
/// If a chain key is configured, `mac` = HMAC-SHA256(chainKey, hash) so an attacker who can
/// write the file but does not know the vault key cannot forge a consistent tail.
public struct AuditEntry: Codable, Equatable, Sendable {
    public var seq: Int
    public var ts: Date
    public var event: String          // request | approved | denied | released | error | unlock | lock
    public var agent: String
    public var ref: String?
    public var mode: String?
    public var code: String?          // 4-char correlation code shown in the system prompt
    public var detail: String?
    public var peerPID: Int32?
    public var peerUID: UInt32?
    public var prev: String
    public var hash: String
    public var mac: String?
}

public final class AuditLog: @unchecked Sendable {
    public let url: URL
    private let lock = NSLock()
    private var lastHash: String
    private var seq: Int
    private let chainKey: SymmetricKey?
    public static let genesis = String(repeating: "0", count: 64)

    public init(url: URL, chainKey: SymmetricKey? = nil) throws {
        self.url = url; self.chainKey = chainKey
        let fm = FileManager.default
        try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        if !fm.fileExists(atPath: url.path) { fm.createFile(atPath: url.path, contents: nil, attributes: [.posixPermissions: 0o600]) }
        let entries = try Self.read(url)
        lastHash = entries.last?.hash ?? Self.genesis
        seq = entries.last?.seq ?? 0
    }

    static let enc: JSONEncoder = { let e = JSONEncoder(); e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]; e.dateEncodingStrategy = .iso8601; return e }()
    static let dec: JSONDecoder = { let d = JSONDecoder(); d.dateDecodingStrategy = .iso8601; return d }()

    static func digest(_ e: AuditEntry) -> String {
        var c = e; c.hash = ""; c.mac = nil
        let body = (try? enc.encode(c)) ?? Data()
        return Data(SHA256.hash(data: Data(e.prev.utf8) + body)).hex
    }

    @discardableResult
    public func append(event: String, agent: String, ref: String? = nil, mode: String? = nil, code: String? = nil,
                       detail: String? = nil, peerPID: Int32? = nil, peerUID: UInt32? = nil) throws -> AuditEntry {
        lock.lock(); defer { lock.unlock() }
        // Second-resolution timestamps so the ISO8601 round-trip is exact.
        let ts = Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down))
        var e = AuditEntry(seq: seq + 1, ts: ts, event: event, agent: agent, ref: ref, mode: mode, code: code,
                           detail: detail, peerPID: peerPID, peerUID: peerUID, prev: lastHash, hash: "", mac: nil)
        e.hash = Self.digest(e)
        if let k = chainKey { e.mac = Data(HMAC<SHA256>.authenticationCode(for: Data(e.hash.utf8), using: k)).hex }
        var line = try Self.enc.encode(e); line.append(0x0a)
        let h = try FileHandle(forWritingTo: url)
        defer { try? h.close() }
        try h.seekToEnd(); try h.write(contentsOf: line)
        lastHash = e.hash; seq = e.seq
        return e
    }

    public static func read(_ url: URL) throws -> [AuditEntry] {
        guard let d = FileManager.default.contents(atPath: url.path), !d.isEmpty else { return [] }
        return try d.split(separator: 0x0a).map { try dec.decode(AuditEntry.self, from: Data($0)) }
    }

    public enum VerifyResult: Equatable { case ok(count: Int), broken(atSeq: Int, reason: String) }

    public static func verify(_ url: URL, chainKey: SymmetricKey? = nil) throws -> VerifyResult {
        var prev = genesis, n = 0
        for e in try read(url) {
            n += 1
            if e.seq != n { return .broken(atSeq: e.seq, reason: "sequence gap") }
            if e.prev != prev { return .broken(atSeq: e.seq, reason: "prev mismatch") }
            if digest(e) != e.hash { return .broken(atSeq: e.seq, reason: "hash mismatch") }
            if let k = chainKey {
                let m = Data(HMAC<SHA256>.authenticationCode(for: Data(e.hash.utf8), using: k)).hex
                if e.mac != m { return .broken(atSeq: e.seq, reason: "mac mismatch") }
            }
            prev = e.hash
        }
        return .ok(count: n)
    }
}
