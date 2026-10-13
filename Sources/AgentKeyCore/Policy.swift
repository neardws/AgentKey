import Foundation

/// Per-agent policy, loaded from ~/Library/Application Support/AgentKey/policy.json.
/// Effective modes for a request = item.agentModes ∩ agent.modes. `reveal` must be granted
/// on BOTH the item and the agent; it is never part of any default.
public struct AgentPolicy: Codable, Equatable, Sendable {
    public struct Rule: Codable, Equatable, Sendable {
        public var modes: [ReleaseMode]
        public var items: [String]?          // title globs, nil = all
        public init(modes: [ReleaseMode], items: [String]? = nil) { self.modes = modes; self.items = items }
    }
    public var defaultRule: Rule
    public var agents: [String: Rule]
    public var approvalTimeoutSeconds: Int

    public init(defaultRule: Rule = Rule(modes: [.run, .totp]), agents: [String: Rule] = [:], approvalTimeoutSeconds: Int = 60) {
        self.defaultRule = defaultRule; self.agents = agents; self.approvalTimeoutSeconds = approvalTimeoutSeconds
    }

    public static func load(_ url: URL) -> AgentPolicy {
        guard let d = FileManager.default.contents(atPath: url.path),
              let p = try? JSONDecoder().decode(AgentPolicy.self, from: d) else { return AgentPolicy() }
        return p
    }

    public enum Decision: Equatable, Sendable { case needsApproval, deny(String) }

    public func evaluate(agent: String, item: VaultItem, mode: ReleaseMode) -> Decision {
        let rule = agents[agent] ?? defaultRule
        guard rule.modes.contains(mode) else { return .deny("mode \(mode.rawValue) not allowed for agent \(agent)") }
        guard item.agentModes.contains(mode) else { return .deny("mode \(mode.rawValue) not enabled on item") }
        if let globs = rule.items, !globs.contains(where: { Glob.match($0, item.title) }) {
            return .deny("item not in agent's allow-list")
        }
        return .needsApproval   // policy can only narrow; a human always approves each release
    }
}

enum Glob {
    static func match(_ pattern: String, _ s: String) -> Bool {
        let p = Array(pattern.lowercased()), t = Array(s.lowercased())
        func m(_ i: Int, _ j: Int) -> Bool {
            if i == p.count { return j == t.count }
            if p[i] == "*" { return m(i + 1, j) || (j < t.count && m(i, j + 1)) }
            return j < t.count && (p[i] == "?" || p[i] == t[j]) && m(i + 1, j + 1)
        }
        return m(0, 0)
    }
}

/// Untrusted strings (agent label, item title, command) that end up in the system prompt.
public enum PromptSanitizer {
    public static func clean(_ s: String, max: Int = 40) -> String {
        let spaced = s.replacingOccurrences(of: "\r\n", with: " ").replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\r", with: " ").replacingOccurrences(of: "\t", with: " ")
        let allowed = spaced.unicodeScalars.filter { u in
            // drop controls, bidi overrides, zero-width & format chars that can spoof the prompt
            if u.properties.generalCategory == .control || u.properties.generalCategory == .format { return false }
            if u.properties.isBidiControl { return false }
            return true
        }
        var out = String(String.UnicodeScalarView(allowed))
            .replacingOccurrences(of: "“", with: "'").replacingOccurrences(of: "”", with: "'")
            .trimmingCharacters(in: .whitespaces)
        if out.count > max { out = String(out.prefix(max - 1)) + "…" }
        return out.isEmpty ? "?" : out
    }

    /// 4-char code shown both in the Touch ID / Watch sheet and in the agent's terminal,
    /// so the user can match the prompt to the request.
    public static func correlationCode() -> String {
        let a = Array("ACDEFHJKMNPRTWXY3479")
        var g = SystemRandomNumberGenerator()
        return String((0..<4).map { _ in a.randomElement(using: &g)! })
    }
}

/// Replace secret values (and common encodings) in text that flows back to an agent.
///
/// - Every non-empty secret is redacted by exact match, whatever its length.
/// - Encoded variants (Base64, Base64URL, hex, percent-encoding) are added for secrets ≥ 4 bytes.
/// - Secrets shorter than `minimumSafeLength` are listed in `weakSecrets`: redacting them is
///   unreliable (they may also hit unrelated output, and transformed copies are not caught).
public struct Redactor: Sendable {
    public static let minimumSafeLength = 8
    let needles: [([UInt8], [UInt8])]       // (pattern, replacement), longest pattern first
    public let maxNeedleLength: Int
    public let weakSecrets: [String]        // labels of secrets shorter than minimumSafeLength

    public init(secrets: [(label: String, value: String)]) {
        var n: [String: String] = [:]
        var weak: [String] = []
        for s in secrets where !s.value.isEmpty {
            let repl = "‹redacted:\(s.label)›"
            if s.value.utf8.count < Self.minimumSafeLength { weak.append(s.label) }
            n[s.value] = repl
            if s.value.utf8.count >= 4 {
                let d = Data(s.value.utf8)
                let b64 = d.base64EncodedString()
                let variants = [b64, b64.replacingOccurrences(of: "=", with: ""),
                                b64.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: ""),
                                d.hex, d.hex.uppercased(),
                                s.value.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? s.value]
                for v in variants where n[v] == nil { n[v] = repl }
            }
        }
        needles = n.map { (Array($0.key.utf8), Array($0.value.utf8)) }.sorted { $0.0.count > $1.0.count }
        maxNeedleLength = needles.first?.0.count ?? 0
        weakSecrets = weak
    }

    public var warning: String? {
        weakSecrets.isEmpty ? nil :
        "secret(s) shorter than \(Self.minimumSafeLength) chars: \(weakSecrets.joined(separator: ", ")) — output redaction is unreliable for short values"
    }

    public func redact(_ text: String) -> String {
        let s = stream()
        return String(decoding: s.feed(Array(text.utf8)) + s.finish(), as: UTF8.self)
    }

    /// Streaming redaction that is safe across arbitrary chunk boundaries (operates on bytes,
    /// so split UTF-8 sequences are fine too).
    public func stream() -> RedactingStream { RedactingStream(self) }

    /// Redact `buf[0..<limit]`, never splitting a match: a match may start before `limit`
    /// and extend past it. Returns (output, bytes consumed).
    func process(_ buf: [UInt8], limit: Int) -> ([UInt8], Int) {
        var out: [UInt8] = []; out.reserveCapacity(limit)
        var i = 0
        outer: while i < limit {
            for (pat, rep) in needles where i + pat.count <= buf.count && buf[i] == pat[0] {
                if buf[i..<(i + pat.count)].elementsEqual(pat) {
                    out.append(contentsOf: rep); i += pat.count; continue outer
                }
            }
            out.append(buf[i]); i += 1
        }
        return (out, i)
    }
}

public final class RedactingStream: @unchecked Sendable {
    let r: Redactor
    var pending: [UInt8] = []
    init(_ r: Redactor) { self.r = r }

    /// Feed a chunk; returns bytes that are safe to emit now. Holds back at most
    /// (longest pattern − 1) bytes that could be the start of a match.
    public func feed(_ chunk: [UInt8]) -> [UInt8] {
        pending.append(contentsOf: chunk)
        let hold = max(0, r.maxNeedleLength - 1)
        guard pending.count > hold else { return [] }
        let (out, used) = r.process(pending, limit: pending.count - hold)
        pending.removeFirst(used)
        return out
    }
    public func feed(_ chunk: Data) -> Data { Data(feed([UInt8](chunk))) }

    /// Flush everything at EOF.
    public func finish() -> [UInt8] {
        let (out, _) = r.process(pending, limit: pending.count)
        pending.removeAll()
        return out
    }
}
