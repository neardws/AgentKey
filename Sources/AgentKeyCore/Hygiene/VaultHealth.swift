import Foundation

/// Vault hygiene analysis. Runs inside the trusted process (agentkeyd / app) that holds the
/// vault key. Output contains only metadata (ids, refs, titles, scores, group ids) — never a
/// secret value or an unkeyed hash of one.
public struct HealthOptions: Codable, Sendable {
    public var staleDays = 365          // not used / modified for this long
    public var rotationDays = 730       // password not changed for this long
    public var trashRetentionDays = 30  // trashed longer than this → purge suggestion
    public var minLength = 12
    public var minEntropyBits = 60.0
    public init() {}
}

public enum FindingKind: String, Codable, CaseIterable, Sendable {
    case reused = "reused_password", weak = "weak_password", duplicate = "duplicate_entry",
         stale = "stale_item", oldPassword = "password_not_rotated", missingTOTP = "missing_totp",
         trashNotPurged = "trash_not_purged"
}

public enum Severity: String, Codable, Comparable, Sendable {
    case low, medium, high
    var rank: Int { switch self { case .low: return 0; case .medium: return 1; case .high: return 2 } }
    public static func < (a: Severity, b: Severity) -> Bool { a.rank < b.rank }
}

public struct HealthFinding: Codable, Equatable, Sendable {
    public var kind: FindingKind
    public var severity: Severity
    public var itemIDs: [UUID]
    public var refs: [String]
    public var detail: String
    public var groupID: String?        // reused/duplicate group (keyed, per-vault, not a password hash)
    public var metrics: [String: Double]?
}

public struct HealthReport: Codable, Sendable {
    public var generatedAt: Date
    public var itemCount: Int
    public var score: Int              // 0–100
    public var counts: [String: Int]
    public var findings: [HealthFinding]
}

public enum VaultHealth {
    /// Small embedded list of the most common passwords (lower-cased). TODO: ship a larger
    /// compressed list (e.g. top 100k from HIBP Pwned Passwords) as a resource.
    static let common: Set<String> = ["123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111",
        "1234567", "dragon", "123123", "baseball", "abc123", "football", "monkey", "letmein", "696969", "shadow", "master",
        "666666", "qwertyuiop", "123321", "mustang", "1234567890", "michael", "654321", "superman", "1qaz2wsx", "7777777",
        "121212", "000000", "qazwsx", "123qwe", "killer", "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter",
        "buster", "soccer", "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou", "2000", "charlie", "robert",
        "thomas", "hockey", "ranger", "daniel", "starwars", "klaster", "112233", "george", "computer", "michelle", "jessica",
        "pepper", "1111", "zxcvbn", "555555", "11111111", "131313", "freedom", "777777", "pass", "maggie", "159753",
        "aaaaaa", "ginger", "princess", "joshua", "cheese", "amanda", "summer", "love", "ashley", "nicole", "chelsea",
        "biteme", "matthew", "access", "yankees", "987654321", "dallas", "austin", "thunder", "taylor", "matrix",
        "admin", "welcome", "password1", "p@ssw0rd", "passw0rd", "changeme", "secret", "qwerty123", "iloveyou1"]

    /// Sites known to support TOTP 2FA (placeholder; TODO: use the 2fa.directory dataset).
    static let totpCapable: Set<String> = ["google.com", "github.com", "gitlab.com", "microsoft.com", "live.com", "apple.com",
        "amazon.com", "aws.amazon.com", "dropbox.com", "facebook.com", "instagram.com", "x.com", "twitter.com", "linkedin.com",
        "discord.com", "slack.com", "cloudflare.com", "digitalocean.com", "stripe.com", "paypal.com", "coinbase.com",
        "binance.com", "npmjs.com", "pypi.org", "docker.com", "heroku.com", "atlassian.com", "notion.so", "openai.com",
        "reddit.com", "twitch.tv", "proton.me", "fastmail.com", "namecheap.com", "godaddy.com", "vercel.com", "figma.com"]

    /// Shannon-style estimate: length × log2(charset), penalized for repeats / sequences / common words.
    public static func entropyBits(_ pw: String) -> Double {
        if pw.isEmpty { return 0 }
        var pool = 0
        if pw.contains(where: { $0.isLowercase }) { pool += 26 }
        if pw.contains(where: { $0.isUppercase }) { pool += 26 }
        if pw.contains(where: { $0.isNumber }) { pool += 10 }
        if pw.contains(where: { !$0.isLetter && !$0.isNumber }) { pool += 33 }
        if pw.unicodeScalars.contains(where: { $0.value > 127 }) { pool += 100 }
        let unique = Set(pw).count
        // effective length: unique characters count fully, repeats half
        let effLen = Double(unique) + Double(pw.count - unique) * 0.5
        var bits = effLen * log2(Double(max(pool, 1)))
        let lower = pw.lowercased()
        if common.contains(lower) { return min(bits, 10) }
        for w in common where w.count >= 5 && lower.contains(w) { bits -= Double(w.count) * 3; break }
        // sequential runs like "1234" / "abcd"
        let s = Array(lower.unicodeScalars.map(\.value))
        var run = 1
        for i in 1..<max(s.count, 1) where i < s.count {
            run = s[i] == s[i - 1] + 1 ? run + 1 : 1
            if run >= 4 { bits -= 4 }
        }
        return max(bits, 0)
    }

    public static func analyze(_ items: [VaultItem], hmacKey: SymmetricKey, options o: HealthOptions = HealthOptions(),
                               now: Date = Date()) -> HealthReport {
        var findings: [HealthFinding] = []
        let ref = { (i: VaultItem) in ItemRef.make(title: i.title) }
        let day: TimeInterval = 86_400
        let live = items.filter { !$0.isTrashed }
        let keyed = { (s: String) in Data(HMAC<SHA256>.authenticationCode(for: Data(s.utf8), using: hmacKey)).hex }
        func secret(_ i: VaultItem) -> String? {
            guard i.kind == .login || i.kind == .apiToken else { return nil }
            let v = i.field(nil)?.value ?? ""
            return v.isEmpty ? nil : v
        }

        // reused: group by keyed hash
        var groups: [String: [VaultItem]] = [:]
        for i in live { if let s = secret(i) { groups[keyed("pw|" + s), default: []].append(i) } }
        for (g, members) in groups where members.count > 1 {
            findings.append(HealthFinding(kind: .reused, severity: .high, itemIDs: members.map(\.id), refs: members.map(ref),
                detail: "\(members.count) items share the same password", groupID: String(g.prefix(12)), metrics: ["count": Double(members.count)]))
        }
        // weak
        for i in live where i.kind == .login {
            guard let s = secret(i) else { continue }
            let bits = entropyBits(s)
            let isCommon = common.contains(s.lowercased())
            if isCommon || s.count < o.minLength || bits < o.minEntropyBits {
                let why = isCommon ? "very common password" : s.count < o.minLength ? "shorter than \(o.minLength) characters" : "low estimated entropy"
                findings.append(HealthFinding(kind: .weak, severity: isCommon || bits < 40 ? .high : .medium, itemIDs: [i.id], refs: [ref(i)],
                    detail: why, groupID: nil, metrics: ["entropyBits": (bits * 10).rounded() / 10, "length": Double(s.count)]))
            }
        }
        // duplicates: same host (or title) + username
        var dup: [String: [VaultItem]] = [:]
        for i in live where i.kind == .login {
            let host = i.urls.first.flatMap(Importer.normalizedHost) ?? i.title.lowercased()
            dup["\(host)|\((i.username ?? "").lowercased())", default: []].append(i)
        }
        for (k, members) in dup where members.count > 1 {
            findings.append(HealthFinding(kind: .duplicate, severity: .medium, itemIDs: members.map(\.id), refs: members.map(ref),
                detail: "\(members.count) entries for the same site and username", groupID: String(keyed("dup|" + k).prefix(12)), metrics: nil))
        }
        // stale / old passwords / missing TOTP
        for i in live where !i.isArchived {
            let last = max(i.lastUsedAt ?? .distantPast, i.updatedAt)
            let idle = now.timeIntervalSince(last) / day
            if idle > Double(o.staleDays) {
                findings.append(HealthFinding(kind: .stale, severity: .low, itemIDs: [i.id], refs: [ref(i)],
                    detail: "not used or modified for \(Int(idle)) days", groupID: nil, metrics: ["days": idle.rounded()]))
            }
            if secret(i) != nil {
                let changed = i.passwordChangedAt ?? i.createdAt
                let age = now.timeIntervalSince(changed) / day
                if age > Double(o.rotationDays) {
                    findings.append(HealthFinding(kind: .oldPassword, severity: .low, itemIDs: [i.id], refs: [ref(i)],
                        detail: "password not changed for \(Int(age)) days", groupID: nil, metrics: ["days": age.rounded()]))
                }
            }
            if i.kind == .login, !i.fields.contains(where: { $0.id == "totp" }),
               let host = i.urls.first.flatMap(Importer.normalizedHost),
               totpCapable.contains(where: { host == $0 || host.hasSuffix("." + $0) }) {
                findings.append(HealthFinding(kind: .missingTOTP, severity: .medium, itemIDs: [i.id], refs: [ref(i)],
                    detail: "\(host) supports authenticator-app 2FA but no TOTP is stored", groupID: nil, metrics: nil))
            }
        }
        // trash
        for i in items where i.isTrashed {
            let d = now.timeIntervalSince(i.trashedAt!) / day
            if d > Double(o.trashRetentionDays) {
                findings.append(HealthFinding(kind: .trashNotPurged, severity: .low, itemIDs: [i.id], refs: [ref(i)],
                    detail: "in trash for \(Int(d)) days", groupID: nil, metrics: ["days": d.rounded()]))
            }
        }
        findings.sort { ($0.severity, $1.kind.rawValue) > ($1.severity, $0.kind.rawValue) }
        var counts: [String: Int] = [:]
        for f in findings { counts[f.kind.rawValue, default: 0] += 1 }
        let penalty = findings.reduce(0) { $0 + ($1.severity == .high ? 8 : $1.severity == .medium ? 4 : 1) }
        let score = live.isEmpty ? 100 : max(0, 100 - Int(Double(penalty) * 20 / Double(max(live.count, 5))))
        return HealthReport(generatedAt: now, itemCount: live.count, score: score, counts: counts, findings: findings)
    }
}
