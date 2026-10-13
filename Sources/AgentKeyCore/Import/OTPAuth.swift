import Foundation

/// Parsed `otpauth://totp/Issuer:account?secret=...&issuer=...` URI (Google Authenticator key URI format).
public struct OTPAuthURI: Equatable, Sendable {
    public var type: String          // "totp" | "hotp"
    public var issuer: String?
    public var account: String?
    public var secret: Data
    public var digits: Int
    public var period: Int
    public var algorithm: TOTP.Algorithm

    public init?(_ s: String) {
        let str = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard str.lowercased().hasPrefix("otpauth://"), let c = URLComponents(string: str),
              let host = c.host?.lowercased(), host == "totp" || host == "hotp" else { return nil }
        type = host
        var label = c.path.hasPrefix("/") ? String(c.path.dropFirst()) : c.path
        label = label.removingPercentEncoding ?? label
        let q = Dictionary((c.queryItems ?? []).map { ($0.name.lowercased(), $0.value ?? "") }, uniquingKeysWith: { a, _ in a })
        guard let sec = q["secret"].flatMap(Base32.decode), !sec.isEmpty else { return nil }
        secret = sec
        if let colon = label.firstIndex(of: ":") {
            issuer = String(label[..<colon]).trimmingCharacters(in: .whitespaces)
            account = String(label[label.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
        } else { account = label.isEmpty ? nil : label }
        if let i = q["issuer"], !i.isEmpty { issuer = i }
        digits = q["digits"].flatMap(Int.init).flatMap { (6...8).contains($0) ? $0 : nil } ?? 6
        period = q["period"].flatMap(Int.init).flatMap { $0 > 0 ? $0 : nil } ?? 30
        algorithm = q["algorithm"].flatMap { TOTP.Algorithm(rawValue: $0.uppercased()) } ?? .sha1
    }

    public var totp: TOTP { TOTP(secret: secret, digits: digits, period: period, algorithm: algorithm) }

    /// Canonical URI (what we store), so bare secrets and URIs normalize the same way.
    public var uriString: String {
        var c = URLComponents()
        c.scheme = "otpauth"; c.host = type
        let label = [issuer, account].compactMap { $0 }.joined(separator: ":")
        c.path = "/" + label
        var items = [URLQueryItem(name: "secret", value: Base32.encode(secret))]
        if let issuer { items.append(URLQueryItem(name: "issuer", value: issuer)) }
        items += [URLQueryItem(name: "algorithm", value: algorithm.rawValue),
                  URLQueryItem(name: "digits", value: String(digits)),
                  URLQueryItem(name: "period", value: String(period))]
        c.queryItems = items
        return c.string ?? ""
    }

    /// Normalize a TOTP value from an export: otpauth URI, or a bare Base32 secret.
    /// Returns nil if it's neither (e.g. Steam guard or garbage).
    public static func normalize(_ raw: String, issuer: String?, account: String?) -> String? {
        let t = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.isEmpty { return nil }
        if let u = OTPAuthURI(t) { return u.uriString }
        guard let sec = Base32.decode(t), sec.count >= 10 else { return nil }
        var c = URLComponents(); c.scheme = "otpauth"; c.host = "totp"
        c.path = "/" + [issuer, account].compactMap { $0 }.joined(separator: ":")
        c.queryItems = [URLQueryItem(name: "secret", value: Base32.encode(sec))] + (issuer.map { [URLQueryItem(name: "issuer", value: $0)] } ?? [])
        return c.string
    }
}
