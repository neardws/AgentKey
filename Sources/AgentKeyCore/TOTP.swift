import Foundation

/// RFC 6238 TOTP / RFC 4226 HOTP.
public struct TOTP: Equatable, Sendable {
    public enum Algorithm: String, Sendable { case sha1 = "SHA1", sha256 = "SHA256", sha512 = "SHA512" }
    public var secret: Data
    public var digits: Int = 6
    public var period: Int = 30
    public var algorithm: Algorithm = .sha1

    public init(secret: Data, digits: Int = 6, period: Int = 30, algorithm: Algorithm = .sha1) {
        self.secret = secret; self.digits = digits; self.period = period; self.algorithm = algorithm
    }

    /// Accepts a bare Base32 secret or an `otpauth://totp/...` URI.
    public init?(string: String) {
        let s = string.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.lowercased().hasPrefix("otpauth://") {
            guard let c = URLComponents(string: s), c.host?.lowercased() == "totp" else { return nil }
            let q = Dictionary((c.queryItems ?? []).map { ($0.name.lowercased(), $0.value ?? "") }, uniquingKeysWith: { a, _ in a })
            guard let sec = q["secret"].flatMap(Base32.decode) else { return nil }
            self.secret = sec
            if let d = q["digits"].flatMap(Int.init), (6...8).contains(d) { digits = d }
            if let p = q["period"].flatMap(Int.init), p > 0 { period = p }
            if let a = q["algorithm"].flatMap({ Algorithm(rawValue: $0.uppercased()) }) { algorithm = a }
        } else {
            guard let sec = Base32.decode(s) else { return nil }
            self.secret = sec
        }
    }

    public func code(at date: Date = Date()) -> String {
        hotp(counter: UInt64(max(0, date.timeIntervalSince1970) / Double(period)))
    }

    public func secondsRemaining(at date: Date = Date()) -> Int {
        period - Int(date.timeIntervalSince1970) % period
    }

    public func hotp(counter: UInt64) -> String {
        var c = counter.bigEndian
        let msg = Data(bytes: &c, count: 8)
        let key = SymmetricKey(data: secret)
        let mac: Data
        switch algorithm {
        case .sha1: mac = Data(HMAC<Insecure.SHA1>.authenticationCode(for: msg, using: key))
        case .sha256: mac = Data(HMAC<SHA256>.authenticationCode(for: msg, using: key))
        case .sha512: mac = Data(HMAC<SHA512>.authenticationCode(for: msg, using: key))
        }
        let off = Int(mac[mac.count - 1] & 0x0f)
        let bin = (UInt32(mac[off] & 0x7f) << 24) | (UInt32(mac[off + 1]) << 16) | (UInt32(mac[off + 2]) << 8) | UInt32(mac[off + 3])
        var mod: UInt32 = 1; for _ in 0..<digits { mod *= 10 }
        let v = String(bin % mod)
        return String(repeating: "0", count: digits - v.count) + v
    }
}

public enum Base32 {
    static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    public static func decode(_ s: String) -> Data? {
        let clean = s.uppercased().filter { $0 != "=" && $0 != " " && $0 != "-" }
        guard !clean.isEmpty else { return nil }
        var bits = 0, value = 0; var out = Data()
        for ch in clean {
            guard let i = alphabet.firstIndex(of: ch) else { return nil }
            value = (value << 5) | i; bits += 5
            if bits >= 8 { out.append(UInt8((value >> (bits - 8)) & 0xff)); bits -= 8 }
        }
        return out
    }
    public static func encode(_ d: Data) -> String {
        var bits = 0, value = 0, out = ""
        for b in d {
            value = (value << 8) | Int(b); bits += 8
            while bits >= 5 { out.append(alphabet[(value >> (bits - 5)) & 31]); bits -= 5 }
        }
        if bits > 0 { out.append(alphabet[(value << (5 - bits)) & 31]) }
        return out
    }
}
