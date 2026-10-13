#if canImport(CryptoKit)
@_exported import CryptoKit
#else
@_exported import Crypto
#endif
import Foundation

public enum AKRandom {
    /// Cryptographically secure random bytes (SystemRandomNumberGenerator is CSPRNG on Apple + Linux).
    public static func bytes(_ count: Int) -> Data {
        var g = SystemRandomNumberGenerator()
        return Data((0..<count).map { _ in UInt8.random(in: .min ... .max, using: &g) })
    }
}

extension Data {
    public var hex: String { map { String(format: "%02x", $0) }.joined() }
    public init?(hex: String) {
        let chars = Array(hex.utf8); guard chars.count % 2 == 0 else { return nil }
        var out = Data(capacity: chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let b = UInt8(String(decoding: chars[i..<i+2], as: UTF8.self), radix: 16) else { return nil }
            out.append(b); i += 2
        }
        self = out
    }
    /// Best-effort zeroing (Swift cannot guarantee no copies exist).
    public mutating func wipe() { resetBytes(in: 0..<count) }
}

extension SymmetricKey {
    public var data: Data { withUnsafeBytes { Data($0) } }
}
