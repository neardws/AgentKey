import Foundation

/// 128-bit device-generated Secret Key (1Password-style 2SKD). Never leaves the device
/// except on the user's printed Emergency Kit. Format: "A1-XXXXX-XXXXX-..." (Crockford Base32).
public struct SecretKey: Equatable, Sendable {
    public let bytes: Data
    public init(bytes: Data) { self.bytes = bytes }
    public static func generate() -> SecretKey { SecretKey(bytes: AKRandom.bytes(16)) }

    static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    public var formatted: String {
        var bits = 0, value = 0, chars: [Character] = []
        for b in bytes {
            value = (value << 8) | Int(b); bits += 8
            while bits >= 5 { chars.append(Self.alphabet[(value >> (bits - 5)) & 31]); bits -= 5 }
        }
        if bits > 0 { chars.append(Self.alphabet[(value << (5 - bits)) & 31]) }
        // checksum char: sum of indices mod 32
        let sum = chars.reduce(0) { $0 + Self.alphabet.firstIndex(of: $1)! } % 32
        chars.append(Self.alphabet[sum])
        let groups = stride(from: 0, to: chars.count, by: 5).map { String(chars[$0..<min($0 + 5, chars.count)]) }
        return "A1-" + groups.joined(separator: "-")
    }

    public init?(formatted s: String) {
        var str = s.uppercased().replacingOccurrences(of: "-", with: "").replacingOccurrences(of: " ", with: "")
        guard str.hasPrefix("A1") else { return nil }
        str.removeFirst(2)
        var chars = Array(str)
        // Crockford aliases
        chars = chars.map { c in c == "O" ? "0" : (c == "I" || c == "L") ? "1" : c }
        guard chars.count == 27, let check = chars.popLast() else { return nil }
        var idx: [Int] = []
        for c in chars { guard let i = Self.alphabet.firstIndex(of: c) else { return nil }; idx.append(i) }
        guard Self.alphabet[idx.reduce(0, +) % 32] == check else { return nil }
        var bits = 0, value = 0; var out = Data()
        for i in idx {
            value = (value << 5) | i; bits += 5
            if bits >= 8 { out.append(UInt8((value >> (bits - 8)) & 0xff)); bits -= 8 }
        }
        guard out.count == 16 else { return nil }
        self.bytes = out
    }
}
