import Foundation
#if canImport(CommonCrypto)
import CommonCrypto
#endif

/// Parameters persisted in the vault header so they can be upgraded later.
public struct KDFParams: Codable, Equatable, Sendable {
    public var algorithm: String      // "pbkdf2-sha256" today; "argon2id" planned
    public var iterations: Int        // PBKDF2 rounds (or Argon2 t)
    public var memoryKiB: Int?        // Argon2 m
    public var parallelism: Int?      // Argon2 p
    public var salt: Data

    public static func pbkdf2Default(salt: Data = AKRandom.bytes(16)) -> KDFParams {
        // OWASP 2023+ recommendation for PBKDF2-HMAC-SHA256.
        KDFParams(algorithm: "pbkdf2-sha256", iterations: 600_000, memoryKiB: nil, parallelism: nil, salt: salt)
    }
}

/// Abstraction so Argon2id can drop in without touching the key hierarchy.
public protocol PasswordKDF: Sendable {
    func derive(password: String, params: KDFParams, length: Int) throws -> Data
}

public enum KDFError: Error { case unsupported(String), failed }

public enum KDFRegistry {
    public static func kdf(for params: KDFParams) throws -> PasswordKDF {
        switch params.algorithm {
        case "pbkdf2-sha256": return PBKDF2SHA256()
        // TODO(argon2id): vendor phc-winner-argon2 (CC0) as a C target or link libsodium
        // crypto_pwhash(ALG_ARGON2ID13), default m=128MiB t=3 p=4, and register it here.
        default: throw KDFError.unsupported(params.algorithm)
        }
    }

    /// Unicode NFKD + whitespace trim, so the same password typed on Mac/iPhone matches.
    public static func normalize(_ password: String) -> Data {
        Data(password.trimmingCharacters(in: .whitespacesAndNewlines)
            .decomposedStringWithCompatibilityMapping.utf8)
    }
}

public struct PBKDF2SHA256: PasswordKDF {
    public init() {}
    public func derive(password: String, params: KDFParams, length: Int = 32) throws -> Data {
        let pw = KDFRegistry.normalize(password)
        return try Self.raw(password: pw, salt: params.salt, iterations: params.iterations, length: length)
    }

    public static func raw(password: Data, salt: Data, iterations: Int, length: Int) throws -> Data {
        #if canImport(CommonCrypto)
        var out = Data(count: length)
        let rc = out.withUnsafeMutableBytes { o in
            password.withUnsafeBytes { p in
                salt.withUnsafeBytes { s in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                        p.baseAddress?.assumingMemoryBound(to: CChar.self), password.count,
                        s.baseAddress?.assumingMemoryBound(to: UInt8.self), salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), UInt32(iterations),
                        o.baseAddress?.assumingMemoryBound(to: UInt8.self), length)
                }
            }
        }
        guard rc == kCCSuccess else { throw KDFError.failed }
        return out
        #else
        return portable(password: password, salt: salt, iterations: iterations, length: length)
        #endif
    }

    /// RFC 8018 PBKDF2 on top of CryptoKit/swift-crypto HMAC (used on Linux, and in tests).
    public static func portable(password: Data, salt: Data, iterations: Int, length: Int) -> Data {
        let key = SymmetricKey(data: password)
        var out = Data()
        var block: UInt32 = 1
        while out.count < length {
            var s = salt
            s.append(contentsOf: [UInt8(block >> 24), UInt8((block >> 16) & 0xff), UInt8((block >> 8) & 0xff), UInt8(block & 0xff)])
            var u = [UInt8](HMAC<SHA256>.authenticationCode(for: s, using: key))
            var t = u
            if iterations > 1 {
                for _ in 1..<iterations {
                    u = [UInt8](HMAC<SHA256>.authenticationCode(for: u, using: key))
                    for i in 0..<t.count { t[i] ^= u[i] }
                }
            }
            out.append(contentsOf: t); block += 1
        }
        return out.prefix(length)
    }
}
