import XCTest
@testable import AgentKeyCore

final class CryptoTests: XCTestCase {
    // RFC 7914 §11 / widely published PBKDF2-HMAC-SHA256 vectors
    func testPBKDF2Vectors() throws {
        let pw = Data("password".utf8), salt = Data("salt".utf8)
        XCTAssertEqual(PBKDF2SHA256.portable(password: pw, salt: salt, iterations: 1, length: 32).hex,
                       "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
        XCTAssertEqual(PBKDF2SHA256.portable(password: pw, salt: salt, iterations: 2, length: 32).hex,
                       "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
        XCTAssertEqual(PBKDF2SHA256.portable(password: pw, salt: salt, iterations: 4096, length: 32).hex,
                       "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")
        // Platform path (CommonCrypto on Apple) must agree with the portable one.
        XCTAssertEqual(try PBKDF2SHA256.raw(password: pw, salt: salt, iterations: 4096, length: 40),
                       PBKDF2SHA256.portable(password: pw, salt: salt, iterations: 4096, length: 40))
    }

    func testUnknownKDFRejected() {
        var p = KDFParams.pbkdf2Default(); p.algorithm = "argon2id"
        XCTAssertThrowsError(try KDFRegistry.kdf(for: p))
    }

    func testPasswordNormalization() {
        // "é" precomposed vs combining sequence must derive the same key
        XCTAssertEqual(KDFRegistry.normalize(" caf\u{00E9} "), KDFRegistry.normalize("cafe\u{0301}"))
    }

    func testSecretKeyRoundTripAndChecksum() {
        for _ in 0..<50 {
            let k = SecretKey.generate()
            let s = k.formatted
            XCTAssertTrue(s.hasPrefix("A1-"))
            XCTAssertEqual(SecretKey(formatted: s), k)
            XCTAssertEqual(SecretKey(formatted: s.lowercased()), k)
        }
        var s = Array(SecretKey.generate().formatted)
        let i = s.count - 3
        s[i] = s[i] == "A" ? "B" : "A"
        XCTAssertNil(SecretKey(formatted: String(s)), "single-char typo must fail checksum")
    }

    func testAUKDependsOnBothFactors() throws {
        let params = KDFParams(algorithm: "pbkdf2-sha256", iterations: 1000, memoryKiB: nil, parallelism: nil, salt: Data(repeating: 1, count: 16))
        let sk = SecretKey.generate(), acct = UUID()
        let a = try KeyHierarchy.accountUnlockKey(password: "correct horse", secretKey: sk, accountID: acct, params: params)
        let b = try KeyHierarchy.accountUnlockKey(password: "correct horse", secretKey: sk, accountID: acct, params: params)
        let c = try KeyHierarchy.accountUnlockKey(password: "correct horsf", secretKey: sk, accountID: acct, params: params)
        let d = try KeyHierarchy.accountUnlockKey(password: "correct horse", secretKey: .generate(), accountID: acct, params: params)
        XCTAssertEqual(a.data, b.data)
        XCTAssertNotEqual(a.data, c.data)
        XCTAssertNotEqual(a.data, d.data)
    }

    func testSealOpenAADBinding() throws {
        let k = SymmetricKey(size: .bits256)
        let ct = try KeyHierarchy.seal(Data("hi".utf8), key: k, aad: Data("a".utf8))
        XCTAssertEqual(try KeyHierarchy.open(ct, key: k, aad: Data("a".utf8)), Data("hi".utf8))
        XCTAssertThrowsError(try KeyHierarchy.open(ct, key: k, aad: Data("b".utf8)))
    }
}
