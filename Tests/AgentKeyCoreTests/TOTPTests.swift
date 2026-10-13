import XCTest
@testable import AgentKeyCore

final class TOTPTests: XCTestCase {
    let s1 = Data("12345678901234567890".utf8)
    let s256 = Data("12345678901234567890123456789012".utf8)
    let s512 = Data("1234567890123456789012345678901234567890123456789012345678901234".utf8)

    // RFC 4226 Appendix D
    func testHOTP() {
        let t = TOTP(secret: s1)
        XCTAssertEqual((0...9).map { t.hotp(counter: UInt64($0)) },
                       ["755224","287082","359152","969429","338314","254676","287922","162583","399871","520489"])
    }

    // RFC 6238 Appendix B
    func testTOTPVectors() {
        let cases: [(TimeInterval, String, String, String)] = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ]
        for (t, a, b, c) in cases {
            let d = Date(timeIntervalSince1970: t)
            XCTAssertEqual(TOTP(secret: s1, digits: 8, algorithm: .sha1).code(at: d), a)
            XCTAssertEqual(TOTP(secret: s256, digits: 8, algorithm: .sha256).code(at: d), b)
            XCTAssertEqual(TOTP(secret: s512, digits: 8, algorithm: .sha512).code(at: d), c)
        }
    }

    func testBase32AndOtpauth() {
        XCTAssertEqual(Base32.encode(s1), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        XCTAssertEqual(Base32.decode("gezd gnbv gy3t qojq gezd gnbv gy3t qojq"), s1)
        let t = TOTP(string: "otpauth://totp/ACME:neil?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30&algorithm=SHA1")
        XCTAssertEqual(t?.digits, 8)
        XCTAssertEqual(t?.code(at: Date(timeIntervalSince1970: 59)), "94287082")
        XCTAssertNil(TOTP(string: "not base32 !!"))
    }
}
