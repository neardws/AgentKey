import XCTest
@testable import AgentKeyCore

final class RedactorTests: XCTestCase {
    // Regression: Mac mini test printed a 3-char secret unredacted.
    func testShortSecretIsRedactedAndFlaggedWeak() {
        let r = Redactor(secrets: [(label: "ak://Test/token", value: "abc")])
        XCTAssertEqual(r.redact("abc\n"), "‹redacted:ak://Test/token›\n")
        XCTAssertEqual(r.weakSecrets, ["ak://Test/token"])
        XCTAssertNotNil(r.warning)
        let one = Redactor(secrets: [(label: "x", value: "z")])
        XCTAssertFalse(one.redact("zzz").contains("z"))
    }

    func testLongSecretNotWeak() {
        let r = Redactor(secrets: [(label: "a", value: "long-enough-secret")])
        XCTAssertTrue(r.weakSecrets.isEmpty); XCTAssertNil(r.warning)
        XCTAssertEqual(Redactor(secrets: [(label: "e", value: "")]).redact("text"), "text")
    }

    func testEncodedVariants() {
        let v = "sk-abc/123+xyz"
        let r = Redactor(secrets: [(label: "ak://OpenAI/token", value: v)])
        let b64 = Data(v.utf8).base64EncodedString()
        let out = r.redact("a \(v) b \(b64) c \(Data(v.utf8).hex) d \(v.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!)")
        XCTAssertFalse(out.contains(v)); XCTAssertFalse(out.contains(b64)); XCTAssertFalse(out.contains(Data(v.utf8).hex))
        XCTAssertTrue(out.contains("‹redacted:ak://OpenAI/token›"))
    }

    /// Every possible split of the input into two chunks, and byte-by-byte feeding,
    /// must give the same result as one-shot redaction.
    func testStreamingChunkBoundaries() {
        let secret = "s3cr3t-tok€n-✓"            // includes multi-byte UTF-8
        let r = Redactor(secrets: [(label: "T", value: secret), (label: "S", value: "ab")])
        let input = "pre \(secret) mid ab\(secret)\(secret) a b post ab"
        let expected = r.redact(input)
        XCTAssertFalse(expected.contains(secret)); XCTAssertFalse(expected.contains("ab"))
        let bytes = Array(input.utf8)
        for cut in 0...bytes.count {
            let s = r.stream()
            let out = s.feed(Array(bytes[..<cut])) + s.feed(Array(bytes[cut...])) + s.finish()
            XCTAssertEqual(String(decoding: out, as: UTF8.self), expected, "split at \(cut)")
        }
        let s = r.stream()
        var out: [UInt8] = []
        for b in bytes { out += s.feed([b]) }
        out += s.finish()
        XCTAssertEqual(String(decoding: out, as: UTF8.self), expected)
    }

    func testStreamEmitsEarlyWithoutNewline() {
        let r = Redactor(secrets: [(label: "T", value: "secret")])
        let s = r.stream()
        let out = s.feed(Array("hello world, no newline here".utf8))
        // holds back at most maxNeedleLength-1 bytes; the rest flows immediately
        XCTAssertGreaterThanOrEqual(out.count, "hello world, no newline here".utf8.count - (r.maxNeedleLength - 1))
    }
}
