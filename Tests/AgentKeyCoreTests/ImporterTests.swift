import XCTest
@testable import AgentKeyCore

final class ImporterTests: XCTestCase {
    func fixture(_ name: String) throws -> Data {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "Fixtures/" + name, withExtension: nil)
                                ?? Bundle.module.url(forResource: name, withExtension: nil, subdirectory: "Fixtures"))
        return try Data(contentsOf: url)
    }
    func run(_ name: String, _ format: ImportFormat? = nil, map: CSVColumnMap = CSVColumnMap()) throws -> ImportResult {
        let d = try fixture(name)
        let f = try format ?? Importer.detect(data: d, filename: name)
        return try Importer.parse(data: d, format: f, columnMap: map)
    }
    func item(_ r: ImportResult, _ title: String) throws -> VaultItem { try XCTUnwrap(r.items.first { $0.title == title }, title) }
    func v(_ i: VaultItem, _ id: String) -> String? { i.fields.first { $0.id == id }?.value }

    func testCSVParser() {
        let rows = CSV.parse("a,\"b,1\",\"c \"\"q\"\"\"\r\n\"multi\nline\",,x\n")
        XCTAssertEqual(rows, [["a", "b,1", "c \"q\""], ["multi\nline", "", "x"]])
        XCTAssertEqual(CSV.parse("\u{FEFF}h1,h2\nv1,v2"), [["h1", "h2"], ["v1", "v2"]])
        XCTAssertEqual(CSV.records("A;B\n1;2").rows.first?["b"], "2")
    }

    func testOTPAuthURI() throws {
        let u = try XCTUnwrap(OTPAuthURI("otpauth://totp/ACME%20Co:john@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60"))
        XCTAssertEqual(u.issuer, "ACME Co"); XCTAssertEqual(u.account, "john@example.com")
        XCTAssertEqual(u.digits, 8); XCTAssertEqual(u.period, 60); XCTAssertEqual(u.algorithm, .sha256)
        XCTAssertEqual(OTPAuthURI(u.uriString), u, "canonical form round-trips")
        XCTAssertNil(OTPAuthURI("otpauth://totp/x?secret="))
        XCTAssertNil(OTPAuthURI("https://example.com"))
        let n = try XCTUnwrap(OTPAuthURI.normalize("jbsw y3dp ehpk 3pxp", issuer: "Site", account: "me"))
        XCTAssertEqual(OTPAuthURI(n)?.secret, Base32.decode("JBSWY3DPEHPK3PXP"))
        XCTAssertNil(OTPAuthURI.normalize("steam://ABCDE", issuer: nil, account: nil))
        XCTAssertNotNil(TOTP(string: n))
    }

    func testDetect() throws {
        let cases: [(String, ImportFormat)] = [("1password.csv", .onePasswordCSV), ("apple.csv", .applePasswordsCSV),
            ("chrome.csv", .chromeCSV), ("firefox.csv", .firefoxCSV), ("bitwarden.json", .bitwardenJSON),
            ("bitwarden.csv", .bitwardenCSV), ("generic.csv", .genericCSV), ("sample.1pux", .onePassword1PUX)]
        for (f, exp) in cases { XCTAssertEqual(try Importer.detect(data: try fixture(f), filename: f), exp, f) }
        XCTAssertEqual(try Importer.detect(data: try fixture("sample.1pux"), filename: "renamed.bin"), .onePassword1PUX)
        XCTAssertThrowsError(try Importer.detect(data: Data("{\"encrypted\":true,\"items\":[]}".utf8), filename: "x.json"))
    }

    func testOnePasswordCSV() throws {
        let r = try run("1password.csv")
        XCTAssertEqual(r.report.totalInSource, 5)
        XCTAssertEqual(r.items.count, 3)
        XCTAssertEqual(r.report.duplicatesInSource, 1)
        XCTAssertTrue(r.report.skipped.contains { $0.reason == "no title, URL or username" })
        let bank = try item(r, "Example Bank")
        XCTAssertEqual(v(bank, "password"), "Fake-Pass-222")
        XCTAssertEqual(OTPAuthURI(v(bank, "totp")!)?.issuer, "Example Bank")
        XCTAssertEqual(bank.notes, "line1\nline2")
        XCTAssertEqual(bank.tags, ["finance"])
        XCTAssertEqual(try item(r, "Example Mail").tags, ["email", "personal"])
        XCTAssertEqual(try item(r, "Server note").kind, .secureNote)
        XCTAssertEqual(r.report.withTOTP, 1)
        XCTAssertTrue(r.items.allSatisfy { $0.agentModes.isEmpty }, "imported items are not agent-accessible by default")
    }

    func testAppleCSV() throws {
        let r = try run("apple.csv")
        XCTAssertEqual(r.items.count, 2)
        let f = try item(r, "forum.example.net")
        XCTAssertEqual(f.notes, "has \"quotes\", commas")
        XCTAssertEqual(OTPAuthURI(v(f, "totp")!)?.digits, 8)
        XCTAssertEqual(f.username, "bob@example.net")
    }

    func testChromeCSVDedupesByHost() throws {
        let r = try run("chrome.csv")
        XCTAssertEqual(r.items.count, 2, "www.example.com and example.com with same creds are duplicates")
        XCTAssertEqual(r.report.duplicatesInSource, 1)
        XCTAssertEqual(try item(r, "app.example.io").notes, "remember me")
    }

    func testFirefoxCSV() throws {
        let r = try run("firefox.csv")
        XCTAssertEqual(r.items.map(\.title), ["news.example.com"])
        XCTAssertEqual(r.report.skipped.first?.reason, "Firefox internal entry")
    }

    func testBitwardenJSON() throws {
        let r = try run("bitwarden.json")
        XCTAssertEqual(r.report.totalInSource, 4)
        let g = try item(r, "Git Example")
        XCTAssertEqual(g.urls, ["https://git.example.com", "https://git2.example.com"])
        XCTAssertEqual(g.tags, ["Work"])
        XCTAssertNotNil(OTPAuthURI(v(g, "totp")!))
        XCTAssertEqual(v(g, "custom.recovery_code"), "FAKE-RC-123")
        XCTAssertEqual(try item(r, "Wifi").kind, .secureNote)
        XCTAssertTrue(r.report.skipped.contains { $0.title == "Fake Card" })
        let bad = try item(r, "Bad TOTP")
        XCTAssertNil(v(bad, "totp"))
        XCTAssertTrue(r.report.warnings.contains { $0.contains("unsupported TOTP") })
    }

    func testBitwardenCSV() throws {
        let r = try run("bitwarden.csv")
        XCTAssertEqual(Set(r.items.map(\.title)), ["VPN Example", "Door code"])
        XCTAssertEqual(try item(r, "Door code").kind, .secureNote)
        XCTAssertEqual(try item(r, "VPN Example").tags, ["Work"])
        XCTAssertEqual(r.report.skipped.count, 1)
    }

    func testGenericCSVWithMapping() throws {
        // semicolon-delimited; "Secret" isn't a known synonym → needs a mapping
        XCTAssertThrowsError(try run("generic.csv", .genericCSV))
        let map = try CSVColumnMap(spec: "password=Secret")
        let r = try run("generic.csv", .genericCSV, map: map)
        let w = try item(r, "Example Wiki")
        XCTAssertEqual(v(w, "password"), "Fake-Gen-1"); XCTAssertEqual(w.username, "gina"); XCTAssertEqual(w.tags, ["Docs"])
        XCTAssertTrue(r.report.skipped.contains { $0.reason == "URL only, no credentials" })
        XCTAssertThrowsError(try CSVColumnMap(spec: "bogus=1"))
    }

    func testOnePUX() throws {
        for name in ["sample.1pux", "stored.1pux"] {
            let r = try run(name)
            XCTAssertEqual(r.report.totalInSource, 6, name)
            let l = try item(r, "Example Login")
            XCTAssertEqual(l.username, "alice"); XCTAssertEqual(v(l, "password"), "Fake-1P-1")
            XCTAssertEqual(OTPAuthURI(v(l, "totp")!)?.issuer, "Example")
            XCTAssertEqual(v(l, "custom.pin"), "Fake-PIN-9")
            XCTAssertEqual(l.tags, ["web"])
            XCTAssertEqual(try item(r, "Secret Recipe").kind, .secureNote)
            let api = try item(r, "Example API")
            XCTAssertEqual(api.kind, .apiToken); XCTAssertEqual(v(api, "token"), "fake-api-key-123456"); XCTAssertEqual(api.username, "svc")
            XCTAssertTrue(try item(r, "Old Login").tags.contains("archived"))
            XCTAssertEqual(try item(r, "Router").tags, ["Shared"])
            XCTAssertTrue(r.report.skipped.contains { $0.title == "Weird" })
        }
    }

    func testInflateDynamicHuffmanAndCRC() throws {
        let z = try ZipArchive(try fixture("inflate-test.zip"))
        let big = try XCTUnwrap(try z.read("big.txt"))
        XCTAssertGreaterThan(big.count, 200_000)
        XCTAssertTrue(String(decoding: big, as: UTF8.self).contains("密码"))
        XCTAssertEqual(try z.read("empty.txt"), Data())
        // corrupt a byte in the middle of compressed data → CRC or deflate error, never silent garbage
        var bytes = [UInt8](try fixture("inflate-test.zip")); bytes[2000] ^= 0xff
        XCTAssertThrowsError(try ZipArchive(Data(bytes)).read("big.txt"))
    }

    func testDropExisting() throws {
        var r = try run("chrome.csv")
        let existing = [VaultItem.login(title: "whatever", username: "carol", password: "Fake-Chrome-1", url: "https://example.com")]
        Importer.dropExisting(&r, existing: existing)
        XCTAssertEqual(r.items.map(\.title), ["app.example.io"])
        XCTAssertEqual(r.report.duplicatesOfExisting, 1)
    }
}
