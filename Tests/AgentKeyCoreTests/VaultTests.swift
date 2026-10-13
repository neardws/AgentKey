import XCTest
@testable import AgentKeyCore

final class VaultTests: XCTestCase {
    var dir: URL!
    let fast = KDFParams(algorithm: "pbkdf2-sha256", iterations: 2000, memoryKiB: nil, parallelism: nil, salt: AKRandom.bytes(16))

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("ak-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }
    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: dir) }

    func testCreateAddUnlockResolve() throws {
        let url = dir.appendingPathComponent("vault.akv")
        let (v, sk) = try Vault.create(at: url, password: "correct horse battery", kdf: fast)
        try v.upsert(.login(title: "GitHub", username: "neardws", password: "s3cr3t-pw!", url: "https://github.com"))
        try v.upsert(.apiToken(title: "OpenAI", token: "sk-test-123456"))
        try v.upsert(.secureNote(title: "Wifi", text: "hunter2hunter2"))
        try v.upsert(.totp(title: "AWS", secretOrURI: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"))

        // file is 0600 and contains no plaintext
        let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        let raw = String(decoding: try Data(contentsOf: url), as: UTF8.self)
        for needle in ["s3cr3t-pw!", "sk-test-123456", "GitHub", "neardws", "hunter2"] { XCTAssertFalse(raw.contains(needle), needle) }

        let v2 = try Vault.unlock(at: url, password: "correct horse battery", secretKey: sk)
        XCTAssertEqual(try v2.items().count, 4)
        let gh = try v2.resolve(ItemRef("ak://github/password")!)
        XCTAssertEqual(gh.field("password")?.value, "s3cr3t-pw!")
        XCTAssertEqual(try v2.resolve(ItemRef("ak://OpenAI")!).field(nil)?.value, "sk-test-123456")
        XCTAssertThrowsError(try v2.resolve(ItemRef("ak://nope")!))
        XCTAssertFalse(gh.overview.fields.isEmpty)
        let ov = String(decoding: try JSONEncoder().encode(gh.overview), as: UTF8.self)
        XCTAssertFalse(ov.contains("s3cr3t-pw!"), "overview must not include values")
    }

    func testWrongPasswordOrSecretKey() throws {
        let url = dir.appendingPathComponent("vault.akv")
        let (_, sk) = try Vault.create(at: url, password: "correct horse battery", kdf: fast)
        XCTAssertThrowsError(try Vault.unlock(at: url, password: "wrong horse battery", secretKey: sk))
        XCTAssertThrowsError(try Vault.unlock(at: url, password: "correct horse battery", secretKey: .generate()))
    }

    func testTamperedItemDetected() throws {
        let url = dir.appendingPathComponent("vault.akv")
        let (v, sk) = try Vault.create(at: url, password: "correct horse battery", kdf: fast)
        try v.upsert(.apiToken(title: "A", token: "aaaaaaaa"))
        try v.upsert(.apiToken(title: "B", token: "bbbbbbbb"))
        var f = try Vault.readFile(url)
        // swap blobs between items: AAD binds blob to item id/revision, so this must fail
        let tmp = f.items[0].blob; f.items[0].blob = f.items[1].blob; f.items[1].blob = tmp
        try Vault.encoder.encode(f).write(to: url)
        let v2 = try Vault.unlock(at: url, password: "correct horse battery", secretKey: sk)
        XCTAssertThrowsError(try v2.items())
    }

    func testRevisionBumpsOnUpdate() throws {
        let url = dir.appendingPathComponent("vault.akv")
        let (v, _) = try Vault.create(at: url, password: "correct horse battery", kdf: fast)
        var item = VaultItem.apiToken(title: "T", token: "one-one-one")
        try v.upsert(item)
        item.fields[0].value = "two-two-two"
        try v.upsert(item)
        XCTAssertEqual(v.file.items.count, 1)
        XCTAssertEqual(v.file.items[0].revision, 2)
        XCTAssertEqual(try v.items()[0].fields[0].value, "two-two-two")
    }

    func testItemRefParsing() {
        XCTAssertEqual(ItemRef("ak://My%20Bank/password"), ItemRef(item: "My Bank", field: "password"))
        XCTAssertEqual(ItemRef("OpenAI"), ItemRef(item: "OpenAI", field: nil))
        XCTAssertNil(ItemRef("ak://"))
        XCTAssertEqual(ItemRef.make(title: "My Bank", field: "password"), "ak://My%20Bank/password")
    }
}
