import XCTest
import Foundation

/// End-to-end tests that run the built `agentkey` / `agentkeyd` binaries.
final class CLITests: XCTestCase {
    var bin: URL!
    var home: URL!
    var daemon: Process?

    override func setUpWithError() throws {
        // .build/<config>/agentkey sits next to the test bundle
        #if os(macOS)
        let dir = Bundle(for: Self.self).bundleURL.deletingLastPathComponent()
        #else
        let dir = Bundle.main.bundleURL
        #endif
        bin = dir
        guard FileManager.default.isExecutableFile(atPath: dir.appendingPathComponent("agentkey").path) else {
            throw XCTSkip("agentkey binary not found in \(dir.path); run `swift build` first")
        }
        home = URL(fileURLWithPath: "/tmp/akt-\(UInt32.random(in: 0...UInt32.max))")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
    }

    override func tearDown() {
        daemon?.terminate(); daemon?.waitUntilExit()
        try? FileManager.default.removeItem(at: home)
    }

    var env: [String: String] {
        var e = ProcessInfo.processInfo.environment
        e["AGENTKEY_HOME"] = home.path
        e["AGENTKEY_PASSWORD"] = "correct horse battery staple"
        e["AGENTKEY_INSECURE_TEST_APPROVE"] = "1"   // honored only by DEBUG builds on non-Apple platforms
        e.removeValue(forKey: "AGENTKEY_OUTPUT")
        return e
    }

    @discardableResult
    func run(_ args: [String]) throws -> (code: Int32, out: String, err: String) {
        let p = Process()
        p.executableURL = bin.appendingPathComponent("agentkey")
        p.arguments = args; p.environment = env
        let o = Pipe(), e = Pipe()
        p.standardOutput = o; p.standardError = e; p.standardInput = FileHandle.nullDevice
        try p.run()
        let od = o.fileHandleForReading.readDataToEndOfFile(), ed = e.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, String(decoding: od, as: UTF8.self), String(decoding: ed, as: UTF8.self))
    }

    func json(_ s: String) throws -> [String: Any] {
        let line = s.split(separator: "\n").last.map(String.init) ?? ""
        return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any], "not JSON: \(s)")
    }

    func startDaemon() throws {
        let p = Process()
        p.executableURL = bin.appendingPathComponent("agentkeyd")
        p.environment = env
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        try p.run(); daemon = p
        let sock = home.appendingPathComponent("agent.sock").path
        for _ in 0..<100 where !FileManager.default.fileExists(atPath: sock) { usleep(50_000) }
    }

    func testErrorsAreJSONWithStableCodes() throws {
        // no daemon running → DAEMON_UNAVAILABLE, exit 69, valid JSON
        let r = try run(["status", "--json"])
        XCTAssertEqual(r.code, 69)
        let o = try json(r.out)
        XCTAssertEqual(o["ok"] as? Bool, false)
        let e = try XCTUnwrap(o["error"] as? [String: Any])
        XCTAssertEqual(e["code"] as? String, "DAEMON_UNAVAILABLE")
        XCTAssertEqual(e["exit"] as? Int, 69)
        // piped stdout (not a TTY) defaults to JSON for metadata commands
        XCTAssertNoThrow(try json(try run(["status"]).out))
        // --text forces plain text
        XCTAssertTrue(try run(["status", "--text"]).out.isEmpty)
        // usage error
        let u = try run(["add", "--json"])
        XCTAssertEqual(u.code, 64)
        XCTAssertEqual((try json(u.out)["error"] as? [String: Any])?["code"] as? String, "USAGE")
        // generate --json
        let g = try json(try run(["generate", "--json", "--length", "20"]).out)
        XCTAssertEqual((g["password"] as? String)?.count, 20)
        // generate stays raw when piped (so $(agentkey generate) works)
        XCTAssertEqual(try run(["generate", "--length", "16"]).out.trimmingCharacters(in: .newlines).count, 16)
    }

    func testFullFlowPositionalTitleJSONAndShortSecretRedaction() throws {
        XCTAssertEqual(try run(["init", "--json"]).code, 0)
        try startDaemon()
        XCTAssertEqual(try json(try run(["unlock"]).out)["locked"] as? Bool, false)

        let st = try json(try run(["status", "--json"]).out)
        XCTAssertEqual(st["ok"] as? Bool, true)
        XCTAssertEqual(st["locked"] as? Bool, false)
        XCTAssertNotNil(st["touchIDReady"] as? Bool)

        // positional title (regression: `agentkey add token Test` failed with '--title required')
        let add = try run(["add", "token", "Test", "--token", "abc", "--json"])
        XCTAssertEqual(add.code, 0, add.out + add.err)
        XCTAssertEqual(try json(add.out)["ref"] as? String, "ak://Test")
        XCTAssertTrue(add.err.contains("SHORT_SECRET"))
        XCTAssertEqual(try run(["add", "token", "--title", "Long", "--token", "a-much-longer-token-value"]).code, 0)
        XCTAssertNotEqual(try run(["add", "token", "Test", "--token", "dup"]).code, 0)

        let list = try json(try run(["list", "--json"]).out)
        XCTAssertEqual(list["count"] as? Int, 2)
        XCTAssertFalse(String(describing: list).contains("abc"))

        let denied = try run(["get", "ak://Test", "--json"])
        XCTAssertEqual(denied.code, 65)
        XCTAssertEqual((try json(denied.out)["error"] as? [String: Any])?["code"] as? String, "POLICY_DENIED")

        #if os(macOS) || os(iOS)
        throw XCTSkip("exec needs a real Touch ID / Apple Watch approval on Apple platforms")
        #else
        // Regression: 3-char secret printed in plaintext. Must be redacted on stdout AND stderr.
        let ex = try run(["exec", "--json", "--env", "TEST_TOKEN=ak://Test", "--", "sh", "-c",
                          "echo out:$TEST_TOKEN; echo err:$TEST_TOKEN 1>&2; printf %s $TEST_TOKEN"])
        XCTAssertEqual(ex.code, 0, ex.err)
        XCTAssertFalse(ex.out.contains("abc"), ex.out)
        XCTAssertTrue(ex.out.contains("out:‹redacted:ak://Test/token›"))
        XCTAssertTrue(ex.out.hasSuffix("‹redacted:ak://Test/token›"))
        XCTAssertTrue(ex.err.contains("err:‹redacted:ak://Test/token›"), ex.err)
        XCTAssertFalse(ex.err.contains("err:abc"))
        XCTAssertTrue(ex.err.contains("\"SHORT_SECRET\""))
        let meta = try json(ex.err)
        let e = try XCTUnwrap(meta["exec"] as? [String: Any])
        XCTAssertEqual(e["exitCode"] as? Int, 0)
        XCTAssertEqual(((e["released"] as? [[String: Any]])?.first)?["weak"] as? Bool, true)

        let t = try run(["exec", "--env", "X=ak://Long", "--", "sh", "-c", "exit 7"])
        XCTAssertEqual(t.code, 7)

        let audit = try json(try run(["audit", "verify", "--json"]).out)
        XCTAssertEqual((audit["audit"] as? [String: Any])?["intact"] as? Bool, true)
        #endif
    }
}
