import XCTest
@testable import AgentKeyCore
@testable import AgentKeyIPC

final class AgentTests: XCTestCase {
    func testPasswordGenerator() {
        var o = PasswordGenerator.Options(length: 32)
        let pws = (0..<200).map { _ in PasswordGenerator.generate(o) }
        XCTAssertEqual(Set(pws).count, 200)
        for p in pws {
            XCTAssertEqual(p.count, 32)
            XCTAssertTrue(p.contains { PasswordGenerator.lower.contains($0) })
            XCTAssertTrue(p.contains { PasswordGenerator.upper.contains($0) })
            XCTAssertTrue(p.contains { PasswordGenerator.digitSet.contains($0) })
            XCTAssertTrue(p.contains { PasswordGenerator.symbolSet.contains($0) })
            XCTAssertFalse(p.contains { "Il1O0o".contains($0) })
        }
        o.symbols = false
        XCTAssertFalse(PasswordGenerator.generate(o).contains { PasswordGenerator.symbolSet.contains($0) })
        XCTAssertEqual(PasswordGenerator.passphrase(words: 5).split(separator: "-").count, 5)
    }

    func testPolicyRevealOffByDefault() {
        let p = AgentPolicy()
        let item = VaultItem.apiToken(title: "OpenAI", token: "x")
        XCTAssertEqual(p.evaluate(agent: "claude-code", item: item, mode: .run), .needsApproval)
        if case .deny = p.evaluate(agent: "claude-code", item: item, mode: .reveal) {} else { XCTFail("reveal must be denied by default") }
        var it2 = item; it2.agentModes.append(.reveal)
        if case .deny = p.evaluate(agent: "claude-code", item: it2, mode: .reveal) {} else { XCTFail("agent rule must also allow reveal") }
        let p2 = AgentPolicy(agents: ["neil": .init(modes: [.run, .reveal], items: ["open*"])])
        XCTAssertEqual(p2.evaluate(agent: "neil", item: it2, mode: .reveal), .needsApproval)
        let other = VaultItem.apiToken(title: "Stripe", token: "x")
        if case .deny = p2.evaluate(agent: "neil", item: other, mode: .run) {} else { XCTFail("glob allow-list") }
        let note = VaultItem.secureNote(title: "n", text: "t")
        if case .deny = p.evaluate(agent: "x", item: note, mode: .run) {} else { XCTFail("notes have no agent modes by default") }
    }

    func testPromptSanitizer() {
        XCTAssertEqual(PromptSanitizer.clean("evil\u{202E}gnp.exe\nline"), "evilgnp.exe line")
        XCTAssertEqual(PromptSanitizer.clean("a\u{200B}b"), "ab")
        XCTAssertEqual(PromptSanitizer.clean(String(repeating: "x", count: 100), max: 10).count, 10)
        XCTAssertEqual(PromptSanitizer.clean("\u{0007}"), "?")
        let c = PromptSanitizer.correlationCode()
        XCTAssertEqual(c.count, 4)
    }

    func testRedactor() {
        let r = Redactor(secrets: [(label: "ak://OpenAI/token", value: "sk-abc/123+xyz")])
        let v = "sk-abc/123+xyz"
        let b64 = Data(v.utf8).base64EncodedString()
        let out = r.redact("a \(v) b \(b64) c \(Data(v.utf8).hex) d \(v.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!)")
        XCTAssertFalse(out.contains(v)); XCTAssertFalse(out.contains(b64)); XCTAssertFalse(out.contains(Data(v.utf8).hex))
        XCTAssertTrue(out.contains("‹redacted:ak://OpenAI/token›"))
    }

    func testAuditChain() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("audit-\(UUID().uuidString).jsonl")
        defer { try? FileManager.default.removeItem(at: url) }
        let key = SymmetricKey(size: .bits256)
        let log = try AuditLog(url: url, chainKey: key)
        try log.append(event: "request", agent: "claude", ref: "ak://A", mode: "run", code: "AB12")
        try log.append(event: "approved", agent: "claude", ref: "ak://A", mode: "run", code: "AB12")
        // reopening continues the chain
        let log2 = try AuditLog(url: url, chainKey: key)
        try log2.append(event: "lock", agent: "cli")
        XCTAssertEqual(try AuditLog.verify(url, chainKey: key), .ok(count: 3))
        XCTAssertEqual((try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber)?.intValue, 0o600)

        // tamper: change "approved" to "denied" in line 2
        var text = try String(contentsOf: url, encoding: .utf8)
        text = text.replacingOccurrences(of: "\"approved\"", with: "\"denied\"")
        try text.write(to: url, atomically: true, encoding: .utf8)
        if case .broken(let seq, _) = try AuditLog.verify(url, chainKey: key) { XCTAssertEqual(seq, 2) } else { XCTFail() }

        // wrong mac key detected even if hashes recomputed
        XCTAssertNotEqual(try AuditLog.verify(url, chainKey: SymmetricKey(size: .bits256)), .ok(count: 3))
    }

    func testFrameEncoding() throws {
        let d = try Frame.encode(RPCRequest(id: 7, method: "status"))
        let len = Int(d[0]) << 24 | Int(d[1]) << 16 | Int(d[2]) << 8 | Int(d[3])
        XCTAssertEqual(len, d.count - 4)
        let back = try JSONDecoder().decode(RPCRequest.self, from: d.dropFirst(4))
        XCTAssertEqual(back.method, "status"); XCTAssertEqual(back.id, 7)
    }

    func testUnixSocketRoundTripAndPermissions() throws {
        let path = "/tmp/ak-test-\(UInt32.random(in: 0...UInt32.max)).sock"
        let l = try UnixListener(path: path)
        let attrs = try FileManager.default.attributesOfItem(atPath: path)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        let t = Thread {
            guard let c = try? l.accept(), let f = try? c.readFrame(),
                  let r = try? JSONDecoder().decode(RPCRequest.self, from: f) else { return }
            try? c.send(RPCMessage(id: nil, method: "progress", params: ["code": "WXYZ"]))
            try? c.send(RPCMessage(id: r.id, result: ["echo": r.method, "uid": String(c.peer().uid)]))
        }
        t.start()
        let cl = try DaemonClient(socketPath: path)
        var progress: [String: String]?
        cl.onProgress = { progress = $0 }
        let res = try cl.call("ping")
        XCTAssertEqual(res["echo"], "ping")
        XCTAssertEqual(res["uid"], String(getuid()))
        XCTAssertEqual(progress?["code"], "WXYZ")
    }
}
