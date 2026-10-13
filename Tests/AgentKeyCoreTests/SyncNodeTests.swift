import XCTest
@testable import AgentKeyCore

/// End-to-end: two devices with their own vault files, paired and synced over TCP loopback
/// through `SyncNode` (the code path `agentkeyd --sync-node` and `agentkey sync now` use).
final class SyncNodeTests: XCTestCase {
    let fast = KDFParams(algorithm: "pbkdf2-sha256", iterations: 1000, memoryKiB: nil, parallelism: nil, salt: AKRandom.bytes(16))

    func testHomeNodePairAndBidirectionalVaultSyncOverTCP() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("ak-node-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let (mv, _) = try Vault.create(at: root.appendingPathComponent("mini.akv"), password: "correct horse battery", kdf: fast)
        let (lv, _) = try Vault.create(at: root.appendingPathComponent("laptop.akv"), password: "correct horse battery", kdf: fast)
        try mv.upsert(.login(title: "GitHub", username: "neil", password: "fake-gh-pw"))
        try lv.upsert(.apiToken(title: "Laptop token", token: "fake-tok-1"))

        let mini = try SyncNode(dir: root.appendingPathComponent("mini-sync"), deviceName: "mac-mini")
        _ = try mini.initHome(vaultID: mv.vaultID)
        try mini.reconcile(vault: mv)
        let listener = try TCPListener(host: "127.0.0.1", port: 0); defer { listener.close() }
        let served = expectation(description: "served"); served.expectedFulfillmentCount = 4
        Thread { while true { guard let t = try? listener.accept() else { return }
            DispatchQueue.global().async { _ = try? mini.serveConnection(t, prepare: { try? mini.reconcile(vault: mv) }); try? mini.reconcile(vault: mv); served.fulfill() } } }.start()

        let offer = try mini.makeOffer(hosts: ["127.0.0.1"], port: listener.port)
        let laptop = try SyncNode(dir: root.appendingPathComponent("laptop-sync"), deviceName: "macbook")
        _ = try laptop.join(try PairingPayload(uri: offer.uri))
        // the one-time secret is consumed: a second join attempt with the same code fails
        let thief = try SyncNode(dir: root.appendingPathComponent("thief-sync"), deviceName: "thief")
        XCTAssertThrowsError(try thief.join(offer))

        try laptop.reconcile(vault: lv)
        let r1 = try laptop.syncNow(); XCTAssertNotNil(try r1.values.first?.get())
        try laptop.reconcile(vault: lv)
        XCTAssertEqual(Set(try lv.items().map(\.title)), ["GitHub", "Laptop token"])

        // edit on the node's vault flows to the laptop's vault
        var gh = try mv.items().first { $0.title == "GitHub" }!; gh.notes = "edited on mini"; try mv.upsert(gh)
        try lv.delete(id: try lv.items().first { $0.title == "Laptop token" }!.id)
        try laptop.reconcile(vault: lv); _ = try laptop.syncNow(); try laptop.reconcile(vault: lv)
        wait(for: [served], timeout: 10)
        XCTAssertEqual(try lv.items().map(\.notes), ["edited on mini"])
        XCTAssertEqual(try mv.items().map(\.title), ["GitHub"])

        let st = laptop.status()
        XCTAssertEqual(st.devices.count, 2); XCTAssertEqual(st.devices.filter(\.isHomeNode).count, 1)
        // nothing written by sync contains plaintext secrets
        for f in try FileManager.default.subpathsOfDirectory(atPath: root.path) where !f.hasSuffix(".akv") {
            let d = (try? Data(contentsOf: root.appendingPathComponent(f))) ?? Data()
            XCTAssertNil(d.range(of: Data("fake-gh-pw".utf8)), f)
        }
        // state survives restart
        let again = try SyncNode(dir: root.appendingPathComponent("laptop-sync"), deviceName: "x")
        XCTAssertEqual(again.identity.fingerprint, laptop.identity.fingerprint)
        XCTAssertEqual(again.replica?.liveItems.count, 1)
    }
}
