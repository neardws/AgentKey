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

    func testEndpointsAndBonjourFallbackToTCP() throws {
        XCTAssertEqual(SyncEndpoint.make(host: "10.0.0.2", port: 7373), "10.0.0.2:7373")
        XCTAssertEqual(SyncEndpoint.make(host: "bonjour:agentkey-abcd1234", port: 7373), "bonjour:agentkey-abcd1234")
        let id = DeviceIdentity(name: "Neil's Mac mini")
        let bn = SyncEndpoint.bonjourName(fingerprint: id.fingerprint)
        XCTAssertTrue(bn.hasPrefix("agentkey-")); XCTAssertEqual(bn.count, 17)
        XCTAssertFalse(bn.lowercased().contains("neil") || bn.contains("mini"), "no device name leaks")
        XCTAssertThrowsError(try SyncEndpoint.dial("nonsense", timeout: 1))

        // pairing payload lists the bonjour name first; on Linux it fails and we fall back to host:port
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("ak-bj-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let node = try SyncNode(dir: root.appendingPathComponent("n"), deviceName: "node")
        _ = try node.initHome(vaultID: UUID())
        let l = try TCPListener(host: "127.0.0.1", port: 0); defer { l.close() }
        let done = expectation(description: "served")
        Thread { if let t = try? l.accept() { _ = try? node.serveConnection(t) }; done.fulfill() }.start()
        let offer = try node.makeOffer(hosts: [SyncEndpoint.bonjourPrefix + SyncEndpoint.bonjourName(fingerprint: node.identity.fingerprint), "127.0.0.1"], port: l.port)
        let dev = try SyncNode(dir: root.appendingPathComponent("d"), deviceName: "dev")
        var tried: [String] = []
        _ = try dev.join(offer) { ep in tried.append(ep)
            if ep.hasPrefix(SyncEndpoint.bonjourPrefix) { throw TransportError.connectFailed("no bonjour in test") }
            return try SyncEndpoint.dial(ep, timeout: 5) }
        wait(for: [done], timeout: 10)
        XCTAssertEqual(tried.count, 2)
        XCTAssertTrue(dev.peers.endpoints.values.first?.first?.hasPrefix("bonjour:") ?? false, "bonjour endpoint remembered first")

        // discovery annotation: only a matching short fingerprint of a trusted device counts as paired
        let hub = dev.replica!.trust.devices.values.first { $0.isHomeNode == true }!
        let seen = [DiscoveredNode(name: "agentkey-x", domain: "local.", endpoint: "bonjour:agentkey-x", fingerprintPrefix: SyncEndpoint.shortFingerprint(hub.fingerprint), protocolVersion: 1, interfaces: ["en0"]),
                    DiscoveredNode(name: "agentkey-evil", domain: "local.", endpoint: "bonjour:agentkey-evil", fingerprintPrefix: "AAAAAAAA", protocolVersion: 1, interfaces: [])]
        let ann = Discovery.annotate(seen, trust: dev.replica!.trust)
        XCTAssertEqual(ann[0].pairedDeviceID, hub.deviceID); XCTAssertNil(ann[1].pairedDeviceID)
        try dev.learnDiscovered(seen)
        XCTAssertEqual(dev.peers.endpoints[hub.deviceID]?.first, "bonjour:agentkey-x")
        XCTAssertFalse(dev.peers.endpoints.values.joined().contains("bonjour:agentkey-evil"))
        if !Discovery.supported { XCTAssertTrue(Discovery.browse(timeout: 0.1).nodes.isEmpty) }
    }
}
