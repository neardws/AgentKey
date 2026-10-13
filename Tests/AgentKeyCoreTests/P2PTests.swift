import XCTest
@testable import AgentKeyCore

final class P2PTests: XCTestCase {
    func bg(_ f: @escaping () throws -> Void) -> XCTestExpectation {
        let e = expectation(description: "bg"); e.assertForOverFulfill = false
        DispatchQueue.global().async { do { try f() } catch { self.bgError = error }; e.fulfill() }
        return e
    }
    var bgError: Error?

    func handshake(_ a: DeviceIdentity, _ b: DeviceIdentity, pskA: Data? = nil, pskB: Data? = nil,
                   tap: ((Data) -> Data?)? = nil, verifyA: @escaping (Data) throws -> Void = { _ in }) throws -> (SecureChannel, SecureChannel?) {
        let (ta, tb) = MemoryTransport.pair(); ta.tap = tap
        var server: SecureChannel?
        let e = bg { server = try SecureChannel.handshake(tb, initiator: false, identity: b, prologue: Data("p".utf8), psk: pskB, timeout: 2) { _ in } }
        do {
            let c = try SecureChannel.handshake(ta, initiator: true, identity: a, prologue: Data("p".utf8), psk: pskA, timeout: 2, verify: verifyA)
            wait(for: [e], timeout: 5); return (c, server)
        } catch { ta.close(); wait(for: [e], timeout: 5); throw error }
    }

    func testHandshakeSuccessAndTransport() throws {
        let a = DeviceIdentity(name: "a"), b = DeviceIdentity(name: "b")
        let (c, s) = try handshake(a, b)
        XCTAssertEqual(c.remoteStatic, b.publicKey); XCTAssertEqual(s?.remoteStatic, a.publicKey)
        XCTAssertEqual(c.handshakeHash, s?.handshakeHash)
        try c.send(Data("hello".utf8)); XCTAssertEqual(try s!.receive(), Data("hello".utf8))
        try s!.send(Data("back".utf8)); XCTAssertEqual(try c.receive(), Data("back".utf8))
    }

    func testPSKMismatchFails() {
        let a = DeviceIdentity(name: "a"), b = DeviceIdentity(name: "b")
        XCTAssertThrowsError(try handshake(a, b, pskA: Data(repeating: 1, count: 32), pskB: Data(repeating: 2, count: 32)))
    }

    func testWrongFingerprintRejected() {
        let a = DeviceIdentity(name: "a"), b = DeviceIdentity(name: "b"), other = DeviceIdentity(name: "x")
        XCTAssertThrowsError(try handshake(a, b) { pub in
            if DeviceIdentity.fingerprint(pub) != other.fingerprint { throw PairingError.fingerprintMismatch(expected: other.fingerprint, got: DeviceIdentity.fingerprint(pub)) }
        }) { XCTAssertTrue($0 is PairingError) }
    }

    func testMITMTamperRejected() {
        let a = DeviceIdentity(name: "a"), b = DeviceIdentity(name: "b")
        // flip a bit in message 1 (initiator ephemeral) — both sides must fail
        var n = 0
        XCTAssertThrowsError(try handshake(a, b) { d in n += 1; var m = d; if n == 1 { m[m.count - 1] ^= 1 }; return m })
    }

    func testMITMRelayWithOwnKeyRejectedByPairingPin() throws {
        // attacker answers the pairing connection with its own key: fingerprint pin fails before msg3
        let node = PeerReplica(identity: DeviceIdentity(name: "node"), vaultID: UUID(), isHomeNode: true)
        let attacker = PeerReplica(identity: DeviceIdentity(name: "evil"), vaultID: node.vaultID, isHomeNode: true)
        let payload = PairingPayload(vaultID: node.vaultID, nodeName: "node", hosts: ["127.0.0.1"], port: 1, fingerprint: node.identity.fingerprint)
        let (ta, tb) = MemoryTransport.pair()
        let e = bg { _ = try SyncSession.servePairing(attacker, payload: payload, over: tb) }
        XCTAssertThrowsError(try SyncSession.pair(identity: DeviceIdentity(name: "phone"), payload: payload, over: ta)) {
            guard case PairingError.fingerprintMismatch = $0 else { return XCTFail("\($0)") }
        }
        wait(for: [e], timeout: 5)
        XCTAssertEqual(attacker.trust.devices.count, 1, "attacker learned nothing / added nothing")
    }

    func testReplayRejected() throws {
        let a = DeviceIdentity(name: "a"), b = DeviceIdentity(name: "b")
        var captured: [Data] = []
        let (ta, tb) = MemoryTransport.pair()
        ta.tap = { captured.append($0); return $0 }
        var s: SecureChannel!
        let e = bg { s = try SecureChannel.handshake(tb, initiator: false, identity: b, prologue: Data(), timeout: 2) { _ in } }
        let c = try SecureChannel.handshake(ta, initiator: true, identity: a, prologue: Data(), timeout: 2) { _ in }
        wait(for: [e], timeout: 5)
        try c.send(Data("pay 1".utf8)); XCTAssertEqual(try s.receive(), Data("pay 1".utf8))
        ta.inject(captured.last!)    // replay the exact ciphertext
        XCTAssertThrowsError(try s.receive()) { XCTAssertEqual($0 as? NoiseError, .decryptFailed) }
    }

    func testPairingPayloadRoundTripAndExpiry() throws {
        let p = PairingPayload(vaultID: UUID(), nodeName: "mini", hosts: ["192.168.1.2", "mini.tail.ts.net"], port: 7373, fingerprint: "ABCD")
        let q = try PairingPayload(uri: p.uri)
        XCTAssertEqual(q.secret, p.secret); XCTAssertEqual(q.hosts, p.hosts); XCTAssertEqual(q.expires, p.expires)
        XCTAssertThrowsError(try PairingPayload(uri: "agentkey-pair:!!"))
        let old = PairingPayload(vaultID: UUID(), nodeName: "m", hosts: [], port: 1, fingerprint: "x", ttl: -1)
        XCTAssertThrowsError(try SyncSession.pair(identity: DeviceIdentity(name: "p"), payload: old, over: MemoryTransport.pair().0)) {
            XCTAssertEqual($0 as? PairingError, .expired)
        }
    }

    /// Pair a new device with `node` over the in-memory transport.
    func pair(_ node: PeerReplica, name: String) throws -> PeerReplica {
        let payload = PairingPayload(vaultID: node.vaultID, nodeName: "node", hosts: [], port: 0, fingerprint: node.identity.fingerprint)
        let (ta, tb) = MemoryTransport.pair()
        let e = bg { _ = try SyncSession.servePairing(node, payload: payload, over: tb) }
        let r = try SyncSession.pair(identity: DeviceIdentity(name: name), payload: payload, over: ta)
        wait(for: [e], timeout: 5); XCTAssertNil(bgError)
        return r
    }

    @discardableResult
    func sync(_ client: PeerReplica, _ hub: PeerReplica) throws -> SyncStats {
        let (ta, tb) = MemoryTransport.pair()
        let e = bg { try SyncSession.serve(hub, over: tb) }
        defer { wait(for: [e], timeout: 10) }
        return try SyncSession.runClient(client, over: ta)
    }

    func sortedItems(_ r: PeerReplica) -> [VaultItem] { r.liveItems.sorted { ($0.title, $0.id.uuidString) < ($1.title, $1.id.uuidString) } }

    func testPairingHandsOverKeysAndThreeDeviceConvergence() throws {
        let node = PeerReplica(identity: DeviceIdentity(name: "mac-mini"), vaultID: UUID(), isHomeNode: true)
        let gh = VaultItem.login(title: "GitHub", username: "neil", password: "fake-pw-1")
        node.write(gh)
        let phone = try pair(node, name: "iphone"), laptop = try pair(node, name: "macbook")
        XCTAssertEqual(phone.trust.devices.count, 2)
        try sync(phone, node); try sync(laptop, node); try sync(phone, node)
        XCTAssertEqual(phone.trust.devices.count, 3)
        XCTAssertEqual(phone.item(gh.id)?.title, "GitHub")

        // concurrent edits to different fields of the same item + independent adds + a delete
        var p = phone.item(gh.id)!; p.username = "neil@phone"; phone.write(p)
        var l = laptop.item(gh.id)!; l.notes = "from laptop"; laptop.write(l)
        phone.write(.apiToken(title: "OpenAI", token: "sk-fake-123"))
        let tmp = VaultItem.secureNote(title: "tmp", text: "x"); laptop.write(tmp)
        try sync(laptop, node); try sync(phone, node)
        laptop.delete(tmp.id); node.write(.secureNote(title: "node-note", text: "fake"))
        for _ in 0..<2 { try sync(phone, node); try sync(laptop, node) }

        let a = sortedItems(node), b = sortedItems(phone), c = sortedItems(laptop)
        XCTAssertEqual(a.map(\.title), ["GitHub", "OpenAI", "node-note"])
        XCTAssertEqual(a, b); XCTAssertEqual(b, c)
        XCTAssertEqual(a[0].username, "neil@phone"); XCTAssertEqual(a[0].notes, "from laptop")

        // idempotent: another round moves nothing
        let st = try sync(phone, node)
        XCTAssertEqual(st.received, 0); XCTAssertEqual(st.sent, 0)
    }

    func testConflictSameFieldResolvesDeterministically() throws {
        let node = PeerReplica(identity: DeviceIdentity(name: "node"), vaultID: UUID(), isHomeNode: true)
        let x = try pair(node, name: "x"), y = try pair(node, name: "y")
        let it = VaultItem.login(title: "Bank", username: "u", password: "fake-a"); x.write(it)
        try sync(x, node); try sync(y, node)
        var i1 = x.item(it.id)!; i1.fields[0].value = "fake-x"; x.write(i1)
        var i2 = y.item(it.id)!; i2.fields[0].value = "fake-y"; y.write(i2)
        try sync(x, node); try sync(y, node); try sync(x, node)
        XCTAssertEqual(x.item(it.id), y.item(it.id))
        XCTAssertEqual(node.item(it.id), x.item(it.id))
        XCTAssertFalse((node.item(it.id)!.history ?? []).isEmpty, "losing value kept in history")
    }

    func testTCPLoopbackSync() throws {
        let node = PeerReplica(identity: DeviceIdentity(name: "node"), vaultID: UUID(), isHomeNode: true)
        let listener = try TCPListener(host: "127.0.0.1", port: 0)
        defer { listener.close() }
        let payload = PairingPayload(vaultID: node.vaultID, nodeName: "node", hosts: ["127.0.0.1"], port: listener.port, fingerprint: node.identity.fingerprint)
        let e1 = bg { _ = try SyncSession.servePairing(node, payload: payload, over: try listener.accept()) }
        let phone = try SyncSession.pair(identity: DeviceIdentity(name: "phone"), payload: payload,
                                         over: try TCPTransport.connect(host: "127.0.0.1", port: listener.port))
        wait(for: [e1], timeout: 5); XCTAssertNil(bgError)
        for i in 0..<30 { node.write(.secureNote(title: "n\(i)", text: String(repeating: "z", count: 2000))) }
        phone.write(.apiToken(title: "phone-token", token: "fake"))
        let e2 = bg { try SyncSession.serve(node, over: try listener.accept(), pageSize: 7) }
        let st = try SyncSession.runClient(phone, over: try TCPTransport.connect(host: "127.0.0.1", port: listener.port),
                                           pinnedFingerprint: node.identity.fingerprint)
        wait(for: [e2], timeout: 10); XCTAssertNil(bgError)
        XCTAssertEqual(st.received, 30); XCTAssertEqual(st.sent, 1)
        XCTAssertEqual(sortedItems(node), sortedItems(phone))
    }

    func testRevocation() throws {
        let node = PeerReplica(identity: DeviceIdentity(name: "node"), vaultID: UUID(), isHomeNode: true)
        let phone = try pair(node, name: "phone"), lost = try pair(node, name: "lost-laptop")
        node.write(.login(title: "Mail", username: "n", password: "fake-old")); try sync(phone, node); try sync(lost, node)
        let oldKV = node.currentKeyVersion
        try node.revoke(lost.device.raw)
        XCTAssertNotEqual(node.currentKeyVersion, oldKV)
        node.write(.login(title: "New", username: "n", password: "fake-new"))

        // revoked device: hub refuses at the handshake
        XCTAssertThrowsError(try sync(lost, node))
        // even if it got a record, it can't decrypt under the rotated key
        let rec = try node.delta(since: 0, limit: 100).records.first { $0.meta.keyVersion == node.currentKeyVersion }!
        XCTAssertThrowsError(try lost.receive(rec, from: node.device.raw))

        // remaining device learns the revocation + new key, and refuses the revoked peer too
        try sync(phone, node)
        XCTAssertNotNil(phone.trust.devices[lost.device.raw]?.revokedAt)
        XCTAssertEqual(phone.currentKeyVersion, node.currentKeyVersion)
        XCTAssertEqual(sortedItems(phone).map(\.title), ["Mail", "New"])
        let (ta, tb) = MemoryTransport.pair()
        let e = bg { try SyncSession.serve(phone, over: tb) }
        XCTAssertThrowsError(try SyncSession.runClient(lost, over: ta)); wait(for: [e], timeout: 5)
        // revocation is sticky: merging an old trust state can't un-revoke
        var stale = lost.trust; stale.devices[lost.device.raw]?.revokedAt = nil
        node.mergeTrust(stale)
        XCTAssertNotNil(node.trust.devices[lost.device.raw]?.revokedAt)
    }

    func testReplicaPersistenceRoundTrip() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let node = PeerReplica(identity: DeviceIdentity(name: "n"), vaultID: UUID(), isHomeNode: true)
        node.write(.login(title: "A", username: "u", password: "fake-secret-zz9"))
        let url = dir.appendingPathComponent("replica.sealed"); try node.save(to: url)
        let raw = try Data(contentsOf: url)
        XCTAssertNil(raw.range(of: Data("fake-secret-zz9".utf8)), "no plaintext at rest")
        let back = try PeerReplica.load(from: url, identity: node.identity)
        XCTAssertEqual(sortedItems(back), sortedItems(node))
        XCTAssertThrowsError(try PeerReplica.load(from: url, identity: DeviceIdentity(name: "other")))
    }

    func testBackupRoundTripAndWrongPassphrase() throws {
        let items: [VaultItem] = [.login(title: "A", username: "u", password: "fake-backup-pw"), .apiToken(title: "T", token: "fake-tok")]
        let fast = KDFParams(algorithm: "pbkdf2-sha256", iterations: 1000, memoryKiB: nil, parallelism: nil, salt: AKRandom.bytes(16))
        let blob = try BackupFile.create(items: items, passphrase: "correct horse battery", createdBy: "test", kdf: fast)
        XCTAssertNil(blob.range(of: Data("fake-backup-pw".utf8)))
        let r = try BackupFile.restore(blob, passphrase: "correct horse battery")
        XCTAssertEqual(r.items, items)
        XCTAssertThrowsError(try BackupFile.restore(blob, passphrase: "wrong horse battery")) { XCTAssertEqual($0 as? BackupError, .wrongPassphraseOrTampered) }
        XCTAssertThrowsError(try BackupFile.create(items: items, passphrase: "short", createdBy: "t")) { XCTAssertEqual($0 as? BackupError, .weakPassphrase) }
        // header tamper (AAD) is detected
        var obj = try JSONSerialization.jsonObject(with: blob) as! [String: Any]; obj["createdBy"] = "evil"
        XCTAssertThrowsError(try BackupFile.restore(try JSONSerialization.data(withJSONObject: obj), passphrase: "correct horse battery"))
        XCTAssertThrowsError(try BackupFile.restore(Data("{}".utf8), passphrase: "x")) { XCTAssertEqual($0 as? BackupError, .notABackup) }
    }
}
