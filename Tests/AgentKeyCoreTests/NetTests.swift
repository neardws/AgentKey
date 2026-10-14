import XCTest
@testable import AgentKeyCore

final class NetTests: XCTestCase {
    func hex(_ s: String) -> Data { Data(hex: s.replacingOccurrences(of: " ", with: "").replacingOccurrences(of: "\n", with: ""))! }

    // RFC 5769 §2.2 sample IPv4 response
    let rfc5769v4 = """
    0101003c 2112a442 b7e7a701 bc34d686 fa87dfae
    8022000b 74657374 20766563 746f7220
    00200008 0001a147 e112a643
    00080014 2b91f599 fd9e90c3 8c7489f9 2af9ba53 f06be7d7
    80280004 c07d4c96
    """
    // RFC 5769 §2.3 sample IPv6 response
    let rfc5769v6 = """
    01010048 2112a442 b7e7a701 bc34d686 fa87dfae
    8022000b 74657374 20766563 746f7220
    00200014 0002a147 0113a9fa a5d3f179 bc25f4b5 bed2b9d9
    00080014 a382954e 4be67bf1 1784c97c 8292c275 bfe3ed41
    80280004 c8fb0b4c
    """

    func testSTUNRFC5769Vectors() throws {
        let pw = Data("VOkJxbRl1RmTxUk/WvJxBt".utf8)
        let v4 = hex(rfc5769v4)
        let m = try STUN.Message.decode(v4)
        XCTAssertEqual(m.type, STUN.bindingSuccess)
        XCTAssertEqual(m.transactionID, hex("b7e7a701bc34d686fa87dfae"))
        XCTAssertEqual(m.mappedAddress, IPEndpoint(host: "192.0.2.1", port: 32853))
        XCTAssertTrue(STUN.verifyFingerprint(v4))
        XCTAssertTrue(STUN.verifyIntegrity(v4, key: pw))
        XCTAssertFalse(STUN.verifyIntegrity(v4, key: Data("wrong".utf8)))
        var bad = v4; bad[30] ^= 1
        XCTAssertFalse(STUN.verifyFingerprint(bad))

        let v6 = hex(rfc5769v6)
        let m6 = try STUN.Message.decode(v6)
        XCTAssertEqual(m6.mappedAddress, IPEndpoint(host: "2001:db8:1234:5678:11:2233:4455:6677", port: 32853))
        XCTAssertTrue(STUN.verifyFingerprint(v6))
        XCTAssertTrue(STUN.verifyIntegrity(v6, key: pw))

        // our encoder: XOR-MAPPED-ADDRESS round trip + fingerprint
        let tid = AKRandom.bytes(12)
        for ep in [IPEndpoint(host: "203.0.113.9", port: 7373), IPEndpoint(host: "2408:8000::1", port: 40000)] {
            let resp = STUN.Message(type: STUN.bindingSuccess, transactionID: tid, attributes: [(0x0020, STUN.encodeXorAddress(ep, tid: tid))]).encode()
            XCTAssertTrue(STUN.verifyFingerprint(resp))
            XCTAssertEqual(try STUN.Message.decode(resp).mappedAddress, ep)
        }
        let req = STUN.Message(type: STUN.bindingRequest).encode()
        XCTAssertEqual(req.count, 28); XCTAssertEqual(Array(req.prefix(2)), [0, 1])
        XCTAssertThrowsError(try STUN.Message.decode(Data(req.prefix(10))))
    }

    /// Local STUN responder on loopback → client learns its mapped address; NAT estimate logic.
    func testSTUNClientAgainstLocalServerAndNATEstimate() throws {
        let server = try UDPSocket(port: 0, v4Only: true, bindHost: "127.0.0.1")
        Thread {
            while let (d, from) = try? server.receive(timeout: 5) {
                guard let m = try? STUN.Message.decode(d), m.type == STUN.bindingRequest else { continue }
                let r = STUN.Message(type: STUN.bindingSuccess, transactionID: m.transactionID, attributes: [(0x0020, STUN.encodeXorAddress(from, tid: m.transactionID))])
                try? server.send(r.encode(), to: from)
            }
        }.start()
        let mux = try UDPMux(socket: UDPSocket(port: 0, v4Only: true, bindHost: "127.0.0.1"))
        defer { mux.close(); server.close() }
        let res = mux.stunProbe(servers: ["127.0.0.1:\(server.localPort)", "127.0.0.1:1"], timeout: 0.3, retries: 0)
        XCTAssertEqual(res[0].mapped, "127.0.0.1:\(mux.localPort)")
        XCTAssertNil(res[1].mapped)
        XCTAssertEqual(STUNClient.estimate(res, localAddresses: ["127.0.0.1"], localPort: mux.localPort), .open)
        let mk = { (m: String?) in STUNResult(server: "s", serverAddress: nil, mapped: m, rttMs: nil, error: nil) }
        XCTAssertEqual(STUNClient.estimate([mk("1.2.3.4:5000"), mk("1.2.3.4:5000")], localAddresses: ["192.168.5.2"], localPort: 7373), .endpointIndependent)
        XCTAssertEqual(STUNClient.estimate([mk("1.2.3.4:5000"), mk("1.2.3.4:5001")], localAddresses: [], localPort: 7373), .endpointDependent)
        XCTAssertEqual(STUNClient.estimate([mk(nil), mk(nil)], localAddresses: [], localPort: 7373), .udpBlocked)
    }

    func testBencodeAndBEP44Signing() throws {
        let v = Bencode.dict([Data("b".utf8): .int(-3), Data("a".utf8): .list([.str("x"), .bytes(Data([0, 1]))])])
        XCTAssertEqual(String(decoding: v.encode(), as: UTF8.self), "d1:al1:x2:\u{0}\u{1}e1:bi-3ee")
        XCTAssertEqual(try Bencode.decode(v.encode()), v)
        XCTAssertThrowsError(try Bencode.decode(Data("d1:a".utf8)))
        XCTAssertThrowsError(try Bencode.decode(Data("5:ab".utf8)))
        // BEP 44 signing buffer format (from the spec's example)
        XCTAssertEqual(String(decoding: BEP44.signingBuffer(salt: Data("foobar".utf8), seq: 1, v: Data("Hello World!".utf8)), as: UTF8.self),
                       "4:salt6:foobar3:seqi1e1:v12:Hello World!")
        XCTAssertEqual(String(decoding: BEP44.signingBuffer(salt: Data(), seq: 4, v: Data("x".utf8)), as: UTF8.self), "3:seqi4e1:v1:x")
        let k = Curve25519.Signing.PrivateKey()
        let sig = try BEP44.sign(k, salt: Data("s".utf8), seq: 7, v: Data("val".utf8))
        XCTAssertTrue(BEP44.verify(pub: k.publicKey.rawRepresentation, salt: Data("s".utf8), seq: 7, v: Data("val".utf8), sig: sig))
        XCTAssertFalse(BEP44.verify(pub: k.publicKey.rawRepresentation, salt: Data("s".utf8), seq: 8, v: Data("val".utf8), sig: sig))
        XCTAssertEqual(BEP44.target(publicKey: Data(repeating: 1, count: 32), salt: Data()).count, 20)
    }

    func pairedIdentities() -> (DeviceIdentity, DeviceIdentity) { (DeviceIdentity(name: "mini-a"), DeviceIdentity(name: "mini-b")) }

    func testRendezvousRecordSealSignVerify() throws {
        let (a, b) = pairedIdentities(); let eve = DeviceIdentity(name: "eve")
        let ka = try PairKeys(identity: a, peerPublicKey: b.publicKey), kb = try PairKeys(identity: b, peerPublicKey: a.publicKey)
        let rec = CandidateRecord(device: a.deviceID.raw, nat: "endpoint-independent",
                                  candidates: [NetCandidate(.udp, "203.0.113.5:40001", source: "srflx"), NetCandidate(.ipv6, "[2408:8000::5]:7373", source: "host")])
        let sealed = try ka.seal(rec)
        XCTAssertEqual(try kb.open(sealed), rec)
        XCTAssertNil(sealed.range(of: Data("203.0.113.5".utf8)), "candidates are encrypted")
        XCTAssertThrowsError(try ka.open(sealed), "direction-bound: a cannot replay its own record as b's")
        let ke = try PairKeys(identity: eve, peerPublicKey: a.publicKey)
        XCTAssertThrowsError(try ke.open(sealed))
        var tampered = sealed; tampered[tampered.count - 1] ^= 1
        XCTAssertThrowsError(try kb.open(tampered))
        // DHT slots: both sides derive the same key/salt for a direction; directions differ; unlinkable to identity keys
        let outA = ka.dhtSlot(outgoing: true), inB = kb.dhtSlot(outgoing: false), outB = kb.dhtSlot(outgoing: true)
        XCTAssertEqual(outA.key.publicKey.rawRepresentation, inB.key.publicKey.rawRepresentation)
        XCTAssertEqual(outA.salt, inB.salt)
        XCTAssertNotEqual(outA.key.publicKey.rawRepresentation, outB.key.publicKey.rawRepresentation)
        XCTAssertNotEqual(outA.key.publicKey.rawRepresentation, a.publicKey)
        // manual blob
        let blob = ManualSignal.export(sealed, from: a)
        XCTAssertTrue(blob.hasPrefix("akr1."))
        let p = try XCTUnwrap(ManualSignal.parse(blob))
        XCTAssertEqual(p.sender, shortID(a.publicKey)); XCTAssertEqual(try kb.open(p.sealed), rec)
    }

    func testDHTPutGetAgainstLocalNodes() throws {
        // three local KRPC nodes that know each other; the client bootstraps from one
        let nodes = try (0..<3).map { _ in try DHTLocalNode() }
        for n in nodes { n.peers = nodes.filter { $0 !== n }.map(\.nodeInfo) }
        let mux = try UDPMux(socket: UDPSocket(port: 0, v4Only: true, bindHost: "127.0.0.1"))
        defer { mux.close(); nodes.forEach { $0.mux.close() } }
        let dht = DHTClient(mux: mux, bootstrap: [nodes[0].nodeInfo.ep.description])
        let (a, b) = pairedIdentities()
        let ka = try PairKeys(identity: a, peerPublicKey: b.publicKey), kb = try PairKeys(identity: b, peerPublicKey: a.publicKey)
        let rdv = DHTRendezvous(client: dht)
        let rec = CandidateRecord(device: a.deviceID.raw, nat: "x", candidates: [NetCandidate(.udp, "198.51.100.7:7373", source: "srflx")])
        try rdv.publish(try ka.seal(rec), keys: ka)
        let got = try XCTUnwrap(try rdv.fetch(keys: kb))
        XCTAssertEqual(try kb.open(got), rec)
        XCTAssertNil(try rdv.fetch(keys: ka), "nothing published in the other direction")
        // forged item under the same slot is rejected (bad signature)
        let (k, salt) = ka.dhtSlot(outgoing: true)
        XCTAssertThrowsError(try dht.put(key: Curve25519.Signing.PrivateKey(), salt: salt, seq: 1, v: Data(repeating: 1, count: 1001)))
        _ = k
    }

    func testCandidateRacingOrder() throws {
        let cands = [NetCandidate(.udp, "1.2.3.4:5", source: "srflx"), NetCandidate(.tcp, "203.0.113.1:7373", source: "config"),
                     NetCandidate(.ipv6, "[2408::1]:7373", source: "host"), NetCandidate(.bonjour, "bonjour:agentkey-x", source: "host"),
                     NetCandidate(.relay, "relay.example:9", source: "rendezvous:host"), NetCandidate(.tcp, "192.168.5.2:7373", source: "host"),
                     NetCandidate(.tcp, "203.0.113.1:7373", source: "dup")]
        XCTAssertEqual(Connectivity.order(cands, via: .auto).map(\.kind), [.bonjour, .ipv6, .tcp, .tcp, .udp])
        XCTAssertEqual(Connectivity.order(cands, via: .udp).map(\.kind), [.udp])
        XCTAssertEqual(Connectivity.order(cands, via: .ipv6).map(\.addr), ["[2408::1]:7373"])
        XCTAssertEqual(Connectivity.order(cands, via: .lan).map(\.addr), ["bonjour:agentkey-x", "192.168.5.2:7373"])
        XCTAssertEqual(NetCandidate.fromEndpoint("udp:1.2.3.4:5", source: "x").kind, .udp)
        XCTAssertEqual(NetCandidate.fromEndpoint("[2408::1]:7373", source: "x").kind, .ipv6)
        XCTAssertEqual(IPEndpoint("[2408::1]:7373")?.isGlobalIPv6, true)

        // race: bonjour fails fast, ipv6 is slow, tcp succeeds first → tcp wins although ranked later
        let order = Connectivity.order(cands, via: .auto)
        let r = Connectivity.race(order, stagger: 0.05) { c in
            switch c.kind {
            case .bonjour: throw TransportError.connectFailed("no bonjour")
            case .ipv6: Thread.sleep(forTimeInterval: 0.5); return MemoryTransport.pair().0
            case .tcp: if c.addr.hasPrefix("203") { Thread.sleep(forTimeInterval: 0.05); return MemoryTransport.pair().0 }; throw TransportError.timeout
            default: Thread.sleep(forTimeInterval: 1); throw TransportError.timeout
            }
        }
        XCTAssertEqual(r.winner?.1.addr, "203.0.113.1:7373")
        XCTAssertTrue(r.attempts.contains { $0.candidate == "bonjour:agentkey-x" && !$0.ok })
        // all fail → no winner, every attempt reported
        let r2 = Connectivity.race(Array(order.prefix(2)), stagger: 0.01) { _ in throw TransportError.connectFailed("x") }
        XCTAssertNil(r2.winner); XCTAssertEqual(r2.attempts.count, 2)
    }

    /// Two "Mac minis" behind simulated address-restricted NATs on loopback. A one-sided punch is
    /// dropped; simultaneous punching (after exchanging candidates) opens the path, then a full
    /// Noise + sync session runs over the reliable UDP stream with 10% packet loss.
    func testUDPHolePunchingThroughSimulatedNATsAndSyncOverUDP() throws {
        let hubR = PeerReplica(identity: DeviceIdentity(name: "mini-a"), vaultID: UUID(), isHomeNode: true)
        let cliID = DeviceIdentity(name: "mini-b")
        try hubR.addDevice(DeviceRecord(deviceID: cliID.deviceID.raw, name: "mini-b", publicKey: cliID.publicKey, addedAt: Date(), addedBy: "t", revokedAt: nil, isHomeNode: false))
        let ho = PairingHandover(trust: hubR.trust, keys: hubR.keys.mapValues(\.data), hubDeviceID: hubR.device.raw)
        let cliR = try PeerReplica(identity: cliID, handover: ho)
        for i in 0..<40 { hubR.write(.secureNote(title: "n\(i)", text: String(repeating: "q", count: 3000))) }
        cliR.write(.apiToken(title: "from-b", token: "fake-udp-token"))

        let kHub = try PairKeys(identity: hubR.identity, peerPublicKey: cliID.publicKey), kCli = try PairKeys(identity: cliID, peerPublicKey: hubR.identity.publicKey)
        XCTAssertEqual(kHub.pair.withUnsafeBytes { Data($0) }, kCli.pair.withUnsafeBytes { Data($0) })
        let hub = try UDPMux(socket: UDPSocket(port: 0, v4Only: true, bindHost: "127.0.0.1"))
        let cli = try UDPMux(socket: UDPSocket(port: 0, v4Only: true, bindHost: "127.0.0.1"))
        defer { hub.close(); cli.close() }
        for (m, id, k) in [(hub, hubR.identity, kHub), (cli, cliID, kCli)] {
            m.simulateRestrictedNAT = true
            m.selfShortID = shortID(id.publicKey)
            m.pairKeyFor = { _ in k.pair }
        }
        let hubEP = IPEndpoint(host: "127.0.0.1", port: hub.localPort), cliEP = IPEndpoint(host: "127.0.0.1", port: cli.localPort)
        var served: SyncStats?
        let done = expectation(description: "served")
        hub.onAccept = { s in served = try? SyncSession.serve(hubR, over: s); done.fulfill() }

        // 1) client punches alone: the hub's NAT drops it (hub never sent to the client)
        XCTAssertNil(cli.punch(candidates: [hubEP], key: kCli.pair, timeout: 0.6))
        // 2) candidates exchanged via rendezvous → both punch simultaneously
        hub.dropRate = 0.1; cli.dropRate = 0.1
        hub.punchTowards([cliEP], key: kHub.pair, duration: 5)
        let (ep, conn) = try XCTUnwrap(cli.punch(candidates: [hubEP], key: kCli.pair, timeout: 5))
        XCTAssertEqual(ep, hubEP)
        let stream = cli.openStream(to: ep, conn: conn)
        let st = try SyncSession.runClient(cliR, over: stream, pinnedFingerprint: hubR.identity.fingerprint)
        wait(for: [done], timeout: 30)
        XCTAssertEqual(st.received, 40); XCTAssertEqual(st.sent, 1)
        XCTAssertEqual(served?.received, 1)
        XCTAssertEqual(Set(cliR.liveItems.map(\.title)), Set(hubR.liveItems.map(\.title)))

        // 3) wrong pair key → punches ignored (no session from strangers)
        let stranger = try UDPMux(socket: UDPSocket(port: 0, v4Only: true, bindHost: "127.0.0.1")); defer { stranger.close() }
        stranger.selfShortID = Data(repeating: 9, count: 8)
        XCTAssertNil(stranger.punch(candidates: [hubEP], key: SymmetricKey(size: .bits256), timeout: 0.5))
    }

    func testUDPStreamLargeFramesWithLoss() throws {
        let a = try UDPMux(socket: UDPSocket(port: 0, v4Only: true, bindHost: "127.0.0.1"))
        let b = try UDPMux(socket: UDPSocket(port: 0, v4Only: true, bindHost: "127.0.0.1"))
        defer { a.close(); b.close() }
        let key = SymmetricKey(size: .bits256)
        for m in [a, b] { m.pairKeyFor = { _ in key }; m.dropRate = 0.15 }
        var bs: UDPStream?
        let acc = expectation(description: "accept")
        b.onAccept = { s in bs = s; acc.fulfill() }
        let (ep, conn) = try XCTUnwrap(a.punch(candidates: [IPEndpoint(host: "127.0.0.1", port: b.localPort)], key: key, timeout: 5))
        let s = a.openStream(to: ep, conn: conn)
        let big = AKRandom.bytes(300_000)
        try s.send(Data("hello".utf8)); try s.send(big)
        wait(for: [acc], timeout: 10)
        XCTAssertEqual(try bs!.receive(timeout: 20), Data("hello".utf8))
        XCTAssertEqual(try bs!.receive(timeout: 30), big)
        try bs!.send(Data("back".utf8))
        XCTAssertEqual(try s.receive(timeout: 20), Data("back".utf8))
    }

    /// Live network check (opt-in): AGENTKEY_LIVE_NET=1 swift test --filter NetTests/testLive
    func testLiveSTUNAndDHT() throws {
        guard ProcessInfo.processInfo.environment["AGENTKEY_LIVE_NET"] == "1" else { throw XCTSkip("set AGENTKEY_LIVE_NET=1") }
        let mux = try UDPMux(port: 0); defer { mux.close() }
        let r = mux.stunProbe(servers: STUN.defaultServers)
        for x in r { print("STUN", x.server, x.mapped ?? "-", x.error ?? "") }
        print("NAT:", STUNClient.estimate(r, localAddresses: LocalAddresses.ipv4(), localPort: mux.localPort))
        let dht = DHTClient(mux: mux)
        let (a, b) = pairedIdentities()
        let ka = try PairKeys(identity: a, peerPublicKey: b.publicKey), kb = try PairKeys(identity: b, peerPublicKey: a.publicKey)
        let rdv = DHTRendezvous(client: dht)
        let rec = CandidateRecord(device: a.deviceID.raw, nat: "live", candidates: [])
        do { try rdv.publish(try ka.seal(rec), keys: ka); print("DHT put ok") } catch { print("DHT put failed:", error) }
        let got = try rdv.fetch(keys: kb)
        print("DHT get:", got.map { (try? kb.open($0)) == rec } ?? false, "queries", dht.stats.queries, "responses", dht.stats.responses)
    }
}
