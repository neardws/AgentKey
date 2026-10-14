import Foundation

public enum ConnectVia: String, Codable, Sendable, CaseIterable { case auto, lan, ipv6, tcp, udp }

public struct ConnectAttempt: Codable, Equatable, Sendable {
    public var candidate: String
    public var kind: String
    public var ok: Bool
    public var ms: Int
    public var error: String?
}

extension NetCandidate {
    /// Parse a stored endpoint string ("bonjour:x", "udp:h:p", "[v6]:p", "h:p").
    public static func fromEndpoint(_ ep: String, source: String) -> NetCandidate {
        if ep.hasPrefix(SyncEndpoint.bonjourPrefix) { return NetCandidate(.bonjour, ep, source: source) }
        if ep.hasPrefix("udp:") { return NetCandidate(.udp, String(ep.dropFirst(4)), source: source) }
        if ep.hasPrefix("relay:") { return NetCandidate(.relay, String(ep.dropFirst(6)), source: source) }
        if let e = IPEndpoint(ep), e.isIPv6 { return NetCandidate(.ipv6, ep, source: source) }
        return NetCandidate(.tcp, ep, source: source)
    }
    /// Inverse of `fromEndpoint` (what peers.json stores).
    public var endpointString: String {
        switch kind { case .udp: return "udp:" + addr; case .relay: return "relay:" + addr; default: return addr }
    }
}

public enum Connectivity {
    /// Filter by `via`, dedupe, sort by rank (stable within a rank: last-known first).
    public static func order(_ cands: [NetCandidate], via: ConnectVia) -> [NetCandidate] {
        var seen = Set<String>(), out: [NetCandidate] = []
        for c in cands where !seen.contains(c.endpointString) {
            seen.insert(c.endpointString)
            switch via {
            case .auto: if c.kind != .relay || c.source == "config" { out.append(c) }
            case .lan: if c.kind == .bonjour || (c.kind == .tcp && (IPEndpoint(c.addr)?.isPrivateV4 ?? false)) { out.append(c) }
            case .ipv6: if c.kind == .ipv6 { out.append(c) }
            case .tcp: if c.kind == .tcp || c.kind == .ipv6 || c.kind == .bonjour { out.append(c) }
            case .udp: if c.kind == .udp { out.append(c) }
            }
        }
        return out.enumerated().sorted { ($0.element.rank, $0.offset) < ($1.element.rank, $1.offset) }.map(\.element)
    }

    /// Happy-eyeballs race: candidates start in rank order, `stagger` apart (all UDP candidates of a
    /// peer share one punching attempt, so only the first UDP candidate is dialled). The first transport
    /// to connect wins; late winners are closed. Returns per-candidate attempts for diagnostics.
    public static func race(_ cands: [NetCandidate], stagger: TimeInterval = 0.3, timeout: TimeInterval = 30,
                            dial: @escaping (NetCandidate) throws -> FrameTransport) -> (winner: (FrameTransport, NetCandidate)?, attempts: [ConnectAttempt]) {
        var list: [NetCandidate] = []
        var udpSeen = false
        for c in cands { if c.kind == .udp { if udpSeen { continue }; udpSeen = true }; list.append(c) }
        guard !list.isEmpty else { return (nil, []) }
        let lock = NSLock(), done = DispatchSemaphore(value: 0)
        var winner: (FrameTransport, NetCandidate)?, attempts: [ConnectAttempt] = [], finished = 0
        let t0 = Date()
        for (i, c) in list.enumerated() {
            DispatchQueue.global().asyncAfter(deadline: .now() + stagger * Double(i)) {
                if lock.withLock({ winner != nil }) {
                    let a = ConnectAttempt(candidate: c.addr, kind: c.kind.rawValue, ok: false, ms: 0, error: "skipped (already connected)")
                    lock.withLock { attempts.append(a); finished += 1 }
                    if lock.withLock({ finished == list.count }) { done.signal() }
                    return
                }
                let s = Date()
                var att = ConnectAttempt(candidate: c.addr, kind: c.kind.rawValue, ok: false, ms: 0, error: nil)
                do {
                    let t = try dial(c)
                    att.ok = true
                    let lost: Bool = lock.withLock { if winner == nil { winner = (t, c); return false }; return true }
                    if lost { t.close(); att.ok = false; att.error = "connected but lost the race" } else { done.signal() }
                } catch { att.error = "\(error)" }
                att.ms = Int(Date().timeIntervalSince(s) * 1000)
                lock.withLock { attempts.append(att); finished += 1; if finished == list.count { done.signal() } }
            }
        }
        while true {
            _ = done.wait(timeout: .now() + max(0.05, timeout - Date().timeIntervalSince(t0)))
            let (w, f) = lock.withLock { (winner, finished) }
            if w != nil || f == list.count || Date().timeIntervalSince(t0) >= timeout { break }
        }
        Thread.sleep(forTimeInterval: 0.01)
        return lock.withLock { (winner, attempts) }
    }
}

/// Persisted networking config: AKPaths.home/sync/net.json. Everything optional.
public struct NetConfig: Codable, Sendable {
    public var stunServers: [String] = STUN.defaultServers
    public var dht: Bool = true                      // BEP 44 rendezvous on the public Mainline DHT
    public var dhtBootstrap: [String] = DHTClient.defaultBootstrap
    public var udpPort: UInt16 = SyncNode.defaultPort
    public var forwardedEndpoints: [String] = []     // e.g. ["203.0.113.5:7373"] if you port-forwarded
    public var relay: String? = nil                  // optional TCP relay you run yourself ("host:port"); off by default
    public var publishInterval: TimeInterval = 300
    public var pollInterval: TimeInterval = 30
    public init() {}
    public static func load(_ url: URL) -> NetConfig {
        guard let d = try? Data(contentsOf: url) else { return NetConfig() }
        let dec = JSONDecoder()
        // tolerate partial files
        guard let obj = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { return NetConfig() }
        var c = NetConfig()
        if let v = obj["stunServers"] as? [String] { c.stunServers = v }
        if let v = obj["dht"] as? Bool { c.dht = v }
        if let v = obj["dhtBootstrap"] as? [String] { c.dhtBootstrap = v }
        if let v = obj["udpPort"] as? Int, let p = UInt16(exactly: v) { c.udpPort = p }
        if let v = obj["forwardedEndpoints"] as? [String] { c.forwardedEndpoints = v }
        if let v = obj["relay"] as? String, !v.isEmpty { c.relay = v }
        if let v = obj["publishInterval"] as? Double { c.publishInterval = max(60, v) }
        if let v = obj["pollInterval"] as? Double { c.pollInterval = max(10, v) }
        _ = dec
        return c
    }
}

public struct NetProbe: Codable, Sendable {
    public var udpPort: UInt16
    public var localIPv4: [String]
    public var globalIPv6: [String]
    public var stun: [STUNResult]
    public var natType: String
    public var publicIPv4: [String]
    public var candidates: [NetCandidate]
    public var dht: DHTStatus
    public var notes: [String]
}
public struct DHTStatus: Codable, Sendable {
    public var enabled: Bool
    public var lastPublish: String?
    public var lastPublishOK: Bool?
    public var nodesAccepted: Int?
    public var queries: Int
    public var responses: Int
}

/// The connectivity runtime owned by agentkeyd: one UDP socket (STUN + punching + streams + DHT),
/// periodic candidate publishing and peer polling, and the hub side of UDP sessions.
public final class NetRuntime: @unchecked Sendable {
    public let mux: UDPMux
    public let config: NetConfig
    unowned let node: SyncNode
    public let dht: DHTClient?
    var providers: [RendezvousProvider] = []
    let lock = NSLock()
    var lastSTUN: [STUNResult] = []
    var natType: NATType = .unknown
    var records: [String: CandidateRecord] = [:]           // peer → latest record (dht / manual)
    var lastPublish: (Date, Bool, Int, String?)?
    public var tcpPort: UInt16
    /// Only devices that accept TCP sync connections (home node) publish TCP/IPv6/Bonjour candidates.
    public var listensTCP = true
    public var bonjourName: String?
    public var log: (String) -> Void = { _ in }
    var recordsURL: URL { node.dir.appendingPathComponent("rendezvous.json") }

    public init(node: SyncNode, config: NetConfig, tcpPort: UInt16, mux: UDPMux? = nil) throws {
        self.node = node; self.config = config; self.tcpPort = tcpPort
        if let mux { self.mux = mux } else {
            if let m = try? UDPMux(port: config.udpPort) { self.mux = m } else { self.mux = try UDPMux(port: 0) }
        }
        dht = config.dht ? DHTClient(mux: self.mux, bootstrap: config.dhtBootstrap) : nil
        if let dht { providers.append(DHTRendezvous(client: dht)) }
        if let d = try? Data(contentsOf: node.dir.appendingPathComponent("rendezvous.json")),
           let r = try? JSONDecoder().decode([String: CandidateRecord].self, from: d) { records = r }
        self.mux.selfShortID = shortID(node.identity.publicKey)
        self.mux.pairKeyFor = { [weak self] sid in self?.pairKeys(shortID: sid)?.pair }
        self.mux.onAccept = { [weak self] stream in
            guard let self else { return }
            do { self.log("udp: \(try self.node.serveConnection(stream, prepare: self.beforeServe))"); self.afterServe?() }
            catch { self.log("udp session from \(stream.remote) failed: \(error)") }
        }
    }
    public var beforeServe: (() -> Void)?
    public var afterServe: (() -> Void)?

    public func addProvider(_ p: RendezvousProvider) { lock.withLock { providers.append(p) } }

    func trustedPeers() -> [DeviceRecord] {
        guard let r = node.replica else { return [] }
        return r.trust.devices.values.filter { $0.revokedAt == nil && $0.deviceID != node.identity.deviceID.raw }
    }
    public func pairKeys(peer: String) -> PairKeys? {
        guard let d = node.replica?.trust.devices[peer], d.revokedAt == nil else { return nil }
        return try? PairKeys(identity: node.identity, peerPublicKey: d.publicKey)
    }
    func pairKeys(shortID sid: Data) -> PairKeys? {
        guard let d = trustedPeers().first(where: { shortID($0.publicKey) == sid }) else { return nil }
        return try? PairKeys(identity: node.identity, peerPublicKey: d.publicKey)
    }
    func peerID(shortID sid: Data) -> String? { trustedPeers().first { shortID($0.publicKey) == sid }?.deviceID }

    public func peersWithRecords() -> [String] { lock.withLock { Array(records.keys) } }

    // MARK: discovery

    @discardableResult
    public func refreshSTUN() -> [STUNResult] {
        let r = mux.stunProbe(servers: config.stunServers)
        let locals = LocalAddresses.ipv4() + LocalAddresses.ipv6Global()
        let nat = STUNClient.estimate(r, localAddresses: locals, localPort: mux.localPort)
        lock.withLock { lastSTUN = r; natType = nat }
        return r
    }

    /// Our own candidates (what we publish to peers).
    public func localCandidates() -> [NetCandidate] {
        var c: [NetCandidate] = []
        if listensTCP, let b = bonjourName { c.append(NetCandidate(.bonjour, SyncEndpoint.bonjourPrefix + b, source: "host")) }
        for v6 in LocalAddresses.ipv6Global() where listensTCP {
            c.append(NetCandidate(.ipv6, IPEndpoint(host: v6, port: tcpPort).description, source: "host"))
        }
        for f in config.forwardedEndpoints { c.append(NetCandidate.fromEndpoint(f, source: "config")) }
        if let relay = config.relay { c.append(NetCandidate(.relay, relay, source: "config")) }
        let mapped = lock.withLock { lastSTUN.compactMap { $0.mapped } }
        for m in mapped { let nc = NetCandidate(.udp, m, source: "srflx"); if !c.contains(nc) { c.append(nc) } }
        for v6 in LocalAddresses.ipv6Global() {
            let nc = NetCandidate(.udp, IPEndpoint(host: v6, port: mux.localPort).description, source: "host"); if !c.contains(nc) { c.append(nc) }
        }
        for v4 in LocalAddresses.ipv4() {
            if listensTCP { c.append(NetCandidate(.tcp, "\(v4):\(tcpPort)", source: "host")) }
            c.append(NetCandidate(.udp, "\(v4):\(mux.localPort)", source: "host"))
        }
        return c
    }

    func record() -> CandidateRecord {
        CandidateRecord(device: node.identity.deviceID.raw, nat: lock.withLock { natType.rawValue }, candidates: Array(localCandidates().prefix(12)))
    }

    /// Seal our record for each trusted peer and publish via all providers (DHT). `blocking=false` runs async.
    public func publishAll(blocking: Bool = true) {
        let work = { [self] in
            if lock.withLock({ lastSTUN.isEmpty }) { refreshSTUN() }
            let rec = record()
            var ok = 0, err: String?
            for p in trustedPeers() {
                guard let k = try? PairKeys(identity: node.identity, peerPublicKey: p.publicKey), var sealed = try? k.seal(rec) else { continue }
                // keep the DHT value under 1000 bytes
                var r2 = rec
                while sealed.count > BEP44.maxValue && !r2.c.isEmpty { r2.c.removeLast(); sealed = (try? k.seal(r2)) ?? sealed }
                for prov in lock.withLock({ providers }) {
                    do { try prov.publish(sealed, keys: k); ok += 1 } catch { err = "\(prov.name): \(error)" }
                }
            }
            lock.withLock { lastPublish = (Date(), err == nil, ok, err) }
            log("rendezvous: published to \(ok) slot(s)\(err.map { " — " + $0 } ?? "")")
        }
        if blocking { work() } else { DispatchQueue.global().async(execute: work) }
    }

    /// Fetch peers' records; for fresh records with UDP candidates, punch towards them so a peer that is
    /// currently dialling us gets through our NAT (the hub half of simultaneous open).
    public func pollPeers() {
        for p in trustedPeers() {
            guard let k = try? PairKeys(identity: node.identity, peerPublicKey: p.publicKey) else { continue }
            for prov in lock.withLock({ providers }) {
                guard let sealed = try? prov.fetch(keys: k), let rec = try? k.open(sealed), rec.d == p.deviceID else { continue }
                let isNew = lock.withLock { () -> Bool in
                    if let cur = records[p.deviceID], cur.t >= rec.t { return false }
                    records[p.deviceID] = rec; return true
                }
                if isNew { saveRecords() }
                if rec.age < 120 { assist(rec, keys: k) }
            }
        }
    }

    func assist(_ rec: CandidateRecord, keys: PairKeys) {
        let eps = rec.c.filter { $0.kind == .udp }.compactMap { IPEndpoint($0.addr) }.filter { mux.socket.isDualStack || !$0.isIPv6 }
        if !eps.isEmpty { mux.punchTowards(eps, key: keys.pair, duration: 15) }
    }

    func saveRecords() {
        let d = lock.withLock { try? JSONEncoder().encode(records) }
        if let d { try? SyncNode.writePrivate(d, to: recordsURL) }
    }

    /// Candidates for a peer from its rendezvous record (fetching it now if stale).
    public func candidates(for peer: String) -> [NetCandidate] {
        var rec = lock.withLock { records[peer] }
        if rec == nil || rec!.age > 60, let k = pairKeys(peer: peer) {
            for prov in lock.withLock({ providers }) {
                if let s = try? prov.fetch(keys: k), let r = try? k.open(s), r.d == peer, r.t > (rec?.t ?? 0) {
                    rec = r; lock.withLock { records[peer] = r }; saveRecords()
                }
            }
        }
        return rec?.c.map { var c = $0; c.source = "rendezvous:" + c.source; return c } ?? []
    }

    // MARK: manual signalling

    public func exportSignal(peer: String) throws -> String {
        guard let k = pairKeys(peer: peer) else { throw SyncNodeError.notInitialized }
        if lock.withLock({ lastSTUN.isEmpty }) { refreshSTUN() }
        return ManualSignal.export(try k.seal(record()), from: node.identity)
    }

    /// Import a peer's blob; returns (peer deviceID, record).
    public func importSignal(_ blob: String) throws -> (String, CandidateRecord) {
        guard let (sid, sealed) = ManualSignal.parse(blob) else { throw PairingError.malformed }
        guard let peer = peerID(shortID: sid), let k = pairKeys(peer: peer) else { throw PairingError.rejected("blob is not from a paired device") }
        let rec = try k.open(sealed)
        guard rec.d == peer else { throw PairingError.rejected("device mismatch") }
        lock.withLock { records[peer] = rec }; saveRecords()
        assist(rec, keys: k)
        return (peer, rec)
    }

    // MARK: UDP dial

    /// Hole-punch to the peer's UDP candidates, then open a reliable stream for the Noise session.
    public func dialUDP(peer: String, candidate: NetCandidate, timeout: TimeInterval = 20) throws -> FrameTransport {
        guard let k = pairKeys(peer: peer) else { throw TransportError.connectFailed("peer not trusted") }
        var eps = (candidates(for: peer) + [candidate]).filter { $0.kind == .udp }.compactMap { IPEndpoint($0.addr) }
        eps = eps.filter { mux.socket.isDualStack || !$0.isIPv6 }
        let uniq = eps.reduce(into: [IPEndpoint]()) { if !$0.contains($1) { $0.append($1) } }
        guard let (ep, conn) = mux.punch(candidates: uniq, key: k.pair, timeout: timeout) else {
            throw TransportError.connectFailed("udp hole punch to \(uniq.count) candidate(s) timed out (peer NAT \(lock.withLock { records[peer]?.n } ?? "?"))")
        }
        log("udp: punched \(ep)")
        return mux.openStream(to: ep, conn: conn)
    }

    // MARK: probe

    public func probe() -> NetProbe {
        let stun = refreshSTUN()
        let v4 = LocalAddresses.ipv4(), v6 = LocalAddresses.ipv6Global()
        var notes: [String] = []
        let nat = lock.withLock { natType }
        switch nat {
        case .udpBlocked: notes.append("no STUN server answered: UDP is blocked or forced through a proxy/VPN; UDP hole punching will not work — use IPv6, a forwarded port, or Tailscale/WireGuard")
        case .endpointDependent: notes.append("NAT maps each destination to a different port (symmetric): hole punching will usually fail unless the other side is open/IPv6")
        case .endpointIndependent: notes.append("NAT mapping is endpoint-independent: UDP hole punching should work")
        case .open: notes.append("this host has a public address on its interface")
        case .unknown: notes.append("only one STUN answer: NAT behaviour unknown")
        }
        if !v6.isEmpty { notes.append("global IPv6 present: peers with IPv6 can try a direct connection to [v6]:\(tcpPort) if the router firewall allows inbound") }
        let pub = Array(Set(stun.compactMap { $0.mapped.flatMap(IPEndpoint.init) }.filter { !$0.isIPv6 }.map(\.host))).sorted()
        let lp = lock.withLock { lastPublish }
        let st = DHTStatus(enabled: dht != nil, lastPublish: lp.map { ISO8601DateFormatter().string(from: $0.0) }, lastPublishOK: lp?.1,
                           nodesAccepted: lp?.2, queries: dht?.stats.queries ?? 0, responses: dht?.stats.responses ?? 0)
        return NetProbe(udpPort: mux.localPort, localIPv4: v4, globalIPv6: v6, stun: stun, natType: nat.rawValue, publicIPv4: pub,
                        candidates: localCandidates(), dht: st, notes: notes)
    }

    /// Background loop: keep the NAT mapping alive, republish, poll peers.
    public func startBackground() {
        Thread { [self] in
            var lastPub = Date.distantPast, lastPoll = Date.distantPast, lastStun = Date.distantPast
            while true {
                if Date().timeIntervalSince(lastStun) > 25 { refreshSTUN(); lastStun = Date() }   // also NAT keepalive
                if node.replica != nil {
                    if Date().timeIntervalSince(lastPub) > config.publishInterval { publishAll(); lastPub = Date() }
                    if Date().timeIntervalSince(lastPoll) > config.pollInterval { pollPeers(); lastPoll = Date() }
                }
                Thread.sleep(forTimeInterval: 5)
            }
        }.start()
    }
}
