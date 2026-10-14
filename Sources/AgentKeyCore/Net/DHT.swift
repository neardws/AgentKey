import Foundation

// MARK: bencode

public indirect enum Bencode: Equatable {
    case int(Int64), bytes(Data), list([Bencode]), dict([Data: Bencode])

    public static func str(_ s: String) -> Bencode { .bytes(Data(s.utf8)) }

    public func encode() -> Data {
        switch self {
        case .int(let i): return Data("i\(i)e".utf8)
        case .bytes(let b): return Data("\(b.count):".utf8) + b
        case .list(let l): return Data("l".utf8) + l.reduce(Data()) { $0 + $1.encode() } + Data("e".utf8)
        case .dict(let d):
            var out = Data("d".utf8)
            for k in d.keys.sorted(by: { $0.lexicographicallyPrecedes($1) }) { out += Bencode.bytes(k).encode() + d[k]!.encode() }
            return out + Data("e".utf8)
        }
    }

    public static func decode(_ d: Data) throws -> Bencode {
        let b = [UInt8](d); var i = 0
        let v = try parse(b, &i, depth: 0)
        guard i == b.count else { throw DHTError.malformed }
        return v
    }
    static func parse(_ b: [UInt8], _ i: inout Int, depth: Int) throws -> Bencode {
        guard i < b.count, depth < 32 else { throw DHTError.malformed }
        switch b[i] {
        case UInt8(ascii: "i"):
            i += 1; let s = i
            while i < b.count && b[i] != UInt8(ascii: "e") { i += 1 }
            guard i < b.count, let v = Int64(String(decoding: b[s..<i], as: UTF8.self)) else { throw DHTError.malformed }
            i += 1; return .int(v)
        case UInt8(ascii: "l"):
            i += 1; var l: [Bencode] = []
            while i < b.count && b[i] != UInt8(ascii: "e") { l.append(try parse(b, &i, depth: depth + 1)) }
            guard i < b.count else { throw DHTError.malformed }
            i += 1; return .list(l)
        case UInt8(ascii: "d"):
            i += 1; var d: [Data: Bencode] = [:]
            while i < b.count && b[i] != UInt8(ascii: "e") {
                guard case .bytes(let k) = try parse(b, &i, depth: depth + 1) else { throw DHTError.malformed }
                d[k] = try parse(b, &i, depth: depth + 1)
            }
            guard i < b.count else { throw DHTError.malformed }
            i += 1; return .dict(d)
        case UInt8(ascii: "0")...UInt8(ascii: "9"):
            let s = i
            while i < b.count && b[i] != UInt8(ascii: ":") { i += 1 }
            guard i < b.count, let n = Int(String(decoding: b[s..<i], as: UTF8.self)), n >= 0, i + 1 + n <= b.count else { throw DHTError.malformed }
            i += 1; let v = Data(b[i..<(i + n)]); i += n; return .bytes(v)
        default: throw DHTError.malformed
        }
    }

    public subscript(_ k: String) -> Bencode? { if case .dict(let d) = self { return d[Data(k.utf8)] }; return nil }
    public var data: Data? { if case .bytes(let b) = self { return b }; return nil }
    public var int: Int64? { if case .int(let i) = self { return i }; return nil }
    public var string: String? { data.map { String(decoding: $0, as: UTF8.self) } }
}

public enum DHTError: Error, Equatable { case malformed, badSignature, tooLarge, noNodes, timeout, putFailed(String) }

// MARK: BEP 44 mutable items

public enum BEP44 {
    public static let maxValue = 1000
    /// The buffer that is signed: bencoded salt (optional), seq and v, concatenated without a dict wrapper.
    public static func signingBuffer(salt: Data, seq: Int64, v: Data) -> Data {
        (salt.isEmpty ? Data() : Data("4:salt".utf8) + Bencode.bytes(salt).encode())
            + Data("3:seqi\(seq)e1:v".utf8) + Bencode.bytes(v).encode()
    }
    public static func target(publicKey: Data, salt: Data) -> Data { Data(Insecure.SHA1.hash(data: publicKey + salt)) }
    public static func sign(_ key: Curve25519.Signing.PrivateKey, salt: Data, seq: Int64, v: Data) throws -> Data {
        try key.signature(for: signingBuffer(salt: salt, seq: seq, v: v))
    }
    public static func verify(pub: Data, salt: Data, seq: Int64, v: Data, sig: Data) -> Bool {
        guard let k = try? Curve25519.Signing.PublicKey(rawRepresentation: pub) else { return false }
        return k.isValidSignature(sig, for: signingBuffer(salt: salt, seq: seq, v: v))
    }
}

// MARK: KRPC client (Mainline DHT, IPv4 compact nodes)

public struct DHTNodeInfo: Hashable { public var id: Data; public var ep: IPEndpoint }

/// Minimal Mainline DHT client: iterative `get` lookups and BEP 44 `put`. Runs on the shared UDPMux
/// socket, marks itself read-only (BEP 43) so it never has to serve other nodes.
public final class DHTClient: @unchecked Sendable {
    public static let defaultBootstrap = ["router.bittorrent.com:6881", "dht.transmissionbt.com:6881", "router.utorrent.com:6881", "dht.libtorrent.org:25401"]
    let mux: UDPMux
    let nodeID = AKRandom.bytes(20)
    let lock = NSLock()
    var waiters: [Data: (Bencode, IPEndpoint) -> Void] = [:]
    public var bootstrap: [String]
    public var log: (String) -> Void = { _ in }
    var tidCounter: UInt16 = UInt16.random(in: 0...UInt16.max)
    public var stats = (queries: 0, responses: 0)

    public init(mux: UDPMux, bootstrap: [String] = DHTClient.defaultBootstrap) {
        self.mux = mux; self.bootstrap = bootstrap
        mux.dhtHandler = { [weak self] d, from in self?.handle(d, from) }
    }

    func handle(_ d: Data, _ from: IPEndpoint) {
        guard let m = try? Bencode.decode(d), let t = m["t"]?.data else { return }
        let w = lock.withLock { waiters.removeValue(forKey: t) }
        if let w { lock.withLock { stats.responses += 1 }; w(m, from) }
    }

    func query(_ q: String, _ args: [String: Bencode], to ep: IPEndpoint, timeout: TimeInterval = 2) -> Bencode? {
        let tid: Data = lock.withLock { tidCounter &+= 1; stats.queries += 1; return be16(tidCounter) }
        var a = args; a["id"] = .bytes(nodeID)
        var dict: [Data: Bencode] = [:]
        for (k, v) in a { dict[Data(k.utf8)] = v }
        let msg = Bencode.dict([Data("t".utf8): .bytes(tid), Data("y".utf8): .str("q"), Data("q".utf8): .str(q),
                                Data("a".utf8): .dict(dict), Data("ro".utf8): .int(1)])
        let sem = DispatchSemaphore(value: 0); var resp: Bencode?
        lock.withLock { waiters[tid] = { m, _ in resp = m; sem.signal() } }
        mux.send(msg.encode(), to: ep)
        _ = sem.wait(timeout: .now() + timeout)
        lock.withLock { _ = waiters.removeValue(forKey: tid) }
        guard let r = resp, r["y"]?.string == "r", let body = r["r"] else { return nil }
        return body
    }

    static func parseNodes(_ d: Data) -> [DHTNodeInfo] {
        let b = [UInt8](d); var out: [DHTNodeInfo] = []
        var i = 0
        while i + 26 <= b.count {
            let ip = b[(i + 20)..<(i + 24)].map(String.init).joined(separator: ".")
            let port = UInt16(b[i + 24]) << 8 | UInt16(b[i + 25])
            if port != 0 { out.append(DHTNodeInfo(id: Data(b[i..<(i + 20)]), ep: IPEndpoint(host: ip, port: port))) }
            i += 26
        }
        return out
    }
    static func distance(_ a: Data, _ b: Data) -> Data { Data(zip(a, b).map { $0 ^ $1 }) }

    public struct Found { public var v: Data; public var seq: Int64; public var from: IPEndpoint }
    struct Responder { var node: DHTNodeInfo; var token: Data? }

    /// Iterative lookup for `target`; returns closest responders (with write tokens) and the best item.
    func lookup(target: Data, verify: @escaping (Bencode) -> Found?, deadline: Date) -> (responders: [Responder], best: Found?) {
        var seeds: [DHTNodeInfo] = []
        for b in bootstrap {
            if let ep = IPEndpoint(b) { seeds.append(DHTNodeInfo(id: Data(count: 20), ep: ep)); continue }
            if let (h, p) = STUNClient.splitHostPort(b) {
                for ep in IPEndpoint.resolve(h, port: p).filter({ !$0.isIPv6 }) { seeds.append(DHTNodeInfo(id: Data(count: 20), ep: ep)) }
            }
        }
        var shortlist = seeds, queried = Set<IPEndpoint>(), responders: [Responder] = [], best: Found?
        let rl = NSLock()
        var rounds = 0
        while Date() < deadline && rounds < 12 {
            rounds += 1
            shortlist.sort { DHTClient.distance($0.id, target).lexicographicallyPrecedes(DHTClient.distance($1.id, target)) }
            let batch = Array(shortlist.filter { !queried.contains($0.ep) }.prefix(8))
            if batch.isEmpty { break }
            let g = DispatchGroup()
            for n in batch {
                queried.insert(n.ep); g.enter()
                DispatchQueue.global().async {
                    defer { g.leave() }
                    guard let r = self.query("get", ["target": .bytes(target)], to: n.ep, timeout: 1.5) else { return }
                    let id = r["id"]?.data ?? n.id
                    let more = r["nodes"]?.data.map(DHTClient.parseNodes) ?? []
                    let f = verify(r)
                    rl.withLock {
                        responders.append(Responder(node: DHTNodeInfo(id: id, ep: n.ep), token: r["token"]?.data))
                        for m in more where !shortlist.contains(where: { $0.ep == m.ep }) { shortlist.append(m) }
                        if let f, f.seq > (best?.seq ?? Int64.min) { best = f }
                    }
                }
            }
            g.wait()
            // stop once the 8 closest known nodes have all been queried
            let closest = shortlist.sorted { DHTClient.distance($0.id, target).lexicographicallyPrecedes(DHTClient.distance($1.id, target)) }.prefix(8)
            if closest.allSatisfy({ queried.contains($0.ep) }) && rounds > 2 { break }
        }
        responders.sort { DHTClient.distance($0.node.id, target).lexicographicallyPrecedes(DHTClient.distance($1.node.id, target)) }
        return (responders, best)
    }

    /// BEP 44 get of a mutable item.
    public func get(publicKey: Data, salt: Data, timeout: TimeInterval = 12) -> Found? {
        let target = BEP44.target(publicKey: publicKey, salt: salt)
        return lookup(target: target, verify: { r in
            guard let v = r["v"], let vb = v.data, let seq = r["seq"]?.int, let sig = r["sig"]?.data, r["k"]?.data == publicKey,
                  BEP44.verify(pub: publicKey, salt: salt, seq: seq, v: vb, sig: sig) else { return nil }
            return Found(v: vb, seq: seq, from: IPEndpoint(host: "0.0.0.0", port: 0))
        }, deadline: Date().addingTimeInterval(timeout)).best
    }

    /// BEP 44 put of a mutable item to the closest nodes. Returns the number of nodes that accepted.
    @discardableResult
    public func put(key: Curve25519.Signing.PrivateKey, salt: Data, seq: Int64, v: Data, timeout: TimeInterval = 15) throws -> Int {
        guard v.count <= BEP44.maxValue else { throw DHTError.tooLarge }
        let pub = key.publicKey.rawRepresentation
        let sig = try BEP44.sign(key, salt: salt, seq: seq, v: v)
        let target = BEP44.target(publicKey: pub, salt: salt)
        let (resp, _) = lookup(target: target, verify: { _ in nil }, deadline: Date().addingTimeInterval(timeout * 0.7))
        let targets = resp.filter { $0.token != nil }.prefix(8)
        guard !targets.isEmpty else { throw DHTError.noNodes }
        var ok = 0; let ol = NSLock(); let g = DispatchGroup()
        for r in targets {
            g.enter()
            DispatchQueue.global().async {
                defer { g.leave() }
                var a: [String: Bencode] = ["token": .bytes(r.token!), "v": .bytes(v), "k": .bytes(pub), "seq": .int(seq), "sig": .bytes(sig)]
                if !salt.isEmpty { a["salt"] = .bytes(salt) }
                if self.query("put", a, to: r.node.ep, timeout: 2) != nil { ol.withLock { ok += 1 } }
            }
        }
        g.wait()
        if ok == 0 { throw DHTError.putFailed("no node accepted the item (\(targets.count) tried)") }
        return ok
    }
}

/// Tiny KRPC responder (get/put/ping/find_node) — used by tests as a local DHT, and handy for
/// running a private bootstrap node on your own machine. Not a full routing-table implementation.
public final class DHTLocalNode: @unchecked Sendable {
    public let mux: UDPMux
    let id = AKRandom.bytes(20)
    var store: [Data: (v: Data, k: Data, salt: Data, seq: Int64, sig: Data)] = [:]
    public var peers: [DHTNodeInfo] = []      // returned in `nodes`
    let lock = NSLock()
    public var nodeInfo: DHTNodeInfo { DHTNodeInfo(id: id, ep: IPEndpoint(host: "127.0.0.1", port: mux.localPort)) }

    public init(port: UInt16 = 0) throws {
        mux = try UDPMux(socket: UDPSocket(port: port, v4Only: true, bindHost: "127.0.0.1"))
        mux.dhtHandler = { [weak self] d, from in self?.handle(d, from) }
    }

    func handle(_ d: Data, _ from: IPEndpoint) {
        guard let m = try? Bencode.decode(d), m["y"]?.string == "q", let t = m["t"]?.data, let q = m["q"]?.string, let a = m["a"] else { return }
        var r: [Data: Bencode] = [Data("id".utf8): .bytes(id)]
        let token = Data(SHA256.hash(data: Data(from.host.utf8) + id)).prefix(8)
        let compact = lock.withLock { peers }.reduce(Data()) { acc, n in
            acc + n.id + Data(n.ep.host.split(separator: ".").compactMap { UInt8($0) }) + be16(n.ep.port) }
        switch q {
        case "ping": break
        case "find_node", "get":
            r[Data("nodes".utf8)] = .bytes(compact)
            r[Data("token".utf8)] = .bytes(Data(token))
            if q == "get", let target = a["target"]?.data, let it = lock.withLock({ store[target] }) {
                r[Data("v".utf8)] = .bytes(it.v); r[Data("k".utf8)] = .bytes(it.k); r[Data("seq".utf8)] = .int(it.seq); r[Data("sig".utf8)] = .bytes(it.sig)
            }
        case "put":
            guard a["token"]?.data == Data(token), let v = a["v"]?.data, let k = a["k"]?.data, let seq = a["seq"]?.int, let sig = a["sig"]?.data,
                  BEP44.verify(pub: k, salt: a["salt"]?.data ?? Data(), seq: seq, v: v, sig: sig) else {
                let e = Bencode.dict([Data("t".utf8): .bytes(t), Data("y".utf8): .str("e"), Data("e".utf8): .list([.int(206), .str("invalid")])])
                mux.send(e.encode(), to: from); return
            }
            let salt = a["salt"]?.data ?? Data()
            let target = BEP44.target(publicKey: k, salt: salt)
            let accepted: Bool = lock.withLock {
                if let cur = store[target], cur.seq >= seq { return false }
                store[target] = (v, k, salt, seq, sig); return true
            }
            if !accepted {
                let e = Bencode.dict([Data("t".utf8): .bytes(t), Data("y".utf8): .str("e"), Data("e".utf8): .list([.int(302), .str("seq too low")])])
                mux.send(e.encode(), to: from); return
            }
        default: return
        }
        mux.send(Bencode.dict([Data("t".utf8): .bytes(t), Data("y".utf8): .str("r"), Data("r".utf8): .dict(r)]).encode(), to: from)
    }
}

/// RendezvousProvider over BEP 44: each direction of each device pair has its own unlinkable
/// ed25519 key + salt derived from the pair secret; the value is the record sealed to the peer.
public final class DHTRendezvous: RendezvousProvider {
    public let name = "dht"
    let client: DHTClient
    public init(client: DHTClient) { self.client = client }
    public func publish(_ sealed: Data, keys: PairKeys) throws {
        let (k, salt) = keys.dhtSlot(outgoing: true)
        try client.put(key: k, salt: salt, seq: Int64(Date().timeIntervalSince1970), v: sealed)
    }
    public func fetch(keys: PairKeys) throws -> Data? {
        let (k, salt) = keys.dhtSlot(outgoing: false)
        return client.get(publicKey: k.publicKey.rawRepresentation, salt: salt)?.v
    }
}
