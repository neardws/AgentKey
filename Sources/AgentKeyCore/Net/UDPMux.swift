import Foundation

/// One UDP socket shared by STUN, hole punching, reliable streams and the DHT client, so that the
/// NAT mapping learned via STUN is exactly the one peers punch towards.
///
/// AgentKey datagrams start with 0xA7 followed by a type byte:
///   PUNCH     A7 01 connID(4) sender(8) nonce(8) mac(16)   mac = HMAC(pairKey, "punch"|connID|sender|nonce)[0..16]
///   PUNCH_ACK A7 02 connID(4) sender(8) nonce(8) mac(16)
///   DATA      A7 03 connID(4) seq(4) payload
///   ACK       A7 04 connID(4) nextExpected(4)
///   FIN       A7 05 connID(4)
///   KEEPALIVE A7 06
/// Punch MACs keep random internet noise from opening sessions; the Noise handshake that follows is
/// still the trust anchor (pinned static key).
public final class UDPMux: @unchecked Sendable {
    public let socket: UDPSocket
    let lock = NSLock()
    var stunWaiters: [Data: (STUN.Message) -> Void] = [:]
    var punchWaiters: [UInt32: (IPEndpoint, Data) -> Void] = [:]
    var streams: [StreamKey: UDPStream] = [:]
    var authorized: [IPEndpoint: Date] = [:]          // endpoints that sent a valid punch recently
    public var dhtHandler: ((Data, IPEndpoint) -> Void)?
    /// Hub side: called for a new inbound stream from a punched endpoint.
    public var onAccept: ((UDPStream) -> Void)?
    /// Resolve a sender short id to the pair key shared with that device (nil = unknown → ignore).
    public var pairKeyFor: ((Data) -> SymmetricKey?)?
    public var selfShortID = Data(count: 8)
    /// Called when a valid PUNCH arrives (sender short id, endpoint) — e.g. hub logs / learns endpoints.
    public var onPunch: ((Data, IPEndpoint) -> Void)?
    public var log: (String) -> Void = { _ in }

    // Test hooks: simulate an address-restricted NAT (inbound only from endpoints we sent to) and loss.
    public var simulateRestrictedNAT = false
    public var dropRate = 0.0
    var sentTo = Set<IPEndpoint>()
    private var running = true

    struct StreamKey: Hashable { var ep: IPEndpoint; var conn: UInt32 }

    public init(socket: UDPSocket) {
        self.socket = socket
        Thread { [weak self] in self?.loop() }.start()
    }
    public convenience init(port: UInt16 = 0) throws { self.init(socket: try UDPSocket(port: port)) }
    public var localPort: UInt16 { socket.localPort }

    public func close() { running = false; socket.close() }

    public func send(_ d: Data, to e: IPEndpoint) {
        lock.withLock { _ = sentTo.insert(e) }
        if dropRate > 0, Double.random(in: 0..<1) < dropRate { return }
        try? socket.send(d, to: e)
    }

    func loop() {
        while running {
            guard let (d, from) = try? socket.receive(timeout: 1) else { continue }
            if simulateRestrictedNAT && !lock.withLock({ sentTo.contains(from) }) { continue }
            if dropRate > 0, Double.random(in: 0..<1) < dropRate { continue }
            guard let first = d.first else { continue }
            if first == 0xA7 { handleAgentKey(d, from: from) }
            else if first < 2, d.count >= 20, let m = try? STUN.Message.decode(d) {
                let w = lock.withLock { stunWaiters.removeValue(forKey: m.transactionID) }
                w?(m)
            } else if first == 0x64 /* 'd' bencode */ { dhtHandler?(d, from) }
        }
    }

    // MARK: STUN

    public func stunTransact(_ req: STUN.Message, to: IPEndpoint, timeout: TimeInterval) -> STUN.Message? {
        let sem = DispatchSemaphore(value: 0); var resp: STUN.Message?
        lock.withLock { stunWaiters[req.transactionID] = { resp = $0; sem.signal() } }
        send(req.encode(), to: to)
        _ = sem.wait(timeout: .now() + timeout)
        lock.withLock { _ = stunWaiters.removeValue(forKey: req.transactionID) }
        return resp
    }

    public func stunProbe(servers: [String], timeout: TimeInterval = 1.5, retries: Int = 1) -> [STUNResult] {
        let group = DispatchGroup(); var out = [STUNResult?](repeating: nil, count: servers.count); let ol = NSLock()
        for (i, s) in servers.enumerated() {
            group.enter()
            DispatchQueue.global().async {
                var r = STUNResult(server: s)
                defer { ol.withLock { out[i] = r }; group.leave() }
                guard let ep = IPEndpoint(s) ?? STUNClient.splitHostPort(s).flatMap({ IPEndpoint.resolve($0.0, port: $0.1).first(where: { !$0.isIPv6 || self.socket.isDualStack }) })
                else { r.error = "resolve failed"; return }
                r.serverAddress = ep.description
                for _ in 0...retries {
                    let t0 = Date(), req = STUN.Message(type: STUN.bindingRequest)
                    if let m = self.stunTransact(req, to: ep, timeout: timeout) {
                        if m.type == STUN.bindingSuccess, let a = m.mappedAddress { r.mapped = a.description; r.rttMs = Int(Date().timeIntervalSince(t0) * 1000); return }
                        r.error = "error response"; return
                    }
                }
                r.error = "no response (UDP blocked or proxied?)"
            }
        }
        group.wait()
        return out.map { $0! }
    }

    // MARK: punching

    static func punchMAC(_ key: SymmetricKey, _ conn: UInt32, _ sender: Data, _ nonce: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: Data("punch".utf8) + be32(conn) + sender + nonce, using: key)).prefix(16)
    }
    func punchPacket(_ type: UInt8, conn: UInt32, key: SymmetricKey) -> Data {
        let nonce = AKRandom.bytes(8)
        return Data([0xA7, type]) + be32(conn) + selfShortID + nonce + UDPMux.punchMAC(key, conn, selfShortID, nonce)
    }

    /// Simultaneous-open hole punch towards `candidates`: send PUNCH every 100 ms (also to any
    /// endpoint the peer punches us from) until a valid PUNCH_ACK arrives. Returns the working endpoint.
    public func punch(candidates: [IPEndpoint], key: SymmetricKey, timeout: TimeInterval = 15, conn: UInt32 = UInt32.random(in: 1...UInt32.max)) -> (IPEndpoint, UInt32)? {
        var targets = candidates
        let sem = DispatchSemaphore(value: 0); var winner: IPEndpoint?
        let wl = NSLock()
        lock.withLock { punchWaiters[conn] = { ep, _ in wl.withLock { if winner == nil { winner = ep; sem.signal() } } } }
        lock.withLock { punchWaiters[0] = { ep, _ in wl.withLock { if !targets.contains(ep) { targets.append(ep) } } } }  // peer-initiated punches reveal its real mapping
        defer { lock.withLock { punchWaiters[conn] = nil; punchWaiters[0] = nil } }
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            for t in wl.withLock({ targets }) { send(punchPacket(1, conn: conn, key: key), to: t) }
            if sem.wait(timeout: .now() + 0.1) == .success { break }
        }
        return wl.withLock { winner }.map { ($0, conn) }
    }

    /// Hub side: punch towards a peer whose candidates we learned (opens our NAT for its packets).
    public func punchTowards(_ eps: [IPEndpoint], key: SymmetricKey, duration: TimeInterval = 10) {
        DispatchQueue.global().async {
            let end = Date().addingTimeInterval(duration)
            while Date() < end { for e in eps { self.send(self.punchPacket(1, conn: 0, key: key), to: e) }; Thread.sleep(forTimeInterval: 0.2) }
        }
    }

    func handleAgentKey(_ d: Data, from: IPEndpoint) {
        let b = [UInt8](d); guard b.count >= 2 else { return }
        switch b[1] {
        case 1, 2:
            guard b.count == 2 + 4 + 8 + 8 + 16 else { return }
            let conn = u32(b, 2), sender = Data(b[6..<14]), nonce = Data(b[14..<22]), mac = Data(b[22..<38])
            guard let key = pairKeyFor?(sender), UDPMux.punchMAC(key, conn, sender, nonce) == mac else { return }
            lock.withLock { authorized[from] = Date() }
            if b[1] == 1 {
                onPunch?(sender, from)
                if conn != 0 { send(punchPacket(2, conn: conn, key: key), to: from) }      // ack the initiator
                else { let w = lock.withLock { punchWaiters[0] }; w?(from, sender) }       // responder-punch: initiator learns endpoint
            } else {
                let w = lock.withLock { punchWaiters[conn] }; w?(from, sender)
            }
        case 3, 4, 5:
            guard b.count >= 6 else { return }
            let key = StreamKey(ep: from, conn: u32(b, 2))
            var s = lock.withLock { streams[key] }
            if s == nil, b[1] == 3 {
                // new inbound stream: only from an endpoint that completed an authenticated punch
                guard let t = lock.withLock({ authorized[from] }), Date().timeIntervalSince(t) < 120, let accept = onAccept else { return }
                let ns = UDPStream(mux: self, remote: from, conn: key.conn)
                lock.withLock { streams[key] = ns }; s = ns
                DispatchQueue.global().async { accept(ns) }
            }
            s?.handle(type: b[1], b)
        default: break
        }
    }

    /// Initiator side: open a reliable stream to an endpoint we punched.
    public func openStream(to ep: IPEndpoint, conn: UInt32) -> UDPStream {
        let s = UDPStream(mux: self, remote: ep, conn: conn)
        lock.withLock { streams[StreamKey(ep: ep, conn: conn)] = s }
        return s
    }
    func remove(_ s: UDPStream) { lock.withLock { _ = streams.removeValue(forKey: StreamKey(ep: s.remote, conn: s.conn)) } }
}

/// Reliable, ordered byte stream over UDP (go-back-N ARQ with cumulative ACKs and exponential
/// RTO), carrying length-prefixed frames — a FrameTransport for the Noise session.
public final class UDPStream: FrameTransport, @unchecked Sendable {
    let mux: UDPMux
    public let remote: IPEndpoint
    let conn: UInt32
    public var peerDescription: String { "udp \(remote)" }
    static let segSize = 1100, window: UInt32 = 64

    let cond = NSCondition()
    // sender
    var nextSeq: UInt32 = 0, base: UInt32 = 0
    var unacked: [UInt32: Data] = [:]
    var rto: TimeInterval = 0.3, lastProgress = Date(), lastSend = Date()
    // receiver
    var expected: UInt32 = 0
    var ooo: [UInt32: Data] = [:]
    var inBytes = Data(), frames: [Data] = []
    var closed = false, failed = false

    init(mux: UDPMux, remote: IPEndpoint, conn: UInt32) {
        self.mux = mux; self.remote = remote; self.conn = conn
        Thread { [weak self] in self?.timerLoop() }.start()
    }

    func timerLoop() {
        while true {
            Thread.sleep(forTimeInterval: 0.05)
            cond.lock()
            if closed { cond.unlock(); return }
            if base < nextSeq {
                if Date().timeIntervalSince(lastProgress) > 20 { failed = true; closed = true; cond.broadcast(); cond.unlock(); mux.remove(self); return }
                if Date().timeIntervalSince(lastSend) > rto {
                    let segs = (base..<nextSeq).compactMap { s in unacked[s].map { (s, $0) } }
                    rto = min(rto * 2, 2); lastSend = Date()
                    cond.unlock()
                    for (s, p) in segs { mux.send(dataPacket(s, p), to: remote) }
                    continue
                }
            }
            cond.unlock()
        }
    }

    func dataPacket(_ seq: UInt32, _ p: Data) -> Data { Data([0xA7, 3]) + be32(conn) + be32(seq) + p }

    func handle(type: UInt8, _ b: [UInt8]) {
        switch type {
        case 3:
            guard b.count >= 10 else { return }
            let seq = u32(b, 6), payload = Data(b[10...])
            cond.lock()
            if seq == expected {
                inBytes += payload; expected &+= 1
                while let n = ooo.removeValue(forKey: expected) { inBytes += n; expected &+= 1 }
                parseFrames()
            } else if seq > expected && seq < expected &+ 512 { ooo[seq] = payload }
            let ack = expected
            cond.broadcast(); cond.unlock()
            mux.send(Data([0xA7, 4]) + be32(conn) + be32(ack), to: remote)
        case 4:
            guard b.count >= 10 else { return }
            let cum = u32(b, 6)
            cond.lock()
            if cum > base && cum <= nextSeq {
                for s in base..<cum { unacked[s] = nil }
                base = cum; rto = 0.3; lastProgress = Date()
                cond.broadcast()
            }
            cond.unlock()
        case 5:
            cond.lock(); closed = true; cond.broadcast(); cond.unlock(); mux.remove(self)
        default: break
        }
    }

    func parseFrames() {
        while inBytes.count >= 4 {
            let b = [UInt8](inBytes.prefix(4))
            let len = Int(b[0]) << 24 | Int(b[1]) << 16 | Int(b[2]) << 8 | Int(b[3])
            guard len <= maxFrameSize else { failed = true; closed = true; return }
            guard inBytes.count >= 4 + len else { return }
            frames.append(Data(inBytes[inBytes.startIndex + 4 ..< inBytes.startIndex + 4 + len]))
            inBytes = Data(inBytes.dropFirst(4 + len))
        }
    }

    public func send(_ frame: Data) throws {
        guard frame.count <= maxFrameSize else { throw TransportError.frameTooLarge }
        let len = UInt32(frame.count)
        let bytes = be32(len) + frame
        var off = 0
        while off < bytes.count {
            let chunk = Data(bytes[off..<min(off + UDPStream.segSize, bytes.count)])
            cond.lock()
            while nextSeq - base >= UDPStream.window && !closed {
                if !cond.wait(until: Date().addingTimeInterval(1)) && Date().timeIntervalSince(lastProgress) > 20 { closed = true; failed = true }
            }
            if closed { cond.unlock(); throw TransportError.closed }
            let s = nextSeq; nextSeq &+= 1; unacked[s] = chunk
            if base == s { lastProgress = Date() }
            lastSend = Date()
            cond.unlock()
            mux.send(dataPacket(s, chunk), to: remote)
            off += chunk.count
        }
    }

    public func receive(timeout: TimeInterval) throws -> Data {
        let dl = Date().addingTimeInterval(timeout)
        cond.lock(); defer { cond.unlock() }
        while frames.isEmpty {
            if closed { throw TransportError.closed }
            if !cond.wait(until: dl) && frames.isEmpty { throw TransportError.timeout }
        }
        return frames.removeFirst()
    }

    public func close() {
        cond.lock()
        // give in-flight data a moment to be acknowledged
        let end = Date().addingTimeInterval(2)
        while base < nextSeq && !closed && Date() < end { _ = cond.wait(until: Date().addingTimeInterval(0.05)) }
        let was = closed; closed = true; cond.broadcast(); cond.unlock()
        if !was { for _ in 0..<3 { mux.send(Data([0xA7, 5]) + be32(conn), to: remote) } }
        mux.remove(self)
    }
}
