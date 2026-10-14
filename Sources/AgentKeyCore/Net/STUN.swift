import Foundation

/// Minimal STUN (RFC 5389 / 8489) — Binding requests only, enough to learn our server-reflexive
/// address and estimate the NAT mapping behaviour. No TURN, no auth on requests.
public enum STUN {
    public static let magicCookie: UInt32 = 0x2112A442
    public static let bindingRequest: UInt16 = 0x0001, bindingSuccess: UInt16 = 0x0101, bindingError: UInt16 = 0x0111
    enum Attr { static let mapped: UInt16 = 0x0001, username: UInt16 = 0x0006, integrity: UInt16 = 0x0008,
                errorCode: UInt16 = 0x0009, xorMapped: UInt16 = 0x0020, software: UInt16 = 0x8022, fingerprint: UInt16 = 0x8028 }

    /// Defaults: public servers on different networks, incl. ones reachable from mainland China.
    /// Configurable in sync/net.json. Only a binding request is sent: no identity, no vault data.
    public static let defaultServers = ["stun.l.google.com:19302", "stun.cloudflare.com:3478", "stun.miwifi.com:3478", "stun.qq.com:3478"]

    public struct Message: Equatable {
        public var type: UInt16
        public var transactionID: Data      // 12 bytes
        public var attributes: [(UInt16, Data)]
        public static func == (a: Message, b: Message) -> Bool {
            a.type == b.type && a.transactionID == b.transactionID && a.attributes.map(\.0) == b.attributes.map(\.0) && a.attributes.map(\.1) == b.attributes.map(\.1)
        }
        public init(type: UInt16, transactionID: Data = AKRandom.bytes(12), attributes: [(UInt16, Data)] = []) {
            self.type = type; self.transactionID = transactionID; self.attributes = attributes
        }

        public func encode(fingerprint: Bool = true) -> Data {
            var body = Data()
            for (t, v) in attributes { body += attr(t, v) }
            var d = header(length: body.count + (fingerprint ? 8 : 0)) + body
            if fingerprint { d += attr(Attr.fingerprint, be32(STUN.crc32(d) ^ 0x5354554E)) }
            return d
        }
        func header(length: Int) -> Data { be16(type) + be16(UInt16(length)) + be32(STUN.magicCookie) + transactionID }

        public static func decode(_ d: Data) throws -> Message {
            let b = [UInt8](d)
            guard b.count >= 20, b[0] & 0xC0 == 0 else { throw STUNError.malformed("header") }
            let len = Int(u16(b, 2))
            guard u32(b, 4) == STUN.magicCookie, len % 4 == 0, b.count == 20 + len else { throw STUNError.malformed("cookie/length") }
            var attrs: [(UInt16, Data)] = []; var i = 20
            while i + 4 <= b.count {
                let t = u16(b, i), l = Int(u16(b, i + 2))
                guard i + 4 + l <= b.count else { throw STUNError.malformed("attr length") }
                attrs.append((t, Data(b[(i + 4)..<(i + 4 + l)])))
                i += 4 + ((l + 3) & ~3)
            }
            return Message(type: u16(b, 0), transactionID: Data(b[8..<20]), attributes: attrs)
        }

        public func attribute(_ t: UInt16) -> Data? { attributes.first { $0.0 == t }?.1 }

        /// XOR-MAPPED-ADDRESS (preferred) or MAPPED-ADDRESS.
        public var mappedAddress: IPEndpoint? {
            if let x = attribute(Attr.xorMapped) { return STUN.decodeAddress(x, xor: true, tid: transactionID) }
            if let m = attribute(Attr.mapped) { return STUN.decodeAddress(m, xor: false, tid: transactionID) }
            return nil
        }
    }

    /// Verify FINGERPRINT (CRC-32 of the message up to the attribute, XOR 0x5354554E).
    public static func verifyFingerprint(_ d: Data) -> Bool {
        let b = [UInt8](d); guard b.count >= 28 else { return false }
        let at = b.count - 8
        guard u16(b, at) == Attr.fingerprint, u16(b, at + 2) == 4 else { return false }
        return crc32(Data(b[0..<at])) ^ 0x5354554E == u32(b, at + 4)
    }

    /// Verify MESSAGE-INTEGRITY (HMAC-SHA1, short-term credential key = password), RFC 5389 §15.4.
    public static func verifyIntegrity(_ d: Data, key: Data) -> Bool {
        let b = [UInt8](d); var i = 20
        while i + 4 <= b.count {
            let t = u16(b, i), l = Int(u16(b, i + 2))
            if t == Attr.integrity, l == 20, i + 24 <= b.count {
                var pre = Data(b[0..<i])
                let adj = UInt16(i + 24 - 20)          // length as if MESSAGE-INTEGRITY were last
                pre[2] = UInt8(adj >> 8); pre[3] = UInt8(adj & 0xff)
                let mac = HMAC<Insecure.SHA1>.authenticationCode(for: pre, using: SymmetricKey(data: key))
                return Data(mac) == Data(b[(i + 4)..<(i + 24)])
            }
            i += 4 + ((l + 3) & ~3)
        }
        return false
    }

    static func decodeAddress(_ v: Data, xor: Bool, tid: Data) -> IPEndpoint? {
        let b = [UInt8](v); guard b.count >= 8 else { return nil }
        var port = u16(b, 2); if xor { port ^= UInt16(magicCookie >> 16) }
        let mask = [UInt8](be32(magicCookie) + tid)
        switch b[1] {
        case 0x01:
            var a = Array(b[4..<8]); if xor { for k in 0..<4 { a[k] ^= mask[k] } }
            return IPEndpoint(host: a.map(String.init).joined(separator: "."), port: port)
        case 0x02:
            guard b.count >= 20 else { return nil }
            var a = Array(b[4..<20]); if xor { for k in 0..<16 { a[k] ^= mask[k] } }
            let groups = stride(from: 0, to: 16, by: 2).map { String(UInt16(a[$0]) << 8 | UInt16(a[$0 + 1]), radix: 16) }
            var buf = [CChar](repeating: 0, count: 64); var in6 = in6_addr()
            withUnsafeMutableBytes(of: &in6) { for k in 0..<16 { $0[k] = a[k] } }
            if inet_ntop(AF_INET6, &in6, &buf, 64) != nil { return IPEndpoint(host: String(cString: buf), port: port) }
            return IPEndpoint(host: groups.joined(separator: ":"), port: port)
        default: return nil
        }
    }

    public static func encodeXorAddress(_ e: IPEndpoint, tid: Data) -> Data {
        let mask = [UInt8](be32(magicCookie) + tid)
        var out = Data([0, e.isIPv6 ? 2 : 1]) + be16(e.port ^ UInt16(magicCookie >> 16))
        if e.isIPv6 {
            var in6 = in6_addr(); inet_pton(AF_INET6, e.host, &in6)
            let a = withUnsafeBytes(of: &in6) { Array($0) }
            out += Data((0..<16).map { a[$0] ^ mask[$0] })
        } else {
            let a = e.host.split(separator: ".").compactMap { UInt8($0) }
            out += Data((0..<4).map { a[$0] ^ mask[$0] })
        }
        return out
    }

    // MARK: CRC-32 (IEEE, as used by STUN FINGERPRINT)
    static let crcTable: [UInt32] = (0..<256).map { i -> UInt32 in
        var c = UInt32(i); for _ in 0..<8 { c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1 }; return c
    }
    public static func crc32(_ d: Data) -> UInt32 {
        var c: UInt32 = 0xFFFFFFFF
        for b in d { c = crcTable[Int((c ^ UInt32(b)) & 0xff)] ^ (c >> 8) }
        return c ^ 0xFFFFFFFF
    }
}

public enum STUNError: Error, Equatable { case malformed(String), noResponse, errorResponse(Int) }

func attr(_ t: UInt16, _ v: Data) -> Data {
    var d = be16(t) + be16(UInt16(v.count)) + v
    while d.count % 4 != 0 { d.append(0) }
    return d
}
func be16(_ v: UInt16) -> Data { Data([UInt8(v >> 8), UInt8(v & 0xff)]) }
func be32(_ v: UInt32) -> Data { Data([UInt8(v >> 24), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)]) }
func u16(_ b: [UInt8], _ i: Int) -> UInt16 { UInt16(b[i]) << 8 | UInt16(b[i + 1]) }
func u32(_ b: [UInt8], _ i: Int) -> UInt32 { UInt32(b[i]) << 24 | UInt32(b[i + 1]) << 16 | UInt32(b[i + 2]) << 8 | UInt32(b[i + 3]) }

// MARK: client + NAT estimate

public struct STUNResult: Codable, Sendable {
    public var server: String
    public var serverAddress: String?
    public var mapped: String?
    public var rttMs: Int?
    public var error: String?
}

public enum NATType: String, Codable, Sendable {
    case open = "open"                                   // mapped == local (public IP on the interface)
    case endpointIndependent = "endpoint-independent"    // same mapping for every server: hole punching works well
    case endpointDependent = "endpoint-dependent"        // "symmetric": different port per destination; punching unlikely
    case udpBlocked = "udp-blocked"                      // no STUN answers at all (or a proxy/VPN eats UDP)
    case unknown = "unknown"                             // only one answer
}

public enum STUNClient {
    /// Send binding requests from `socket` to each server; returns results in server order.
    /// The socket is shared with hole punching so the learned mapping is the one peers should use.
    public static func probe(socket: UDPSocket, servers: [String] = STUN.defaultServers, timeout: TimeInterval = 1.5, retries: Int = 2) -> [STUNResult] {
        servers.map { s in
            var r = STUNResult(server: s)
            guard let hp = IPEndpoint(s) ?? splitHostPort(s).flatMap({ IPEndpoint.resolve($0.0, port: $0.1).first(where: { !$0.isIPv6 || socket.isDualStack }) }) else {
                r.error = "resolve failed"; return r
            }
            r.serverAddress = hp.description
            for _ in 0...retries {
                let req = STUN.Message(type: STUN.bindingRequest)
                let t0 = Date()
                do {
                    try socket.send(req.encode(), to: hp)
                    let dl = Date().addingTimeInterval(timeout)
                    while Date() < dl {
                        let (d, _) = try socket.receive(timeout: dl.timeIntervalSinceNow)
                        guard let m = try? STUN.Message.decode(d), m.transactionID == req.transactionID else { continue }
                        if m.type == STUN.bindingSuccess, let a = m.mappedAddress {
                            r.mapped = a.description; r.rttMs = Int(Date().timeIntervalSince(t0) * 1000); r.error = nil; return r
                        }
                        r.error = "error response"; break
                    }
                } catch { r.error = "\(error)" }
            }
            if r.error == nil { r.error = "no response" }
            return r
        }
    }

    public static func estimate(_ results: [STUNResult], localAddresses: [String], localPort: UInt16) -> NATType {
        let mapped = results.compactMap { $0.mapped.flatMap(IPEndpoint.init) }
        if mapped.isEmpty { return .udpBlocked }
        if mapped.contains(where: { m in m.port == localPort && localAddresses.contains(m.host) }) { return .open }
        let v4 = mapped.filter { !$0.isIPv6 }
        if v4.count < 2 { return .unknown }
        return Set(v4).count == 1 ? .endpointIndependent : .endpointDependent
    }

    static func splitHostPort(_ s: String) -> (String, UInt16)? {
        guard let i = s.lastIndex(of: ":"), let p = UInt16(s[s.index(after: i)...]) else { return nil }
        return (String(s[..<i]), p)
    }
}
