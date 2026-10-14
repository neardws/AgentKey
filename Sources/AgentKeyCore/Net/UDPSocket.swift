import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// An IP endpoint (v4 or v6). `description` uses `[v6]:port` for IPv6.
public struct IPEndpoint: Hashable, Codable, Sendable, CustomStringConvertible {
    public var host: String
    public var port: UInt16
    public init(host: String, port: UInt16) {
        var h = host
        if h.hasPrefix("[") && h.hasSuffix("]") { h = String(h.dropFirst().dropLast()) }
        if h.hasPrefix("::ffff:"), h.contains(".") { h = String(h.dropFirst(7)) }   // v4-mapped → v4
        self.host = h; self.port = port
    }
    public var isIPv6: Bool { host.contains(":") }
    public var description: String { isIPv6 ? "[\(host)]:\(port)" : "\(host):\(port)" }

    /// Parse "1.2.3.4:5", "[2408::1]:5", "name:5".
    public init?(_ s: String) {
        if s.hasPrefix("["), let close = s.firstIndex(of: "]") {
            let h = String(s[s.index(after: s.startIndex)..<close])
            let rest = s[s.index(after: close)...]
            guard rest.hasPrefix(":"), let p = UInt16(rest.dropFirst()) else { return nil }
            self.init(host: h, port: p); return
        }
        guard let i = s.lastIndex(of: ":"), let p = UInt16(s[s.index(after: i)...]) else { return nil }
        let h = String(s[..<i]); guard !h.contains(":") else { return nil }
        self.init(host: h, port: p)
    }

    /// Global-unicast IPv6 (2000::/3) — candidate for direct connection without NAT.
    public var isGlobalIPv6: Bool {
        guard isIPv6, let f = host.split(separator: ":").first, let v = UInt16(f, radix: 16) else { return false }
        return v & 0xE000 == 0x2000
    }
    public var isPrivateV4: Bool {
        let p = host.split(separator: ".").compactMap { Int($0) }
        guard p.count == 4 else { return false }
        return p[0] == 10 || (p[0] == 172 && (16...31).contains(p[1])) || (p[0] == 192 && p[1] == 168) || (p[0] == 100 && (64...127).contains(p[1])) || p[0] == 127
    }

    func withSockaddr<T>(_ f: (UnsafePointer<sockaddr>, socklen_t) throws -> T) throws -> T {
        if isIPv6 {
            var a = sockaddr_in6()
            #if canImport(Darwin)
            a.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            #endif
            a.sin6_family = sa_family_t(AF_INET6); a.sin6_port = port.bigEndian
            guard inet_pton(AF_INET6, host, &a.sin6_addr) == 1 else { throw UDPError.badAddress(host) }
            return try withUnsafePointer(to: &a) { try $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { try f($0, socklen_t(MemoryLayout<sockaddr_in6>.size)) } }
        } else {
            var a = sockaddr_in()
            #if canImport(Darwin)
            a.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            #endif
            a.sin_family = sa_family_t(AF_INET); a.sin_port = port.bigEndian
            guard inet_pton(AF_INET, host, &a.sin_addr) == 1 else { throw UDPError.badAddress(host) }
            return try withUnsafePointer(to: &a) { try $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { try f($0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        }
    }

    static func from(_ ss: sockaddr_storage) -> IPEndpoint? {
        var s = ss
        switch Int32(s.ss_family) {
        case AF_INET:
            return withUnsafePointer(to: &s) { $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { p in
                var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN)); var addr = p.pointee.sin_addr
                inet_ntop(AF_INET, &addr, &buf, socklen_t(buf.count))
                return IPEndpoint(host: String(cString: buf), port: UInt16(bigEndian: p.pointee.sin_port)) } }
        case AF_INET6:
            return withUnsafePointer(to: &s) { $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { p in
                var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN)); var addr = p.pointee.sin6_addr
                inet_ntop(AF_INET6, &addr, &buf, socklen_t(buf.count))
                return IPEndpoint(host: String(cString: buf), port: UInt16(bigEndian: p.pointee.sin6_port)) } }
        default: return nil
        }
    }

    /// Resolve a hostname (A/AAAA) to endpoints.
    public static func resolve(_ host: String, port: UInt16, udp: Bool = true) -> [IPEndpoint] {
        var hints = addrinfo(); hints.ai_family = AF_UNSPEC
        #if canImport(Darwin)
        hints.ai_socktype = udp ? SOCK_DGRAM : SOCK_STREAM
        #else
        hints.ai_socktype = Int32((udp ? SOCK_DGRAM : SOCK_STREAM).rawValue)
        #endif
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &res) == 0, let first = res else { return [] }
        defer { freeaddrinfo(res) }
        var out: [IPEndpoint] = []; var p: UnsafeMutablePointer<addrinfo>? = first
        while let ai = p {
            var ss = sockaddr_storage()
            memcpy(&ss, ai.pointee.ai_addr, Int(ai.pointee.ai_addrlen))
            if let e = from(ss), !out.contains(e) { out.append(e) }
            p = ai.pointee.ai_next
        }
        return out
    }
}

public enum UDPError: Error, Equatable { case badAddress(String), socket(String), timeout, closed }

/// Minimal blocking UDP socket, dual-stack (IPv6 socket with V6ONLY=0) unless `v4Only`.
/// Sending to an IPv4 endpoint from a dual-stack socket uses the v4-mapped form.
public final class UDPSocket: @unchecked Sendable {
    public let fd: Int32
    public let isDualStack: Bool
    public private(set) var localPort: UInt16 = 0
    private var closed = false

    public init(port: UInt16 = 0, v4Only: Bool = false, bindHost: String? = nil) throws {
        #if canImport(Darwin)
        let dgram = SOCK_DGRAM
        #else
        let dgram = Int32(SOCK_DGRAM.rawValue)
        #endif
        var fd: Int32 = -1, dual = false
        if !v4Only && (bindHost == nil || bindHost!.contains(":")) {
            fd = socket(AF_INET6, dgram, 0)
            if fd >= 0 { var zero: Int32 = 0; setsockopt(fd, Int32(IPPROTO_IPV6), IPV6_V6ONLY, &zero, socklen_t(MemoryLayout<Int32>.size)); dual = true }
        }
        if fd < 0 { fd = socket(AF_INET, dgram, 0); dual = false }
        guard fd >= 0 else { throw UDPError.socket("socket: \(String(cString: strerror(errno)))") }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        self.fd = fd; self.isDualStack = dual
        let bindEP = IPEndpoint(host: bindHost ?? (dual ? "::" : "0.0.0.0"), port: port)
        let rc = try bindEP.withSockaddr { bind(fd, $0, $1) }
        guard rc == 0 else { let e = String(cString: strerror(errno)); Darwin_or_Glibc_close(fd); throw UDPError.socket("bind \(bindEP): \(e)") }
        var ss = sockaddr_storage(); var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
        _ = withUnsafeMutablePointer(to: &ss) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        localPort = IPEndpoint.from(ss)?.port ?? 0
    }
    deinit { close() }

    func mapped(_ e: IPEndpoint) -> IPEndpoint {
        (isDualStack && !e.isIPv6) ? IPEndpoint(host: "::ffff:" + e.host, port: e.port).withRawHost("::ffff:" + e.host) : e
    }

    public func send(_ d: Data, to e: IPEndpoint) throws {
        let target = mapped(e)
        let n = try target.withSockaddr { sa, len in d.withUnsafeBytes { sendto(fd, $0.baseAddress, d.count, 0, sa, len) } }
        if n < 0 { throw UDPError.socket("sendto \(e): \(String(cString: strerror(errno)))") }
    }

    /// Receive one datagram or throw `.timeout`.
    public func receive(timeout: TimeInterval) throws -> (Data, IPEndpoint) {
        let dl = Date().addingTimeInterval(timeout)
        while true {
            if closed { throw UDPError.closed }
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ms = Int32(max(0, min(dl.timeIntervalSinceNow, 0.5) * 1000))
            let pr = poll(&pfd, 1, ms)
            if pr < 0 { if errno == EINTR { continue }; throw UDPError.closed }
            if pr == 0 { if Date() >= dl { throw UDPError.timeout }; continue }
            var buf = [UInt8](repeating: 0, count: 65536)
            var ss = sockaddr_storage(); var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let n = withUnsafeMutablePointer(to: &ss) { p in p.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fd, &buf, buf.count, 0, $0, &len) } }
            if n < 0 { if errno == EINTR || errno == EAGAIN { continue }; if closed { throw UDPError.closed }; continue }  // ICMP errors etc.
            guard let from = IPEndpoint.from(ss) else { continue }
            return (Data(buf[0..<n]), from)
        }
    }

    public func close() { if !closed { closed = true; shutdown(fd, Int32(SHUT_RDWR)); Darwin_or_Glibc_close(fd) } }
}

extension IPEndpoint {
    /// Keep the raw host string (used for v4-mapped addresses, which `init` would normalise away).
    func withRawHost(_ h: String) -> IPEndpoint { var e = self; e.host = h; return e }
}
