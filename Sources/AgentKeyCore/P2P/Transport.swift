import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// A reliable, ordered, message-framed byte pipe (TCP, Bonjour/NWConnection, Multipeer, in-memory).
/// Blocking API; sessions run on their own threads.
public protocol FrameTransport: AnyObject {
    func send(_ frame: Data) throws
    func receive(timeout: TimeInterval) throws -> Data
    func close()
    var peerDescription: String { get }
}

public enum TransportError: Error, Equatable { case closed, timeout, frameTooLarge, connectFailed(String) }

public let maxFrameSize = 8 << 20

/// In-process transport pair (tests, same-process replicas). Optional tap lets tests act as a MITM.
public final class MemoryTransport: FrameTransport, @unchecked Sendable {
    final class Queue: @unchecked Sendable {
        let cond = NSCondition(); var items: [Data] = []; var closed = false
    }
    let inbox: Queue, outbox: Queue
    public var tap: ((Data) -> Data?)?          // modify/drop outgoing frames (nil = drop)
    public let peerDescription: String
    init(inbox: Queue, outbox: Queue, name: String) { self.inbox = inbox; self.outbox = outbox; peerDescription = name }

    public static func pair() -> (MemoryTransport, MemoryTransport) {
        let a = Queue(), b = Queue()
        return (MemoryTransport(inbox: a, outbox: b, name: "mem:b"), MemoryTransport(inbox: b, outbox: a, name: "mem:a"))
    }
    public func send(_ frame: Data) throws {
        guard frame.count <= maxFrameSize else { throw TransportError.frameTooLarge }
        let f = tap.map { $0(frame) } ?? frame
        outbox.cond.lock(); defer { outbox.cond.unlock() }
        if outbox.closed { throw TransportError.closed }
        if let f { outbox.items.append(f); outbox.cond.signal() }
    }
    /// Inject a raw frame into the peer's inbox (tests: replay attacks).
    public func inject(_ frame: Data) { outbox.cond.lock(); outbox.items.append(frame); outbox.cond.signal(); outbox.cond.unlock() }
    public func receive(timeout: TimeInterval) throws -> Data {
        let deadline = Date().addingTimeInterval(timeout)
        inbox.cond.lock(); defer { inbox.cond.unlock() }
        while inbox.items.isEmpty {
            if inbox.closed { throw TransportError.closed }
            if !inbox.cond.wait(until: deadline) { throw TransportError.timeout }
        }
        return inbox.items.removeFirst()
    }
    public func close() {
        for q in [inbox, outbox] { q.cond.lock(); q.closed = true; q.cond.broadcast(); q.cond.unlock() }
    }
}

/// Plain TCP with 4-byte big-endian length framing. Use it on the LAN, or for remote access over
/// a user-run Tailscale / WireGuard network. All payloads are already Noise-encrypted.
public final class TCPTransport: FrameTransport, @unchecked Sendable {
    let fd: Int32
    public let peerDescription: String
    var closed = false
    init(fd: Int32, peer: String) { self.fd = fd; peerDescription = peer
        var one: Int32 = 1
        setsockopt(fd, Int32(IPPROTO_TCP), TCP_NODELAY, &one, socklen_t(MemoryLayout<Int32>.size))
    }
    deinit { close() }

    public static func connect(host: String, port: UInt16, timeout: TimeInterval = 10) throws -> TCPTransport {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        #if canImport(Darwin)
        hints.ai_socktype = SOCK_STREAM
        #else
        hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
        #endif
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &res) == 0, let first = res else { throw TransportError.connectFailed("resolve \(host)") }
        defer { freeaddrinfo(res) }
        var p: UnsafeMutablePointer<addrinfo>? = first
        while let ai = p {
            let fd = socket(ai.pointee.ai_family, ai.pointee.ai_socktype, ai.pointee.ai_protocol)
            if fd >= 0 {
                #if canImport(Darwin)
                let rc = Darwin.connect(fd, ai.pointee.ai_addr, ai.pointee.ai_addrlen)
                #else
                let rc = Glibc.connect(fd, ai.pointee.ai_addr, ai.pointee.ai_addrlen)
                #endif
                if rc == 0 { return TCPTransport(fd: fd, peer: "\(host):\(port)") }
                Darwin_or_Glibc_close(fd)
            }
            p = ai.pointee.ai_next
        }
        throw TransportError.connectFailed("\(host):\(port): \(String(cString: strerror(errno)))")
    }

    func writeAll(_ d: Data) throws {
        try d.withUnsafeBytes { b in
            var off = 0
            while off < b.count {
                let n = write(fd, b.baseAddress! + off, b.count - off)
                if n < 0 { if errno == EINTR { continue }; throw TransportError.closed }
                off += n
            }
        }
    }
    func readExactly(_ n: Int, deadline: Date) throws -> Data {
        var out = Data(count: n), off = 0
        while off < n {
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ms = Int32(max(0, deadline.timeIntervalSinceNow * 1000))
            let pr = poll(&pfd, 1, ms)
            if pr == 0 { throw TransportError.timeout }
            if pr < 0 { if errno == EINTR { continue }; throw TransportError.closed }
            let r = out.withUnsafeMutableBytes { read(fd, $0.baseAddress! + off, n - off) }
            if r <= 0 { if r < 0 && errno == EINTR { continue }; throw TransportError.closed }
            off += r
        }
        return out
    }
    public func send(_ frame: Data) throws {
        guard frame.count <= maxFrameSize else { throw TransportError.frameTooLarge }
        let len = UInt32(frame.count)
        try writeAll(Data([UInt8(len >> 24), UInt8((len >> 16) & 0xff), UInt8((len >> 8) & 0xff), UInt8(len & 0xff)]) + frame)
    }
    public func receive(timeout: TimeInterval) throws -> Data {
        let dl = Date().addingTimeInterval(timeout)
        let h = try readExactly(4, deadline: dl)
        let len = Int(h[0]) << 24 | Int(h[1]) << 16 | Int(h[2]) << 8 | Int(h[3])
        guard len <= maxFrameSize else { throw TransportError.frameTooLarge }
        return try readExactly(len, deadline: dl)
    }
    public func close() { if !closed { closed = true; shutdown(fd, Int32(SHUT_RDWR)); Darwin_or_Glibc_close(fd) } }
}

@inline(__always) func Darwin_or_Glibc_close(_ fd: Int32) {
    #if canImport(Darwin)
    _ = Darwin.close(fd)
    #else
    _ = Glibc.close(fd)
    #endif
}

public final class TCPListener: @unchecked Sendable {
    let fd: Int32
    public let port: UInt16

    /// Bind to `host` (default all interfaces) and `port` (0 = ephemeral).
    public init(host: String = "0.0.0.0", port: UInt16 = 0) throws {
        #if canImport(Darwin)
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        #else
        let fd = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        #endif
        self.fd = fd
        guard fd >= 0 else { throw TransportError.connectFailed("socket") }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        var a = sockaddr_in()
        a.sin_family = sa_family_t(AF_INET)
        a.sin_port = port.bigEndian
        inet_pton(AF_INET, host, &a.sin_addr)
        let rc = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard rc == 0, listen(fd, 16) == 0 else { Darwin_or_Glibc_close(fd); throw TransportError.connectFailed("bind \(host):\(port)") }
        var b = sockaddr_in(); var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &b) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        self.port = UInt16(bigEndian: b.sin_port)
    }
    public func accept() throws -> TCPTransport {
        while true {
            #if canImport(Darwin)
            let c = Darwin.accept(fd, nil, nil)
            #else
            let c = Glibc.accept(fd, nil, nil)
            #endif
            if c >= 0 { return TCPTransport(fd: c, peer: "tcp-client") }
            if errno == EINTR { continue }
            throw TransportError.closed
        }
    }
    public func close() { shutdown(fd, Int32(SHUT_RDWR)); Darwin_or_Glibc_close(fd) }
}
