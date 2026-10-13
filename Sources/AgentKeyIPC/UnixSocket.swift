import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

public enum SocketError: Error, CustomStringConvertible {
    case sys(String, Int32), pathTooLong, closed, frameTooLarge
    public var description: String {
        switch self {
        case .sys(let w, let e): return "\(w): \(String(cString: strerror(e)))"
        case .pathTooLong: return "socket path too long (must be < 104 bytes)"
        case .closed: return "connection closed"
        case .frameTooLarge: return "frame too large"
        }
    }
}

public final class UnixConnection: @unchecked Sendable {
    public let fd: Int32
    public init(fd: Int32) { self.fd = fd }
    deinit { close(fd) }

    public func writeAll(_ d: Data) throws {
        try d.withUnsafeBytes { buf in
            var off = 0
            while off < buf.count {
                let n = write(fd, buf.baseAddress! + off, buf.count - off)
                if n < 0 { if errno == EINTR { continue }; throw SocketError.sys("write", errno) }
                off += n
            }
        }
    }

    func readExactly(_ n: Int) throws -> Data {
        var out = Data(count: n); var off = 0
        try out.withUnsafeMutableBytes { buf in
            while off < n {
                let r = read(fd, buf.baseAddress! + off, n - off)
                if r < 0 { if errno == EINTR { continue }; throw SocketError.sys("read", errno) }
                if r == 0 { throw SocketError.closed }
                off += r
            }
        }
        return out
    }

    public func readFrame() throws -> Data {
        let h = try readExactly(4)
        let len = Int(UInt32(h[0]) << 24 | UInt32(h[1]) << 16 | UInt32(h[2]) << 8 | UInt32(h[3]))
        guard len <= IPC.maxFrame else { throw SocketError.frameTooLarge }
        return try readExactly(len)
    }

    public func send<T: Encodable>(_ v: T) throws { try writeAll(try Frame.encode(v)) }

    /// Peer credentials (uid, pid) of the connected process.
    public func peer() -> (uid: UInt32, pid: Int32?) {
        #if canImport(Darwin)
        var uid: uid_t = 0, gid: gid_t = 0
        _ = getpeereid(fd, &uid, &gid)
        var pid: pid_t = 0; var len = socklen_t(MemoryLayout<pid_t>.size)
        let ok = getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &len) == 0
        return (uid, ok ? pid : nil)
        #else
        // struct ucred { pid_t pid; uid_t uid; gid_t gid; } — SO_PEERCRED = 17 (not exported without _GNU_SOURCE)
        var cred = [Int32](repeating: -1, count: 3); var len = socklen_t(12)
        guard getsockopt(fd, SOL_SOCKET, 17, &cred, &len) == 0 else { return (UInt32.max, nil) }
        return (UInt32(bitPattern: cred[1]), cred[0])
        #endif
    }
}

enum SockAddr {
    static func make(_ path: String) throws -> sockaddr_un {
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else { throw SocketError.pathTooLong }
        withUnsafeMutableBytes(of: &addr.sun_path) { p in
            for (i, b) in bytes.enumerated() { p[i] = b }
            p[bytes.count] = 0
        }
        return addr
    }
    static var streamType: Int32 {
        #if canImport(Darwin)
        return SOCK_STREAM
        #else
        return Int32(SOCK_STREAM.rawValue)
        #endif
    }
}

public final class UnixListener: @unchecked Sendable {
    public let fd: Int32
    public let path: String

    /// Binds with umask 0177 so the socket is created 0600, inside a 0700 directory.
    public init(path: String) throws {
        self.path = path
        let dir = (path as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        chmod(dir, 0o700)
        unlink(path)
        fd = socket(AF_UNIX, SockAddr.streamType, 0)
        guard fd >= 0 else { throw SocketError.sys("socket", errno) }
        var addr = try SockAddr.make(path)
        let old = umask(0o177)
        let rc = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        umask(old)
        guard rc == 0 else { throw SocketError.sys("bind", errno) }
        chmod(path, 0o600)
        guard listen(fd, 16) == 0 else { throw SocketError.sys("listen", errno) }
    }

    public func accept() throws -> UnixConnection {
        while true {
            let c = Glibc_or_Darwin_accept(fd)
            if c >= 0 { return UnixConnection(fd: c) }
            if errno == EINTR { continue }
            throw SocketError.sys("accept", errno)
        }
    }
    deinit { close(fd); unlink(path) }
}

@inline(__always) func Glibc_or_Darwin_accept(_ fd: Int32) -> Int32 {
    #if canImport(Darwin)
    return Darwin.accept(fd, nil, nil)
    #else
    return Glibc.accept(fd, nil, nil)
    #endif
}

public enum UnixClient {
    public static func connect(path: String) throws -> UnixConnection {
        let fd = socket(AF_UNIX, SockAddr.streamType, 0)
        guard fd >= 0 else { throw SocketError.sys("socket", errno) }
        var addr = try SockAddr.make(path)
        let rc = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            #if canImport(Darwin)
            Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            #else
            Glibc.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            #endif
        } }
        guard rc == 0 else { let e = errno; close(fd); throw SocketError.sys("connect \(path)", e) }
        return UnixConnection(fd: fd)
    }
}
