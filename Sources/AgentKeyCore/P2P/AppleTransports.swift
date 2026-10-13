// Apple-only transports for P2P sync. Same FrameTransport contract as TCPTransport
// (4-byte big-endian length + frame); the Noise channel runs on top, so these only move bytes.
// STATUS: written against the Network.framework / MultipeerConnectivity APIs but NOT compiled or
// run on a Mac yet — everything here is TODO(mac). Linux builds use TCPTransport/TCPListener.
#if canImport(Network)
import Foundation
import Network

public enum Bonjour {
    /// Service type advertised by the home node (and by any device that serves sync).
    public static let serviceType = "_agentkey._tcp"
    /// TXT record carries only non-secret routing hints: protocol version + node fingerprint prefix.
    public static func txt(fingerprint: String) -> NWTXTRecord {
        var t = NWTXTRecord(); t["v"] = "1"; t["fp"] = String(fingerprint.prefix(9)); return t
    }
}

/// FrameTransport over an NWConnection (TCP). TODO(mac): verify on device; tune timeouts.
public final class NWFrameTransport: FrameTransport, @unchecked Sendable {
    let conn: NWConnection
    let queue = DispatchQueue(label: "agentkey.nw")
    public var peerDescription: String { "\(conn.endpoint)" }

    public init(_ conn: NWConnection) { self.conn = conn }

    public static func connect(_ endpoint: NWEndpoint, timeout: TimeInterval = 10) throws -> NWFrameTransport {
        let t = NWFrameTransport(NWConnection(to: endpoint, using: .tcp))
        try t.start(timeout: timeout); return t
    }

    func start(timeout: TimeInterval) throws {
        let sem = DispatchSemaphore(value: 0); var err: Error?
        conn.stateUpdateHandler = { st in
            switch st {
            case .ready: sem.signal()
            case .failed(let e), .waiting(let e): err = e; sem.signal()
            default: break
            }
        }
        conn.start(queue: queue)
        guard sem.wait(timeout: .now() + timeout) == .success else { conn.cancel(); throw TransportError.timeout }
        conn.stateUpdateHandler = nil
        if let err { conn.cancel(); throw TransportError.connectFailed("\(err)") }
    }

    public func send(_ frame: Data) throws {
        guard frame.count <= maxFrameSize else { throw TransportError.frameTooLarge }
        var len = UInt32(frame.count).bigEndian
        let d = Data(bytes: &len, count: 4) + frame
        let sem = DispatchSemaphore(value: 0); var err: Error?
        conn.send(content: d, completion: .contentProcessed { e in err = e; sem.signal() })
        sem.wait()
        if err != nil { throw TransportError.closed }
    }

    func read(_ n: Int, timeout: TimeInterval) throws -> Data {
        let sem = DispatchSemaphore(value: 0); var out: Data?; var done = false
        conn.receive(minimumIncompleteLength: n, maximumLength: n) { d, _, complete, e in
            out = d; done = complete || e != nil; sem.signal()
        }
        guard sem.wait(timeout: .now() + timeout) == .success else { throw TransportError.timeout }
        guard let out, out.count == n else { _ = done; throw TransportError.closed }
        return out
    }

    public func receive(timeout: TimeInterval) throws -> Data {
        let h = try read(4, timeout: timeout)
        let n = Int(h.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }.bigEndian)
        guard n <= maxFrameSize else { close(); throw TransportError.frameTooLarge }
        return n == 0 ? Data() : try read(n, timeout: timeout)
    }

    public func close() { conn.cancel() }
}

/// Bonjour-advertised listener for `agentkeyd --sync-node`. TODO(mac): verify on device,
/// add NSLocalNetworkUsageDescription + NSBonjourServices (_agentkey._tcp) to the app Info.plist.
public final class BonjourSyncListener: @unchecked Sendable {
    let listener: NWListener
    public init(name: String, port: UInt16, fingerprint: String, onConnection: @escaping (FrameTransport) -> Void) throws {
        listener = try NWListener(using: .tcp, on: NWEndpoint.Port(rawValue: port) ?? .any)
        listener.service = NWListener.Service(name: name, type: Bonjour.serviceType, txtRecord: Bonjour.txt(fingerprint: fingerprint))
        listener.newConnectionHandler = { c in
            let t = NWFrameTransport(c)
            DispatchQueue.global().async { if (try? t.start(timeout: 10)) != nil { onConnection(t) } }
        }
    }
    public func start() { listener.start(queue: DispatchQueue(label: "agentkey.bonjour")) }
    public func cancel() { listener.cancel() }
}

/// Browse for home nodes on the LAN. Results are only *hints*: the Noise handshake still pins the
/// node's static key fingerprint, so a spoofed Bonjour advertisement cannot impersonate it.
/// TODO(mac): verify on device.
public final class BonjourBrowser: @unchecked Sendable {
    let browser = NWBrowser(for: .bonjourWithTXTRecord(type: Bonjour.serviceType, domain: nil), using: .tcp)
    public init() {}
    public func find(timeout: TimeInterval = 3) -> [NWEndpoint] {
        let sem = DispatchSemaphore(value: 0); var found: [NWEndpoint] = []
        browser.browseResultsChangedHandler = { results, _ in found = results.map(\.endpoint) }
        browser.start(queue: DispatchQueue(label: "agentkey.browse"))
        _ = sem.wait(timeout: .now() + timeout)
        browser.cancel(); return found
    }
}
#endif

#if canImport(MultipeerConnectivity) && AGENTKEY_MULTIPEER
// Optional Multipeer Connectivity transport (peer-to-peer Wi-Fi / Bluetooth when no shared network).
// Off by default; build with -DAGENTKEY_MULTIPEER.
// TODO(mac): implement FrameTransport over MCSession.send(_:toPeers:with: .reliable) with an inbound
// queue fed by session(_:didReceive:fromPeer:). MC's own encryption is NOT relied on — the Noise
// channel runs on top, exactly as for TCP. Use MCNearbyServiceAdvertiser with serviceType "agentkey".
import MultipeerConnectivity
public enum MultipeerTransportInfo { public static let serviceType = "agentkey" }
#endif
