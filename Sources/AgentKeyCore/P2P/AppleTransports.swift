// Apple-only transports for P2P sync. Same FrameTransport contract as TCPTransport
// (4-byte big-endian length + frame); the Noise channel runs on top, so these only move bytes.
// STATUS: compiles on macOS (Xcode 26.2); runtime behaviour still to be verified on the Mac mini.
// Linux builds use TCPTransport/TCPListener only.
#if canImport(Network)
import Foundation
import Network

public enum Bonjour {
    /// Service type advertised by the home node (and by any device that serves sync).
    public static let serviceType = "_agentkey._tcp"
    /// TXT record carries only non-secret routing hints: protocol version + short node fingerprint.
    /// No device name, vault id or item count.
    public static func txt(fingerprint: String) -> NWTXTRecord {
        var t = NWTXTRecord(); t["v"] = String(SyncSession.protocolVersion); t["fp"] = SyncEndpoint.shortFingerprint(fingerprint); return t
    }
}

/// FrameTransport over an NWConnection (TCP). TODO(mac): verify on device; tune timeouts.
public final class NWFrameTransport: FrameTransport, @unchecked Sendable {
    let conn: NWConnection
    let queue = DispatchQueue(label: "agentkey.nw")
    public var peerDescription: String { "\(conn.endpoint)" }

    public init(_ conn: NWConnection) { self.conn = conn }

    /// Connect to a Bonjour service by instance name; Network.framework resolves it.
    public static func connectBonjour(name: String, timeout: TimeInterval = 10) throws -> NWFrameTransport {
        try connect(.service(name: name, type: Bonjour.serviceType, domain: "local.", interface: nil), timeout: timeout)
    }

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
    /// `port` 0 = any free port (the TCP listener for Tailscale/WireGuard keeps the fixed port).
    public init(name: String, port: UInt16 = 0, fingerprint: String, onConnection: @escaping (FrameTransport) -> Void) throws {
        listener = try port == 0 ? NWListener(using: .tcp) : NWListener(using: .tcp, on: NWEndpoint.Port(rawValue: port) ?? .any)
        listener.service = NWListener.Service(name: name, type: Bonjour.serviceType, txtRecord: Bonjour.txt(fingerprint: fingerprint))
        listener.newConnectionHandler = { c in
            let t = NWFrameTransport(c)
            DispatchQueue.global().async { if (try? t.start(timeout: 10)) != nil { onConnection(t) } }
        }
    }
    public func start(log: @escaping (String) -> Void = { _ in }) {
        listener.stateUpdateHandler = { st in
            switch st {
            case .ready: log("bonjour: advertising \(Bonjour.serviceType) on port \(self.listener.port?.rawValue ?? 0)")
            case .failed(let e): log("bonjour: listener failed: \(e)")
            case .waiting(let e): log("bonjour: waiting (Local Network permission?): \(e)")
            default: break
            }
        }
        listener.start(queue: DispatchQueue(label: "agentkey.bonjour"))
    }
    public func cancel() { listener.cancel() }
}

/// Browse for home nodes on the LAN. Results are only *hints*: the Noise handshake still pins the
/// node's static key fingerprint, so a spoofed Bonjour advertisement cannot impersonate it.
public final class BonjourBrowser: @unchecked Sendable {
    public init() {}
    public func find(timeout: TimeInterval = 3) -> [DiscoveredNode] {
        let browser = NWBrowser(for: .bonjourWithTXTRecord(type: Bonjour.serviceType, domain: nil), using: .tcp)
        let lock = NSLock(); var found: [String: DiscoveredNode] = [:]; var failure: String?
        browser.stateUpdateHandler = { st in
            if case .failed(let e) = st { lock.withLock { failure = "\(e)" } }
            if case .waiting(let e) = st { lock.withLock { failure = "\(e)" } }
        }
        browser.browseResultsChangedHandler = { results, _ in
            lock.withLock {
                found = [:]
                for r in results {
                    guard case .service(let name, _, let domain, _) = r.endpoint else { continue }
                    var fp: String?, v: String?
                    if case .bonjour(let txt) = r.metadata { fp = txt["fp"]; v = txt["v"] }
                    let ifs = r.interfaces.map(\.name)
                    var n = found[name] ?? DiscoveredNode(name: name, domain: domain, endpoint: SyncEndpoint.bonjourPrefix + name,
                                                          fingerprintPrefix: fp, protocolVersion: v.flatMap(Int.init), interfaces: [])
                    n.interfaces = Array(Set(n.interfaces + ifs)).sorted()
                    found[name] = n
                }
            }
        }
        browser.start(queue: DispatchQueue(label: "agentkey.browse"))
        Thread.sleep(forTimeInterval: timeout)
        browser.cancel()
        return lock.withLock {
            if found.isEmpty, let failure { lastError = failure }
            return found.values.sorted { $0.name < $1.name }
        }
    }
    public private(set) var lastError: String?
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
