import Foundation

/// Per-device sync runtime used by `agentkeyd`: identity, replica, pairing offers, known peers,
/// and the bridge between the local vault file and the sync replica. No external services:
/// devices talk directly (LAN / Bonjour / Tailscale / WireGuard), usually via an always-on home node.
public final class SyncNode: @unchecked Sendable {
    public static let defaultPort: UInt16 = 7373
    public let dir: URL
    public let identity: DeviceIdentity
    public private(set) var replica: PeerReplica?
    public internal(set) var peers = Peers()
    private var offer: PairingPayload?
    private let lock = NSRecursiveLock()
    func lock2(_ f: () -> Void) { lock.withLock(f) }

    public struct Peers: Codable {
        public var homeNode: String?                       // deviceID of the home node
        public var endpoints: [String: [String]] = [:]     // deviceID → ["host:port", …]
    }

    var identityURL: URL { dir.appendingPathComponent("identity.json") }
    var replicaURL: URL { dir.appendingPathComponent("replica.sealed") }
    var peersURL: URL { dir.appendingPathComponent("peers.json") }
    var bridgeURL: URL { dir.appendingPathComponent("bridge.json") }

    /// Loads or creates this device's Curve25519 identity.
    /// TODO(mac): store the identity in the Keychain (ThisDeviceOnly), wrapped by a Secure Enclave
    /// P-256 key (the SE cannot do X25519 itself). On Linux/dev boxes it is a 0600 file.
    public init(dir: URL, deviceName: String) throws {
        self.dir = dir
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        if let d = try? Data(contentsOf: dir.appendingPathComponent("identity.json")) {
            identity = try DeviceIdentity(stored: try JSONDecoder().decode(DeviceIdentity.Stored.self, from: d))
        } else {
            identity = DeviceIdentity(name: deviceName)
            try Self.writePrivate(try JSONEncoder().encode(identity.stored), to: dir.appendingPathComponent("identity.json"))
        }
        if FileManager.default.fileExists(atPath: replicaURL.path) { replica = try PeerReplica.load(from: replicaURL, identity: identity) }
        if let d = try? Data(contentsOf: peersURL), let p = try? JSONDecoder().decode(Peers.self, from: d) { peers = p }
    }

    static func writePrivate(_ d: Data, to url: URL) throws {
        let tmp = url.appendingPathExtension("tmp")
        FileManager.default.createFile(atPath: tmp.path, contents: d, attributes: [.posixPermissions: 0o600])
        guard rename(tmp.path, url.path) == 0 else { throw CocoaError(.fileWriteUnknown) }
    }

    public func save() throws {
        try lock.withLock {
            try replica?.save(to: replicaURL)
            try Self.writePrivate(try JSONEncoder().encode(peers), to: peersURL)
        }
    }

    /// Make this device the home node of a new sync group for `vaultID`.
    public func initHome(vaultID: UUID) throws -> PeerReplica {
        try lock.withLock {
            if let r = replica { return r }
            let r = PeerReplica(identity: identity, vaultID: vaultID, isHomeNode: true)
            replica = r; peers.homeNode = identity.deviceID.raw; try save(); return r
        }
    }

    // MARK: pairing

    /// Issue a one-time pairing payload (shown as QR / `agentkey-pair:` URI). Replaces any previous one.
    public func makeOffer(hosts: [String], port: UInt16, ttl: TimeInterval = 600) throws -> PairingPayload {
        try lock.withLock {
            guard let r = replica else { throw SyncNodeError.notInitialized }
            let p = PairingPayload(vaultID: r.vaultID, nodeName: identity.name, hosts: hosts, port: port,
                                   fingerprint: identity.fingerprint, ttl: ttl)
            offer = p; return p
        }
    }

    /// Join a sync group with a scanned payload. Tries each advertised host.
    public func join(_ payload: PairingPayload, connect: (String) throws -> FrameTransport = { try SyncEndpoint.dial($0, timeout: 10) }) throws -> PeerReplica {
        try lock.withLock {
            guard replica == nil else { throw SyncNodeError.alreadyPaired }
            var last: Error = SyncNodeError.unreachable
            let eps = payload.hosts.map { SyncEndpoint.make(host: $0, port: payload.port) }
            for ep in eps {
                do {
                    let t = try connect(ep)
                    try t.send(Data(SecureChannel.proloquePair.utf8))
                    let r = try SyncSession.pair(identity: identity, payload: payload, over: t)
                    guard let hub = r.trust.devices.values.first(where: { $0.fingerprint == payload.fingerprint }) else { throw PairingError.rejected("node missing") }
                    replica = r; peers.homeNode = hub.deviceID
                    peers.endpoints[hub.deviceID] = eps
                    try save(); return r
                } catch let e as PairingError { throw e }
                catch { last = error }
            }
            throw last
        }
    }

    // MARK: serving

    /// Handle one inbound connection (pairing or sync). The first plaintext frame selects the mode;
    /// it is also bound into the Noise prologue, so tampering with it fails the handshake.
    public func serveConnection(_ t: FrameTransport, prepare: (() -> Void)? = nil) throws -> String {
        let mode = String(decoding: try t.receive(timeout: 10), as: UTF8.self)
        guard let r = lock.withLock({ replica }) else { t.close(); throw SyncNodeError.notInitialized }
        switch mode {
        case SecureChannel.proloquePair:
            let p: PairingPayload? = lock.withLock { let o = offer; offer = nil; return o }   // single use, even on failure
            guard let p else { t.close(); throw PairingError.secretAlreadyUsed }
            let d = try SyncSession.servePairing(r, payload: p, over: t)
            try save(); return "paired \(d.name) (\(d.fingerprint))"
        case SecureChannel.prologueSync:
            prepare?()          // e.g. pull fresh local vault edits into the replica before serving
            let st = try SyncSession.serve(r, over: t)
            try save(); return "synced with \(r.trust.devices[st.peer]?.name ?? st.peer): in \(st.received) out \(st.sent)"
        default:
            t.close(); throw SyncProtocolError.protocolViolation("unknown mode")
        }
    }

    /// Run a blocking accept loop (used by `agentkeyd --sync-node`). `after` runs after each session.
    public func runListener(_ l: TCPListener, log: @escaping (String) -> Void, before: @escaping () -> Void, after: @escaping () -> Void) {
        while true {
            guard let t = try? l.accept() else { continue }
            Thread { [self] in
                do { log(try serveConnection(t, prepare: before)); after() } catch { log("session from \(t.peerDescription) failed: \(error)") }
            }.start()
        }
    }

    // MARK: client sync

    /// Sync with the home node (or every known peer endpoint). Returns per-peer results.
    public func syncNow(connect: (String) throws -> FrameTransport = { try SyncEndpoint.dial($0, timeout: 5) }) throws -> [String: Result<SyncStats, Error>] {
        guard let r = lock.withLock({ replica }) else { throw SyncNodeError.notInitialized }
        var out: [String: Result<SyncStats, Error>] = [:]
        for (peer, eps) in peers.endpoints.sorted(by: { $0.key < $1.key }) where peer != identity.deviceID.raw {
            var res: Result<SyncStats, Error> = .failure(SyncNodeError.unreachable)
            for ep in eps {
                do {
                    let t = try connect(ep)
                    try t.send(Data(SecureChannel.prologueSync.utf8))
                    let fp = r.trust.devices[peer]?.fingerprint
                    res = .success(try SyncSession.runClient(r, over: t, pinnedFingerprint: fp)); break
                } catch let e as TransportError {
                    if case .failure(let prev) = res, !(prev is TransportError || prev is SyncNodeError) { continue }  // keep the meaningful error
                    res = .failure(e)
                } catch { res = .failure(error); break }   // reached the peer: auth/protocol error is the answer
            }
            out[peer] = res
        }
        try save()
        return out
    }

    public func addEndpoint(peer: String, _ ep: String) throws {
        lock.withLock { var l = peers.endpoints[peer] ?? []; if !l.contains(ep) { l.append(ep) }; peers.endpoints[peer] = l }
        try save()
    }

    public func revoke(_ deviceID: String) throws {
        guard let r = lock.withLock({ replica }) else { throw SyncNodeError.notInitialized }
        guard deviceID != identity.deviceID.raw else { throw SyncNodeError.cannotRevokeSelf }
        try r.revoke(deviceID); lock.withLock { _ = peers.endpoints.removeValue(forKey: deviceID) }; try save()
    }

    // MARK: status

    public struct Status: Codable {
        public var deviceID: String, name: String, fingerprint: String
        public var initialized: Bool, isHomeNode: Bool, keyVersion: Int, items: Int
        public var devices: [DeviceInfo]
    }
    public struct DeviceInfo: Codable {
        public var deviceID: String, name: String, fingerprint: String, isHomeNode: Bool, revoked: Bool, isSelf: Bool
        public var endpoints: [String], lastSync: Date?, pendingOut: Int
    }

    public func status() -> Status {
        lock.withLock {
            let r = replica
            let devs = (r?.trust.devices.values.sorted { $0.addedAt < $1.addedAt } ?? []).map { d in
                DeviceInfo(deviceID: d.deviceID, name: d.name, fingerprint: d.fingerprint, isHomeNode: d.isHomeNode ?? false,
                           revoked: d.revokedAt != nil, isSelf: d.deviceID == identity.deviceID.raw,
                           endpoints: peers.endpoints[d.deviceID] ?? [], lastSync: r?.lastSync[d.deviceID],
                           pendingOut: d.deviceID == identity.deviceID.raw ? 0 : (r?.pendingCount(for: d.deviceID) ?? 0))
            }
            return Status(deviceID: identity.deviceID.raw, name: identity.name, fingerprint: identity.fingerprint,
                          initialized: r != nil, isHomeNode: peers.homeNode == identity.deviceID.raw,
                          keyVersion: r?.currentKeyVersion ?? 0, items: r?.liveItems.count ?? 0, devices: devs)
        }
    }

    // MARK: vault bridge

    /// Two-way reconcile between the local vault file and the replica, using a keyed snapshot of the
    /// last reconciled state: vault-side changes go to the replica (and out to peers); replica-side
    /// changes (from peers) are written into the vault. Snapshot stores only HMACs, never plaintext.
    @discardableResult
    public func reconcile(vault: Vault) throws -> (toReplica: Int, toVault: Int) {
        try lock.withLock {
            guard let r = replica else { throw SyncNodeError.notInitialized }
            let key = KeyHierarchy.subkey(SymmetricKey(data: identity.staticKey.rawRepresentation), purpose: "bridge")
            func h(_ i: VaultItem?) throws -> String? {
                guard let i else { return nil }
                return Data(HMAC<SHA256>.authenticationCode(for: try Vault.encoder.encode(i), using: key)).base64EncodedString()
            }
            var snap: [UUID: String] = (try? JSONDecoder().decode([UUID: String].self, from: Data(contentsOf: bridgeURL))) ?? [:]
            let v = Dictionary(uniqueKeysWithValues: try vault.items().map { ($0.id, $0) })
            let rp = Dictionary(uniqueKeysWithValues: r.liveItems.map { ($0.id, $0) })
            var toR = 0, toV = 0
            for id in Set(v.keys).union(rp.keys).union(snap.keys) {
                let hv = try h(v[id]), hr = try h(rp[id]), hs = snap[id]
                if hv == hr { snap[id] = hv; continue }
                if hv != hs {                       // vault changed locally → replica
                    if let i = v[id] { r.write(i) } else { r.delete(id) }
                    snap[id] = hv; toR += 1
                } else {                            // replica changed (from a peer) → vault
                    if let i = rp[id] { try vault.put(i) } else { try vault.delete(id: id) }
                    snap[id] = hr; toV += 1
                }
            }
            snap = snap.filter { $0.value != nil }.mapValues { $0 }
            try Self.writePrivate(try JSONEncoder().encode(snap), to: bridgeURL)
            try save()
            return (toR, toV)
        }
    }
}

public enum SyncNodeError: Error, CustomStringConvertible {
    case notInitialized, alreadyPaired, unreachable, cannotRevokeSelf
    public var description: String {
        switch self {
        case .notInitialized: return "sync not set up on this device (run `agentkeyd --sync-node` on the home node, or `agentkey device pair <code>`)"
        case .alreadyPaired: return "this device is already paired"
        case .unreachable: return "no peer endpoint reachable"
        case .cannotRevokeSelf: return "cannot revoke this device from itself"
        }
    }
}

public enum LocalAddresses {
    /// Non-loopback IPv4 addresses of this machine (for pairing payloads). Includes Tailscale/WireGuard
    /// interfaces if up; users can add hostnames (e.g. a MagicDNS name) with `--host`.
    public static func ipv4() -> [String] {
        var out: [String] = []
        var ifa: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifa) == 0, let first = ifa else { return out }
        defer { freeifaddrs(ifa) }
        var p: UnsafeMutablePointer<ifaddrs>? = first
        while let cur = p {
            if let sa = cur.pointee.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET) || Int32(sa.pointee.sa_family) == AF_INET {
                var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(sa, socklen_t(MemoryLayout<sockaddr_in>.size), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                    let s = String(cString: host)
                    if !s.hasPrefix("127.") && !out.contains(s) { out.append(s) }
                }
            }
            p = cur.pointee.ifa_next
        }
        return out
    }
}

/// Endpoint strings stored in peers.json and carried in pairing payloads:
///   "host:port"            plain TCP (LAN IP, Tailscale/WireGuard address or name)
///   "bonjour:<service>"    Bonjour service `_agentkey._tcp` on the local network (Apple platforms)
/// Whatever the endpoint, the Noise handshake + pinned fingerprint is the trust anchor; discovery
/// only finds an address.
public enum SyncEndpoint {
    public static let bonjourPrefix = "bonjour:"

    public static func make(host: String, port: UInt16) -> String {
        host.hasPrefix(bonjourPrefix) ? host : "\(host):\(port)"
    }

    public static func dial(_ ep: String, timeout: TimeInterval) throws -> FrameTransport {
        if ep.hasPrefix(bonjourPrefix) {
            #if canImport(Network)
            return try NWFrameTransport.connectBonjour(name: String(ep.dropFirst(bonjourPrefix.count)), timeout: timeout)
            #else
            throw TransportError.connectFailed("Bonjour is not available on this platform (\(ep))")
            #endif
        }
        guard let i = ep.lastIndex(of: ":"), let port = UInt16(ep[ep.index(after: i)...]) else {
            throw TransportError.connectFailed("bad endpoint \(ep)")
        }
        return try TCPTransport.connect(host: String(ep[..<i]), port: port, timeout: timeout)
    }

    /// Bonjour instance name for a node: derived from its public key fingerprint only, so the
    /// advertisement leaks neither the device name nor anything about the vault.
    public static func bonjourName(fingerprint: String) -> String {
        "agentkey-" + fingerprint.replacingOccurrences(of: "-", with: "").prefix(8).lowercased()
    }
    /// Short fingerprint published in the TXT record (`fp`), compared against pinned fingerprints.
    public static func shortFingerprint(_ fp: String) -> String { String(fp.replacingOccurrences(of: "-", with: "").prefix(8)) }
}

/// A node seen via Bonjour (platform-neutral so CLI/JSON code compiles everywhere).
public struct DiscoveredNode: Codable, Sendable, Equatable {
    public var name: String
    public var domain: String
    public var endpoint: String
    public var fingerprintPrefix: String?
    public var protocolVersion: Int?
    public var interfaces: [String]
    /// Filled in by the caller: whether this matches a paired device's pinned fingerprint.
    public var pairedDeviceID: String?
    public var pairedName: String?

    public init(name: String, domain: String, endpoint: String, fingerprintPrefix: String?, protocolVersion: Int?, interfaces: [String]) {
        self.name = name; self.domain = domain; self.endpoint = endpoint
        self.fingerprintPrefix = fingerprintPrefix; self.protocolVersion = protocolVersion; self.interfaces = interfaces
    }
}

public enum Discovery {
    /// Bonjour browse (Apple). Returns [] with `supported == false` elsewhere.
    public static var supported: Bool {
        #if canImport(Network)
        return true
        #else
        return false
        #endif
    }

    public static func browse(timeout: TimeInterval = 3) -> (nodes: [DiscoveredNode], error: String?) {
        #if canImport(Network)
        let b = BonjourBrowser(); let n = b.find(timeout: timeout); return (n, b.lastError)
        #else
        return ([], "Bonjour discovery is not available on this platform")
        #endif
    }

    /// Mark nodes whose advertised short fingerprint matches a paired (non-revoked) device.
    /// This is display-only; connecting still requires the full fingerprint in the Noise handshake.
    public static func annotate(_ nodes: [DiscoveredNode], trust: TrustState?) -> [DiscoveredNode] {
        nodes.map { n in
            var n = n
            if let fp = n.fingerprintPrefix, let d = trust?.devices.values.first(where: { $0.revokedAt == nil && SyncEndpoint.shortFingerprint($0.fingerprint) == fp }) {
                n.pairedDeviceID = d.deviceID; n.pairedName = d.name
            }
            return n
        }
    }
}

extension SyncNode {
    /// Record a Bonjour endpoint for a paired device found on the LAN (tried before host:port next time).
    public func learnDiscovered(_ nodes: [DiscoveredNode]) throws {
        let ann = Discovery.annotate(nodes, trust: replica?.trust)
        var changed = false
        lock2 { 
            for n in ann { guard let id = n.pairedDeviceID else { continue }
                var l = peers.endpoints[id] ?? []
                if !l.contains(n.endpoint) { l.insert(n.endpoint, at: 0); peers.endpoints[id] = l; changed = true } }
        }
        if changed { try save() }
    }
}
