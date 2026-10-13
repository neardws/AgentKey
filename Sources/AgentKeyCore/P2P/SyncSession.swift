import Foundation

/// Wire messages (inside the Noise channel). JSON, one message per frame.
public enum SyncMessage: Codable {
    case hello(Hello)
    case delta(Delta)
    case push(Push)
    case pushResult(PushResult)
    case done(UInt64)
    case error(String)

    public struct Hello: Codable { public var proto: Int; public var device: String; public var vaultID: UUID; public var since: UInt64; public var trust: TrustState }
    public struct Delta: Codable { public var trust: TrustState; public var records: [SyncRecord]; public var upTo: UInt64; public var more: Bool }
    public struct Push: Codable { public var items: [PushItem] }
    public struct PushItem: Codable { public var record: SyncRecord; public var base: Stamp? }
    public struct PushResult: Codable { public var accepted: [UUID]; public var conflicts: [SyncRecord] }
}

public struct SyncStats: Codable, Equatable, Sendable {
    public var received = 0, sent = 0, conflicts = 0, rounds = 0
    public var peer = ""
}

/// Sync session state machine. Client = initiator, hub = responder.
///
///   C → H  hello(since = cursor[H], trust)
///   H → C  delta(trust, records > since, upTo, more)   … repeated while `more`
///   C      applies records, then cursor[H] = upTo      (resumable: cursor only moves after apply)
///   C → H  push(records with CAS base)                  … repeated until nothing pending (max 8 rounds)
///   H → C  pushResult(accepted, conflicts)              conflicts are merged by C and re-pushed
///   C → H  done(0);  H → C done(seq)
public enum SyncSession {
    public static let protocolVersion = 1
    static func prologue(_ vault: UUID) -> Data { Data("\(SecureChannel.prologueSync)|\(vault.uuidString)".utf8) }

    /// Verify a peer static key against the replicated device registry (fail closed).
    static func trustCheck(_ r: PeerReplica) -> (Data) throws -> Void {
        return { pub in
            guard r.trust.isTrusted(pub) else {
                throw NoiseError.untrustedPeer(r.trust.device(pub: pub)?.revokedAt != nil ? "revoked device" : "unknown device \(DeviceIdentity.fingerprint(pub))")
            }
        }
    }

    // MARK: client

    @discardableResult
    public static func runClient(_ r: PeerReplica, over t: FrameTransport, pinnedFingerprint: String? = nil) throws -> SyncStats {
        defer { t.close() }
        guard !r.isRevoked else { throw SyncProtocolError.revoked }
        let ch = try SecureChannel.handshake(t, initiator: true, identity: r.identity, prologue: prologue(r.vaultID)) { pub in
            if let fp = pinnedFingerprint, DeviceIdentity.fingerprint(pub) != fp {
                throw PairingError.fingerprintMismatch(expected: fp, got: DeviceIdentity.fingerprint(pub))
            }
            try trustCheck(r)(pub)
        }
        guard let hub = r.trust.device(pub: ch.remoteStatic)?.deviceID else { throw NoiseError.untrustedPeer("?") }
        var st = SyncStats(); st.peer = hub

        try ch.send(json: SyncMessage.hello(.init(proto: protocolVersion, device: r.device.raw, vaultID: r.vaultID,
                                                  since: r.cursors[hub] ?? 0, trust: r.trust)))
        // download
        while true {
            guard case .delta(let d) = try ch.receive(json: SyncMessage.self) else { throw SyncProtocolError.protocolViolation("expected delta") }
            r.mergeTrust(d.trust)
            if r.isRevoked { throw SyncProtocolError.revoked }
            for rec in d.records { try r.receive(rec, from: hub); st.received += 1 }
            r.setCursor(hub, d.upTo)
            if !d.more { break }
        }
        // upload (compare-and-set, merge on conflict)
        for _ in 0..<8 {
            let pend = try r.pending(for: hub)
            if pend.isEmpty { break }
            st.rounds += 1
            try ch.send(json: SyncMessage.push(.init(items: pend.map { .init(record: $0.0, base: $0.1) })))
            guard case .pushResult(let res) = try ch.receive(json: SyncMessage.self) else { throw SyncProtocolError.protocolViolation("expected pushResult") }
            let sentStamps = Dictionary(uniqueKeysWithValues: pend.map { ($0.0.meta.id, $0.0.meta.stamp) })
            for id in res.accepted { if let s = sentStamps[id] { r.didAccept(id, stamp: s, peer: hub); st.sent += 1 } }
            for c in res.conflicts { try r.receive(c, from: hub); st.conflicts += 1 }
        }
        try ch.send(json: SyncMessage.done(0))
        guard case .done(let hubSeq) = try ch.receive(json: SyncMessage.self) else { throw SyncProtocolError.protocolViolation("expected done") }
        // the hub served this session exclusively, so every hub change ≤ hubSeq is ours or already applied
        r.setCursor(hub, hubSeq)
        return st
    }

    // MARK: hub

    /// Serve one session. Callers should serialize sessions per hub (`hubLock`).
    @discardableResult
    public static func serve(_ r: PeerReplica, over t: FrameTransport, pageSize: Int = 500) throws -> SyncStats {
        defer { t.close() }
        let ch = try SecureChannel.handshake(t, initiator: false, identity: r.identity, prologue: prologue(r.vaultID), verify: trustCheck(r))
        var st = SyncStats()
        r.hubLock.lock(); defer { r.hubLock.unlock() }
        guard case .hello(let h) = try ch.receive(json: SyncMessage.self) else { throw SyncProtocolError.protocolViolation("expected hello") }
        guard h.vaultID == r.vaultID else { throw SyncProtocolError.vaultMismatch }
        guard r.trust.device(pub: ch.remoteStatic)?.deviceID == h.device else { throw SyncProtocolError.protocolViolation("device id does not match key") }
        st.peer = h.device
        r.mergeTrust(h.trust)
        if r.trust.devices[h.device]?.revokedAt != nil { try? ch.send(json: SyncMessage.error("revoked")); throw SyncProtocolError.revoked }
        var since = h.since
        while true {
            let d = try r.delta(since: since, limit: pageSize)
            try ch.send(json: SyncMessage.delta(.init(trust: r.trust, records: d.records, upTo: d.upTo, more: d.more)))
            st.sent += d.records.count
            since = d.upTo
            if !d.more { break }
        }
        while true {
            switch try ch.receive(json: SyncMessage.self) {
            case .push(let p):
                var accepted: [UUID] = [], conflicts: [SyncRecord] = []
                for it in p.items {
                    if let c = try r.accept(it.record, base: it.base) { conflicts.append(c); st.conflicts += 1 }
                    else { accepted.append(it.record.meta.id); st.received += 1 }
                }
                try ch.send(json: SyncMessage.pushResult(.init(accepted: accepted, conflicts: conflicts)))
            case .done:
                try ch.send(json: SyncMessage.done(r.seq))
                return st
            default:
                throw SyncProtocolError.protocolViolation("unexpected message")
            }
        }
    }

    // MARK: pairing

    /// Home node side: accept one pairing connection for a payload it issued.
    public static func servePairing(_ r: PeerReplica, payload: PairingPayload, over t: FrameTransport) throws -> DeviceRecord {
        defer { t.close() }
        guard payload.expires > Date() else { throw PairingError.expired }
        let ch = try SecureChannel.handshake(t, initiator: false, identity: r.identity,
                                             prologue: Data("\(SecureChannel.proloquePair)|\(payload.vaultID.uuidString)".utf8),
                                             psk: payload.secret) { pub in
            if r.trust.device(pub: pub)?.revokedAt != nil { throw PairingError.revoked }
        }
        let req = try ch.receive(json: PairingRequest.self)
        let rec = DeviceRecord(deviceID: req.deviceID, name: PromptSanitizer.clean(req.name, max: 64), publicKey: ch.remoteStatic,
                               addedAt: Date(), addedBy: r.device.raw, revokedAt: nil, isHomeNode: false)
        try r.addDevice(rec)
        let ho = PairingHandover(trust: r.trust, keys: r.keys.mapValues(\.data), hubDeviceID: r.device.raw)
        try ch.send(json: ho)
        return rec
    }

    /// New device side: connect with a scanned pairing payload; returns a fresh replica.
    public static func pair(identity: DeviceIdentity, payload: PairingPayload, over t: FrameTransport) throws -> PeerReplica {
        defer { t.close() }
        guard payload.expires > Date() else { throw PairingError.expired }
        let ch = try SecureChannel.handshake(t, initiator: true, identity: identity,
                                             prologue: Data("\(SecureChannel.proloquePair)|\(payload.vaultID.uuidString)".utf8),
                                             psk: payload.secret) { pub in
            let fp = DeviceIdentity.fingerprint(pub)
            guard fp == payload.fingerprint else { throw PairingError.fingerprintMismatch(expected: payload.fingerprint, got: fp) }
        }
        try ch.send(json: PairingRequest(deviceID: identity.deviceID.raw, name: identity.name))
        let ho = try ch.receive(json: PairingHandover.self)
        guard ho.trust.vaultID == payload.vaultID, ho.trust.isTrusted(identity.publicKey),
              ho.trust.device(pub: ch.remoteStatic)?.deviceID == ho.hubDeviceID else { throw PairingError.rejected("bad handover") }
        return try PeerReplica(identity: identity, handover: ho)
    }
}

struct PairingRequest: Codable { var deviceID: String; var name: String }

/// Sent by the home node over the authenticated pairing channel.
struct PairingHandover: Codable { var trust: TrustState; var keys: [Int: Data]; var hubDeviceID: String }
