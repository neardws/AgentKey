import Foundation

/// A way for this device to be reached: produced locally, exchanged via a RendezvousProvider.
public struct NetCandidate: Codable, Hashable, Sendable {
    public enum Kind: String, Codable, Sendable { case bonjour, ipv6, tcp, udp, relay }
    public var kind: Kind
    public var addr: String          // "bonjour:<name>", "[v6]:port", "host:port"
    public var source: String        // host | srflx | config | lastKnown | stun
    public init(_ kind: Kind, _ addr: String, source: String) { self.kind = kind; self.addr = addr; self.source = source }

    /// Racing order (lower first): LAN Bonjour → direct IPv6 → configured/forwarded TCP → UDP punch → relay.
    public var rank: Int {
        switch kind { case .bonjour: return 0; case .ipv6: return 1; case .tcp: return 2; case .udp: return 3; case .relay: return 4 }
    }
}

/// NetCandidate record a device publishes for ONE peer (sealed per pair).
public struct CandidateRecord: Codable, Equatable, Sendable {
    public var d: String             // sender deviceID
    public var t: Int64              // unix seconds; also the BEP44 seq
    public var n: String             // NAT type estimate
    public var c: [NetCandidate]
    public init(device: String, time: Int64 = Int64(Date().timeIntervalSince1970), nat: String, candidates: [NetCandidate]) {
        d = device; t = time; n = nat; c = candidates
    }
    public var age: TimeInterval { Date().timeIntervalSince1970 - Double(t) }
}

/// Keys shared by exactly two paired devices, derived from X25519(static_a, static_b).
/// Nothing here is linkable to the devices' identity keys by an outside observer.
public struct PairKeys {
    public let pair: SymmetricKey          // punch MACs
    let enc: SymmetricKey                  // record encryption
    let selfPub: Data, peerPub: Data
    let raw: SymmetricKey

    public init(identity: DeviceIdentity, peerPublicKey: Data) throws {
        let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey)
        let ss = try identity.staticKey.sharedSecretFromKeyAgreement(with: peer)
        raw = ss.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data("agentkey-net/v1".utf8), sharedInfo: Data("pair".utf8), outputByteCount: 32)
        pair = PairKeys.sub(raw, "punch"); enc = PairKeys.sub(raw, "record")
        selfPub = identity.publicKey; peerPub = peerPublicKey
    }
    static func sub(_ k: SymmetricKey, _ info: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: k, info: Data("agentkey-net/\(info)".utf8), outputByteCount: 32)
    }
    /// Direction label: records from `from` to `to`.
    static func dir(_ from: Data, _ to: Data) -> String { shortID(from).hexString + ">" + shortID(to).hexString }

    /// ed25519 signing key + salt for the BEP44 slot `from → to`. Both peers can compute both slots.
    public func dhtSlot(outgoing: Bool) -> (key: Curve25519.Signing.PrivateKey, salt: Data) {
        let d = outgoing ? PairKeys.dir(selfPub, peerPub) : PairKeys.dir(peerPub, selfPub)
        let seed = PairKeys.sub(raw, "dht-sign|" + d).withUnsafeBytes { Data($0) }
        let salt = PairKeys.sub(raw, "dht-salt|" + d).withUnsafeBytes { Data($0) }.prefix(16)
        return (try! Curve25519.Signing.PrivateKey(rawRepresentation: seed), Data(salt))
    }

    public func seal(_ r: CandidateRecord) throws -> Data {
        let pt = try JSONEncoder().encode(r)
        let ad = Data(("agentkey-rdv/1|" + PairKeys.dir(selfPub, peerPub)).utf8)
        return try ChaChaPoly.seal(pt, using: enc, authenticating: ad).combined
    }
    public func open(_ ct: Data) throws -> CandidateRecord {
        let ad = Data(("agentkey-rdv/1|" + PairKeys.dir(peerPub, selfPub)).utf8)
        let pt = try ChaChaPoly.open(try ChaChaPoly.SealedBox(combined: ct), using: enc, authenticating: ad)
        return try JSONDecoder().decode(CandidateRecord.self, from: pt)
    }
}

/// First 8 bytes of SHA-256(pub): used in punch packets / manual blobs to pick the pair key.
public func shortID(_ pub: Data) -> Data { Data(SHA256.hash(data: Data("agentkey-sid/1".utf8) + pub)).prefix(8) }

extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}

/// Exchanges sealed candidate records between paired devices without any AgentKey server.
public protocol RendezvousProvider: AnyObject {
    var name: String { get }
    /// Publish our record for one peer.
    func publish(_ sealed: Data, keys: PairKeys) throws
    /// Fetch the peer's latest record for us (nil if none found).
    func fetch(keys: PairKeys) throws -> Data?
}

/// Manual copy-paste channel: `agentkey sync signal export` prints a blob, `import` on the other side.
/// Blob = "akr1." + base64url(senderShortID(8) ‖ sealed record).
public enum ManualSignal {
    public static func export(_ sealed: Data, from identity: DeviceIdentity) -> String {
        "akr1." + (shortID(identity.publicKey) + sealed).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    public static func parse(_ blob: String) -> (sender: Data, sealed: Data)? {
        let t = blob.trimmingCharacters(in: .whitespacesAndNewlines)
        guard t.hasPrefix("akr1.") else { return nil }
        var b = String(t.dropFirst(5)).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b.count % 4 != 0 { b += "=" }
        guard let d = Data(base64Encoded: b), d.count > 8 else { return nil }
        return (d.prefix(8), d.dropFirst(8))
    }
}
