import Foundation

/// Long-term device identity: an X25519 static key used as the Noise `s` key.
/// The Secure Enclave only supports P-256, so on Apple platforms the X25519 private key is
/// stored in the Keychain (ThisDeviceOnly) wrapped by an SE P-256 key — TODO(mac): implement
/// `SecureEnclaveIdentityStore`. Elsewhere it is a 0600 file / in-memory (tests).
public struct DeviceIdentity: Sendable {
    public let deviceID: DeviceID
    public let name: String
    public let staticKey: Curve25519.KeyAgreement.PrivateKey

    public init(name: String, deviceID: DeviceID = .generate(), staticKey: Curve25519.KeyAgreement.PrivateKey = .init()) {
        self.name = name; self.deviceID = deviceID; self.staticKey = staticKey
    }
    public var publicKey: Data { staticKey.publicKey.rawRepresentation }
    public var fingerprint: String { Self.fingerprint(publicKey) }

    /// Human-comparable fingerprint: first 20 bytes of SHA-256(pubkey), Base32, groups of 4.
    public static func fingerprint(_ pub: Data) -> String {
        let b = Base32.encode(Data(SHA256.hash(data: Data("agentkey-fp/1".utf8) + pub).prefix(20)))
        return stride(from: 0, to: b.count, by: 4).map { i -> String in
            let s = b.index(b.startIndex, offsetBy: i); return String(b[s..<b.index(s, offsetBy: min(4, b.count - i))])
        }.joined(separator: "-")
    }

    /// Serialized form for local persistence (protect at rest!).
    public struct Stored: Codable { public var deviceID: String; public var name: String; public var key: Data }
    public var stored: Stored { Stored(deviceID: deviceID.raw, name: name, key: staticKey.rawRepresentation) }
    public init(stored s: Stored) throws {
        self.init(name: s.name, deviceID: DeviceID(s.deviceID), staticKey: try .init(rawRepresentation: s.key))
    }
}

/// QR code content shown by the home node: "agentkey-pair:" + base64url(JSON).
public struct PairingPayload: Codable, Equatable, Sendable {
    public var v = 1
    public var vaultID: UUID
    public var nodeName: String
    public var hosts: [String]          // LAN IPs / hostnames (and Tailscale name if configured)
    public var port: UInt16
    public var fingerprint: String      // node static key fingerprint (pinned by the new device)
    public var secret: Data             // 32-byte one-time pairing secret (Noise psk)
    public var expires: Date

    public init(vaultID: UUID, nodeName: String, hosts: [String], port: UInt16, fingerprint: String,
                secret: Data = AKRandom.bytes(32), ttl: TimeInterval = 600) {
        self.vaultID = vaultID; self.nodeName = nodeName; self.hosts = hosts; self.port = port
        self.fingerprint = fingerprint; self.secret = secret
        self.expires = Date(timeIntervalSince1970: (Date().timeIntervalSince1970 + ttl).rounded(.down))
    }

    public var uri: String {
        let e = JSONEncoder(); e.dateEncodingStrategy = .secondsSince1970; e.outputFormatting = .sortedKeys
        let b64 = (try! e.encode(self)).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        return "agentkey-pair:" + b64
    }

    public init(uri: String) throws {
        guard uri.hasPrefix("agentkey-pair:") else { throw PairingError.malformed }
        var b = String(uri.dropFirst("agentkey-pair:".count)).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b.count % 4 != 0 { b += "=" }
        guard let d = Data(base64Encoded: b) else { throw PairingError.malformed }
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .secondsSince1970
        self = try dec.decode(PairingPayload.self, from: d)
        guard v == 1, secret.count == 32, port > 0 else { throw PairingError.malformed }
    }
}

public enum PairingError: Error, Equatable, CustomStringConvertible {
    case malformed, expired, fingerprintMismatch(expected: String, got: String), secretAlreadyUsed, rejected(String), revoked
    public var description: String {
        switch self {
        case .malformed: return "pairing code is malformed"
        case .expired: return "pairing code expired"
        case .fingerprintMismatch(let e, let g): return "home node fingerprint mismatch (expected \(e), got \(g)) — possible MITM"
        case .secretAlreadyUsed: return "pairing code already used"
        case .rejected(let s): return "pairing rejected: \(s)"
        case .revoked: return "device is revoked"
        }
    }
}

/// Seal data to a device's X25519 public key (ephemeral-static ECDH + HKDF + ChaChaPoly).
/// Used to hand vault keys to devices (pairing, key rotation keyring).
public enum KeyWrap {
    public static func seal(_ pt: Data, to recipient: Data, context: String) throws -> Data {
        let rpk = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipient)
        let eph = Curve25519.KeyAgreement.PrivateKey()
        let shared = try eph.sharedSecretFromKeyAgreement(with: rpk)
        let k = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: eph.publicKey.rawRepresentation + recipient,
                                               sharedInfo: Data("agentkey/keywrap/v1|\(context)".utf8), outputByteCount: 32)
        return eph.publicKey.rawRepresentation + (try ChaChaPoly.seal(pt, using: k).combined)
    }
    public static func open(_ ct: Data, with key: Curve25519.KeyAgreement.PrivateKey, context: String) throws -> Data {
        guard ct.count > 32 + 28 else { throw NoiseError.decryptFailed }
        let epk = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ct.prefix(32))
        let shared = try key.sharedSecretFromKeyAgreement(with: epk)
        let k = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(ct.prefix(32)) + key.publicKey.rawRepresentation,
                                               sharedInfo: Data("agentkey/keywrap/v1|\(context)".utf8), outputByteCount: 32)
        do { return try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: ct.dropFirst(32)), using: k) }
        catch { throw NoiseError.decryptFailed }
    }
}

/// Encrypted, authenticated message channel over any FrameTransport (after a Noise handshake).
public final class SecureChannel {
    let t: FrameTransport
    var session: SecureSession
    public var remoteStatic: Data { session.remoteStatic.rawRepresentation }
    public var handshakeHash: Data { session.handshakeHash }
    public var timeout: TimeInterval = 30

    init(_ t: FrameTransport, _ s: SecureSession) { self.t = t; session = s }

    public func send(_ d: Data) throws { try t.send(try session.seal(d)) }
    public func receive() throws -> Data { try session.open(try t.receive(timeout: timeout)) }
    public func send<T: Encodable>(json v: T) throws { try send(try P2PCodec.enc.encode(v)) }
    public func receive<T: Decodable>(json: T.Type) throws -> T { try P2PCodec.dec.decode(T.self, from: try receive()) }
    public func close() { t.close() }

    public static let prologueSync = "agentkey-sync/1"
    public static let proloquePair = "agentkey-pair/1"

    /// Run the Noise XX handshake. `verify` decides whether the peer's static key is acceptable.
    public static func handshake(_ t: FrameTransport, initiator: Bool, identity: DeviceIdentity, prologue: Data,
                                 psk: Data? = nil, timeout: TimeInterval = 15,
                                 verify: (Data) throws -> Void) throws -> SecureChannel {
        let hs = NoiseXX(initiator: initiator, staticKey: identity.staticKey, prologue: prologue, psk: psk)
        let s: SecureSession
        if initiator {
            try t.send(try hs.writeMessage1())
            let (m3, sess) = try hs.readMessage2WriteMessage3(try t.receive(timeout: timeout))
            try verify(sess.remoteStatic.rawRepresentation)    // check responder BEFORE revealing our identity
            try t.send(m3); s = sess
        } else {
            try t.send(try hs.readMessage1WriteMessage2(try t.receive(timeout: timeout)))
            s = try hs.readMessage3(try t.receive(timeout: timeout))
            try verify(s.remoteStatic.rawRepresentation)
        }
        return SecureChannel(t, s)
    }
}

enum P2PCodec {
    static let enc: JSONEncoder = { let e = JSONEncoder(); e.dateEncodingStrategy = .deferredToDate; e.outputFormatting = .sortedKeys; return e }()
    static let dec: JSONDecoder = { let d = JSONDecoder(); d.dateDecodingStrategy = .deferredToDate; return d }()
}
