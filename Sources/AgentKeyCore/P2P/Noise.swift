import Foundation

/// Noise Protocol Framework, pattern XX, DH 25519, cipher ChaChaPoly, hash SHA256
/// ("Noise_XX_25519_ChaChaPoly_SHA256"), with an optional pre-shared key mixed in at the start
/// (psk0-style, used for one-time pairing secrets). Implemented on CryptoKit / swift-crypto.
///
///   -> e
///   <- e, ee, s, es
///   -> s, se
///
/// Gives mutual authentication of static keys, forward secrecy (ephemeral DH), and identity hiding
/// for the initiator. Transport messages use per-direction counters: replayed, reordered or
/// modified frames fail to decrypt.
public enum NoiseError: Error, Equatable, CustomStringConvertible {
    case decryptFailed, badMessage(String), nonceExhausted, untrustedPeer(String), wrongState
    public var description: String {
        switch self {
        case .decryptFailed: return "noise: authentication failed (wrong key, tampered, or replayed message)"
        case .badMessage(let s): return "noise: malformed message: \(s)"
        case .nonceExhausted: return "noise: nonce exhausted"
        case .untrustedPeer(let s): return "noise: untrusted peer: \(s)"
        case .wrongState: return "noise: wrong handshake state"
        }
    }
}

public struct CipherState: Sendable {
    var k: SymmetricKey?
    var n: UInt64 = 0
    init(_ k: SymmetricKey? = nil) { self.k = k }

    static func nonce(_ n: UInt64) -> ChaChaPoly.Nonce {
        var b = [UInt8](repeating: 0, count: 12)
        for i in 0..<8 { b[4 + i] = UInt8((n >> (8 * UInt64(i))) & 0xff) }   // little-endian per spec
        return try! ChaChaPoly.Nonce(data: b)
    }

    mutating func encrypt(ad: Data, _ pt: Data) throws -> Data {
        guard let k else { return pt }
        guard n < UInt64.max else { throw NoiseError.nonceExhausted }
        let box = try ChaChaPoly.seal(pt, using: k, nonce: Self.nonce(n), authenticating: ad)
        n += 1
        return box.ciphertext + box.tag
    }

    mutating func decrypt(ad: Data, _ ct: Data) throws -> Data {
        guard let k else { return ct }
        guard ct.count >= 16 else { throw NoiseError.decryptFailed }
        do {
            let box = try ChaChaPoly.SealedBox(nonce: Self.nonce(n), ciphertext: ct.dropLast(16), tag: ct.suffix(16))
            let pt = try ChaChaPoly.open(box, using: k, authenticating: ad)
            n += 1     // only advance on success
            return pt
        } catch { throw NoiseError.decryptFailed }
    }
}

struct SymmetricState {
    var ck: Data
    var h: Data
    var cs = CipherState()

    init(protocolName: String) {
        var p = Data(protocolName.utf8)
        if p.count <= 32 { p.append(Data(repeating: 0, count: 32 - p.count)); h = p } else { h = Data(SHA256.hash(data: p)) }
        ck = h
    }
    mutating func mixHash(_ d: Data) { h = Data(SHA256.hash(data: h + d)) }

    /// Noise HKDF (HMAC-SHA256 based).
    static func hkdf(_ ck: Data, _ ikm: Data, n: Int) -> [Data] {
        let temp = SymmetricKey(data: Data(HMAC<SHA256>.authenticationCode(for: ikm, using: SymmetricKey(data: ck))))
        let o1 = Data(HMAC<SHA256>.authenticationCode(for: Data([1]), using: temp))
        let o2 = Data(HMAC<SHA256>.authenticationCode(for: o1 + Data([2]), using: temp))
        if n == 2 { return [o1, o2] }
        let o3 = Data(HMAC<SHA256>.authenticationCode(for: o2 + Data([3]), using: temp))
        return [o1, o2, o3]
    }
    mutating func mixKey(_ ikm: Data) {
        let o = Self.hkdf(ck, ikm, n: 2); ck = o[0]; cs = CipherState(SymmetricKey(data: o[1]))
    }
    mutating func mixKeyAndHash(_ ikm: Data) {
        let o = Self.hkdf(ck, ikm, n: 3); ck = o[0]; mixHash(o[1]); cs = CipherState(SymmetricKey(data: o[2]))
    }
    mutating func encryptAndHash(_ pt: Data) throws -> Data {
        let c = try cs.encrypt(ad: h, pt); mixHash(c); return c
    }
    mutating func decryptAndHash(_ c: Data) throws -> Data {
        let p = try cs.decrypt(ad: h, c); mixHash(c); return p
    }
    func split() -> (CipherState, CipherState) {
        let o = Self.hkdf(ck, Data(), n: 2)
        return (CipherState(SymmetricKey(data: o[0])), CipherState(SymmetricKey(data: o[1])))
    }
}

public final class NoiseXX {
    public static let protocolName = "Noise_XX_25519_ChaChaPoly_SHA256"
    let initiator: Bool
    let s: Curve25519.KeyAgreement.PrivateKey
    var e: Curve25519.KeyAgreement.PrivateKey?
    var re: Curve25519.KeyAgreement.PublicKey?
    public private(set) var rs: Curve25519.KeyAgreement.PublicKey?
    var ss: SymmetricState
    var step = 0

    /// - prologue: context both sides must agree on (protocol id, vault id …); mismatch ⇒ handshake fails.
    /// - psk: optional 32-byte pre-shared secret (pairing code); mismatch ⇒ handshake fails.
    public init(initiator: Bool, staticKey: Curve25519.KeyAgreement.PrivateKey, prologue: Data, psk: Data? = nil,
                ephemeral: Curve25519.KeyAgreement.PrivateKey? = nil) {
        self.initiator = initiator; s = staticKey; e = ephemeral
        ss = SymmetricState(protocolName: Self.protocolName + (psk == nil ? "" : "+psk0"))
        ss.mixHash(prologue)
        if let psk { ss.mixKeyAndHash(psk) }
    }

    func dh(_ a: Curve25519.KeyAgreement.PrivateKey, _ b: Curve25519.KeyAgreement.PublicKey) throws -> Data {
        try a.sharedSecretFromKeyAgreement(with: b).withUnsafeBytes { Data($0) }
    }

    /// Initiator msg 1: -> e
    public func writeMessage1() throws -> Data {
        guard initiator, step == 0 else { throw NoiseError.wrongState }
        let ek = e ?? Curve25519.KeyAgreement.PrivateKey(); e = ek
        let epub = ek.publicKey.rawRepresentation
        ss.mixHash(epub)
        if ss.cs.k != nil { ss.mixKey(epub) }   // psk mode: ephemeral also mixed into key (Noise psk rule)
        let payload = try ss.encryptAndHash(Data())
        step = 1
        return epub + payload
    }

    /// Responder: read msg 1, write msg 2: <- e, ee, s, es
    public func readMessage1WriteMessage2(_ m: Data) throws -> Data {
        guard !initiator, step == 0 else { throw NoiseError.wrongState }
        guard m.count >= 32 else { throw NoiseError.badMessage("msg1 too short") }
        let rePub = m.prefix(32)
        re = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: rePub)
        ss.mixHash(rePub)
        if ss.cs.k != nil { ss.mixKey(rePub) }
        _ = try ss.decryptAndHash(m.dropFirst(32))
        let ek = e ?? Curve25519.KeyAgreement.PrivateKey(); e = ek
        let epub = ek.publicKey.rawRepresentation
        ss.mixHash(epub)
        if ss.cs.k != nil { ss.mixKey(epub) }
        ss.mixKey(try dh(ek, re!))                                    // ee
        let encS = try ss.encryptAndHash(s.publicKey.rawRepresentation)
        ss.mixKey(try dh(s, re!))                                     // es
        let payload = try ss.encryptAndHash(Data())
        step = 2
        return epub + encS + payload
    }

    /// Initiator: read msg 2, write msg 3: -> s, se. Returns (msg3, transport ciphers).
    public func readMessage2WriteMessage3(_ m: Data) throws -> (Data, SecureSession) {
        guard initiator, step == 1 else { throw NoiseError.wrongState }
        guard m.count >= 32 + 48 + 16 else { throw NoiseError.badMessage("msg2 too short") }
        let rePub = m.prefix(32)
        re = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: rePub)
        ss.mixHash(rePub)
        if ss.cs.k != nil { ss.mixKey(rePub) }
        ss.mixKey(try dh(e!, re!))                                    // ee
        let rsRaw = try ss.decryptAndHash(m.dropFirst(32).prefix(48))
        rs = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: rsRaw)
        ss.mixKey(try dh(e!, rs!))                                    // es
        _ = try ss.decryptAndHash(m.dropFirst(80))
        let encS = try ss.encryptAndHash(s.publicKey.rawRepresentation)
        ss.mixKey(try dh(s, re!))                                     // se
        let payload = try ss.encryptAndHash(Data())
        step = 3
        let (c1, c2) = ss.split()
        return (encS + payload, SecureSession(send: c1, recv: c2, handshakeHash: ss.h, remoteStatic: rs!))
    }

    /// Responder: read msg 3.
    public func readMessage3(_ m: Data) throws -> SecureSession {
        guard !initiator, step == 2 else { throw NoiseError.wrongState }
        guard m.count >= 48 + 16 else { throw NoiseError.badMessage("msg3 too short") }
        let rsRaw = try ss.decryptAndHash(m.prefix(48))
        rs = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: rsRaw)
        ss.mixKey(try dh(e!, rs!))                                    // se
        _ = try ss.decryptAndHash(m.dropFirst(48))
        step = 3
        let (c1, c2) = ss.split()
        return SecureSession(send: c2, recv: c1, handshakeHash: ss.h, remoteStatic: rs!)
    }
}

/// Post-handshake transport state.
public struct SecureSession {
    var send: CipherState
    var recv: CipherState
    public let handshakeHash: Data            // channel binding (same on both sides)
    public let remoteStatic: Curve25519.KeyAgreement.PublicKey
    public mutating func seal(_ pt: Data) throws -> Data { try send.encrypt(ad: Data(), pt) }
    public mutating func open(_ ct: Data) throws -> Data { try recv.decrypt(ad: Data(), ct) }
}
