import Foundation

/// Encrypted offline backup file (".akbackup"). Self-contained: restorable with only the backup
/// passphrase, on any device, with no network. Format (JSON envelope):
///   { format: "agentkey-backup", version: 1, createdAt, kdf: {...}, nonceAAD, ciphertext }
/// ciphertext = AES-256-GCM(KDF(passphrase), JSON payload, AAD = header fields)
public struct BackupFile: Codable, Sendable {
    public var format = "agentkey-backup"
    public var version = 1
    public var createdAt: Date
    public var createdBy: String
    public var itemCount: Int
    public var kdf: KDFParams
    public var ciphertext: Data

    struct Payload: Codable { var items: [VaultItem]; var trust: TrustState?; var note: String }

    var aad: Data { Data("agentkey-backup|\(version)|\(createdBy)|\(itemCount)|\(createdAt.timeIntervalSince1970)|\(kdf.salt.base64EncodedString())|\(kdf.iterations)".utf8) }

    public static func create(items: [VaultItem], trust: TrustState? = nil, passphrase: String, createdBy: String,
                              kdf: KDFParams = .pbkdf2Default()) throws -> Data {
        guard passphrase.count >= 12 else { throw BackupError.weakPassphrase }
        var f = BackupFile(createdAt: Date(timeIntervalSince1970: Date().timeIntervalSince1970.rounded(.down)), createdBy: createdBy,
                           itemCount: items.count, kdf: kdf, ciphertext: Data())
        let key = SymmetricKey(data: try KDFRegistry.kdf(for: kdf).derive(password: passphrase, params: kdf, length: 32))
        let pt = try P2PCodec.enc.encode(Payload(items: items, trust: trust, note: "AgentKey encrypted backup"))
        f.ciphertext = try KeyHierarchy.seal(pt, key: key, aad: f.aad)
        let e = JSONEncoder(); e.outputFormatting = [.prettyPrinted, .sortedKeys]; e.dateEncodingStrategy = .secondsSince1970
        return try e.encode(f)
    }

    public static func restore(_ data: Data, passphrase: String) throws -> (items: [VaultItem], trust: TrustState?, header: BackupFile) {
        let d = JSONDecoder(); d.dateDecodingStrategy = .secondsSince1970
        guard let f = try? d.decode(BackupFile.self, from: data), f.format == "agentkey-backup" else { throw BackupError.notABackup }
        guard f.version == 1 else { throw BackupError.unsupportedVersion(f.version) }
        let key = SymmetricKey(data: try KDFRegistry.kdf(for: f.kdf).derive(password: passphrase, params: f.kdf, length: 32))
        guard let pt = try? KeyHierarchy.open(f.ciphertext, key: key, aad: f.aad) else { throw BackupError.wrongPassphraseOrTampered }
        let p = try P2PCodec.dec.decode(Payload.self, from: pt)
        guard p.items.count == f.itemCount else { throw BackupError.wrongPassphraseOrTampered }
        return (p.items, p.trust, f)
    }
}

public enum BackupError: Error, Equatable, CustomStringConvertible {
    case weakPassphrase, notABackup, unsupportedVersion(Int), wrongPassphraseOrTampered
    public var description: String {
        switch self {
        case .weakPassphrase: return "backup passphrase must be at least 12 characters"
        case .notABackup: return "not an AgentKey backup file"
        case .unsupportedVersion(let v): return "unsupported backup version \(v)"
        case .wrongPassphraseOrTampered: return "wrong passphrase or backup file was modified"
        }
    }
}
