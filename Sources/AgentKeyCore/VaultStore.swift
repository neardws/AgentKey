import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// On-disk JSON envelope. Everything except KDF params / ids is AES-256-GCM ciphertext.
public struct VaultFile: Codable, Sendable {
    public var format: String = "agentkey-vault"
    public var version: Int = 1
    public var vaultID: UUID
    public var accountID: UUID
    public var kdf: KDFParams
    /// VK sealed with AUK, AAD = "agentkey/vk|<vaultID>"
    public var wrappedVaultKey: Data
    public var items: [EncryptedItem]
    public var updatedAt: Date
}

public struct EncryptedItem: Codable, Sendable {
    public var id: UUID
    public var revision: Int
    /// VaultItem JSON sealed with VK, AAD = "agentkey/item|<vaultID>|<itemID>|<revision>"
    public var blob: Data
}

public enum VaultError: Error, CustomStringConvertible {
    case badPassword, notFound(String), ambiguous(String), corrupt(String), exists(String)
    public var description: String {
        switch self {
        case .badPassword: return "wrong master password or Secret Key"
        case .notFound(let s): return "item not found: \(s)"
        case .ambiguous(let s): return "more than one item matches: \(s)"
        case .corrupt(let s): return "vault corrupt: \(s)"
        case .exists(let s): return "already exists: \(s)"
        }
    }
}

/// An unlocked vault. Holds the VK in memory; re-reads the file on demand so the
/// daemon and CLI can both write it.
public final class Vault: @unchecked Sendable {
    public let url: URL
    public private(set) var file: VaultFile
    private let vk: SymmetricKey

    static func vkAAD(_ v: UUID) -> Data { Data("agentkey/vk|\(v.uuidString)".utf8) }
    static func itemAAD(_ v: UUID, _ i: UUID, _ r: Int) -> Data { Data("agentkey/item|\(v.uuidString)|\(i.uuidString)|\(r)".utf8) }

    public static var encoder: JSONEncoder {
        let e = JSONEncoder(); e.outputFormatting = [.prettyPrinted, .sortedKeys]; e.dateEncodingStrategy = .iso8601; return e
    }
    public static var decoder: JSONDecoder { let d = JSONDecoder(); d.dateDecodingStrategy = .iso8601; return d }

    /// Create a brand-new vault. Returns the vault and the freshly generated Secret Key
    /// (caller must store it in the Keychain and show it to the user once).
    public static func create(at url: URL, password: String, kdf: KDFParams = .pbkdf2Default(),
                              secretKey: SecretKey = .generate()) throws -> (Vault, SecretKey) {
        if FileManager.default.fileExists(atPath: url.path) { throw VaultError.exists(url.path) }
        let accountID = UUID(), vaultID = UUID()
        let auk = try KeyHierarchy.accountUnlockKey(password: password, secretKey: secretKey, accountID: accountID, params: kdf)
        let vk = SymmetricKey(size: .bits256)
        let wrapped = try KeyHierarchy.seal(vk.data, key: auk, aad: vkAAD(vaultID))
        let f = VaultFile(vaultID: vaultID, accountID: accountID, kdf: kdf, wrappedVaultKey: wrapped, items: [], updatedAt: Date())
        let v = Vault(url: url, file: f, vk: vk)
        try v.save()
        return (v, secretKey)
    }

    public static func unlock(at url: URL, password: String, secretKey: SecretKey) throws -> Vault {
        let f = try readFile(url)
        let auk = try KeyHierarchy.accountUnlockKey(password: password, secretKey: secretKey, accountID: f.accountID, params: f.kdf)
        guard let raw = try? KeyHierarchy.open(f.wrappedVaultKey, key: auk, aad: vkAAD(f.vaultID)) else { throw VaultError.badPassword }
        return Vault(url: url, file: f, vk: SymmetricKey(data: raw))
    }

    static func readFile(_ url: URL) throws -> VaultFile {
        let d = try Data(contentsOf: url)
        let f = try decoder.decode(VaultFile.self, from: d)
        guard f.format == "agentkey-vault", f.version == 1 else { throw VaultError.corrupt("unknown format/version") }
        return f
    }

    init(url: URL, file: VaultFile, vk: SymmetricKey) { self.url = url; self.file = file; self.vk = vk }

    /// Pick up writes made by another process.
    public func reload() throws {
        let f = try Self.readFile(url)
        guard f.vaultID == file.vaultID else { throw VaultError.corrupt("vault id changed") }
        file = f
    }

    public func items() throws -> [VaultItem] {
        try file.items.map { e in
            let pt = try KeyHierarchy.open(e.blob, key: vk, aad: Self.itemAAD(file.vaultID, e.id, e.revision))
            return try Self.decoder.decode(VaultItem.self, from: pt)
        }
    }

    public func upsert(_ item: VaultItem) throws {
        var item = item; item.updatedAt = Date()
        let rev = (file.items.first { $0.id == item.id }?.revision ?? 0) + 1
        let blob = try KeyHierarchy.seal(try Self.encoder.encode(item), key: vk, aad: Self.itemAAD(file.vaultID, item.id, rev))
        file.items.removeAll { $0.id == item.id }
        file.items.append(EncryptedItem(id: item.id, revision: rev, blob: blob))
        try save()
    }

    public func delete(id: UUID) throws {
        file.items.removeAll { $0.id == id }; try save()
    }

    /// Resolve by UUID, exact title (case-insensitive), or URL-encoded title.
    public func resolve(_ ref: ItemRef) throws -> VaultItem {
        let all = try items()
        if let u = UUID(uuidString: ref.item), let i = all.first(where: { $0.id == u }) { return i }
        let m = all.filter { $0.title.caseInsensitiveCompare(ref.item) == .orderedSame }
        if m.count > 1 { throw VaultError.ambiguous(ref.item) }
        guard let i = m.first else { throw VaultError.notFound(ref.item) }
        return i
    }

    public var auditKey: SymmetricKey { KeyHierarchy.subkey(vk, purpose: "audit") }

    public func save() throws {
        file.updatedAt = Date()
        let dir = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let data = try Self.encoder.encode(file)
        let tmp = dir.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp")
        FileManager.default.createFile(atPath: tmp.path, contents: data, attributes: [.posixPermissions: 0o600])
        // POSIX rename(2) is atomic within a directory: readers see old or new file, never half.
        guard rename(tmp.path, url.path) == 0 else {
            try? FileManager.default.removeItem(at: tmp)
            throw VaultError.corrupt("atomic rename failed (errno \(errno))")
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}

extension Vault {
    /// Read the (unencrypted) account id so the Secret Key can be fetched before unlocking.
    public static func accountID(at url: URL) throws -> UUID { try readFile(url).accountID }
}
