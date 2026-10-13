import Foundation
#if canImport(Security)
import Security
#endif

/// Stores the Secret Key on this device only. macOS/iOS: Keychain generic password,
/// kSecAttrAccessibleWhenUnlockedThisDeviceOnly, NOT synchronizable. Elsewhere: 0600 file.
public enum SecretKeyStore {
    static let service = "com.neardws.agentkey.secret-key"

    public static func save(_ key: SecretKey, account: UUID) throws {
        #if canImport(Security) && !os(Linux)
        let base: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                   kSecAttrService as String: service,
                                   kSecAttrAccount as String: account.uuidString]
        SecItemDelete(base as CFDictionary)
        var add = base
        add[kSecValueData as String] = Data(key.formatted.utf8)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        add[kSecAttrSynchronizable as String] = kCFBooleanFalse
        let st = SecItemAdd(add as CFDictionary, nil)
        guard st == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(st)) }
        #else
        let url = AKPaths.secretKeyFile
        FileManager.default.createFile(atPath: url.path, contents: Data("\(account.uuidString) \(key.formatted)\n".utf8),
                                       attributes: [.posixPermissions: 0o600])
        #endif
    }

    public static func load(account: UUID) -> SecretKey? {
        if let env = ProcessInfo.processInfo.environment["AGENTKEY_SECRET_KEY"] { return SecretKey(formatted: env) }
        #if canImport(Security) && !os(Linux)
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: service,
                                kSecAttrAccount as String: account.uuidString,
                                kSecReturnData as String: true]
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return SecretKey(formatted: String(decoding: d, as: UTF8.self))
        #else
        guard let s = try? String(contentsOf: AKPaths.secretKeyFile, encoding: .utf8) else { return nil }
        let parts = s.split(separator: " ")
        guard parts.count == 2, parts[0] == account.uuidString else { return nil }
        return SecretKey(formatted: String(parts[1]).trimmingCharacters(in: .whitespacesAndNewlines))
        #endif
    }
}
