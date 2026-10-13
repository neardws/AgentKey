import Foundation

/// AUK = KDF(masterPassword) XOR HKDF-SHA256(SecretKey, salt: accountID, info: "agentkey/2skd/v1")
/// The AUK only unwraps the Vault Key (VK). Items are sealed with the VK.
public enum KeyHierarchy {
    public static let info2SKD = Data("agentkey/2skd/v1".utf8)

    public static func accountUnlockKey(password: String, secretKey: SecretKey,
                                        accountID: UUID, params: KDFParams) throws -> SymmetricKey {
        var k1 = try KDFRegistry.kdf(for: params).derive(password: password, params: params, length: 32)
        let k2 = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: secretKey.bytes),
                                        salt: Data(accountID.uuidString.lowercased().utf8),
                                        info: info2SKD, outputByteCount: 32).data
        var auk = Data(count: 32)
        for i in 0..<32 { auk[i] = k1[i] ^ k2[i] }
        k1.wipe()
        defer { auk.wipe() }
        return SymmetricKey(data: auk)
    }

    /// Per-purpose subkey (e.g. audit chain HMAC key) derived from the VK.
    public static func subkey(_ vk: SymmetricKey, purpose: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: vk, info: Data("agentkey/\(purpose)/v1".utf8), outputByteCount: 32)
    }

    public static func seal(_ plaintext: Data, key: SymmetricKey, aad: Data) throws -> Data {
        try AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce(), authenticating: aad).combined!
    }

    public static func open(_ combined: Data, key: SymmetricKey, aad: Data) throws -> Data {
        try AES.GCM.open(AES.GCM.SealedBox(combined: combined), using: key, authenticating: aad)
    }
}
