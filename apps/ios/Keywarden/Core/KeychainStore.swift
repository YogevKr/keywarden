import Foundation
import Security

final class KeychainStore {
    private let service: String
    private let accessGroup: String?

    init(service: String = "ai.sawmills.keywarden", accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }

    func save(_ data: Data, for key: String) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        let attributes: [String: Any] = [kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        let updated = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if updated == errSecSuccess { return }
        guard updated == errSecItemNotFound else { throw KeywardenError.keychain(updated) }
        var item = query
        item[kSecValueData as String] = data
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeywardenError.keychain(status) }
    }

    func load(_ key: String) throws -> Data? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw KeywardenError.keychain(status)
        }
        return data
    }

    func allData() throws -> [Data] {
        var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let values = result as? [Data] else { throw KeywardenError.keychain(status) }
        return values
    }

    func remove(_ key: String) throws {
        var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrAccount as String: key]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw KeywardenError.keychain(status) }
    }
}

enum KeywardenError: LocalizedError {
    case invalidEncoding
    case invalidKey
    case missingSetting(String)
    case keychain(OSStatus)
    case invalidEnvelope
    case authenticationFailed
    case invalidSetupQR
    case requestExpired
    case relayStatus(Int)

    var errorDescription: String? {
        switch self {
        case .invalidEncoding: return "The relay returned invalid base64 data."
        case .invalidKey: return "The stored key is invalid."
        case .missingSetting(let name): return "Missing setting: \(name)"
        case .keychain(let status): return "Keychain error: \(status)"
        case .invalidEnvelope: return "The approval request is invalid."
        case .authenticationFailed: return "Face ID approval failed."
        case .invalidSetupQR: return "The setup QR code is invalid."
        case .requestExpired: return "This request expired. Ask the agent to send a new request."
        case .relayStatus(let status): return "Relay returned HTTP \\(status). Check the connection settings."
        }
    }
}
