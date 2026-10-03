import Foundation
import Security

public protocol ProfileStoring {
    func load() throws -> VPNProfile
    func save(_ profile: VPNProfile) throws
}

public final class ProfileVault: ProfileStoring {
    private let service: String
    private let account = "profile-v1"
    public init(service: String = "ru.smartvpn.router.ios.profile") { self.service = service }
    private func query() -> [String: Any] {
        var result: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
        #if os(iOS) && !targetEnvironment(simulator)
        if let group = Bundle.main.object(forInfoDictionaryKey: "FoxKeychainGroup") as? String, !group.isEmpty { result[kSecAttrAccessGroup as String] = group }
        #endif
        return result
    }
    public func load() throws -> VPNProfile {
        var q = query(); q[kSecReturnData as String] = true; q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        if status == errSecItemNotFound { return VPNProfile() }
        guard status == errSecSuccess, let data = item as? Data else { throw status == errSecInteractionNotAllowed ? FoxError.locked : FoxError.storage }
        let profile = try JSONDecoder().decode(VPNProfile.self, from: data); try profile.validate(); return profile
    }
    public func save(_ profile: VPNProfile) throws {
        try profile.validate()
        let data = try JSONEncoder().encode(profile)
        let values: [String: Any] = [kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        let status = SecItemUpdate(query() as CFDictionary, values as CFDictionary)
        if status == errSecItemNotFound {
            let add = query().merging(values) { _, value in value }
            guard SecItemAdd(add as CFDictionary, nil) == errSecSuccess else { throw FoxError.storage }
        } else if status != errSecSuccess { throw FoxError.storage }
    }
}
