import Foundation
import Security

/// Minimal keychain wrapper (generic password) for small secrets that more than one
/// process reads: the external-controller secret and the LAN-share password.
///
/// The App Group ID doubles as the keychain access group: the app, the widget and the
/// PacketTunnel extension all carry the com.apple.security.application-groups entitlement
/// (this project configures no keychain-access-groups entitlement), and iOS accepts an
/// app group as a keychain access group — so one item is shared by all three processes
/// without touching provisioning profiles.
enum Keychain {
    private static let service = "com.astemo6.mihomo"

    /// kSecAttrAccount names used through this wrapper.
    static let controllerSecretAccount = "controller-secret"
    static let lanSharePasswordAccount = "lan-share-password"

    private static func baseQuery(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessGroup as String: AppShared.appGroup,
            // The tunnel extension may need the secret while the device is locked
            // (on-demand restarts), so allow access after first unlock.
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]
    }

    /// The stored value, or nil when absent / unreadable (e.g. keychain unavailable).
    static func read(_ account: String) -> String? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let value = String(data: data, encoding: .utf8),
              !value.isEmpty else { return nil }
        return value
    }

    /// Adds or updates the item. An empty value deletes it.
    @discardableResult
    static func write(_ account: String, _ value: String) -> Bool {
        guard !value.isEmpty, let data = value.data(using: .utf8) else {
            delete(account)
            return true
        }
        let query = baseQuery(account: account)
        let update: [String: Any] = [kSecValueData as String: data]
        if SecItemUpdate(query as CFDictionary, update as CFDictionary) == errSecSuccess {
            return true
        }
        var add = query
        add[kSecValueData as String] = data
        return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
    }

    static func delete(_ account: String) {
        let query = baseQuery(account: account)
        SecItemDelete(query as CFDictionary)
    }
}
