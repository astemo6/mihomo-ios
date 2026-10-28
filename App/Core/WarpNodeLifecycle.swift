import Foundation

/// feat/nc-warp-register-ui: lifecycle hooks for WARP nodes (delete cleanup, rename migration, re-register).
/// All static methods are injectable for UI tests via `WarpRegisterModel`'s injection points.
enum WarpNodeLifecycle {

    /// The HTTP transport, injectable for tests. Defaults to `WarpRegistration.urlSession`.
    static var http: WarpRegistration.HTTP = WarpRegistration.urlSession

    /// The credential store, injectable for tests. Defaults to `WarpRegistration.CredentialStore.keychain`.
    static var credentials: WarpRegistration.CredentialStore = .keychain

    /// Performs cleanup when a WARP node is deleted.
    /// - Returns: A warning message if unregister failed (nil on success or no account record).
    @discardableResult
    static func deleteCleanup(nodeName: String) async -> String? {
        guard let account = WarpRegistration.account(nodeName: nodeName, store: credentials) else {
            return nil
        }
        do {
            try await WarpRegistration.unregister(account, http: http)
        } catch {
            // Unregister failed — forget the local record anyway, but return a warning.
            // (No error detail in the text: failure descriptions can carry server bodies.)
            WarpRegistration.forgetAccount(nodeName: nodeName, store: credentials)
            return String(localized: "节点已删除，但设备未能注销", table: "WarpRegister")
        }
        WarpRegistration.forgetAccount(nodeName: nodeName, store: credentials)
        return nil
    }

    /// Migrates the WARP account record from an old node name to a new one.
    /// Called when a manual WARP node is renamed.
    static func migrateRename(from oldName: String, to newName: String) {
        guard oldName != newName,
              let account = WarpRegistration.account(nodeName: oldName, store: credentials) else { return }
        WarpRegistration.saveAccount(account, nodeName: newName, store: credentials)
        WarpRegistration.forgetAccount(nodeName: oldName, store: credentials)
    }

    /// Re-registers a WARP node with the same name, replacing its keys and credentials.
    /// - Parameters:
    ///   - nodeName: The node name (same as before).
    ///   - save: A closure that saves the node fields (e.g., `ProfileStore.upsertManualNode`).
    /// - Returns: A warning message if unregistering the old device failed (nil on success).
    /// - Throws: If saving the new node fails (the new device is unregistered and the error is propagated).
    @discardableResult
    static func reregister(nodeName: String, save: @escaping @MainActor ([String: Any]) async throws -> Void) async throws -> String? {
        let node = try await WarpRegistration.register(name: nodeName, http: http)
        do {
            try await save(node.proxyFields)
        } catch {
            // Save failed: unregister the new device and propagate the error.
            try? await WarpRegistration.unregister(node.account, http: http)
            throw error
        }
        // Save succeeded: unregister the old device (best effort), then save the new account.
        var warning: String? = nil
        if let oldAccount = WarpRegistration.account(nodeName: nodeName, store: credentials) {
            do {
                try await WarpRegistration.unregister(oldAccount, http: http)
            } catch {
                warning = String(localized: "节点已重新注册，但旧设备未能注销", table: "WarpRegister")
            }
        }
        WarpRegistration.saveAccount(node.account, nodeName: node.name, store: credentials)
        return warning
    }
}