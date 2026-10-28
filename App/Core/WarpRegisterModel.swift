import Foundation

/// feat/nc-warp-register: the thin view-model behind WarpRegisterSheet. Registers a WARP device
/// (WarpRegistration.register), saves the node as a manual node (ProfileStore.upsertManualNode — the manual profile in
/// the App Group, like every hand-added node) and the device credentials in the shared Keychain. When saving the node
/// fails the just-registered device is deleted again so nothing is left behind at Cloudflare.
@MainActor
final class WarpRegisterModel: ObservableObject {
    enum Phase: Equatable {
        case idle, working, done(String), failed(String)
    }

    @Published var name = WarpRegistration.defaultName
    @Published var acceptedTerms = false
    @Published private(set) var phase: Phase = .idle

    /// Injected for tests / previews; the app uses the real API and ProfileStore.
    /// Defaults read from WarpNodeLifecycle so UI tests can override in one place.
    var http: WarpRegistration.HTTP = WarpNodeLifecycle.http
    var existingNames: @MainActor () -> Set<String> = {
        Set(ProfileStore.shared.manualNodes().compactMap { $0["name"] as? String })
    }
    var save: @MainActor ([String: Any]) async throws -> Void = { try await ProfileStore.shared.upsertManualNode($0, oldName: nil) }
    var credentials: WarpRegistration.CredentialStore = WarpNodeLifecycle.credentials

    /// The current registration task, for cancellation.
    private var currentTask: Task<WarpRegistration.Node, Error>?

    var canRegister: Bool { acceptedTerms && phase != .working }

    /// "Cloudflare WARP", "Cloudflare WARP 2", … — a manual node with the same name would be replaced otherwise.
    nonisolated static func uniqueName(_ wanted: String, taken: Set<String>) -> String {
        let base = wanted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? WarpRegistration.defaultName : wanted.trimmingCharacters(in: .whitespacesAndNewlines)
        if !taken.contains(base) { return base }
        var i = 2
        while taken.contains("\(base) \(i)") { i += 1 }
        return "\(base) \(i)"
    }

    /// Cancels the ongoing registration. If a device was already registered, it will be unregistered.
    func cancel() {
        currentTask?.cancel()
        currentTask = nil
    }

    @discardableResult
    func register() async -> WarpRegistration.Node? {
        guard canRegister else { return nil }
        phase = .working
        let nodeName = Self.uniqueName(name, taken: existingNames())
        // The work runs in its own task so cancel() can stop it; a cancellation
        // inside WarpRegistration.register unregisters a half-registered device
        // (its PATCH failure path), and lands back here as CancellationError.
        let task = Task { () throws -> WarpRegistration.Node in
            let node = try await WarpRegistration.register(name: nodeName, http: http)
            do {
                try await save(node.proxyFields)
            } catch {
                try? await WarpRegistration.unregister(node.account, http: http)
                throw error
            }
            WarpRegistration.saveAccount(node.account, nodeName: node.name, store: credentials)
            return node
        }
        currentTask = task
        defer { currentTask = nil }
        do {
            let node = try await task.value
            phase = .done(node.name)
            return node
        } catch is CancellationError {
            phase = .idle
            return nil
        } catch {
            phase = .failed(error.localizedDescription)
            return nil
        }
    }
}
