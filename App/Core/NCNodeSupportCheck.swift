import Foundation

/// One node of the current config the native core cannot dial, with the kernel's own reason
/// (NCSupport.unsupportedReason — the same conclusion the tunnel reports at startup).
struct NCUnsupportedNode: Identifiable, Equatable {
    var name: String
    var reason: String
    var id: String { name }
}

enum NCNodeSupportCheck {
    /// Evaluates a profile exactly the way a connect does (NCRuntimeBuilder → NCConfig.decode)
    /// and returns the nodes NCSupport rejects, in config order. nil = the runtime config could
    /// not be built, so there is no honest verdict to show. Call off the main thread: it runs
    /// the full runtime build (providers, overrides, group chains).
    static func unsupportedNodes(home: String, profilePath: String, text: String) -> [NCUnsupportedNode]? {
        let req = NCRuntimeBuilder.Request.load(home: home, profilePath: profilePath)
        guard let built = try? NCRuntimeBuilder.build(profile: Data(text.utf8), req: req, fd: 0) else { return nil }
        let cfg = NCConfig.decode(root: built.raw)
        return cfg.proxies.compactMap { p in
            NCSupport.unsupportedReason(p).map { NCUnsupportedNode(name: p.name, reason: $0) }
        }
    }
}
