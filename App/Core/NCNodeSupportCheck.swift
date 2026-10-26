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

    /// The kernel's reason (NCSupport, Chinese — it is also written to the startup log) for display in the App's
    /// language. Known shapes go through Localizable.xcstrings with the variable part (type / transport / plugin
    /// names, field names) kept verbatim; anything else is shown as the kernel wrote it.
    static func localizedReason(_ r: String) -> String {
        func m(_ pattern: String) -> [String]? {
            guard let re = try? NSRegularExpression(pattern: pattern),
                  let hit = re.firstMatch(in: r, range: NSRange(r.startIndex..., in: r)) else { return nil }
            return (1..<hit.numberOfRanges).compactMap { Range(hit.range(at: $0), in: r).map { String(r[$0]) } }
        }
        if let g = m("^类型 (.+) 尚未接入$") { return String(localized: "类型 \(g[0]) 尚未接入") }
        if let g = m("^传输 (.+) 尚未接入$") { return String(localized: "传输 \(g[0]) 尚未接入") }
        if let g = m("^Shadowsocks 插件 (.+) 尚未接入$") { return String(localized: "Shadowsocks 插件 \(g[0]) 尚未接入") }
        if let g = m("^SSR 加密 (.+) 尚未接入$") { return String(localized: "SSR 加密 \(g[0]) 尚未接入") }
        if let g = m("^SSR 协议 (.+) 尚未接入$") { return String(localized: "SSR 协议 \(g[0]) 尚未接入") }
        if let g = m("^SSR 混淆 (.+) 尚未接入$") { return String(localized: "SSR 混淆 \(g[0]) 尚未接入") }
        if let g = m("^([^\\p{Han}]+) 缺少 ([^\\p{Han}]+)$") { return String(localized: "\(g[0]) 缺少 \(g[1])") }
        if let g = m("^([^\\p{Han}]+) 尚未接入$") { return String(localized: "\(g[0]) 尚未接入") }
        if let g = m("^([^\\p{Han}]+) 无效$") { return String(localized: "\(g[0]) 无效") }
        return r
    }
}
