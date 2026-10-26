import Foundation

/// v0.19.8: the order of the running core's policy groups. The app used GLOBAL's member list for it (Clash.Meta builds
/// GLOBAL from every proxy and group in config order); once the profile or a 策略组编辑 edit defines its own GLOBAL
/// group, GLOBAL lists only what the user put in it. Every apply writes the runtime's group order to
/// <home>/runtime-groups.json (bridge writeRuntimeGroupOrder); it is read here, and groups the file does not know
/// (an older extension, a group added since) follow in GLOBAL's order.
enum LiveGroupOrder {
    static var url: URL { AppShared.homeURL.appendingPathComponent("runtime-groups.json") }

    static func fileOrder() -> [String] {
        guard let d = try? Data(contentsOf: url), let l = try? JSONDecoder().decode([String].self, from: d) else { return [] }
        return l
    }

    /// Names in order: groups from the runtime file that the core has, then the rest of GLOBAL's members.
    static func names(_ proxies: [String: ProxyItem]) -> [String] {
        var out: [String] = []
        var seen: Set<String> = []
        for n in fileOrder() where proxies[n] != nil && !seen.contains(n) { out.append(n); seen.insert(n) }
        for n in proxies["GLOBAL"]?.all ?? [] where !seen.contains(n) { out.append(n); seen.insert(n) }
        return out
    }
}
