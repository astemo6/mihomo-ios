import Foundation
import SwiftUI
import Libmihomo

/// 代理链 (Loon proxy chain): named chains of nodes / policy groups, entry first → exit last, kept app-wide in
/// <home>/proxy-chains.json. The Go side (bridge/proxychains.go) turns each 启用 chain into a policy group named
/// after the chain while the runtime config is built (mihomo dialer-proxy; the relay group type is gone), so a
/// chain is picked in policy groups and rules like any group. Members are looked up by name in the current
/// profile; a chain whose members are missing there is skipped and its name removed from groups and rules.
struct ProxyChain: Codable, Identifiable, Hashable {
    var id: String = UUID().uuidString
    var name: String
    var udp: Bool = false
    var enabled: Bool = true
    var members: [String] = []
}

@MainActor
final class ProxyChainStore: ObservableObject {
    static let shared = ProxyChainStore()

    /// Proxy-providers the Go side makes for chains (copies of member nodes); hidden from node lists.
    nonisolated static let generatedPrefix = "tern.chain/"
    nonisolated static func isGenerated(_ provider: String) -> Bool { provider.hasPrefix(generatedPrefix) }

    @Published private(set) var chains: [ProxyChain] = []

    nonisolated static var url: URL { AppShared.homeURL.appendingPathComponent("proxy-chains.json") }

    private init() { reload() }

    func reload() {
        if let d = try? Data(contentsOf: Self.url), let v = try? JSONDecoder().decode([ProxyChain].self, from: d) {
            chains = v
        } else {
            chains = []
        }
    }

    /// Names a new or renamed chain cannot use (other chains).
    func nameTaken(_ name: String, except id: String?) -> Bool {
        chains.contains { $0.id != id && $0.name == name }
    }

    func save(_ c: ProxyChain) async -> String? {
        var list = chains
        if let i = list.firstIndex(where: { $0.id == c.id }) {
            let old = list[i].name
            list[i] = c
            if old != c.name {
                // The chain is a policy: references to its old name follow it.
                if let pid = AppShared.activeProfileID { NameRefs.rename(old, to: c.name, profileID: pid, isGroup: true) }
            }
        } else {
            list.append(c)
        }
        return await write(list)
    }

    func delete(_ c: ProxyChain) async -> String? {
        await write(chains.filter { $0.id != c.id })
    }

    func setEnabled(_ c: ProxyChain, _ on: Bool) async -> String? {
        guard let i = chains.firstIndex(where: { $0.id == c.id }), chains[i].enabled != on else { return nil }
        var list = chains
        list[i].enabled = on
        return await write(list)
    }

    func move(from: IndexSet, to: Int) async -> String? {
        var list = chains
        list.move(fromOffsets: from, toOffset: to)
        return await write(list)
    }

    /// A node or group renamed (new != nil) or deleted elsewhere in the app: chain members follow.
    func renameMember(_ old: String, to new: String?) {
        var changed = false
        var list = chains
        for i in list.indices where list[i].members.contains(old) {
            list[i].members = list[i].members.compactMap { $0 == old ? new : $0 }
            changed = true
        }
        guard changed else { return }
        chains = list
        persist(list)
    }

    private func persist(_ list: [ProxyChain]) {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let d = try? enc.encode(list) { try? d.write(to: Self.url, options: .atomic) }
    }

    /// Writes the list, then reloads the core when connected. Returns an error message or nil.
    private func write(_ list: [ProxyChain]) async -> String? {
        chains = list
        persist(list)
        if VPNManager.shared.isConnected, let e = await VPNManager.shared.reload() { return e }
        await ProfileInspector.shared.load()
        return nil
    }
}

/// A node or group a chain can use, from bridge ProxyChainCandidates (the current profile without chains).
enum ProxyChainCandidates {
    private struct Response: Decodable { var candidates: [ChainCandidate] }

    static func load() async -> [ChainCandidate] {
        guard let path = AppShared.activeProfileURL?.path else { return [] }
        let home = AppShared.homeURL.path
        let json = await Task.detached(priority: .userInitiated) { LibmihomoProxyChainCandidates(home, path) }.value
        return (try? JSONDecoder().decode(Response.self, from: Data(json.utf8)))?.candidates ?? []
    }
}
