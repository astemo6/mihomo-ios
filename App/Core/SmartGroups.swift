import Foundation

/// 智能选择 option for url-test / fallback groups, stored per profile in <home>/groups.json
/// ({"<profile id>": {"smart": [names]}}); the Go side scores members and pins the best (bridge/smart.go).
@MainActor
final class SmartGroups: ObservableObject {
    static let shared = SmartGroups()

    struct Settings: Codable { var smart: [String]? }
    struct Member: Decodable, Hashable { var name: String; var score: Double; var avg: Int; var fails: Int; var count: Int; var alive: Bool }
    struct Status: Decodable, Hashable {
        var name: String
        var type: String?
        var now: String?
        var pinned: String?
        var switchedAt: Double?
        var checkedAt: Double?
        var members: [Member]?
    }
    private struct StatusResponse: Decodable { var groups: [Status] }

    @Published private(set) var all: [String: Settings] = [:]
    @Published var status: [String: Status] = [:]

    static var url: URL { AppShared.homeURL.appendingPathComponent("groups.json") }
    var profileID: String? { AppShared.activeProfileURL?.deletingPathExtension().lastPathComponent }

    init() { load() }

    func load() {
        if let d = try? Data(contentsOf: Self.url), let m = try? JSONDecoder().decode([String: Settings].self, from: d) { all = m }
    }

    func isSmart(_ group: String) -> Bool {
        guard let id = profileID else { return false }
        return all[id]?.smart?.contains(group) == true
    }

    func set(_ group: String, smart on: Bool) {
        guard let id = profileID else { return }
        var list = all[id]?.smart ?? []
        list.removeAll { $0 == group }
        if on { list.append(group) }
        all[id] = Settings(smart: list.isEmpty ? nil : list)
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let d = try? enc.encode(all) { try? d.write(to: Self.url, options: .atomic) }
        Task {
            if VPNManager.shared.isConnected { _ = await VPNManager.shared.reload() }
            await refreshStatus()
        }
    }

    func refreshStatus() async {
        guard VPNManager.shared.isConnected,
              let r = try? await ControllerClient.shared.get(StatusResponse.self, "/smart") else { status = [:]; return }
        var m: [String: Status] = [:]
        for g in r.groups { m[g.name] = g }
        status = m
    }

    /// One line for the group card.
    func summary(_ group: String) -> String? {
        guard isSmart(group) else { return nil }
        guard let st = status[group], let members = st.members, !members.isEmpty else {
            return String(localized: "等待首次评分（使用策略组自身的健康检查结果）")
        }
        let cur = st.pinned ?? st.now ?? ""
        if let m = members.first(where: { $0.name == cur }), m.score >= 0 {
            return String(localized: "已选 \(cur) · 近期平均 \(m.avg) ms · 失败 \(m.fails)/\(m.count)")
        }
        return String(localized: "暂无足够的测速记录，沿用 \(st.now ?? "—")")
    }
}
