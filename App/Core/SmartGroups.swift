import Foundation
import Libmihomo

/// 智能选择 option for url-test / fallback groups, stored per profile in <home>/groups.json
/// ({"<profile id>": {"smart": [names]}}); the Go side scores members and pins the best (bridge/smart.go).
@MainActor
final class SmartGroups: ObservableObject {
    static let shared = SmartGroups()

    /// groups.json entry; `dialer` (group → 前置代理) is written by the Go side (SetGroupChain) and kept here.
    struct Settings: Codable { var smart: [String]?; var dialer: [String: String]? }
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
        load() // pick up chain changes written by Go
        var st = all[id] ?? Settings()
        st.smart = list.isEmpty ? nil : list
        all[id] = st
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let d = try? enc.encode(all) { try? d.write(to: Self.url, options: .atomic) }
        Task {
            if VPNManager.shared.isConnected { _ = await VPNManager.shared.reload() }
            await refreshStatus()
        }
    }

    /// 前置代理 of a group in the active profile.
    func via(_ group: String) -> String? {
        guard let id = profileID else { return nil }
        return all[id]?.dialer?[group]
    }

    /// Stores (or clears) a group's 前置代理 through Go (validates against loops), then reloads.
    func setVia(_ group: String, _ via: String?) async -> String? {
        guard let path = AppShared.activeProfileURL?.path else { return String(localized: "没有当前配置") }
        let home = AppShared.homeURL.path
        let err = await Task.detached { LibmihomoSetGroupChain(home, path, group, via ?? "") }.value
        load()
        if !err.isEmpty { return err }
        if VPNManager.shared.isConnected { return await VPNManager.shared.reload() }
        return nil
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
