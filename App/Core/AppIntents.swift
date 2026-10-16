import AppIntents
import NetworkExtension
import Foundation

// Shortcuts / Siri actions: connect, disconnect, toggle, switch outbound mode, switch node.
// They run in the app process without opening the UI.

enum OutboundModeOption: String, AppEnum {
    case rule, global, direct

    static var typeDisplayRepresentation: TypeDisplayRepresentation = "出站模式"
    static var caseDisplayRepresentations: [OutboundModeOption: DisplayRepresentation] = [
        .rule: "规则",
        .global: "全局",
        .direct: "直连",
    ]
}

struct ConnectIntent: AppIntent {
    static var title: LocalizedStringResource = "连接 Mihomo"
    static var description = IntentDescription("连接代理（使用当前配置）。")
    static var openAppWhenRun = false

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        let ok = await VPNManager.shared.connectAndWait()
        let msg = ok ? "已连接" : "连接失败：\(VPNManager.shared.lastError ?? "请打开 App 查看")"
        return .result(dialog: "\(msg)")
    }
}

struct DisconnectIntent: AppIntent {
    static var title: LocalizedStringResource = "断开 Mihomo"
    static var description = IntentDescription("断开代理。")
    static var openAppWhenRun = false

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        await VPNManager.shared.disconnectAndWait()
        return .result(dialog: "已断开")
    }
}

struct ToggleIntent: AppIntent {
    static var title: LocalizedStringResource = "切换 Mihomo 连接"
    static var description = IntentDescription("已连接时断开，未连接时连接。")
    static var openAppWhenRun = false

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        let vpn = VPNManager.shared
        await vpn.load()
        if vpn.isConnected || vpn.status == .connecting {
            await vpn.disconnectAndWait()
            return .result(dialog: "已断开")
        }
        let ok = await vpn.connectAndWait()
        let msg = ok ? "已连接" : "连接失败：\(vpn.lastError ?? "请打开 App 查看")"
        return .result(dialog: "\(msg)")
    }
}

struct SwitchModeIntent: AppIntent {
    static var title: LocalizedStringResource = "切换出站模式"
    static var description = IntentDescription("在规则、全局、直连之间切换。")
    static var openAppWhenRun = false

    @Parameter(title: "模式", default: .rule)
    var mode: OutboundModeOption

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        await VPNManager.shared.load()
        await DashboardModel.shared.setMode(mode.rawValue)
        let name = ["rule": "规则", "global": "全局", "direct": "直连"][mode.rawValue] ?? mode.rawValue
        return .result(dialog: "已切换到\(name)模式")
    }
}

struct SwitchNodeIntent: AppIntent {
    static var title: LocalizedStringResource = "切换节点"
    static var description = IntentDescription("在策略组中选择节点。未连接时保存到当前配置，下次连接生效。")
    static var openAppWhenRun = false

    @Parameter(title: "节点名称")
    var node: String

    @Parameter(title: "策略组（留空 = 第一个手动选择组）")
    var group: String?

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        let vpn = VPNManager.shared
        await vpn.load()
        let wanted = node.trimmingCharacters(in: .whitespaces)
        if vpn.isConnected {
            let all = try await ControllerClient.shared.proxies()
            let order = all["GLOBAL"]?.all ?? []
            let selectable = order.compactMap { all[$0] }.filter { $0.isSelectable }
            let target: ProxyItem?
            if let g = group, !g.isEmpty { target = all[g] } else { target = selectable.first { $0.all?.contains(wanted) == true } ?? selectable.first }
            guard let t = target, t.isSelectable else { return .result(dialog: "找不到可手动选择的策略组") }
            guard let match = Self.match(wanted, in: t.all ?? []) else { return .result(dialog: "「\(t.name)」中没有节点「\(wanted)」") }
            try await ControllerClient.shared.select(group: t.name, node: match)
            ProfileInspector.rememberLiveSelection(group: t.name, node: match)
            NotificationCenter.default.post(name: .egressMayHaveChanged, object: nil)
            return .result(dialog: "「\(t.name)」已切换到 \(match)")
        }
        let insp = ProfileInspector.shared
        await insp.load()
        let groups = insp.result.groups.filter { $0.type == "select" }
        let target: InspectGroup?
        if let g = group, !g.isEmpty { target = groups.first { $0.name == g } } else { target = groups.first { insp.members(of: $0).contains(wanted) } ?? groups.first }
        guard let t = target else { return .result(dialog: "当前配置没有可手动选择的策略组") }
        guard let match = Self.match(wanted, in: insp.members(of: t)) else { return .result(dialog: "「\(t.name)」中没有节点「\(wanted)」") }
        insp.select(group: t.name, node: match)
        return .result(dialog: "已保存：「\(t.name)」→ \(match)（下次连接生效）")
    }

    /// Exact name first, then a case-insensitive substring match.
    static func match(_ q: String, in names: [String]) -> String? {
        if names.contains(q) { return q }
        return names.first { $0.localizedCaseInsensitiveContains(q) }
    }
}

struct MihomoShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(intent: ConnectIntent(), phrases: ["连接 \(.applicationName)", "Connect \(.applicationName)"])
        AppShortcut(intent: DisconnectIntent(), phrases: ["断开 \(.applicationName)", "Disconnect \(.applicationName)"])
        AppShortcut(intent: ToggleIntent(), phrases: ["切换 \(.applicationName)", "Toggle \(.applicationName)"])
    }
}
