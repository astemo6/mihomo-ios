import AppIntents
import NetworkExtension
import Foundation

// Shortcuts / Siri actions: connect, disconnect, toggle, switch outbound mode, switch node; v0.8 adds status,
// switch profile, toggle module, update subscriptions and run a script.
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
    static var title: LocalizedStringResource = "连接 Tern"
    static var description = IntentDescription("连接代理（使用当前配置）。")
    static var openAppWhenRun = false

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        let ok = await VPNManager.shared.connectAndWait()
        // v0.19.2: was built from plain literals (always Chinese).
        let msg = ok ? String(localized: "已连接") : Self.failure(VPNManager.shared.lastError)
        return .result(dialog: "\(msg)")
    }

    /// The failure dialog of the connect intents, in the app language.
    static func failure(_ error: String?) -> String {
        guard let e = error, !e.isEmpty else { return String(localized: "连接失败，请打开 App 查看") }
        return e.hasPrefix(String(localized: "连接失败：")) ? e : String(localized: "连接失败：") + e
    }
}

struct DisconnectIntent: AppIntent {
    static var title: LocalizedStringResource = "断开 Tern"
    static var description = IntentDescription("断开代理。")
    static var openAppWhenRun = false

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        await VPNManager.shared.disconnectAndWait()
        return .result(dialog: "已断开")
    }
}

struct ToggleIntent: AppIntent {
    static var title: LocalizedStringResource = "切换 Tern 连接"
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
        let msg = ok ? String(localized: "已连接") : ConnectIntent.failure(vpn.lastError)
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
        let name = ["rule": String(localized: "规则"), "global": String(localized: "全局"), "direct": String(localized: "直连")][mode.rawValue] ?? mode.rawValue
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
            let order = LiveGroupOrder.names(all)
            let selectable = order.compactMap { all[$0] }.filter { $0.isSelectable }
            let target: ProxyItem?
            if let g = group, !g.isEmpty { target = all[g] } else { target = selectable.first { $0.all?.contains(wanted) == true } ?? selectable.first }
            guard let t = target, t.isSelectable else { return .result(dialog: "找不到可手动选择的策略组") }
            guard let match = Self.match(wanted, in: t.all ?? []) else { return .result(dialog: "「\(t.name)」中没有节点「\(wanted)」") }
            try await ControllerClient.shared.select(group: t.name, node: match)
            await ControllerClient.shared.afterUserSwitch() // v0.19
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

// MARK: - v0.8 Shortcuts: status, profile, module, subscriptions, script

struct StatusIntent: AppIntent {
    static var title: LocalizedStringResource = "查询 Tern 状态"
    static var description = IntentDescription("返回连接状态、出站模式、当前节点与配置，可在快捷指令中继续使用。")
    static var openAppWhenRun = false

    @MainActor
    func perform() async throws -> some IntentResult & ReturnsValue<String> & ProvidesDialog {
        let vpn = VPNManager.shared
        await vpn.load()
        let profile = ProfileStore.shared.active?.name ?? String(localized: "未选择")
        guard vpn.isConnected else {
            let text = String(localized: "未连接 · 配置 \(profile)")
            return .result(value: text, dialog: "\(text)")
        }
        let mode = (try? await ControllerClient.shared.configs())?["mode"] as? String ?? CoreOverrides.load().mode
        let modeName = ["rule": String(localized: "规则"), "global": String(localized: "全局"), "direct": String(localized: "直连")][mode.lowercased()] ?? mode
        await DashboardModel.shared.refreshSelectedNode()
        let node = DashboardModel.shared.selectedNode
        let text = String(localized: "已连接 · \(modeName)模式 · 节点 \(node) · 配置 \(profile)")
        return .result(value: text, dialog: "\(text)")
    }
}

struct ProfileEntity: AppEntity {
    static var typeDisplayRepresentation: TypeDisplayRepresentation = "配置"
    static var defaultQuery = ProfileEntityQuery()
    var id: String
    var name: String
    var displayRepresentation: DisplayRepresentation { DisplayRepresentation(title: "\(name)") }
}

struct ProfileEntityQuery: EntityQuery {
    @MainActor
    func entities(for identifiers: [String]) async throws -> [ProfileEntity] {
        ProfileStore.shared.profiles.filter { identifiers.contains($0.id) }.map { ProfileEntity(id: $0.id, name: $0.name) }
    }

    @MainActor
    func suggestedEntities() async throws -> [ProfileEntity] {
        ProfileStore.shared.profiles.filter(\.enabled).map { ProfileEntity(id: $0.id, name: $0.name) }
    }
}

struct SwitchProfileIntent: AppIntent {
    static var title: LocalizedStringResource = "切换配置"
    static var description = IntentDescription("把当前配置切换为所选配置；已连接时立即重载。")
    static var openAppWhenRun = false

    @Parameter(title: "配置")
    var profile: ProfileEntity

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        await VPNManager.shared.load()
        guard let p = ProfileStore.shared.profiles.first(where: { $0.id == profile.id }) else {
            return .result(dialog: "找不到配置「\(profile.name)」")
        }
        if !p.enabled { return .result(dialog: "「\(p.name)」已停用，启用后才能设为当前配置") }
        if let e = await ProfileStore.shared.setActive(p) { return .result(dialog: "已切换到「\(p.name)」，但重载失败：\(e)") }
        NotificationCenter.default.post(name: .egressMayHaveChanged, object: nil)
        return .result(dialog: "已切换到「\(p.name)」")
    }
}

struct ModuleEntity: AppEntity {
    static var typeDisplayRepresentation: TypeDisplayRepresentation = "模块"
    static var defaultQuery = ModuleEntityQuery()
    var id: String
    var name: String
    var displayRepresentation: DisplayRepresentation { DisplayRepresentation(title: "\(name)") }
}

struct ModuleEntityQuery: EntityQuery {
    @MainActor
    func entities(for identifiers: [String]) async throws -> [ModuleEntity] {
        EngineStore.shared.config.modules.filter { identifiers.contains($0.id) }.map { ModuleEntity(id: $0.id, name: $0.name) }
    }

    @MainActor
    func suggestedEntities() async throws -> [ModuleEntity] {
        EngineStore.shared.config.modules.map { ModuleEntity(id: $0.id, name: $0.name) }
    }
}

enum SwitchAction: String, AppEnum {
    case on, off, toggle
    static var typeDisplayRepresentation: TypeDisplayRepresentation = "操作"
    static var caseDisplayRepresentations: [SwitchAction: DisplayRepresentation] = [
        .on: "开启",
        .off: "关闭",
        .toggle: "切换",
    ]
}

struct ToggleModuleIntent: AppIntent {
    static var title: LocalizedStringResource = "开关模块"
    static var description = IntentDescription("开启、关闭或切换一个模块；已连接时自动重载。")
    static var openAppWhenRun = false

    @Parameter(title: "模块")
    var module: ModuleEntity

    @Parameter(title: "操作", default: .toggle)
    var action: SwitchAction

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        await VPNManager.shared.load()
        let store = EngineStore.shared
        guard let i = store.config.modules.firstIndex(where: { $0.id == module.id }) else {
            return .result(dialog: "找不到模块「\(module.name)」")
        }
        let on: Bool
        switch action {
        case .on: on = true
        case .off: on = false
        case .toggle: on = !store.config.modules[i].enabled
        }
        store.config.modules[i].enabled = on
        store.save(reload: false)
        if VPNManager.shared.isConnected, let e = await VPNManager.shared.reload(hot: true) {
            return .result(dialog: "模块「\(module.name)」已\(on ? String(localized: "开启") : String(localized: "关闭"))，但重载失败：\(e)")
        }
        return .result(dialog: "模块「\(module.name)」已\(on ? String(localized: "开启") : String(localized: "关闭"))")
    }
}

struct UpdateSubscriptionsIntent: AppIntent {
    static var title: LocalizedStringResource = "更新订阅"
    static var description = IntentDescription("更新所有远程配置（订阅）；当前配置更新后，已连接时自动重载。")
    static var openAppWhenRun = false

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        await VPNManager.shared.load()
        let store = ProfileStore.shared
        // r7 R7A-5: refreshAll() skips disabled profiles, so they are not counted either.
        let count = store.profiles.filter { $0.kind == .remote && $0.enabled }.count
        guard count > 0 else { return .result(dialog: "没有远程订阅") }
        let errors = await store.refreshAll()
        if errors.isEmpty { return .result(dialog: "已更新 \(count) 个订阅") }
        return .result(dialog: "\(count - errors.count)/\(count) 个订阅已更新。失败：\(errors.joined(separator: "；"))")
    }
}

struct RunScriptIntent: AppIntent {
    static var title: LocalizedStringResource = "运行脚本"
    static var description = IntentDescription("立即运行一个定时（cron）或通用脚本任务，按脚本名匹配。需要已连接。")
    static var openAppWhenRun = false

    @Parameter(title: "脚本名称")
    var name: String

    @MainActor
    func perform() async throws -> some IntentResult & ReturnsValue<String> & ProvidesDialog {
        let vpn = VPNManager.shared
        await vpn.load()
        guard vpn.isConnected else { return .result(value: "", dialog: "未连接：脚本在隧道内运行，请先连接") }
        let tasks = try await ControllerClient.shared.mitmTasks()
        let q = name.trimmingCharacters(in: .whitespaces)
        guard let t = tasks.first(where: { $0.script.name == q }) ?? tasks.first(where: { $0.script.name.localizedCaseInsensitiveContains(q) }) else {
            return .result(value: "", dialog: "没有名为「\(q)」的脚本任务")
        }
        let r = try await ControllerClient.shared.mitmRunTask(t.id)
        if r.ok { return .result(value: "ok", dialog: "已运行「\(t.script.name)」") }
        return .result(value: r.error ?? "error", dialog: "「\(t.script.name)」运行失败：\(r.error ?? "")")
    }
}

struct TernShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(intent: ConnectIntent(), phrases: ["连接 \(.applicationName)", "Connect \(.applicationName)"])
        AppShortcut(intent: DisconnectIntent(), phrases: ["断开 \(.applicationName)", "Disconnect \(.applicationName)"])
        AppShortcut(intent: ToggleIntent(), phrases: ["切换 \(.applicationName)", "Toggle \(.applicationName)"])
        AppShortcut(intent: StatusIntent(), phrases: ["\(.applicationName) 状态", "\(.applicationName) status"])
        AppShortcut(intent: UpdateSubscriptionsIntent(), phrases: ["更新 \(.applicationName) 订阅", "Update \(.applicationName) subscriptions"])
    }
}
