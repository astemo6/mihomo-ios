import SwiftUI

// The per-kind adapters of the shared SubscriptionSheet (SubscriptionKit.swift): each owns its fields and how a
// save is written and re-downloaded; the shell, labels and order are the same everywhere.

extension SubscriptionStatus {
    /// Expiry + used / total of a subscription-userinfo header.
    static func usage(_ i: SubscriptionUserInfo?) -> (String?, Double?) {
        guard let i, i.total > 0 || i.expireDate != nil else { return (nil, nil) }
        var parts: [String] = []
        if let d = i.expireDate { parts.append(String(localized: "到期 \(d.formatted(date: .numeric, time: .omitted))")) }
        if i.total > 0 { parts.append(SubscriptionRowFormat.bytes.string(fromByteCount: i.used) + " / " + SubscriptionRowFormat.bytes.string(fromByteCount: i.total)) }
        return (parts.joined(separator: "  "), i.total > 0 ? i.fraction : nil)
    }
}

enum SubscriptionRowFormat {
    static let bytes: ByteCountFormatter = {
        let f = ByteCountFormatter()
        f.countStyle = .binary
        return f
    }()
}

// MARK: - 配置订阅

struct ProfileSubSheet: View {
    let profile: Profile
    /// The active profile's node list (nil for another profile: the core / inspector only knows the active one).
    var nodes: NodeListScope? = nil
    var onDelete: (Profile) -> Void
    @EnvironmentObject var store: ProfileStore
    @State private var name: String
    @State private var url: String
    @State private var ua: String
    @State private var interval: Int
    @State private var alert: UsageAlertRule
    @State private var message: String?

    init(profile: Profile, nodes: NodeListScope? = nil, onDelete: @escaping (Profile) -> Void) {
        self.profile = profile
        self.nodes = nodes
        self.onDelete = onDelete
        _name = State(initialValue: profile.name)
        _url = State(initialValue: profile.url ?? "")
        _ua = State(initialValue: profile.userAgent)
        _interval = State(initialValue: profile.updateIntervalHours * 3600)
        _alert = State(initialValue: UsageAlerts.rule(for: profile.id))
    }

    var current: Profile { store.profiles.first { $0.id == profile.id } ?? profile }

    var dirty: Bool {
        name != profile.name || url != (profile.url ?? "") || ua != profile.userAgent
            || interval != profile.updateIntervalHours * 3600 || alert != UsageAlerts.rule(for: profile.id)
    }

    var status: SubscriptionStatus {
        let p = current
        let (u, f) = SubscriptionStatus.usage(p.userInfo)
        return SubscriptionStatus(source: String(localized: "配置订阅"), updated: p.lastUpdated, interval: p.updateIntervalHours * 3600,
                                  disabled: !p.enabled, downloaded: true, usage: u, usageFraction: f)
    }

    var body: some View {
        SubscriptionSheet(title: "配置订阅", name: $name, url: $url, interval: $interval, status: status,
                          updating: store.updating.contains(profile.id), dirty: dirty, save: save,
                          update: { await store.refresh(current) },
                          deleteTitle: Text("删除「\(profile.displayName)」？"), deleteMessage: deleteMessage,
                          delete: { onDelete(current) }) {
            Section {
                Picker("User-Agent", selection: $ua) {
                    Text(verbatim: "clash.meta").tag("clash.meta")
                    Text(verbatim: "Clash.Meta (Meta core)").tag(SubscriptionUA.metaCore)
                    Text(verbatim: "clash-verge/v2").tag("clash-verge/v2")
                    if !["clash.meta", SubscriptionUA.metaCore, "clash-verge/v2"].contains(ua) { Text(verbatim: ua).tag(ua) }
                }
                if profile.id != store.activeID {
                    Button {
                        Task {
                            if let block = store.activationBlock(current) { message = block; return }
                            message = await store.setActive(current).map { String(localized: "已切换，但重载失败：\($0)") } ?? String(localized: "已设为当前配置")
                        }
                    } label: { Label("设为当前配置", systemImage: "checkmark.circle") }
                        .disabled(!current.enabled)
                        .accessibilityIdentifier("sub.sheet.activate")
                } else if let nodes {
                    NavigationLink { NodeListView(scope: nodes) } label: { Label("查看节点", systemImage: "list.bullet") }
                }
                NavigationLink { SubscriptionRulesView(profile: current) } label: {
                    Label("节点处理（过滤 / 重命名 / 排序）", systemImage: "line.3.horizontal.decrease.circle")
                }
                if let message { Text(verbatim: message).font(.footnote).foregroundStyle(.secondary) }
            } header: { Text("选项") }
            .listRowBackground(Theme.card)
            UsageAlertSection(rule: $alert)
        }
    }

    var deleteMessage: Text {
        let names = store.copies(of: profile).map(\.displayName).joined(separator: "、")
        return names.isEmpty ? DeleteText.recoverable : Text("这些副本是从它复制的：\(names)。删除后它们会保留为本地配置，不再随订阅更新。")
    }

    func save() async -> String? {
        var p = current
        let u = url.trimmingCharacters(in: .whitespacesAndNewlines)
        let changed = p.url != u || p.userAgent != ua
        p.url = u
        p.name = name.trimmingCharacters(in: .whitespaces).isEmpty ? p.name : name.trimmingCharacters(in: .whitespaces)
        p.userAgent = ua
        p.updateIntervalHours = interval / 3600
        store.update(p)
        UsageAlerts.setRule(alert, for: p.id)
        UsageAlerts.evaluate(id: p.id, name: p.name, info: p.userInfo)
        if changed { return await store.refresh(p) }
        return nil
    }
}

// MARK: - 节点订阅

struct NodeSubSheet: View {
    let sub: NodeSubscription
    var onDelete: ((NodeSubscription) -> Void)? = nil
    @ObservedObject private var nodes = NodeSubStore.shared
    @ObservedObject private var offline = ProfileInspector.shared
    @ObservedObject private var model = NodeManagerModel.shared
    @EnvironmentObject var store: ProfileStore
    @State private var name: String
    @State private var url: String
    @State private var ua: String
    @State private var interval: Int
    @State private var customGroups: Bool
    @State private var groups: Set<String>
    @State private var alert: UsageAlertRule
    @State private var pickingIcon = false

    init(sub: NodeSubscription, onDelete: ((NodeSubscription) -> Void)? = nil) {
        self.sub = sub
        self.onDelete = onDelete
        _name = State(initialValue: sub.name)
        _url = State(initialValue: sub.url)
        _ua = State(initialValue: sub.userAgent)
        _interval = State(initialValue: sub.updateIntervalHours * 3600)
        _customGroups = State(initialValue: !(sub.groups ?? []).isEmpty)
        _groups = State(initialValue: Set(sub.groups ?? []))
        _alert = State(initialValue: UsageAlerts.rule(for: sub.id))
    }

    var current: NodeSubscription { nodes.subs.first { $0.id == sub.id } ?? sub }
    var deleteAction: (() -> Void)? {
        guard let d = onDelete else { return nil }
        let s = current
        return { d(s) }
    }
    var groupNames: [String] { offline.result.groups.filter { $0.hidden != true && $0.name != "GLOBAL" }.map(\.name) }
    var otherGroups: [String] { (sub.groups ?? []).filter { !groupNames.contains($0) } }
    var chosenGroups: [String]? { customGroups && !groups.isEmpty ? (groupNames + otherGroups).filter { groups.contains($0) } : nil }

    var dirty: Bool {
        name != sub.name || url != sub.url || ua != sub.userAgent || interval != sub.updateIntervalHours * 3600
            || chosenGroups != (sub.groups?.isEmpty == false ? sub.groups : nil) || alert != UsageAlerts.rule(for: sub.id)
    }

    var status: SubscriptionStatus {
        let s = current
        let (u, f) = SubscriptionStatus.usage(s.userInfo)
        return SubscriptionStatus(source: String(localized: "节点订阅"), updated: s.lastUpdated, interval: s.updateIntervalHours * 3600,
                                  error: s.lastError, disabled: !s.enabled,
                                  downloaded: FileManager.default.fileExists(atPath: s.cacheURL.path), usage: u, usageFraction: f)
    }

    var body: some View {
        SubscriptionSheet(title: "节点订阅", name: $name, namePlaceholder: String(localized: "名称（留空自动获取）"), url: $url,
                          interval: $interval, status: status, updating: nodes.updating.contains(sub.id), dirty: dirty, save: save,
                          update: { await nodes.refresh(current) },
                          deleteTitle: Text("删除这个订阅？"),
                          deleteMessage: Text("「\(sub.name)」的节点会从所有配置中移除，引用它的策略组改用其他节点。"),
                          delete: deleteAction) {
            Section {
                Picker("User-Agent", selection: $ua) {
                    Text(verbatim: "clash.meta").tag("clash.meta")
                    Text(verbatim: "Clash.Meta (Meta core)").tag(SubscriptionUA.metaCore)
                    Text(verbatim: "Quantumult X").tag("Quantumult%20X/1.5.2")
                    Text(verbatim: "Shadowrocket").tag("Shadowrocket/2070")
                    if !["clash.meta", SubscriptionUA.metaCore, "Quantumult%20X/1.5.2", "Shadowrocket/2070"].contains(ua) { Text(verbatim: ua).tag(ua) }
                }
                Button { pickingIcon = true } label: { Label("图标", systemImage: "photo") }
                let src = model.source(subID: sub.id)
                NavigationLink {
                    NodeListView(scope: NodeListScope(title: sub.name, sourceIDs: [src?.id ?? NodeSource(kind: .subscription, name: sub.name, subID: sub.id).id],
                                                      emptyTitle: sub.enabled ? String(localized: "还没有节点") : String(localized: "订阅已停用"),
                                                      emptyMessage: sub.enabled ? (sub.lastError ?? String(localized: "更新订阅后显示节点。")) : String(localized: "启用订阅后，节点会加入配置。"),
                                                      subID: sub.id))
                } label: { Label("查看节点", systemImage: "list.bullet") }
                if let p = store.active {
                    NavigationLink { SubscriptionRulesView(profile: p, rulesKey: sub.rulesKey, previewPath: sub.cacheURL.path) } label: {
                        Label("节点处理（过滤 / 重命名 / 排序）", systemImage: "line.3.horizontal.decrease.circle")
                    }
                }
            } header: { Text("选项") }
            .listRowBackground(Theme.card)
            Section {
                Toggle("指定策略组", isOn: $customGroups)
                if customGroups {
                    ForEach(groupNames, id: \.self) { g in
                        Toggle(g, isOn: Binding(get: { groups.contains(g) }, set: { if $0 { groups.insert(g) } else { groups.remove(g) } }))
                    }
                    ForEach(otherGroups, id: \.self) { g in
                        Toggle(isOn: Binding(get: { groups.contains(g) }, set: { if $0 { groups.insert(g) } else { groups.remove(g) } })) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(verbatim: g)
                                Text("不在当前配置").font(.caption2).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            } header: { Text("加入的策略组") } footer: {
                Text("默认加入含节点的手动选择组和自动选择（url-test）组；这些组在别的配置中不存在时也按默认处理。")
            }
            .listRowBackground(Theme.card)
            UsageAlertSection(rule: $alert)
        }
        .sheet(isPresented: $pickingIcon) {
            IconPickerSheet(title: sub.name, current: current.icon) { v in nodes.setIcon(sub.id, v?.isEmpty == true ? nil : v) }
        }
    }

    func save() async -> String? {
        var s = current
        let u = url.trimmingCharacters(in: .whitespacesAndNewlines)
        let changed = s.url != u || s.userAgent != ua
        s.url = u
        s.name = name.trimmingCharacters(in: .whitespaces)
        s.userAgent = ua
        s.updateIntervalHours = interval / 3600
        s.groups = chosenGroups
        UsageAlerts.setRule(alert, for: s.id)
        await nodes.save(s)
        if changed { return await nodes.refresh(s) }
        return nil
    }
}

// MARK: - 节点集 (a proxy-provider of the current profile; changes go to the override store)

struct ProviderSubSheet: View {
    let profileID: String
    let info: ProfileProviderInfo
    let status: SubscriptionStatus
    /// Its nodes (节点集 node list).
    var nodes: NodeListScope? = nil
    var onDelete: () -> Void
    /// Reload after a change (VPN reload, offline view); runs after the sheet closed.
    let onApply: () async -> Void
    @ObservedObject private var store = ProviderOverrideStore.shared
    @ObservedObject private var updater = ProviderUpdater.shared
    @State private var name: String
    @State private var url: String
    @State private var interval: Int
    @State private var filter: String
    @State private var exclude: String
    @State private var pickingIcon = false
    private let initial: ProviderOverride

    init(profileID: String, info: ProfileProviderInfo, status: SubscriptionStatus, nodes: NodeListScope? = nil,
         onDelete: @escaping () -> Void, onApply: @escaping () async -> Void) {
        self.profileID = profileID
        self.info = info
        self.status = status
        self.nodes = nodes
        self.onDelete = onDelete
        self.onApply = onApply
        let o = ProviderOverrideStore.shared.get(profileID, info.name)
        initial = o
        _name = State(initialValue: o.name ?? "")
        _url = State(initialValue: o.url ?? info.url ?? "")
        _interval = State(initialValue: o.interval ?? 0)
        _filter = State(initialValue: o.filter ?? "")
        _exclude = State(initialValue: o.excludeFilter ?? "")
    }

    var isHTTP: Bool { info.vehicle == "http" }
    var updateAction: (() async -> String?)? {
        guard isHTTP else { return nil }
        let k = key
        let u = updater
        return { @MainActor in await u.update(k); return u.errors[k] }
    }
    var key: String { "proxy:" + info.name }

    var dirty: Bool {
        name != (initial.name ?? "") || url != (initial.url ?? info.url ?? "") || interval != (initial.interval ?? 0)
            || filter != (initial.filter ?? "") || exclude != (initial.excludeFilter ?? "")
    }

    var body: some View {
        SubscriptionSheet(title: "节点集", name: $name, namePlaceholder: info.name,
                          nameFooter: Text("只改本页显示的名称；策略组和规则仍按配置里的名称「\(info.name)」引用它。"),
                          url: isHTTP ? $url : nil, interval: $interval, zeroInterval: "跟随配置", status: status,
                          updating: updater.busy.contains(key), dirty: dirty, save: save,
                          update: updateAction,
                          deleteTitle: Text("删除节点集「\(info.name)」？"),
                          deleteMessage: Text("只从这个配置里移除：它不再加载，引用它的策略组改用其他节点（没有其他节点时用 DIRECT）。配置文件不会改动，更新配置也不会让它回来；可以在本页底部「恢复已删除的节点集」找回。"),
                          delete: onDelete) {
            Section {
                TextField(info.filter?.isEmpty == false ? info.filter! : String(localized: "保留：正则，如 (?i)港|hk"), text: $filter)
                    .font(.footnote.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled()
                    .accessibilityIdentifier("provider.edit.filter")
                TextField(info.excludeFilter?.isEmpty == false ? info.excludeFilter! : String(localized: "排除：正则，如 到期|剩余"), text: $exclude)
                    .font(.footnote.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled()
                    .accessibilityIdentifier("provider.edit.exclude")
            } header: { Text("筛选节点") } footer: { Text("留空使用配置里的设置。") }
            .listRowBackground(Theme.card)
            Section {
                Button { pickingIcon = true } label: { Label("图标", systemImage: "photo") }
                if let nodes {
                    NavigationLink { NodeListView(scope: nodes) } label: { Label("查看节点", systemImage: "list.bullet") }
                }
                if !initial.isEmpty {
                    Button("恢复默认", role: .destructive) {
                        store.set(profileID, info.name, ProviderOverride(disabled: initial.disabled, icon: initial.icon))
                        name = ""; url = info.url ?? ""; interval = 0; filter = ""; exclude = ""
                        let apply = onApply
                        Task { await apply() }
                    }
                    .accessibilityIdentifier("provider.edit.reset")
                }
            } footer: { if !initial.isEmpty { Text("清除这里的修改，使用配置里的设置（图标和停用状态保留）。") } }
            .listRowBackground(Theme.card)
        }
        .sheet(isPresented: $pickingIcon) {
            IconPickerSheet(title: info.name, current: store.get(profileID, info.name).icon) { v in
                store.update(profileID, info.name) { $0.icon = v?.isEmpty == true ? nil : v }
            }
        }
    }

    static func validRegex(_ s: String) -> Bool { s.isEmpty || (try? NSRegularExpression(pattern: s)) != nil }

    func save() async -> String? {
        let n = name.trimmingCharacters(in: .whitespaces)
        let u = url.trimmingCharacters(in: .whitespacesAndNewlines)
        let f = filter.trimmingCharacters(in: .whitespaces)
        let x = exclude.trimmingCharacters(in: .whitespaces)
        guard Self.validRegex(f), Self.validRegex(x) else { return String(localized: "筛选表达式无效") }
        let urlChanged = u != (initial.url ?? info.url ?? "")
        store.update(profileID, info.name) { o in
            o.name = n.isEmpty || n == info.name ? nil : n
            o.url = u.isEmpty || u == info.url ? nil : u
            o.interval = interval > 0 ? interval : nil
            o.filter = f.isEmpty ? nil : f
            o.excludeFilter = x.isEmpty ? nil : x
        }
        if urlChanged && isHTTP {
            await updater.update(key)
            if let e = updater.errors[key] { return e }
        }
        let apply = onApply
        Task { await apply() }
        return nil
    }
}

// MARK: - 重写订阅 (module)

struct ModuleSubSheet: View {
    let module: EngineModule
    var onDelete: (EngineModule) -> Void
    @ObservedObject private var store = EngineStore.shared
    @ObservedObject private var res = ResourceStore.shared
    @State private var name: String
    @State private var url: String
    @State private var interval: Int

    init(module: EngineModule, onDelete: @escaping (EngineModule) -> Void) {
        self.module = module
        self.onDelete = onDelete
        _name = State(initialValue: module.name)
        _url = State(initialValue: module.url)
        _interval = State(initialValue: module.interval ?? 86400)
    }

    var current: EngineModule { store.config.modules.first { $0.id == module.id } ?? module }
    var remote: Bool { !module.url.isEmpty }
    var updateAction: (() async -> String?)? {
        guard remote else { return nil }
        let r = res
        let k = "module:" + module.id
        return { @MainActor in await r.refresh(key: k) }
    }
    var dirty: Bool { name != module.name || url != module.url || interval != (module.interval ?? 86400) }
    var item: ResourceItem? { res.items.first { $0.key == "module:" + module.id } }

    var body: some View {
        SubscriptionSheet(title: "重写订阅", name: $name, url: remote ? $url : nil, interval: $interval, zeroInterval: nil,
                          status: ModuleSubSheet.status(current, item: item, info: store.moduleInfo[module.id]),
                          updating: store.busy.contains(module.id) || res.busy.contains("module:" + module.id), dirty: dirty, save: save,
                          update: updateAction,
                          deleteTitle: Text("删除「\(module.name)」？"), deleteMessage: DeleteText.recoverable,
                          delete: { onDelete(current) }) {
            Section {
                NavigationLink { ModuleDetailView(moduleID: module.id) } label: { Label("参数、策略与内容", systemImage: "doc.text.magnifyingglass") }
                    .accessibilityIdentifier("sub.sheet.moduleDetail")
            }
            .listRowBackground(Theme.card)
        }
    }

    /// Row / sheet status of a module: 「Surge 模块 · 更新于 … · 每 1 天」.
    static func status(_ m: EngineModule, item: ResourceItem?, info: ParsedEngineText?) -> SubscriptionStatus {
        let updated = (item?.updatedAt ?? m.updatedAt ?? 0) > 0 ? Date(timeIntervalSince1970: item?.updatedAt ?? m.updatedAt ?? 0) : nil
        return SubscriptionStatus(source: formatSource(info?.format), remote: !m.url.isEmpty, updated: updated, interval: m.interval ?? 86400,
                                  error: item?.error, disabled: !m.enabled, downloaded: info != nil)
    }

    /// 「Surge 模块」/「Loon 插件」/「QX 引用」… (the format word stays a subtitle, the page says 重写 / 订阅).
    static func formatSource(_ f: String?) -> String {
        switch (f ?? "").lowercased() {
        case "surge": return String(localized: "Surge 模块")
        case "loon": return String(localized: "Loon 插件")
        case "qx": return String(localized: "QX 引用")
        case "stash": return String(localized: "Stash 覆写")
        case "egern": return String(localized: "Egern 模块")
        case "list", "list-own", "domainset": return String(localized: "规则列表")
        default: return String(localized: "重写")
        }
    }

    func save() async -> String? {
        guard let i = store.config.modules.firstIndex(where: { $0.id == module.id }) else { return nil }
        let u = url.trimmingCharacters(in: .whitespacesAndNewlines)
        let changed = remote && u != store.config.modules[i].url
        let n = name.trimmingCharacters(in: .whitespaces)
        if !n.isEmpty { store.config.modules[i].name = n }
        if remote { store.config.modules[i].url = u }
        store.config.modules[i].interval = interval
        store.save(reload: !changed)
        if changed { return await res.refresh(key: "module:" + module.id) }
        res.reload()
        return nil
    }
}

/// Subscription User-Agent option values. Servers pick the returned format by the UA, so the values are the ones
/// Clash.Meta-family clients send (interop, not branding); the picker shows them as "Clash.Meta (Meta core)".
enum SubscriptionUA {
    static let metaCore = "mihomo"
}
