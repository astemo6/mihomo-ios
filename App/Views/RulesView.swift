import SwiftUI
import Libmihomo

// 规则 (live from the controller, or offline from the profile), 自定义规则 (rules.json, Surge / QX /
// Loon / mihomo syntax with live validation) and 提供者 (live, or offline from the cache files).

// MARK: - Custom rules store

struct CustomRule: Codable, Identifiable, Hashable {
    var id: String = UUID().uuidString
    var line: String
    var enabled: Bool = true
    var interval: Int? = nil
}

/// Result of LibmihomoCheckRuleLine / CheckCustomRules (bridge/customrules.go ruleCheck).
struct RuleCheck: Decodable, Hashable {
    var id: String?
    var line: String?
    var enabled: Bool?
    var rule: String?
    var policy: String?
    var error: String?
    var note: String?
    var unresolved: String?
}

@MainActor
final class CustomRulesStore: ObservableObject {
    static let shared = CustomRulesStore()

    @Published var rules: [CustomRule] = []
    @Published var checks: [String: RuleCheck] = [:]
    @Published var message: String?

    static var url: URL { AppShared.homeURL.appendingPathComponent("rules.json") }

    private struct File: Codable { var rules: [CustomRule] }

    init() { load() }

    func load() {
        if let d = try? Data(contentsOf: Self.url), let f = try? JSONDecoder().decode(File.self, from: d) {
            rules = f.rules
        }
    }

    func save() {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let d = try? enc.encode(File(rules: rules)) { try? d.write(to: Self.url, options: .atomic) }
        Task {
            await recheck()
            if VPNManager.shared.isConnected, let e = await VPNManager.shared.reload() { message = "重载失败：\(e)" }
        }
    }

    func recheck() async {
        guard let path = AppShared.activeProfileURL?.path else { checks = [:]; return }
        let home = AppShared.homeURL.path
        let json = await Task.detached(priority: .utility) { LibmihomoCheckCustomRules(home, path) }.value
        let list = (try? JSONDecoder().decode([RuleCheck].self, from: Data(json.utf8))) ?? []
        var out: [String: RuleCheck] = [:]
        for c in list { if let id = c.id { out[id] = c } }
        checks = out
    }

    nonisolated static func check(line: String) async -> RuleCheck? {
        guard let path = AppShared.activeProfileURL?.path else { return nil }
        let home = AppShared.homeURL.path
        let json = await Task.detached(priority: .userInitiated) { LibmihomoCheckRuleLine(home, path, line) }.value
        return try? JSONDecoder().decode(RuleCheck.self, from: Data(json.utf8))
    }
}

// MARK: - Rules page

struct RulesView: View {
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var offline = ProfileInspector.shared
    @ObservedObject private var custom = CustomRulesStore.shared
    @State private var live: [RuleItem] = []
    @State private var search = ""
    @State private var tab = 0
    @State private var editing: CustomRule?
    @State private var adding = false

    struct Row: Hashable { var type: String; var payload: String; var proxy: String; var size: Int? }

    var rows: [Row] {
        let all: [Row] = vpn.isConnected
            ? live.map { Row(type: $0.type, payload: $0.payload, proxy: $0.proxy, size: $0.size) }
            : offline.result.rules.map { Row(type: $0.type, payload: $0.payload, proxy: $0.proxy, size: nil) }
        guard !search.isEmpty else { return all }
        let q = search.lowercased()
        return all.filter { $0.payload.lowercased().contains(q) || $0.type.lowercased().contains(q) || $0.proxy.lowercased().contains(q) }
    }

    var body: some View {
        VStack(spacing: 0) {
            Picker("", selection: $tab) {
                Text("配置规则").tag(0)
                Text("自定义 \(custom.rules.count)").tag(1)
            }
            .pickerStyle(.segmented)
            .padding(.horizontal, 16).padding(.vertical, 8)
            if tab == 0 { profileRules } else { customRules }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("规则")
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                if tab == 1 {
                    Button { adding = true } label: { Image(systemName: "plus") }
                }
            }
        }
        .task(id: vpn.isConnected) { await load() }
        .sheet(isPresented: $adding) { CustomRuleEditor(rule: CustomRule(line: "")) { r in custom.rules.insert(r, at: 0); custom.save() } }
        .sheet(item: $editing) { r in
            CustomRuleEditor(rule: r) { nr in
                if let i = custom.rules.firstIndex(where: { $0.id == nr.id }) { custom.rules[i] = nr; custom.save() }
            }
        }
        .alert("提示", isPresented: Binding(get: { custom.message != nil }, set: { if !$0 { custom.message = nil } })) {
            Button("好") { custom.message = nil }
        } message: { Text(custom.message ?? "") }
    }

    func load() async {
        if vpn.isConnected, let r = try? await ControllerClient.shared.rules() { live = r } else { await offline.load() }
        await custom.recheck()
    }

    var profileRules: some View {
        List {
            if !vpn.isConnected {
                Label("未连接 · 来自配置文件（含自定义规则）", systemImage: "doc.text.magnifyingglass")
                    .font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                    .listRowBackground(Color.clear)
            }
            ForEach(Array(rows.enumerated()), id: \.offset) { i, r in
                HStack(alignment: .top, spacing: 10) {
                    Text("\(i + 1)").font(.caption2.monospacedDigit()).foregroundStyle(.secondary).frame(width: 30, alignment: .trailing)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(r.payload.isEmpty ? r.type : r.payload).font(.system(.footnote, design: .monospaced)).lineLimit(2)
                        HStack(spacing: 6) {
                            RuleTypeTag(type: r.type)
                            if let s = r.size, s > 0 { Text("\(s) 条").font(.caption2).foregroundStyle(.secondary) }
                            Spacer()
                            Text(r.proxy).font(.caption).foregroundStyle(Theme.accent).lineLimit(1)
                        }
                    }
                }
                .listRowBackground(Theme.card)
            }
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
        .searchable(text: $search, prompt: "搜索规则")
        .refreshable { await load() }
        .overlay { if rows.isEmpty && search.isEmpty { EmptyStateView(icon: "list.bullet.rectangle", title: AppShared.activeProfileURL == nil ? "没有选择配置" : "没有规则") } }
    }

    var customRules: some View {
        List {
            Section {
                if custom.rules.isEmpty {
                    Text("点右上角 + 添加。自定义规则排在配置规则之前，可以直接粘贴 Surge / Quantumult X / Loon / mihomo 写法，也可以添加远程规则列表（RULE-SET / DOMAIN-SET / filter_remote）。")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                ForEach(custom.rules) { r in
                    CustomRuleRow(rule: r, check: custom.checks[r.id]) { on in
                        if let i = custom.rules.firstIndex(where: { $0.id == r.id }) { custom.rules[i].enabled = on; custom.save() }
                    }
                    .contentShape(Rectangle())
                    .onTapGesture { editing = r }
                }
                .onDelete { custom.rules.remove(atOffsets: $0); custom.save() }
                .onMove { custom.rules.move(fromOffsets: $0, toOffset: $1); custom.save() }
            } footer: {
                Text("策略名会对应到当前配置的策略组；找不到时使用第一个手动选择组并标黄。远程列表通过内核下载并转换为 mihomo 规则集；QX filter_remote 没有 force-policy 时整份列表走 proxy（第一个手动选择组）。")
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
    }
}

struct RuleTypeTag: View {
    let type: String
    var body: some View {
        Text(type).font(.caption2.weight(.semibold))
            .padding(.horizontal, 5).padding(.vertical, 1)
            .background(Capsule().fill(Color.white.opacity(0.1)))
    }
}

struct CustomRuleRow: View {
    let rule: CustomRule
    let check: RuleCheck?
    let onToggle: (Bool) -> Void

    var body: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 4) {
                Text(rule.line).scaledFont(12, design: .monospaced).lineLimit(3)
                RuleCheckLine(check: check)
            }
            Spacer()
            Toggle("", isOn: Binding(get: { rule.enabled }, set: onToggle)).labelsHidden()
        }
        .opacity(rule.enabled ? 1 : 0.55)
    }
}

struct RuleCheckLine: View {
    let check: RuleCheck?
    var body: some View {
        if let c = check {
            if let e = c.error, !e.isEmpty {
                Label(e, systemImage: "xmark.octagon.fill").font(.caption2).foregroundStyle(Theme.bad)
            } else {
                VStack(alignment: .leading, spacing: 2) {
                    if let r = c.rule, !r.isEmpty {
                        Label(r, systemImage: "checkmark.circle.fill").scaledFont(10, design: .monospaced).foregroundStyle(Theme.good).lineLimit(2)
                    }
                    if let u = c.unresolved, !u.isEmpty {
                        Label("配置里没有策略「\(u)」，改用 \(c.policy ?? "第一个手动组")", systemImage: "exclamationmark.triangle.fill").font(.caption2).foregroundStyle(Theme.warn)
                    }
                    if let n = c.note, !n.isEmpty { Text(n).font(.caption2).foregroundStyle(.secondary) }
                }
            }
        }
    }
}

struct CustomRuleEditor: View {
    @Environment(\.dismiss) var dismiss
    @State var rule: CustomRule
    let onSave: (CustomRule) -> Void
    @State private var check: RuleCheck?
    @State private var checking = false

    static let examples = [
        "DOMAIN-SUFFIX,google.com,Proxy",
        "DOMAIN-KEYWORD,openai,Proxy",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "GEOIP,CN,DIRECT",
        "host-suffix, apple.com, direct          (Quantumult X)",
        "RULE-SET,https://example.com/ad.list,REJECT          (Surge)",
        "DOMAIN-SET,https://example.com/cdn.txt,DIRECT          (Surge)",
        "https://example.com/x.list, tag=x, force-policy=Proxy          (QX filter_remote)",
    ]

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("规则", text: $rule.line, axis: .vertical)
                        .scaledFont(13, design: .monospaced)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .lineLimit(1...5)
                    if checking { ProgressView().controlSize(.small) } else { RuleCheckLine(check: check) }
                } header: { Text("规则") } footer: {
                    Text("输入时实时校验：显示转换后的 mihomo 规则和对应的策略组。")
                }
                .listRowBackground(Theme.card)
                if rule.line.contains("://") {
                    Section("远程列表更新间隔") {
                        Picker("间隔", selection: Binding(get: { rule.interval ?? 86400 }, set: { rule.interval = $0 })) {
                            Text("6 小时").tag(21600)
                            Text("12 小时").tag(43200)
                            Text("1 天").tag(86400)
                            Text("7 天").tag(604800)
                        }
                    }
                    .listRowBackground(Theme.card)
                }
                Section("示例（轻点填入）") {
                    ForEach(Self.examples, id: \.self) { ex in
                        Button {
                            rule.line = ex.components(separatedBy: "          ").first ?? ex
                        } label: {
                            Text(ex).scaledFont(11, design: .monospaced).foregroundStyle(.secondary)
                        }
                    }
                }
                .listRowBackground(Theme.card)
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("自定义规则").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") {
                        rule.line = rule.line.trimmingCharacters(in: .whitespacesAndNewlines)
                        onSave(rule)
                        dismiss()
                    }
                    .disabled(rule.line.trimmingCharacters(in: .whitespaces).isEmpty || (check?.error?.isEmpty == false))
                }
            }
            .task(id: rule.line) {
                let line = rule.line.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !line.isEmpty else { check = nil; return }
                try? await Task.sleep(nanoseconds: 300_000_000)
                if Task.isCancelled { return }
                checking = true
                let c = await CustomRulesStore.check(line: line)
                checking = false
                if !Task.isCancelled { check = c }
            }
        }
    }
}

// MARK: - Providers

struct ProvidersView: View {
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var offline = ProfileInspector.shared
    @ObservedObject private var updater = ProviderUpdater.shared
    @State private var proxyProviders: [ProviderItem] = []
    @State private var ruleProviders: [ProviderItem] = []
    @State private var updating: Set<String> = []
    @State private var error: String?

    var body: some View {
        Group {
            if vpn.isConnected { liveList } else { offlineList }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("提供者")
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                if !vpn.isConnected {
                    if updater.running {
                        HStack(spacing: 6) {
                            ProgressView()
                            Text("\(updater.done)/\(updater.total)").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                        }
                    } else {
                        Button("全部更新") { Task { await updater.updateAll() } }
                    }
                }
                if vpn.isConnected {
                    Button("全部更新") {
                        Task {
                            for p in proxyProviders where p.vehicleType == "HTTP" { try? await ControllerClient.shared.updateProxyProvider(p.name) }
                            for p in ruleProviders where p.vehicleType == "HTTP" { try? await ControllerClient.shared.updateRuleProvider(p.name) }
                            await load()
                        }
                    }
                }
            }
        }
        .task(id: vpn.isConnected) { if vpn.isConnected { await load() } else { await offline.load() } }
    }

    var liveList: some View {
        List {
            if let error { Text(error).font(.footnote).foregroundStyle(Theme.bad).listRowBackground(Theme.card) }
            Section("节点集 \(proxyProviders.count)") {
                ForEach(proxyProviders) { p in
                    row(p, detail: "\(p.proxies?.count ?? 0) 个节点 · \(p.vehicleType ?? "")", key: "p:" + p.name) {
                        try await ControllerClient.shared.updateProxyProvider(p.name)
                    }
                }
            }
            .listRowBackground(Theme.card)
            Section("规则集 \(ruleProviders.count)") {
                ForEach(ruleProviders) { p in
                    row(p, detail: "\(p.ruleCount ?? 0) 条 · \(p.behavior ?? "") · \(p.vehicleType ?? "")", key: "r:" + p.name) {
                        try await ControllerClient.shared.updateRuleProvider(p.name)
                    }
                }
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .refreshable { await load() }
    }

    var offlineList: some View {
        List {
            Label("未连接 · 来自配置文件与本地缓存", systemImage: "doc.text.magnifyingglass")
                .font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                .listRowBackground(Color.clear)
            Section("节点集 \(offline.result.proxyProviders.count)") {
                ForEach(offline.result.proxyProviders) { p in offlineRow(p) }
            }
            .listRowBackground(Theme.card)
            Section {
                ForEach(offline.result.ruleProviders) { p in offlineRow(p) }
            } header: { Text("规则集 \(offline.result.ruleProviders.count)") } footer: {
                Text("未连接时由 App 直接下载并转换（使用 GitHub 镜像设置），连接后内核会按更新间隔从源地址刷新。")
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .refreshable { await offline.load() }
    }

    @ViewBuilder
    func offlineRow(_ p: InspectProvider) -> some View {
        let key = p.kind + ":" + p.name
        HStack {
            NavigationLink { OfflineProviderDetail(p: p) } label: {
                OfflineProviderRow(p: p, error: updater.errors[key])
            }
            if p.vehicle == "http" {
                if updater.busy.contains(key) {
                    ProgressView()
                } else {
                    Button { Task { await updater.update(key) } } label: { Image(systemName: "arrow.clockwise") }
                        .buttonStyle(.borderless)
                        .disabled(updater.running)
                        .accessibilityLabel(Text("更新"))
                }
            }
        }
    }

    @ViewBuilder
    func row(_ p: ProviderItem, detail: String, key: String, update: @escaping () async throws -> Void) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 3) {
                Text(p.name).font(.subheadline.weight(.semibold))
                Text(detail).font(.caption2).foregroundStyle(.secondary)
                if let u = p.updatedAt, let d = ConnectionItem.iso.date(from: u) ?? ConnectionItem.isoNoFrac.date(from: u) {
                    Text("更新于 \(d.formatted(.relative(presentation: .named)))").font(.caption2).foregroundStyle(.secondary)
                }
                if let s = p.subscriptionInfo, let t = s.Total, t > 0 {
                    Text("已用 \(Fmt.bytes((s.Upload ?? 0) + (s.Download ?? 0))) / \(Fmt.bytes(t))").font(.caption2).foregroundStyle(.secondary)
                }
            }
            Spacer()
            if updating.contains(key) { ProgressView() } else {
                Button {
                    Task {
                        updating.insert(key)
                        do { try await update(); error = nil } catch { self.error = error.localizedDescription }
                        updating.remove(key)
                        await load()
                    }
                } label: { Image(systemName: "arrow.clockwise") }
                .buttonStyle(.borderless)
                .disabled(p.vehicleType != "HTTP")
            }
        }
    }

    func load() async {
        do {
            proxyProviders = try await ControllerClient.shared.proxyProviders()
            ruleProviders = try await ControllerClient.shared.ruleProviders()
        } catch { self.error = error.localizedDescription }
    }
}

struct OfflineProviderRow: View {
    let p: InspectProvider
    var error: String? = nil

    var cacheSummary: String {
        var parts: [String] = ["已缓存"]
        if p.count >= 0 {
            parts.append(p.kind == "proxy" ? "\(p.count) 个节点" : "\(p.count) 条")
        } else {
            parts.append("二进制格式")
        }
        if let s = p.size { parts.append(Fmt.bytes(s)) }
        if let d = p.cachedDate { parts.append(d.formatted(.relative(presentation: .named))) }
        return parts.joined(separator: " · ")
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Text(p.name).font(.subheadline.weight(.semibold)).lineLimit(1)
                RuleTypeTag(type: p.vehicle.uppercased())
                if let b = p.behavior, !b.isEmpty { RuleTypeTag(type: b) }
            }
            if p.cached {
                Text(cacheSummary).font(.caption2).foregroundStyle(.secondary)
            } else {
                Text(p.vehicle == "inline" ? "内联" : "尚未下载 · 轻点右侧按钮下载").font(.caption2).foregroundStyle(Theme.warn)
            }
            if let error {
                Text(error).font(.caption2).foregroundStyle(Theme.bad).lineLimit(2)
            }
            if let u = p.url, !u.isEmpty {
                Text(u).scaledFont(9, design: .monospaced).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
        }
    }
}

struct OfflineProviderDetail: View {
    let p: InspectProvider
    var body: some View {
        List {
            Section {
                LabeledContent("类型", value: p.kind == "proxy" ? "节点集" : "规则集")
                LabeledContent("来源", value: p.vehicle)
                if let b = p.behavior, !b.isEmpty { LabeledContent("行为", value: b) }
                if let f = p.format, !f.isEmpty { LabeledContent("格式", value: f) }
                if let i = p.interval, i > 0 { LabeledContent("更新间隔", value: "\(i / 3600) 小时") }
                if let u = p.url, !u.isEmpty {
                    Text(u).scaledFont(10, design: .monospaced).foregroundStyle(.secondary).textSelection(.enabled)
                }
                if let c = p.cachePath, !c.isEmpty {
                    LabeledContent("缓存文件", value: (c as NSString).lastPathComponent)
                }
            }
            .listRowBackground(Theme.card)
            if let nodes = p.proxies, !nodes.isEmpty {
                Section("缓存的节点 \(nodes.count)") {
                    ForEach(nodes, id: \.name) { n in
                        HStack { Text(n.name).font(.footnote).lineLimit(1); Spacer(); ProtocolBadge(type: n.type) }
                    }
                }
                .listRowBackground(Theme.card)
            }
            if let lines = p.preview, !lines.isEmpty {
                Section("缓存内容（前 \(lines.count) 行）") {
                    ForEach(Array(lines.enumerated()), id: \.offset) { _, l in
                        Text(l).scaledFont(10, design: .monospaced)
                    }
                }
                .listRowBackground(Theme.card)
            }
            if !p.cached && p.vehicle != "inline" {
                Text("还没有缓存。在「提供者」页点更新即可由 App 直接下载；连接后内核也会下载。").font(.footnote).foregroundStyle(.secondary)
                    .listRowBackground(Color.clear)
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle(p.name)
    }
}
