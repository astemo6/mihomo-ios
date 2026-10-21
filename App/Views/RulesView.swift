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
            if VPNManager.shared.isConnected, let e = await VPNManager.shared.reload() { message = String(localized: "重载失败：\(e)") }
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
    @ObservedObject private var hits = RuleHitsStore.shared
    @AppStorage("rules.sortByHits") private var sortByHits = false
    @State private var confirmReset = false

    struct Row: Hashable { var index: Int; var type: String; var payload: String; var proxy: String; var size: Int?; var session: Int? }

    var rows: [Row] {
        var all: [Row] = vpn.isConnected
            ? live.enumerated().map { Row(index: $0.offset, type: $0.element.type, payload: $0.element.payload, proxy: $0.element.proxy, size: $0.element.size, session: $0.element.extra?.hitCount) }
            : offline.result.rules.enumerated().map { Row(index: $0.offset, type: $0.element.type, payload: $0.element.payload, proxy: $0.element.proxy, size: nil, session: nil) }
        if !search.isEmpty {
            let q = search.lowercased()
            all = all.filter { $0.payload.lowercased().contains(q) || $0.type.lowercased().contains(q) || $0.proxy.lowercased().contains(q) }
        }
        if sortByHits {
            // Review 5: one lookup per row (each builds a normalized key), not two per comparison.
            let total = Dictionary(uniqueKeysWithValues: all.map { ($0.index, hits.entry($0.type, $0.payload, $0.proxy)?.total ?? 0) })
            all.sort { a, b in
                let ta = total[a.index] ?? 0, tb = total[b.index] ?? 0
                return ta != tb ? ta > tb : a.index < b.index
            }
        }
        return all
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
                        .accessibilityIdentifier("rules.add")
                } else {
                    Menu {
                        Picker("排序", selection: $sortByHits) {
                            Label("配置顺序", systemImage: "list.number").tag(false)
                            Label("命中最多", systemImage: "chart.bar.fill").tag(true)
                        }
                        Button(role: .destructive) { confirmReset = true } label: { Label("重置全部命中计数", systemImage: "arrow.counterclockwise") }
                            .disabled(hits.entries.isEmpty)
                    } label: { Image(systemName: "chart.bar.xaxis") }
                    .accessibilityLabel(Text("命中统计"))
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
        .confirmationDialog("重置全部规则的命中计数？", isPresented: $confirmReset, titleVisibility: .visible) {
            Button("重置", role: .destructive) { hits.reset(nil) }
        }
        .alert("提示", isPresented: Binding(get: { custom.message != nil }, set: { if !$0 { custom.message = nil } })) {
            Button("好") { custom.message = nil }
        } message: { Text(custom.message ?? "") }
    }

    func load() async {
        if vpn.isConnected, let r = try? await ControllerClient.shared.rules() { live = r } else { await offline.load() }
        await hits.refresh()
        await custom.recheck()
    }

    var profileRules: some View {
        let rows = self.rows // built once per render (it was evaluated for the list and again for the overlay)
        return List {
            if !vpn.isConnected {
                Label("未连接 · 来自配置文件（含自定义规则）", systemImage: "doc.text.magnifyingglass")
                    .font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                    .listRowBackground(Color.clear)
            }
            if !hits.entries.isEmpty, search.isEmpty {
                RuleHitsSummary(store: hits).listRowBackground(Color.clear)
            }
            ForEach(rows, id: \.index) { r in
                let h = hits.entry(r.type, r.payload, r.proxy)
                HStack(alignment: .top, spacing: 10) {
                    Text("\(r.index + 1)").font(.caption2.monospacedDigit()).foregroundStyle(.secondary).frame(width: 30, alignment: .trailing)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(r.payload.isEmpty ? r.type : r.payload).font(.system(.footnote, design: .monospaced)).lineLimit(2)
                        HStack(spacing: 6) {
                            RuleTypeTag(type: Theme.ruleTypeName(r.type))
                            if let s = r.size, s > 0 { Text("\(s) 条").font(.caption2).foregroundStyle(.secondary) }
                            Spacer()
                            if !r.proxy.isEmpty { PolicyChip(name: r.proxy) }
                        }
                        if h != nil || (r.session ?? 0) > 0 { RuleHitLine(entry: h, session: r.session) }
                    }
                }
                .listRowBackground(Theme.card)
                .contextMenu {
                    if h != nil {
                        Button(role: .destructive) { hits.reset(h?.key) } label: { Label("重置此规则的命中计数", systemImage: "arrow.counterclockwise") }
                    }
                    Button { UIPasteboard.general.string = [r.type, r.payload, r.proxy].filter { !$0.isEmpty }.joined(separator: ",") } label: { Label("复制规则", systemImage: "doc.on.doc") }
                }
            }
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
        .searchable(text: $search, placement: .navigationBarDrawer(displayMode: .always), prompt: "搜索规则")
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

/// v0.16: rule types are tinted by category (Theme.ruleTypeColor); other tags (provider vehicle / behavior) stay neutral.
struct RuleTypeTag: View {
    let type: String
    var body: some View {
        if let c = Theme.ruleTypeColor(type) {
            Text(verbatim: type).font(.caption2.weight(.semibold))
                .padding(.horizontal, 5).padding(.vertical, 1)
                .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
                .background(Capsule().fill(c.opacity(0.16)))
                .foregroundStyle(c)
                .lineLimit(1).fixedSize()
                .accessibilityIdentifier("ruletype." + type)
        } else {
            Text(verbatim: type).font(.caption2.weight(.semibold))
                .padding(.horizontal, 5).padding(.vertical, 1)
                .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
                .background(Capsule().fill(Theme.ink(0.1)))
                .lineLimit(1).fixedSize()
        }
    }
}

/// v0.16: the policy a rule sends traffic to, as a chip on the right of the row.
struct PolicyChip: View {
    let name: String
    var body: some View {
        let c = Theme.policyColor(name)
        Text(verbatim: name).font(.caption.weight(.medium))
            .padding(.horizontal, 7).padding(.vertical, 2)
            .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
            .background(Capsule().fill(c.opacity(0.14)))
            .foregroundStyle(c)
            .lineLimit(1).truncationMode(.middle)
            .accessibilityIdentifier("policychip." + name)
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
                if let c = check, (c.error ?? "").isEmpty, let r = c.rule, !r.isEmpty {
                    HStack(spacing: 6) {
                        RuleTypeTag(type: Theme.ruleTypeName(String(r.split(separator: ",").first ?? Substring(r)).trimmingCharacters(in: .whitespaces)))
                        Spacer(minLength: 4)
                        if let p = c.policy, !p.isEmpty { PolicyChip(name: p) }
                    }
                }
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

/// v0.19.8: one rule type of the structured editor.
struct RuleKind: Identifiable, Hashable {
    enum Group: String, CaseIterable { case domain, ip, other }
    let id: String          // the mihomo rule type
    let group: Group
    let caption: String
    let placeholder: String
    var isIP = false
    var keyboard: UIKeyboardType = .asciiCapable
    var noValue = false

    static var all: [RuleKind] { [
        RuleKind(id: "DOMAIN-SUFFIX", group: .domain, caption: String(localized: "域名及其所有子域名"), placeholder: "google.com"),
        RuleKind(id: "DOMAIN", group: .domain, caption: String(localized: "完全相同的域名"), placeholder: "www.google.com"),
        RuleKind(id: "DOMAIN-KEYWORD", group: .domain, caption: String(localized: "域名里包含这个关键词"), placeholder: "openai"),
        RuleKind(id: "DOMAIN-REGEX", group: .domain, caption: String(localized: "域名匹配正则表达式"), placeholder: "^ad\\..*"),
        RuleKind(id: "GEOSITE", group: .domain, caption: String(localized: "域名分类（GeoSite）"), placeholder: "netflix"),
        RuleKind(id: "IP-CIDR", group: .ip, caption: String(localized: "IPv4 网段"), placeholder: "192.168.0.0/16", isIP: true, keyboard: .numbersAndPunctuation),
        RuleKind(id: "IP-CIDR6", group: .ip, caption: String(localized: "IPv6 网段"), placeholder: "2001:db8::/32", isIP: true, keyboard: .numbersAndPunctuation),
        RuleKind(id: "IP-ASN", group: .ip, caption: String(localized: "IP 所属的自治系统编号"), placeholder: "13335", isIP: true, keyboard: .numberPad),
        RuleKind(id: "GEOIP", group: .ip, caption: String(localized: "IP 所属的国家或地区代码"), placeholder: "CN", isIP: true),
        RuleKind(id: "PROCESS-NAME", group: .other, caption: String(localized: "发起连接的进程名"), placeholder: "Telegram"),
        RuleKind(id: "DST-PORT", group: .other, caption: String(localized: "目标端口"), placeholder: "443", keyboard: .numberPad),
        RuleKind(id: "NETWORK", group: .other, caption: String(localized: "网络类型：tcp 或 udp"), placeholder: "udp"),
        RuleKind(id: "RULE-SET", group: .other, caption: String(localized: "远程规则列表（Surge / QX / Clash 格式）"), placeholder: "https://example.com/rules.list", keyboard: .URL),
        RuleKind(id: "MATCH", group: .other, caption: String(localized: "其余所有连接（最后一条）"), placeholder: "", noValue: true),
    ] }

    static func groupTitle(_ g: Group) -> String {
        switch g {
        case .domain: return String(localized: "域名")
        case .ip: return "IP"
        case .other: return String(localized: "进程与其他")
        }
    }

    /// Surge / QX spellings → the mihomo type the form shows.
    static let aliases: [String: String] = [
        "HOST": "DOMAIN", "HOST-SUFFIX": "DOMAIN-SUFFIX", "HOST-KEYWORD": "DOMAIN-KEYWORD", "HOST-REGEX": "DOMAIN-REGEX",
        "IP6-CIDR": "IP-CIDR6", "IP-CIDR6": "IP-CIDR6", "FINAL": "MATCH", "PROCESS": "PROCESS-NAME", "DEST-PORT": "DST-PORT",
    ]
}

/// v0.19.8: the fields of the structured editor, two-way with the rule line.
struct RuleFormFields: Equatable {
    var type = "DOMAIN-SUFFIX"
    var value = ""
    var policy = ""
    var noResolve = false

    var kind: RuleKind? { RuleKind.all.first { $0.id == type } }

    var line: String {
        let k = kind
        if k?.noValue == true { return "\(type),\(policy)" }
        var parts = [type, value.trimmingCharacters(in: .whitespaces), policy]
        if k?.isIP == true && noResolve { parts.append("no-resolve") }
        return parts.joined(separator: ",")
    }

    /// nil when the line is not one the form can show (remote QX filter_remote lines, logical rules, …): text mode.
    static func parse(_ line: String) -> RuleFormFields? {
        let parts = line.split(separator: ",", omittingEmptySubsequences: false).map { $0.trimmingCharacters(in: .whitespaces) }
        guard let first = parts.first, !first.isEmpty else { return nil }
        var t = first.uppercased()
        t = RuleKind.aliases[t] ?? t
        guard let k = RuleKind.all.first(where: { $0.id == t }) else { return nil }
        var f = RuleFormFields(type: t)
        if k.noValue {
            guard parts.count == 2 else { return nil }
            f.policy = parts[1]
            return f
        }
        guard parts.count >= 3, parts.count <= 4 else { return nil }
        f.value = parts[1]
        f.policy = parts[2]
        if parts.count == 4 {
            guard parts[3].lowercased() == "no-resolve" else { return nil }
            f.noResolve = true
        }
        // QX spells built-in policies in lower case.
        if ["direct", "reject", "proxy"].contains(f.policy) { f.policy = f.policy == "proxy" ? f.policy : f.policy.uppercased() }
        return f
    }
}

struct CustomRuleEditor: View {
    @Environment(\.dismiss) var dismiss
    @ObservedObject private var vpn = VPNManager.shared
    @ObservedObject private var offline = ProfileInspector.shared
    @State var rule: CustomRule
    let onSave: (CustomRule) -> Void
    @State private var check: RuleCheck?
    @State private var checking = false
    /// v0.19.8 (user: QX-like form, 「不要照抄」): type / value / policy fields; 文本模式 shows the raw line.
    @State private var form = RuleFormFields()
    @State private var textMode = false
    @State private var policies: [String] = []

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

    static let builtins = ["DIRECT", "REJECT", "REJECT-DROP"]

    var policyChoices: [String] {
        var out = policies + Self.builtins
        if !form.policy.isEmpty && !out.contains(form.policy) { out.insert(form.policy, at: 0) }
        return out
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("编辑方式", selection: Binding(get: { textMode }, set: { setTextMode($0) })) {
                        Text("表单").tag(false)
                        Text("文本模式").tag(true)
                    }
                    .pickerStyle(.segmented)
                    .accessibilityIdentifier("rule.mode")
                }
                .listRowBackground(Color.clear)
                .listRowInsets(EdgeInsets())

                if textMode { textSections } else { formSections }

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
                    .disabled(!canSave)
                    .accessibilityIdentifier("rule.save")
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
            .task { await loadPolicies() }
            .onAppear {
                if let f = RuleFormFields.parse(rule.line) { form = f }
                else if !rule.line.trimmingCharacters(in: .whitespaces).isEmpty { textMode = true }
                if form.policy.isEmpty { form.policy = policies.first ?? "DIRECT" }
                if !textMode && rule.line.isEmpty { rule.line = form.line }
            }
            .onChange(of: form) { f in if !textMode { rule.line = f.line } }
        }
    }

    var canSave: Bool {
        let line = rule.line.trimmingCharacters(in: .whitespaces)
        if line.isEmpty || check?.error?.isEmpty == false { return false }
        if !textMode, form.kind?.noValue != true, form.value.trimmingCharacters(in: .whitespaces).isEmpty { return false }
        return true
    }

    @ViewBuilder var formSections: some View {
        Section {
            Picker("类型", selection: $form.type) {
                ForEach(RuleKind.Group.allCases, id: \.self) { g in
                    Section(RuleKind.groupTitle(g)) {
                        ForEach(RuleKind.all.filter { $0.group == g }) { k in Text(verbatim: k.id).tag(k.id) }
                    }
                }
            }
            .pickerStyle(.navigationLink)
            .accessibilityIdentifier("rule.type")
            if let k = form.kind { Text(k.caption).font(.caption).foregroundStyle(.secondary) }
            if form.kind?.noValue != true {
                TextField(form.kind?.placeholder ?? "", text: $form.value)
                    .font(.body.monospaced())
                    .keyboardType(form.kind?.keyboard ?? .asciiCapable)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .accessibilityIdentifier("rule.value")
            }
            if form.kind?.isIP == true {
                Toggle("不解析域名（no-resolve）", isOn: $form.noResolve)
            }
        } header: { Text("匹配") }
        .listRowBackground(Theme.card)

        Section {
            Picker("策略", selection: $form.policy) {
                ForEach(policyChoices, id: \.self) { Text(verbatim: $0).tag($0) }
            }
            .pickerStyle(.navigationLink)
            .accessibilityIdentifier("rule.policy")
        } header: { Text("策略") } footer: {
            Text("策略组来自当前配置；找不到时使用第一个手动选择组并标黄。")
        }
        .listRowBackground(Theme.card)

        Section {
            Text(verbatim: rule.line).font(.footnote.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                .accessibilityIdentifier("rule.line")
            if checking { ProgressView().controlSize(.small) } else { RuleCheckLine(check: check) }
        } header: { Text("规则") } footer: { Text("实时校验：显示转换后的 mihomo 规则和对应的策略组。") }
        .listRowBackground(Theme.card)
    }

    @ViewBuilder var textSections: some View {
        Section {
            TextField("规则", text: $rule.line, axis: .vertical)
                .scaledFont(13, design: .monospaced)
                .textInputAutocapitalization(.never).autocorrectionDisabled()
                .lineLimit(1...5)
                .accessibilityIdentifier("rule.text")
            if checking { ProgressView().controlSize(.small) } else { RuleCheckLine(check: check) }
        } header: { Text("规则") } footer: {
            Text("可以粘贴 Surge / QX / Clash 规则；切回表单时会填入各个字段。输入时实时校验：显示转换后的 mihomo 规则和对应的策略组。")
        }
        .listRowBackground(Theme.card)
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

    /// Switching to the form parses the line; a line the form cannot show stays in text mode.
    func setTextMode(_ on: Bool) {
        if on {
            // An empty form (no value typed yet) opens an empty text field instead of a half line like
            // "DOMAIN-SUFFIX,,Proxy" that the pasted rule would be appended to.
            if form.kind?.noValue != true && form.value.trimmingCharacters(in: .whitespaces).isEmpty { rule.line = "" }
            textMode = true
            return
        }
        if let f = RuleFormFields.parse(rule.line) {
            form = f
            textMode = false
            rule.line = f.line
        } else if rule.line.trimmingCharacters(in: .whitespaces).isEmpty {
            textMode = false
            rule.line = form.line
        } else {
            check = RuleCheck(error: String(localized: "这条规则无法用表单编辑（例如远程列表的 QX 写法或逻辑规则），请在文本模式里修改。"))
        }
    }

    func loadPolicies() async {
        var names: [String] = []
        if vpn.isConnected, let p = try? await ControllerClient.shared.proxies() {
            names = LiveGroupOrder.names(p).filter { p[$0]?.isGroup == true && p[$0]?.hidden != true && $0 != "GLOBAL" }
        }
        if names.isEmpty { names = offline.result.groups.filter { $0.hidden != true && $0.name != "GLOBAL" }.map(\.name) }
        policies = names
        if form.policy.isEmpty || (rule.line.isEmpty && !textMode) { form.policy = names.first ?? "DIRECT" }
    }
}

// MARK: - Providers

/// 工具 → 模块 → 配置里的规则集: the profile's rule-providers (feat/more-dedup). The profile's 节点集
/// (proxy-providers) are managed only on 节点与订阅, so this page no longer lists them.
struct ProvidersView: View {
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var offline = ProfileInspector.shared
    @ObservedObject private var updater = ProviderUpdater.shared
    @State private var ruleProviders: [ProviderItem] = []
    @State private var updating: Set<String> = []
    @State private var error: String?

    var body: some View {
        Group {
            if vpn.isConnected { liveList } else { offlineList }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("配置里的规则集")
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                if !vpn.isConnected {
                    if updater.running {
                        HStack(spacing: 6) {
                            ProgressView()
                            Text("\(updater.done)/\(updater.total)").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                        }
                    } else {
                        Button("全部更新") { Task { await updater.updateAll(only: Set(offline.result.ruleProviders.map { $0.kind + ":" + $0.name })) } }
                            .disabled(offline.result.ruleProviders.isEmpty)
                    }
                }
                if vpn.isConnected {
                    Button("全部更新") {
                        Task {
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
            Section {
                if ruleProviders.isEmpty {
                    EmptyStateRow(icon: "list.bullet.rectangle", title: "当前配置没有规则集", message: "自己添加的远程规则集在「模块」页的规则集里。")
                }
                ForEach(ruleProviders) { p in
                    row(p, detail: String(localized: "\(p.ruleCount ?? 0) 条") + " · \(p.behavior ?? "") · \(p.vehicleType ?? "")", key: "r:" + p.name) {
                        try await ControllerClient.shared.updateRuleProvider(p.name)
                    }
                }
            } header: { Text("规则集 \(ruleProviders.count)") }
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
            Section {
                if offline.result.ruleProviders.isEmpty {
                    EmptyStateRow(icon: "list.bullet.rectangle", title: "当前配置没有规则集", message: "自己添加的远程规则集在「模块」页的规则集里。")
                }
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
            ruleProviders = try await ControllerClient.shared.ruleProviders()
        } catch { self.error = error.localizedDescription }
    }
}

struct OfflineProviderRow: View {
    let p: InspectProvider
    var error: String? = nil

    var cacheSummary: String {
        var parts: [String] = [String(localized: "已缓存")]
        if p.count >= 0 {
            parts.append(p.kind == "proxy" ? String(localized: "\(p.count) 个节点") : String(localized: "\(p.count) 条"))
        } else {
            parts.append(String(localized: "二进制格式"))
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
                LabeledContent("类型", value: p.kind == "proxy" ? String(localized: "节点集") : String(localized: "规则集"))
                LabeledContent("来源", value: p.vehicle)
                if let b = p.behavior, !b.isEmpty { LabeledContent("行为", value: b) }
                if let f = p.format, !f.isEmpty { LabeledContent("格式", value: f) }
                if let i = p.interval, i > 0 { LabeledContent("更新间隔", value: String(localized: "\(i / 3600) 小时")) }
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
                Text("还没有缓存。在列表里点更新即可由 App 直接下载；连接后内核也会下载。").font(.footnote).foregroundStyle(.secondary)
                    .listRowBackground(Color.clear)
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle(p.name)
    }
}

// MARK: - v0.14 rule hit counters (saved by the extension in <home>/rule-hits.json)

@MainActor
final class RuleHitsStore: ObservableObject {
    static let shared = RuleHitsStore()

    struct Entry: Decodable, Hashable {
        var type: String
        var payload: String
        var proxy: String
        var total: Int
        var day: String?
        var today: Int?
        var lastHit: Int64?
        var key: String { "\(type),\(payload),\(proxy)" }
        var todayCount: Int { day == RuleHitsStore.dayString(Date()) ? (today ?? 0) : 0 }
        var lastHitDate: Date? { (lastHit ?? 0) > 0 ? Date(timeIntervalSince1970: TimeInterval(lastHit!)) : nil }
    }
    private struct File: Decodable { var since: Int64?; var rules: [String: Entry]? }

    @Published private(set) var entries: [String: Entry] = [:]
    @Published private(set) var since: Date?
    private var byNorm: [String: Entry] = [:]

    static var url: URL { AppShared.homeURL.appendingPathComponent("rule-hits.json") }

    nonisolated static func dayString(_ d: Date) -> String {
        let f = DateFormatter()
        f.calendar = Calendar(identifier: .gregorian)
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd"
        return f.string(from: d)
    }

    /// Live rules say "DomainSuffix", the offline inspector may say "DOMAIN-SUFFIX": compare without case / dashes.
    nonisolated static func norm(_ t: String, _ p: String, _ x: String) -> String {
        t.lowercased().filter { $0.isLetter || $0.isNumber } + "\u{1}" + p + "\u{1}" + x
    }

    func entry(_ type: String, _ payload: String, _ proxy: String) -> Entry? { byNorm[Self.norm(type, payload, proxy)] }

    var total: Int { entries.values.reduce(0) { $0 + $1.total } }
    var today: Int { entries.values.reduce(0) { $0 + $1.todayCount } }
    var top: [Entry] { entries.values.sorted { $0.total > $1.total }.prefix(5).map { $0 } }

    /// Asks a running tunnel to save its counters first, then reads the file.
    func refresh() async {
        if VPNManager.shared.isConnected { _ = await VPNManager.shared.send(.flushStats, timeout: 3) }
        load()
    }

    func load() {
        guard let d = try? Data(contentsOf: Self.url), let f = try? JSONDecoder().decode(File.self, from: d) else {
            entries = [:]; byNorm = [:]; since = nil; return
        }
        entries = f.rules ?? [:]
        var m: [String: Entry] = [:]
        for e in entries.values { m[Self.norm(e.type, e.payload, e.proxy)] = e }
        byNorm = m
        since = (f.since ?? 0) > 0 ? Date(timeIntervalSince1970: TimeInterval(f.since!)) : nil
    }

    /// key nil = all rules.
    func reset(_ key: String?) {
        let err = LibmihomoResetRuleHits(AppShared.homeURL.path, key ?? "")
        if !err.isEmpty { return }
        load()
    }
}

struct RuleHitLine: View {
    let entry: RuleHitsStore.Entry?
    let session: Int?

    var body: some View {
        HStack(spacing: 8) {
            if let e = entry {
                Label("累计 \(Fmt.count(e.total))", systemImage: "chart.bar.fill")
                if e.todayCount > 0 { Text("今天 \(Fmt.count(e.todayCount))") }
                if let d = e.lastHitDate { Text(d.formatted(.relative(presentation: .named))) }
            }
            if let s = session, s > 0 { Text("本次 \(Fmt.count(s))") }
        }
        .font(.caption2.monospacedDigit()).foregroundStyle(.secondary).labelStyle(.titleAndIcon).lineLimit(1)
    }
}

struct RuleHitsSummary: View {
    @ObservedObject var store: RuleHitsStore

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label("命中统计", systemImage: "chart.bar.xaxis").font(.caption.weight(.semibold))
                Spacer()
                if let d = store.since { Text("自 \(d.formatted(date: .abbreviated, time: .omitted)) 起").font(.caption2).foregroundStyle(.secondary) }
            }
            HStack(spacing: 16) {
                VStack(alignment: .leading) { Text(Fmt.count(store.total)).font(.headline.monospacedDigit()); Text("累计").font(.caption2).foregroundStyle(.secondary) }
                VStack(alignment: .leading) { Text(Fmt.count(store.today)).font(.headline.monospacedDigit()); Text("今天").font(.caption2).foregroundStyle(.secondary) }
                VStack(alignment: .leading) { Text("\(store.entries.count)").font(.headline.monospacedDigit()); Text("条规则有命中").font(.caption2).foregroundStyle(.secondary) }
            }
            let maxTotal = max(store.top.first?.total ?? 1, 1)
            ForEach(store.top, id: \.key) { e in
                HStack(spacing: 8) {
                    Text(e.payload.isEmpty ? e.type : e.payload).font(.caption2.monospaced()).lineLimit(1).frame(maxWidth: .infinity, alignment: .leading)
                    GeometryReader { g in
                        Capsule().fill(Theme.accent.opacity(0.7)).frame(width: max(g.size.width * CGFloat(e.total) / CGFloat(maxTotal), 3))
                    }
                    .frame(width: 70, height: 5)
                    Text(Fmt.count(e.total)).font(.caption2.monospacedDigit()).foregroundStyle(.secondary).frame(width: 44, alignment: .trailing)
                }
            }
            Text("连接时每 30 秒保存一次，断开、重载配置后继续累计。长按规则可单独重置。").font(.caption2).foregroundStyle(.secondary)
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 14).fill(Theme.card))
    }
}
