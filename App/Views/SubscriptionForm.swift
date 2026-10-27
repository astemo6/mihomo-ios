import SwiftUI

// fix/nc-0.20.2: one form for remote subscriptions (重写 → 添加 / 编辑订阅, 分流规则 → 订阅规则集), like QX's
// 资源 → 重写 / 分流 sheet: URL (paste button, install links), 名称 / 标签 (optional), 自动更新 interval, 启用.

struct SubscriptionFormFields: Equatable {
    var url = ""
    var name = ""
    /// seconds
    var interval = 86400
    var enabled = true

    static let intervals: [(seconds: Int, title: LocalizedStringKey)] = [
        (21600, "6 小时"), (43200, "12 小时"), (86400, "1 天"), (604800, "7 天"),
    ]

    /// The URL with an install link (surge:/// loon:// quantumult-x:/// stash:// egern:/// tern://) unwrapped.
    var resolvedURL: String {
        let u = url.trimmingCharacters(in: .whitespacesAndNewlines)
        if case .moduleURL(let inner, _)? = ImportRouter.parse(u) { return inner }
        return u
    }

    var trimmedName: String { name.trimmingCharacters(in: .whitespacesAndNewlines) }

    var isValidURL: Bool {
        guard let u = URL(string: resolvedURL), let s = u.scheme?.lowercased(), s == "http" || s == "https",
              let h = u.host, !h.isEmpty else { return false }
        return true
    }

    /// The interval picker shows only fixed choices: another stored value snaps to the nearest one.
    static func snap(_ s: Int?) -> Int {
        guard let s, s > 0 else { return 86400 }
        return intervals.map(\.seconds).min { abs($0 - s) < abs($1 - s) } ?? 86400
    }
}

/// The form sections; `extra` sits between 名称 and 自动更新 (e.g. the rule set's 策略).
struct SubscriptionFormSections<Extra: View>: View {
    @Binding var fields: SubscriptionFormFields
    var urlPlaceholder: String = "https://…"
    /// Shown greyed in the name field: the name used when it stays empty.
    var defaultName: String = ""
    var urlFooter: LocalizedStringKey = "也可以粘贴 surge:/// loon:// stash:// quantumult-x:/// egern:/// 安装链接。"
    var idPrefix: String
    @ViewBuilder var extra: () -> Extra

    var body: some View {
        Section {
            HStack {
                TextField(urlPlaceholder, text: $fields.url)
                    .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                    .accessibilityIdentifier(idPrefix + ".url")
                PasteButton(payloadType: String.self) { strings in
                    let t = (strings.first ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
                    DispatchQueue.main.async {
                        if case .moduleURL(let u, _)? = ImportRouter.parse(t) { fields.url = u } else { fields.url = t }
                    }
                }
                .labelStyle(.iconOnly)
                .buttonBorderShape(.capsule)
                .accessibilityIdentifier(idPrefix + ".paste")
            }
        } header: { Text("链接") } footer: { Text(urlFooter) }
        .listRowBackground(Theme.card)

        Section {
            TextField(defaultName.isEmpty ? String(localized: "可选") : defaultName, text: $fields.name)
                .textInputAutocapitalization(.never).autocorrectionDisabled()
                .accessibilityIdentifier(idPrefix + ".name")
        } header: { Text("名称 / 标签") } footer: {
            Text("留空时使用订阅内容里的名称或文件名。自己填写的名称在更新后保持不变。")
        }
        .listRowBackground(Theme.card)

        extra()

        Section {
            Picker("自动更新", selection: $fields.interval) {
                ForEach(SubscriptionFormFields.intervals, id: \.seconds) { Text($0.title).tag($0.seconds) }
            }
            .accessibilityIdentifier(idPrefix + ".interval")
            Toggle("启用", isOn: $fields.enabled)
                .accessibilityIdentifier(idPrefix + ".enabled")
        }
        .listRowBackground(Theme.card)
    }
}

extension SubscriptionFormSections where Extra == EmptyView {
    init(fields: Binding<SubscriptionFormFields>, urlPlaceholder: String = "https://…", defaultName: String = "",
         idPrefix: String) {
        self.init(fields: fields, urlPlaceholder: urlPlaceholder, defaultName: defaultName, idPrefix: idPrefix) { EmptyView() }
    }
}

// MARK: - 重写 → 添加 / 编辑订阅

/// fix/nc-0.20.2: replaces the URL-only ModuleURLSheet. `editing` nil = add.
struct ModuleSubscriptionSheet: View {
    let editing: EngineModule?
    let onSave: (SubscriptionFormFields) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var fields = SubscriptionFormFields()

    init(editing: EngineModule? = nil, initialURL: String = "", onSave: @escaping (SubscriptionFormFields) -> Void) {
        self.editing = editing
        self.onSave = onSave
        var f = SubscriptionFormFields()
        if let m = editing {
            f.url = m.url
            f.name = m.customName == true ? m.name : ""
            f.interval = SubscriptionFormFields.snap(m.interval)
            f.enabled = m.enabled
        } else {
            f.url = initialURL
        }
        _fields = State(initialValue: f)
    }

    var body: some View {
        NavigationStack {
            Form {
                SubscriptionFormSections(fields: $fields, urlPlaceholder: "https://…/xxx.sgmodule",
                                         defaultName: editing?.name ?? "", idPrefix: "moduleurl")
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle(editing == nil ? "添加订阅" : "编辑订阅")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button(editing == nil ? "添加" : "保存") {
                        var f = fields
                        f.url = f.resolvedURL
                        onSave(f)
                        dismiss()
                    }
                    .disabled(!fields.isValidURL)
                    .accessibilityIdentifier("moduleurl.save")
                }
            }
        }
    }
}

// MARK: - 分流规则 → 订阅规则集

/// fix/nc-0.20.2: a remote rule set as a managed 订阅 — stored as the user's remote custom rule (rules.json, QX
/// filter_remote spelling: `<url>, tag=<name>, force-policy=<policy>`), the same item 分流规则 → 订阅 already lists,
/// updates, reorders and the runtime turns into a rule provider. 「列表自带策略」 leaves out force-policy (QX lists keep
/// their per-line policies).
struct RuleSetSubscriptionSheet: View {
    let editing: CustomRule?
    let onSave: (CustomRule) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var fields = SubscriptionFormFields()
    @State private var policy = ""
    @State private var targets = PolicyTargets()

    static let ownPolicy = "\u{1}own"

    init(editing: CustomRule? = nil, onSave: @escaping (CustomRule) -> Void) {
        self.editing = editing
        self.onSave = onSave
        var f = SubscriptionFormFields()
        var p = ""
        if let r = editing, let parts = Self.parse(r.line) {
            f.url = parts.url; f.name = parts.tag; p = parts.policy ?? Self.ownPolicy
            f.interval = SubscriptionFormFields.snap(r.interval); f.enabled = r.enabled
        }
        _fields = State(initialValue: f)
        _policy = State(initialValue: p)
    }

    /// `<url>, tag=…, force-policy=…` / `RULE-SET,<url>,<policy>` / `DOMAIN-SET,…` → parts (nil = not a remote line).
    nonisolated static func parse(_ line: String) -> (url: String, tag: String, policy: String?)? {
        let parts = line.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        guard !parts.isEmpty else { return nil }
        if parts[0].lowercased().hasPrefix("http") {
            var tag = "", pol: String? = nil
            for p in parts.dropFirst() {
                let kv = p.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                guard kv.count == 2 else { continue }
                switch kv[0].lowercased() {
                case "tag": tag = kv[1]
                case "force-policy", "policy": pol = kv[1]
                default: break
                }
            }
            return (parts[0], tag, pol)
        }
        let t = parts[0].uppercased()
        if (t == "RULE-SET" || t == "DOMAIN-SET"), parts.count >= 3, parts[1].lowercased().hasPrefix("http") {
            return (parts[1], "", parts[2])
        }
        return nil
    }

    /// The rules.json line for these fields.
    nonisolated static func line(url: String, tag: String, policy: String?) -> String {
        var s = url
        let t = tag.replacingOccurrences(of: ",", with: " ").trimmingCharacters(in: .whitespaces)
        if !t.isEmpty { s += ", tag=" + t }
        if let p = policy, !p.isEmpty { s += ", force-policy=" + p }
        return s
    }

    var body: some View {
        NavigationStack {
            Form {
                SubscriptionFormSections(fields: $fields, urlPlaceholder: "https://…/xxx.list",
                                         urlFooter: "Surge / QX / Loon / Clash 规则列表（.list / .txt / .yaml）。",
                                         idPrefix: "rulesub") {
                    Section {
                        Picker("策略", selection: $policy) {
                            Text("列表自带策略（QX）").tag(Self.ownPolicy)
                            if !policy.isEmpty, policy != Self.ownPolicy, !targets.all.contains(policy) {
                                Text(verbatim: policy).tag(policy)
                            }
                            if !targets.groups.isEmpty {
                                Section("策略组") { ForEach(targets.groups, id: \.self) { Text(verbatim: $0).tag($0) } }
                            }
                            Section("内置策略") { ForEach(targets.builtins, id: \.self) { Text(verbatim: $0).tag($0) } }
                        }
                        .pickerStyle(.navigationLink)
                        .accessibilityIdentifier("rulesub.policy")
                    } header: { Text("策略") } footer: {
                        Text("列表里每一行都使用这个策略；QX 列表可以选「列表自带策略」，按每行写的策略分流。")
                    }
                    .listRowBackground(Theme.card)
                }
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle(editing == nil ? "订阅规则集" : "编辑规则集")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button(editing == nil ? "添加" : "保存") {
                        let pol = policy == Self.ownPolicy ? nil : policy
                        var r = editing ?? CustomRule(line: "")
                        r.line = Self.line(url: fields.resolvedURL, tag: fields.trimmedName, policy: pol)
                        r.enabled = fields.enabled
                        r.interval = fields.interval
                        onSave(r)
                        dismiss()
                    }
                    .disabled(!fields.isValidURL || policy.isEmpty)
                    .accessibilityIdentifier("rulesub.save")
                }
            }
            .task {
                targets = await PolicyTargets.load()
                if policy.isEmpty { policy = targets.groups.first ?? "DIRECT" }
            }
        }
    }
}
