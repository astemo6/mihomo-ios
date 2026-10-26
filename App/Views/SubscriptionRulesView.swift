import SwiftUI

/// Mirrors the retired bridge. Stored in <home>/subscriptions.json keyed by profile id and
/// applied by the old side whenever the runtime config is built (the downloaded file is untouched).
struct SubRules: Codable, Equatable {
    struct Rename: Codable, Equatable, Identifiable {
        var id = UUID()
        var pattern: String = ""
        var replace: String = ""
        var enabled: Bool = true
        enum CodingKeys: String, CodingKey { case pattern, replace, enabled }
        init(pattern: String = "", replace: String = "") { self.pattern = pattern; self.replace = replace }
        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            pattern = (try? c.decodeIfPresent(String.self, forKey: .pattern)) ?? ""
            replace = (try? c.decodeIfPresent(String.self, forKey: .replace)) ?? ""
            enabled = (try? c.decodeIfPresent(Bool.self, forKey: .enabled)) ?? true
        }
    }

    var enabled = true
    var include = ""
    var exclude = ""
    var regex = false
    var stripPrefixes: [String] = []
    var stripFlags = false
    var renames: [Rename] = []
    var addFlag = false
    var prefix = ""
    var dedupe = false
    var sort = ""

    init() {}

    enum CodingKeys: String, CodingKey { case enabled, include, exclude, regex, stripPrefixes, stripFlags, renames, addFlag, prefix, dedupe, sort }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        func get<T: Decodable>(_ k: CodingKeys, _ d: T) -> T { (try? c.decodeIfPresent(T.self, forKey: k)) ?? d }
        enabled = get(.enabled, true)
        include = get(.include, "")
        exclude = get(.exclude, "")
        regex = get(.regex, false)
        stripPrefixes = get(.stripPrefixes, [])
        stripFlags = get(.stripFlags, false)
        renames = get(.renames, [])
        addFlag = get(.addFlag, false)
        prefix = get(.prefix, "")
        dedupe = get(.dedupe, false)
        sort = get(.sort, "")
    }

    var isEmpty: Bool {
        include.isEmpty && exclude.isEmpty && stripPrefixes.isEmpty && !stripFlags && renames.isEmpty && !addFlag && prefix.isEmpty && !dedupe && sort.isEmpty
    }

    /// One-line summary for the profile row.
    var summary: String {
        var parts: [String] = []
        if !include.isEmpty { parts.append(String(localized: "保留")) }
        if !exclude.isEmpty { parts.append(String(localized: "排除")) }
        if !renames.isEmpty || !stripPrefixes.isEmpty || stripFlags || !prefix.isEmpty { parts.append(String(localized: "重命名")) }
        if addFlag { parts.append(String(localized: "旗帜")) }
        if dedupe { parts.append(String(localized: "去重")) }
        if !sort.isEmpty { parts.append(String(localized: "排序")) }
        return parts.joined(separator: " · ")
    }
}

enum SubRulesStore {
    static var url: URL { AppShared.homeURL.appendingPathComponent("subscriptions.json") }

    static func all() -> [String: SubRules] {
        guard let d = try? Data(contentsOf: url) else { return [:] }
        return (try? JSONDecoder().decode([String: SubRules].self, from: d)) ?? [:]
    }

    static func get(_ id: String) -> SubRules? { all()[id] }

    static func set(_ id: String, _ r: SubRules?) {
        var m = all()
        m[id] = r
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let d = try? enc.encode(m) { try? d.write(to: url, options: .atomic) }
    }
}

struct SubPreviewNode: Decodable, Hashable {
    var original: String
    var name: String
    var type: String
    var region: String?
    var kept: Bool
    var reason: String?
    var source: String?
}

struct SubPreviewResult: Decodable {
    var nodes: [SubPreviewNode]
    var total: Int
    var kept: Int
    var providers: [String]
    var errors: [String]
}

struct SubscriptionRulesView: View {
    let profile: Profile
    /// v0.9 订阅管理: node subscriptions store their rules under "nodesub-<id>" and preview their cache file;
    /// saving always reloads a running tunnel (they apply to every profile).
    var rulesKey: String? = nil
    var previewPath: String? = nil
    private var key: String { rulesKey ?? profile.id }
    @EnvironmentObject var store: ProfileStore
    @Environment(\.dismiss) private var dismiss
    @State private var rules = SubRules()
    @State private var saved: SubRules?
    @State private var preview: SubPreviewResult?
    @State private var previewTask: Task<Void, Never>?
    @State private var showRemoved = true
    @State private var newPrefix = ""
    @State private var message: String?

    private let presets: [(String, SubRules.Rename)] = [
        ("去掉「| 倍率」等后缀", .init(pattern: #"\s*[|｜\-]\s*(\d+(\.\d+)?\s*[xX倍]|倍率.*)$"#, replace: "")),
        ("「Hong Kong」→「香港」", .init(pattern: #"(?i)hong\s?kong"#, replace: "香港")),
        ("去掉括号内容", .init(pattern: #"\s*[\(（\[【].*?[\)）\]】]\s*"#, replace: " ")),
        ("合并多余空格", .init(pattern: #"\s{2,}"#, replace: " ")),
    ]

    var body: some View {
        List {
            Section {
                Toggle("启用节点处理", isOn: $rules.enabled)
            } footer: {
                Text("规则只保存在本机覆写里，在生成运行配置时应用；订阅文件本身不改动，更新订阅后规则依然有效。")
            }
            .listRowBackground(Theme.card)

            Section {
                TextField(rules.regex ? "保留：正则，例如 香港|日本|(?i)hk" : "保留：关键词，用 | 分隔，留空表示全部", text: $rules.include, axis: .vertical)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .font(.system(.callout, design: .monospaced))
                TextField(rules.regex ? "排除：正则，例如 剩余|到期|官网" : "排除：关键词，例如 剩余|到期|官网", text: $rules.exclude, axis: .vertical)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .font(.system(.callout, design: .monospaced))
                Toggle("使用正则（JavaScript 写法，不区分大小写）", isOn: $rules.regex)
                if rules.exclude.isEmpty {
                    Button { rules.exclude = "剩余|到期|流量|官网|套餐|重置|过期|Expire|Traffic" } label: {
                        Label("填入常见的信息节点关键词", systemImage: "wand.and.stars")
                    }
                }
            } header: { Text("过滤") }
            .listRowBackground(Theme.card)

            Section {
                ForEach($rules.renames) { $r in
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            TextField("正则", text: $r.pattern)
                                .font(.system(.callout, design: .monospaced))
                                .textInputAutocapitalization(.never).autocorrectionDisabled()
                            Toggle("", isOn: $r.enabled).labelsHidden()
                        }
                        TextField("替换为（可用 $1）", text: $r.replace)
                            .font(.system(.callout, design: .monospaced))
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                    }
                }
                .onDelete { rules.renames.remove(atOffsets: $0) }
                .onMove { rules.renames.move(fromOffsets: $0, toOffset: $1) }
                Menu {
                    Button("空白规则") { rules.renames.append(.init()) }
                    ForEach(presets, id: \.0) { p in
                        Button(LocalizedStringKey(p.0)) { rules.renames.append(p.1) }
                    }
                } label: { Label("添加重命名规则", systemImage: "plus") }
            } header: { Text("重命名（按顺序执行）") }
            .listRowBackground(Theme.card)

            Section {
                ForEach(rules.stripPrefixes, id: \.self) { p in
                    Text(p).font(.system(.callout, design: .monospaced))
                }
                .onDelete { rules.stripPrefixes.remove(atOffsets: $0) }
                HStack {
                    TextField("要去掉的前缀，例如 [SS]", text: $newPrefix)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    Button("添加") {
                        let t = newPrefix.trimmingCharacters(in: .whitespaces)
                        if !t.isEmpty && !rules.stripPrefixes.contains(t) { rules.stripPrefixes.append(t) }
                        newPrefix = ""
                    }.disabled(newPrefix.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                Toggle("去掉原有的旗帜 Emoji", isOn: $rules.stripFlags)
                Toggle("按地区添加旗帜 Emoji", isOn: $rules.addFlag)
                TextField("统一添加前缀（可选）", text: $rules.prefix)
            } header: { Text("前缀与旗帜") }
            .listRowBackground(Theme.card)

            Section {
                Toggle("去除重复节点（类型、地址、端口、凭据相同）", isOn: $rules.dedupe)
                Picker("排序", selection: $rules.sort) {
                    Text("保持原顺序").tag("")
                    Text("按名称").tag("name")
                    Text("按地区").tag("region")
                }
            } header: { Text("去重与排序") } footer: {
                Text("同名节点会自动加序号。节点集（proxy-providers）只应用过滤和重命名（Clash 原生 filter / override），旗帜、去重、排序只作用于配置里直接列出的节点。")
            }
            .listRowBackground(Theme.card)

            previewSection
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("节点处理")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("保存") { save() }.disabled(rules == saved)
            }
            ToolbarItem(placement: .secondaryAction) {
                Button(role: .destructive) { rules = SubRules() } label: { Label("清空规则", systemImage: "trash") }
            }
        }
        .onAppear {
            let r = SubRulesStore.get(key)
            saved = r
            rules = r ?? SubRules()
            schedulePreview()
        }
        .onChange(of: rules) { _ in schedulePreview() }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
    }

    @ViewBuilder var previewSection: some View {
        Section {
            if let p = preview {
                HStack {
                    Text("保留 \(p.kept) / 共 \(p.total)").font(.subheadline.weight(.semibold).monospacedDigit())
                    Spacer()
                    Toggle("显示已移除", isOn: $showRemoved).labelsHidden()
                    Text("显示已移除").font(.caption).foregroundStyle(.secondary)
                }
                ForEach(p.errors, id: \.self) { e in
                    Label(e, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(Theme.bad)
                }
                if p.total == 0 {
                    Text("没有可预览的节点（节点集未下载时，连接一次后再来看）").font(.footnote).foregroundStyle(.secondary)
                }
                ForEach(Array(p.nodes.enumerated()).filter { showRemoved || $0.element.kept }, id: \.offset) { _, n in
                    PreviewRow(n: n)
                }
            } else {
                LoadingRow(text: "生成预览…")
            }
        } header: { Text("实时预览") }
        .listRowBackground(Theme.card)
    }

    func schedulePreview() {
        previewTask?.cancel()
        let r = rules
        let path = previewPath ?? profile.fileURL.path
        previewTask = Task {
            try? await Task.sleep(nanoseconds: 300_000_000)
            if Task.isCancelled { return }
            let json = String(decoding: (try? JSONEncoder().encode(r)) ?? Data("{}".utf8), as: UTF8.self)
            let out = await Task.detached(priority: .userInitiated) {
                NCSubPreview.preview(home: AppShared.homeURL.path, profilePath: path, rulesJSON: json)
            }.value
            if Task.isCancelled { return }
            preview = try? JSONDecoder().decode(SubPreviewResult.self, from: Data(out.utf8))
        }
    }

    func save() {
        if let p = preview, p.kept == 0, p.total > 0, rules.enabled {
            message = String(localized: "当前规则会移除全部节点，请调整后再保存。")
            return
        }
        SubRulesStore.set(key, rules.isEmpty ? nil : rules)
        saved = rules.isEmpty ? nil : rules
        store.objectWillChange.send()
        if profile.id == store.activeID || (rulesKey != nil && VPNManager.shared.isConnected) {
            Task {
                if let err = await VPNManager.shared.reload() { message = String(localized: "已保存，但重载失败：\(err)") }
                else { dismiss() }
            }
        } else {
            dismiss()
        }
    }
}

private struct PreviewRow: View {
    let n: SubPreviewNode
    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            ProtocolBadge(type: n.type)
            VStack(alignment: .leading, spacing: 2) {
                Text(n.name)
                    .font(.callout)
                    .strikethrough(!n.kept)
                    .foregroundStyle(n.kept ? .primary : .secondary)
                    .lineLimit(1)
                if n.kept && n.name != n.original {
                    Text(n.original).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                }
                if let r = n.reason, !n.kept {
                    Text(LocalizedStringKey(r)).font(.caption2).foregroundStyle(Theme.warn)
                }
            }
            Spacer(minLength: 4)
            if let s = n.source {
                Text(s).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
            }
            if let r = n.region, !r.isEmpty {
                Text(r).font(.caption2.monospaced()).foregroundStyle(.secondary)
            }
        }
    }
}
