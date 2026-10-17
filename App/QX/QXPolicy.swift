import SwiftUI
import Libmihomo

// QX-3: 策略 editor in QX's form (frame 09): × / ⟨⟩ (正则筛选 ↔ 手动引用) / ✓; 类型, 策略名, 图标 (浏览),
// 需匹配的资源标签 - 正则, 需匹配的节点标签 - 正则, then 结果 = live preview of the matched nodes.
// 手动引用: 可引用 (current members, ⊖ and reorder) and 更多 (everything else, ⊕). Stored as v0.9 group
// edits (group-edits.json); the resource-tag regex is kept beside it so it reopens as typed.
// Also: home policy order (排序) and card background (背景) from the policy long-press menu.

enum QXPolicyType: String, CaseIterable, Identifiable {
    case staticP = "static", available, roundRobin = "round-robin", destHash = "dest-hash", urlLatency = "url-latency-benchmark"
    var id: String { rawValue }

    var hint: String {
        switch self {
        case .staticP: return String(localized: "手动选择")
        case .available: return String(localized: "故障转移：使用第一个可用的")
        case .roundRobin: return String(localized: "轮询")
        case .destHash: return String(localized: "按目标地址散列")
        case .urlLatency: return String(localized: "延迟最低")
        }
    }

    static func from(_ spec: GroupSpec) -> QXPolicyType {
        switch spec.type {
        case "url-test": return .urlLatency
        case "fallback": return .available
        case "load-balance": return spec.strategy == "round-robin" ? .roundRobin : .destHash
        default: return .staticP
        }
    }

    func apply(to s: inout GroupSpec) {
        switch self {
        case .staticP: s.type = "select"; s.strategy = nil
        case .available: s.type = "fallback"; s.strategy = nil
        case .roundRobin: s.type = "load-balance"; s.strategy = "round-robin"
        case .destHash: s.type = "load-balance"; s.strategy = "consistent-hashing"
        case .urlLatency: s.type = "url-test"; s.strategy = nil
        }
    }
}

/// resource-tag-regex per profile + policy (mihomo has `use:` only, so the regex is resolved at save time).
enum QXPolicyMeta {
    static let key = "qx.policyResourceRegex"
    static func all() -> [String: String] {
        guard let s = UserDefaults.standard.string(forKey: key), let d = s.data(using: .utf8),
              let m = try? JSONDecoder().decode([String: String].self, from: d) else { return [:] }
        return m
    }
    static func get(_ profile: String, _ group: String) -> String? { all()[profile + "|" + group] }
    static func set(_ profile: String, _ group: String, _ v: String?) {
        var m = all()
        m[profile + "|" + group] = (v?.isEmpty == false) ? v : nil
        if let d = try? JSONEncoder().encode(m) { UserDefaults.standard.set(String(decoding: d, as: UTF8.self), forKey: key) }
    }
}

struct QXPolicyEditor: View {
    let groupName: String?
    @EnvironmentObject var store: ProfileStore
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var offline = ProfileInspector.shared
    @Environment(\.dismiss) private var dismiss

    @State private var specs = GroupSpecsResult()
    @State private var edits = GroupEdits()
    @State private var originalName: String?
    @State private var addedIndex: Int?
    @State private var spec = GroupSpec(name: "")
    @State private var qxType = QXPolicyType.staticP
    @State private var resourceRegex = ""
    @State private var manual = false
    @State private var loaded = false
    @State private var saving = false
    @State private var message: String?
    @State private var iconTarget: QXIconTarget?
    @State private var browsing: QXIconBrowseTarget?
    @State private var confirmDelete = false
    @State private var showAdvanced = false

    var profile: Profile? { store.active }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 26) {
                QXLargeTitle(title: String(localized: "策略"))
                if !loaded {
                    ProgressView().frame(maxWidth: .infinity).padding(.top, 40)
                } else {
                    typeField
                    textField(String(localized: "策略名"), required: true, placeholder: String(localized: "例如：自动选择"), text: $spec.name)
                    iconField
                    if manual { manualSection } else { regexSection }
                    advancedSection
                    if groupName != nil { dangerSection }
                }
            }
            .padding(.horizontal, 24)
            .padding(.top, 70)
            .padding(.bottom, 50)
        }
        .background(Theme.bg.ignoresSafeArea())
        .overlay(alignment: .top) {
            HStack {
                QXCircleButton(systemName: "xmark") { dismiss() }.accessibilityLabel(Text("取消"))
                Spacer()
                QXCapsuleBar {
                    QXBarIcon(systemName: manual ? "chevron.left.forwardslash.chevron.right" : "hand.point.up.left",
                              tint: qxType == .staticP || manual ? .primary : .secondary) {
                        withAnimation(.spring(response: 0.3)) { manual.toggle() }
                    }
                    .accessibilityLabel(Text(manual ? LocalizedStringKey("正则筛选") : LocalizedStringKey("手动引用")))
                    if saving {
                        ProgressView().frame(width: 38, height: 40)
                    } else {
                        QXBarIcon(systemName: "checkmark", tint: QXColor.switchOn) { Task { await save() } }
                            .accessibilityLabel(Text("保存"))
                            .disabled(!loaded)
                    }
                }
            }
            .padding(.horizontal, 16).padding(.top, 12).padding(.bottom, 8)
            .background(LinearGradient(colors: [Theme.bg, Theme.bg.opacity(0)], startPoint: .top, endPoint: .bottom))
        }
        .task { await load() }
        .sheet(item: $iconTarget) { t in GroupIconPicker(group: t.name, profileIcon: t.profileIcon) }
        .sheet(item: $browsing) { _ in
            QXIconBrowser { url in
                spec.icon = url
                if let n = groupName { GroupIconStore.shared.set(group: n, url: url) }
            }
        }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
        .confirmationDialog("删除策略「\(spec.name)」？", isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("删除", role: .destructive) { Task { await delete() } }
        } message: { Text("其他策略中对它的引用会一并移除；指向它的规则改用第一个手动选择策略。") }
    }

    // MARK: Fields

    var typeField: some View {
        VStack(alignment: .leading, spacing: 8) {
            label(String(localized: "类型"), required: true)
            Menu {
                ForEach(QXPolicyType.allCases) { t in
                    Button { qxType = t } label: { Text(verbatim: "\(t.rawValue) — \(t.hint)") }
                }
            } label: {
                HStack {
                    Text(verbatim: qxType.rawValue).foregroundStyle(.primary)
                    Text(verbatim: qxType.hint).font(.footnote).foregroundStyle(.secondary)
                    Spacer()
                    Image(systemName: "chevron.up.chevron.down").font(.caption).foregroundStyle(.secondary)
                }
            }
            Divider()
        }
    }

    var iconField: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                label(String(localized: "图标"), required: false)
                Spacer()
                // QX-4: 浏览 works for new policies too: the picked URL goes into the form (img-url);
                // for an existing policy it also becomes its icon override so the home card shows it at once.
                QXPill(title: String(localized: "浏览")) { browsing = QXIconBrowseTarget() }
            }
            HStack(spacing: 10) {
                if let i = spec.icon, i.hasPrefix("http") { RemoteIcon(url: i, size: 28) }
                TextField("https://…/icon.png", text: Binding(get: { spec.icon ?? "" }, set: { spec.icon = $0.isEmpty ? nil : $0 }))
                    .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                    .lineLimit(1)
            }
            Divider()
        }
    }

    var regexSection: some View {
        VStack(alignment: .leading, spacing: 26) {
            VStack(alignment: .leading, spacing: 8) {
                label(String(localized: "需匹配的资源标签 - 正则"), required: false)
                TextField("^CN", text: $resourceRegex)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .font(.system(size: 16, design: .monospaced))
                Divider()
                if !specs.providers.isEmpty {
                    Text("资源：\(matchedProviders.isEmpty && !resourceRegex.isEmpty ? String(localized: "无匹配") : (resourceRegex.isEmpty ? String(localized: "全部") : matchedProviders.joined(separator: "、")))")
                        .font(.caption).foregroundStyle(.secondary).lineLimit(2)
                }
            }
            textField(String(localized: "需匹配的节点标签 - 正则"), required: false, placeholder: "^(?!.*CFT).*$",
                      text: Binding(get: { spec.filter ?? "" }, set: { spec.filter = $0.isEmpty ? nil : $0 }), mono: true)
            textField(String(localized: "排除的节点标签 - 正则"), required: false, placeholder: String(localized: "可选"),
                      text: Binding(get: { spec.excludeFilter ?? "" }, set: { spec.excludeFilter = $0.isEmpty ? nil : $0 }), mono: true)
            resultSection
        }
    }

    var resultSection: some View {
        let nodes = previewNodes
        let members = spec.proxies
        return VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Text("结果").font(.system(size: QXMetrics.largeTitle, weight: .bold))
                Text(verbatim: "\(members.count + nodes.count)").font(.system(size: 17)).foregroundStyle(.secondary)
            }
            .padding(.bottom, 10)
            if let e = regexError {
                Text(verbatim: e).font(.footnote).foregroundStyle(Theme.bad).padding(.bottom, 8)
            }
            ForEach(members, id: \.self) { m in
                resultRow(m, note: NSLocalizedString(memberKindKey(m), comment: ""))
            }
            ForEach(nodes.prefix(300), id: \.self) { n in resultRow(n, note: nil) }
            if nodes.count > 300 {
                Text("另有 \(nodes.count - 300) 个").font(.footnote).foregroundStyle(.secondary).padding(.vertical, 10)
            }
            if members.isEmpty && nodes.isEmpty {
                Text(regexActive ? LocalizedStringKey("没有匹配的节点。节点集未下载时，先在节点资源中更新。") : LocalizedStringKey("填写正则后这里实时显示匹配到的节点；也可以点右上角切换到手动引用。"))
                    .font(.footnote).foregroundStyle(.secondary)
            }
        }
    }

    func resultRow(_ name: String, note: String?) -> some View {
        VStack(spacing: 0) {
            HStack {
                Text(verbatim: name).font(.system(size: 17)).lineLimit(1)
                Spacer()
                if let note { Text(verbatim: note).font(.caption2).foregroundStyle(.secondary) }
            }
            .padding(.vertical, 12)
            Divider()
        }
    }

    var manualSection: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 0) {
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    Text("可引用").font(.system(size: 22, weight: .bold))
                    Text(verbatim: "\(spec.proxies.count)").font(.system(size: 15)).foregroundStyle(.secondary)
                }
                .padding(.bottom, 6)
                if qxType != .staticP {
                    Text("手动引用一般用于 static 策略；其他类型也可以按顺序引用。").font(.caption).foregroundStyle(.secondary).padding(.bottom, 6)
                }
                ForEach(Array(spec.proxies.enumerated()), id: \.element) { i, m in
                    HStack(spacing: 12) {
                        Button { _ = withAnimation { spec.proxies.remove(at: i) } } label: {
                            Image(systemName: "minus.circle.fill").font(.system(size: 22)).foregroundStyle(QXColor.red)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel(Text("移除"))
                        Text(verbatim: m).font(.system(size: 17)).lineLimit(1)
                        Spacer()
                        Text(LocalizedStringKey(memberKindKey(m))).font(.caption2).foregroundStyle(.secondary)
                        Button { move(i, -1) } label: { Image(systemName: "chevron.up") }.buttonStyle(.plain).disabled(i == 0)
                            .accessibilityLabel(Text("上移"))
                        Button { move(i, 1) } label: { Image(systemName: "chevron.down") }.buttonStyle(.plain).disabled(i == spec.proxies.count - 1)
                            .accessibilityLabel(Text("下移"))
                    }
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 10)
                    Divider()
                }
            }
            VStack(alignment: .leading, spacing: 0) {
                Text("更多").font(.system(size: 22, weight: .bold)).padding(.bottom, 6)
                ForEach(candidates.filter { !spec.proxies.contains($0) }, id: \.self) { c in
                    HStack(spacing: 12) {
                        Button { withAnimation { spec.proxies.append(c) } } label: {
                            Image(systemName: "plus.circle.fill").font(.system(size: 22)).foregroundStyle(QXColor.mitm)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel(Text("添加"))
                        Text(verbatim: c).font(.system(size: 17)).lineLimit(1)
                        Spacer()
                        Text(LocalizedStringKey(memberKindKey(c))).font(.caption2).foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 10)
                    Divider()
                }
            }
        }
    }

    var advancedSection: some View {
        VStack(alignment: .leading, spacing: 14) {
            Button { withAnimation(.spring(response: 0.3)) { showAdvanced.toggle() } } label: {
                HStack(spacing: 8) {
                    Text("高级").font(.system(size: 20, weight: .bold)).foregroundStyle(.primary)
                    Image(systemName: showAdvanced ? "arrowtriangle.down.fill" : "arrowtriangle.right.fill")
                        .font(.system(size: 10, weight: .bold)).foregroundStyle(.primary)
                    Spacer()
                }
            }
            .buttonStyle(.plain)
            if showAdvanced {
                if qxType != .staticP {
                    textField(String(localized: "测速地址"), required: false, placeholder: String(localized: "留空用默认"),
                              text: Binding(get: { spec.url ?? "" }, set: { spec.url = $0.isEmpty ? nil : $0 }))
                    Stepper(value: Binding(get: { spec.interval ?? 300 }, set: { spec.interval = $0 }), in: 30...86400, step: 30) {
                        Text("检测间隔 \(spec.interval ?? 300) 秒")
                    }
                    if qxType == .urlLatency {
                        Stepper(value: Binding(get: { spec.tolerance ?? 0 }, set: { spec.tolerance = $0 > 0 ? $0 : nil }), in: 0...1000, step: 10) {
                            Text("容差 \(spec.tolerance ?? 0) ms")
                        }
                    }
                    Toggle("持续检测（alive-checking）", isOn: Binding(get: { spec.lazy == false }, set: { spec.lazy = $0 ? false : nil }))
                        .tint(QXColor.switchOn)
                }
                Toggle("在首页隐藏", isOn: Binding(get: { spec.hidden == true }, set: { spec.hidden = $0 ? true : nil }))
                    .tint(QXColor.switchOn)
                Text("check-interval、tolerance、alive-checking 对应 mihomo 的 interval、tolerance、lazy。重命名时，规则与其他策略中的引用会一起更新。")
                    .font(.footnote).foregroundStyle(.secondary)
            }
        }
    }

    var dangerSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let o = originalName, edits.edits?[o] != nil {
                Button { Task { await restore() } } label: { Label("恢复原始", systemImage: "arrow.uturn.backward") }
            }
            Button(role: .destructive) { confirmDelete = true } label: { Label("删除策略", systemImage: "trash") }
                .foregroundStyle(QXColor.red)
        }
        .font(.system(size: 17, weight: .semibold))
    }

    private func label(_ t: String, required: Bool) -> some View {
        HStack(spacing: 2) {
            Text(verbatim: t).font(.system(size: 20, weight: .bold))
            if required { Text(verbatim: "*").font(.system(size: 20, weight: .bold)).foregroundStyle(QXColor.red) }
        }
    }

    private func textField(_ title: String, required: Bool, placeholder: String, text: Binding<String>, mono: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            label(title, required: required)
            TextField(placeholder, text: text)
                .textInputAutocapitalization(.never).autocorrectionDisabled()
                .font(mono ? .system(size: 16, design: .monospaced) : .body)
            Divider()
        }
    }

    // MARK: Data

    var candidates: [String] {
        var out = ["DIRECT", "REJECT"]
        out += specs.groups.map(\.name).filter { $0 != spec.name && $0 != groupName }
        out += (edits.added ?? []).map(\.name).filter { $0 != spec.name && $0 != groupName }
        out += specs.proxies
        for pv in offline.result.proxyProviders { out += (pv.proxies ?? []).map(\.name) }
        return out.reduce(into: [String]()) { if !$0.contains($1) { $0.append($1) } }
    }

    func memberKindKey(_ m: String) -> String {
        if ["DIRECT", "REJECT", "REJECT-DROP", "PASS"].contains(m.uppercased()) { return "内置" }
        if specs.groups.contains(where: { $0.name == m }) || (edits.added ?? []).contains(where: { $0.name == m }) { return "策略组" }
        return "节点"
    }

    var regexActive: Bool { !resourceRegex.isEmpty || !(spec.filter ?? "").isEmpty }

    var regexError: String? {
        for p in [resourceRegex, spec.filter ?? "", spec.excludeFilter ?? ""] where !p.isEmpty {
            for part in p.split(separator: "`") where (try? NSRegularExpression(pattern: String(part))) == nil {
                return String(localized: "正则无效：\(String(part))")
            }
        }
        return nil
    }

    static func matches(_ pattern: String?, _ s: String) -> Bool? {
        guard let p = pattern, !p.isEmpty else { return nil }
        for part in p.split(separator: "`") {
            if let re = try? NSRegularExpression(pattern: String(part)),
               re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil { return true }
        }
        return false
    }

    var matchedProviders: [String] {
        guard !resourceRegex.isEmpty else { return [] }
        return specs.providers.filter { Self.matches(resourceRegex, $0) == true }
    }

    /// QX semantics: resource regex picks the resources (empty = every resource when a node regex is set),
    /// the node regex filters their nodes, the exclude regex removes nodes.
    var previewNodes: [String] {
        guard regexActive || spec.includeAll == true || !(spec.use ?? []).isEmpty else { return [] }
        var pool: [String] = []
        let providers: [String]
        if !resourceRegex.isEmpty { providers = matchedProviders }
        else if regexActive || spec.includeAll == true { providers = offline.result.proxyProviders.map(\.name) }
        else { providers = spec.use ?? [] }
        if resourceRegex.isEmpty && (regexActive || spec.includeAll == true) {
            pool += offline.result.proxies.map(\.name).filter { !QXNodesModel.builtins.contains($0) }
        }
        for pv in offline.result.proxyProviders where providers.contains(pv.name) {
            pool += (pv.proxies ?? []).map(\.name)
        }
        var seen = Set<String>()
        return pool.filter { n in
            guard !seen.contains(n) else { return false }
            seen.insert(n)
            if Self.matches(spec.filter, n) == false { return false }
            if Self.matches(spec.excludeFilter, n) == true { return false }
            return true
        }
    }

    private func move(_ i: Int, _ d: Int) {
        let j = i + d
        guard spec.proxies.indices.contains(j) else { return }
        withAnimation { spec.proxies.swapAt(i, j) }
    }

    func load() async {
        guard let p = profile else { message = String(localized: "请先选择一个配置"); loaded = true; return }
        if offline.result.groups.isEmpty { await offline.load() }
        specs = await GroupSpecsResult.load(p.fileURL.path)
        edits = GroupEditStore.get(p.id)
        if let groupName {
            if let i = (edits.added ?? []).firstIndex(where: { $0.name == groupName }) {
                addedIndex = i
                spec = edits.added![i]
            } else if let hit = (edits.edits ?? [:]).first(where: { $0.value.spec?.name == groupName }), let s = hit.value.spec {
                originalName = hit.key
                spec = s
            } else if let s = specs.groups.first(where: { $0.name == groupName }) {
                originalName = groupName
                spec = s
            } else {
                spec = GroupSpec(name: groupName)
            }
            resourceRegex = QXPolicyMeta.get(p.id, groupName) ?? ""
        } else {
            spec = GroupSpec(name: String(localized: "新策略"))
        }
        qxType = QXPolicyType.from(spec)
        // Groups that only list members open in 手动引用, like QX's static policies without regexes.
        manual = resourceRegex.isEmpty && (spec.filter ?? "").isEmpty && (spec.use ?? []).isEmpty && spec.includeAll != true && !spec.proxies.isEmpty
        loaded = true
    }

    func save() async {
        guard let p = profile else { return }
        if let e = regexError { message = e; return }
        var s = spec
        s.name = s.name.trimmingCharacters(in: .whitespaces)
        if s.name.isEmpty { message = String(localized: "名称不能为空"); return }
        qxType.apply(to: &s)
        if s.type == "select" { s.url = nil; s.interval = nil; s.tolerance = nil; s.lazy = nil }
        if !resourceRegex.isEmpty {
            s.use = matchedProviders.isEmpty ? nil : matchedProviders
            s.includeAll = nil
        } else if !(s.filter ?? "").isEmpty && (s.use ?? []).isEmpty {
            s.includeAll = true
        }
        let clash = s.name != groupName && ((specs.groups.contains { $0.name == s.name } && s.name != originalName)
            || (edits.added ?? []).enumerated().contains { $0.element.name == s.name && $0.offset != addedIndex }
            || specs.proxies.contains(s.name))
        if clash { message = String(localized: "已有同名的策略组或节点"); return }
        var e = edits
        if let i = addedIndex {
            e.added?[i] = s
        } else if let orig = originalName {
            var m = e.edits ?? [:]
            m[orig] = GroupEdit(deleted: nil, spec: s)
            e.edits = m
        } else {
            e.added = (e.added ?? []) + [s]
        }
        if let old = groupName, old != s.name { QXPolicyMeta.set(p.id, old, nil) }
        QXPolicyMeta.set(p.id, s.name, resourceRegex)
        await persist(e, profile: p)
    }

    func persist(_ e: GroupEdits, profile p: Profile) async {
        saving = true
        defer { saving = false }
        let json = GroupEditStore.json(e)
        let path = p.fileURL.path
        let err = await Task.detached(priority: .userInitiated) { LibmihomoGroupEditCheck(AppShared.homeURL.path, path, json) }.value
        if !err.isEmpty { message = err; return }
        GroupEditStore.set(p.id, e)
        if vpn.isConnected, let r = await VPNManager.shared.reload() {
            message = String(localized: "已保存，但重载失败：\(r)")
            return
        }
        await offline.load()
        dismiss()
    }

    func delete() async {
        guard let p = profile else { return }
        var e = edits
        if let i = addedIndex {
            e.added?.remove(at: i)
        } else if let orig = originalName {
            var m = e.edits ?? [:]
            m[orig] = GroupEdit(deleted: true, spec: nil)
            e.edits = m
        }
        if let n = groupName { QXPolicyMeta.set(p.id, n, nil) }
        await persist(e, profile: p)
    }

    func restore() async {
        guard let p = profile, let orig = originalName else { return }
        var e = edits
        e.edits?[orig] = nil
        await persist(e, profile: p)
    }
}

// MARK: - 排序 / 背景 (home presentation only)

enum QXPolicyPrefs {
    static let orderKey = "qx.policyOrder"
    static let bgKey = "qx.policyBackground"

    private static func dict(_ key: String) -> [String: String] {
        guard let s = UserDefaults.standard.string(forKey: key), let d = s.data(using: .utf8),
              let m = try? JSONDecoder().decode([String: String].self, from: d) else { return [:] }
        return m
    }

    private static func store(_ key: String, _ m: [String: String]) {
        if let d = try? JSONEncoder().encode(m) { UserDefaults.standard.set(String(decoding: d, as: UTF8.self), forKey: key) }
    }

    /// Saved order for a profile (names joined by a newline).
    static func order(_ profile: String) -> [String] {
        (dict(orderKey)[profile] ?? "").split(separator: "\n").map(String.init)
    }

    static func setOrder(_ profile: String, _ names: [String]) {
        var m = dict(orderKey)
        m[profile] = names.isEmpty ? nil : names.joined(separator: "\n")
        store(orderKey, m)
    }

    static func sorted(_ groups: [QXGroup], profile: String) -> [QXGroup] {
        let o = order(profile)
        guard !o.isEmpty else { return groups }
        var idx: [String: Int] = [:]
        for (i, n) in o.enumerated() where idx[n] == nil { idx[n] = i }
        return groups.enumerated().sorted { a, b in
            let ia = idx[a.element.name] ?? (o.count + a.offset)
            let ib = idx[b.element.name] ?? (o.count + b.offset)
            return ia < ib
        }.map(\.element)
    }

    static let palette: [(String, Color)] = [
        ("blue", QXColor.nodes), ("purple", QXColor.rules), ("pink", QXColor.rewrite), ("green", QXColor.mitm),
        ("orange", Color(red: 0.98, green: 0.58, blue: 0.13)), ("red", QXColor.red), ("teal", QXColor.teal), ("gray", QXColor.logs),
    ]

    static func background(_ group: String) -> Color? {
        guard let k = dict(bgKey)[group] else { return nil }
        return palette.first { $0.0 == k }?.1
    }

    static func backgroundKey(_ group: String) -> String? { dict(bgKey)[group] }

    static func setBackground(_ group: String, _ key: String?) {
        var m = dict(bgKey)
        m[group] = key
        store(bgKey, m)
    }
}

struct QXPolicySortSheet: View {
    let profileID: String
    let names: [String]
    let onDone: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var order: [String] = []

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(order, id: \.self) { n in
                        HStack(spacing: 12) {
                            GroupIconView(group: n, profileIcon: nil, fallback: "square.stack.3d.up", size: 30)
                            Text(verbatim: n).lineLimit(1)
                        }
                    }
                    .onMove { order.move(fromOffsets: $0, toOffset: $1) }
                } footer: { Text("拖动调整首页「自定义策略」的显示顺序，不改变配置文件。") }
                .listRowBackground(Theme.card)
            }
            .environment(\.editMode, .constant(.active))
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("排序").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("恢复默认") { QXPolicyPrefs.setOrder(profileID, []); onDone(); dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("完成") { QXPolicyPrefs.setOrder(profileID, order); onDone(); dismiss() }
                }
            }
            .onAppear { order = names }
        }
    }
}

struct QXPolicyBackgroundSheet: View {
    let group: String
    let onDone: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var current: String?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text("为「\(group)」的卡片选择背景色。").font(.subheadline).foregroundStyle(.secondary)
                    LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 16), count: 4), spacing: 16) {
                        swatch(nil, Theme.card)
                        ForEach(QXPolicyPrefs.palette, id: \.0) { item in swatch(item.0, item.1) }
                    }
                }
                .padding(20)
            }
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("背景").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("完成") { dismiss() } }
            }
            .onAppear { current = QXPolicyPrefs.backgroundKey(group) }
        }
        .presentationDetents([.medium])
    }

    func swatch(_ key: String?, _ color: Color) -> some View {
        Button {
            current = key
            QXPolicyPrefs.setBackground(group, key)
            onDone()
        } label: {
            ZStack {
                RoundedRectangle(cornerRadius: 16, style: .continuous).fill(key == nil ? color : color.opacity(0.22))
                    .frame(height: 64)
                    .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).stroke(current == key ? QXColor.switchOn : Color.primary.opacity(0.1), lineWidth: current == key ? 3 : 1))
                if key == nil { Text("默认").font(.caption).foregroundStyle(.secondary) }
                else { Circle().fill(color).frame(width: 18, height: 18) }
            }
        }
        .buttonStyle(.plain)
        .accessibilityLabel(key == nil ? Text("默认") : Text(verbatim: key ?? ""))
    }
}
