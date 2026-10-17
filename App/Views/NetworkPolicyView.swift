import SwiftUI
import Network

/// 更多 → 连接方式 → 按网络切换策略 (v0.9). One row per select group: a member for Wi-Fi, one for cellular
/// and one per named Wi-Fi network. The extension switches the group when the network changes; with no
/// matching rule the group keeps its member.
struct NetworkPolicyView: View {
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var insp = ProfileInspector.shared
    @ObservedObject private var wifi = WiFiInfo.shared
    @StateObject private var path = PathTypeWatcher()
    @State private var rules: [NetworkPolicyRule] = []
    @State private var state: NetworkPolicyState?
    @State private var showLocationInfo = false
    @State private var trigger = ModeTrigger.load()

    private var selectGroups: [InspectGroup] {
        insp.result.groups.filter { $0.type == "select" && $0.hidden != true }
    }

    var body: some View {
        Form {
            networkSection
            modeSection
            rulesSection
            if let state, vpn.isConnected, !state.applied.isEmpty || state.mode != nil { lastSection(state) }
        }
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("按网络切换策略")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            rules = NetworkPolicyStore.rules()
            trigger = ModeTrigger.load()
            state = NetworkPolicyStore.state()
            if insp.result.groups.isEmpty { await insp.load() }
            await wifi.refresh()
        }
        .onChange(of: path.type) { _ in Task { await wifi.refresh() } }
        .alert("读取 Wi-Fi 名称", isPresented: $showLocationInfo) {
            Button("继续") { wifi.requestLocation() }
            Button("取消", role: .cancel) {}
        } message: {
            Text("iOS 只在 App 获得「使用 App 期间」的精确位置权限时才提供当前 Wi-Fi 的名称。Mihomo 只用它读取 Wi-Fi 名称，不读取、不保存你的位置。不授权也可以手动输入名称。")
        }
    }

    // MARK: Sections

    var networkSection: some View {
        Section {
            HStack {
                Label("当前网络", systemImage: path.icon)
                Spacer()
                Text(LocalizedStringKey(path.title)).foregroundStyle(.secondary)
            }
            if path.type == "wifi" {
                HStack {
                    Text("Wi-Fi 名称")
                    Spacer()
                    if let s = wifi.ssid {
                        Text(verbatim: s).foregroundStyle(.secondary).textSelection(.enabled)
                    } else {
                        Text(wifi.checked ? "无法读取" : "读取中…").foregroundStyle(.secondary)
                    }
                }
                if wifi.checked && wifi.ssid == nil {
                    if wifi.locationDenied {
                        Text("位置权限已关闭，无法读取 Wi-Fi 名称。可在 设置 → Mihomo → 位置 中选择「使用 App 期间」并打开「精确位置」，或手动输入名称。")
                            .font(.caption).foregroundStyle(Theme.warn)
                    } else {
                        Button { showLocationInfo = true } label: { Label("允许读取 Wi-Fi 名称", systemImage: "location") }
                    }
                }
            }
        } header: { Text("网络") } footer: {
            Text("连接后，网络扩展在每次网络变化时读取网络类型和 Wi-Fi 名称（读不到名称时只按 Wi-Fi / 蜂窝匹配）。")
        }
        .listRowBackground(Theme.card)
    }

    /// v0.12: QX running_mode_trigger.
    var modeSection: some View {
        Section {
            NavigationLink {
                ModeTriggerEditor(trigger: trigger, currentSSID: wifi.ssid) { t in
                    trigger = t
                    t.save()
                    persist()
                }
            } label: {
                HStack {
                    Label("运行模式", systemImage: "arrow.triangle.branch")
                    Spacer()
                    if trigger.enabled && !trigger.summary.isEmpty {
                        Text(verbatim: trigger.summary).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    } else {
                        Text("关闭").foregroundStyle(.secondary)
                    }
                }
            }
        } header: { Text("按网络切换运行模式") } footer: {
            Text("在不同网络下自动使用 规则 / 全局 / 直连 模式（与 Quantumult X 的 running_mode_trigger 相同）。手动切换的模式会保持到下一次网络变化。")
        }
        .listRowBackground(Theme.card)
    }

    var rulesSection: some View {
        Section {
            if insp.result.groups.isEmpty && !insp.loading {
                EmptyStateRow(icon: "square.stack.3d.up", title: "没有可用的策略组", message: "先在「配置」中选择一个配置。")
            }
            ForEach(rules) { r in
                NavigationLink {
                    NetworkPolicyRuleEditor(rule: r, members: members(r.group), currentSSID: wifi.ssid) { updated in
                        replace(r.group, with: updated)
                    }
                } label: { ruleRow(r) }
            }
            .onDelete { idx in
                rules.remove(atOffsets: idx)
                persist()
            }
            let unused = selectGroups.filter { g in !rules.contains { $0.group == g.name } }
            if !unused.isEmpty {
                Menu {
                    ForEach(unused) { g in
                        Button(g.name) { rules.append(NetworkPolicyRule(group: g.name)) }
                    }
                } label: { Label("添加策略组", systemImage: "plus.circle") }
            }
        } header: { Text("规则") } footer: {
            Text("只对 select（手动选择）类型的策略组生效。指定 Wi-Fi 优先于「Wi-Fi」；当前网络没有匹配的项时，策略组保持原来的选择。切换不会改动你手动保存的选择，下次连接时先恢复手动选择，再按网络切换。")
        }
        .listRowBackground(Theme.card)
    }

    func lastSection(_ s: NetworkPolicyState) -> some View {
        Section {
            if let m = s.mode {
                HStack {
                    Text("运行模式").font(.subheadline)
                    Spacer()
                    Text(verbatim: "➤ " + NSLocalizedString(ModeTrigger.title(m), comment: "")).font(.caption)
                    Text(LocalizedStringKey(Self.reasonText(s.modeReason ?? ""))).font(.caption).foregroundStyle(.secondary)
                }
            }
            ForEach(s.applied, id: \.self) { a in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(a.group).font(.subheadline)
                        Text(verbatim: "➤ \(a.node)").font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                    Spacer()
                    if let e = a.error {
                        Text(LocalizedStringKey(Self.errorText(e))).font(.caption).foregroundStyle(Theme.bad)
                    } else {
                        Text(LocalizedStringKey(Self.reasonText(a.reason))).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
        } header: { Text("最近一次切换") } footer: {
            Text(Date(timeIntervalSince1970: s.at), style: .relative) + Text(verbatim: " · ") + Text(LocalizedStringKey(PathTypeWatcher.title(for: s.type)))
        }
        .listRowBackground(Theme.card)
    }

    func ruleRow(_ r: NetworkPolicyRule) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(r.group).font(.subheadline.weight(.semibold))
            HStack(spacing: 10) {
                if let w = r.wifi, !w.isEmpty { chip("wifi", w) }
                if let c = r.cellular, !c.isEmpty { chip("antenna.radiowaves.left.and.right", c) }
                if let n = r.ssids?.count, n > 0 { Text("\(n) 个指定 Wi-Fi").font(.caption).foregroundStyle(.secondary) }
                if r.isEmpty { Text("未设置").font(.caption).foregroundStyle(Theme.warn) }
            }
        }
        .padding(.vertical, 2)
    }

    func chip(_ icon: String, _ text: String) -> some View {
        HStack(spacing: 3) {
            Image(systemName: icon).font(.caption2)
            Text(verbatim: text).font(.caption).lineLimit(1)
        }
        .foregroundStyle(.secondary)
    }

    static func reasonText(_ r: String) -> String {
        switch r {
        case "ssid": return "指定 Wi-Fi"
        case "cellular": return "蜂窝网络"
        default: return "Wi-Fi"
        }
    }

    static func errorText(_ e: String) -> String {
        switch e {
        case "group not found": return "找不到策略组"
        case "not a select group": return "不是手动选择组"
        default: return "切换失败"
        }
    }

    // MARK: Data

    func members(_ group: String) -> [String] {
        guard let g = insp.result.groups.first(where: { $0.name == group }) else { return [] }
        return insp.members(of: g)
    }

    func replace(_ group: String, with r: NetworkPolicyRule?) {
        if let i = rules.firstIndex(where: { $0.group == group }) {
            if let r { rules[i] = r } else { rules.remove(at: i) }
        }
        persist()
    }

    func persist() {
        NetworkPolicyStore.save(rules)
        Task {
            if vpn.isConnected {
                _ = await vpn.send(.applyNetworkPolicy, timeout: 4)
                try? await Task.sleep(nanoseconds: 300_000_000)
                state = NetworkPolicyStore.state()
            }
        }
    }
}

/// 运行模式按网络切换 (v0.12). v0.15.4: applied on change (debounced), no 保存 button.
struct ModeTriggerEditor: View {
    @State var trigger: ModeTrigger
    @StateObject private var debounce = Debouncer()
    let currentSSID: String?
    let onSave: (ModeTrigger) -> Void
    @State private var newSSID = ""
    @State private var newMode = "direct"

    var body: some View {
        Form {
            Section {
                Toggle("按网络切换运行模式", isOn: $trigger.enabled)
            }
            .listRowBackground(Theme.card)
            Section {
                modePicker("蜂窝网络", selection: Binding(get: { trigger.cellular ?? "" }, set: { trigger.cellular = $0.isEmpty ? nil : $0 }))
                modePicker("Wi-Fi", selection: Binding(get: { trigger.wifi ?? "" }, set: { trigger.wifi = $0.isEmpty ? nil : $0 }))
            } header: { Text("按网络类型") }
            .listRowBackground(Theme.card)
            .disabled(!trigger.enabled)
            Section {
                ForEach((trigger.ssids ?? [:]).keys.sorted(), id: \.self) { ssid in
                    HStack {
                        Image(systemName: "wifi").foregroundStyle(.secondary)
                        Text(verbatim: ssid).lineLimit(1)
                        Spacer()
                        Text(LocalizedStringKey(ModeTrigger.title(trigger.ssids?[ssid]))).foregroundStyle(.secondary)
                    }
                }
                .onDelete { idx in
                    let keys = (trigger.ssids ?? [:]).keys.sorted()
                    for i in idx { trigger.ssids?[keys[i]] = nil }
                    if trigger.ssids?.isEmpty == true { trigger.ssids = nil }
                }
                HStack {
                    TextField("Wi-Fi 名称（SSID）", text: $newSSID)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    if let s = currentSSID, newSSID != s {
                        Button("当前") { newSSID = s }.buttonStyle(.borderless).font(.caption)
                    }
                }
                Picker("使用", selection: $newMode) {
                    ForEach(ModeTrigger.modes, id: \.self) { Text(LocalizedStringKey(ModeTrigger.title($0))).tag($0) }
                }
                Button {
                    let s = newSSID.trimmingCharacters(in: .whitespaces)
                    guard !s.isEmpty else { return }
                    var m = trigger.ssids ?? [:]
                    m[s] = newMode
                    trigger.ssids = m
                    newSSID = ""
                } label: { Label("添加", systemImage: "plus") }
                .disabled(newSSID.trimmingCharacters(in: .whitespaces).isEmpty)
            } header: { Text("指定 Wi-Fi") } footer: {
                Text("按名称精确匹配（区分大小写），优先于上面的「Wi-Fi」。读取 Wi-Fi 名称需要重签描述文件包含 wifi-info 权限。")
            }
            .listRowBackground(Theme.card)
            .disabled(!trigger.enabled)
        }
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .onChange(of: trigger) { t in debounce.schedule { onSave(t) } }
        .onDisappear { debounce.flush() }
        .navigationTitle("运行模式")
        .navigationBarTitleDisplayMode(.inline)
    }

    func modePicker(_ title: String, selection: Binding<String>) -> some View {
        Picker(LocalizedStringKey(title), selection: selection) {
            Text("不切换").tag("")
            ForEach(ModeTrigger.modes, id: \.self) { Text(LocalizedStringKey(ModeTrigger.title($0))).tag($0) }
        }
    }
}

/// One group's network rule.
struct NetworkPolicyRuleEditor: View {
    @Environment(\.dismiss) private var dismiss
    @State var rule: NetworkPolicyRule
    let members: [String]
    let currentSSID: String?
    let onSave: (NetworkPolicyRule?) -> Void
    @State private var newSSID = ""
    @State private var newNode = ""

    var body: some View {
        Form {
            Section {
                memberPicker("Wi-Fi", selection: Binding(get: { rule.wifi ?? "" }, set: { rule.wifi = $0.isEmpty ? nil : $0 }))
                memberPicker("蜂窝网络", selection: Binding(get: { rule.cellular ?? "" }, set: { rule.cellular = $0.isEmpty ? nil : $0 }))
            } header: { Text("按网络类型") }
            .listRowBackground(Theme.card)

            Section {
                ForEach((rule.ssids ?? [:]).keys.sorted(), id: \.self) { ssid in
                    HStack {
                        Image(systemName: "wifi").foregroundStyle(.secondary)
                        Text(verbatim: ssid).lineLimit(1)
                        Spacer()
                        Text(verbatim: rule.ssids?[ssid] ?? "").foregroundStyle(.secondary).lineLimit(1)
                    }
                }
                .onDelete { idx in
                    let keys = (rule.ssids ?? [:]).keys.sorted()
                    for i in idx { rule.ssids?[keys[i]] = nil }
                    if rule.ssids?.isEmpty == true { rule.ssids = nil }
                }
                HStack {
                    TextField("Wi-Fi 名称（SSID）", text: $newSSID)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    if let s = currentSSID, newSSID != s {
                        Button("当前") { newSSID = s }.buttonStyle(.borderless).font(.caption)
                    }
                }
                memberPicker("使用", selection: $newNode, allowNone: false)
                Button {
                    let s = newSSID.trimmingCharacters(in: .whitespaces)
                    guard !s.isEmpty, !newNode.isEmpty else { return }
                    var m = rule.ssids ?? [:]
                    m[s] = newNode
                    rule.ssids = m
                    newSSID = ""
                } label: { Label("添加", systemImage: "plus") }
                .disabled(newSSID.trimmingCharacters(in: .whitespaces).isEmpty || newNode.isEmpty)
            } header: { Text("指定 Wi-Fi") } footer: {
                Text("按名称精确匹配（区分大小写），优先于上面的「Wi-Fi」。")
            }
            .listRowBackground(Theme.card)

            Section {
                Button("保存") { onSave(rule); dismiss() }
                Button("删除此规则", role: .destructive) { onSave(nil); dismiss() }
            }
            .listRowBackground(Theme.card)
        }
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle(rule.group)
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { if newNode.isEmpty { newNode = members.first ?? "" } }
    }

    @ViewBuilder func memberPicker(_ title: String, selection: Binding<String>, allowNone: Bool = true) -> some View {
        Picker(LocalizedStringKey(title), selection: selection) {
            if allowNone { Text("不切换").tag("") }
            ForEach(members, id: \.self) { Text(verbatim: $0).tag($0) }
            // A member that disappeared from the profile stays visible instead of silently resetting.
            if !selection.wrappedValue.isEmpty && !members.contains(selection.wrappedValue) {
                Text(verbatim: selection.wrappedValue).tag(selection.wrappedValue)
            }
        }
    }
}

/// Physical network type for the page header (the app's own view; the extension has its own watcher).
@MainActor
final class PathTypeWatcher: ObservableObject {
    @Published private(set) var type = "other"
    private let monitor = NWPathMonitor(prohibitedInterfaceTypes: [.other, .loopback])

    init() {
        monitor.pathUpdateHandler = { [weak self] p in
            let t: String
            if p.status != .satisfied { t = "none" }
            else if p.usesInterfaceType(.wifi) { t = "wifi" }
            else if p.usesInterfaceType(.cellular) { t = "cellular" }
            else if p.usesInterfaceType(.wiredEthernet) { t = "wired" }
            else { t = "other" }
            Task { @MainActor in self?.type = t }
        }
        monitor.start(queue: DispatchQueue(label: "mihomo.path-type"))
    }

    deinit { monitor.cancel() }

    var title: String { Self.title(for: type) }
    var icon: String {
        switch type {
        case "wifi": return "wifi"
        case "cellular": return "antenna.radiowaves.left.and.right"
        case "none": return "wifi.slash"
        default: return "network"
        }
    }

    nonisolated static func title(for t: String) -> String {
        switch t {
        case "wifi": return "Wi-Fi"
        case "cellular": return "蜂窝网络"
        case "wired": return "有线网络"
        case "none": return "无网络"
        default: return "其他"
        }
    }
}
