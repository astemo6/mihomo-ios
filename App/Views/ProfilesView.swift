import SwiftUI
import UniformTypeIdentifiers
import Libmihomo

struct ProfilesView: View {
    @EnvironmentObject var store: ProfileStore
    @State private var showAddRemote = false
    @State private var showNewLocal = false
    @State private var message: String?
    @State private var busy = false
    @State private var editing: Profile?
    @State private var showManual = false
    @State private var subRulesFor: Profile?
    @State private var showSubs = false
    @State private var showSample = false

    var body: some View {
        NavigationStack {
            List {
                if store.profiles.isEmpty {
                    Section {
                        EmptyStateRow(icon: "doc.badge.plus", title: "还没有配置",
                                      message: "点右上角 + 添加订阅链接，或从文件 / 剪贴板导入 mihomo（Clash Meta）YAML 配置。也支持 ss/vmess/vless/trojan/hysteria2/tuic 分享链接列表。") {
                            Button { showSample = true } label: { Label("看看示例配置", systemImage: "text.book.closed") }
                                .font(.footnote.weight(.semibold)).buttonStyle(.borderless)
                                .accessibilityIdentifier("profiles.empty.sample")
                        }
                    }
                    .listRowBackground(Theme.card)
                }
                Section {
                    NavigationLink { ManualNodesView() } label: {
                        Label("手动节点（粘贴链接 / 扫码 / 手动填写）", systemImage: "plus.viewfinder")
                    }
                    NavigationLink { SampleProfileView() } label: {
                        Label("示例配置", systemImage: "text.book.closed")
                    }
                    .accessibilityIdentifier("profiles.sample")
                }
                .listRowBackground(Theme.card)
                Section {
                    ForEach(store.profiles) { p in
                        ProfileRow(profile: p, active: p.id == store.activeID,
                                   updating: store.updating.contains(p.id) || p.sourceID.map { store.updating.contains($0) } == true,
                                   source: p.sourceID == nil ? nil : (store.source(of: p)?.displayName ?? p.sourceName ?? ""),
                                   sourceIsRemote: store.source(of: p)?.kind == .remote)
                            .contentShape(Rectangle())
                            .onTapGesture { select(p) }
                            .swipeActions(edge: .trailing) {
                                Button(role: .destructive) { store.delete(p) } label: { Label("删除", systemImage: "trash") }
                                Button { editing = p } label: { Label(LocalizedStringKey(p.kind == .remote ? "查看" : "编辑"), systemImage: p.kind == .remote ? "doc.text" : "pencil") }.tint(.indigo)
                                if p.id != ProfileStore.manualID {
                                    Button { subRulesFor = p } label: { Label("节点处理", systemImage: "line.3.horizontal.decrease.circle") }.tint(.teal)
                                }
                            }
                            .swipeActions(edge: .leading) {
                                if p.kind == .remote || store.source(of: p)?.kind == .remote {
                                    Button { refresh(p) } label: { Label("更新", systemImage: "arrow.clockwise") }.tint(.blue)
                                }
                            }
                            .contextMenu {
                                Button { select(p) } label: { Label("设为当前配置", systemImage: "checkmark.circle") }
                                if p.kind == .remote {
                                    Button { refresh(p) } label: { Label("更新订阅", systemImage: "arrow.clockwise") }
                                    Button { UIPasteboard.general.string = p.url } label: { Label("复制订阅链接", systemImage: "doc.on.doc") }
                                }
                                if p.id != ProfileStore.manualID {
                                    Button { subRulesFor = p } label: { Label("节点处理（过滤 / 重命名 / 排序）", systemImage: "line.3.horizontal.decrease.circle") }
                                }
                                Button { editing = p } label: { Label(LocalizedStringKey(p.kind == .remote ? "查看 YAML" : "编辑 YAML"), systemImage: p.kind == .remote ? "doc.text" : "pencil") }
                                Button(role: .destructive) { store.delete(p) } label: { Label("删除", systemImage: "trash") }
                            }
                            .listRowBackground(Theme.card)
                    }
                } footer: {
                    if !store.profiles.isEmpty { Text("轻点切换当前配置；左滑编辑、节点处理或删除，右滑更新订阅。") }
                }
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("配置")
            .toolbar {
                ToolbarItemGroup(placement: .navigationBarLeading) {
                    Button { updateAll() } label: { Label("全部更新", systemImage: "arrow.triangle.2.circlepath") }
                        .disabled(busy || !store.profiles.contains { $0.kind == .remote })
                    Button { showSubs = true } label: { Label("订阅管理", systemImage: "tray.full") }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Menu {
                        Button { showAddRemote = true } label: { Label("添加订阅链接", systemImage: "link.badge.plus") }
                        Button { importClipboard() } label: { Label("从剪贴板导入", systemImage: "doc.on.clipboard") }
                        Button { ImportRouter.shared.pickFile() } label: { Label("从文件导入（YAML / Surge·QX .conf）", systemImage: "folder") }
                        Button { importConfFromClipboard() } label: { Label("粘贴 Surge / QX 配置（.conf）", systemImage: "arrow.triangle.2.circlepath.doc.on.clipboard") }
                        Button { showNewLocal = true } label: { Label("新建本地配置", systemImage: "square.and.pencil") }
                        Button { showSample = true } label: { Label("示例配置", systemImage: "text.book.closed") }
                        Button { showManual = true } label: { Label("添加单个节点", systemImage: "plus.viewfinder") }
                    } label: { Image(systemName: "plus.circle.fill").font(.title3) }
                }
            }
            .navigationDestination(isPresented: $showManual) { ManualNodesView() }
            .navigationDestination(isPresented: $showSample) { SampleProfileView() }
            .navigationDestination(isPresented: $showSubs) { SubscriptionsView() }
            .overlay { if busy { ProgressView().padding(20).background(RoundedRectangle(cornerRadius: 12).fill(Theme.cardHi)) } }
            .sheet(isPresented: $showAddRemote) { AddRemoteSheet { msg in message = msg } }
            .sheet(isPresented: $showNewLocal) {
                YAMLEditorView(title: "新建本地配置", initialName: "本地配置", initialText: YAMLEditorView.template, profile: nil)
            }
            .sheet(item: $subRulesFor) { p in
                NavigationStack {
                    SubscriptionRulesView(profile: p)
                        .toolbar { ToolbarItem(placement: .cancellationAction) { Button("取消") { subRulesFor = nil } } }
                }
                .environmentObject(store)
            }
            .sheet(item: $editing) { p in
                YAMLEditorView(title: p.kind == .remote ? "查看配置" : "编辑配置", initialName: p.name, initialText: store.content(of: p), profile: p)
            }
            .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
                Button("好", role: .cancel) {}
            } message: { Text(message ?? "") }
        }
    }

    func select(_ p: Profile) {
        Task {
            if let err = await store.setActive(p) { message = "已切换，但重载失败：\(err)" }
        }
    }

    func refresh(_ p: Profile) {
        Task { if let e = await store.refresh(p) { message = e } }
    }

    func updateAll() {
        busy = true
        Task {
            let errs = await store.refreshAll()
            busy = false
            message = errs.isEmpty ? "全部订阅已更新" : errs.joined(separator: "\n")
        }
    }

    func importConfFromClipboard() {
        guard let s = UIPasteboard.general.string, !s.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            message = "剪贴板为空"; return
        }
        ImportRouter.shared.present(.confText(name: String(localized: "导入的配置"), text: s))
    }

    static func looksLikeConf(_ s: String) -> Bool {
        let l = s.lowercased()
        return (l.contains("[proxy]") && l.contains("[rule]")) || l.contains("[server_local]") || l.contains("[server_remote]") || l.contains("[policy]") || l.contains("[filter_local]") || l.contains("[filter_remote]")
    }

    func importClipboard() {
        guard let s = UIPasteboard.general.string?.trimmingCharacters(in: .whitespacesAndNewlines), !s.isEmpty else {
            message = "剪贴板为空"; return
        }
        // Links of our own scheme or of other clients (loon:// stash:// surge:/// quantumult-x:///).
        if !s.contains("\n"), let a = ImportRouter.parse(s) {
            ImportRouter.shared.run(a)
            return
        }
        if Self.looksLikeConf(s) {
            ImportRouter.shared.present(.confText(name: String(localized: "导入的配置"), text: s))
            return
        }
        busy = true
        Task {
            defer { busy = false }
            do {
                if (s.hasPrefix("http://") || s.hasPrefix("https://")) && !s.contains("\n") && !s.contains("@") {
                    _ = try await store.addRemote(url: s, name: "", userAgent: "clash.meta", intervalHours: 24)
                    message = "已添加订阅"
                } else if s.contains("proxies:") || s.contains("proxy-providers:") {
                    _ = try await store.addLocal(name: "剪贴板导入", text: s)
                    message = "已导入配置"
                } else {
                    let n = try await store.addManualNodes(text: s)
                    message = "已添加 \(n) 个节点到「手动节点」"
                }
            } catch { message = error.localizedDescription }
        }
    }

}

struct ProfileRow: View {
    let profile: Profile
    let active: Bool
    let updating: Bool
    /// feat/group-order: on an 自定义 copy, the name of the profile it was copied from.
    var source: String? = nil
    var sourceIsRemote = false

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: active ? "checkmark.circle.fill" : "circle")
                .font(.title3)
                .foregroundStyle(active ? Theme.good : .secondary)
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text(verbatim: profile.displayName).font(.headline).lineLimit(1)
                    Text(profile.kind == .remote ? "订阅" : "本地")
                        .font(.caption2.weight(.semibold))
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Capsule().fill((profile.kind == .remote ? Theme.accent : Color.orange).opacity(0.2)))
                    Spacer()
                    if updating { ProgressView().controlSize(.small) }
                }
                if let source {
                    Label {
                        if sourceIsRemote { Text("复制自「\(source)」· 随订阅更新") } else { Text("复制自「\(source)」") }
                    } icon: { Image(systemName: "doc.on.doc") }
                        .font(.caption2).foregroundStyle(.secondary)
                        .accessibilityIdentifier("profiles.source." + profile.id)
                }
                if let info = profile.userInfo {
                    if info.total > 0 {
                        ProgressView(value: info.fraction)
                            .tint(info.fraction > 0.9 ? Theme.bad : Theme.accent)
                        Text("已用 \(Fmt.bytes(info.used)) / \(Fmt.bytes(info.total))  ·  剩余 \(Fmt.bytes(max(info.total - info.used, 0)))")
                            .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                    }
                    if let exp = info.expireDate {
                        let days = Int(ceil(exp.timeIntervalSinceNow / 86400))
                        Group {
                            if exp < Date() {
                                Text("到期 \(exp.formatted(date: .abbreviated, time: .omitted))（已过期）")
                            } else {
                                Text("到期 \(exp.formatted(date: .abbreviated, time: .omitted))  ·  还有 \(days) 天")
                            }
                        }
                        .font(.caption2).foregroundStyle(exp < Date() || days <= 3 ? Theme.bad : (days <= 7 ? Theme.warn : .secondary))
                    }
                }
                if let r = SubRulesStore.get(profile.id), r.enabled, !r.isEmpty {
                    Label(r.summary, systemImage: "line.3.horizontal.decrease.circle")
                        .font(.caption2).foregroundStyle(Theme.accent)
                }
                if let d = profile.lastUpdated {
                    Text("更新于 \(d.formatted(.relative(presentation: .named)))")
                        .font(.caption2).foregroundStyle(.secondary)
                }
            }
        }
        .padding(.vertical, 4)
    }
}

struct AddRemoteSheet: View {
    @EnvironmentObject var store: ProfileStore
    @Environment(\.dismiss) var dismiss
    var onDone: (String) -> Void
    @State private var url = ""
    @State private var name = ""
    @State private var ua = "clash.meta"
    @State private var interval = 24
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("订阅") {
                    TextField("订阅链接 https://…", text: $url)
                        .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                    TextField("名称（留空自动获取）", text: $name)
                }
                Section("选项") {
                    Picker("User-Agent", selection: $ua) {
                        Text("clash.meta").tag("clash.meta")
                        Text("mihomo").tag("mihomo")
                        Text("clash-verge/v2").tag("clash-verge/v2")
                    }
                    Picker("自动更新", selection: $interval) {
                        Text("关闭").tag(0)
                        Text("每 6 小时").tag(6)
                        Text("每 12 小时").tag(12)
                        Text("每天").tag(24)
                        Text("每周").tag(168)
                    }
                }
                if let error { Section { Text(error).foregroundStyle(Theme.bad).font(.footnote) } }
            }
            .navigationTitle("添加订阅")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    if busy { ProgressView() } else {
                        Button("添加") { add() }.disabled(url.isEmpty)
                    }
                }
            }
            .onAppear {
                if url.isEmpty, let s = UIPasteboard.general.string, s.hasPrefix("http") { url = s }
            }
        }
    }

    func add() {
        busy = true; error = nil
        Task {
            defer { busy = false }
            do {
                let p = try await store.addRemote(url: url, name: name, userAgent: ua, intervalHours: interval)
                onDone(String(localized: "已添加「\(p.name)」"))
                dismiss()
            } catch { self.error = error.localizedDescription }
        }
    }
}

/// Profile editor: YAML with highlighting and live validation through the core parser (line / column of
/// the error). Local profiles save and reload; remote ones open read-only with 复制为本地配置.
struct YAMLEditorView: View {
    @EnvironmentObject var store: ProfileStore
    @Environment(\.dismiss) var dismiss
    let title: String
    @State var name: String
    @State var text: String
    let profile: Profile?
    @State private var error: String?
    @State private var busy = false
    @State private var check: ProfileCheckResult?
    @State private var checking = false
    @State private var checkTask: Task<Void, Never>?
    @State private var scrollToken = 0

    struct ProfileCheckResult: Decodable, Equatable {
        var ok: Bool
        var error: String?
        var line: Int?
        var column: Int?
        var nodes: Int
        var groups: Int
        var rules: Int
        var providers: Int
    }

    init(title: String, initialName: String, initialText: String, profile: Profile?) {
        self.title = title
        _name = State(initialValue: initialName)
        _text = State(initialValue: initialText)
        self.profile = profile
    }

    var readOnly: Bool { profile?.kind == .remote }

    static let template = """
    # mihomo 配置示例（请替换为你自己的节点）
    mode: rule
    proxies: []
    proxy-groups:
      - name: 节点选择
        type: select
        proxies: [DIRECT]
    rules:
      - MATCH,节点选择
    """

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if readOnly {
                    HStack(spacing: 8) {
                        Image(systemName: "lock.fill")
                        Text("订阅配置只读：更新订阅时会被覆盖。需要修改请复制为本地配置。")
                    }
                    .font(.caption).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
                    .background(Theme.cardHi)
                } else {
                    TextField("名称", text: $name)
                        .padding(12)
                        .background(Theme.cardHi)
                }
                if let error {
                    Text(error).font(.caption).foregroundStyle(Theme.bad).padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                CodeEditor(text: $text, language: .yaml, editable: !readOnly,
                           errorLine: check?.ok == false ? check?.line : nil, scrollToken: scrollToken)
                statusBar
            }
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(readOnly ? "关闭" : "取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    if busy { ProgressView() }
                    else if readOnly { Button("复制为本地配置") { copyAsLocal() } }
                    else { Button(profile == nil ? "校验并保存" : "保存并重载") { save() }.disabled(check?.ok == false) }
                }
            }
            .onAppear { scheduleCheck(delay: 0) }
            .onChange(of: text) { _ in scheduleCheck(delay: 700_000_000) }
            .onDisappear { checkTask?.cancel() }
        }
    }

    var statusBar: some View {
        HStack(spacing: 8) {
            if checking {
                ProgressView().controlSize(.mini)
                Text("校验中…").font(.caption2).foregroundStyle(.secondary)
            } else if let c = check {
                if c.ok {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(Theme.good)
                    Text("\(c.nodes) 个节点 · \(c.groups) 个策略组 · \(c.rules) 条规则 · \(c.providers) 个节点集")
                        .font(.caption2.monospacedDigit()).foregroundStyle(.secondary).lineLimit(1)
                } else {
                    Image(systemName: "xmark.octagon.fill").foregroundStyle(Theme.bad)
                    Text(c.error ?? "").font(.caption2).foregroundStyle(Theme.bad).lineLimit(3)
                }
            }
            Spacer(minLength: 4)
            if let c = check, !c.ok, let l = c.line, l > 0 {
                Button { scrollToken += 1 } label: {
                    lineLabel(l, c.column ?? 0)
                        .font(.caption2.weight(.semibold))
                        .padding(.horizontal, 8).padding(.vertical, 4)
                        .background(Capsule().fill(Theme.bad.opacity(0.18)))
                        .foregroundStyle(Theme.bad)
                }
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .frame(minHeight: 36)
        .background(Theme.card)
    }

    func lineLabel(_ l: Int, _ col: Int) -> Text {
        col > 0 ? Text("第 \(l) 行 \(col) 列") : Text("第 \(l) 行")
    }

    func scheduleCheck(delay: UInt64) {
        checkTask?.cancel()
        let t = text
        let path = profile?.fileURL.path ?? AppShared.homeURL.appendingPathComponent("new-profile.yaml").path
        let home = AppShared.homeURL.path
        checkTask = Task {
            if delay > 0 { try? await Task.sleep(nanoseconds: delay) }
            guard !Task.isCancelled else { return }
            checking = true
            let json = await Task.detached(priority: .userInitiated) { LibmihomoProfileCheck(home, path, t) }.value
            guard !Task.isCancelled else { return }
            checking = false
            if let d = json.data(using: .utf8), let r = try? JSONDecoder().decode(ProfileCheckResult.self, from: d) {
                let jump = check?.line != r.line && r.ok == false
                check = r
                if jump && delay == 0 { scrollToken += 1 }
            }
        }
    }

    func save() {
        busy = true; error = nil
        Task {
            defer { busy = false }
            do {
                if let p = profile {
                    try await store.saveLocalEdit(p, text: text)
                    if name != p.name { store.rename(p, to: name) }
                } else {
                    _ = try await store.addLocal(name: name, text: text)
                }
                dismiss()
            } catch { self.error = error.localizedDescription }
        }
    }

    func copyAsLocal() {
        busy = true; error = nil
        let base = profile?.name ?? name
        Task {
            defer { busy = false }
            do {
                _ = try await store.addLocal(name: String(localized: "\(base) 副本"), text: text)
                dismiss()
            } catch { self.error = error.localizedDescription }
        }
    }
}
