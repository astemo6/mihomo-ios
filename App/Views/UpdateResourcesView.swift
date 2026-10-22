import SwiftUI

// 更多 → 更新资源: node-related remote resources only — 配置订阅 and 节点订阅 (incl. the profile's own node sets) —
// each with its link, last update, failure and its own 更新, plus 「更新全部」 in the toolbar.
// User 2026-10-23: 「如果这里只是用来更新的，那还有必要搞这个吗？分配在不同的模块订阅，规则订阅里就行了。这里只放节点管理相关的」
// — modules (and the scripts / rule sets they reference) update in 工具 → 模块, rule sets in 规则 → 订阅.

struct UpdateResourcesView: View {
    @ObservedObject private var profiles = ProfileStore.shared
    @ObservedObject private var subs = NodeSubStore.shared
    // User 2026-10-22 「不要特别体现配置自带…直接展开」: the profile's own node sets sit in the same 节点订阅
    // section as the ones the user added, with no "from the profile" label.
    @ObservedObject private var offline = ProfileInspector.shared
    @ObservedObject private var providers = ProviderUpdater.shared
    @ObservedObject private var vpn = VPNManager.shared
    /// Profile update errors of this visit (profiles.json keeps no last error).
    @State private var profileErrors: [String: String] = [:]
    @State private var updatingAll = false
    @State private var message: String?

    var remoteProfiles: [Profile] { profiles.profiles.filter { $0.kind == .remote } }

    /// The active profile's downloadable node sets, minus the ones generated from the user's node subscriptions.
    var profileNodeSets: [InspectProvider] {
        let mine = Set(subs.subs.map(\.name))
        return offline.result.proxyProviders.filter { $0.vehicle == "http" && !mine.contains($0.name) }
    }

    @ViewBuilder
    func providerRow(_ p: InspectProvider, symbol: String, tone: TileTone) -> some View {
        ResourceUpdateRow(kind: p.kind == "proxy" ? "nodesub" : "ruleset", name: p.name, url: p.url ?? "", symbol: symbol, tone: tone,
                          updated: p.cachedDate, error: providers.errors[p.id],
                          busy: providers.busy.contains(p.id)) {
            Task { await updateProvider(p) }
        }
    }

    /// Connected: the core downloads and swaps it in place. Disconnected: the app downloads it (ProviderUpdater
    /// reloads the tunnel itself when it is up).
    func updateProvider(_ p: InspectProvider) async {
        if !(await coreUpdate(p)) { await providers.update(p.id) }
        await offline.load()
    }

    /// Connected: asks the core to refresh the set in place (no reload). False when disconnected or the core failed.
    func coreUpdate(_ p: InspectProvider) async -> Bool {
        guard vpn.isConnected else { return false }
        do {
            if p.kind == "proxy" { try await ControllerClient.shared.updateProxyProvider(p.name) }
            else { try await ControllerClient.shared.updateRuleProvider(p.name) }
            return true
        } catch {
            return false
        }
    }

    var body: some View {
        List {
            if remoteProfiles.isEmpty && subs.subs.isEmpty && profileNodeSets.isEmpty {
                Section {
                    EmptyStateRow(icon: "arrow.triangle.2.circlepath", title: "没有远程资源",
                                  message: "添加的配置订阅和节点订阅会列在这里，可以逐个或一次全部更新。")
                }
                .listRowBackground(Theme.card)
            }
            if !remoteProfiles.isEmpty {
                Section {
                    ForEach(remoteProfiles) { p in
                        ResourceUpdateRow(kind: "profile", name: p.displayName, url: p.url ?? "", symbol: "doc.text.fill", tone: .blue,
                                          updated: p.lastUpdated, error: profileErrors[p.id], disabled: !p.enabled,
                                          busy: profiles.updating.contains(p.id)) {
                            Task {
                                let e = await profiles.refresh(p)
                                profileErrors[p.id] = e
                            }
                        }
                        .enableActions(enabled: p.enabled, id: "profile.\(p.displayName)") { on in
                            if let e = profiles.setEnabled(p, on) { message = e }
                        }
                    }
                } header: { Text("配置订阅 \(remoteProfiles.count)") }
                .listRowBackground(Theme.card)
            }
            if !subs.subs.isEmpty || !profileNodeSets.isEmpty {
                Section {
                    ForEach(subs.subs) { s in
                        ResourceUpdateRow(kind: "nodesub", name: s.name, url: s.url, symbol: "tray.2.fill", tone: .teal,
                                          updated: s.lastUpdated, error: s.lastError, disabled: !s.enabled,
                                          busy: subs.updating.contains(s.id)) {
                            Task { _ = await subs.refresh(s) }
                        }
                        .enableActions(enabled: s.enabled, id: "nodesub.\(s.name)") { on in
                            var c = s
                            c.enabled = on
                            Task { await subs.save(c) }
                        }
                    }
                    ForEach(profileNodeSets) { p in providerRow(p, symbol: "tray.2.fill", tone: .teal) }
                } header: { Text("节点订阅 \(subs.subs.count + profileNodeSets.count)") }
                .listRowBackground(Theme.card)
            }
            Section {} footer: {
                Text("向右轻扫或按住某一项可以启用 / 停用。有更新时自动下载并应用到当前配置。模块在 工具 → 模块 里更新，规则集在 规则 → 订阅 里更新。")
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("更新资源")
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                if updatingAll { ProgressView() } else {
                    Button("更新全部") { Task { await updateAll() } }
                        .accessibilityIdentifier("res.updateAll")
                }
            }
        }
        .task { await offline.load() }
        .alert("更新资源", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
    }

    /// Profiles, then node subscriptions, then the profile's own node sets.
    func updateAll() async {
        updatingAll = true
        defer { updatingAll = false }
        var failed = 0
        for p in remoteProfiles where p.enabled {
            let e = await profiles.refresh(p)
            profileErrors[p.id] = e
            if e != nil { failed += 1 }
        }
        failed += await subs.refreshAll().count
        let sets = profileNodeSets
        // Review 0.19.18 S1: sets the core could not refresh are downloaded by the app in ONE batch, so the
        // tunnel reloads at most once (not once per failed set).
        var fallback: [String] = []
        for p in sets where !(await coreUpdate(p)) { fallback.append(p.id) }
        if !fallback.isEmpty {
            failed += await providers.updateAll(only: Set(fallback)).failed
        }
        if !sets.isEmpty { await offline.load() }
        message = failed == 0 ? String(localized: "已全部更新") : String(localized: "\(failed) 项更新失败，详见列表")
    }
}

private extension View {
    /// User 2026-10-22: 「点进去没有启用的选项，禁用的启用不了，启用的无法禁用」 — each row can be turned on / off right
    /// here: swipe right, or touch and hold.
    func enableActions(enabled: Bool, id: String, set: @escaping (Bool) -> Void) -> some View {
        self
            .swipeActions(edge: .leading, allowsFullSwipe: true) {
                Button { set(!enabled) } label: {
                    Label(LocalizedStringKey(enabled ? "停用" : "启用"), systemImage: enabled ? "pause.circle" : "play.circle")
                }
                .tint(enabled ? Color.gray : Theme.good)
                .accessibilityIdentifier("res.toggle.\(id)")
            }
            .contextMenu {
                Button { set(!enabled) } label: {
                    Label(LocalizedStringKey(enabled ? "停用" : "启用"), systemImage: enabled ? "pause.circle" : "play.circle")
                }
            }
    }
}

struct ResourceUpdateRow: View {
    let kind: String
    let name: String
    let url: String
    let symbol: String
    var tone: TileTone = .accent
    var updated: Date?
    var error: String?
    var disabled = false
    /// User 2026-10-22: a remote script's source — the rewrite subscription(s) / modules that reference it, or 脚本
    /// for the user's own script lines.
    var owner: String? = nil
    var busy = false
    let update: () -> Void
    /// User 2026-10-22: 「默认折叠，展开后才显示」 — the source line stays hidden until the row is tapped.
    @State private var expanded = false

    /// 「https://sub.example.com/api/v1/client/subscribe?token=abc」 → 「sub.example.com/…」; a link without a host
    /// (local file, malformed) shows only its last path component.
    static func displayURL(_ s: String) -> String {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let u = URLComponents(string: t), let host = u.host, !host.isEmpty else {
            return (t as NSString).lastPathComponent
        }
        let port = u.port.map { ":\($0)" } ?? ""
        let rest = (u.path.isEmpty || u.path == "/") && (u.query ?? "").isEmpty && (u.fragment ?? "").isEmpty ? "" : "/…"
        return host + port + rest
    }

    static let relative: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .short
        return f
    }()

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            IconTile(symbol: symbol, tone: tone, dimmed: disabled)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 4) {
                    Text(verbatim: name).foregroundStyle(disabled ? Color.secondary : Color.primary).lineLimit(1)
                    if let owner, !owner.isEmpty {
                        Image(systemName: expanded ? "chevron.up" : "chevron.down")
                            .font(.caption2.weight(.semibold)).foregroundStyle(.tertiary)
                    }
                }
                // r7 P3-6: host only — subscription links usually carry a token (?token=…, /api/v1/client/<token>)
                // that a screenshot or screen recording would leak.
                Text(verbatim: Self.displayURL(url)).font(.caption2.monospaced()).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                if expanded, let owner, !owner.isEmpty {
                    Text("来自 \(owner)").font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                HStack(spacing: 6) {
                    if disabled {
                        Text("已停用")
                    } else if let updated {
                        Text("更新于 \(Self.relative.localizedString(for: updated, relativeTo: Date()))")
                    } else {
                        Text("从未更新")
                    }
                }
                .font(.caption).foregroundStyle(.secondary)
                if let error, !error.isEmpty {
                    Label { Text(verbatim: error).lineLimit(2) } icon: { Image(systemName: "exclamationmark.triangle.fill") }
                        .font(.caption).foregroundStyle(Theme.bad)
                }
            }
            .contentShape(Rectangle())
            .onTapGesture {
                guard let owner, !owner.isEmpty else { return }
                withAnimation(.easeInOut(duration: 0.15)) { expanded.toggle() }
            }
            Spacer(minLength: 6)
            if busy {
                ProgressView().frame(width: 30, height: 30)
            } else {
                Button(action: update) {
                    Image(systemName: "arrow.clockwise").font(.body.weight(.semibold)).frame(width: 30, height: 30)
                }
                .buttonStyle(.borderless)
                .disabled(disabled)
                .accessibilityLabel(Text("更新"))
                .accessibilityIdentifier("res.update.\(kind).\(name)")
            }
        }
        .padding(.vertical, 2)
    }
}
