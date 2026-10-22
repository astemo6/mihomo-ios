import SwiftUI

// 更多 → 更新资源 (feat/more-dedup, user 2026-10-21 18:06, Egern-style): every remote resource in one list —
// 配置订阅, 节点订阅, 模块, 规则集, 远程脚本 — each with its link, last update, failure and its own 更新, plus
// 「更新全部」 in the toolbar. Each item still updates through its own store (ProfileStore / NodeSubStore /
// ResourceStore), so nothing is downloaded differently from the pages that own them.

struct UpdateResourcesView: View {
    @ObservedObject private var profiles = ProfileStore.shared
    @ObservedObject private var subs = NodeSubStore.shared
    @ObservedObject private var res = ResourceStore.shared
    /// Profile update errors of this visit (profiles.json keeps no last error).
    @State private var profileErrors: [String: String] = [:]
    @State private var updatingAll = false
    @State private var message: String?

    var remoteProfiles: [Profile] { profiles.profiles.filter { $0.kind == .remote } }
    func items(_ kind: String) -> [ResourceItem] { res.items.filter { $0.kind == kind && $0.isRemote } }

    var body: some View {
        List {
            if remoteProfiles.isEmpty && subs.subs.isEmpty && res.items.allSatisfy({ !$0.isRemote }) {
                Section {
                    EmptyStateRow(icon: "arrow.triangle.2.circlepath", title: "没有远程资源",
                                  message: "添加的订阅、远程模块、规则集和脚本会列在这里，可以逐个或一次全部更新。")
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
            if !subs.subs.isEmpty {
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
                } header: { Text("节点订阅 \(subs.subs.count)") }
                .listRowBackground(Theme.card)
            }
            resourceSection("module", symbol: "puzzlepiece.extension.fill", tone: .green) { Text("模块 \($0)") }
            resourceSection("ruleset", symbol: "list.bullet.rectangle.fill", tone: .orange) { Text("规则集 \($0)") }
            resourceSection("script", symbol: "curlybraces", tone: .purple) { Text("脚本 \($0)") }
            Section {} footer: {
                Text("向右轻扫或按住某一项可以启用 / 停用。配置文件里的规则集和节点集（rule-providers / proxy-providers）由内核按配置更新，也可在「工具 → 分流规则 → 配置里的规则集」和「工具 → 节点与订阅」中手动更新。")
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
        .task { await res.reloadInBackground() }
        .alert("更新资源", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
    }

    @ViewBuilder
    func resourceSection(_ kind: String, symbol: String, tone: TileTone, header: @escaping (Int) -> Text) -> some View {
        let list = items(kind)
        if !list.isEmpty {
            Section {
                ForEach(list) { it in
                    ResourceUpdateRow(kind: kind, name: it.name, url: it.url, symbol: symbol, tone: tone,
                                      updated: it.updatedAt > 0 ? Date(timeIntervalSince1970: it.updatedAt) : nil,
                                      error: it.error, disabled: !it.enabled,
                                      owner: kind == "script" ? it.owner : nil,
                                      busy: res.busy.contains(it.key) || res.updatingAll) {
                        Task { await res.update(it); res.message = nil }
                    }
                    .enableActions(enabled: it.enabled, id: "\(kind).\(it.name)") { on in
                        if kind == "module", let id = it.refId {
                            // Same path as 工具 → 模块 (also turns the rewrite engine on when a module is enabled).
                            EngineStore.shared.setModuleEnabled(id, on)
                            res.reload()
                        } else {
                            res.setEnabled(it, on)
                        }
                    }
                }
            } header: { header(list.count) }
            .listRowBackground(Theme.card)
        }
    }

    /// Profiles, then node subscriptions, then modules / rule sets / scripts (ResourceStore does modules first).
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
        await res.updateAll()
        res.message = nil
        failed += res.items.filter { $0.isRemote && $0.enabled && !($0.error ?? "").isEmpty }.count
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
