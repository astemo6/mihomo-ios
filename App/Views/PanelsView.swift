import SwiftUI

/// Surge [Panel] / Stash tiles from modules, as one in-app 「面板」 screen (not home-screen widgets).
@MainActor
final class PanelsModel: ObservableObject {
    static let shared = PanelsModel()
    @Published var panels: [PanelItem] = []
    @Published var refreshing: Set<String> = []
    /// Lane D: a panel refresh that failed (controller unreachable, timeout, HTTP error) used to be dropped by `try?`
    /// — the spinner stopped and the old content stayed. The failure is kept with the controller's own reason and
    /// shown on the card until the panel has content newer than the failure.
    @Published private(set) var refreshFailures: [String: PanelRefreshFailure] = [:]
    /// Lane D: why the panel list itself could not be read (the list on screen is the last one that loaded).
    @Published private(set) var loadError: String?
    /// v0.15: panel ids pinned to Home (ids are stable hashes of module + panel name), in pin order.
    @Published var pinned: [String] = UserDefaults.standard.stringArray(forKey: "panels.pinned") ?? []
    /// v0.17 UI tests (-UITestSeed -UITestDemoPanels): one script panel + one static Stash tile, no engine.
    let demo = UITestSeed.enabled && UITestSeed.args.contains("-UITestDemoPanels")
    /// UI tests: demo panels, but 刷新 sends the real request (no engine runs, so it fails with the real reason).
    let demoLiveRefresh = UITestSeed.enabled && UITestSeed.args.contains("-UITestPanelRefreshLive")

    init() {
        if demo { panels = UITestSeed.demoPanels() }
    }

    /// Demo only: mirror what the engine does with an interval override (the live engine reports it itself).
    func applyDemoInterval(id: String, interval: Int?) {
        guard demo, let i = panels.firstIndex(where: { $0.id == id }) else { return }
        let module = panels[i].intervalOverridden == true ? panels[i].defaultInterval : panels[i].interval
        if let interval {
            panels[i].defaultInterval = module
            panels[i].interval = interval
            panels[i].intervalOverridden = true
        } else {
            panels[i].interval = module
            panels[i].defaultInterval = nil
            panels[i].intervalOverridden = nil
        }
    }

    var pinnedPanels: [PanelItem] { pinned.compactMap { id in panels.first { $0.id == id } } }

    func isPinned(_ p: PanelItem) -> Bool { pinned.contains(p.id) }

    func togglePin(_ p: PanelItem) {
        if let i = pinned.firstIndex(of: p.id) { pinned.remove(at: i) } else { pinned.append(p.id) }
        UserDefaults.standard.set(pinned, forKey: "panels.pinned")
        HomePanelStore.shared.sync() // feat/panels: hidden / pinned scripts / engine config
    }

    func load() async {
        if demo { return }
        guard VPNManager.shared.isConnected else { panels = []; loadError = nil; return }
        do {
            panels = try await ControllerClient.shared.mitmPanels()
            loadError = nil
        } catch {
            if let reason = Self.reason(error) { loadError = reason }
        }
    }

    func refresh(_ p: PanelItem) async {
        if demo && !demoLiveRefresh { return }
        refreshing.insert(p.id)
        defer { refreshing.remove(p.id) }
        do {
            let np = try await ControllerClient.shared.mitmRefreshPanel(p.id)
            refreshFailures[p.id] = nil
            if let i = panels.firstIndex(where: { $0.id == p.id }) { panels[i] = np }
        } catch {
            guard let reason = Self.reason(error) else { return }
            refreshFailures[p.id] = PanelRefreshFailure(reason: reason, at: Date().timeIntervalSince1970)
        }
    }

    /// The failure to show on a card: only while the panel has nothing newer (an auto-refresh by the extension that
    /// succeeded later replaces it).
    func failure(for p: PanelItem) -> String? {
        guard let f = refreshFailures[p.id], f.at > (p.updated ?? 0) else { return nil }
        return f.reason
    }

    /// The error's own text; nil for a cancelled request (page left, pull-to-refresh replaced), which is no failure.
    static func reason(_ error: Error) -> String? {
        if error is CancellationError { return nil }
        if let u = error as? URLError, u.code == .cancelled { return nil }
        let text = error.localizedDescription.trimmingCharacters(in: .whitespacesAndNewlines)
        return text.isEmpty ? nil : text
    }

    /// Fills panels that were never run, or whose update-interval has passed.
    func refreshStale() async {
        let now = Date().timeIntervalSince1970
        await withTaskGroup(of: Void.self) { g in
            for p in panels where p.script != nil {
                let interval = Double(max(p.interval ?? 0, 60))
                if (p.updated ?? 0) == 0 || now - (p.updated ?? 0) > interval {
                    g.addTask { await self.refresh(p) }
                }
            }
        }
    }
}

struct PanelRefreshFailure: Equatable {
    let reason: String
    /// When the refresh failed (seconds since 1970, like PanelItem.updated).
    let at: Double
}

extension Color {
    /// "#RRGGBB" / "#RRGGBBAA" / "RRGGBB".
    init?(hex: String?) {
        guard var s = hex?.trimmingCharacters(in: .whitespaces), !s.isEmpty else { return nil }
        if s.hasPrefix("#") { s.removeFirst() }
        guard s.count == 6 || s.count == 8, let v = UInt64(s, radix: 16) else { return nil }
        let r, g, b, a: Double
        if s.count == 6 {
            r = Double((v >> 16) & 0xFF) / 255; g = Double((v >> 8) & 0xFF) / 255; b = Double(v & 0xFF) / 255; a = 1
        } else {
            r = Double((v >> 24) & 0xFF) / 255; g = Double((v >> 16) & 0xFF) / 255; b = Double((v >> 8) & 0xFF) / 255; a = Double(v & 0xFF) / 255
        }
        self.init(red: r, green: g, blue: b, opacity: a)
    }
}

struct PanelsView: View {
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject var model = PanelsModel.shared
    @State private var editPanel: PanelItem?

    var body: some View {
        ScrollView {
            VStack(spacing: 12) {
                if !vpn.isConnected && !model.demo {
                    Card { EmptyStateRow(icon: "bolt.horizontal.circle", title: "连接后可查看", message: "面板由模块里的脚本生成，连接后显示。") }
                } else if model.panels.isEmpty {
                    Card { EmptyStateRow(icon: "square.grid.2x2", title: "没有面板", message: "启用带 Surge [Panel] 或 Stash tiles 的模块后，面板会出现在这里。") }
                }
                if vpn.isConnected, let e = model.loadError {
                    Label { Text("无法读取面板：\(e)") } icon: { Image(systemName: "exclamationmark.triangle.fill") }
                        .font(.caption).foregroundStyle(Theme.warn).lineLimit(3)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .accessibilityIdentifier("panels.loadError")
                }
                if model.panels.isEmpty {
                    // User 2026-10-22 「这些面板在哪里可以安装」: panels come from modules — one tap to the module library.
                    NavigationLink { LazyDestination { ModuleGalleryView() } } label: {
                        Label("去模块库添加", systemImage: "puzzlepiece.extension")
                            .font(.body.weight(.semibold))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 12)
                            .background(RoundedRectangle(cornerRadius: Theme.radius, style: .continuous).fill(Theme.card))
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(Theme.accent)
                    .accessibilityIdentifier("panels.gallery")
                }
                ForEach(model.panels) { p in
                    PanelCard(p: p, refreshing: model.refreshing.contains(p.id) || p.running, pinned: model.isPinned(p),
                              refreshFailure: model.failure(for: p)) {
                        Task { await model.refresh(p) }
                    }
                    .contextMenu {
                        PanelPinButton(p: p)
                        PanelEditButton { editPanel = p }
                    }
                }
                if (vpn.isConnected || model.demo) && !model.panels.isEmpty {
                    Text("长按面板可以固定到首页，或编辑标题、图标和刷新间隔。").font(.caption2).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(16)
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("面板")
        .navigationBarTitleDisplayMode(.inline)
        .sheet(item: $editPanel) { p in PanelEditSheet(p: p) }
        .refreshable {
            await model.load()
            await withTaskGroup(of: Void.self) { g in
                for p in model.panels where p.script != nil { g.addTask { await model.refresh(p) } }
            }
        }
        .task {
            await model.load()
            await model.refreshStale()
            // While the page is visible: pick up auto-refreshed content. The extension only auto-refreshes
            // panels the app has shown recently, so nothing runs once this page (and the app) is gone.
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 30_000_000_000)
                if Task.isCancelled { break }
                await model.load()
            }
        }
    }
}

struct PanelCard: View {
    let p: PanelItem
    let refreshing: Bool
    var pinned = false
    /// feat/panels: last result shown while disconnected (no refresh button).
    var offline = false
    /// Lane D: why the last 刷新 of this panel failed (PanelsModel.failure(for:)); nil when it did not or content is newer.
    var refreshFailure: String? = nil
    let onRefresh: () -> Void
    @ObservedObject private var overrides = PanelOverrideStore.shared
    /// v0.17: the user's title / icon (磁贴编辑) over the module's.
    var shown: PanelItem { p.applying(overrides.map[p.id]) }

    var accent: Color {
        if let c = Color(hex: p.iconColor) { return c }
        switch p.style?.lowercased() {
        case "good": return Theme.good
        case "alert": return Theme.warn
        case "error": return Theme.bad
        default: return Theme.accent
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: Self.symbol(shown.icon))
                .font(.title3)
                .foregroundStyle(accent)
                .frame(width: 34, height: 34)
                .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(accent.opacity(0.15)))
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(shown.title?.isEmpty == false ? shown.title! : shown.name).font(.subheadline.weight(.semibold)).lineLimit(2)
                    if pinned { Image(systemName: "pin.fill").font(.caption2).foregroundStyle(.secondary).accessibilityLabel(Text("已固定")) }
                    Spacer(minLength: 4)
                    if p.script != nil && !offline {
                        if refreshing {
                            ProgressView().controlSize(.small)
                        } else {
                            Button(action: onRefresh) { Image(systemName: "arrow.clockwise").font(.caption) }
                                .buttonStyle(.borderless)
                                .accessibilityLabel(Text("刷新"))
                                .accessibilityIdentifier("panel.refresh")
                        }
                    }
                }
                if let c = p.content, !c.isEmpty {
                    Text(c).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                }
                if let e = p.error, !e.isEmpty {
                    Text(e).font(.caption2).foregroundStyle(Theme.bad).lineLimit(3)
                }
                if let f = refreshFailure, !offline, !refreshing {
                    Label { Text("刷新失败：\(f)") } icon: { Image(systemName: "exclamationmark.triangle.fill") }
                        .font(.caption2).foregroundStyle(Theme.warn).lineLimit(2)
                        .accessibilityIdentifier("panel.refreshError")
                }
                HStack(spacing: 6) {
                    FormatBadge(format: p.format)
                    Text(p.source).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                    if p.script != nil, let i = overrides.map[p.id]?.interval ?? p.interval, i > 0 {
                        Label(PanelOverrideStore.intervalText(i), systemImage: "clock.arrow.circlepath")
                            .labelStyle(.titleAndIcon)
                            .font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                            .accessibilityIdentifier("panel.interval")
                    }
                    Spacer()
                    if let u = p.updated, u > 0 {
                        if offline { Image(systemName: "clock").font(.caption2).foregroundStyle(.secondary).accessibilityLabel(Text("上次结果")) }
                        Text(Date(timeIntervalSince1970: u).formatted(.relative(presentation: .named))).font(.caption2).foregroundStyle(.secondary)
                    }
                }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: Theme.radius, style: .continuous)
                .fill(Color(hex: p.backgroundColor).map { $0.opacity(0.22) } ?? Theme.card)
        )
    }

    /// Panel icons are SF Symbol names; fall back for empty / unknown names.
    static func symbol(_ name: String?) -> String {
        guard let n = name?.trimmingCharacters(in: .whitespaces), !n.isEmpty, UIImage(systemName: n) != nil else { return "square.grid.2x2" }
        return n
    }
}

/// Context-menu item shared by the 面板 page and Home.
struct PanelPinButton: View {
    @ObservedObject var model = PanelsModel.shared
    let p: PanelItem
    var body: some View {
        if model.isPinned(p) {
            Button { model.togglePin(p) } label: { Label("取消固定", systemImage: "pin.slash") }
        } else {
            Button { model.togglePin(p) } label: { Label("固定到首页", systemImage: "pin") }
        }
    }
}
