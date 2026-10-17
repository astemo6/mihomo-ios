import SwiftUI

/// Surge [Panel] / Stash tiles from modules, as one in-app 「面板」 screen (not home-screen widgets).
@MainActor
final class PanelsModel: ObservableObject {
    static let shared = PanelsModel()
    @Published var panels: [PanelItem] = []
    @Published var refreshing: Set<String> = []

    func load() async {
        guard VPNManager.shared.isConnected else { panels = []; return }
        if let l = try? await ControllerClient.shared.mitmPanels() { panels = l }
    }

    func refresh(_ p: PanelItem) async {
        refreshing.insert(p.id)
        defer { refreshing.remove(p.id) }
        if let np = try? await ControllerClient.shared.mitmRefreshPanel(p.id),
           let i = panels.firstIndex(where: { $0.id == p.id }) {
            panels[i] = np
        }
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

    var body: some View {
        ScrollView {
            VStack(spacing: 12) {
                if !vpn.isConnected {
                    Card { EmptyStateRow(icon: "bolt.horizontal.circle", title: "连接后可查看", message: "面板由模块里的脚本生成，连接后显示。") }
                } else if model.panels.isEmpty {
                    Card { EmptyStateRow(icon: "square.grid.2x2", title: "没有面板", message: "启用带 Surge [Panel] 或 Stash tiles 的模块后，面板会出现在这里。") }
                }
                ForEach(model.panels) { p in
                    PanelCard(p: p, refreshing: model.refreshing.contains(p.id) || p.running) {
                        Task { await model.refresh(p) }
                    }
                }
            }
            .padding(16)
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("面板")
        .navigationBarTitleDisplayMode(.inline)
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
    let onRefresh: () -> Void

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
            Image(systemName: Self.symbol(p.icon))
                .font(.title3)
                .foregroundStyle(accent)
                .frame(width: 34, height: 34)
                .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(accent.opacity(0.15)))
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(p.title?.isEmpty == false ? p.title! : p.name).font(.subheadline.weight(.semibold)).lineLimit(2)
                    Spacer(minLength: 4)
                    if p.script != nil {
                        if refreshing {
                            ProgressView().controlSize(.small)
                        } else {
                            Button(action: onRefresh) { Image(systemName: "arrow.clockwise").font(.caption) }
                                .buttonStyle(.borderless)
                        }
                    }
                }
                if let c = p.content, !c.isEmpty {
                    Text(c).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                }
                if let e = p.error, !e.isEmpty {
                    Text(e).font(.caption2).foregroundStyle(Theme.bad).lineLimit(3)
                }
                HStack(spacing: 6) {
                    FormatBadge(format: p.format)
                    Text(p.source).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                    Spacer()
                    if let u = p.updated, u > 0 {
                        Text(Date(timeIntervalSince1970: u).formatted(.relative(presentation: .named))).font(.caption2).foregroundStyle(.secondary)
                    }
                }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .fill(Color(hex: p.backgroundColor).map { $0.opacity(0.22) } ?? Theme.card)
        )
        .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(Color.primary.opacity(0.06)))
    }

    /// Panel icons are SF Symbol names; fall back for empty / unknown names.
    static func symbol(_ name: String?) -> String {
        guard let n = name?.trimmingCharacters(in: .whitespaces), !n.isEmpty, UIImage(systemName: n) != nil else { return "square.grid.2x2" }
        return n
    }
}

/// Compact Home entry: one slim row, only when the running engine has panels (keeps Home minimal).
struct PanelsEntry: View {
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject var model = PanelsModel.shared

    var body: some View {
        VStack(spacing: 0) {
            if vpn.isConnected && !model.panels.isEmpty {
                NavigationLink { PanelsView() } label: {
                    HStack(spacing: 10) {
                        Image(systemName: "square.grid.2x2").foregroundStyle(Theme.accent)
                        Text("面板").font(.subheadline.weight(.semibold))
                        Text("\(model.panels.count)").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                        if let first = model.panels.first(where: { ($0.content ?? "").isEmpty == false }) {
                            Text(first.content!.split(separator: "\n").first.map(String.init) ?? "")
                                .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                        }
                        Spacer()
                        Image(systemName: "chevron.right").font(.caption).foregroundStyle(.secondary)
                    }
                    .padding(.horizontal, 16).padding(.vertical, 12)
                    .background(RoundedRectangle(cornerRadius: 18, style: .continuous).fill(Theme.card))
                    .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).stroke(Color.primary.opacity(0.06)))
                }
                .buttonStyle(.plain)
            }
        }
        .task(id: vpn.isConnected) { await model.load() }
    }
}
