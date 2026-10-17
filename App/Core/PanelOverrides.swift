import SwiftUI

// v0.17 磁贴编辑 (parity #10, Stash override tiles): the user's title, icon and refresh interval per panel /
// tile, kept as an override (engine/panel-overrides.json, keyed by the panel's stable id). Modules are not
// edited, so updating or re-importing a module keeps the override. Title and icon are display-only (they
// replace what the module or its script sets); the interval goes to the engine through home-panels.json
// ("intervals", PUT /mitm/panels-home while connected) and replaces update-interval / Stash interval.

struct PanelOverride: Codable, Hashable {
    var title: String?
    var icon: String?
    /// Seconds (≥ 60). nil = the module's own interval.
    var interval: Int?

    var isEmpty: Bool { (title ?? "").isEmpty && (icon ?? "").isEmpty && interval == nil }
}

@MainActor
final class PanelOverrideStore: ObservableObject {
    static let shared = PanelOverrideStore()
    @Published private(set) var map: [String: PanelOverride] = [:]

    static var url: URL { EnginePaths.dir.appendingPathComponent("panel-overrides.json") }

    private init() {
        if let d = try? Data(contentsOf: Self.url), let m = try? JSONDecoder().decode([String: PanelOverride].self, from: d) { map = m }
    }

    /// Interval overrides for the engine (script panels only; static tiles have nothing to refresh).
    var intervals: [String: Int] { map.compactMapValues { $0.interval } }

    func set(_ o: PanelOverride?, for id: String) {
        var m = map
        if var o, !o.isEmpty {
            o.title = o.title?.trimmingCharacters(in: .whitespacesAndNewlines)
            if o.title?.isEmpty == true { o.title = nil }
            o.icon = o.icon?.trimmingCharacters(in: .whitespaces)
            if o.icon?.isEmpty == true { o.icon = nil }
            if let i = o.interval { o.interval = max(i, 60) }
            m[id] = o.isEmpty ? nil : o
        } else {
            m.removeValue(forKey: id)
        }
        map = m
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let d = try? enc.encode(m) { try? d.write(to: Self.url, options: .atomic) }
        // Engine side (intervals) + the demo list used by UI tests.
        HomePanelStore.shared.sync()
        PanelsModel.shared.applyDemoInterval(id: id, interval: m[id]?.interval)
    }

    /// The module's own interval for a panel as the engine reports it (before the override).
    static func moduleInterval(_ p: PanelItem) -> Int? {
        p.intervalOverridden == true ? p.defaultInterval : p.interval
    }

    static let intervalChoices: [Int] = [300, 900, 1800, 3600, 21600, 86400]

    static func intervalText(_ s: Int?) -> String {
        guard let s, s > 0 else { return String(localized: "打开时或手动") }
        switch s {
        case 300: return String(localized: "每 5 分钟")
        case 900: return String(localized: "每 15 分钟")
        case 1800: return String(localized: "每 30 分钟")
        case 3600: return String(localized: "每小时")
        case 21600: return String(localized: "每 6 小时")
        case 86400: return String(localized: "每天")
        default:
            if s % 3600 == 0 { return String(localized: "每 \(s / 3600) 小时") }
            return String(localized: "每 \(max(s / 60, 1)) 分钟")
        }
    }

    /// Curated SF Symbols that suit tiles; any other valid symbol name can be typed.
    static let iconChoices = ["network", "globe", "wifi", "antenna.radiowaves.left.and.right", "speedometer", "bolt.horizontal.circle",
                              "chart.bar.xaxis", "clock", "calendar", "airplane", "tv", "play.rectangle", "music.note", "gamecontroller",
                              "cloud", "lock.shield", "checkmark.seal", "exclamationmark.triangle", "info.circle", "star", "heart",
                              "flame", "leaf", "server.rack", "externaldrive", "creditcard", "cart", "bell", "location", "house"]
}

extension PanelItem {
    /// The panel as shown: the user's title / icon instead of the module's or the script's.
    func applying(_ o: PanelOverride?) -> PanelItem {
        guard let o else { return self }
        var p = self
        if let t = o.title, !t.isEmpty { p.title = t }
        if let i = o.icon, !i.isEmpty { p.icon = i }
        return p
    }
}

/// Context-menu item: opens the tile editor.
struct PanelEditButton: View {
    let action: () -> Void
    var body: some View {
        Button(action: action) { Label("编辑面板…", systemImage: "pencil") }
    }
}

struct PanelEditSheet: View {
    let p: PanelItem
    @Environment(\.dismiss) private var dismiss
    @ObservedObject private var store = PanelOverrideStore.shared
    @State private var title = ""
    @State private var icon = ""
    @State private var interval: Int? = nil

    var original: String { p.title?.isEmpty == false ? p.title! : p.name }
    var iconValid: Bool { icon.isEmpty || UIImage(systemName: icon) != nil }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    HStack(spacing: 12) {
                        Image(systemName: PanelCard.symbol(icon.isEmpty ? p.icon : icon))
                            .font(.title3).foregroundStyle(Theme.accent)
                            .frame(width: 34, height: 34)
                            .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Theme.accent.opacity(0.15)))
                        Text(verbatim: title.isEmpty ? original : title).font(.subheadline.weight(.semibold)).lineLimit(2)
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("panel.edit.preview")
                } header: { Text("预览") }

                Section {
                    TextField(original, text: $title)
                        .accessibilityIdentifier("panel.edit.title")
                } header: { Text("标题") } footer: { Text("留空则用模块或脚本给出的标题。") }

                Section {
                    LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 8), count: 6), spacing: 10) {
                        ForEach(PanelOverrideStore.iconChoices, id: \.self) { s in
                            Button { icon = (icon == s ? "" : s) } label: {
                                Image(systemName: s)
                                    .frame(width: 38, height: 38)
                                    .foregroundStyle(icon == s ? Theme.onAccent : Theme.accent)
                                    .background(RoundedRectangle(cornerRadius: 9, style: .continuous).fill(icon == s ? Theme.accent : Theme.ink(0.06)))
                            }
                            .buttonStyle(.plain)
                            .accessibilityLabel(Text(verbatim: s))
                            .accessibilityIdentifier("panel.edit.icon.\(s)")
                        }
                    }
                    .padding(.vertical, 4)
                    TextField("SF Symbol", text: $icon)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .font(.callout.monospaced())
                        .accessibilityIdentifier("panel.edit.iconField")
                    if !iconValid {
                        Text("没有这个 SF Symbol").font(.caption).foregroundStyle(Theme.bad)
                    }
                } header: { Text("图标") } footer: { Text("留空则用模块或脚本给出的图标。") }

                if p.script != nil {
                    Section {
                        Picker("刷新间隔", selection: $interval) {
                            Text("跟随模块（\(PanelOverrideStore.intervalText(PanelOverrideStore.moduleInterval(p)))）").tag(Int?.none)
                            ForEach(PanelOverrideStore.intervalChoices, id: \.self) { s in
                                Text(verbatim: PanelOverrideStore.intervalText(s)).tag(Int?.some(s))
                            }
                        }
                        .pickerStyle(.inline)
                        .labelsHidden()
                        .accessibilityIdentifier("panel.edit.interval")
                    } header: { Text("刷新间隔") } footer: { Text("连接时由引擎按这个间隔运行脚本；不在前台时首页面板至少间隔 5 分钟。") }
                }

                if store.map[p.id] != nil {
                    Section {
                        Button(role: .destructive) {
                            store.set(nil, for: p.id)
                            dismiss()
                        } label: { Text("恢复默认") }
                        .accessibilityIdentifier("panel.edit.reset")
                    }
                }
            }
            .navigationTitle("编辑面板")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") {
                        store.set(PanelOverride(title: title, icon: icon, interval: p.script != nil ? interval : nil), for: p.id)
                        dismiss()
                    }
                    .disabled(!iconValid)
                    .accessibilityIdentifier("panel.edit.save")
                }
            }
            .onAppear {
                let o = store.map[p.id]
                title = o?.title ?? ""
                icon = o?.icon ?? ""
                interval = o?.interval
            }
        }
    }
}
