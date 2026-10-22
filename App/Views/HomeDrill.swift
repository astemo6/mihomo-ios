import SwiftUI
import Charts

// feat/home-drilldown (user 2026-10-22 「空有其表」: Egern's 分析 cards all open a detail page, ours looked the same but
// did nothing). Every Home card now opens a real page:
//   全部连接 / 活跃连接 → 连接 (filter chips 规则▾ 策略▾ 主机 HTTP 活跃 已拦截)
//   网络 speed card / 网速波形图 → 网络 (秒 / 分钟 / 小时 chart, scrub, connections at that moment) → connection detail
//   策略 → 策略流量 (per policy ↑↓) → 连接 filtered by that policy
//   规则 ring → 连接 filtered by that rule; 查看全部 → 规则命中 → 连接
//   主机名 → 主机名 (↑↓ per host) → 连接 filtered by that host
//   DNS (opt-in) → DNS 日志
// Data is what the app already has: ConnectionAnalytics (session totals + the connections it saw open and close),
// the 请求 poll (RequestsModel) while a page is open, and NetworkHistory (samples DashboardModel already takes).
// Nothing is invented; where a window is limited (closed connections capped, samples only while the app is open)
// the page says so. Pages are pushed leaves: they poll only while on screen, and filtering runs off the main thread.

// MARK: - Shared chrome

/// Press feedback for a card that opens a page (NavigationLink label).
struct PressableCardStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.985 : 1)
            .opacity(configuration.isPressed ? 0.82 : 1)
            .animation(.easeOut(duration: 0.12), value: configuration.isPressed)
    }
}

/// The small chevron a tappable card shows in its corner.
struct CardChevron: View {
    var body: some View {
        Image(systemName: "chevron.right")
            .font(.caption2.weight(.semibold))
            .foregroundStyle(.tertiary)
            .accessibilityHidden(true)
    }
}

// MARK: - Connection filter

struct ConnFilter: Equatable {
    /// ConnectionItem.ruleText (「—」 for none), as ConnectionAnalytics keys rule hits.
    var rules: Set<String> = []
    /// Final policy = chains.last (the group the rule chose), as ConnectionAnalytics keys policies.
    var policies: Set<String> = []
    /// ConnectionAnalytics.hostName (host, sniffed host or IP).
    var host: String? = nil
    var activeOnly = false
    var httpOnly = false
    var blockedOnly = false

    var isEmpty: Bool { rules.isEmpty && policies.isEmpty && host == nil && !activeOnly && !httpOnly && !blockedOnly }

    static func rule(_ c: ConnectionItem) -> String { c.ruleText.isEmpty ? "—" : c.ruleText }
    static func policy(_ c: ConnectionItem) -> String { c.chains?.last ?? "DIRECT" }
    static func isBlocked(_ c: ConnectionItem) -> Bool {
        (c.chains ?? []).contains { $0.uppercased().hasPrefix("REJECT") }
    }
    /// Plain HTTP (port 80) or handled by the HTTP engine (MitM / rewrite) — the connections whose requests can be read.
    static func isHTTP(_ c: ConnectionItem) -> Bool {
        (c.chains ?? []).contains("__MITM__") || c.metadata.destinationPort == "80"
    }

    func matches(_ c: ConnectionItem, search q: String) -> Bool {
        if activeOnly && c.closedAt != nil { return false }
        if httpOnly && !Self.isHTTP(c) { return false }
        if blockedOnly && !Self.isBlocked(c) { return false }
        if !rules.isEmpty && !rules.contains(Self.rule(c)) { return false }
        if !policies.isEmpty && !policies.contains(Self.policy(c)) { return false }
        if let host, ConnectionAnalytics.hostName(c.metadata) != host { return false }
        if !q.isEmpty {
            let hay = [c.metadata.displayHost, c.chainText, c.ruleText, c.metadata.destinationIP ?? ""].joined(separator: " ").lowercased()
            if !hay.contains(q) { return false }
        }
        return true
    }

    /// Active connections first (newest start first), then closed ones (most recently closed first); duplicates
    /// (an id in both lists, or in two closed lists) appear once. Pure, so it runs off the main thread.
    static func merge(active: [ConnectionItem], closed: [[ConnectionItem]]) -> [ConnectionItem] {
        var seen = Set<String>()
        var out: [ConnectionItem] = []
        out.reserveCapacity(active.count + closed.reduce(0) { $0 + $1.count })
        for c in active.sorted(by: { ($0.startDate ?? .distantPast) > ($1.startDate ?? .distantPast) }) where seen.insert(c.id).inserted {
            out.append(c)
        }
        let cl = closed.flatMap { $0 }.sorted { ($0.closedAt ?? .distantPast) > ($1.closedAt ?? .distantPast) }
        for c in cl where seen.insert(c.id).inserted { out.append(c) }
        return out
    }
}

/// Live feed for the 连接 / 网络 pages: the 请求 poll (RequestsModel, 1 s, only while the page is on screen) plus the
/// connections ConnectionAnalytics saw close since the tunnel connected. UI tests (-UITestDemoAnalytics) read the
/// synthetic ConnectionAnalytics instead and never poll.
@MainActor
struct ConnectionFeedSource {
    static var demo: Bool { HomeAnalysisModel.demo }
    static var analytics: ConnectionAnalytics { HomeAnalysisModel.shared.source }

    static func seed(_ model: RequestsModel) {
        if model.active.isEmpty { model.active = analytics.activeItems }
    }
}

// MARK: - 连接

struct ConnectionsListView: View {
    @EnvironmentObject var vpn: VPNManager
    @State var filter: ConnFilter
    var title: String = String(localized: "连接")
    @StateObject private var model = RequestsModel()
    @State private var rows: [ConnectionItem] = []
    @State private var activeCount = 0
    @State private var search = ""
    @State private var sheet: ConnFilterSheet.Kind?
    @State private var job: Task<Void, Never>?
    @Environment(\.scenePhase) private var scenePhase
    @State private var onScreen = false
    @State private var quickRule: ConnectionItem?
    static let rowLimit = 1000

    var body: some View {
        List {
            chips
                .listRowInsets(EdgeInsets(top: 4, leading: 0, bottom: 4, trailing: 0))
                .listRowBackground(Color.clear)
            Section {
                if rows.isEmpty {
                    EmptyStateRow(icon: "line.3.horizontal.decrease.circle", title: "没有符合条件的连接",
                                  message: filter.isEmpty ? nil : "试试去掉一些筛选条件。")
                        .listRowBackground(Theme.card)
                        .accessibilityIdentifier("connlist.empty")
                }
                ForEach(rows.prefix(Self.rowLimit)) { c in
                    NavigationLink { ConnectionDetailView(c: c, model: model) } label: { ConnectionRow(c: c) }
                        .listRowBackground(Theme.card)
                        .accessibilityIdentifier("connlist.row")
                        .contextMenu {
                            Button { quickRule = c } label: { Label("添加规则…", systemImage: "plus.rectangle.on.rectangle") }
                            if let h = c.metadata.host ?? c.metadata.sniffHost, !h.isEmpty {
                                Button { UIPasteboard.general.string = h } label: { Label("拷贝主机", systemImage: "doc.on.doc") }
                            }
                        }
                }
            } header: {
                Text("\(rows.count) 条连接 · 活跃 \(activeCount)")
                    .accessibilityIdentifier("connlist.count")
            } footer: {
                Text("当前连接和连接后最近关闭的连接（App 打开期间记录，最多 \(ConnectionAnalytics.closedCap) 条）。规则命中次数统计整个连接期间，可能多于这里列出的连接。")
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .searchable(text: $search, placement: .navigationBarDrawer(displayMode: .automatic), prompt: "搜索主机、规则、策略")
        .navigationTitle(Text(verbatim: title))
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                if !ConnectionFeedSource.demo {
                    Button { model.paused.toggle() } label: { Image(systemName: model.paused ? "play.fill" : "pause.fill") }
                        .accessibilityLabel(Text(LocalizedStringKey(model.paused ? "继续" : "暂停")))
                }
            }
        }
        .sheet(item: $sheet) { k in
            ConnFilterSheet(kind: k, options: options(k), selected: Binding(
                get: { k == .rules ? filter.rules : filter.policies },
                set: { if k == .rules { filter.rules = $0 } else { filter.policies = $0 } }))
        }
        .sheet(item: $quickRule) { c in QuickRuleSheet(conn: c) }
        .onAppear { onScreen = true; start() }
        .onDisappear { onScreen = false; model.stop(); job?.cancel() }
        .onChange(of: scenePhase) { p in if p == .active { if onScreen { start() } } else { model.stop() } }
        .onChange(of: vpn.isConnected) { _ in if onScreen { start() } }
        .onReceive(model.$active) { _ in recompute() }
        .onReceive(model.$recent) { _ in recompute() }
        .onChange(of: filter) { _ in recompute() }
        .onChange(of: search) { _ in recompute() }
    }

    func start() {
        ConnectionFeedSource.seed(model)
        if !ConnectionFeedSource.demo && vpn.isConnected { model.start() } else { model.stop() }
        recompute()
    }

    func recompute() {
        let active = model.active
        let closed = [model.recent, ConnectionFeedSource.analytics.closedItems]
        let f = filter
        let q = search.lowercased().trimmingCharacters(in: .whitespaces)
        job?.cancel()
        job = Task {
            let (out, act) = await Task.detached(priority: .userInitiated) { () -> ([ConnectionItem], Int) in
                let all = ConnFilter.merge(active: active, closed: closed).filter { f.matches($0, search: q) }
                return (all, all.reduce(0) { $0 + ($1.closedAt == nil ? 1 : 0) })
            }.value
            guard !Task.isCancelled else { return }
            if out != rows { rows = out }
            if act != activeCount { activeCount = act }
        }
    }

    /// Rule / policy options: everything the session counted (ConnectionAnalytics) plus whatever the listed
    /// connections carry, busiest first.
    func options(_ k: ConnFilterSheet.Kind) -> [ConnFilterSheet.Option] {
        var counts: [String: Int] = [:]
        let a = ConnectionFeedSource.analytics
        let all = ConnFilter.merge(active: model.active, closed: [model.recent, a.closedItems])
        switch k {
        case .rules:
            for r in a.rules.values { counts[r.rule, default: 0] += r.hits }
            for c in all where counts[ConnFilter.rule(c)] == nil { counts[ConnFilter.rule(c)] = 0 }
        case .policies:
            var seen: [String: Int] = [:]
            for c in all { seen[ConnFilter.policy(c), default: 0] += 1 }
            for r in a.rules.values { counts[r.policy, default: 0] += r.hits }
            for (p, n) in seen where counts[p] == nil { counts[p] = n }
        }
        for s in (k == .rules ? filter.rules : filter.policies) where counts[s] == nil { counts[s] = 0 }
        return counts.map { ConnFilterSheet.Option(key: $0.key, count: $0.value) }
            .sorted { $0.count != $1.count ? $0.count > $1.count : $0.key < $1.key }
    }

    var chips: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                FilterChip(title: String(localized: "规则"), count: filter.rules.count, menu: true, id: "connlist.chip.rules") { sheet = .rules }
                FilterChip(title: String(localized: "策略"), count: filter.policies.count, menu: true, id: "connlist.chip.policies") { sheet = .policies }
                if let h = filter.host {
                    FilterChip(title: h, on: true, removable: true, id: "connlist.chip.host") { filter.host = nil }
                }
                FilterChip(title: "HTTP", on: filter.httpOnly, id: "connlist.chip.http") { filter.httpOnly.toggle() }
                FilterChip(title: String(localized: "活跃"), on: filter.activeOnly, id: "connlist.chip.active") { filter.activeOnly.toggle() }
                FilterChip(title: String(localized: "已拦截"), on: filter.blockedOnly, id: "connlist.chip.blocked") { filter.blockedOnly.toggle() }
            }
            .padding(.horizontal, 4)
        }
    }
}

/// Egern's filter capsule: filled when on; a ▾ for the multi-select ones, ✕ for a removable one.
struct FilterChip: View {
    let title: String
    var count = 0
    var on = false
    var menu = false
    var removable = false
    let id: String
    let action: () -> Void

    var body: some View {
        let active = on || count > 0
        Button(action: action) {
            HStack(spacing: 4) {
                Text(verbatim: title).lineLimit(1).truncationMode(.middle)
                if count > 0 { Text(verbatim: "\(count)").monospacedDigit() }
                if menu { Image(systemName: "chevron.down").font(.caption2.weight(.bold)) }
                if removable { Image(systemName: "xmark").font(.caption2.weight(.bold)) }
            }
            .font(.footnote.weight(.medium))
            .padding(.horizontal, 12).padding(.vertical, 6)
            .frame(maxWidth: 220)
            .foregroundStyle(active ? Theme.onAccent : Color.primary)
            .background(Capsule().fill(active ? Theme.accent : Theme.card))
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier(id)
        .accessibilityValue(Text(verbatim: active ? "1" : "0"))
        .accessibilityAddTraits(active ? .isSelected : [])
    }
}

/// Multi-select sheet for 规则 / 策略 (「已选择 N 项」 like Egern's rule filter).
struct ConnFilterSheet: View {
    enum Kind: String, Identifiable { case rules, policies; var id: String { rawValue } }
    struct Option: Identifiable { let key: String; let count: Int; var id: String { key } }
    let kind: Kind
    let options: [Option]
    @Binding var selected: Set<String>
    @Environment(\.dismiss) private var dismiss
    @State private var search = ""

    var body: some View {
        NavigationStack {
            List {
                let shown = search.isEmpty ? options : options.filter { $0.key.localizedCaseInsensitiveContains(search) }
                if shown.isEmpty {
                    Text("没有可选项").font(.footnote).foregroundStyle(.secondary).listRowBackground(Theme.card)
                }
                ForEach(shown) { o in
                    Button {
                        if selected.contains(o.key) { selected.remove(o.key) } else { selected.insert(o.key) }
                    } label: {
                        HStack(spacing: 10) {
                            VStack(alignment: .leading, spacing: 2) {
                                if kind == .rules {
                                    let p = HomeRuleHitsCard.split(o.key)
                                    Text(verbatim: p.payload ?? p.type).font(.subheadline).lineLimit(2)
                                    if p.payload != nil { Text(verbatim: p.type).font(.caption2).foregroundStyle(.secondary) }
                                } else {
                                    Text(verbatim: o.key).font(.subheadline).lineLimit(1)
                                }
                            }
                            Spacer(minLength: 6)
                            if o.count > 0 { Text(verbatim: "\(o.count)").font(.caption.monospacedDigit()).foregroundStyle(.secondary) }
                            Image(systemName: selected.contains(o.key) ? "checkmark.circle.fill" : "circle")
                                .foregroundStyle(selected.contains(o.key) ? Theme.accent : Color.secondary)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .listRowBackground(Theme.card)
                    .accessibilityIdentifier("connfilter.option")
                    .accessibilityValue(Text(verbatim: selected.contains(o.key) ? "1" : "0"))
                }
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .searchable(text: $search, placement: .navigationBarDrawer(displayMode: .always))
            .navigationTitle(selected.isEmpty ? Text(LocalizedStringKey(kind == .rules ? "规则" : "策略")) : Text("已选择 \(selected.count) 项"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("清除") { selected = [] }.disabled(selected.isEmpty)
                        .accessibilityIdentifier("connfilter.clear")
                }
                ToolbarItem(placement: .confirmationAction) { Button("完成") { dismiss() } }
            }
        }
        .presentationDetents([.medium, .large])
    }
}

// MARK: - 策略流量

struct PolicyTrafficView: View {
    @State private var list: [ConnectionAnalytics.Usage] = []
    @State private var counts: [String: Int] = [:]

    var body: some View {
        let total = max(list.reduce(Int64(0)) { $0 + $1.bytes.total }, 1)
        let colors = AnalyticsView.palette
        List {
            if list.isEmpty {
                EmptyStateRow(icon: "chart.bar.xaxis", title: "还没有流量").listRowBackground(Theme.card)
            } else {
                Section {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            Text("合计").font(.subheadline.weight(.semibold))
                            Spacer()
                            Text(verbatim: Fmt.bytes(list.reduce(Int64(0)) { $0 + $1.bytes.total })).font(.subheadline.weight(.semibold).monospacedDigit())
                        }
                        GeometryReader { geo in
                            HStack(spacing: 2) {
                                ForEach(Array(list.prefix(12).enumerated()), id: \.offset) { i, p in
                                    Rectangle().fill(colors[i % (colors.count - 1)])
                                        .frame(width: max(2, geo.size.width * CGFloat(Double(p.bytes.total) / Double(total)) - 2))
                                }
                            }
                            .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                        }
                        .frame(height: 12)
                        .accessibilityHidden(true)
                    }
                    .padding(.vertical, 4)
                }
                .listRowBackground(Theme.card)
                Section {
                    ForEach(Array(list.enumerated()), id: \.element.id) { i, p in
                        NavigationLink {
                            ConnectionsListView(filter: ConnFilter(policies: [p.name]), title: p.name)
                        } label: {
                            HStack(spacing: 10) {
                                Circle().fill(i < 12 ? colors[i % (colors.count - 1)] : (colors.last ?? .gray)).frame(width: 9, height: 9)
                                    .accessibilityHidden(true)
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(verbatim: p.name).font(.subheadline).lineLimit(1)
                                    HStack(spacing: 10) {
                                        Label(Fmt.bytes(p.bytes.up), systemImage: "arrow.up").foregroundStyle(Theme.up)
                                        Label(Fmt.bytes(p.bytes.down), systemImage: "arrow.down").foregroundStyle(Theme.down)
                                    }
                                    .font(.caption2.monospacedDigit())
                                    .fixedSize()
                                }
                                Spacer(minLength: 6)
                                VStack(alignment: .trailing, spacing: 2) {
                                    Text(Double(p.bytes.total) / Double(total), format: .percent.precision(.fractionLength(0)))
                                        .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                                    if let n = counts[p.name] {
                                        Text("\(n) 次命中").font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                                    }
                                }
                                .fixedSize()
                            }
                        }
                        .listRowBackground(Theme.card)
                        .accessibilityIdentifier("policytraffic.row.\(p.name)")
                    }
                } footer: {
                    Text("本次连接期间各策略（规则选中的策略组）的流量，App 打开时采样，断开后清零。轻点查看经过该策略的连接。")
                }
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("策略流量")
        .task {
            // A leaf page: copies the session numbers every 2 s while it is on screen (no store observed).
            while !Task.isCancelled {
                let a = ConnectionFeedSource.analytics
                let l = a.policyList
                var c: [String: Int] = [:]
                for r in a.rules.values { c[r.policy, default: 0] += r.hits }
                if l.map(\.name) != list.map(\.name) || l.map(\.bytes) != list.map(\.bytes) { list = l }
                if c != counts { counts = c }
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }
}

// MARK: - 网络 history

/// Speed samples for the 网络 page: the 1 s /app/traffic answers DashboardModel already takes (both scopes), kept as
/// the last 10 minutes of seconds plus per-minute (3 h) and per-hour (48 h) averages of the sampled seconds.
/// Only while the app is open and connected; nothing is filled in for time the app did not sample. In memory only.
@MainActor
final class NetworkHistory {
    static let shared = NetworkHistory()

    struct Sample { let t: Date; let up: Int64; let down: Int64; let pUp: Int64; let pDown: Int64 }
    struct Bucket {
        let start: Date
        var up: Int64 = 0, down: Int64 = 0, pUp: Int64 = 0, pDown: Int64 = 0
        var n = 0
    }

    static let secondCap = 600
    static let minuteCap = 180
    static let hourCap = 48

    private(set) var seconds: [Sample] = []
    private(set) var minutes: [Bucket] = []
    private(set) var hours: [Bucket] = []
    private(set) var version = 0

    func add(_ t: AppTraffic, at date: Date) {
        let s = Sample(t: date, up: max(t.up, 0), down: max(t.down, 0), pUp: max(t.proxyUp, 0), pDown: max(t.proxyDown, 0))
        seconds.append(s)
        if seconds.count > Self.secondCap { seconds.removeFirst(seconds.count - Self.secondCap) }
        Self.fold(s, into: &minutes, step: 60, cap: Self.minuteCap)
        Self.fold(s, into: &hours, step: 3600, cap: Self.hourCap)
        version &+= 1
    }

    private static func fold(_ s: Sample, into list: inout [Bucket], step: TimeInterval, cap: Int) {
        let start = Date(timeIntervalSince1970: floor(s.t.timeIntervalSince1970 / step) * step)
        if list.last?.start != start {
            list.append(Bucket(start: start))
            if list.count > cap { list.removeFirst(list.count - cap) }
        }
        let i = list.count - 1
        list[i].up += s.up; list[i].down += s.down; list[i].pUp += s.pUp; list[i].pDown += s.pDown
        list[i].n += 1
    }

    /// UI tests only (-UITestDemoAnalytics): a synthetic sampled stretch with one gap, never on a device run.
    func fillDemoIfNeeded() {
        guard HomeAnalysisModel.demo, seconds.isEmpty else { return }
        let now = Date()
        for i in stride(from: 299, through: 0, by: -1) {
            if (120..<150).contains(i) { continue } // the app was in the background here
            let x = Double(i)
            let down = Int64(400_000 + 350_000 * sin(x / 9) + (i % 37 == 0 ? 2_400_000 : 0))
            let up = Int64(40_000 + 30_000 * cos(x / 7))
            add(AppTraffic(up: up, down: max(down, 0), upTotal: 0, downTotal: 0, proxyUp: up / 2, proxyDown: max(down, 0) / 2,
                           proxyUpTotal: 0, proxyDownTotal: 0), at: now.addingTimeInterval(-x))
        }
    }

    struct Point: Identifiable, Equatable {
        let t: Date
        let up: Int64
        let down: Int64
        /// Coverage of a minute / hour bucket (sampled seconds), 1 for a single second.
        let n: Int
        /// A new segment starts after a stretch that was not sampled (drawn as a break, never bridged).
        let segment: Int
        var id: Date { t }
    }

    func points(scale: Int, proxy: Bool) -> [Point] {
        var out: [Point] = []
        var seg = 0
        switch scale {
        case 0:
            var prev: Date?
            for s in seconds {
                if let p = prev, s.t.timeIntervalSince(p) > SpeedSeries.maxGap { seg += 1 }
                prev = s.t
                out.append(Point(t: s.t, up: proxy ? s.pUp : s.up, down: proxy ? s.pDown : s.down, n: 1, segment: seg))
            }
        default:
            let list = scale == 1 ? minutes : hours
            let step: TimeInterval = scale == 1 ? 60 : 3600
            var prev: Date?
            for b in list where b.n > 0 {
                if let p = prev, b.start.timeIntervalSince(p) > step + 1 { seg += 1 }
                prev = b.start
                let n = Int64(b.n)
                out.append(Point(t: b.start, up: (proxy ? b.pUp : b.up) / n, down: (proxy ? b.pDown : b.down) / n, n: b.n, segment: seg))
            }
        }
        return out
    }
}

// MARK: - 网络

struct NetworkView: View {
    @EnvironmentObject var vpn: VPNManager
    @AppStorage("network.scale") private var scale = 0
    @State private var points: [NetworkHistory.Point] = []
    @State private var selected: NetworkHistory.Point?
    @State private var builtVersion = -1
    @State private var builtScale = -1
    @StateObject private var model = RequestsModel()
    @State private var conns: [ConnectionItem] = []
    @State private var job: Task<Void, Never>?
    @Environment(\.scenePhase) private var scenePhase
    @State private var onScreen = false
    private var proxyOnly: Bool { DashboardModel.shared.scope == .proxy }
    static let connLimit = 60

    var body: some View {
        List {
            Section {
                VStack(alignment: .leading, spacing: 10) {
                    Picker("刻度", selection: $scale) {
                        Text("秒").tag(0)
                        Text("分钟").tag(1)
                        Text("小时").tag(2)
                    }
                    .pickerStyle(.segmented)
                    .accessibilityIdentifier("network.scale")
                    readout
                    chart
                        .frame(height: 200)
                        .accessibilityIdentifier("network.chart")
                    HStack(spacing: 14) {
                        legend(Theme.up, "上传")
                        legend(Theme.down, "下载")
                        Spacer()
                        if proxyOnly { Text("仅代理").font(.caption2).foregroundStyle(.secondary) }
                        if selected != nil {
                            Button("显示当前") { selected = nil; recomputeConns() }
                                .font(.caption.weight(.semibold)).buttonStyle(.borderless)
                                .accessibilityIdentifier("network.clearSelection")
                        }
                    }
                }
                .padding(.vertical, 4)
            } footer: {
                Text("只在 App 打开且已连接时采样，没有采样的时段留空（不补画）。分钟、小时是该时段内已采样秒的平均速度；App 退出后清空。按住图表左右拖动查看某一时刻。")
            }
            .listRowBackground(Theme.card)

            Section {
                if conns.isEmpty {
                    Text(LocalizedStringKey(selected == nil ? "没有连接" : "这一时刻没有记录到的连接"))
                        .font(.footnote).foregroundStyle(.secondary)
                        .listRowBackground(Theme.card)
                }
                ForEach(conns.prefix(Self.connLimit)) { c in
                    NavigationLink { ConnectionDetailView(c: c, model: model) } label: { ConnectionRow(c: c) }
                        .listRowBackground(Theme.card)
                        .accessibilityIdentifier("network.conn")
                }
                NavigationLink { ConnectionsListView(filter: ConnFilter()) } label: {
                    Label("全部连接", systemImage: "list.bullet")
                }
                .listRowBackground(Theme.card)
                .accessibilityIdentifier("network.allConnections")
            } header: {
                Text(selected.map { String(localized: "\(timeText($0.t)) 的连接") } ?? String(localized: "连接"))
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("网络")
        .onAppear { onScreen = true; start() }
        .onDisappear { onScreen = false; model.stop() }
        .onChange(of: scenePhase) { p in if p == .active { if onScreen { start() } } else { model.stop() } }
        .onChange(of: scale) { _ in selected = nil; rebuild(force: true); recomputeConns() }
        .onReceive(model.$active) { _ in recomputeConns() }
        .task {
            NetworkHistory.shared.fillDemoIfNeeded()
            while !Task.isCancelled {
                rebuild(force: false)
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
    }

    func start() {
        ConnectionFeedSource.seed(model)
        if !ConnectionFeedSource.demo && vpn.isConnected { model.start() } else { model.stop() }
        recomputeConns()
    }

    func rebuild(force: Bool) {
        let h = NetworkHistory.shared
        guard force || h.version != builtVersion || scale != builtScale else { return }
        // While scrubbing, the drawn data stays put (a new sample would shift the point under the finger).
        if selected != nil && !force && scale == builtScale { return }
        builtVersion = h.version
        builtScale = scale
        let p = h.points(scale: scale, proxy: proxyOnly)
        if p != points { points = p }
    }

    var bucketLength: TimeInterval { scale == 0 ? 1 : (scale == 1 ? 60 : 3600) }

    func timeText(_ d: Date) -> String {
        scale == 2 ? d.formatted(date: .omitted, time: .shortened) : d.formatted(date: .omitted, time: .standard)
    }

    @ViewBuilder var readout: some View {
        let shown = selected ?? points.last
        HStack(alignment: .firstTextBaseline, spacing: 16) {
            SpeedLabel(icon: "arrow.up", color: Theme.up, title: "上传", value: shown?.up ?? 0)
            SpeedLabel(icon: "arrow.down", color: Theme.down, title: "下载", value: shown?.down ?? 0)
            Spacer(minLength: 4)
            VStack(alignment: .trailing, spacing: 1) {
                if let s = shown {
                    Text(verbatim: timeText(s.t)).font(.caption.monospacedDigit())
                    if scale > 0 {
                        Text("已采样 \(s.n) 秒").font(.caption2).foregroundStyle(.secondary)
                    }
                } else {
                    Text("还没有采样").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("network.readout")
    }

    func legend(_ c: Color, _ t: LocalizedStringKey) -> some View {
        HStack(spacing: 4) {
            Circle().fill(c).frame(width: 7, height: 7)
            Text(t).font(.caption2)
        }
    }

    @ViewBuilder var chart: some View {
        if points.isEmpty {
            ZStack {
                RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Theme.ink(0.04))
                Text(LocalizedStringKey(vpn.isConnected || ConnectionFeedSource.demo ? "正在采样…" : "连接后开始采样"))
                    .font(.footnote).foregroundStyle(.secondary)
            }
        } else {
            Chart {
                ForEach(points) { p in
                    LineMark(x: .value("时间", p.t), y: .value("下载", Double(p.down)), series: .value("分段", "dl\(p.segment)"))
                        .foregroundStyle(Theme.down)
                        .lineStyle(StrokeStyle(lineWidth: 1.8))
                        .interpolationMethod(.monotone)
                    LineMark(x: .value("时间", p.t), y: .value("上传", Double(p.up)), series: .value("分段", "u\(p.segment)"))
                        .foregroundStyle(Theme.up)
                        .lineStyle(StrokeStyle(lineWidth: 1.3))
                        .interpolationMethod(.monotone)
                }
                if let s = selected {
                    RuleMark(x: .value("时间", s.t))
                        .foregroundStyle(Theme.ink(0.35))
                        .lineStyle(StrokeStyle(lineWidth: 1, dash: [3, 3]))
                    PointMark(x: .value("时间", s.t), y: .value("下载", Double(s.down)))
                        .foregroundStyle(Theme.down).symbolSize(30)
                    PointMark(x: .value("时间", s.t), y: .value("上传", Double(s.up)))
                        .foregroundStyle(Theme.up).symbolSize(24)
                }
            }
            .chartLegend(.hidden)
            .chartYAxis {
                AxisMarks(position: .leading, values: .automatic(desiredCount: 3)) { v in
                    AxisGridLine().foregroundStyle(Theme.ink(0.06))
                    AxisValueLabel {
                        if let d = v.as(Double.self) { Text(verbatim: Fmt.speed(Int64(d))).font(.caption2) }
                    }
                }
            }
            .chartXAxis {
                AxisMarks(values: .automatic(desiredCount: 4)) { v in
                    AxisValueLabel {
                        if let d = v.as(Date.self) { Text(verbatim: d.formatted(date: .omitted, time: .shortened)).font(.caption2) }
                    }
                }
            }
            .chartOverlay { proxy in
                GeometryReader { geo in
                    Rectangle().fill(Color.clear).contentShape(Rectangle())
                        .gesture(
                            DragGesture(minimumDistance: 0)
                                .onChanged { v in
                                    let x = v.location.x - geo[proxy.plotAreaFrame].origin.x
                                    guard let d: Date = proxy.value(atX: x) else { return }
                                    let near = points.min { abs($0.t.timeIntervalSince(d)) < abs($1.t.timeIntervalSince(d)) }
                                    if let near, near != selected {
                                        selected = near
                                        UISelectionFeedbackGenerator().selectionChanged()
                                    }
                                }
                                .onEnded { _ in recomputeConns() }
                        )
                }
            }
        }
    }

    /// Connections open at the chosen moment (or bucket); without a choice, the open ones now and the newest closed.
    func recomputeConns() {
        let active = model.active
        let closed = [model.recent, ConnectionFeedSource.analytics.closedItems]
        let sel = selected.map { ($0.t, $0.t.addingTimeInterval(bucketLength)) }
        job?.cancel()
        job = Task {
            let out = await Task.detached(priority: .userInitiated) { () -> [ConnectionItem] in
                let all = ConnFilter.merge(active: active, closed: closed)
                guard let (from, to) = sel else { return Array(all.prefix(200)) }
                return all.filter { c in
                    guard let s = c.startDate else { return false } // unknown start: can't say it was open then
                    return s < to && (c.closedAt ?? Date()) >= from
                }
            }.value
            guard !Task.isCancelled else { return }
            if out != conns { conns = out }
        }
    }
}

// MARK: - DNS (Home card)

/// Upstream share of the DNS answers the tunnel logged since it connected (GET /hark/logs kind dns, read
/// incrementally every 10 s while Home is on screen with the card added). Same lines as DNS 日志; parsing runs off
/// the main thread.
@MainActor
final class HomeDNSModel {
    static let shared = HomeDNSModel()

    struct Share: Equatable, Identifiable { let name: String; let count: Int; var id: String { name } }
    struct Snap: Equatable {
        var total = 0
        var cached = 0
        var failed = 0
        var top: [Share] = []
    }

    @Published private(set) var snap = Snap()
    private var seq: UInt64 = 0
    private var counts: [String: Int] = [:]
    private var cached = 0
    private var failed = 0
    private var polling = false

    static let cacheKey = "\u{1}cache"

    func poll() async {
        if HomeAnalysisModel.demo { applyDemo(); return }
        guard !polling, VPNManager.shared.isConnected, HomeAnalysisModel.shared.homeActive else { return }
        polling = true
        defer { polling = false }
        guard let h = try? await ControllerClient.shared.harkLogs(kind: "dns", since: seq) else { return }
        if h.seq < seq { reset() } // a new tunnel started its log over
        let lines = (h.logs ?? []).map(\.payload)
        seq = max(seq, h.seq)
        guard !lines.isEmpty else { return }
        let delta = await Task.detached(priority: .utility) { Self.parse(lines) }.value
        for (k, v) in delta.upstreams { counts[k, default: 0] += v }
        cached += delta.cached
        failed += delta.failed
        publish()
    }

    func reset() { seq = 0; counts = [:]; cached = 0; failed = 0; publish() }

    private func publish() {
        var s = Snap()
        var all = counts
        if cached > 0 { all[Self.cacheKey] = cached }
        s.cached = cached
        s.failed = failed
        s.total = all.values.reduce(0, +) + failed
        let sorted = all.sorted { $0.value != $1.value ? $0.value > $1.value : $0.key < $1.key }
        s.top = sorted.prefix(4).map { Share(name: $0.key, count: $0.value) }
        let rest = sorted.dropFirst(4).reduce(0) { $0 + $1.value }
        if rest > 0 { s.top.append(Share(name: "\u{1}other", count: rest)) }
        if s != snap { snap = s }
    }

    private func applyDemo() {
        guard snap.total == 0 else { return }
        counts = ["1.1.1.1": 41, "223.5.5.5": 26, "8.8.8.8": 9]
        cached = 18
        failed = 1
        publish()
    }

    struct Delta: Sendable { var upstreams: [String: Int] = [:]; var cached = 0; var failed = 0 }

    nonisolated static func parse(_ lines: [String]) -> Delta {
        var d = Delta()
        for l in lines where l.hasPrefix("[DNS]") {
            if l.hasPrefix("[DNS] cache hit ") { d.cached += 1; continue }
            if l.hasPrefix("[DNS] resolve "), l.contains(" error: ") { d.failed += 1; continue }
            guard let r = l.range(of: " from ", options: .backwards) else { continue }
            let up = String(l[r.upperBound...]).trimmingCharacters(in: .whitespaces)
            d.upstreams[upstreamLabel(up), default: 0] += 1
        }
        return d
    }

    /// 「https://1.1.1.1/dns-query」 → 1.1.1.1; 「tls://dns.google:853」 → dns.google; plain addresses unchanged.
    nonisolated static func upstreamLabel(_ s: String) -> String {
        if let u = URL(string: s), let h = u.host, !h.isEmpty { return h }
        return s
    }

    static func displayName(_ key: String) -> String {
        switch key {
        case cacheKey: return String(localized: "缓存")
        case "\u{1}other": return String(localized: "其他")
        default: return key
        }
    }
}

struct HomeDNSCard: View {
    let collapsed: Bool
    let toggle: () -> Void
    @State private var snap = HomeDNSModel.shared.snap

    var body: some View {
        let colors = AnalyticsView.palette
        VStack(spacing: 10) {
            HomeSectionLabel(title: HomeAnalysisCard.dns.title, summary: snap.total > 0 ? String(localized: "\(snap.total) 次查询") : nil,
                             collapsed: collapsed, id: "home.analysis.header.dns", toggle: toggle)
            if !collapsed {
                NavigationLink { LazyDestination { DNSLogView() } } label: {
                    HStack(spacing: 16) {
                        DonutChart(parts: snap.top.enumerated().map { i, s in (Double(s.count), colors[i % (colors.count - 1)]) })
                            .frame(width: 84, height: 84)
                            .accessibilityHidden(true)
                        VStack(alignment: .leading, spacing: 5) {
                            if snap.top.isEmpty {
                                Text("还没有 DNS 查询").font(.footnote).foregroundStyle(.secondary)
                            }
                            ForEach(Array(snap.top.enumerated()), id: \.element.id) { i, s in
                                HStack(spacing: 6) {
                                    Circle().fill(colors[i % (colors.count - 1)]).frame(width: 7, height: 7)
                                    Text(verbatim: HomeDNSModel.displayName(s.name)).font(.caption).lineLimit(1).truncationMode(.middle)
                                    Spacer(minLength: 4)
                                    Text(verbatim: "\(s.count)").font(.caption.monospacedDigit())
                                    Text(Double(s.count) / Double(max(snap.total, 1)), format: .percent.precision(.fractionLength(0)))
                                        .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                                }
                                .accessibilityElement(children: .combine)
                            }
                            if snap.failed > 0 {
                                Text("\(snap.failed) 次失败").font(.caption2).foregroundStyle(Theme.bad)
                            }
                        }
                        CardChevron()
                    }
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: Theme.radius, style: .continuous).fill(Theme.card))
                    .contentShape(Rectangle())
                }
                .buttonStyle(PressableCardStyle())
                .accessibilityIdentifier("home.analysis.dns")
            }
        }
        .onReceive(HomeDNSModel.shared.$snap.removeDuplicates()) { if $0 != snap { snap = $0 } }
        .task {
            while !Task.isCancelled {
                await HomeDNSModel.shared.poll()
                try? await Task.sleep(nanoseconds: 10_000_000_000)
            }
        }
    }
}

/// Ring split into proportional coloured arcs (iOS 16 has no SectorMark).
struct DonutChart: View {
    let parts: [(Double, Color)]
    var body: some View {
        let total = max(parts.reduce(0) { $0 + $1.0 }, 0)
        ZStack {
            Circle().stroke(Theme.ink(0.08), lineWidth: 14)
            if total > 0 {
                ForEach(Array(parts.enumerated()), id: \.offset) { i, p in
                    let from = parts.prefix(i).reduce(0) { $0 + $1.0 } / total
                    let to = from + p.0 / total
                    Circle().trim(from: from, to: max(from, to - (parts.count > 1 ? 0.004 : 0)))
                        .stroke(p.1, style: StrokeStyle(lineWidth: 14, lineCap: .butt))
                        .rotationEffect(.degrees(-90))
                }
            }
        }
        .padding(7)
    }
}

// MARK: - 出口 IP detail

/// 出口 IP tile → the exit (through the proxy) and the direct IP (the device's own network) in full, with the lookup
/// source and time; refresh and copy. The same IPInfoModel the header and tile use — nothing is looked up twice.
struct ExitInfoDetailView: View {
    @EnvironmentObject var ip: IPInfoModel
    @EnvironmentObject var vpn: VPNManager

    var body: some View {
        List {
            section(title: "出口（经代理）", info: ip.exit, id: "exit")
            if vpn.isConnected { section(title: "直连（本机网络）", info: ip.direct, id: "direct") }
            Section {
                Button {
                    ip.scheduleRefresh()
                } label: {
                    HStack {
                        Label("重新查询", systemImage: "arrow.clockwise")
                        Spacer()
                        if ip.loading { ProgressView() }
                    }
                }
                .disabled(ip.loading)
                Button { ip.copy() } label: { Label("复制", systemImage: "doc.on.doc") }
                    .disabled(ip.exit == nil)
                NavigationLink { GeoCheckerView() } label: { Label("出口信息来源", systemImage: "slider.horizontal.3") }
            } footer: {
                if let d = ip.updatedAt { Text("更新于 \(d.formatted(date: .omitted, time: .standard))") }
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("出口 IP")
    }

    @ViewBuilder func section(title: LocalizedStringKey, info: IPInfo?, id: String) -> some View {
        Section {
            if let i = info {
                LabeledContent("IP") { Text(verbatim: i.ip).font(.callout.monospaced()).textSelection(.enabled) }
                    .accessibilityIdentifier("exitdetail.\(id).ip")
                LabeledContent("位置") { Text(verbatim: "\(i.flag) \(i.placeText)").lineLimit(2) }
                if let a = i.asn, !a.isEmpty { LabeledContent("ASN") { Text(verbatim: a).monospaced() } }
                if let o = i.org, !o.isEmpty { LabeledContent("运营商") { Text(verbatim: o).lineLimit(2) } }
                if let t = i.timezone, !t.isEmpty { LabeledContent("时区") { Text(verbatim: t) } }
                if let s = i.source, !s.isEmpty { LabeledContent("来源") { Text(verbatim: s).foregroundStyle(.secondary) } }
            } else {
                Text(LocalizedStringKey(ip.loading ? "正在查询…" : (ip.failed ? "查询失败" : "—"))).foregroundStyle(.secondary)
            }
        } header: {
            Text(title)
        }
        .listRowBackground(Theme.card)
    }
}
