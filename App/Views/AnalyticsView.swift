import SwiftUI

/// 连接分析 (v0.7, Egern-style analytics, NOT on Home): traffic per policy, rule hit counts and top hosts,
/// accumulated in the app from the /connections snapshots DashboardModel already polls every 2 s.
/// Nothing runs in the Network Extension, so its memory budget is untouched. Session-scoped: resets
/// when the tunnel disconnects (or from the toolbar).
@MainActor
final class ConnectionAnalytics: ObservableObject {
    static let shared = ConnectionAnalytics()

    struct Bytes: Equatable { var up: Int64 = 0; var down: Int64 = 0; var total: Int64 { up + down } }
    struct Usage: Identifiable { var id: String { name }; let name: String; let bytes: Bytes }
    struct RuleHit: Identifiable, Equatable {
        var id: String { rule + "\u{1}" + policy }
        let rule: String
        let policy: String
        var hits: Int
    }

    @Published private(set) var policies: [String: Bytes] = [:]
    @Published private(set) var rules: [String: RuleHit] = [:]
    @Published private(set) var hosts: [String: Bytes] = [:]
    @Published private(set) var totalConnections = 0
    @Published private(set) var activeConnections = 0
    @Published private(set) var since = Date()

    private var last: [String: (up: Int64, down: Int64)] = [:]
    /// feat/home-analysis: the UI-test demo instance never writes the saved day history.
    var recordsHistory = true
    private static let hostCap = 600

    func reset() {
        policies = [:]; rules = [:]; hosts = [:]; last = [:]
        totalConnections = 0; activeConnections = 0; since = Date()
    }

    func ingest(_ conns: [ConnectionItem]) {
        var seen: [String: (up: Int64, down: Int64)] = [:]
        seen.reserveCapacity(conns.count)
        var pol = policies, hs = hosts, rs = rules
        var newCount = 0
        var stepPol: [String: Bytes] = [:], stepHost: [String: Bytes] = [:]
        for c in conns {
            let policy = c.chains?.last ?? "DIRECT"
            let prev = last[c.id]
            if prev == nil {
                newCount += 1
                let rule = c.ruleText.isEmpty ? "—" : c.ruleText
                let key = rule + "\u{1}" + policy
                rs[key, default: RuleHit(rule: rule, policy: policy, hits: 0)].hits += 1
            }
            let du = max(0, c.upload - (prev?.up ?? 0))
            let dd = max(0, c.download - (prev?.down ?? 0))
            if du > 0 || dd > 0 {
                pol[policy, default: Bytes()].up += du
                pol[policy, default: Bytes()].down += dd
                let h = Self.hostName(c.metadata)
                hs[h, default: Bytes()].up += du
                hs[h, default: Bytes()].down += dd
                stepPol[policy, default: Bytes()].up += du
                stepPol[policy, default: Bytes()].down += dd
                stepHost[h, default: Bytes()].up += du
                stepHost[h, default: Bytes()].down += dd
            }
            seen[c.id] = (c.upload, c.download)
        }
        if hs.count > Self.hostCap * 2 {
            let keep = hs.sorted { $0.value.total > $1.value.total }.prefix(Self.hostCap)
            hs = Dictionary(uniqueKeysWithValues: keep.map { ($0.key, $0.value) })
        }
        last = seen
        policies = pol; hosts = hs; rules = rs
        if recordsHistory { AnalyticsHistory.shared.add(policies: stepPol, hosts: stepHost) }
        totalConnections += newCount
        activeConnections = conns.count
    }

    static func hostName(_ m: ConnectionMetadata) -> String {
        if let h = m.host, !h.isEmpty { return h }
        if let h = m.sniffHost, !h.isEmpty { return h }
        return m.destinationIP ?? "?"
    }

    var policyList: [Usage] {
        policies.map { Usage(name: $0.key, bytes: $0.value) }.filter { $0.bytes.total > 0 }.sorted { $0.bytes.total > $1.bytes.total }
    }
    var ruleList: [RuleHit] { rules.values.sorted { $0.hits > $1.hits } }
    var hostList: [Usage] {
        hosts.map { Usage(name: $0.key, bytes: $0.value) }.sorted { $0.bytes.total > $1.bytes.total }
    }
}

struct AnalyticsView: View {
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var a = ConnectionAnalytics.shared
    @ObservedObject private var history = AnalyticsHistory.shared
    /// 0 = 本次连接 (session), otherwise the last N days from the saved history (v0.8).
    @AppStorage("analytics.range") private var range = 0
    @State private var netDays: [TrafficDay] = []
    @State private var confirmClear = false

    static let palette: [Color] = [Theme.accent, Theme.up, Theme.good, Theme.tone(0.62, 0.48, 1.0),
                                   Theme.tone(1.0, 0.42, 0.62), Theme.warn, Theme.neutral]

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                Picker("范围", selection: $range) {
                    Text("本次连接").tag(0)
                    Text("今天").tag(1)
                    Text("7 天").tag(7)
                    Text("30 天").tag(30)
                }
                .pickerStyle(.segmented)
                if range == 0 && !vpn.isConnected && a.totalConnections == 0 {
                    NotConnectedPlaceholder(text: "连接后开始统计")
                } else {
                    if range == 0 { tiles }
                    splitCard
                    policyCard
                    if range == 0 { rulesCard }
                    hostsCard
                    Text(range == 0
                         ? String(localized: "从本次连接开始（\(a.since.formatted(date: .omitted, time: .shortened))）统计，数据只在 App 打开时采样，断开后清零。")
                         : String(localized: "直连 / 代理、策略与主机名来自 App 打开期间的采样，按天保存（最多 90 天）；Wi-Fi / 蜂窝来自隧道每 2 分钟记录的全部流量。规则命中只统计本次连接。"))
                        .font(.caption2).foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 4)
                }
            }
            .padding(16)
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("连接分析")
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Menu {
                    Button { a.reset() } label: { Label("清零本次连接", systemImage: "arrow.counterclockwise") }
                    Button(role: .destructive) { confirmClear = true } label: { Label("清除历史", systemImage: "trash") }
                } label: { Image(systemName: "arrow.counterclockwise") }
                .accessibilityLabel(Text("清零"))
            }
        }
        .confirmationDialog("清除保存的连接分析历史？", isPresented: $confirmClear, titleVisibility: .visible) {
            Button("清除历史", role: .destructive) { history.clear() }
        }
        .onAppear { netDays = TrafficHistory.load() }
    }

    /// Policy usage for the chosen range.
    var policyUsages: [ConnectionAnalytics.Usage] {
        if range == 0 { return a.policyList }
        return history.summary(lastDays: range).policies
            .map { ConnectionAnalytics.Usage(name: $0.key, bytes: ConnectionAnalytics.Bytes(up: $0.value.up, down: $0.value.down)) }
            .filter { $0.bytes.total > 0 }.sorted { $0.bytes.total > $1.bytes.total }
    }

    var hostUsages: [ConnectionAnalytics.Usage] {
        if range == 0 { return a.hostList }
        return history.summary(lastDays: range).hosts
            .map { ConnectionAnalytics.Usage(name: $0.key, bytes: ConnectionAnalytics.Bytes(up: $0.value.up, down: $0.value.down)) }
            .sorted { $0.bytes.total > $1.bytes.total }
    }

    /// 直连 vs 代理 (from the policy usage) and Wi-Fi vs 蜂窝 (from the tunnel's daily totals).
    var splitCard: some View {
        var direct: Int64 = 0, proxy: Int64 = 0
        for u in policyUsages where !AnalyticsHistory.skipNames.contains(u.name) {
            if AnalyticsHistory.directNames.contains(u.name) { direct += u.bytes.total } else { proxy += u.bytes.total }
        }
        let net = TrafficHistory.recent(max(range, 1), from: netDays)
        let wifi = net.reduce(Int64(0)) { $0 + ($1.wifi ?? 0) }
        let cell = net.reduce(Int64(0)) { $0 + ($1.cell ?? 0) }
        let other = net.reduce(Int64(0)) { $0 + $1.otherNet }
        return Card {
            VStack(alignment: .leading, spacing: 14) {
                Text("流量构成").font(.headline)
                SplitBar(title: String(localized: "直连 / 代理"),
                         parts: [(String(localized: "直连"), direct, Theme.good), (String(localized: "代理"), proxy, Theme.accent)])
                SplitBar(title: range == 0 ? String(localized: "Wi-Fi / 蜂窝（今天）") : String(localized: "Wi-Fi / 蜂窝"),
                         parts: [("Wi-Fi", wifi, Theme.accent), (String(localized: "蜂窝"), cell, Theme.up), (String(localized: "其他 / 未区分"), other, Theme.neutral)])
            }
        }
    }

    var tiles: some View {
        HStack(spacing: 12) {
            StatTile(icon: "point.3.connected.trianglepath.dotted", color: Theme.accent, title: "全部连接", value: "\(a.totalConnections)")
            StatTile(icon: "bolt.horizontal.fill", color: Theme.good, title: "活跃连接", value: "\(a.activeConnections)")
        }
    }

    var policyCard: some View {
        let list = policyUsages
        let total = max(list.reduce(Int64(0)) { $0 + $1.bytes.total }, 1)
        let shown = Array(list.prefix(6))
        let rest = list.dropFirst(6).reduce(Int64(0)) { $0 + $1.bytes.total }
        return Card {
            VStack(alignment: .leading, spacing: 12) {
                Text("策略").font(.headline)
                if list.isEmpty {
                    Text("还没有流量").font(.footnote).foregroundStyle(.secondary)
                } else {
                    GeometryReader { geo in
                        HStack(spacing: 2) {
                            ForEach(Array(shown.enumerated()), id: \.offset) { i, p in
                                Rectangle().fill(Self.palette[i % Self.palette.count])
                                    .frame(width: max(2, geo.size.width * CGFloat(Double(p.bytes.total) / Double(total)) - 2))
                            }
                            if rest > 0 {
                                Rectangle().fill(Self.palette.last ?? .gray)
                                    .frame(width: max(2, geo.size.width * CGFloat(Double(rest) / Double(total)) - 2))
                            }
                        }
                        .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                    }
                    .frame(height: 14)
                    .accessibilityHidden(true)
                    VStack(spacing: 8) {
                        ForEach(Array(shown.enumerated()), id: \.offset) { i, p in
                            legendRow(color: Self.palette[i % Self.palette.count], name: p.name, bytes: p.bytes, share: Double(p.bytes.total) / Double(total))
                        }
                        if rest > 0 {
                            legendRow(color: Self.palette.last ?? .gray, name: String(localized: "其他"), bytes: ConnectionAnalytics.Bytes(up: 0, down: rest), share: Double(rest) / Double(total))
                        }
                    }
                }
            }
        }
    }

    func legendRow(color: Color, name: String, bytes: ConnectionAnalytics.Bytes, share: Double) -> some View {
        HStack(spacing: 8) {
            Circle().fill(color).frame(width: 8, height: 8).accessibilityHidden(true)
            Text(name).font(.subheadline).lineLimit(1)
            Spacer()
            Text(Fmt.bytes(bytes.total)).font(.caption.monospacedDigit())
            Text(share.formatted(.percent.precision(.fractionLength(0)))).font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                .frame(width: 40, alignment: .trailing)
        }
    }

    var rulesCard: some View {
        let list = a.ruleList
        let maxHits = max(list.first?.hits ?? 1, 1)
        return Card {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("规则").font(.headline)
                    Spacer()
                    if list.count > 8 {
                        NavigationLink { RuleHitsList() } label: { Text("查看全部").font(.caption) }
                    }
                }
                if list.isEmpty {
                    Text("还没有命中记录").font(.footnote).foregroundStyle(.secondary)
                } else {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 10) {
                            ForEach(list.prefix(8)) { r in
                                VStack(alignment: .leading, spacing: 8) {
                                    ZStack {
                                        Circle().stroke(Theme.ink(0.08), lineWidth: 5)
                                        Circle().trim(from: 0, to: CGFloat(Double(r.hits) / Double(maxHits)))
                                            .stroke(Theme.accent, style: StrokeStyle(lineWidth: 5, lineCap: .round))
                                            .rotationEffect(.degrees(-90))
                                        Text("\(r.hits)").font(.caption.weight(.bold).monospacedDigit())
                                    }
                                    .frame(width: 46, height: 46)
                                    Text(r.rule).font(.caption2.monospaced()).lineLimit(2)
                                    Text(r.policy).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                                }
                                .frame(width: 128, alignment: .leading)
                                .padding(10)
                                .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Theme.cardHi))
                            }
                        }
                    }
                }
            }
        }
    }

    var hostsCard: some View {
        let list = hostUsages
        let maxB = max(list.first?.bytes.total ?? 1, 1)
        return Card {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("主机名").font(.headline)
                    Spacer()
                    if list.count > 10 {
                        NavigationLink { HostTrafficList(list: list) } label: { Text("查看全部").font(.caption) }
                    }
                }
                if list.isEmpty {
                    Text("还没有流量").font(.footnote).foregroundStyle(.secondary)
                } else {
                    ForEach(list.prefix(10)) { h in
                        HostBarRow(name: h.name, bytes: h.bytes.total, fraction: Double(h.bytes.total) / Double(maxB))
                    }
                }
            }
        }
    }
}

/// One labelled stacked bar with a legend (流量构成, v0.8).
struct SplitBar: View {
    let title: String
    let parts: [(String, Int64, Color)]

    var body: some View {
        let shown = parts.filter { $0.1 > 0 }
        let total = max(shown.reduce(Int64(0)) { $0 + $1.1 }, 1)
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(title).font(.subheadline)
                Spacer()
                Text(Fmt.bytes(shown.reduce(Int64(0)) { $0 + $1.1 })).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
            }
            GeometryReader { geo in
                HStack(spacing: 2) {
                    if shown.isEmpty {
                        Rectangle().fill(Theme.ink(0.06))
                    }
                    ForEach(Array(shown.enumerated()), id: \.offset) { _, p in
                        Rectangle().fill(p.2).frame(width: max(2, geo.size.width * CGFloat(Double(p.1) / Double(total)) - 2))
                    }
                }
                .clipShape(RoundedRectangle(cornerRadius: 5, style: .continuous))
            }
            .frame(height: 10)
            .accessibilityHidden(true)
            HStack(spacing: 12) {
                ForEach(Array(parts.enumerated()), id: \.offset) { _, p in
                    HStack(spacing: 4) {
                        Circle().fill(p.2).frame(width: 7, height: 7)
                        Text(p.0).font(.caption2)
                        Text(Double(p.1) / Double(total), format: .percent.precision(.fractionLength(0)))
                            .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                    }
                    .accessibilityElement(children: .combine)
                }
            }
        }
    }
}

struct HostBarRow: View {
    let name: String
    let bytes: Int64
    let fraction: Double
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(name).font(.footnote).lineLimit(1).truncationMode(.middle)
                Spacer()
                Text(Fmt.bytes(bytes)).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
            }
            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    Capsule().fill(Theme.ink(0.06))
                    Capsule().fill(Theme.accent.opacity(0.8)).frame(width: max(3, geo.size.width * CGFloat(fraction)))
                }
            }
            .frame(height: 4)
            .accessibilityHidden(true)
        }
    }
}

struct RuleHitsList: View {
    @ObservedObject private var a = ConnectionAnalytics.shared
    var body: some View {
        List(a.ruleList) { r in
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(r.rule).font(.footnote.monospaced()).lineLimit(2)
                    Text(r.policy).font(.caption2).foregroundStyle(.secondary)
                }
                Spacer()
                Text("\(r.hits)").font(.subheadline.weight(.semibold).monospacedDigit())
            }
            .listRowBackground(Theme.card)
        }
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("规则命中")
    }
}

struct HostTrafficList: View {
    let list: [ConnectionAnalytics.Usage]
    @State private var search = ""
    var body: some View {
        let maxB = max(list.first?.bytes.total ?? 1, 1)
        let shown = search.isEmpty ? list : list.filter { $0.name.localizedCaseInsensitiveContains(search) }
        List(shown) { h in
            HostBarRow(name: h.name, bytes: h.bytes.total, fraction: Double(h.bytes.total) / Double(maxB))
                .listRowBackground(Theme.card)
        }
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("主机名")
        .searchable(text: $search, placement: .navigationBarDrawer(displayMode: .always), prompt: "搜索主机名")
    }
}
