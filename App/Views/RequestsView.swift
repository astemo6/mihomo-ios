import SwiftUI
import NetworkExtension

@MainActor
final class RequestsModel: ObservableObject {
    @Published var active: [ConnectionItem] = []
    @Published var recent: [ConnectionItem] = []   // closed connections, newest first
    @Published var paused = false
    /// v0.17 passive timeline records by connection id (kept for closed connections in 最近 too).
    @Published var timeline: [String: TimelineRecord] = [:]
    @Published var timelineResolution = 20
    /// v0.16 summary bar: core totals and the speed derived from them between polls.
    @Published var uploadTotal: Int64 = 0
    @Published var downloadTotal: Int64 = 0
    @Published var upSpeed: Int64 = 0
    @Published var downSpeed: Int64 = 0
    private var lastSample: (Date, Int64, Int64)?
    /// Simulator UI tests (-UITestSeed -UITestDemoConnections): synthetic connections, no controller.
    let demo = UITestSeed.enabled && UITestSeed.args.contains("-UITestDemoConnections")
    private var task: Task<Void, Never>?

    init() {
        if demo {
            active = UITestSeed.demoConnections()
            timeline = UITestSeed.demoTimeline()
            uploadTotal = 12_582_912; downloadTotal = 98_566_144; upSpeed = 24_576; downSpeed = 1_310_720
        }
    }

    var tcpCount: Int { active.filter { ($0.metadata.network ?? "tcp").lowercased() != "udp" }.count }
    var udpCount: Int { active.filter { ($0.metadata.network ?? "").lowercased() == "udp" }.count }

    func start() {
        guard !demo else { return }
        task?.cancel()
        task = Task { [weak self] in
            while !Task.isCancelled {
                if self?.paused == false { await self?.poll() }
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
    }

    func stop() { task?.cancel(); task = nil; lastSample = nil }

    private func poll() async {
        guard let r = try? await ControllerClient.shared.connections() else { return }
        let now = r.connections ?? []
        let up = r.uploadTotal ?? 0, down = r.downloadTotal ?? 0
        let t = Date()
        // fix/bg-chart: only between polls a second or so apart. After the app was in the background (or
        // paused) the gap is long, and a speed averaged over it would be a made-up number.
        if let last = lastSample, t.timeIntervalSince(last.0) > 0.2, t.timeIntervalSince(last.0) <= SpeedSeries.maxGap {
            let dt = t.timeIntervalSince(last.0)
            upSpeed = max(0, Int64(Double(up - last.1) / dt))
            downSpeed = max(0, Int64(Double(down - last.2) / dt))
        }
        lastSample = (t, up, down)
        uploadTotal = up
        downloadTotal = down
        let ids = Set(now.map(\.id))
        let closed = active.filter { !ids.contains($0.id) }.map { c -> ConnectionItem in
            var c = c; c.closedAt = Date(); return c
        }
        if !closed.isEmpty {
            recent.insert(contentsOf: closed, at: 0)
            if recent.count > 300 { recent.removeLast(recent.count - 300) }
        }
        active = now.sorted { ($0.startDate ?? .distantPast) > ($1.startDate ?? .distantPast) }
        await pollTimeline()
    }

    /// Renews the core's 20 s watch lease and merges its records; ids no longer listed anywhere are dropped.
    private func pollTimeline() async {
        guard let t = try? await TimelineAPI.conns() else { return }
        if let r = t.resolutionMs { timelineResolution = r }
        var merged = timeline
        for r in t.records ?? [] { merged[r.id] = r }
        let keep = Set(active.map(\.id)).union(recent.map(\.id))
        if merged.count > 700 { merged = merged.filter { keep.contains($0.key) } }
        timeline = merged
    }

    func close(_ c: ConnectionItem) async {
        if demo { active.removeAll { $0.id == c.id }; return }
        try? await ControllerClient.shared.closeConnection(c.id)
        await poll()
    }

    func closeAll() async {
        if demo { recent.insert(contentsOf: active, at: 0); active = []; upSpeed = 0; downSpeed = 0; return }
        try? await ControllerClient.shared.closeAllConnections()
        await poll()
    }
}

struct RequestsView: View {
    @State private var quickRule: ConnectionItem?
    @EnvironmentObject var vpn: VPNManager
    @StateObject private var model = RequestsModel()
    @StateObject private var http = HTTPLogModel()
    @State private var search = ""
    @State private var tab = 0
    @State private var confirmCloseAll = false
    @State private var harProgress: (Int, Int)?
    @State private var harShare: ShareItem?
    @State private var harError: String?
    @Environment(\.scenePhase) private var scenePhase
    @State private var onScreen = false

    var items: [ConnectionItem] {
        let list = tab == 0 ? model.active : model.recent
        guard !search.isEmpty else { return list }
        let q = search.lowercased()
        return list.filter {
            $0.metadata.displayHost.lowercased().contains(q) ||
            $0.chainText.lowercased().contains(q) ||
            $0.ruleText.lowercased().contains(q)
        }
    }

    /// v0.17 主机: active + recent grouped by host (search filters hosts and their policies).
    var hostItems: [HostAggregate] {
        let all = HostAggregate.build(active: model.active, recent: model.recent, timeline: model.timeline)
        guard !search.isEmpty else { return all }
        return all.filter { $0.host.localizedCaseInsensitiveContains(search) || $0.policies.joined().localizedCaseInsensitiveContains(search) }
    }

    var httpItems: [HTTPRequestSummary] {
        guard !search.isEmpty else { return http.items }
        return http.items.filter { $0.url.localizedCaseInsensitiveContains(search) || ($0.matched ?? []).joined().localizedCaseInsensitiveContains(search) }
    }

    var body: some View {
        NavigationStack {
            Group {
                if !vpn.isConnected && !model.demo {
                    NotConnectedPlaceholder(text: "连接后可查看实时请求")
                } else {
                    List {
                        ConnectionSummaryBar(model: model) { confirmCloseAll = true }
                            .listRowInsets(EdgeInsets())
                            .listRowBackground(Color.clear)
                        if model.paused {
                            PausedChip(id: "requests.paused") { model.paused = false }
                                .listRowInsets(EdgeInsets(top: 2, leading: 4, bottom: 2, trailing: 4))
                                .listRowBackground(Color.clear)
                        }
                        Picker("", selection: $tab) {
                            Text("活跃 \(model.active.count)").tag(0)
                            Text("最近 \(model.recent.count)").tag(1)
                            Text("HTTP \(http.items.count)").tag(2)
                            Text("主机").tag(3)
                        }
                        .pickerStyle(.segmented)
                        .listRowBackground(Color.clear)
                        if tab == 2 {
                            if http.items.isEmpty {
                                EmptyStateRow(icon: "lock.open", title: "还没有 HTTP 请求",
                                              message: "经过 MitM / 重写引擎的 HTTP(S) 请求会显示在这里。需要在 工具 → 重写 开启重写与脚本，并在 工具 → HTTPS 解密 中开启。")
                                    .listRowBackground(Theme.card)
                            }
                            ForEach(httpItems) { r in
                                NavigationLink { HTTPRequestDetailView(id: r.id) } label: { HTTPRequestRow(r: r) }
                                    .listRowBackground(Theme.card)
                            }
                        }
                        if tab == 3 {
                            if hostItems.isEmpty {
                                EmptyStateRow(icon: "server.rack", title: "还没有连接")
                                    .listRowBackground(Theme.card)
                            }
                            ForEach(hostItems) { h in
                                NavigationLink { HostConnectionsView(host: h.host, model: model) } label: { HostAggregateRow(h: h) }
                                    .listRowBackground(Theme.card)
                            }
                        }
                        ForEach(tab >= 2 ? [] : items) { c in
                            NavigationLink { ConnectionDetailView(c: c, model: model) } label: {
                                ConnectionRow(c: c, engineMarks: http.hosts[c.metadata.host ?? ""] ?? http.hosts[c.metadata.sniffHost ?? ""])
                            }
                                .listRowBackground(Theme.card)
                                .contextMenu {
                                    // v0.12: 从连接一键加规则.
                                    Button { quickRule = c } label: { Label("添加规则…", systemImage: "plus.rectangle.on.rectangle") }
                                    if let h = c.metadata.host ?? c.metadata.sniffHost, !h.isEmpty {
                                        Button { UIPasteboard.general.string = h } label: { Label("拷贝主机", systemImage: "doc.on.doc") }
                                    }
                                }
                                .swipeActions {
                                    if tab == 0 {
                                        Button(role: .destructive) { Task { await model.close(c) } } label: { Label("断开", systemImage: "xmark") }
                                    }
                                }
                        }
                    }
                    .listStyle(.insetGrouped)
                    .scrollContentBackground(.hidden)
                    .searchable(text: $search, placement: .navigationBarDrawer(displayMode: .always), prompt: "搜索主机、规则、策略")
                }
            }
            .background(Theme.bg.ignoresSafeArea())
            .tabRootChrome("请求")
            .toolbar {
                ToolbarItemGroup(placement: .navigationBarTrailing) {
                    PauseToggleButton(paused: $model.paused, id: "requests.pause")
                    if tab == 2 {
                        Button { exportHAR() } label: { Image(systemName: "square.and.arrow.up") }
                            .disabled(httpItems.isEmpty || harProgress != nil)
                            .accessibilityLabel(Text("导出 HAR"))
                        Button(role: .destructive) { Task { await http.clear() } } label: { Image(systemName: "trash") }
                    }
                }
            }
            .sheet(item: $quickRule) { c in QuickRuleSheet(conn: c) }
            .confirmationDialog("断开全部连接？", isPresented: $confirmCloseAll, titleVisibility: .visible) {
                Button("全部断开", role: .destructive) { Task { await model.closeAll() } }
            }
            .overlay(alignment: .bottom) {
                if let p = harProgress {
                    HStack(spacing: 10) {
                        ProgressView()
                        Text("正在导出 HAR \(p.0)/\(p.1)").font(.footnote.monospacedDigit())
                    }
                    .padding(.horizontal, 16).padding(.vertical, 10)
                    .background(Capsule().fill(Theme.cardHi))
                    .padding(.bottom, 12)
                }
            }
            .sheet(item: $harShare) { ActivityView(items: [$0.url]) }
            .alert("导出失败", isPresented: Binding(get: { harError != nil }, set: { if !$0 { harError = nil } })) {
                Button("好") { harError = nil }
            } message: { Text(harError ?? "") }
        }
        .onAppear { onScreen = true; if vpn.isConnected { model.start(); http.start() } }
        .onDisappear { onScreen = false; model.stop(); http.stop() }
        .onChange(of: vpn.isConnected) { on in if on { model.start(); http.start() } else { model.stop(); http.stop() } }
        // fix/bg-chart: nothing polls while the app is not on screen; on return the speed restarts from fresh samples.
        .onChange(of: scenePhase) { p in
            if p == .active { if onScreen && vpn.isConnected { model.start(); http.start() } } else { model.stop(); http.stop() }
        }
    }
}

extension RequestsView {
    /// HAR 1.2 of the HTTP requests currently listed (search filter applies).
    func exportHAR() {
        let ids = httpItems.filter { $0.method != "TLS" }.map(\.id)
        guard !ids.isEmpty else { return }
        harProgress = (0, ids.count)
        Task {
            do {
                let url = try await HARExport.export(ids: ids) { done, total in harProgress = (done, total) }
                harProgress = nil
                harShare = ShareItem(url: url)
            } catch {
                harProgress = nil
                harError = error.localizedDescription
            }
        }
    }
}

struct ConnectionRow: View {
    let c: ConnectionItem
    /// Rules / scripts the HTTP engine matched for this host (nil = not seen by the engine).
    var engineMarks: [String]? = nil
    var isMitM: Bool { (c.chains ?? []).contains("__MITM__") }
    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 6) {
                Text((c.metadata.network ?? "tcp").uppercased())
                    .scaledFont(9, weight: .bold)
                    .padding(.horizontal, 5).padding(.vertical, 2)
                    .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
                    .background(Capsule().fill((c.metadata.network == "udp" ? Theme.tone(0.55, 0.45, 1.0) : Theme.accent).opacity(0.2)))
                if isMitM {
                    Text(c.metadata.destinationPort == "80" ? "HTTP" : "MitM")
                        .scaledFont(9, weight: .bold)
                        .padding(.horizontal, 5).padding(.vertical, 2)
                        .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
                        .background(Capsule().fill(Theme.warn.opacity(0.2)))
                        .foregroundStyle(Theme.warn)
                }
                Text(c.metadata.displayHost)
                    .font(.system(.subheadline, design: .monospaced))
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            if isMitM, let m = engineMarks, !m.isEmpty {
                Text(m.joined(separator: " · ")).font(.caption2).foregroundStyle(Theme.accent).lineLimit(2)
            }
            HStack(spacing: 6) {
                // fix/rule-labels: human rule type + payload and policy names (RuleDisplay) — the engine's own rule and
                // outbound read 「重写 · HTTP 明文（端口 80）」 / 「重写引擎」, never the logical rule text or 「__MITM__」.
                if let r = c.rule, !r.isEmpty {
                    let parts = RuleDisplay.describe(type: r, payload: c.rulePayload, policy: c.chains?.first)
                    if !parts.type.isEmpty { RuleTypeTag(type: parts.type, key: parts.key) }
                    Text(verbatim: parts.primary).lineLimit(1).truncationMode(.middle).foregroundStyle(.secondary)
                }
                Spacer(minLength: 4)
                if !c.chainText.isEmpty { PolicyChip(name: RuleDisplay.chainText(c.chains)) }
            }
            .font(.caption)
            HStack(spacing: 10) {
                Label(Fmt.bytes(c.upload), systemImage: "arrow.up").foregroundStyle(Theme.up)
                Label(Fmt.bytes(c.download), systemImage: "arrow.down").foregroundStyle(Theme.down)
                Spacer()
                if let s = c.startDate {
                    Text(Fmt.duration((c.closedAt ?? Date()).timeIntervalSince(s)))
                        .foregroundStyle(.secondary)
                }
                if c.closedAt != nil {
                    Text("已关闭").foregroundStyle(.secondary)
                }
            }
            .font(.caption2.monospacedDigit())
        }
        .padding(.vertical, 2)
    }
}

/// 添加规则 from a connection (v0.12): DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR + a policy, saved
/// as a 自定义规则 (rules.json, checked before the profile's rules) and applied with a reload.
struct QuickRuleSheet: View {
    @Environment(\.dismiss) private var dismiss
    let conn: ConnectionItem
    @ObservedObject private var store = CustomRulesStore.shared
    @ObservedObject private var insp = ProfileInspector.shared
    @State private var type = "DOMAIN-SUFFIX"
    @State private var value = ""
    @State private var policy = "DIRECT"

    private var host: String { conn.metadata.host ?? conn.metadata.sniffHost ?? "" }
    private var ip: String { conn.metadata.destinationIP ?? "" }
    private var policies: [String] {
        var out = ["DIRECT", "REJECT"]
        for g in insp.result.groups where g.hidden != true && !out.contains(g.name) { out.append(g.name) }
        if let last = conn.chains?.last, !last.isEmpty, !out.contains(last), last != "__MITM__" { out.append(last) }
        return out
    }
    private var line: String {
        let v = value.trimmingCharacters(in: .whitespaces)
        return type == "IP-CIDR" ? "IP-CIDR,\(v.contains("/") ? v : v + (v.contains(":") ? "/128" : "/32")),\(policy),no-resolve" : "\(type),\(v),\(policy)"
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("类型", selection: $type) {
                        if !host.isEmpty {
                            Text("域名后缀").tag("DOMAIN-SUFFIX")
                            Text("完整域名").tag("DOMAIN")
                            Text("域名关键词").tag("DOMAIN-KEYWORD")
                        }
                        if !ip.isEmpty { Text("IP 段").tag("IP-CIDR") }
                    }
                    TextField("值", text: $value).textInputAutocapitalization(.never).autocorrectionDisabled()
                        .font(.body.monospaced())
                    Picker("策略", selection: $policy) {
                        ForEach(policies, id: \.self) { Text(verbatim: $0).tag($0) }
                    }
                } footer: {
                    Text(verbatim: line).font(.caption.monospaced())
                }
                .listRowBackground(Theme.card)
                Section {
                    Text("规则加入「工具 → 分流规则 → 自定义规则」，优先于配置文件里的规则；连接中会立即重载。")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                .listRowBackground(Color.clear)
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("添加规则")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("添加") {
                        store.rules.insert(CustomRule(line: line), at: 0)
                        store.save()
                        dismiss()
                    }
                    .disabled(value.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
            .task {
                if host.isEmpty { type = "IP-CIDR" }
                value = type == "IP-CIDR" ? ip : Self.suffix(of: host)
                if let last = conn.chains?.last, policies.contains(last) { policy = last }
                if insp.result.groups.isEmpty { await insp.load() }
            }
            .onChange(of: type) { t in
                value = t == "IP-CIDR" ? ip : (t == "DOMAIN-SUFFIX" ? Self.suffix(of: host) : host)
            }
        }
        .presentationDetents([.medium, .large])
    }

    /// "a.b.example.co.uk" → "example.co.uk"; "www.google.com" → "google.com" (simple 2/3-label heuristic).
    static func suffix(of host: String) -> String {
        let parts = host.split(separator: ".")
        guard parts.count > 2, Int(parts.last ?? "") == nil else { return host }
        let sld = parts[parts.count - 2]
        let n = (sld.count <= 3 && parts.last!.count == 2) ? 3 : 2
        return parts.suffix(n).joined(separator: ".")
    }
}

/// v0.16 请求 summary: TCP / UDP counts, ↑↓ speed, session totals and 全部断开 (moved here from the toolbar).
struct ConnectionSummaryBar: View {
    @ObservedObject var model: RequestsModel
    let onCloseAll: () -> Void

    var body: some View {
        Card(padding: 14) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .firstTextBaseline, spacing: 18) {
                    count("TCP", model.tcpCount, Theme.accent, id: "requests.tcpCount")
                    count("UDP", model.udpCount, Theme.tone(0.55, 0.45, 1.0), id: "requests.udpCount")
                    Spacer(minLength: 6)
                    Button(role: .destructive, action: onCloseAll) {
                        Label("全部断开", systemImage: "xmark.circle")
                            .font(.footnote.weight(.semibold))
                    }
                    .buttonStyle(.bordered)
                    .tint(Theme.bad)
                    .controlSize(.small)
                    .disabled(model.active.isEmpty)
                    .accessibilityIdentifier("requests.closeAll")
                }
                HStack(spacing: 14) {
                    rate("arrow.up", Theme.up, model.upSpeed, model.uploadTotal)
                    rate("arrow.down", Theme.down, model.downSpeed, model.downloadTotal)
                    Spacer(minLength: 0)
                }
            }
        }
    }

    private func count(_ title: String, _ n: Int, _ color: Color, id: String) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(verbatim: "\(n)")
                .font(.system(size: 26, weight: .semibold, design: .rounded).monospacedDigit())
                .foregroundStyle(color)
                .accessibilityIdentifier(id)
            Text(verbatim: title).font(.caption2.weight(.semibold)).foregroundStyle(.secondary)
        }
    }

    private func rate(_ icon: String, _ color: Color, _ speed: Int64, _ total: Int64) -> some View {
        HStack(spacing: 6) {
            Image(systemName: icon).font(.caption.bold()).foregroundStyle(color)
            VStack(alignment: .leading, spacing: 0) {
                Text(verbatim: Fmt.speed(speed)).font(.subheadline.monospacedDigit().weight(.medium))
                Text(verbatim: "Σ " + Fmt.bytes(total)).font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
            }
        }
    }
}
