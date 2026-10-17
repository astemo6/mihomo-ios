import SwiftUI
import NetworkExtension

// QX 网络活动 panel + 流量 / 流速 + 阻止 list, fed by the /connections snapshots (DashboardModel polls every
// 2 s while connected; the panel polls every second while it is visible). App-side only: the Network
// Extension's memory budget is untouched.

struct QXRecord: Identifiable, Hashable {
    var id: String { conn.id }
    var conn: ConnectionItem
    /// Sequence number in order of first sight (QX shows "↪ 2102").
    let seq: Int

    var isUDP: Bool { conn.metadata.network?.lowercased() == "udp" }
    var leaf: String { conn.chains?.first ?? "DIRECT" }
    var policy: String { conn.chains?.last ?? "DIRECT" }
    var isRejected: Bool {
        let p = leaf.uppercased()
        return p.hasPrefix("REJECT") || (conn.chains ?? []).contains { $0.uppercased().hasPrefix("REJECT") }
    }
    /// "HOST-SUFFIX, WHATSAPP.NET, 圣何塞"
    var ruleLine: String {
        var parts: [String] = []
        if let r = conn.rule, !r.isEmpty { parts.append(QXFmt.ruleType(r)) }
        if let p = conn.rulePayload, !p.isEmpty { parts.append(p.uppercased()) }
        parts.append(policy)
        return parts.joined(separator: ", ")
    }
}

@MainActor
final class QXActivityModel: ObservableObject {
    static let shared = QXActivityModel()

    struct Bytes: Equatable { var up: Int64 = 0; var down: Int64 = 0; var total: Int64 { up + down } }
    struct NetBytes: Equatable { var tcp = Bytes(); var udp = Bytes(); var total: Int64 { tcp.total + udp.total } }

    @Published private(set) var records: [QXRecord] = []
    @Published private(set) var tcpCount = 0
    @Published private(set) var udpCount = 0
    @Published private(set) var traffic: [String: NetBytes] = [:]
    @Published private(set) var speed: [String: NetBytes] = [:]
    @Published private(set) var maxSpeed: [String: Bytes] = [:]
    @Published private(set) var since = Date()

    private var seqByID: [String: Int] = [:]
    private var last: [String: (up: Int64, down: Int64)] = [:]
    private var lastTick: Date?
    private var nextSeq = 1
    private static let recordCap = 500
    private var sessionID = QXSessionStore.idFormatter.string(from: Date())
    private var lastSave = Date.distantPast

    /// Writes the running session to the history (throttled to every 20 s unless forced).
    func saveSession(force: Bool = false) {
        guard !traffic.isEmpty, force || Date().timeIntervalSince(lastSave) > 20 else { return }
        lastSave = Date()
        var nodes: [String: QXTrafficSession.Net] = [:]
        for (k, v) in traffic {
            nodes[k] = QXTrafficSession.Net(tcpUp: v.tcp.up, tcpDown: v.tcp.down, udpUp: v.udp.up, udpDown: v.udp.down)
        }
        QXSessionStore.upsert(QXTrafficSession(id: sessionID, start: since, end: Date(), nodes: nodes, connections: tcpCount + udpCount))
    }

    func reset() {
        saveSession(force: true)
        sessionID = QXSessionStore.idFormatter.string(from: Date())
        records = []; tcpCount = 0; udpCount = 0; traffic = [:]; speed = [:]; maxSpeed = [:]
        seqByID = [:]; last = [:]; lastTick = nil; nextSeq = 1; since = Date()
    }

    func ingest(_ conns: [ConnectionItem]) {
        let now = Date()
        let dt = lastTick.map { max(now.timeIntervalSince($0), 0.5) } ?? 0
        lastTick = now
        var byID: [String: QXRecord] = [:]
        for r in records { byID[r.id] = r }
        var seen: [String: (up: Int64, down: Int64)] = [:]
        var tr = traffic
        var step: [String: NetBytes] = [:]
        for c in conns {
            let isNew = seqByID[c.id] == nil
            if isNew {
                seqByID[c.id] = nextSeq; nextSeq += 1
                if c.metadata.network?.lowercased() == "udp" { udpCount += 1 } else { tcpCount += 1 }
            }
            let rec = QXRecord(conn: c, seq: seqByID[c.id] ?? 0)
            byID[c.id] = rec
            let prev = last[c.id]
            let du = max(0, c.upload - (prev?.up ?? 0))
            let dd = max(0, c.download - (prev?.down ?? 0))
            if du > 0 || dd > 0 {
                let key = rec.leaf
                if rec.isUDP {
                    tr[key, default: NetBytes()].udp.up += du; tr[key, default: NetBytes()].udp.down += dd
                    step[key, default: NetBytes()].udp.up += du; step[key, default: NetBytes()].udp.down += dd
                } else {
                    tr[key, default: NetBytes()].tcp.up += du; tr[key, default: NetBytes()].tcp.down += dd
                    step[key, default: NetBytes()].tcp.up += du; step[key, default: NetBytes()].tcp.down += dd
                }
            }
            seen[c.id] = (c.upload, c.download)
        }
        // Closed since the last snapshot: keep them, stamped.
        let live = Set(conns.map(\.id))
        for (id, r) in byID where !live.contains(id) && r.conn.closedAt == nil {
            var c = r.conn
            c.closedAt = now
            byID[id] = QXRecord(conn: c, seq: r.seq)
        }
        var list = Array(byID.values)
        list.sort { $0.seq > $1.seq }
        if list.count > Self.recordCap {
            for r in list[Self.recordCap...] { seqByID.removeValue(forKey: r.id) }
            list.removeLast(list.count - Self.recordCap)
        }
        // QX preview 7: publish only what changed (each assignment notifies every observer).
        if list != records { records = list }
        last = seen
        if tr != traffic { traffic = tr }
        saveSession()
        if dt > 0 {
            var sp: [String: NetBytes] = [:]
            var mx = maxSpeed
            for (k, v) in step {
                let s = NetBytes(tcp: Bytes(up: Int64(Double(v.tcp.up) / dt), down: Int64(Double(v.tcp.down) / dt)),
                                 udp: Bytes(up: Int64(Double(v.udp.up) / dt), down: Int64(Double(v.udp.down) / dt)))
                sp[k] = s
                var m = mx[k] ?? Bytes()
                m.up = max(m.up, s.tcp.up + s.udp.up)
                m.down = max(m.down, s.tcp.down + s.udp.down)
                mx[k] = m
            }
            if sp != speed { speed = sp }
            if mx != maxSpeed { maxSpeed = mx }
        }
    }

    var blocked: [QXRecord] { records.filter(\.isRejected) }

    func record(_ id: String) -> QXRecord? { records.first { $0.id == id } }

    func poll() async {
        if let r = try? await ControllerClient.shared.connections() { ingest(r.connections ?? []) }
    }
}

// MARK: - Panel

struct QXActivityPanel: View {
    let active: Bool
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var nav: QXNavigator
    @ObservedObject private var model = QXActivityModel.shared
    @State private var network = "tcp"
    @State private var scriptCount = 0

    var shown: [QXRecord] {
        let q = nav.activityQuery.trimmingCharacters(in: .whitespaces).lowercased()
        return model.records.filter { r in
            (network == "udp") == r.isUDP &&
            (q.isEmpty || r.conn.metadata.displayHost.lowercased().contains(q) || r.ruleLine.lowercased().contains(q) || r.conn.chainText.lowercased().contains(q))
        }
    }

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                if nav.activitySearch {
                    HStack {
                        Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                        TextField("搜索主机、规则、策略", text: $nav.activityQuery)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                        if !nav.activityQuery.isEmpty {
                            Button { nav.activityQuery = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary) }
                        }
                    }
                    .padding(10)
                    .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(QXPalette.card))
                    .padding(.horizontal, 16)
                    .padding(.top, 10)
                }
                counters
                    .padding(.horizontal, QXMetrics.inset)
                    .padding(.vertical, 16)
                if !vpn.isConnected && model.records.isEmpty {
                    EmptyStateView(icon: "bolt.horizontal.circle", title: "连接后可查看实时请求")
                } else if shown.isEmpty {
                    Text(nav.activityQuery.isEmpty ? LocalizedStringKey("还没有记录") : LocalizedStringKey("没有匹配的记录"))
                        .font(.footnote).foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity).padding(.top, 30)
                }
                ForEach(shown) { r in
                    Button { nav.push(.connection(r.id)) } label: { QXActivityRow(record: r) }
                        .buttonStyle(.plain)
                        .contextMenu {
                            Button { UIPasteboard.general.string = r.conn.metadata.host ?? r.conn.metadata.displayHost } label: { Label("拷贝主机名", systemImage: "doc.on.doc") }
                            if r.conn.closedAt == nil {
                                Button(role: .destructive) { Task { try? await ControllerClient.shared.closeConnection(r.id); await model.poll() } } label: { Label("断开", systemImage: "xmark") }
                            }
                        }
                    Divider().padding(.leading, 20)
                }
            }
            .padding(.bottom, 110)
        }
        .task(id: "\(active)|\(vpn.isConnected)") {
            guard active, vpn.isConnected else { return }
            while !Task.isCancelled {
                await model.poll()
                if let logs = try? await ControllerClient.shared.mitmLogs() { scriptCount = logs.count }
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
    }

    var counters: some View {
        HStack(alignment: .center, spacing: 14) {
            VStack(alignment: .leading, spacing: 12) {
                counterRow("TCP", model.tcpCount, selected: network == "tcp") { network = "tcp" }
                counterRow("UDP", model.udpCount, selected: network == "udp") { network = "udp" }
            }
            RoundedRectangle(cornerRadius: 1).fill(Color.primary.opacity(0.1)).frame(width: 3, height: 70)
            VStack(alignment: .trailing, spacing: 12) {
                Button { nav.push(.dest(.blocked)) } label: {
                    HStack {
                        Image(systemName: "network.slash").font(.system(size: 22)).foregroundStyle(QXColor.activity)
                        Spacer()
                        Text(verbatim: "\(model.blocked.count)").font(.system(size: 34, weight: .regular).monospacedDigit())
                    }
                }
                .buttonStyle(.plain)
                .accessibilityLabel(Text("已阻止"))
                Button { nav.push(.dest(.scriptLogs)) } label: {
                    HStack {
                        Text(verbatim: "JS")
                            .font(.system(size: 11, weight: .heavy, design: .rounded))
                            .foregroundStyle(QXColor.activity)
                            .frame(width: 26, height: 26)
                            .overlay(Image(systemName: "hexagon").font(.system(size: 26, weight: .regular)).foregroundStyle(QXColor.activity))
                        Spacer()
                        Text(verbatim: "\(scriptCount)").font(.system(size: 34, weight: .regular).monospacedDigit())
                    }
                }
                .buttonStyle(.plain)
                .accessibilityLabel(Text("脚本记录"))
            }
        }
        .foregroundStyle(.primary)
    }

    private func counterRow(_ title: String, _ n: Int, selected: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack {
                Text(verbatim: title)
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(selected ? Color.white : QXColor.activity)
                    .frame(width: 52, height: 26)
                    .background(Capsule().fill(selected ? QXColor.activity : Color.clear))
                    .overlay(Capsule().stroke(QXColor.activity, lineWidth: 2))
                Spacer(minLength: 10)
                Text(verbatim: "\(n)").font(.system(size: 34, weight: .regular).monospacedDigit())
            }
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

struct QXActivityRow: View {
    let record: QXRecord
    var body: some View {
        let c = record.conn
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Image(systemName: "dot.radiowaves.left.and.right").font(.system(size: 10)).foregroundStyle(.secondary)
                if let d = c.startDate { Text(verbatim: QXFmt.stamp.string(from: d)).font(.system(size: 15).monospacedDigit()) }
                if let d = c.startDate {
                    Text(verbatim: "#" + Fmt.duration((c.closedAt ?? Date()).timeIntervalSince(d)))
                        .font(.system(size: 15).monospacedDigit())
                }
                Spacer()
                Text(verbatim: "↪ \(record.seq)").font(.system(size: 14).monospacedDigit()).foregroundStyle(.secondary)
            }
            HStack(spacing: 6) {
                Text(verbatim: c.metadata.displayHost)
                    .font(.system(size: 19, weight: .regular))
                    .foregroundStyle(record.isRejected ? QXColor.red : Color.primary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                if (c.chains ?? []).contains("__MITM__") {
                    Image(systemName: "lock.fill").font(.system(size: 11)).foregroundStyle(QXColor.mitm).accessibilityLabel(Text("MitM"))
                }
                if c.closedAt != nil {
                    Text("已关闭").font(.caption2).foregroundStyle(.secondary)
                }
            }
            Text(verbatim: record.ruleLine).font(.system(size: 13, weight: .medium)).foregroundStyle(.secondary).lineLimit(1)
            HStack(spacing: 6) {
                if record.isRejected {
                    Image(systemName: "xmark.octagon.fill").font(.system(size: 12)).foregroundStyle(QXColor.red)
                    Text(verbatim: record.leaf).font(.system(size: 14, weight: .medium)).foregroundStyle(QXColor.red)
                } else {
                    Image(systemName: "server.rack").font(.system(size: 11)).foregroundStyle(QXColor.nodes)
                    Text(verbatim: record.leaf).font(.system(size: 14)).lineLimit(1)
                }
                Spacer(minLength: 6)
                Label(Fmt.bytes(c.download), systemImage: "arrow.down.circle.fill").labelStyle(.titleAndIcon)
                    .font(.system(size: 13).monospacedDigit()).foregroundStyle(.secondary)
                Label(Fmt.bytes(c.upload), systemImage: "arrow.up.circle.fill").labelStyle(.titleAndIcon)
                    .font(.system(size: 13).monospacedDigit()).foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, QXMetrics.inset)
        .padding(.vertical, 10)
        .contentShape(Rectangle())
    }
}

// MARK: - Connection detail

struct QXConnectionDetailView: View {
    let id: String
    @EnvironmentObject var nav: QXNavigator
    @ObservedObject private var engine = EngineStore.shared
    @ObservedObject private var model = QXActivityModel.shared
    @ObservedObject private var rules = CustomRulesStore.shared
    @State private var newRule: CustomRule?
    @State private var message: String?

    var body: some View {
        QXPage(title: String(localized: "网络活动")) {
            if let r = model.record(id) {
                QXCapsuleBar {
                    // QX: @ = MitM 主机名 (add this host), ≣ = the rule's resource, funnel = new rule from this record.
                    Menu {
                        let host = r.conn.metadata.host ?? ""
                        if !host.isEmpty && !engine.config.hostnames.contains(host) {
                            Button {
                                engine.config.hostnames.append(host)
                                engine.save()
                                message = String(localized: "已添加到 MitM 主机名")
                            } label: { Label("添加 \(host) 到 MitM", systemImage: "plus") }
                        }
                        Button { nav.push(.dest(.mitm)) } label: { Label("MitM 主机名", systemImage: "at") }
                    } label: {
                        Image(systemName: "at").font(.system(size: 18, weight: .medium)).foregroundStyle(QXColor.mitm).frame(width: 40, height: 40)
                    }
                    .accessibilityLabel(Text("MitM"))
                    QXBarIcon(systemName: "list.bullet.rectangle", tint: QXColor.rules) {
                        nav.push(.dest(QXFmt.isRuleSet(r.conn.rule ?? "") ? .filterResources : .customRules))
                    }
                    .accessibilityLabel(Text("规则来源"))
                    QXBarIcon(systemName: "line.3.horizontal.decrease", tint: QXColor.rules) {
                        let host = r.conn.metadata.host?.isEmpty == false ? r.conn.metadata.host! : (r.conn.metadata.sniffHost ?? "")
                        let line = host.isEmpty
                            ? "IP-CIDR,\(r.conn.metadata.destinationIP ?? "0.0.0.0")/32,\(r.policy),no-resolve"
                            : "DOMAIN-SUFFIX,\(host),\(r.policy)"
                        newRule = CustomRule(line: line)
                    }
                    .accessibilityLabel(Text("添加分流规则"))
                    QXBarIcon(systemName: "doc.on.doc") {
                        UIPasteboard.general.string = summary(r)
                        message = String(localized: "已复制")
                    }
                    .accessibilityLabel(Text("复制"))
                }
            }
        } content: {
            ScrollView {
                if let r = model.record(id) {
                    VStack(alignment: .leading, spacing: 16) {
                        QXLargeTitle(title: r.conn.metadata.displayHost)
                        if let message { Text(verbatim: message).font(.footnote).foregroundStyle(QXColor.success) }
                        section(String(localized: "目标地址"), [
                            (String(localized: "主机"), r.conn.metadata.displayHost),
                            (String(localized: "目标 IP"), (r.conn.metadata.destinationIP ?? "—") + (r.conn.metadata.destinationPort.map { ":" + $0 } ?? "")),
                            (String(localized: "网络"), (r.conn.metadata.network ?? "tcp").uppercased()),
                            (String(localized: "类型"), r.conn.metadata.type ?? "—"),
                        ], geoIP: r.conn.metadata.destinationIP.flatMap { $0.isEmpty ? nil : $0 })
                        section(String(localized: "分流"), ruleRows(r))
                        section(String(localized: "策略走向"), [
                            (String(localized: "策略"), r.policy),
                            (String(localized: "链路"), r.conn.chainText),
                            (String(localized: "出口节点"), r.leaf),
                        ])
                        section(String(localized: "流量"), [
                            (String(localized: "上传"), Fmt.bytes(r.conn.upload)),
                            (String(localized: "下载"), Fmt.bytes(r.conn.download)),
                        ])
                        section(String(localized: "状态"), [
                            (String(localized: "开始"), r.conn.startDate.map { QXFmt.stamp.string(from: $0) } ?? "—"),
                            (String(localized: "时长"), r.conn.startDate.map { Fmt.duration((r.conn.closedAt ?? Date()).timeIntervalSince($0)) } ?? "—"),
                            (String(localized: "状态"), r.conn.closedAt == nil ? String(localized: "活跃") : String(localized: "已关闭")),
                            (String(localized: "来源"), "\(r.conn.metadata.sourceIP ?? "—"):\(r.conn.metadata.sourcePort ?? "")"),
                        ])
                        if r.conn.closedAt == nil {
                            Button(role: .destructive) {
                                Task { try? await ControllerClient.shared.closeConnection(r.id); await model.poll() }
                            } label: {
                                Text("断开连接").font(.body.weight(.semibold)).frame(maxWidth: .infinity, minHeight: 50)
                                    .background(RoundedRectangle(cornerRadius: 25, style: .continuous).fill(QXPalette.card))
                            }
                        }
                    }
                    .padding(.horizontal, QXMetrics.inset)
                    .padding(.bottom, 40)
                } else {
                    EmptyStateView(icon: "clock.arrow.circlepath", title: "记录已过期")
                }
            }
        }
        .sheet(item: $newRule) { r in
            CustomRuleEditor(rule: r) { saved in
                rules.rules.insert(saved, at: 0)
                rules.save()
                message = String(localized: "已添加分流规则")
            }
        }
    }

    private func section(_ title: String, _ rows: [(String, String)], geoIP: String? = nil) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(verbatim: title).font(.system(size: 20, weight: .bold))
            QXCard {
                VStack(spacing: 0) {
                    if let geoIP {
                        QXRemoteGeoRow(ip: geoIP)
                        Divider().padding(.leading, 16)
                    }
                    ForEach(Array(rows.enumerated()), id: \.offset) { i, row in
                        if i > 0 { Divider().padding(.leading, 16) }
                        HStack(alignment: .top) {
                            Text(verbatim: row.0).foregroundStyle(.secondary)
                            Spacer(minLength: 12)
                            Text(verbatim: row.1).multilineTextAlignment(.trailing).textSelection(.enabled)
                        }
                        .font(.subheadline)
                        .padding(.horizontal, 16).padding(.vertical, 11)
                    }
                }
            }
        }
    }

    private func ruleRows(_ r: QXRecord) -> [(String, String)] {
        var rows: [(String, String)] = [(String(localized: "规则"), r.ruleLine)]
        if QXFmt.isRuleSet(r.conn.rule ?? "") { rows.append((String(localized: "规则集"), r.conn.rulePayload ?? "—")) }
        if let p = r.conn.metadata.process, !p.isEmpty { rows.append((String(localized: "进程"), p)) }
        return rows
    }

    private func summary(_ r: QXRecord) -> String {
        [r.conn.metadata.displayHost, r.ruleLine, r.conn.chainText,
         "↑ \(Fmt.bytes(r.conn.upload)) ↓ \(Fmt.bytes(r.conn.download))"].joined(separator: "\n")
    }
}

// MARK: - 阻止 (rejected connections)

struct QXBlockedView: View {
    @ObservedObject private var model = QXActivityModel.shared
    @State private var query = ""

    var body: some View {
        QXPage {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    QXLargeTitle(title: String(localized: "已阻止的请求"), count: "\(model.blocked.count)",
                                 caption: String(localized: "本次打开 App 以来，命中 REJECT 的连接。"))
                        .padding(.horizontal, QXMetrics.inset).padding(.bottom, 10)
                    TextField("搜索", text: $query)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .padding(10).background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(QXPalette.card))
                        .padding(.horizontal, QXMetrics.inset).padding(.bottom, 8)
                    let list = model.blocked.filter { query.isEmpty || $0.conn.metadata.displayHost.localizedCaseInsensitiveContains(query) }
                    if list.isEmpty {
                        Text("还没有记录").font(.footnote).foregroundStyle(.secondary).frame(maxWidth: .infinity).padding(.top, 30)
                    }
                    ForEach(list) { r in
                        VStack(alignment: .leading, spacing: 3) {
                            HStack(spacing: 8) {
                                if let d = r.conn.startDate { Text(verbatim: QXFmt.stamp.string(from: d)).font(.system(size: 14).monospacedDigit()).foregroundStyle(.secondary) }
                                Text(verbatim: r.conn.metadata.host ?? r.conn.metadata.displayHost).font(QXType.rowTitle).foregroundStyle(QXColor.red).lineLimit(1)
                            }
                            Text(verbatim: r.ruleLine).font(.system(size: 12, weight: .medium)).foregroundStyle(.secondary)
                            Text(verbatim: "➤ " + r.leaf).font(.system(size: 13)).foregroundStyle(.secondary)
                        }
                        .padding(.horizontal, QXMetrics.inset).padding(.vertical, 9)
                        Divider().padding(.leading, 20)
                    }
                }
                .padding(.bottom, 40)
            }
        }
    }
}

// MARK: - 流量 / 流速 (toolbar 3)

struct QXTrafficStatsView: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var nav: QXNavigator
    @ObservedObject private var model = QXActivityModel.shared
    @State private var tab = 0

    var body: some View {
        QXPage(title: tab == 0 ? String(localized: "流量") : String(localized: "流速")) {
            Menu {
                Button { nav.push(.dest(.sessions)) } label: { Label("流量统计（已完成）", systemImage: "clock.arrow.circlepath") }
                Button { nav.push(.dest(.stats)) } label: { Label("按日流量", systemImage: "chart.bar.xaxis") }
                Button { nav.push(.dest(.analytics)) } label: { Label("连接分析", systemImage: "chart.pie") }
            } label: {
                Image(systemName: "line.3.horizontal.decrease")
                    .font(.system(size: 18, weight: .semibold)).foregroundStyle(.primary)
                    .frame(width: 44, height: 44)
                    .background(Circle().fill(QXPalette.card))
                    .shadow(color: QXPalette.shadow(0.10), radius: 8, y: 2)
            }
            .accessibilityLabel(Text("更多统计"))
        } content: {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    if tab == 0 { trafficBody } else { speedBody }
                }
                .padding(.horizontal, QXMetrics.inset)
                .padding(.bottom, 110)
            }
            .overlay(alignment: .bottom) {
                QXBottomSegment(icons: ["chart.bar.fill", "gauge"], selection: $tab).padding(.bottom, 10)
            }
        }
        .task(id: vpn.isConnected) {
            guard vpn.isConnected else { return }
            while !Task.isCancelled {
                await model.poll()
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
    }

    @ViewBuilder var trafficBody: some View {
        HStack {
            bigNumber(String(localized: "下载")) { QXLiveTotal(download: true) }
            bigNumber(String(localized: "上传")) { QXLiveTotal(download: false) }
        }
        .padding(.top, 8)
        if !vpn.isConnected && model.traffic.isEmpty {
            EmptyStateView(icon: "chart.bar", title: "连接后可查看")
        }
        ForEach(model.traffic.sorted { $0.value.total > $1.value.total }, id: \.key) { e in
            netCard(e.key, tcp: e.value.tcp, udp: e.value.udp, suffix: "")
        }
        Text("按出口节点统计，从本次打开 App 起累计（总量来自内核）。按日统计与连接分析在右上角。")
            .font(.caption).foregroundStyle(.secondary)
    }

    @ViewBuilder var speedBody: some View {
        VStack(alignment: .leading, spacing: 4) {
            QXLiveSpeed().font(.title3.monospacedDigit()).foregroundStyle(.secondary)
            Text("已运行").font(.subheadline).foregroundStyle(.secondary).padding(.top, 8)
            if let d = vpn.connectedDate {
                TimelineView(.periodic(from: .now, by: 1)) { ctx in
                    Text(verbatim: Self.clock(ctx.date.timeIntervalSince(d))).font(.system(size: 52, weight: .regular).monospacedDigit())
                }
            } else {
                Text(verbatim: "--:--:--").font(.system(size: 52, weight: .regular).monospacedDigit())
            }
        }
        ForEach(model.traffic.keys.sorted { (model.traffic[$0]?.total ?? 0) > (model.traffic[$1]?.total ?? 0) }, id: \.self) { k in
            let s = model.speed[k] ?? QXActivityModel.NetBytes()
            VStack(alignment: .leading, spacing: 6) {
                netCard(k, tcp: s.tcp, udp: s.udp, suffix: "/s")
                if let m = model.maxSpeed[k] {
                    HStack(spacing: 8) {
                        QXChip(text: "max ↓ " + Fmt.speed(m.down), color: QXColor.trafficDown)
                        QXChip(text: "max ↑ " + Fmt.speed(m.up), color: QXColor.trafficUp)
                    }
                    .padding(.leading, 4)
                }
            }
        }
    }

    private func bigNumber<V: View>(_ title: String, @ViewBuilder value: () -> V) -> some View {
        VStack(spacing: 6) {
            Text(verbatim: title).font(.subheadline).foregroundStyle(.secondary)
            value().font(.system(size: 40, weight: .regular).monospacedDigit()).lineLimit(1).minimumScaleFactor(0.5)
        }
        .frame(maxWidth: .infinity)
    }

    private func netCard(_ name: String, tcp: QXActivityModel.Bytes, udp: QXActivityModel.Bytes, suffix: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(verbatim: name.uppercased()).font(.footnote.weight(.semibold)).foregroundStyle(.secondary).padding(.leading, 4)
            QXCard {
                VStack(spacing: 0) {
                    netRow("UDP", udp, suffix)
                    Divider().padding(.leading, 16)
                    netRow("TCP", tcp, suffix)
                }
            }
        }
    }

    private func netRow(_ title: String, _ b: QXActivityModel.Bytes, _ suffix: String) -> some View {
        HStack {
            Text(verbatim: title).font(.body.weight(.medium)).frame(width: 50, alignment: .leading)
            Image(systemName: "chevron.down.circle.fill").foregroundStyle(QXColor.trafficDown)
            Text(verbatim: Fmt.bytes(b.down) + suffix).monospacedDigit()
            Spacer()
            Image(systemName: "chevron.up.circle.fill").foregroundStyle(QXColor.trafficUp)
            Text(verbatim: Fmt.bytes(b.up) + suffix).monospacedDigit()
                .frame(minWidth: 80, alignment: .leading)
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
    }

    static func clock(_ t: TimeInterval) -> String {
        let s = Int(max(t, 0))
        return String(format: "%02d:%02d:%02d", s / 3600, (s / 60) % 60, s % 60)
    }
}

// MARK: - HTTP 抓取 (engine request log)

struct QXHTTPCaptureView: View {
    @EnvironmentObject var vpn: VPNManager
    @StateObject private var http = HTTPLogModel()
    @ObservedObject private var engine = EngineStore.shared

    var body: some View {
        QXPage {
            QXCapsuleBar {
                QXBarIcon(systemName: (engine.config.captureBodies ?? true) ? "record.circle.fill" : "record.circle",
                          tint: (engine.config.captureBodies ?? true) ? QXColor.tools : .secondary) {
                    engine.config.captureBodies = !(engine.config.captureBodies ?? true)
                    engine.save()
                }
                .accessibilityLabel(Text("HTTP 抓取"))
                QXBarIcon(systemName: "trash") { Task { await http.clear() } }
                    .accessibilityLabel(Text("清空"))
            }
        } content: {
            List {
                Section {
                    QXLargeTitle(title: String(localized: "数据抓取"),
                                 caption: String(localized: "经过重写 / MitM 引擎的 HTTP(S) 请求会记录在这里（含请求与响应体，最多 32 KB）。HTTPS 请求需要在 MitM 主机名中添加对应域名才会被解析。被重写命中的请求记录修改后的结果。"))
                        .listRowBackground(Color.clear)
                        .listRowInsets(EdgeInsets(top: 0, leading: 4, bottom: 8, trailing: 4))
                }
                if !vpn.isConnected {
                    Text("连接后可查看").foregroundStyle(.secondary).listRowBackground(QXPalette.card)
                } else if http.items.isEmpty {
                    EmptyStateRow(icon: "lock.open", title: "还没有 HTTP 请求", message: "需要在设置中开启重写或 MitM。")
                        .listRowBackground(QXPalette.card)
                }
                ForEach(http.items) { r in
                    NavigationLink { HTTPRequestDetailView(id: r.id) } label: { HTTPRequestRow(r: r) }
                        .listRowBackground(QXPalette.card)
                }
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
        }
        .onAppear { if vpn.isConnected { http.start() } }
        .onDisappear { http.stop() }
    }
}


// QX preview 7: live numbers in their own tiny views, so the per-second DashboardModel sample re-renders a
// Text, not the whole 流量 page.
struct QXLiveTotal: View {
    let download: Bool
    @ObservedObject private var dash = DashboardModel.shared
    var body: some View {
        Text(verbatim: Fmt.bytes(download ? dash.downloadTotal : dash.uploadTotal))
            .contentTransition(.numericText())
    }
}

struct QXLiveSpeed: View {
    @ObservedObject private var dash = DashboardModel.shared
    var body: some View { Text(verbatim: Fmt.speed(dash.down + dash.up)) }
}
