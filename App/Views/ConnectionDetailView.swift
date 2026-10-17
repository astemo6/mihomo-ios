import SwiftUI

// v0.17 请求 → connection detail with the timeline (parity #8), and the 主机 aggregate.

extension TimelineStage {
    /// Existing protocol / rule hues (Theme.tone), no new colours.
    var color: Color {
        switch self {
        case .dns: return Theme.tone(0.55, 0.45, 1.0)
        case .connect: return Theme.tone(0.25, 0.6, 1.0)
        case .tls: return Theme.tone(0.2, 0.8, 0.85)
        case .firstByte: return Theme.tone(1.0, 0.62, 0.2)
        }
    }
}

enum TimelineFmt {
    static func ms(_ v: Double) -> String {
        v < 10 ? String(format: "%.1f ms", v) : "\(Int(v.rounded())) ms"
    }
}

/// Stacked horizontal bar of the measured phases (widths proportional to time).
struct TimelineBar: View {
    let phases: [(TimelineStage, Double)]
    var body: some View {
        let total = max(phases.reduce(0) { $0 + $1.1 }, 0.001)
        GeometryReader { geo in
            HStack(spacing: 2) {
                ForEach(Array(phases.enumerated()), id: \.offset) { _, p in
                    RoundedRectangle(cornerRadius: 3)
                        .fill(p.0.color)
                        .frame(width: max(4, (geo.size.width - CGFloat(phases.count - 1) * 2) * CGFloat(p.1 / total)))
                }
            }
        }
        .frame(height: 10)
        .background(RoundedRectangle(cornerRadius: 3).fill(Theme.ink(0.06)))
        .accessibilityHidden(true)
    }
}

struct ConnectionDetailView: View {
    let c: ConnectionItem
    @ObservedObject var model: RequestsModel
    @State private var probe: TimelineProbe?
    @State private var probing = false
    @State private var probeError: String?

    var record: TimelineRecord? { model.timeline[c.id] }
    var current: ConnectionItem { model.active.first { $0.id == c.id } ?? model.recent.first { $0.id == c.id } ?? c }

    var body: some View {
        List {
            Section {
                ConnectionRow(c: current)
                if let r = c.metadata.remoteDestination, !r.isEmpty {
                    LabeledContent("远端地址") { Text(verbatim: r).font(.caption.monospaced()) }
                }
            }
            .listRowBackground(Theme.card)

            passiveSection
            probeSection
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle(Text(verbatim: c.metadata.displayHost))
        .navigationBarTitleDisplayMode(.inline)
    }

    // MARK: 本次连接 (passive)

    @ViewBuilder var passiveSection: some View {
        Section {
            if let r = record, r.preexisting != true {
                HStack {
                    stageLabel(.dns, "DNS 查询")
                    Spacer(minLength: 8)
                    if let d = r.dns {
                        VStack(alignment: .trailing, spacing: 2) {
                            Text(d.cached == true ? String(localized: "缓存命中") : TimelineFmt.ms(d.ms)).monospacedDigit()
                            if let u = d.upstream, !u.isEmpty { Text(verbatim: u).font(.caption2.monospaced()).foregroundStyle(.secondary) }
                        }
                    } else {
                        Text("未观察到").foregroundStyle(.secondary)
                    }
                }
                .accessibilityElement(children: .combine)
                .accessibilityIdentifier("timeline.passive.dns")
                boundRow("首个上行字节", r.firstUp, id: "timeline.passive.up", stage: .connect)
                boundRow("首个下行字节", r.firstDown, id: "timeline.passive.down", stage: .firstByte)
            } else {
                Text(LocalizedStringKey(record == nil ? "打开「请求」页之后建立的连接才有时间点。" : "这条连接在开始记录前已建立，没有时间点。"))
                    .font(.footnote).foregroundStyle(.secondary)
                    .accessibilityIdentifier("timeline.passive.none")
            }
        } header: {
            Text("本次连接")
        } footer: {
            Text("时间从内核建立出站连接（拨号与代理握手已完成）算起，每 \(model.timelineResolution) ms 采样一次，所以显示为区间。DNS 是连接前 10 秒内内核收到的该域名应答（上游往返或缓存）；经代理时域名通常由代理服务器解析。真实连接的 TLS 握手在 App 与服务器之间端到端完成，内核看不到。")
        }
        .listRowBackground(Theme.card)
    }

    func boundRow(_ title: String, _ b: TimelineBound?, id: String, stage: TimelineStage) -> some View {
        HStack {
            stageLabel(stage, title)
            Spacer(minLength: 8)
            if let b {
                Text("建立后 \(b.text)").monospacedDigit()
            } else {
                Text(LocalizedStringKey(current.closedAt == nil ? "尚无数据" : "无")).foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier(id)
    }

    func stageLabel(_ s: TimelineStage, _ title: String) -> some View {
        HStack(spacing: 8) {
            Circle().fill(s.color).frame(width: 8, height: 8)
            Text(LocalizedStringKey(title))
        }
    }

    // MARK: 测量时间线 (active)

    @ViewBuilder var probeSection: some View {
        Section {
            if let p = probe {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("合计").font(.subheadline.weight(.semibold))
                        Spacer()
                        Text(TimelineFmt.ms(p.totalMs)).font(.subheadline.weight(.semibold).monospacedDigit())
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityIdentifier("timeline.probe.total")
                    if !p.phases.isEmpty { TimelineBar(phases: p.phases) }
                }
                .padding(.vertical, 4)
                ForEach(TimelineStage.allCases, id: \.self) { s in
                    phaseRow(s, p.phase(s))
                }
                if let ch = p.chain, !ch.isEmpty {
                    LabeledContent("出站") { PolicyChip(name: ch) }
                }
                if let t = p.tlsInfo, !t.isEmpty {
                    LabeledContent("TLS") { Text(verbatim: t).font(.caption.monospaced()) }
                }
                if let st = p.status, !st.isEmpty {
                    LabeledContent("HTTP 状态") { Text(verbatim: st).monospacedDigit() }
                }
                if let e = p.error, !e.isEmpty {
                    Text(verbatim: e).font(.caption).foregroundStyle(Theme.bad)
                }
            }
            if let e = probeError {
                Text(verbatim: e).font(.caption).foregroundStyle(Theme.bad)
            }
            Button {
                runProbe()
            } label: {
                HStack {
                    Label(LocalizedStringKey(probe == nil ? "测量" : "重新测量"), systemImage: "stopwatch")
                    Spacer()
                    if probing { ProgressView() }
                }
            }
            .disabled(probing)
            .accessibilityIdentifier("timeline.probe.run")
        } header: {
            Text("测量时间线")
        } footer: {
            Text("按这条连接的出站重新建立一次连接（HTTPS 只发送 HEAD /），测出 DNS、连接、TLS 握手和首字节。这是新连接的耗时，不是原请求本身的。")
        }
        .listRowBackground(Theme.card)
    }

    func phaseRow(_ s: TimelineStage, _ p: TimelinePhase) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack {
                stageLabel(s, s.title)
                Spacer()
                if let v = p.ms {
                    Text(TimelineFmt.ms(v)).monospacedDigit().foregroundStyle(p.error == nil ? Color.primary : Theme.bad)
                } else {
                    Text("—").foregroundStyle(.secondary)
                }
            }
            if let n = p.note, !n.isEmpty {
                Text(LocalizedStringKey(n)).font(.caption2).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            if let e = p.error, !e.isEmpty {
                Text(verbatim: e).font(.caption2).foregroundStyle(Theme.bad)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("timeline.probe.\(s.rawValue)")
    }

    func runProbe() {
        probing = true
        probeError = nil
        Task {
            do {
                probe = try await TimelineAPI.probe(c)
            } catch {
                probeError = error.localizedDescription
            }
            probing = false
        }
    }
}

// MARK: 主机 aggregate

struct HostAggregateRow: View {
    let h: HostAggregate
    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack {
                Text(verbatim: h.host).font(.system(.subheadline, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                Spacer(minLength: 6)
                Text("\(h.connections.count) 个连接").font(.caption).foregroundStyle(.secondary)
            }
            HStack(spacing: 6) {
                if let p = h.policies.first { PolicyChip(name: p) }
                if h.policies.count > 1 { Text(verbatim: "+\(h.policies.count - 1)").font(.caption2).foregroundStyle(.secondary) }
                Spacer(minLength: 4)
                if h.active > 0 { Text("活跃 \(h.active)").font(.caption2).foregroundStyle(Theme.good) }
            }
            HStack(spacing: 10) {
                Label(Fmt.bytes(h.upload), systemImage: "arrow.up").foregroundStyle(Theme.up)
                Label(Fmt.bytes(h.download), systemImage: "arrow.down").foregroundStyle(Theme.down)
                Spacer()
                if let d = h.dnsMs { Text("DNS \(TimelineFmt.ms(d))").foregroundStyle(TimelineStage.dns.color) }
                if let f = h.firstDown { Text("首字节 \(f.text)").foregroundStyle(TimelineStage.firstByte.color) }
            }
            .font(.caption2.monospacedDigit())
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("hosts.row.\(h.host)")
    }
}

struct HostConnectionsView: View {
    let host: String
    @ObservedObject var model: RequestsModel
    var agg: HostAggregate? {
        HostAggregate.build(active: model.active, recent: model.recent, timeline: model.timeline).first { $0.host == host }
    }
    var body: some View {
        List {
            if let a = agg {
                Section {
                    LabeledContent("连接") { Text("\(a.connections.count)").monospacedDigit() }
                    LabeledContent("上传 / 下载") { Text(verbatim: "\(Fmt.bytes(a.upload)) / \(Fmt.bytes(a.download))").monospacedDigit() }
                    if let d = a.dnsMs { LabeledContent("DNS 中位数") { Text(TimelineFmt.ms(d)).monospacedDigit() } }
                    if let f = a.firstDown { LabeledContent("首个下行字节中位数") { Text("建立后 \(f.text)").monospacedDigit() } }
                    if !a.policies.isEmpty {
                        LabeledContent("出站") {
                            VStack(alignment: .trailing, spacing: 4) { ForEach(a.policies, id: \.self) { PolicyChip(name: $0) } }
                        }
                    }
                } footer: {
                    Text("中位数只统计打开「请求」页之后建立、有时间点的 \(a.measured) 个连接。")
                }
                .listRowBackground(Theme.card)
                Section {
                    ForEach(a.connections) { c in
                        NavigationLink { ConnectionDetailView(c: c, model: model) } label: { ConnectionRow(c: c) }
                    }
                }
                .listRowBackground(Theme.card)
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle(Text(verbatim: host))
        .navigationBarTitleDisplayMode(.inline)
    }
}
