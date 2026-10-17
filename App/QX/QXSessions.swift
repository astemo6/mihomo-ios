import SwiftUI

// QX 流量统计（已完成）: one record per tunnel session (per exit node TCP / UDP, plus totals), kept in the
// App Group (last 30 sessions). Written by QXActivityModel while the app watches the tunnel.

struct QXTrafficSession: Codable, Identifiable, Hashable {
    struct Net: Codable, Hashable { var tcpUp: Int64 = 0; var tcpDown: Int64 = 0; var udpUp: Int64 = 0; var udpDown: Int64 = 0
        var total: Int64 { tcpUp + tcpDown + udpUp + udpDown } }
    var id: String
    var start: Date
    var end: Date
    var nodes: [String: Net]
    var connections: Int

    var up: Int64 { nodes.values.reduce(0) { $0 + $1.tcpUp + $1.udpUp } }
    var down: Int64 { nodes.values.reduce(0) { $0 + $1.tcpDown + $1.udpDown } }
}

enum QXSessionStore {
    static var url: URL { AppShared.containerURL.appendingPathComponent("qx-sessions.json") }
    static let keep = 30

    static func load() -> [QXTrafficSession] {
        guard let d = try? Data(contentsOf: url), let l = try? JSONDecoder().decode([QXTrafficSession].self, from: d) else { return [] }
        return l
    }

    /// Insert or replace the session with this id (newest first).
    static func upsert(_ s: QXTrafficSession) {
        var l = load().filter { $0.id != s.id }
        l.insert(s, at: 0)
        if l.count > keep { l.removeLast(l.count - keep) }
        if let d = try? JSONEncoder().encode(l) { try? d.write(to: url, options: .atomic) }
    }

    static func clear() { try? FileManager.default.removeItem(at: url) }

    static let idFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "MM-dd-HHmmss"
        return f
    }()
}

struct QXSessionListView: View {
    @State private var sessions: [QXTrafficSession] = []
    @State private var confirm = false

    var body: some View {
        QXPage(title: String(localized: "流量统计（已完成）")) {
            QXCircleButton(systemName: "trash") { confirm = true }
                .accessibilityLabel(Text("清空"))
        } content: {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    HStack {
                        bigNumber(String(localized: "下载（已完成）"), Fmt.bytes(sessions.reduce(0) { $0 + $1.down }))
                        bigNumber(String(localized: "上传（已完成）"), Fmt.bytes(sessions.reduce(0) { $0 + $1.up }))
                    }
                    if sessions.isEmpty {
                        Text("还没有记录").font(.footnote).foregroundStyle(.secondary).frame(maxWidth: .infinity).padding(.top, 30)
                    }
                    QXCard {
                        VStack(spacing: 0) {
                            ForEach(Array(sessions.enumerated()), id: \.element.id) { i, s in
                                if i > 0 { Divider().padding(.leading, 16) }
                                NavigationLink { QXSessionDetailView(session: s) } label: {
                                    HStack {
                                        VStack(alignment: .leading, spacing: 3) {
                                            Text(verbatim: s.id).font(.system(size: 17).monospacedDigit())
                                            Text(verbatim: "\(QXFmt.stamp.string(from: s.start)) – \(QXFmt.stamp.string(from: s.end))")
                                                .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                                        }
                                        Spacer()
                                        VStack(alignment: .trailing, spacing: 3) {
                                            Text(verbatim: "↓ " + Fmt.bytes(s.down)).font(.footnote.monospacedDigit())
                                            Text(verbatim: "↑ " + Fmt.bytes(s.up)).font(.footnote.monospacedDigit()).foregroundStyle(.secondary)
                                        }
                                        Image(systemName: "chevron.right").font(.caption.weight(.semibold)).foregroundStyle(.tertiary)
                                    }
                                    .padding(.horizontal, 16).padding(.vertical, 12)
                                    .contentShape(Rectangle())
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                    Text("每次连接记录一份（App 打开期间按出口节点统计），保留最近 30 次。").font(.caption).foregroundStyle(.secondary)
                }
                .padding(.horizontal, QXMetrics.inset)
                .padding(.bottom, 40)
            }
        }
        .onAppear { sessions = QXSessionStore.load() }
        .confirmationDialog("清空流量记录？", isPresented: $confirm, titleVisibility: .visible) {
            Button("清空", role: .destructive) { QXSessionStore.clear(); sessions = [] }
        }
    }

    private func bigNumber(_ title: String, _ value: String) -> some View {
        VStack(spacing: 6) {
            Text(verbatim: title).font(.subheadline).foregroundStyle(.secondary)
            Text(verbatim: value).font(.system(size: 36, weight: .regular).monospacedDigit()).lineLimit(1).minimumScaleFactor(0.5)
        }
        .frame(maxWidth: .infinity)
    }
}

struct QXSessionDetailView: View {
    let session: QXTrafficSession
    var body: some View {
        QXPage(title: session.id) {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    HStack {
                        stat(String(localized: "下载（已完成）"), Fmt.bytes(session.down))
                        stat(String(localized: "上传（已完成）"), Fmt.bytes(session.up))
                    }
                    ForEach(session.nodes.sorted { $0.value.total > $1.value.total }, id: \.key) { e in
                        VStack(alignment: .leading, spacing: 6) {
                            Text(verbatim: e.key.uppercased()).font(.footnote.weight(.semibold)).foregroundStyle(.secondary).padding(.leading, 4)
                            QXCard {
                                VStack(spacing: 0) {
                                    row("UDP", e.value.udpDown, e.value.udpUp)
                                    Divider().padding(.leading, 16)
                                    row("TCP", e.value.tcpDown, e.value.tcpUp)
                                }
                            }
                        }
                    }
                    Text("连接数 \(session.connections)").font(.caption).foregroundStyle(.secondary)
                }
                .padding(.horizontal, QXMetrics.inset)
                .padding(.bottom, 40)
            }
        }
    }

    private func stat(_ t: String, _ v: String) -> some View {
        VStack(spacing: 6) {
            Text(verbatim: t).font(.subheadline).foregroundStyle(.secondary)
            Text(verbatim: v).font(.system(size: 36).monospacedDigit()).lineLimit(1).minimumScaleFactor(0.5)
        }
        .frame(maxWidth: .infinity)
    }

    private func row(_ title: String, _ down: Int64, _ up: Int64) -> some View {
        HStack {
            Text(verbatim: title).font(.body.weight(.medium)).frame(width: 50, alignment: .leading)
            Image(systemName: "chevron.down.circle.fill").foregroundStyle(QXColor.trafficDown)
            Text(verbatim: Fmt.bytes(down)).monospacedDigit()
            Spacer()
            Image(systemName: "chevron.up.circle.fill").foregroundStyle(QXColor.trafficUp)
            Text(verbatim: Fmt.bytes(up)).monospacedDigit().frame(minWidth: 80, alignment: .leading)
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
    }
}
