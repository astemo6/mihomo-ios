import SwiftUI
import Charts

/// 流量统计: daily totals recorded by the tunnel (TrafficHistory, about 120 days).
struct StatsView: View {
    @EnvironmentObject var vpn: VPNManager
    @State private var days: [TrafficDay] = []
    @State private var range = 7
    @State private var confirmClear = false

    struct Bar: Identifiable {
        let id = UUID()
        let date: Date
        let kind: String
        let bytes: Int64
    }

    var shown: [TrafficDay] { TrafficHistory.recent(range, from: days) }

    var bars: [Bar] {
        shown.flatMap { d in
            [Bar(date: d.date, kind: "下载", bytes: d.down), Bar(date: d.date, kind: "上传", bytes: d.up)]
        }
    }

    var today: TrafficDay? { TrafficHistory.recent(1, from: days).first }

    var thisMonth: (Int64, Int64) {
        let key = String(TrafficHistory.dayFormatter.string(from: Date()).prefix(7))
        let m = days.filter { $0.day.hasPrefix(key) }
        return (m.reduce(0) { $0 + $1.up }, m.reduce(0) { $0 + $1.down })
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                LazyVGrid(columns: [GridItem(.flexible(), spacing: 12), GridItem(.flexible(), spacing: 12)], spacing: 12) {
                    StatTile(icon: "sun.max.fill", color: Theme.warn, title: "今天", value: Fmt.bytes(today?.total ?? 0))
                    StatTile(icon: "calendar", color: Theme.accent, title: "本月", value: Fmt.bytes(thisMonth.0 + thisMonth.1))
                    StatTile(icon: "arrow.up.circle.fill", color: Theme.up, title: "本月上传", value: Fmt.bytes(thisMonth.0))
                    StatTile(icon: "arrow.down.circle.fill", color: Theme.down, title: "本月下载", value: Fmt.bytes(thisMonth.1))
                }

                Card {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Text("每日流量").font(.headline)
                            Spacer()
                            Picker("", selection: $range) {
                                Text("7 天").tag(7)
                                Text("30 天").tag(30)
                                Text("120 天").tag(120)
                            }
                            .pickerStyle(.segmented)
                            .frame(width: 200)
                        }
                        Chart(bars) { b in
                            BarMark(x: .value("日期", b.date, unit: .day),
                                    y: .value("流量", Double(b.bytes) / 1_048_576))
                                .foregroundStyle(by: .value("方向", b.kind))
                        }
                        .chartForegroundStyleScale(["下载": Theme.down, "上传": Theme.up])
                        .chartYAxis {
                            AxisMarks(position: .leading) { v in
                                AxisGridLine().foregroundStyle(Color.white.opacity(0.08))
                                AxisValueLabel {
                                    if let mb = v.as(Double.self) { Text(Fmt.bytes(Int64(mb * 1_048_576))).font(.system(size: 9)) }
                                }
                            }
                        }
                        .chartXAxis {
                            AxisMarks(values: .automatic(desiredCount: range == 7 ? 7 : 5)) { _ in
                                AxisValueLabel(format: .dateTime.month(.defaultDigits).day(), centered: true).font(.system(size: 9))
                            }
                        }
                        .frame(height: 200)
                    }
                }

                Card {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("明细").font(.headline)
                        let rows = Array(shown.reversed().filter { $0.total > 0 })
                        if rows.isEmpty {
                            Text("暂无数据。连接后每 2 分钟记录一次。").font(.footnote).foregroundStyle(.secondary)
                        }
                        ForEach(rows) { d in
                            HStack {
                                Text(d.date.formatted(.dateTime.month().day().weekday(.abbreviated))).font(.footnote)
                                Spacer()
                                Text("↑ \(Fmt.bytes(d.up))").font(.caption.monospacedDigit()).foregroundStyle(Theme.up)
                                Text("↓ \(Fmt.bytes(d.down))").font(.caption.monospacedDigit()).foregroundStyle(Theme.down)
                                    .frame(minWidth: 80, alignment: .trailing)
                            }
                        }
                    }
                }

                Button(role: .destructive) { confirmClear = true } label: {
                    Text("清除统计").font(.footnote)
                }
                .padding(.top, 4)
            }
            .padding(16)
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("流量统计")
        .task { await reload() }
        .refreshable { await reload() }
        .confirmationDialog("清除全部流量统计？", isPresented: $confirmClear, titleVisibility: .visible) {
            Button("清除", role: .destructive) { TrafficHistory.clear(); days = [] }
        }
    }

    func reload() async {
        if vpn.isConnected { _ = await vpn.send(.flushStats) }
        days = TrafficHistory.load()
    }
}
