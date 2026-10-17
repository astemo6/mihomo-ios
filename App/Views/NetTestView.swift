import SwiftUI

// v0.10 网络测试: NAT type (STUN, RFC 5780) and bandwidth, both run inside the core through the current
// rules (/tools/stun, /tools/speed), so they measure the path your traffic actually takes.

struct NATResult: Decodable {
    var type: String
    var mapping: String
    var filtering: String
    var server: String?
    var mapped: String?
    var chain: String?
    var rule: String?
    var rulePayload: String?
    var steps: [String]
    var ms: Double
    var error: String?

    var title: String {
        switch type {
        case "full-cone": return String(localized: "完全锥形（NAT1）")
        case "restricted-cone": return String(localized: "受限锥形（NAT2）")
        case "port-restricted-cone": return String(localized: "端口受限锥形（NAT3）")
        case "symmetric": return String(localized: "对称型（NAT4）")
        case "cone": return String(localized: "锥形（过滤方式未知）")
        case "blocked": return String(localized: "UDP 不通")
        default: return String(localized: "无法判断")
        }
    }

    var color: Color {
        switch type {
        case "full-cone", "restricted-cone": return Theme.good
        case "port-restricted-cone", "cone": return Theme.accent
        case "symmetric": return Theme.warn
        default: return Theme.bad
        }
    }

    var advice: String {
        switch type {
        case "full-cone", "restricted-cone": return String(localized: "适合游戏联机、语音通话和 P2P。")
        case "port-restricted-cone", "cone": return String(localized: "大多数游戏和通话可用，部分 P2P 连接需要中转。")
        case "symmetric": return String(localized: "P2P 和部分游戏联机困难。节点不支持 Full Cone 时常见。")
        case "blocked": return String(localized: "节点或规则不转发 UDP（例如策略为 REJECT，或节点未开启 UDP）。")
        default: return String(localized: "STUN 服务器未提供足够信息。")
        }
    }

    static func behaviour(_ s: String) -> String {
        switch s {
        case "endpoint-independent": return String(localized: "与目标无关")
        case "address-dependent": return String(localized: "取决于目标地址")
        case "address-port-dependent": return String(localized: "取决于目标地址和端口")
        default: return String(localized: "未知")
        }
    }
}

struct SpeedEvent: Decodable {
    var phase: String
    var bps: Double?
    var bytes: Int64?
    var seconds: Double?
    var ms: Double?
    var downBps: Double?
    var upBps: Double?
    var chain: String?
    var rule: String?
    var rulePayload: String?
    var error: String?
}

@MainActor
final class NetTestModel: ObservableObject {
    @Published var natRunning = false
    @Published var nat: NATResult?
    @Published var natError: String?

    @Published var speedRunning = false
    @Published var phase = ""
    @Published var latency: Double?
    @Published var current: Double = 0
    @Published var down: Double?
    @Published var up: Double?
    @Published var samples: [Double] = []
    @Published var route = ""
    @Published var speedError: String?
    private var speedTask: Task<Void, Never>?

    func runNAT(server: String) async {
        natRunning = true
        nat = nil
        natError = nil
        defer { natRunning = false }
        var q: [URLQueryItem] = []
        let s = server.trimmingCharacters(in: .whitespaces)
        if !s.isEmpty { q.append(URLQueryItem(name: "server", value: s)) }
        do {
            nat = try await ControllerClient.shared.get(NATResult.self, "/tools/stun", query: q, timeout: 70)
        } catch {
            natError = error.localizedDescription
        }
    }

    func startSpeed(seconds: Int, upload: Bool) {
        speedTask?.cancel()
        speedTask = Task { await runSpeed(seconds: seconds, upload: upload) }
    }

    func stopSpeed() {
        speedTask?.cancel()
        speedTask = nil
        speedRunning = false
        if phase != "done" { phase = "" }
    }

    private func runSpeed(seconds: Int, upload: Bool) async {
        speedRunning = true
        phase = "latency"
        latency = nil; down = nil; up = nil; current = 0; samples = []; route = ""; speedError = nil
        defer { speedRunning = false }
        let s = BandwidthSettings.load()
        var q = [URLQueryItem(name: "seconds", value: String(seconds))]
        if !s.downloadURL.isEmpty { q.append(URLQueryItem(name: "down", value: s.downloadURL)) }
        q.append(URLQueryItem(name: "up", value: upload ? s.uploadURL : "none"))
        do {
            let lines = try await ControllerClient.shared.lines("/tools/speed", query: q, timeout: TimeInterval(seconds * 2 + 40))
            for try await line in lines {
                if Task.isCancelled { break }
                guard let e = try? JSONDecoder().decode(SpeedEvent.self, from: Data(line.utf8)) else { continue }
                if let c = e.chain, !c.isEmpty { route = ToolsView.routeText(chain: c, rule: e.rule, payload: e.rulePayload) }
                switch e.phase {
                case "latency":
                    latency = e.ms
                case "down", "up":
                    if phase != e.phase {
                        if e.phase == "up", !samples.isEmpty { down = samples.reduce(0, +) / Double(samples.count) }
                        samples = []
                        phase = e.phase
                    }
                    current = e.bps ?? 0
                    samples.append(current)
                    if samples.count > 60 { samples.removeFirst(samples.count - 60) }
                case "done":
                    down = e.downBps
                    up = upload ? e.upBps : nil
                    phase = "done"
                case "error":
                    speedError = e.error
                    if let d = e.downBps { down = d }
                    phase = "done"
                default: break
                }
            }
        } catch {
            if !Task.isCancelled { speedError = error.localizedDescription }
        }
    }

    static func mbps(_ bytesPerSecond: Double) -> String {
        let v = bytesPerSecond * 8 / 1_000_000
        return v >= 100 ? String(format: "%.0f", v) : String(format: "%.1f", v)
    }
}

/// Download / upload URLs for the bandwidth test, kept in the shared defaults.
struct BandwidthSettings: Codable {
    var downloadURL = "https://speed.cloudflare.com/__down?bytes=200000000"
    var uploadURL = "https://speed.cloudflare.com/__up"
    static let key = "bandwidthTest.v1"
    static func load() -> BandwidthSettings {
        guard let d = AppShared.defaults.data(forKey: key), let s = try? JSONDecoder().decode(BandwidthSettings.self, from: d) else { return BandwidthSettings() }
        return s
    }
    func save() { if let d = try? JSONEncoder().encode(self) { AppShared.defaults.set(d, forKey: Self.key) } }
}

struct NetTestView: View {
    @EnvironmentObject var vpn: VPNManager
    @StateObject private var model = NetTestModel()
    @State private var tab = 0
    @State private var stunServer = ""
    @State private var seconds = 8
    @State private var upload = true
    @State private var settings = BandwidthSettings.load()
    @State private var showSteps = false

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                Picker("", selection: $tab) {
                    Text("带宽").tag(0)
                    Text("NAT 类型").tag(1)
                }
                .pickerStyle(.segmented)
                if !vpn.isConnected {
                    Card {
                        EmptyStateRow(icon: "bolt.horizontal.circle", title: "连接后可用",
                                      message: "测试在内核中按当前规则进行，结果就是你的流量实际走的那条路径。")
                    }
                } else if tab == 0 {
                    speedCard
                } else {
                    natCard
                }
            }
            .padding(16)
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("网络测试")
        .onDisappear { model.stopSpeed() }
    }

    // MARK: Bandwidth

    var speedCard: some View {
        VStack(spacing: 14) {
            Card {
                VStack(spacing: 14) {
                    VStack(spacing: 4) {
                        Text(phaseTitle).font(.caption).foregroundStyle(.secondary)
                        HStack(alignment: .firstTextBaseline, spacing: 4) {
                            Text(model.speedRunning && model.phase != "latency" ? NetTestModel.mbps(model.current) : (model.down.map(NetTestModel.mbps) ?? "—"))
                                .font(.system(size: 52, weight: .semibold, design: .rounded).monospacedDigit())
                                .foregroundStyle(model.phase == "up" ? Theme.up : Theme.accent)
                                .contentTransition(.numericText())
                            Text("Mbps").font(.headline).foregroundStyle(.secondary)
                        }
                    }
                    SpeedSparkline(values: model.samples, color: model.phase == "up" ? Theme.up : Theme.accent)
                        .frame(height: 48)
                    HStack {
                        metric("延迟", model.latency.map { String(format: "%.0f ms", $0) } ?? "—", Theme.ink(0.8))
                        Divider().frame(height: 30)
                        metric("下载", model.down.map { NetTestModel.mbps($0) + " Mbps" } ?? "—", Theme.down)
                        Divider().frame(height: 30)
                        metric("上传", model.up.map { NetTestModel.mbps($0) + " Mbps" } ?? "—", Theme.up)
                    }
                    if !model.route.isEmpty {
                        Label(model.route, systemImage: "arrow.triangle.branch").font(.caption2).foregroundStyle(.secondary).lineLimit(2)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    if let e = model.speedError { ErrorRow(message: e) }
                    startButton(running: model.speedRunning, title: model.speedRunning ? "停止" : "开始测速") {
                        if model.speedRunning { model.stopSpeed() } else { model.startSpeed(seconds: seconds, upload: upload) }
                    }
                }
            }
            Card {
                VStack(alignment: .leading, spacing: 10) {
                    Stepper(value: $seconds, in: 4...20, step: 2) { Text("每项时长 \(seconds) 秒") }
                    Toggle("测试上传", isOn: $upload).tint(Theme.accent)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("下载地址").font(.caption2).foregroundStyle(.secondary)
                        TextField("https://", text: $settings.downloadURL).urlField()
                    }
                    VStack(alignment: .leading, spacing: 4) {
                        Text("上传地址（POST）").font(.caption2).foregroundStyle(.secondary)
                        TextField("https://", text: $settings.uploadURL).urlField()
                    }
                    Text("4 路并发，经过当前规则和策略。测速会消耗流量：每项约等于速度 × 时长（100 Mbps × 8 秒 ≈ 100 MB）。")
                        .font(.caption2).foregroundStyle(.secondary)
                }
                .onChange(of: settings.downloadURL) { _ in settings.save() }
                .onChange(of: settings.uploadURL) { _ in settings.save() }
            }
        }
    }

    var phaseTitle: String {
        switch model.phase {
        case "latency": return String(localized: "测量延迟…")
        case "down": return String(localized: "下载中")
        case "up": return String(localized: "上传中")
        case "done": return String(localized: "下载速度")
        default: return String(localized: "经过当前策略")
        }
    }

    func metric(_ title: String, _ value: String, _ color: Color) -> some View {
        VStack(spacing: 2) {
            Text(LocalizedStringKey(title)).font(.caption2).foregroundStyle(.secondary)
            Text(value).font(.subheadline.monospacedDigit().weight(.semibold)).foregroundStyle(color).lineLimit(1).minimumScaleFactor(0.7)
        }
        .frame(maxWidth: .infinity)
    }

    func startButton(running: Bool, title: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack {
                Spacer()
                Text(LocalizedStringKey(title)).bold()
                Spacer()
            }
            .padding(.vertical, 10)
            .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(running ? Theme.bad.opacity(0.85) : Theme.accent.opacity(0.9)))
            .foregroundStyle(Theme.onAccent)
        }
        .buttonStyle(.plain)
    }

    // MARK: NAT

    var natCard: some View {
        VStack(spacing: 14) {
            Card {
                VStack(alignment: .leading, spacing: 12) {
                    if let r = model.nat {
                        HStack(alignment: .top) {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(r.title).font(.title3.weight(.semibold)).foregroundStyle(r.color)
                                Text(r.advice).font(.footnote).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                            }
                            Spacer()
                            Image(systemName: r.type == "blocked" ? "xmark.octagon" : "point.3.connected.trianglepath.dotted")
                                .font(.title2).foregroundStyle(r.color)
                        }
                        Divider()
                        row("映射", NATResult.behaviour(r.mapping))
                        row("过滤", NATResult.behaviour(r.filtering))
                        if let m = r.mapped, !m.isEmpty { row("公网 UDP 地址", m, mono: true) }
                        if let s = r.server, !s.isEmpty { row("STUN 服务器", s, mono: true) }
                        if let c = r.chain, !c.isEmpty { row("路径", ToolsView.routeText(chain: c, rule: r.rule, payload: r.rulePayload)) }
                        if let e = r.error, !e.isEmpty { ErrorRow(message: e) }
                        DisclosureGroup(isExpanded: $showSteps) {
                            VStack(alignment: .leading, spacing: 3) {
                                ForEach(Array(r.steps.enumerated()), id: \.offset) { _, s in
                                    Text(s).scaledFont(10, design: .monospaced).foregroundStyle(.secondary).textSelection(.enabled)
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                        } label: {
                            Text("测试步骤").font(.caption)
                        }
                    } else if model.natRunning {
                        LoadingRow(text: "正在测试（约 5–20 秒）…")
                    } else {
                        Text("按 RFC 5780 检测当前策略下 UDP 的映射和过滤方式。").font(.footnote).foregroundStyle(.secondary)
                    }
                    if let e = model.natError { ErrorRow(message: e) }
                    startButton(running: false, title: model.natRunning ? "测试中…" : "开始检测") {
                        Task { await model.runNAT(server: stunServer) }
                    }
                    .disabled(model.natRunning)
                }
            }
            Card {
                VStack(alignment: .leading, spacing: 4) {
                    Text("STUN 服务器（可选，逗号分隔）").font(.caption2).foregroundStyle(.secondary)
                    TextField("stun.miwifi.com:3478", text: $stunServer).urlField()
                    Text("留空时依次尝试 stun.miwifi.com、stun.stunprotocol.org、Google、Cloudflare。只有支持 RFC 5780 的服务器才能测出过滤方式。")
                        .font(.caption2).foregroundStyle(.secondary)
                }
            }
        }
    }

    func row(_ title: String, _ value: String, mono: Bool = false) -> some View {
        HStack(alignment: .top) {
            Text(LocalizedStringKey(title)).font(.footnote).foregroundStyle(.secondary)
            Spacer(minLength: 12)
            Text(value).font(mono ? .system(.footnote, design: .monospaced) : .footnote).multilineTextAlignment(.trailing).textSelection(.enabled)
        }
    }
}

private extension View {
    func urlField() -> some View {
        self.keyboardType(.URL)
            .textInputAutocapitalization(.never).autocorrectionDisabled()
            .font(.system(.footnote, design: .monospaced))
            .padding(10)
            .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Theme.cardHi))
    }
}

struct SpeedSparkline: View {
    let values: [Double]
    let color: Color
    var body: some View {
        GeometryReader { geo in
            let maxV = max(values.max() ?? 1, 1)
            let step = values.count > 1 ? geo.size.width / CGFloat(values.count - 1) : 0
            ZStack {
                if values.count > 1 {
                    Path { p in
                        for (i, v) in values.enumerated() {
                            let pt = CGPoint(x: CGFloat(i) * step, y: geo.size.height * (1 - CGFloat(v / maxV)))
                            if i == 0 { p.move(to: pt) } else { p.addLine(to: pt) }
                        }
                    }
                    .stroke(color, style: StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))
                } else {
                    Rectangle().fill(Theme.ink(0.08)).frame(height: 1).frame(maxHeight: .infinity, alignment: .bottom)
                }
            }
        }
    }
}
