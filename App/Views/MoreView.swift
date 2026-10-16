import SwiftUI
import NetworkExtension
import Libmihomo

struct MoreView: View {
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject var engine = EngineStore.shared

    var body: some View {
        NavigationStack {
            List {
                Section("连接") {
                    NavigationLink { ConnectionView() } label: {
                        row("连接方式与按需连接", "point.3.filled.connected.trianglepath.dotted",
                            CoreOverrides.load().isProxyOnly ? "仅代理" : "全局隧道")
                    }
                    NavigationLink { DNSView() } label: {
                        row("DNS", "network", DNSOverrideSettings.load().enabled ? "自定义" : "配置文件")
                    }
                }
                .listRowBackground(Theme.card)

                Section("规则与资源") {
                    NavigationLink { RulesView() } label: { row("规则", "list.bullet.rectangle", nil) }
                    NavigationLink { ProvidersView() } label: { row("提供者（规则集 / 节点集）", "shippingbox", nil) }
                    NavigationLink { GeoView() } label: { row("地理与规则库", "globe.asia.australia", nil) }
                }
                .listRowBackground(Theme.card)

                Section {
                    NavigationLink { ModulesView() } label: {
                        row("模块", "puzzlepiece.extension", "\(engine.config.modules.filter(\.enabled).count)/\(engine.config.modules.count)")
                    }
                    NavigationLink { RewriteView() } label: { row("重写", "arrow.triangle.swap", "\(engine.config.rules.count)") }
                    NavigationLink { ScriptsView() } label: { row("脚本", "curlybraces", "\(engine.config.scripts.count)") }
                    NavigationLink { MitMView() } label: {
                        HStack {
                            Label("MitM", systemImage: "lock.open")
                            Spacer()
                            Text(engine.config.mitm ? "已开启" : "关闭").font(.caption).foregroundStyle(engine.config.mitm ? Theme.good : .secondary)
                        }
                    }
                } header: { Text("模块、重写与 MitM") } footer: {
                    Text(engine.config.enabled ? "重写与脚本已启用" : "重写与脚本未启用（在模块、重写或脚本页面顶部开启）")
                }
                .listRowBackground(Theme.card)

                Section("工具与数据") {
                    NavigationLink { ToolsView() } label: { row("网络工具（Ping / TCP / DNS）", "stethoscope.circle", nil) }
                    NavigationLink { StatsView() } label: { row("流量统计", "chart.bar.xaxis", nil) }
                    NavigationLink { LogsView() } label: { row("日志", "text.alignleft", nil) }
                    NavigationLink { BackupView() } label: { row("备份与恢复", "externaldrive.badge.icloud", nil) }
                }
                .listRowBackground(Theme.card)

                Section("设置") {
                    NavigationLink { SettingsView() } label: { row("内核设置", "slider.horizontal.3", nil) }
                    NavigationLink { DiagnosticsView() } label: {
                        HStack {
                            Label("诊断", systemImage: "waveform.path.ecg")
                            Spacer()
                            Text(AppShared.containerOK ? "App Group 正常" : "App Group 异常")
                                .font(.caption).foregroundStyle(AppShared.containerOK ? Theme.good : Theme.bad)
                        }
                    }
                }
                .listRowBackground(Theme.card)

                Section {
                    NavigationLink { AboutView() } label: { row("关于 / 开源许可", "info.circle", nil) }
                }
                .listRowBackground(Theme.card)
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("更多")
        }
    }

    func row(_ title: String, _ icon: String, _ value: String?) -> some View {
        HStack {
            Label(title, systemImage: icon)
            Spacer()
            if let value { Text(value).font(.caption).foregroundStyle(.secondary) }
        }
    }
}

// MARK: - Logs

@MainActor
final class LogsModel: ObservableObject {
    @Published var lines: [LogLine] = []
    @Published var paused = false
    private var task: Task<Void, Never>?

    func start(level: String) {
        task?.cancel()
        task = Task { [weak self] in
            while !Task.isCancelled {
                for await l in ControllerClient.shared.stream("/logs", query: [URLQueryItem(name: "level", value: level)], as: LogPayload.self) {
                    guard let self else { return }
                    if self.paused { continue }
                    self.lines.append(LogLine(level: l.type, message: l.payload, time: Date()))
                    if self.lines.count > 1000 { self.lines.removeFirst(self.lines.count - 1000) }
                }
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }

    func stop() { task?.cancel(); task = nil }
}

struct LogsView: View {
    @EnvironmentObject var vpn: VPNManager
    @StateObject private var model = LogsModel()
    @State private var level = "info"
    @State private var search = ""

    var shown: [LogLine] {
        guard !search.isEmpty else { return model.lines }
        return model.lines.filter { $0.message.localizedCaseInsensitiveContains(search) }
    }

    var body: some View {
        Group {
            if !vpn.isConnected { NotConnectedPlaceholder() } else {
                VStack(spacing: 0) {
                    Picker("级别", selection: $level) {
                        Text("调试").tag("debug")
                        Text("信息").tag("info")
                        Text("警告").tag("warning")
                        Text("错误").tag("error")
                    }
                    .pickerStyle(.segmented)
                    .padding(12)
                    ScrollViewReader { proxy in
                        List(shown) { l in
                            VStack(alignment: .leading, spacing: 2) {
                                HStack {
                                    Text(l.level.uppercased()).font(.system(size: 9, weight: .bold)).foregroundStyle(color(l.level))
                                    Text(l.time.formatted(date: .omitted, time: .standard)).font(.system(size: 9).monospacedDigit()).foregroundStyle(.secondary)
                                }
                                Text(l.message).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                            }
                            .id(l.id)
                            .listRowBackground(Theme.card)
                        }
                        .listStyle(.plain)
                        .scrollContentBackground(.hidden)
                        .onChange(of: model.lines.count) { _ in
                            if !model.paused, let last = shown.last { proxy.scrollTo(last.id, anchor: .bottom) }
                        }
                    }
                }
                .searchable(text: $search, prompt: "过滤日志")
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("日志")
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                Button { model.paused.toggle() } label: { Image(systemName: model.paused ? "play.fill" : "pause.fill") }
                Button { model.lines.removeAll() } label: { Image(systemName: "trash") }
                Button { UIPasteboard.general.string = model.lines.map { "[\($0.level)] \($0.message)" }.joined(separator: "\n") } label: { Image(systemName: "doc.on.doc") }
            }
        }
        .onAppear { if vpn.isConnected { model.start(level: level) } }
        .onDisappear { model.stop() }
        .onChange(of: level) { l in model.lines.removeAll(); model.start(level: l) }
    }

    func color(_ l: String) -> Color {
        switch l {
        case "error": return Theme.bad
        case "warning": return Theme.warn
        case "debug": return .secondary
        default: return Theme.accent
        }
    }
}

// MARK: - Settings

struct SettingsView: View {
    @EnvironmentObject var vpn: VPNManager
    @State private var o = CoreOverrides.load()
    @State private var portText = ""
    @State private var status: String?

    var body: some View {
        Form {
            Section {
                Picker("日志级别", selection: $o.logLevel) {
                    Text("静默").tag("silent")
                    Text("错误").tag("error")
                    Text("警告").tag("warning")
                    Text("信息").tag("info")
                    Text("调试").tag("debug")
                }
                Toggle("IPv6", isOn: $o.ipv6)
                Toggle("域名嗅探（Sniffer）", isOn: $o.sniffer)
                Toggle("允许局域网连接（\(o.mixedPort) 端口）", isOn: $o.allowLan)
            } header: { Text("内核") } footer: {
                Text("这些选项会覆盖配置文件里的同名字段。DNS 模式在「更多 → DNS」中设置。IPv6 变更需重新连接。")
            }
            .listRowBackground(Theme.card)

            Section {
                Toggle("把手动节点加入每个配置", isOn: $o.mergeManual)
            } header: { Text("节点") } footer: {
                Text("开启后「手动节点」配置里的节点和同名策略组会合并进当前使用的订阅，可以在策略页直接选择。")
            }
            .listRowBackground(Theme.card)

            Section {
                Stepper(value: $o.memoryLimitMB, in: 24...45, step: 1) {
                    HStack {
                        Text("内核内存上限")
                        Spacer()
                        Text("\(o.memoryLimitMB) MB").monospacedDigit().foregroundStyle(.secondary)
                    }
                }
                Picker("隧道 MTU", selection: $o.tunMTU) {
                    ForEach(CoreOverrides.mtuChoices, id: \.self) { Text(String($0)).tag($0) }
                }
            } header: { Text("性能") } footer: {
                Text("iOS 限制网络扩展约 50 MB 内存。内存上限是 Go 运行时的软上限（默认 \(CoreOverrides.defaultMemoryLimitMB) MB）：调低更稳但更费电，调高可容纳更多连接。接近系统上限时扩展会先释放内存，再关闭连接。MTU 默认 4064，遇到个别网络异常可改为 1500。两项都在重新连接后生效。")
            }
            .listRowBackground(Theme.card)

            Section("外部控制器") {
                HStack {
                    Text("端口")
                    Spacer()
                    TextField("9090", text: $portText).keyboardType(.numberPad).multilineTextAlignment(.trailing).frame(width: 90)
                }
                HStack {
                    Text("密钥")
                    Spacer()
                    Text(String(o.secret.prefix(6)) + "••••").font(.system(.body, design: .monospaced)).foregroundStyle(.secondary)
                }
                Button("重新生成密钥") { o.secret = CoreOverrides.randomSecret() }
                Text("仅监听 127.0.0.1。").font(.caption).foregroundStyle(.secondary)
            }
            .listRowBackground(Theme.card)

            Section {
                Button {
                    apply()
                } label: {
                    HStack { Spacer(); Text(vpn.isConnected ? "保存并重载内核" : "保存").bold(); Spacer() }
                }
                if let status { Text(status).font(.footnote).foregroundStyle(.secondary) }
            }
            .listRowBackground(Theme.card)
        }
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("内核设置")
        .onAppear { o = CoreOverrides.load(); portText = String(o.controllerPort) }
    }

    func apply() {
        if let p = Int(portText), (1024...65535).contains(p) { o.controllerPort = p } else { portText = String(o.controllerPort) }
        let old = CoreOverrides.load()
        // Fields owned by other pages: keep what they saved.
        o.mode = old.mode
        o.dnsMode = old.dnsMode
        o.tunnelMode = old.tunnelMode
        o.geoMirror = old.geoMirror
        o.geoURLs = old.geoURLs
        o.save()
        Task {
            if vpn.isConnected {
                if old.ipv6 != o.ipv6 || old.controllerPort != o.controllerPort || old.secret != o.secret || old.tunMTU != o.tunMTU || old.memoryLimitMB != o.memoryLimitMB {
                    if let err = await vpn.reload() { status = "重载失败：\(err)" } else {
                        status = "已保存。端口 / 密钥 / IPv6 / MTU / 内存上限在断开后重新连接时生效。"
                    }
                } else if let err = await vpn.reload() {
                    status = "重载失败：\(err)"
                } else {
                    status = "已保存并重载"
                }
            } else {
                status = "已保存，下次连接生效"
            }
        }
    }
}

// MARK: - Diagnostics

struct DiagnosticsView: View {
    @EnvironmentObject var vpn: VPNManager
    @State private var startupLog = StartupLog.read()
    var body: some View {
        let group = AppShared.appGroup
        List {
            Section {
                LabeledContent("主程序 ID", value: AppShared.mainAppBundleID)
                LabeledContent("隧道扩展 ID", value: AppShared.tunnelBundleID)
                LabeledContent("App Group", value: group)
                LabeledContent("来源", value: AppShared.appGroupSource)
                LabeledContent("共享容器") {
                    Text(AppShared.containerOK ? "正常" : "不可用").foregroundStyle(AppShared.containerOK ? Theme.good : Theme.bad)
                }
                let groups = AppShared.provisionedAppGroups()
                LabeledContent("描述文件中的组", value: groups.isEmpty ? "（未找到 embedded.mobileprovision）" : groups.sorted().joined(separator: "\n"))
                LabeledContent("VPN 状态", value: vpn.statusText)
                LabeledContent("连接方式", value: CoreOverrides.load().isProxyOnly ? "仅代理（NEProxySettings）" : "全局隧道（PacketFlowBridge）")
            } header: { Text("签名与容器") } footer: {
                Text("重签名后描述文件会替换 entitlements。App 与扩展会在运行时从描述文件读取 App Group 并按字母序选第一个可用的；共享容器不可用时扩展无法读取配置，连接会失败。")
            }
            .listRowBackground(Theme.card)
            if let e = vpn.lastError {
                Section("最近错误") { Text(e).font(.footnote).textSelection(.enabled) }.listRowBackground(Theme.card)
            }
            Section {
                let log = startupLog.isEmpty ? "（暂无，连接一次后生成）" : startupLog
                ScrollView(.horizontal) {
                    Text(log)
                        .font(.system(size: 10, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 360)
                HStack {
                    Button("复制启动日志") { UIPasteboard.general.string = startupLog }
                    Spacer()
                    Button("刷新") { startupLog = StartupLog.read() }
                }
                .buttonStyle(.borderless)
            } header: { Text("启动日志") } footer: {
                Text("记录每次连接的阶段与耗时：网络设置、数据包桥接、内核启动开始 / 结束、内存占用和错误。连接失败时请复制发给开发者。")
            }
            .listRowBackground(Theme.card)
            Section {
                Button("复制诊断信息") {
                    UIPasteboard.general.string = """
                    app=\(AppShared.mainAppBundleID)
                    tunnel=\(AppShared.tunnelBundleID)
                    group=\(group) (\(AppShared.appGroupSource)) ok=\(AppShared.containerOK)
                    provisioned=\(AppShared.provisionedAppGroups().joined(separator: ","))
                    status=\(vpn.statusText) error=\(vpn.lastError ?? "-")
                    mode=\(CoreOverrides.load().tunnelMode) mtu=\(CoreOverrides.load().tunMTU) memlimit=\(CoreOverrides.load().memoryLimitMB)MB ondemand=\(OnDemandSettings.load().mode.rawValue) paused=\(OnDemandSettings.isPaused)
                    version=\(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?")
                    --- startup log ---
                    \(StartupLog.read())
                    """
                }
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("诊断")
        .onAppear { startupLog = StartupLog.read() }
    }
}

// MARK: - About

struct AboutView: View {
    var appVersion: String {
        let v = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        let b = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"
        return "\(v) (\(b))"
    }

    struct Credit: Identifiable {
        var id: String { name }
        let name: String
        let note: String
        let license: String
        let url: String
    }

    static let credits: [Credit] = [
        Credit(name: "mihomo", note: "代理内核（MetaCubeX）", license: "GPL-3.0", url: "https://github.com/MetaCubeX/mihomo"),
        Credit(name: "TokenPLS/Hako", note: "iOS 客户端设计参考：NetworkExtension 内存控制与 GC 节奏（现 ProjectClash/Clash-Legacy）", license: "GPL-3.0", url: "https://github.com/ProjectClash/Clash-Legacy"),
        Credit(name: "Hako-Adapter", note: "PacketFlowBridge 思路：socketpair 连接 NEPacketTunnelFlow 与内核（现 ProjectClash/Clash-Adapter-Legacy）", license: "GPL-3.0", url: "https://github.com/ProjectClash/Clash-Adapter-Legacy"),
        Credit(name: "ProjectClash", note: "Hako / Hako-Adapter 的维护者，后续项目 Clash-Adapter", license: "GPL-3.0", url: "https://github.com/ProjectClash"),
        Credit(name: "MetaCubeX/meta-rules-dat", note: "内置 GeoIP / GeoSite / ASN 数据库", license: "见上游仓库", url: "https://github.com/MetaCubeX/meta-rules-dat"),
        Credit(name: "goja · gojq · regexp2", note: "脚本、jq 与正则引擎", license: "MIT", url: "https://github.com/dop251/goja"),
    ]

    var body: some View {
        List {
            Section {
                LabeledContent("应用版本", value: appVersion)
                LabeledContent("内核", value: LibmihomoVersion())
            }
            .listRowBackground(Theme.card)
            Section {
                Text("本应用以 GNU General Public License v3.0 发布，与 mihomo 内核许可一致。你可以在 GPL-3.0 的条款下自由使用、修改和再分发本软件及其源代码。本软件不提供任何担保。")
                    .font(.footnote)
                Link("本项目源代码", destination: URL(string: "https://github.com/astemo6/mihomo-ios")!)
                Link("GNU GPL v3.0 全文", destination: URL(string: "https://www.gnu.org/licenses/gpl-3.0.html")!)
            } header: { Text("开源许可") }
            .listRowBackground(Theme.card)
            Section {
                ForEach(Self.credits) { c in
                    Link(destination: URL(string: c.url)!) {
                        VStack(alignment: .leading, spacing: 2) {
                            HStack {
                                Text(c.name).font(.subheadline.weight(.semibold)).foregroundStyle(.primary)
                                Spacer()
                                Text(c.license).font(.caption2.weight(.bold)).foregroundStyle(Theme.accent)
                            }
                            Text(c.note).font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                }
            } header: { Text("致谢") } footer: {
                Text("PacketFlowBridge 与内存守护参考了 TokenPLS/Hako 与 Hako-Adapter（现 ProjectClash）的设计，均为 GPL-3.0；本项目的实现是独立编写的，同样以 GPL-3.0 发布。完整说明见仓库中的 NOTICE。")
            }
            .listRowBackground(Theme.card)
            Section("说明") {
                Text("仅供个人学习与合法用途。请遵守当地法律法规。").font(.footnote).foregroundStyle(.secondary)
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("关于")
    }
}
