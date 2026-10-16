import SwiftUI
import NetworkExtension
import Libmihomo

struct MoreView: View {
    @EnvironmentObject var vpn: VPNManager

    var body: some View {
        NavigationStack {
            List {
                Section("运行") {
                    NavigationLink { RulesView() } label: { Label("规则", systemImage: "list.bullet.rectangle") }
                    NavigationLink { ProvidersView() } label: { Label("提供者（规则集 / 节点集）", systemImage: "shippingbox") }
                    NavigationLink { LogsView() } label: { Label("日志", systemImage: "text.alignleft") }
                }
                .listRowBackground(Theme.card)
                Section("设置") {
                    NavigationLink { SettingsView() } label: { Label("内核覆写设置", systemImage: "slider.horizontal.3") }
                }
                .listRowBackground(Theme.card)
                Section {
                    ForEach(["重写 / MitM", "脚本", "模块", "桌面小组件", "控制中心开关", "快捷指令"], id: \.self) { f in
                        HStack {
                            Label(f, systemImage: "sparkles")
                            Spacer()
                            Text("即将推出").font(.caption).foregroundStyle(.secondary)
                        }
                        .foregroundStyle(.secondary)
                    }
                } header: { Text("高级功能") }
                .listRowBackground(Theme.card)
                Section("关于") {
                    NavigationLink { AboutView() } label: { Label("关于 / 开源许可", systemImage: "info.circle") }
                }
                .listRowBackground(Theme.card)
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("更多")
        }
    }
}

// MARK: - Rules

struct RulesView: View {
    @EnvironmentObject var vpn: VPNManager
    @State private var rules: [RuleItem] = []
    @State private var search = ""

    var filtered: [RuleItem] {
        guard !search.isEmpty else { return rules }
        let q = search.lowercased()
        return rules.filter { $0.payload.lowercased().contains(q) || $0.type.lowercased().contains(q) || $0.proxy.lowercased().contains(q) }
    }

    var body: some View {
        Group {
            if !vpn.isConnected { NotConnectedPlaceholder() } else {
                List(Array(filtered.enumerated()), id: \.offset) { i, r in
                    HStack(alignment: .top, spacing: 10) {
                        Text("\(i + 1)").font(.caption2.monospacedDigit()).foregroundStyle(.secondary).frame(width: 30, alignment: .trailing)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(r.payload.isEmpty ? r.type : r.payload).font(.system(.footnote, design: .monospaced)).lineLimit(2)
                            HStack(spacing: 6) {
                                Text(r.type).font(.caption2.weight(.semibold))
                                    .padding(.horizontal, 5).padding(.vertical, 1)
                                    .background(Capsule().fill(Color.white.opacity(0.1)))
                                if let s = r.size, s > 0 { Text("\(s) 条").font(.caption2).foregroundStyle(.secondary) }
                                Spacer()
                                Text(r.proxy).font(.caption).foregroundStyle(Theme.accent)
                            }
                        }
                    }
                    .listRowBackground(Theme.card)
                }
                .listStyle(.plain)
                .scrollContentBackground(.hidden)
                .searchable(text: $search, prompt: "搜索规则")
                .refreshable { await load() }
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("规则 \(rules.count)")
        .task { await load() }
    }

    func load() async { if let r = try? await ControllerClient.shared.rules() { rules = r } }
}

// MARK: - Providers

struct ProvidersView: View {
    @EnvironmentObject var vpn: VPNManager
    @State private var proxyProviders: [ProviderItem] = []
    @State private var ruleProviders: [ProviderItem] = []
    @State private var updating: Set<String> = []
    @State private var error: String?

    var body: some View {
        Group {
            if !vpn.isConnected { NotConnectedPlaceholder() } else {
                List {
                    if let error { Text(error).font(.footnote).foregroundStyle(Theme.bad).listRowBackground(Theme.card) }
                    Section("节点集 \(proxyProviders.count)") {
                        ForEach(proxyProviders) { p in
                            row(p, detail: "\(p.proxies?.count ?? 0) 个节点 · \(p.vehicleType ?? "")", key: "p:" + p.name) {
                                try await ControllerClient.shared.updateProxyProvider(p.name)
                            }
                        }
                    }
                    .listRowBackground(Theme.card)
                    Section("规则集 \(ruleProviders.count)") {
                        ForEach(ruleProviders) { p in
                            row(p, detail: "\(p.ruleCount ?? 0) 条 · \(p.behavior ?? "") · \(p.vehicleType ?? "")", key: "r:" + p.name) {
                                try await ControllerClient.shared.updateRuleProvider(p.name)
                            }
                        }
                    }
                    .listRowBackground(Theme.card)
                }
                .listStyle(.insetGrouped)
                .scrollContentBackground(.hidden)
                .refreshable { await load() }
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("提供者")
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button("全部更新") {
                    Task {
                        for p in proxyProviders where p.vehicleType == "HTTP" { try? await ControllerClient.shared.updateProxyProvider(p.name) }
                        for p in ruleProviders where p.vehicleType == "HTTP" { try? await ControllerClient.shared.updateRuleProvider(p.name) }
                        await load()
                    }
                }
                .disabled(!vpn.isConnected)
            }
        }
        .task { await load() }
    }

    @ViewBuilder
    func row(_ p: ProviderItem, detail: String, key: String, update: @escaping () async throws -> Void) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 3) {
                Text(p.name).font(.subheadline.weight(.semibold))
                Text(detail).font(.caption2).foregroundStyle(.secondary)
                if let u = p.updatedAt, let d = ConnectionItem.iso.date(from: u) ?? ConnectionItem.isoNoFrac.date(from: u) {
                    Text("更新于 \(d.formatted(.relative(presentation: .named)))").font(.caption2).foregroundStyle(.secondary)
                }
                if let s = p.subscriptionInfo, let t = s.Total, t > 0 {
                    Text("已用 \(Fmt.bytes((s.Upload ?? 0) + (s.Download ?? 0))) / \(Fmt.bytes(t))").font(.caption2).foregroundStyle(.secondary)
                }
            }
            Spacer()
            if updating.contains(key) { ProgressView() } else {
                Button {
                    Task {
                        updating.insert(key)
                        do { try await update(); error = nil } catch { self.error = error.localizedDescription }
                        updating.remove(key)
                        await load()
                    }
                } label: { Image(systemName: "arrow.clockwise") }
                .buttonStyle(.borderless)
                .disabled(p.vehicleType != "HTTP")
            }
        }
    }

    func load() async {
        do {
            proxyProviders = try await ControllerClient.shared.proxyProviders()
            ruleProviders = try await ControllerClient.shared.ruleProviders()
        } catch { self.error = error.localizedDescription }
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
                Toggle("允许局域网连接（7890 端口）", isOn: $o.allowLan)
                Picker("DNS 模式", selection: $o.dnsMode) {
                    Text("Fake-IP").tag("fake-ip")
                    Text("Redir-Host").tag("redir-host")
                }
                Toggle("域名嗅探（Sniffer）", isOn: $o.sniffer)
            } header: { Text("覆写（应用在配置之上）") } footer: {
                Text("这些选项会覆盖配置文件里的同名字段。修改 IPv6 需重新连接才能生效。")
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
                Text("仅监听 127.0.0.1。内核内存上限 \(o.memoryLimitMB) MB（系统对网络扩展的限制约 50 MB）。")
                    .font(.caption).foregroundStyle(.secondary)
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
        .navigationTitle("内核覆写设置")
        .onAppear { o = CoreOverrides.load(); portText = String(o.controllerPort) }
    }

    func apply() {
        if let p = Int(portText), (1024...65535).contains(p) { o.controllerPort = p } else { portText = String(o.controllerPort) }
        let old = CoreOverrides.load()
        o.mode = old.mode
        o.save()
        Task {
            if vpn.isConnected {
                if old.ipv6 != o.ipv6 || old.controllerPort != o.controllerPort || old.secret != o.secret {
                    status = "已保存。端口 / 密钥 / IPv6 变更需断开后重新连接。"
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

// MARK: - About

struct AboutView: View {
    var appVersion: String {
        let v = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        let b = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"
        return "\(v) (\(b))"
    }

    var body: some View {
        List {
            Section {
                LabeledContent("应用版本", value: appVersion)
                LabeledContent("内核", value: LibmihomoVersion())
            }
            .listRowBackground(Theme.card)
            Section("开源许可") {
                Text("本应用基于 mihomo（MetaCubeX/mihomo）内核，按 GNU General Public License v3.0 发布。你可以在 GPL-3.0 的条款下自由使用、修改和再分发本软件及其源代码。本软件不提供任何担保。")
                    .font(.footnote)
                Link("mihomo 源代码", destination: URL(string: "https://github.com/MetaCubeX/mihomo")!)
                Link("GNU GPL v3.0 全文", destination: URL(string: "https://www.gnu.org/licenses/gpl-3.0.html")!)
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
