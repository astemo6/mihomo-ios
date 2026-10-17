import SwiftUI
import NetworkExtension

// QX 分流规则 / 重写规则 / 日志 panels and the DNS page (toolbar 4).

// MARK: - 分流规则

struct QXRuleLine: Hashable {
    let type: String
    let payload: String
    let policy: String
}

struct QXRuleBlock: Identifiable, Hashable {
    enum Kind: Hashable { case set, local, final }
    let id: String
    let kind: Kind
    let name: String
    let policy: String
    let count: Int
    /// Inline rules (local / final blocks).
    let rules: [QXRuleLine]
}

@MainActor
final class QXRulesModel: ObservableObject {
    static let shared = QXRulesModel()
    @Published var blocks: [QXRuleBlock] = []
    @Published var total = 0
    @Published var loading = false
    @Published var expandedRules: [String: [QXRuleLine]] = [:]
    @Published var expandedNote: [String: String] = [:]

    func load() async {
        loading = true
        defer { loading = false }
        let insp = ProfileInspector.shared
        if insp.result.groups.isEmpty && insp.result.rules.isEmpty { await insp.load() }
        var lines: [QXRuleLine] = []
        var setCounts: [String: Int] = [:]
        if VPNManager.shared.isConnected, let live = try? await ControllerClient.shared.rules() {
            lines = live.map { QXRuleLine(type: $0.type, payload: $0.payload, policy: $0.proxy) }
            for p in (try? await ControllerClient.shared.ruleProviders()) ?? [] { setCounts[p.name] = p.ruleCount ?? 0 }
        } else {
            lines = insp.result.rules.map { QXRuleLine(type: $0.type, payload: $0.payload, policy: $0.proxy) }
        }
        for p in insp.result.ruleProviders where setCounts[p.name] == nil { setCounts[p.name] = p.count }
        var out: [QXRuleBlock] = []
        var local: [QXRuleLine] = []
        func flushLocal() {
            guard !local.isEmpty else { return }
            out.append(QXRuleBlock(id: "local-\(out.count)", kind: .local, name: String(localized: "本地规则"), policy: "", count: local.count, rules: local))
            local = []
        }
        for l in lines {
            if QXFmt.isRuleSet(l.type) {
                flushLocal()
                out.append(QXRuleBlock(id: "set-\(out.count)-\(l.payload)", kind: .set, name: l.payload, policy: l.policy, count: setCounts[l.payload] ?? 0, rules: []))
            } else if QXFmt.isFinal(l.type) {
                flushLocal()
                out.append(QXRuleBlock(id: "final", kind: .final, name: "FINAL", policy: l.policy, count: 1, rules: [l]))
            } else {
                local.append(l)
            }
        }
        flushLocal()
        blocks = out
        total = out.reduce(0) { $0 + $1.count }
    }

    /// Rules inside a rule set, read from the provider's cache file (text / YAML; .mrs is binary).
    func expand(_ b: QXRuleBlock) {
        guard b.kind == .set, expandedRules[b.id] == nil else { return }
        let insp = ProfileInspector.shared
        guard let p = insp.result.ruleProviders.first(where: { $0.name == b.name }) else {
            expandedNote[b.id] = String(localized: "找不到这个规则集的信息")
            expandedRules[b.id] = []
            return
        }
        if (p.format ?? "").lowercased() == "mrs" {
            expandedNote[b.id] = String(localized: "二进制规则集（mrs），无法展开查看。")
            expandedRules[b.id] = []
            return
        }
        guard let path = p.cachePath, let text = try? String(contentsOfFile: path, encoding: .utf8) else {
            if let prev = p.preview, !prev.isEmpty {
                expandedRules[b.id] = prev.map { Self.parseLine($0, behavior: p.behavior, policy: b.policy) }
            } else {
                expandedNote[b.id] = String(localized: "规则集尚未下载。")
                expandedRules[b.id] = []
            }
            return
        }
        var out: [QXRuleLine] = []
        var count = 0
        for raw in text.split(whereSeparator: \.isNewline) {
            var s = raw.trimmingCharacters(in: .whitespaces)
            if s.isEmpty || s.hasPrefix("#") || s.hasPrefix("//") || s.hasPrefix(";") || s == "payload:" { continue }
            if s.hasPrefix("- ") { s = String(s.dropFirst(2)).trimmingCharacters(in: CharacterSet(charactersIn: " '\"")) }
            count += 1
            if out.count < 1000 { out.append(Self.parseLine(s, behavior: p.behavior, policy: b.policy)) }
        }
        if count > out.count { expandedNote[b.id] = String(localized: "只显示前 \(out.count) 条，共 \(count) 条。") }
        expandedRules[b.id] = out
    }

    static func parseLine(_ s: String, behavior: String?, policy: String) -> QXRuleLine {
        switch (behavior ?? "").lowercased() {
        case "domain":
            if s.hasPrefix("+.") { return QXRuleLine(type: "DOMAIN-SUFFIX", payload: String(s.dropFirst(2)), policy: policy) }
            if s.hasPrefix(".") { return QXRuleLine(type: "DOMAIN-SUFFIX", payload: String(s.dropFirst()), policy: policy) }
            return QXRuleLine(type: "DOMAIN", payload: s, policy: policy)
        case "ipcidr":
            return QXRuleLine(type: s.contains(":") ? "IP-CIDR6" : "IP-CIDR", payload: s, policy: policy)
        default:
            let parts = s.split(separator: ",", maxSplits: 2).map { $0.trimmingCharacters(in: .whitespaces) }
            if parts.count >= 2 { return QXRuleLine(type: parts[0], payload: parts[1], policy: policy) }
            return QXRuleLine(type: "", payload: s, policy: policy)
        }
    }
}

struct QXRulesPanel: View {
    let active: Bool
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var store: ProfileStore
    @EnvironmentObject var nav: QXNavigator
    @ObservedObject private var model = QXRulesModel.shared
    @State private var expanded: Set<String> = []

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    Text("分流规则").font(.system(size: 22, weight: .bold))
                    Text(verbatim: QXFmt.count(model.total)).font(.system(size: 17)).foregroundStyle(.secondary)
                    Spacer()
                    if model.loading { ProgressView().controlSize(.small) }
                }
                .padding(.horizontal, 4).padding(.top, 14)
                if model.blocks.isEmpty && !model.loading {
                    Text("没有规则。").font(.footnote).foregroundStyle(.secondary).padding(.horizontal, 4)
                }
                ForEach(model.blocks) { b in
                    QXRuleBlockCard(block: b, expanded: expanded.contains(b.id), rules: rules(for: b), note: model.expandedNote[b.id]) {
                        withAnimation(.spring(response: 0.3)) {
                            if expanded.contains(b.id) { expanded.remove(b.id) } else { expanded.insert(b.id); model.expand(b) }
                        }
                    }
                    .contextMenu {
                        if b.kind == .set && vpn.isConnected {
                            Button { Task { try? await ControllerClient.shared.updateRuleProvider(b.name); await model.load() } } label: {
                                Label("更新", systemImage: "arrow.triangle.2.circlepath")
                            }
                        }
                        if b.kind == .local {
                            Button { nav.push(.dest(.customRules)) } label: { Label("编辑本地规则", systemImage: "square.and.pencil") }
                        }
                        Button { nav.push(.dest(.filterResources)) } label: { Label("规则资源", systemImage: "link") }
                        Button { UIPasteboard.general.string = b.name } label: { Label("拷贝名称", systemImage: "doc.on.doc") }
                    }
                }
            }
            .padding(.horizontal, QXMetrics.inset)
            .padding(.bottom, 110)
        }
        .refreshable { await model.load() }
        .task(id: "\(active)|\(vpn.isConnected)|\(store.activeID ?? "")") {
            guard active else { return }
            model.expandedRules = [:]
            model.expandedNote = [:]
            await model.load()
        }
    }

    private func rules(for b: QXRuleBlock) -> [QXRuleLine] {
        b.kind == .set ? (model.expandedRules[b.id] ?? []) : b.rules
    }
}

struct QXRuleBlockCard: View {
    let block: QXRuleBlock
    let expanded: Bool
    let rules: [QXRuleLine]
    let note: String?
    let onTap: () -> Void

    var body: some View {
        QXCard {
            VStack(spacing: 0) {
                HStack(spacing: 14) {
                    QXFunnel().fill(QXColor.rules).frame(width: 20, height: 20).frame(width: 30)
                    Text(verbatim: block.name).font(.system(size: 17)).lineLimit(1)
                    Spacer(minLength: 6)
                    if expanded && !block.policy.isEmpty {
                        QXChip(text: block.policy, color: QXPolicyColor.color(block.policy))
                    }
                    RoundedRectangle(cornerRadius: 1.5).fill(QXPolicyColor.color(block.policy)).frame(width: 3, height: 34)
                    Text(verbatim: QXFmt.count(block.count)).font(.system(size: 15).monospacedDigit()).foregroundStyle(.secondary)
                    Image(systemName: "chevron.right").font(.system(size: 13, weight: .semibold)).foregroundStyle(.secondary)
                        .rotationEffect(.degrees(expanded ? 90 : 0))
                }
                .padding(.horizontal, 16).padding(.vertical, 15)
                .contentShape(Rectangle())
                .onTapGesture(perform: onTap)
                if expanded {
                    if let note { Text(verbatim: note).font(.caption).foregroundStyle(.secondary).padding(.horizontal, 16).padding(.bottom, 8) }
                    ForEach(Array(rules.enumerated()), id: \.offset) { _, r in
                        Divider().padding(.leading, 20)
                        HStack(spacing: 6) {
                            Text(verbatim: r.payload).font(.system(size: 16)).lineLimit(1).truncationMode(.middle)
                            Spacer(minLength: 6)
                            if !r.type.isEmpty { QXChip(text: QXFmt.ruleType(r.type), color: QXColor.rules) }
                            if !r.policy.isEmpty { QXChip(text: r.policy, color: QXPolicyColor.color(r.policy)) }
                        }
                        .padding(.horizontal, QXMetrics.inset).padding(.vertical, 11)
                    }
                }
            }
        }
    }
}

// MARK: - 重写规则

struct QXRewriteBlock: Identifiable {
    let id: String
    let name: String
    let enabled: Bool
    let lines: [(kind: String, text: String)]
    let isLocal: Bool
}

struct QXRewritePanel: View {
    let active: Bool
    @EnvironmentObject var nav: QXNavigator
    @ObservedObject private var engine = EngineStore.shared
    @State private var expanded: Set<String> = []

    static func kind(of line: String) -> String {
        let l = line.lowercased()
        let types = ["script-response-body", "script-request-body", "script-response-header", "script-request-header", "script-echo-response",
                     "script-analyze-echo-response", "jsonjq-response-body", "jsonjq-request-body", "response-body", "request-body",
                     "response-header", "request-header", "echo-response", "reject-dict", "reject-array", "reject-200", "reject-img", "reject", "302", "307"]
        for t in types where l.contains(" " + t) { return t.uppercased() }
        if l.contains("script-path") || l.hasPrefix("http-request") || l.hasPrefix("http-response") { return "SCRIPT" }
        if l.contains("hostname") { return "HOSTNAME" }
        return "RULE"
    }

    var blocks: [QXRewriteBlock] {
        var out: [QXRewriteBlock] = []
        let local = (engine.config.rules + engine.config.scripts).filter(\.enabled)
        if !local.isEmpty {
            out.append(QXRewriteBlock(id: "local", name: String(localized: "已保存"), enabled: engine.config.enabled,
                                      lines: local.map { (kind: Self.kind(of: $0.line), text: $0.line) }, isLocal: true))
        }
        for m in engine.config.modules {
            let info = engine.moduleInfo[m.id]
            let lines = (info?.rules ?? []).map { (kind: $0.kind.uppercased(), text: $0.line.isEmpty ? $0.pattern : $0.line) }
            out.append(QXRewriteBlock(id: m.id, name: m.name, enabled: m.enabled, lines: lines, isLocal: false))
        }
        return out
    }

    var body: some View {
        let list = blocks
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    Text("重写规则").font(.system(size: 22, weight: .bold))
                    Text(verbatim: QXFmt.count(list.filter(\.enabled).reduce(0) { $0 + $1.lines.count })).font(.system(size: 17)).foregroundStyle(.secondary)
                    Spacer()
                    Toggle("", isOn: Binding(get: { engine.config.enabled }, set: { engine.config.enabled = $0; engine.save() }))
                        .labelsHidden().tint(QXColor.rewrite)
                        .accessibilityLabel(Text("重写"))
                }
                .padding(.horizontal, 4).padding(.top, 14)
                if list.isEmpty {
                    QXCard {
                        EmptyStateRow(icon: "pencil", title: "还没有重写", message: "在「设置 → 重写 → 规则资源」中添加模块，或长按「重写规则」磁贴。")
                            .padding(14)
                    }
                }
                ForEach(list) { b in
                    QXCard {
                        VStack(spacing: 0) {
                            HStack(spacing: 14) {
                                Image(systemName: "pencil").font(.system(size: 20, weight: .semibold)).foregroundStyle(QXColor.rewrite).frame(width: 30)
                                Text(verbatim: b.name).font(.system(size: 17)).lineLimit(1)
                                    .foregroundStyle(b.enabled ? Color.primary : Color.secondary)
                                if !b.enabled { Text("已停用").font(.caption2).foregroundStyle(.secondary) }
                                Spacer(minLength: 6)
                                RoundedRectangle(cornerRadius: 1.5).fill(Color.primary.opacity(0.08)).frame(width: 3, height: 34)
                                Text(verbatim: "\(b.lines.count)").font(.system(size: 15).monospacedDigit()).foregroundStyle(.secondary)
                                Image(systemName: "chevron.right").font(.system(size: 13, weight: .semibold)).foregroundStyle(.secondary)
                                    .rotationEffect(.degrees(expanded.contains(b.id) ? 90 : 0))
                            }
                            .padding(.horizontal, 16).padding(.vertical, 15)
                            .contentShape(Rectangle())
                            .onTapGesture {
                                withAnimation(.spring(response: 0.3)) {
                                    if expanded.contains(b.id) { expanded.remove(b.id) } else { expanded.insert(b.id) }
                                }
                            }
                            if expanded.contains(b.id) {
                                ForEach(Array(b.lines.prefix(500).enumerated()), id: \.offset) { _, l in
                                    Divider().padding(.leading, 20)
                                    VStack(alignment: .leading, spacing: 4) {
                                        QXChip(text: l.kind, color: QXColor.rewrite)
                                        Text(verbatim: l.text).font(.system(size: 13, design: .monospaced)).lineLimit(4).textSelection(.enabled)
                                    }
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .padding(.horizontal, QXMetrics.inset).padding(.vertical, 10)
                                }
                            }
                        }
                    }
                    .contextMenu {
                        if b.isLocal {
                            Button { nav.push(.dest(.localRewrite)) } label: { Label("编辑", systemImage: "square.and.pencil") }
                        } else if let i = engine.config.modules.firstIndex(where: { $0.id == b.id }) {
                            Button {
                                engine.config.modules[i].enabled.toggle()
                                engine.save()
                            } label: { Label(b.enabled ? LocalizedStringKey("停用") : LocalizedStringKey("启用"), systemImage: b.enabled ? "pause.circle" : "play.circle") }
                            Button {
                                let m = engine.config.modules[i]
                                Task { await engine.updateModule(m) }
                            } label: { Label("更新", systemImage: "arrow.triangle.2.circlepath") }
                        }
                        Button { nav.push(.dest(.rewriteResources)) } label: { Label("规则资源", systemImage: "link") }
                    }
                }
            }
            .padding(.horizontal, QXMetrics.inset)
            .padding(.bottom, 110)
        }
        .onAppear { if active { engine.reparseModules() } }
    }
}

// MARK: - 日志

struct QXLogPanel: View {
    let active: Bool
    @EnvironmentObject var vpn: VPNManager
    @StateObject private var model = LogsModel()
    @AppStorage("qx.logLevel") private var level = "info"
    @State private var startupLog = ""

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(vpn.isConnected ? LocalizedStringKey("内核日志") : LocalizedStringKey("启动日志")).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                        Spacer()
                        Menu {
                            Picker("级别", selection: $level) {
                                Text("调试").tag("debug")
                                Text("信息").tag("info")
                                Text("警告").tag("warning")
                                Text("错误").tag("error")
                            }
                            Button { model.lines.removeAll() } label: { Label("清空", systemImage: "trash") }
                            Button {
                                UIPasteboard.general.string = vpn.isConnected ? model.lines.map { "[\($0.level)] \($0.message)" }.joined(separator: "\n") : startupLog
                            } label: { Label("复制", systemImage: "doc.on.doc") }
                        } label: {
                            Image(systemName: "ellipsis.circle").font(.title3).foregroundStyle(.secondary)
                        }
                    }
                    .padding(.top, 12)
                    if vpn.isConnected {
                        if model.lines.isEmpty {
                            Text("暂无日志").font(.footnote).foregroundStyle(.secondary).padding(.top, 20)
                        }
                        ForEach(model.lines) { l in
                            Text(verbatim: "\(Self.time.string(from: l.time)) <\(l.level)> \(l.message)")
                                .font(.system(size: 12, design: .monospaced))
                                .foregroundStyle(l.level == "error" ? Theme.bad : (l.level == "warning" ? Theme.warn : Color.primary))
                                .textSelection(.enabled)
                                .id(l.id)
                        }
                    } else {
                        Text(verbatim: startupLog.isEmpty ? String(localized: "连接一次后生成。") : startupLog)
                            .font(.system(size: 12, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    Color.clear.frame(height: 1).id("qx-log-end")
                }
                .padding(.horizontal, 16)
                .padding(.bottom, 110)
            }
            .overlay(alignment: .bottomTrailing) {
                Button { withAnimation { proxy.scrollTo("qx-log-end", anchor: .bottom) } } label: {
                    Image(systemName: "chevron.down")
                        .font(.system(size: 17, weight: .semibold)).foregroundStyle(.primary)
                        .frame(width: 44, height: 44)
                        .background(Circle().fill(QXPalette.card)).shadow(color: QXPalette.shadow(0.12), radius: 8, y: 2)
                }
                .padding(.trailing, 20).padding(.bottom, 92)
                .accessibilityLabel(Text("跳到末尾"))
            }
        }
        .onAppear { startupLog = StartupLog.read() }
        .task(id: "\(active)|\(vpn.isConnected)|\(level)") {
            if active && vpn.isConnected {
                model.lines.removeAll()
                model.start(level: level)
            } else {
                model.stop()
                startupLog = StartupLog.read()
            }
        }
        .onDisappear { model.stop() }
    }

    static let time: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()
}

// MARK: - DNS (toolbar 4)

/// QX DNS 缓存. mihomo has no cache listing API yet, so this lists host → address pairs seen in this
/// session's connections, with flush (/cache/dns/flush) and the DNS settings.
struct QXDNSLogView: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var nav: QXNavigator
    @ObservedObject private var model = QXActivityModel.shared
    @State private var query = ""
    @State private var message: String?

    struct Entry: Identifiable {
        var id: String { host }
        let host: String
        var addrs: [String]
        var time: Date?
        var rule: String
    }

    var entries: [Entry] {
        var map: [String: Entry] = [:]
        var order: [String] = []
        for r in model.records {
            let m = r.conn.metadata
            guard let h = (m.host?.isEmpty == false ? m.host : m.sniffHost), !h.isEmpty else { continue }
            let ip = m.destinationIP ?? ""
            if var e = map[h] {
                if !ip.isEmpty && !e.addrs.contains(ip) { e.addrs.append(ip) }
                map[h] = e
            } else {
                map[h] = Entry(host: h, addrs: ip.isEmpty ? [] : [ip], time: r.conn.startDate, rule: r.ruleLine)
                order.append(h)
            }
        }
        return order.compactMap { map[$0] }.filter { query.isEmpty || $0.host.localizedCaseInsensitiveContains(query) }
    }

    var body: some View {
        QXPage {
            QXCapsuleBar {
                QXBarIcon(systemName: "gearshape") { nav.push(.dest(.dns)) }
                    .accessibilityLabel(Text("DNS 设置"))
                QXBarIcon(systemName: "network.slash", tint: QXColor.activity) {
                    Task {
                        do {
                            _ = try await ControllerClient.shared.send("/cache/dns/flush", method: "POST")
                            message = String(localized: "已清空 DNS 缓存")
                        } catch {
                            message = error.localizedDescription
                        }
                    }
                }
                .accessibilityLabel(Text("清空 DNS 缓存"))
                .disabled(!vpn.isConnected)
            }
        } content: {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    QXLargeTitle(title: String(localized: "DNS 缓存"), count: "\(entries.count)",
                                 caption: String(localized: "本次连接中解析过的域名与地址（来自连接记录）。使用 fake-ip 时地址为 198.18.x.x 占位地址。"))
                        .padding(.horizontal, QXMetrics.inset).padding(.bottom, 10)
                    if let message { Text(verbatim: message).font(.footnote).foregroundStyle(Theme.good).padding(.horizontal, QXMetrics.inset).padding(.bottom, 6) }
                    TextField("搜索", text: $query)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .padding(10).background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(QXPalette.card))
                        .padding(.horizontal, QXMetrics.inset).padding(.bottom, 8)
                    if !vpn.isConnected && entries.isEmpty {
                        EmptyStateView(icon: "globe", title: "连接后可查看")
                    }
                    ForEach(entries) { e in
                        VStack(alignment: .leading, spacing: 4) {
                            if let t = e.time { Text(verbatim: QXFmt.stamp.string(from: t)).font(.system(size: 14).monospacedDigit()).foregroundStyle(.secondary) }
                            Text(verbatim: e.host).font(.system(size: 19)).lineLimit(1).truncationMode(.middle)
                            HStack(spacing: 6) {
                                QXChip(text: "ADDR", color: QXColor.rules)
                                Text(verbatim: e.addrs.isEmpty ? "—" : e.addrs.joined(separator: ", "))
                                    .font(.system(size: 13, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1)
                            }
                            Text(verbatim: e.rule).font(.system(size: 12, weight: .medium)).foregroundStyle(.secondary).lineLimit(1)
                        }
                        .padding(.horizontal, QXMetrics.inset).padding(.vertical, 10)
                        .contextMenu {
                            Button { UIPasteboard.general.string = e.host } label: { Label("拷贝主机名", systemImage: "doc.on.doc") }
                        }
                        Divider().padding(.leading, 20)
                    }
                }
                .padding(.bottom, 40)
            }
        }
        .task(id: vpn.isConnected) {
            guard vpn.isConnected else { return }
            await model.poll()
        }
    }
}
