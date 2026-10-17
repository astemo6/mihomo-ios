import SwiftUI

// QX-3: QX chrome wrappers for the remaining classic pages (DNS, 脚本, 持久化存储), 配置片段 and 初始化.

/// Any classic page inside QX chrome (floating back circle, inline title, no navigation bar).
struct QXWrappedPage<Content: View>: View {
    let title: String
    @ViewBuilder var content: Content
    var body: some View {
        QXPage(title: title) {
            content.toolbar(.hidden, for: .navigationBar)
        }
    }
}

struct QXDNSPage: View {
    @EnvironmentObject var nav: QXNavigator
    var body: some View {
        QXPage(title: "DNS") {
            QXCapsuleBar {
                QXBarIcon(systemName: "globe") { nav.push(.dest(.dnsLog)) }
                    .accessibilityLabel(Text("DNS 缓存"))
                QXBarIcon(systemName: "network.slash") { nav.push(.dest(.blocked)) }
                    .accessibilityLabel(Text("DNS 阻止的域名"))
            }
        } content: {
            DNSView().toolbar(.hidden, for: .navigationBar)
        }
    }
}

struct QXScriptsPage: View {
    @EnvironmentObject var nav: QXNavigator
    @State private var adding = false
    @State private var addingRaw = false
    var body: some View {
        QXPage(title: String(localized: "脚本")) {
            QXCapsuleBar {
                QXBarIcon(systemName: "alarm") { nav.push(.dest(.tasks)) }
                    .accessibilityLabel(Text("请求列表"))
                QXBarIcon(systemName: "text.alignleft") { nav.push(.dest(.scriptLogs)) }
                    .accessibilityLabel(Text("运行日志"))
                Menu {
                    Button { adding = true } label: { Label("新建 / 导入脚本", systemImage: "doc.badge.plus") }
                    Button { addingRaw = true } label: { Label("粘贴脚本行", systemImage: "text.badge.plus") }
                } label: {
                    Image(systemName: "plus").font(.system(size: 17, weight: .semibold)).foregroundStyle(.primary).frame(width: 38, height: 40)
                }
                .accessibilityLabel(Text("添加"))
            }
        } content: {
            ScriptsView().toolbar(.hidden, for: .navigationBar)
        }
        .sheet(isPresented: $adding) { ScriptFormSheet(item: nil) }
        .sheet(isPresented: $addingRaw) { LineEditorSheet(title: String(localized: "粘贴脚本行"), scripts: true, item: nil) }
    }
}

// MARK: - 配置片段

enum QXSnippetKind: String, Identifiable, CaseIterable {
    case nodes, filter, rewrite
    var id: String { rawValue }

    var title: String {
        switch self {
        case .nodes: return String(localized: "片段 - 节点")
        case .filter: return String(localized: "片段 - 分流")
        case .rewrite: return String(localized: "片段 - 重写")
        }
    }

    var caption: String {
        switch self {
        case .nodes: return String(localized: "每行一个节点：分享链接（vless:// hysteria2:// tuic:// ss:// …）、Surge / Quantumult X / Loon 节点行或 Clash YAML，保存到「已保存」节点。")
        case .filter: return String(localized: "每行一条分流规则：mihomo / Surge 写法（DOMAIN-SUFFIX,example.com,PROXY）或 Quantumult X 写法（host-suffix, example.com, proxy），也可以是远程列表行。加在分流规则最前面。")
        case .rewrite: return String(localized: "每行一条重写或脚本：Quantumult X、Surge、Loon 写法都可以；hostname = … 会加入 MitM 主机名。")
        }
    }

    var sample: String {
        switch self {
        case .nodes: return "vless://uuid@example.com:443?security=reality&pbk=…&sid=…&sni=www.apple.com#🇯🇵 东京\nshadowsocks=example.com:8388, method=aes-128-gcm, password=pwd, tag=🇭🇰 香港"
        case .filter: return "host-suffix, example.com, proxy\nDOMAIN-KEYWORD,openai,PROXY\nhttps://example.com/AI.list, tag=AI, force-policy=PROXY"
        case .rewrite: return "^https?:\\/\\/api\\.example\\.com\\/ad url reject-dict\nhostname = api.example.com"
        }
    }

    var color: Color {
        switch self {
        case .nodes: return QXColor.nodes
        case .filter: return QXColor.rules
        case .rewrite: return QXColor.rewrite
        }
    }
}

struct QXSnippetEditor: View {
    let kind: QXSnippetKind
    @EnvironmentObject var store: ProfileStore
    @ObservedObject private var rules = CustomRulesStore.shared
    @ObservedObject private var engine = EngineStore.shared
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""
    @State private var saving = false
    @State private var result: String?
    @State private var failed = false

    var lines: [String] {
        text.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") && !$0.hasPrefix(";") && !$0.hasPrefix("//") && !$0.hasPrefix("[") }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                QXLargeTitle(title: kind.title, caption: kind.caption)
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("内容").font(.system(size: 20, weight: .bold))
                        Text(verbatim: "\(lines.count)").foregroundStyle(.secondary)
                        Spacer()
                        QXPill(title: String(localized: "粘贴")) { text += (text.isEmpty ? "" : "\n") + (UIPasteboard.general.string ?? "") }
                    }
                    TextEditor(text: $text)
                        .font(.system(size: 14, design: .monospaced))
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .frame(minHeight: 220)
                        .scrollContentBackground(.hidden)
                        .padding(8)
                        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(QXPalette.card))
                }
                VStack(alignment: .leading, spacing: 6) {
                    Text("示例").font(.system(size: 17, weight: .semibold))
                    Text(verbatim: kind.sample).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                }
                if let result {
                    Text(verbatim: result).font(.footnote).foregroundStyle(failed ? Theme.bad : QXColor.mitm)
                }
            }
            .padding(.horizontal, 24)
            .padding(.top, 70)
            .padding(.bottom, 40)
        }
        .background(QXPalette.bg.ignoresSafeArea())
        .overlay(alignment: .top) {
            HStack {
                QXCircleButton(systemName: "xmark") { dismiss() }.accessibilityLabel(Text("取消"))
                Spacer()
                if saving {
                    ProgressView().frame(width: 44, height: 44)
                } else {
                    QXCircleButton(systemName: "checkmark", tint: lines.isEmpty ? .secondary : kind.color) { Task { await save() } }
                        .disabled(lines.isEmpty)
                        .accessibilityLabel(Text("保存"))
                }
            }
            .padding(.horizontal, 16).padding(.top, 12).padding(.bottom, 8)
            .background(LinearGradient(colors: [QXPalette.bg, QXPalette.bg.opacity(0)], startPoint: .top, endPoint: .bottom))
        }
    }

    func save() async {
        saving = true
        failed = false
        defer { saving = false }
        switch kind {
        case .nodes:
            do {
                let n = try await store.addManualNodes(text: text)
                result = String(localized: "已添加 \(n) 个节点到手动节点")
                text = ""
            } catch {
                failed = true
                result = error.localizedDescription
            }
        case .filter:
            let new = lines.map { CustomRule(line: $0, enabled: true) }
            rules.rules.insert(contentsOf: new, at: 0)
            rules.save()
            ResourceStore.shared.reload()
            if VPNManager.shared.isConnected, let e = await VPNManager.shared.reload() {
                failed = true
                result = String(localized: "已保存，但重载失败：\(e)")
            } else {
                result = String(localized: "已添加 \(new.count) 条分流规则（在「分流规则」中查看检查结果）")
                text = ""
            }
        case .rewrite:
            let n = engine.addLines(text, toScripts: false)
            if !engine.config.enabled { engine.config.enabled = true; engine.save() }
            result = String(localized: "已添加 \(n) 条重写 / 脚本")
            text = ""
        }
    }
}

struct QXSnippetsView: View {
    @EnvironmentObject var nav: QXNavigator
    @EnvironmentObject var store: ProfileStore
    @ObservedObject private var rules = CustomRulesStore.shared
    @ObservedObject private var engine = EngineStore.shared
    @State private var editing: QXSnippetKind?

    var body: some View {
        QXPage(title: String(localized: "配置片段")) {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    QXLargeTitle(title: String(localized: "配置片段"),
                                 caption: String(localized: "本地片段与配置一起生效：节点加入「已保存」，分流规则排在配置的规则之前，重写与本地模块一起加载。"))
                    snippetCard(.nodes, count: store.manualNodes().count, open: .manualNodes)
                    snippetCard(.filter, count: rules.rules.count, open: .customRules)
                    snippetCard(.rewrite, count: engine.config.rules.count + engine.config.scripts.count, open: .localRewrite)
                }
                .padding(.horizontal, QXMetrics.inset)
                .padding(.bottom, 50)
            }
        }
        .sheet(item: $editing) { k in QXSnippetEditor(kind: k).environmentObject(store) }
    }

    func snippetCard(_ k: QXSnippetKind, count: Int, open: QXDest) -> some View {
        QXCard {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .firstTextBaseline) {
                    Text(verbatim: k.title).font(.system(size: 20, weight: .bold))
                    Text(verbatim: "\(count)").foregroundStyle(.secondary)
                    Spacer()
                }
                Text(verbatim: k.caption).font(.footnote).foregroundStyle(.secondary)
                QXActionGrid(color: k.color, items: [
                    QXActionSpec(title: String(localized: "添加"), icon: "plus") { editing = k },
                    QXActionSpec(title: String(localized: "查看"), icon: "list.bullet") { nav.push(.dest(open)) },
                ])
            }
            .padding(16)
        }
    }
}

// MARK: - 初始化

struct QXResetView: View {
    @EnvironmentObject var store: ProfileStore
    @EnvironmentObject var vpn: VPNManager
    @Environment(\.dismiss) private var dismiss
    @State private var resetRules = true
    @State private var resetPolicies = true
    @State private var resetRewrite = true
    @State private var resetNodeSubs = true
    @State private var resetUI = true
    @State private var resetCore = false
    @State private var resetProfiles = false
    @State private var confirm = false
    @State private var working = false
    @State private var done: String?

    var anySelected: Bool { resetRules || resetPolicies || resetRewrite || resetNodeSubs || resetUI || resetCore || resetProfiles }

    var body: some View {
        QXPage(title: String(localized: "初始化")) {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    QXLargeTitle(title: String(localized: "初始化"),
                                 caption: String(localized: "把选中的部分恢复为默认值。MitM 证书始终保留；配置与订阅默认保留。此操作无法撤销，建议先在「备份与恢复」中备份。"))
                    QXCard {
                        VStack(spacing: 0) {
                            row(String(localized: "分流规则与规则资源"), String(localized: "本地分流规则、添加的规则集"), $resetRules)
                            Divider().padding(.leading, 16)
                            row(String(localized: "策略修改"), String(localized: "新建 / 编辑的策略、首页策略顺序与背景"), $resetPolicies)
                            Divider().padding(.leading, 16)
                            row(String(localized: "重写、脚本与模块"), String(localized: "本地重写、脚本、MitM 主机名、所有模块；证书保留"), $resetRewrite)
                            Divider().padding(.leading, 16)
                            row(String(localized: "节点订阅"), String(localized: "订阅管理中添加的节点订阅"), $resetNodeSubs)
                            Divider().padding(.leading, 16)
                            row(String(localized: "面板 & 工具栏"), String(localized: "磁贴顺序、样式、工具栏"), $resetUI)
                            Divider().padding(.leading, 16)
                            row(String(localized: "DNS 与内核设置"), String(localized: "自定义 DNS、本地 DNS、端口与内核覆盖"), $resetCore)
                            Divider().padding(.leading, 16)
                            row(String(localized: "全部配置与订阅"), String(localized: "删除所有配置文件（含手动节点）"), $resetProfiles, danger: true)
                        }
                    }
                    Button { confirm = true } label: {
                        HStack {
                            if working { ProgressView().tint(.white) }
                            Text("初始化").font(.system(size: 20, weight: .semibold))
                        }
                        .foregroundStyle(.white)
                        .frame(maxWidth: .infinity, minHeight: 60)
                        .background(Capsule().fill(anySelected ? QXColor.red : Color.secondary.opacity(0.4)))
                    }
                    .buttonStyle(.plain)
                    .disabled(!anySelected || working)
                    if let done { Text(verbatim: done).font(.footnote).foregroundStyle(QXColor.mitm) }
                }
                .padding(.horizontal, QXMetrics.inset)
                .padding(.bottom, 50)
            }
        }
        .confirmationDialog("确定初始化选中的部分？", isPresented: $confirm, titleVisibility: .visible) {
            Button("初始化", role: .destructive) { Task { await perform() } }
        } message: { Text("此操作无法撤销。") }
    }

    func row(_ title: String, _ detail: String, _ b: Binding<Bool>, danger: Bool = false) -> some View {
        Toggle(isOn: b) {
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: title).foregroundStyle(danger ? QXColor.red : Color.primary)
                Text(verbatim: detail).font(.caption).foregroundStyle(.secondary)
            }
        }
        .tint(danger ? QXColor.red : QXColor.switchOn)
        .padding(.horizontal, 16).padding(.vertical, 10)
    }

    func perform() async {
        working = true
        defer { working = false }
        let fm = FileManager.default
        let home = AppShared.homeURL
        if resetRules {
            CustomRulesStore.shared.rules = []
            CustomRulesStore.shared.save()
        }
        if resetPolicies {
            try? fm.removeItem(at: GroupEditStore.url)
            for k in [QXPolicyMeta.key, QXPolicyPrefs.orderKey, QXPolicyPrefs.bgKey] { UserDefaults.standard.removeObject(forKey: k) }
        }
        if resetRewrite {
            let es = EngineStore.shared
            for m in es.config.modules { try? fm.removeItem(at: EnginePaths.moduleURL(m.id)) }
            es.config = EngineConfig()
            es.reparseModules()
            es.save(reload: false)
        }
        if resetNodeSubs {
            for s in NodeSubStore.shared.subs { await NodeSubStore.shared.delete(s) }
        }
        if resetUI {
            for k in [QXPanel.orderKey, "qx.panelStyle", "qx.toolbarStyle", QXToolbar.hiddenKey, "qx.proxyExpanded", "qx.policyExpanded", QXParserPrefs.key] {
                UserDefaults.standard.removeObject(forKey: k)
            }
        }
        if resetCore {
            for f in ["dns.json", "localdns.json", "overrides.json"] { try? fm.removeItem(at: home.appendingPathComponent(f)) }
        }
        if resetProfiles {
            for p in store.profiles { store.delete(p) }
        }
        ResourceStore.shared.reload()
        await ProfileInspector.shared.load()
        if vpn.isConnected {
            if store.profiles.isEmpty { await vpn.disconnectAndWait() } else { _ = await vpn.reload() }
        }
        done = String(localized: "已初始化。")
    }
}
