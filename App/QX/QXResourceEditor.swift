import SwiftUI
import Libmihomo

// QX-3: 资源编辑 for existing resources in QX's underline form (frames 04/05): 资源标签, 资源路径, 自动更新,
// 启用 (+ 策略偏好 for rule sets), then the detected format and counts from our native parsers. The
// resource parser is only an optional advanced toggle: nothing needs it, and it is never executed.

struct QXResourceTarget: Identifiable {
    enum Kind {
        case profile(String)    // Profile.id (remote config subscription)
        case nodeSub(String)    // NodeSubscription.id
        case ruleSet(String)    // CustomRule.id
        case module(String)     // EngineModule.id
    }
    let id = UUID()
    let kind: Kind
}

/// Parser URLs kept per resource (display / round-trip only; the native parsers do the work).
enum QXParserPrefs {
    static let key = "qx.parserURLs"
    static func all() -> [String: String] {
        guard let s = UserDefaults.standard.string(forKey: key), let d = s.data(using: .utf8),
              let m = try? JSONDecoder().decode([String: String].self, from: d) else { return [:] }
        return m
    }
    static func get(_ id: String) -> String? { all()[id] }
    static func set(_ id: String, _ url: String?) {
        var m = all()
        m[id] = (url?.isEmpty == false) ? url : nil
        if let d = try? JSONEncoder().encode(m) { UserDefaults.standard.set(String(decoding: d, as: UTF8.self), forKey: key) }
    }
}

struct QXResourceEditor: View {
    let target: QXResourceTarget
    @EnvironmentObject var store: ProfileStore
    @ObservedObject private var engine = EngineStore.shared
    @ObservedObject private var subs = NodeSubStore.shared
    @ObservedObject private var res = ResourceStore.shared
    @ObservedObject private var rules = CustomRulesStore.shared
    @ObservedObject private var insp = ProfileInspector.shared
    @Environment(\.dismiss) private var dismiss

    @State private var tag = ""
    @State private var url = ""
    @State private var hours = 24
    @State private var enabled = true
    @State private var ua = "clash.meta"
    @State private var policy = ""
    @State private var domainSet = false
    @State private var groups: [String] = []
    @State private var parserOn = false
    @State private var parserURL = ""
    @State private var showAdvanced = false
    @State private var detecting = false
    @State private var detected: String?
    @State private var detectedCount: String?
    @State private var detectError: String?
    @State private var saving = false
    @State private var error: String?
    @State private var loaded = false
    @State private var originalURL = ""
    @State private var detectTask: Task<Void, Never>?

    static let hourChoices = [1, 6, 12, 24, 48, 72, 168]

    var kindTitle: String {
        switch target.kind {
        case .profile: return String(localized: "资源 - 配置")
        case .nodeSub: return String(localized: "资源 - 节点")
        case .ruleSet: return String(localized: "资源 - 分流")
        case .module: return String(localized: "资源 - 重写")
        }
    }

    var caption: String {
        switch target.kind {
        case .profile: return String(localized: "完整的配置订阅：包含节点、策略与分流规则，更新时整体替换。")
        case .nodeSub: return String(localized: "资源内容包含若干节点信息，作为远程资源来引用。")
        case .ruleSet: return String(localized: "资源内容包含若干分流规则，按策略偏好指定的策略匹配。")
        case .module: return String(localized: "资源内容包含若干重写规则、脚本与 MitM 主机名。")
        }
    }

    var accent: Color {
        switch target.kind {
        case .profile, .nodeSub: return QXColor.nodes
        case .ruleSet: return QXColor.rules
        case .module: return QXColor.rewrite
        }
    }

    var parserKey: String {
        switch target.kind {
        case .profile(let i), .nodeSub(let i), .ruleSet(let i), .module(let i): return i
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 26) {
                QXLargeTitle(title: kindTitle, caption: caption)
                field(String(localized: "资源标签"), placeholder: tagPlaceholder, text: $tag)
                    .disabled(isDomainSetRule)
                if hasEnable {
                    VStack(alignment: .leading, spacing: 8) {
                        Toggle(isOn: $enabled) { Text("启用").font(.system(size: 20, weight: .bold)) }.tint(QXColor.switchOn)
                        Text("停用后保留设置，但不参与匹配与更新。").font(.subheadline).foregroundStyle(.secondary)
                        Divider()
                    }
                }
                VStack(alignment: .leading, spacing: 8) {
                    Text("自动更新").font(.system(size: 20, weight: .bold))
                    Menu {
                        ForEach(Self.hourChoices, id: \.self) { h in
                            Button { hours = h } label: { Text(verbatim: QXSubscriptionEditor.label(h)) }
                        }
                    } label: {
                        Text(verbatim: QXSubscriptionEditor.label(hours)).foregroundStyle(.primary)
                    }
                    Divider()
                }
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 2) {
                        Text("资源路径").font(.system(size: 20, weight: .bold))
                        Text(verbatim: "*").font(.system(size: 20, weight: .bold)).foregroundStyle(QXColor.red)
                        Spacer()
                        QXPill(title: String(localized: "粘贴")) { url = UIPasteboard.general.string ?? url }
                    }
                    TextField("https://", text: $url, axis: .vertical)
                        .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                        .lineLimit(1...4)
                        .onChange(of: url) { _ in if loaded { scheduleDetect() } }
                    Divider()
                }
                if case .ruleSet = target.kind {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("策略偏好").font(.system(size: 20, weight: .bold))
                        Menu {
                            ForEach(["DIRECT", "REJECT"] + groups, id: \.self) { g in
                                Button { policy = g } label: { Text(verbatim: g) }
                            }
                        } label: {
                            HStack(spacing: 8) {
                                QXChip(text: policy.isEmpty ? "PROXY" : policy, color: QXPolicyColor.color(policy))
                                Image(systemName: "chevron.up.chevron.down").font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        Text("整份列表使用这个策略（QX force-policy）。").font(.subheadline).foregroundStyle(.secondary)
                        Divider()
                    }
                }

                detectionSection
                advancedSection
                if let error { ErrorRow(message: error) }
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
                Text(verbatim: kindTitle).font(.headline)
                Spacer()
                if saving {
                    ProgressView().frame(width: 44, height: 44)
                } else {
                    QXCircleButton(systemName: "checkmark", tint: canSave ? QXColor.switchOn : .secondary) { Task { await save() } }
                        .disabled(!canSave)
                        .accessibilityLabel(Text("保存"))
                }
            }
            .padding(.horizontal, 16).padding(.top, 12).padding(.bottom, 8)
            .background(LinearGradient(colors: [QXPalette.bg, QXPalette.bg.opacity(0)], startPoint: .top, endPoint: .bottom))
        }
        .task { await load() }
    }

    var isDomainSetRule: Bool { if case .ruleSet = target.kind { return domainSet } else { return false } }
    var hasEnable: Bool { if case .profile = target.kind { return false } else { return true } }
    var tagPlaceholder: String {
        isDomainSetRule ? String(localized: "DOMAIN-SET 列表没有标签") : String(localized: "留空则使用资源提供的名称")
    }

    var canSave: Bool {
        let u = url.trimmingCharacters(in: .whitespacesAndNewlines)
        if case .module = target.kind, u.isEmpty { return true }   // local module
        return URL(string: u)?.scheme?.hasPrefix("http") == true
    }

    var detectionSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("格式识别").font(.system(size: 22, weight: .bold))
            HStack(spacing: 8) {
                if detecting {
                    ProgressView().controlSize(.small)
                    Text("正在识别…").font(.subheadline).foregroundStyle(.secondary)
                } else if let d = detected {
                    QXChip(text: d, color: accent)
                    if let c = detectedCount { Text(verbatim: c).font(.subheadline) }
                } else if let detectError {
                    Text(verbatim: detectError).font(.subheadline).foregroundStyle(Theme.bad)
                } else {
                    Text("填写资源路径后自动识别").font(.subheadline).foregroundStyle(.secondary)
                }
            }
            Text("无需资源解析器：节点支持 Clash / mihomo YAML、Base64 或明文分享链接（含 VLESS Reality、Hysteria2、TUIC、AnyTLS、WireGuard 等）、SIP008、sing-box JSON 与 Surge / QX / Loon 节点行；分流支持 Surge / Loon / Stash / QX 列表与 DOMAIN-SET；重写支持 Surge / Loon / Stash / Egern 模块与 QX 片段。")
                .font(.footnote).foregroundStyle(.secondary)
        }
    }

    var advancedSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Button { withAnimation(.spring(response: 0.3)) { showAdvanced.toggle() } } label: {
                HStack(spacing: 8) {
                    Text("高级").font(.system(size: 20, weight: .bold)).foregroundStyle(.primary)
                    Image(systemName: showAdvanced ? "arrowtriangle.down.fill" : "arrowtriangle.right.fill")
                        .font(.system(size: 10, weight: .bold)).foregroundStyle(.primary)
                    Spacer()
                }
            }
            .buttonStyle(.plain)
            if showAdvanced {
                switch target.kind {
                case .profile, .nodeSub:
                    field("User-Agent", placeholder: "clash.meta", text: $ua)
                        .onChange(of: ua) { _ in if loaded { scheduleDetect() } }
                default:
                    EmptyView()
                }
                if case .ruleSet = target.kind {
                    Toggle("纯域名列表（DOMAIN-SET）", isOn: $domainSet).tint(QXColor.switchOn)
                }
                VStack(alignment: .leading, spacing: 8) {
                    Toggle(isOn: $parserOn) { Text("资源解析器（可选）").font(.system(size: 17, weight: .semibold)) }.tint(QXColor.switchOn)
                    if parserOn {
                        TextField("https://…/resource-parser.js", text: $parserURL)
                            .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                            .font(.footnote.monospaced())
                        Divider()
                    }
                    Text("一般不需要：上面的格式都由内置解析器直接转换。解析器地址只会随资源保存（便于从 Quantumult X 迁移），不会在本机执行脚本。")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
        }
    }

    private func field(_ title: String, placeholder: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(verbatim: title).font(.system(size: 20, weight: .bold))
            TextField(placeholder, text: text).textInputAutocapitalization(.never).autocorrectionDisabled()
            Divider()
        }
    }

    // MARK: Load

    func load() async {
        switch target.kind {
        case .profile(let id):
            guard let p = store.profiles.first(where: { $0.id == id }) else { error = String(localized: "找不到这个资源"); return }
            tag = p.name; url = p.url ?? ""; hours = p.updateIntervalHours; ua = p.userAgent
            if id == store.activeID {
                let n = insp.result.proxies.count + insp.result.proxyProviders.reduce(0) { $0 + max($1.count, 0) }
                detected = "mihomo YAML"
                detectedCount = String(localized: "\(n) 个节点 · \(insp.result.groups.count) 个策略 · \(insp.result.rules.count) 条规则")
            }
        case .nodeSub(let id):
            guard let s = subs.subs.first(where: { $0.id == id }) else { error = String(localized: "找不到这个资源"); return }
            tag = s.name; url = s.url; hours = s.updateIntervalHours; enabled = s.enabled; ua = s.userAgent
            if let c = s.count { detectedCount = String(localized: "识别到 \(c) 个节点") }
        case .ruleSet(let id):
            guard let r = rules.rules.first(where: { $0.id == id }) else { error = String(localized: "找不到这个资源"); return }
            enabled = r.enabled
            parseRuleLine(r.line)
            if let iv = r.interval, iv > 0 { hours = max(1, iv / 3600) }
            if let it = res.items.first(where: { $0.kind == "ruleset" && $0.refId == id }) {
                detected = (it.format ?? "list").uppercased()
                detectedCount = it.detail
                if let e = it.error, !e.isEmpty { detectError = e }
            }
            await loadGroups()
        case .module(let id):
            guard let m = engine.config.modules.first(where: { $0.id == id }) else { error = String(localized: "找不到这个资源"); return }
            tag = m.name; url = m.url; enabled = m.enabled; hours = max(1, (m.interval ?? 86400) / 3600)
            if let p = engine.moduleInfo[m.id] {
                let scripts = p.rules.filter { $0.kind == "script" }.count
                detected = p.format.isEmpty ? "MODULE" : p.format.uppercased()
                detectedCount = String(localized: "\(p.rules.count - scripts) 重写 · \(scripts) 脚本 · \(p.hostnames.count) 主机") + ((p.tasks ?? []).isEmpty ? "" : String(localized: " · \((p.tasks ?? []).count) 任务"))
            }
        }
        originalURL = url
        if let p = QXParserPrefs.get(parserKey) { parserOn = true; parserURL = p }
        loaded = true
        if detected == nil && detectedCount == nil { scheduleDetect() }
    }

    private func loadGroups() async {
        guard let profile = AppShared.activeProfileURL?.path else { return }
        let home = AppShared.homeURL.path
        let g = await Task.detached { LibmihomoProfileGroups(home, profile) }.value
        groups = (try? JSONDecoder().decode([String].self, from: Data(g.utf8))) ?? []
    }

    /// "RULE-SET,url,policy[,opts]", "DOMAIN-SET,url,policy" or a QX filter_remote line.
    private func parseRuleLine(_ line: String) {
        let parts = line.split(separator: ",", omittingEmptySubsequences: false).map { $0.trimmingCharacters(in: .whitespaces) }
        guard let first = parts.first else { return }
        if first.hasPrefix("http") {
            url = first
            for p in parts.dropFirst() {
                let kv = p.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                guard kv.count == 2 else { continue }
                switch kv[0].lowercased() {
                case "tag": tag = kv[1]
                case "force-policy": policy = kv[1]
                case "update-interval": if let n = Int(kv[1]), n > 0 { hours = max(1, n / 3600) }
                case "enabled": enabled = !["false", "0", "no"].contains(kv[1].lowercased())
                default: break
                }
            }
        } else {
            domainSet = first.uppercased() == "DOMAIN-SET"
            if parts.count > 1 { url = parts[1] }
            if parts.count > 2 { policy = parts[2] }
        }
    }

    // MARK: Detect

    private func scheduleDetect() {
        detectTask?.cancel()
        guard canSave else { return }
        let u = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !u.isEmpty else { return }
        let agent = ua.isEmpty ? "clash.meta" : ua
        let kind = target.kind
        detectTask = Task {
            try? await Task.sleep(nanoseconds: 800_000_000)
            if Task.isCancelled { return }
            detecting = true
            detectError = nil
            defer { detecting = false }
            guard let t = URL(string: u) else { return }
            var req = URLRequest(url: t, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 20)
            req.setValue(agent, forHTTPHeaderField: "User-Agent")
            do {
                let (data, resp) = try await URLSession.shared.data(for: req)
                if Task.isCancelled { return }
                if let h = resp as? HTTPURLResponse, !(200..<300).contains(h.statusCode) {
                    detectError = String(localized: "下载失败：HTTP \(h.statusCode)")
                    return
                }
                let text = String(data: data, encoding: .utf8) ?? ""
                switch kind {
                case .profile, .nodeSub:
                    let json = await Task.detached { LibmihomoDetectNodeFormat(text) }.value
                    if let d = json.data(using: .utf8), let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any] {
                        let c = (o["count"] as? NSNumber)?.intValue ?? 0
                        detected = o["format"] as? String ?? ""
                        detectedCount = c > 0 ? String(localized: "识别到 \(c) 个节点") : String(localized: "未识别到节点")
                    }
                case .ruleSet:
                    let lines = text.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
                        .filter { !$0.isEmpty && !$0.hasPrefix("#") && !$0.hasPrefix(";") && !$0.hasPrefix("//") }
                    let yaml = text.contains("payload:")
                    detected = yaml ? "YAML" : (lines.allSatisfy { !$0.contains(",") } ? "DOMAIN-SET" : "LIST")
                    detectedCount = String(localized: "\(lines.count) 条规则")
                case .module:
                    let p = await Task.detached { LibmihomoEngineParseText(text, "{}") }.value
                    if let m = ParsedEngineText.parse(p) {
                        let scripts = m.rules.filter { $0.kind == "script" }.count
                        detected = m.format.isEmpty ? "MODULE" : m.format.uppercased()
                        detectedCount = String(localized: "\(m.rules.count - scripts) 重写 · \(scripts) 脚本 · \(m.hostnames.count) 主机")
                    }
                }
            } catch {
                if !Task.isCancelled { detectError = error.localizedDescription }
            }
        }
    }

    // MARK: Save

    func save() async {
        saving = true
        error = nil
        defer { saving = false }
        let u = url.trimmingCharacters(in: .whitespacesAndNewlines)
        let t = tag.trimmingCharacters(in: .whitespaces)
        QXParserPrefs.set(parserKey, parserOn ? parserURL.trimmingCharacters(in: .whitespacesAndNewlines) : nil)
        switch target.kind {
        case .profile(let id):
            guard var p = store.profiles.first(where: { $0.id == id }) else { return }
            let changed = u != (p.url ?? "") || ua != p.userAgent
            if !t.isEmpty { p.name = t }
            p.url = u; p.userAgent = ua.isEmpty ? "clash.meta" : ua; p.updateIntervalHours = hours
            store.update(p)
            if changed, let e = await store.refresh(p) { error = e; return }
        case .nodeSub(let id):
            guard var s = subs.subs.first(where: { $0.id == id }) else { return }
            let changed = u != s.url || ua != s.userAgent
            if !t.isEmpty { s.name = t }
            s.url = u; s.userAgent = ua.isEmpty ? "clash.meta" : ua; s.updateIntervalHours = hours; s.enabled = enabled
            await subs.save(s)
            if changed, let e = await subs.refresh(s) { error = e; return }
        case .ruleSet(let id):
            guard let i = rules.rules.firstIndex(where: { $0.id == id }) else { return }
            let pol = policy.isEmpty ? (groups.first ?? "DIRECT") : policy
            let line: String
            if domainSet {
                line = "DOMAIN-SET,\(u),\(pol)"
            } else if !t.isEmpty {
                line = "\(u), tag=\(t.replacingOccurrences(of: ",", with: " ")), force-policy=\(pol)"
            } else {
                line = "RULE-SET,\(u),\(pol)"
            }
            rules.rules[i].line = line
            rules.rules[i].enabled = enabled
            rules.rules[i].interval = hours * 3600
            rules.save()
            res.reload()
            if u != originalURL, let it = res.items.first(where: { $0.kind == "ruleset" && $0.refId == id }) { await res.update(it) }
        case .module(let id):
            guard let i = engine.config.modules.firstIndex(where: { $0.id == id }) else { return }
            if !t.isEmpty { engine.config.modules[i].name = t }
            engine.config.modules[i].url = u
            engine.config.modules[i].enabled = enabled
            engine.config.modules[i].interval = hours * 3600
            engine.save()
            if u != originalURL, !u.isEmpty { await engine.updateModule(engine.config.modules[i]) }
            res.reload()
        }
        dismiss()
    }
}
