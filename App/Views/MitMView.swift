import SwiftUI
import UIKit
import UniformTypeIdentifiers
import Libmihomo

// MARK: - Shared helpers

struct ActivityView: UIViewControllerRepresentable {
    let items: [Any]
    /// Review 5 P2-9: a temp export holding secrets (backup JSON, CA .p12) is deleted once the share sheet ends.
    var cleanup: URL? = nil
    func makeUIViewController(context: Context) -> UIActivityViewController {
        let vc = UIActivityViewController(activityItems: items, applicationActivities: nil)
        if let cleanup {
            vc.completionWithItemsHandler = { _, _, _, _ in try? FileManager.default.removeItem(at: cleanup) }
        }
        return vc
    }
    func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
}

struct ShareItem: Identifiable {
    let id = UUID()
    let url: URL
    /// Delete the file when the share sheet goes away (it holds secrets).
    var temporary = false
}

struct KindBadge: View {
    let kind: String
    var phase: String = ""
    var body: some View {
        let (t, c) = Self.style(kind, phase)
        Text(LocalizedStringKey(t))
            .scaledFont(9, weight: .bold)
            .padding(.horizontal, 5).padding(.vertical, 2)
            .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
            .background(Capsule().fill(c.opacity(0.18)))
            .foregroundStyle(c)
    }

    static func style(_ kind: String, _ phase: String) -> (String, Color) {
        switch kind {
        case "url": return ("URL", Theme.bad)
        case "header": return (phase == "response" ? "响应头" : "请求头", Theme.warn)
        case "body", "jq", "json": return (phase == "response" ? "响应体" : "请求体", Theme.tone(0.55, 0.45, 1.0))
        case "maplocal": return ("本地", Theme.good)
        case "script": return (phase == "response" ? "响应脚本" : "请求脚本", Theme.accent)
        case "core": return ("规则", .secondary)
        case "hostname": return ("主机", .secondary)
        case "cron": return ("定时", Theme.tone(1.0, 0.62, 0.2))
        case "event": return ("事件", Theme.tone(1.0, 0.4, 0.75))
        case "generic": return ("通用", Theme.tone(0.2, 0.8, 0.85))
        case "interaction": return ("交互", Theme.tone(0.35, 0.4, 0.95))
        default: return ("?", .secondary)
        }
    }
}

struct EngineSwitchFooter: View {
    @EnvironmentObject var vpn: VPNManager
    var body: some View {
        Text(vpn.isConnected ? "修改会自动重载内核。" : "VPN 未连接，修改在下次连接时生效。")
    }
}

// MARK: - MitM

struct MitMView: View {
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject var store = EngineStore.shared
    @State private var newHost = ""
    @State private var share: ShareItem?
    @State private var confirmRegen = false
    @State private var p12Password = ""
    @State private var askP12 = false
    @State private var importing = false
    @State private var importURL: URL?
    @State private var importPassword = ""
    @State private var askImportPassword = false
    @State private var status: MitMStatus?
    @State private var showLocalHosts = false
    /// Module ids whose MitM host list is unfolded (one section per module, folded by default).
    @State private var expandedModuleHosts: Set<String> = []

    /// The MitM hostnames of each enabled module, in module order (feat/loon-rewrite-ui: grouped by module
    /// instead of one merged list, so it is clear which module asks to decrypt which host).
    struct ModuleHostGroup: Identifiable {
        let id: String
        let name: String
        let hosts: [String]
    }

    var moduleHostGroups: [ModuleHostGroup] {
        store.config.modules.compactMap { (m: EngineModule) -> ModuleHostGroup? in
            guard m.enabled, let hosts = store.moduleInfo[m.id]?.hostnames, !hosts.isEmpty else { return nil }
            return ModuleHostGroup(id: m.id, name: m.name, hosts: hosts)
        }
    }

    func moduleHostsExpanded(_ id: String) -> Binding<Bool> {
        Binding(get: { expandedModuleHosts.contains(id) },
                set: { on in if on { expandedModuleHosts.insert(id) } else { expandedModuleHosts.remove(id) } })
    }

    /// Collapsible host-list header (主机名: 本地 / each module), folded by default.
    func hostsHeader(_ title: Text, expanded: Binding<Bool>, id: String) -> some View {
        Button {
            withAnimation { expanded.wrappedValue.toggle() }
        } label: {
            HStack {
                title
                Spacer()
                Image(systemName: "chevron.right")
                    .rotationEffect(.degrees(expanded.wrappedValue ? 90 : 0))
                    .font(.caption.weight(.semibold))
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier(id)
    }

    var body: some View {
        List {
            Section {
                Toggle(isOn: Binding(get: { store.config.mitm }, set: { store.config.mitm = $0; store.save() })) {
                    Label("HTTPS 解密（MitM）", systemImage: "lock.open.fill")
                }
                .disabled(!store.caInfo.exists)
                Toggle("跳过服务器证书校验", isOn: Binding(get: { store.config.skipCertVerify }, set: { store.config.skipCertVerify = $0; store.save() }))
                Toggle("对客户端启用 HTTP/2", isOn: Binding(get: { store.config.h2 ?? true }, set: { store.config.h2 = $0; store.save() }))
                Toggle("记录请求 / 响应内容", isOn: Binding(get: { store.config.captureBodies ?? true }, set: { store.config.captureBodies = $0; store.save() }))
            } footer: {
                VStack(alignment: .leading, spacing: 4) {
                    Text("只解密下方主机名列表（含已启用模块）中的 HTTPS 流量；这些主机的 QUIC/HTTP3 默认被阻断以回落到 TCP（见下方 QUIC 设置）。证书固定（pinning）的 App 握手失败后会自动放行 30 分钟。")
                    EngineSwitchFooter()
                }
            }
            .listRowBackground(Theme.card)

            caSection

            Section {
                if showLocalHosts {
                    ForEach(store.config.hostnames, id: \.self) { h in
                        HStack {
                            Text(h).font(.system(.callout, design: .monospaced))
                            Spacer()
                            if h.hasPrefix("-") { Text("排除").font(.caption2).foregroundStyle(.secondary) }
                        }
                    }
                    .onDelete { idx in store.config.hostnames.remove(atOffsets: idx); store.save() }
                }
                HStack {
                    TextField("example.com、*.example.com、-排除.com", text: $newHost)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .font(.system(.callout, design: .monospaced))
                        .onSubmit(addHost)
                    Button("添加", action: addHost).disabled(newHost.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            } header: {
                hostsHeader(Text("本地 \(store.config.hostnames.count)"), expanded: $showLocalHosts, id: "mitm.hosts.local")
            } footer: {
                Text("支持 * 和 ? 通配、前缀 - 表示排除、:端口（默认 443）。可一次粘贴多个，用逗号分隔。左滑删除。")
            }
            .listRowBackground(Theme.card)

            ForEach(moduleHostGroups) { g in
                Section {
                    if expandedModuleHosts.contains(g.id) {
                        ForEach(g.hosts, id: \.self) { h in
                            HStack {
                                Text(h).font(.system(.footnote, design: .monospaced)).foregroundStyle(.secondary)
                                Spacer()
                                if h.hasPrefix("-") { Text("排除").font(.caption2).foregroundStyle(.secondary) }
                            }
                        }
                    }
                } header: {
                    hostsHeader(Text(verbatim: "\(g.name) \(g.hosts.count)"), expanded: moduleHostsExpanded(g.id), id: "mitm.hosts.module." + g.name)
                }
                .listRowBackground(Theme.card)
            }

            quicSection

            if let s = status, vpn.isConnected {
                Section("运行状态") {
                    LabeledContent("引擎", value: s.running ? String(localized: "运行中（127.0.0.1:\(String(s.port))）") : String(localized: "未运行"))
                    LabeledContent("证书已加载", value: s.caLoaded ? String(localized: "是") : String(localized: "否"))
                    LabeledContent("规则 / 脚本", value: "\(s.rules) / \(s.scripts)")
                    if !s.pinned.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("已临时放行（握手失败）").font(.caption).foregroundStyle(.secondary)
                            ForEach(s.pinned, id: \.self) { Text($0).font(.system(.caption, design: .monospaced)) }
                        }
                    }
                    ForEach(s.errors, id: \.self) { e in Text(e).font(.caption).foregroundStyle(Theme.warn) }
                }
                .listRowBackground(Theme.card)
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("MitM")
        .sheet(item: $share, onDismiss: { EngineStore.purgeP12() }) { ActivityView(items: [$0.url], cleanup: $0.temporary ? $0.url : nil) }
        .confirmationDialog("重新生成证书？", isPresented: $confirmRegen, titleVisibility: .visible) {
            Button("重新生成", role: .destructive) { store.generateCA() }
        } message: { Text("旧证书将失效，需要重新安装并信任新的描述文件。") }
        .alert("导出 p12", isPresented: $askP12) {
            SecureField("设置密码", text: $p12Password)
            Button("导出") { if let u = store.p12File(password: p12Password) { share = ShareItem(url: u, temporary: true) }; p12Password = "" }
            Button("取消", role: .cancel) { p12Password = "" }
        } message: { Text("p12 包含私钥，请妥善保管，切勿分享给他人。") }
        .fileImporter(isPresented: $importing, allowedContentTypes: [UTType(filenameExtension: "p12") ?? .data, .data]) { r in
            if case .success(let u) = r { importURL = u; askImportPassword = true }
        }
        .alert("导入 p12", isPresented: $askImportPassword) {
            SecureField("密码", text: $importPassword)
            Button("导入") { if let u = importURL { store.importP12(u, password: importPassword) }; importPassword = "" }
            Button("取消", role: .cancel) { importPassword = "" }
        }
        .alert("提示", isPresented: Binding(get: { store.message != nil }, set: { if !$0 { store.message = nil } })) {
            Button("好") { store.message = nil }
        } message: { Text(store.message ?? "") }
        // fix/nav-jank: the CA check (Go leaf + SecTrust evaluation) runs off main, not during the push.
        .task { await store.refreshCAInBackground() }
        .task { if vpn.isConnected { status = try? await ControllerClient.shared.mitmStatus() } }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.didBecomeActiveNotification)) { _ in Task { await store.refreshCAInBackground() } }
    }

    @ViewBuilder var caSection: some View {
        Section {
            if store.caInfo.exists {
                HStack(spacing: 10) {
                    Image(systemName: store.caTrusted == true ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                        .font(.title2)
                        .foregroundStyle(store.caTrusted == true ? Theme.good : Theme.warn)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(store.caInfo.subject ?? "CA").font(.subheadline.weight(.semibold))
                        Text(store.caTrusted == true ? "已安装并完全信任" : "未信任：请安装描述文件并开启完全信任")
                            .font(.caption).foregroundStyle(store.caTrusted == true ? Theme.good : Theme.warn)
                    }
                    Spacer()
                    Button { store.refreshCA() } label: { Image(systemName: "arrow.clockwise") }.buttonStyle(.borderless)
                }
                LabeledContent("算法", value: store.caInfo.algorithm ?? "")
                LabeledContent("有效期至", value: store.caInfo.notAfter ?? "")
                VStack(alignment: .leading, spacing: 2) {
                    Text("SHA-256 指纹").font(.caption).foregroundStyle(.secondary)
                    Text(store.caInfo.fingerprint ?? "").scaledFont(10, design: .monospaced).textSelection(.enabled)
                }
                Button { store.installViaSafari() } label: { Label("安装证书（通过 Safari）", systemImage: "safari") }
                Button { if let u = store.mobileConfigFile() { share = ShareItem(url: u) } } label: {
                    Label("分享 / 存储描述文件", systemImage: "square.and.arrow.up")
                }
                Button { if let u = store.certFile() { share = ShareItem(url: u) } } label: { Label("导出 .cer（仅证书）", systemImage: "doc.badge.arrow.up") }
                Button { askP12 = true } label: { Label("导出 p12（含私钥，需密码）", systemImage: "key") }
                Button { importing = true } label: { Label("从 p12 导入", systemImage: "square.and.arrow.down") }
                Button(role: .destructive) { confirmRegen = true } label: { Label("重新生成证书", systemImage: "arrow.triangle.2.circlepath") }
            } else {
                Text("尚未生成 CA 证书。证书与私钥只保存在本机 App Group 容器内。").font(.footnote).foregroundStyle(.secondary)
                Button { store.generateCA() } label: { Label("生成 CA 证书", systemImage: "plus.circle.fill") }
            }
        } header: { Text("CA 证书") } footer: {
            if store.caInfo.exists && store.caTrusted != true {
                VStack(alignment: .leading, spacing: 6) {
                    Text("安装步骤").font(.caption.weight(.semibold))
                    Text("1. 点「安装证书（通过 Safari）」，在弹窗中选择「允许」下载描述文件（或用「分享 / 存储描述文件」存到“文件”后在“文件”App 中点开）。")
                    Text("2. 打开 设置 → 已下载描述文件（或 通用 → VPN 与设备管理）→ 安装，输入锁屏密码。")
                    Text("3. 打开 设置 → 通用 → 关于本机 → 证书信任设置，打开「\(store.caInfo.subject ?? "Tern MitM CA")」的完全信任。")
                    Text("4. 回到本页，状态变为「已安装并完全信任」即可开启 HTTPS 解密。")
                }
            }
        }
        .listRowBackground(Theme.card)
    }

    @State private var newQUICHost = ""

    /// QUIC / HTTP/3: MitM hosts are blocked (fallback to TCP) by default; everything else may use QUIC.
    var quicSection: some View {
        Section {
            Picker("QUIC（HTTP/3）", selection: Binding(get: { store.config.quic ?? "mitm" }, set: { store.config.quic = $0 == "mitm" ? nil : $0; store.save() })) {
                Text("仅阻断 MitM 主机").tag("mitm")
                Text("全部阻断").tag("all")
            }
            ForEach(store.config.quicAllow ?? [], id: \.self) { h in
                HStack {
                    Text(h).font(.system(.callout, design: .monospaced))
                    Spacer()
                    Text("允许 QUIC").font(.caption2).foregroundStyle(.secondary)
                }
            }
            .onDelete { idx in
                var l = store.config.quicAllow ?? []
                l.remove(atOffsets: idx)
                store.config.quicAllow = l.isEmpty ? nil : l
                store.save()
            }
            if (store.config.quic ?? "mitm") == "mitm" {
                HStack {
                    TextField("允许 QUIC 的 MitM 主机，如 *.googlevideo.com", text: $newQUICHost)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .font(.system(.callout, design: .monospaced))
                    Button("添加") {
                        let h = newQUICHost.trimmingCharacters(in: .whitespaces).lowercased()
                        guard !h.isEmpty else { return }
                        var l = store.config.quicAllow ?? []
                        if !l.contains(h) { l.append(h) }
                        store.config.quicAllow = l
                        newQUICHost = ""
                        store.save()
                    }
                    .disabled(newQUICHost.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
        } header: { Text("QUIC / HTTP3") } footer: {
            Text("默认只阻断 MitM 主机的 UDP 443，让它们回落到 TCP 以便解密；其他流量照常使用 QUIC。「全部阻断」让所有 App 都回落到 TCP（即使没有开启 MitM）。列表中的 MitM 主机不阻断 QUIC，它们的 HTTP/3 流量不会被解密。")
        }
        .listRowBackground(Theme.card)
    }

    func addHost() {
        let hosts = newHost.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces).lowercased() }.filter { !$0.isEmpty }
        for h in hosts where !store.config.hostnames.contains(h) { store.config.hostnames.append(h) }
        newHost = ""
        store.save()
    }
}

// MARK: - Rewrite (rows and help shared with the local module)

struct RuleRow: View {
    let item: EngineItem
    var onToggle: (Bool) -> Void
    var body: some View {
        let d = EngineStore.describe(item.line, section: item.line.contains("type=") ? "script" : "")
        HStack(alignment: .top, spacing: 10) {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    KindBadge(kind: d.kind, phase: item.line.lowercased().contains("response") ? "response" : "request")
                    Text(verbatim: GoText.localize(d.desc)).font(.caption.weight(.semibold)).foregroundStyle(d.error == nil ? Color.primary : Theme.bad).lineLimit(1)
                }
                Text(item.line).scaledFont(11, design: .monospaced).foregroundStyle(.secondary).lineLimit(3)
                if let e = d.error { Text(e).font(.caption2).foregroundStyle(Theme.bad) }
            }
            Spacer(minLength: 4)
            Toggle("", isOn: Binding(get: { item.enabled }, set: onToggle)).labelsHidden()
        }
        .opacity(item.enabled ? 1 : 0.5)
    }
}

struct SyntaxHelp: View {
    let samples: [(String, String)] = [
        ("Surge URL 重写", #"^https?://ad\.example\.com/v1 - reject"#),
        ("302 跳转", #"^http://a\.com/(.*) https://b.com/$1 302"#),
        ("请求头", #"^https?://api\.example\.com header-add X-Token 123"#),
        ("响应体", #"http-response ^https?://api\.example\.com/feed "ad":true "ad":false"#),
        ("jq", #"http-response-jq ^https?://api\.example\.com/v2 'del(.data.ads)'"#),
        ("本地映射", #"^https?://example\.com/api data="{}" data-type=text header="Content-Type:application/json""#),
        ("QX", #"^https?:\/\/api\.example\.com\/ad url reject-dict"#),
        ("QX 脚本", #"^https?:\/\/api\.example\.com\/feed url script-response-body https://example.com/a.js"#),
        ("Loon JSON", #"^https?://api\.example\.com/feed response-body-json-del data.ads"#),
    ]
    var body: some View {
        ForEach(samples, id: \.0) { s in
            VStack(alignment: .leading, spacing: 2) {
                Text(LocalizedStringKey(s.0)).font(.caption2.weight(.semibold)).foregroundStyle(.secondary)
                Text(s.1).scaledFont(10, design: .monospaced).textSelection(.enabled)
            }
        }
        Text("动作：reject / reject-200 / reject-img / reject-dict / reject-array / reject-drop / 302 / 307 / header；头部：header-add / header-del / header-replace / header-replace-regex。").font(.caption2).foregroundStyle(.secondary)
    }
}

/// Add / edit rewrite rules or script lines as raw text (multi-line paste supported when adding).
struct LineEditorSheet: View {
    @Environment(\.dismiss) var dismiss
    @ObservedObject var store = EngineStore.shared
    let title: String
    let scripts: Bool
    let item: EngineItem?
    @State private var text = ""
    @State private var note = ""

    var preview: [(String, (desc: String, kind: String, error: String?))] {
        text.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") && !$0.hasPrefix("[") }
            .prefix(30).map { ($0, EngineStore.describe($0, section: scripts ? "script" : "")) }
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextEditor(text: $text)
                        .scaledFont(12, design: .monospaced)
                        .frame(minHeight: 160)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    if item == nil {
                        Button { text += (text.isEmpty ? "" : "\n") + (UIPasteboard.general.string ?? "") } label: { Label("粘贴", systemImage: "doc.on.clipboard") } // clipboard-read: explicit 粘贴 tap only (see ClipboardRuleTests)
                    }
                } header: { Text(item == nil ? "每行一条（hostname = … 会加入 MitM 列表）" : "规则") }
                if item != nil {
                    Section("备注") { TextField("可选", text: $note) }
                }
                if !preview.isEmpty {
                    Section("解析预览") {
                        ForEach(Array(preview.enumerated()), id: \.offset) { e in
                            let p = e.element
                            VStack(alignment: .leading, spacing: 2) {
                                HStack { KindBadge(kind: p.1.kind); Text(verbatim: GoText.localize(p.1.desc)).font(.caption.weight(.semibold)) }
                                if let e = p.1.error { Text(e).font(.caption2).foregroundStyle(Theme.bad) }
                            }
                        }
                    }
                }
            }
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") { save(); dismiss() }.disabled(text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
            .onAppear { if let item { text = item.line; note = item.note ?? "" } }
        }
    }

    func save() {
        if let item {
            let line = text.trimmingCharacters(in: .whitespacesAndNewlines).components(separatedBy: .newlines).first ?? ""
            if scripts, let i = store.config.scripts.firstIndex(where: { $0.id == item.id }) {
                store.config.scripts[i].line = line; store.config.scripts[i].note = note.isEmpty ? nil : note
            } else if let i = store.config.rules.firstIndex(where: { $0.id == item.id }) {
                store.config.rules[i].line = line; store.config.rules[i].note = note.isEmpty ? nil : note
            }
            store.save()
        } else {
            store.addLines(text, toScripts: scripts)
        }
    }
}

// MARK: - Scripts

/// Form for a Surge-style script line, with an inline editor for local scripts.
struct ScriptFormSheet: View {
    @Environment(\.dismiss) var dismiss
    @ObservedObject var store = EngineStore.shared
    let item: EngineItem?
    @State private var name = ""
    @State private var type = "http-response"
    @State private var pattern = ""
    @State private var source = 0 // 0 local, 1 url
    @State private var path = ""
    @State private var requiresBody = true
    @State private var binary = false
    @State private var maxSize = ""
    @State private var timeout = "10"
    @State private var argument = ""
    @State private var code = ""
    @State private var rawLine = ""
    @State private var rawMode = false
    @State private var debugSample = ScriptDebugSample()
    /// load() runs once: onAppear fires again when 调试运行 is popped, and re-parsing would revert unsaved edits.
    @State private var loaded = false
    @State private var initial = ""
    @State private var confirmDiscard = false

    /// Fingerprint of everything the form saves, to tell whether there are unsaved edits.
    var fingerprint: String { rawMode ? rawLine : line + "\u{1}" + (source == 0 ? code : "") }
    var dirty: Bool { loaded && fingerprint != initial }

    var line: String {
        var parts = ["type=\(type)", "pattern=\(pattern)"]
        if requiresBody { parts.append("requires-body=1") }
        if binary { parts.append("binary-body-mode=1") }
        if let m = Int(maxSize), m > 0 { parts.append("max-size=\(m)") }
        parts.append("script-path=\(scriptPath)")
        if !argument.isEmpty { parts.append("argument=\"\(argument)\"") }
        if let t = Int(timeout), t > 0 { parts.append("timeout=\(t)") }
        return "\(name.isEmpty ? "script" : name) = " + parts.joined(separator: ",")
    }

    var scriptPath: String { source == 1 ? path : (path.hasSuffix(".js") ? path : EnginePaths.safe(name.isEmpty ? "script" : name) + ".js") }

    var body: some View {
        NavigationStack {
            Form {
                if rawMode {
                    Section("脚本行（Quantumult X / Loon 等非 Surge 语法）") {
                        TextEditor(text: $rawLine).scaledFont(12, design: .monospaced).frame(minHeight: 120)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                        let d = EngineStore.describe(rawLine, section: "script")
                        Text(verbatim: d.error ?? GoText.localize(d.desc)).font(.caption).foregroundStyle(d.error == nil ? Color.secondary : Theme.bad)
                    }
                } else {
                    Section("基本") {
                        TextField("名称", text: $name)
                        Picker("类型", selection: $type) {
                            Text("http-response").tag("http-response")
                            Text("http-request").tag("http-request")
                        }
                        TextField("pattern（正则，匹配完整 URL）", text: $pattern)
                            .font(.system(.footnote, design: .monospaced)).textInputAutocapitalization(.never).autocorrectionDisabled()
                    }
                    Section("选项") {
                        Toggle("requires-body", isOn: $requiresBody)
                        Toggle("binary-body-mode", isOn: $binary)
                        HStack { Text("max-size"); TextField("0 = 2 MB 上限", text: $maxSize).keyboardType(.numberPad).multilineTextAlignment(.trailing) }
                        HStack { Text("timeout（秒）"); TextField("10", text: $timeout).keyboardType(.numberPad).multilineTextAlignment(.trailing) }
                        TextField("argument（可选）", text: $argument).textInputAutocapitalization(.never).autocorrectionDisabled()
                    }
                    Section("脚本来源") {
                        Picker("", selection: $source) {
                            Text("本地").tag(0)
                            Text("URL").tag(1)
                        }.pickerStyle(.segmented)
                        if source == 1 {
                            TextField("https://…/script.js", text: $path).keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                        } else {
                            CodeEditor(text: $code, language: .javascript)
                                .frame(minHeight: 260)
                                .listRowInsets(EdgeInsets())
                            Text("保存为 \(scriptPath)").font(.caption2).foregroundStyle(.secondary)
                            NavigationLink {
                                ScriptDebugForm(code: code, path: nil, name: name.isEmpty ? "script" : name, sample: $debugSample)
                                    .navigationTitle("调试运行")
                                    .navigationBarTitleDisplayMode(.inline)
                                    .onAppear { debugSample.type = type }
                            } label: { Label("调试运行", systemImage: "play.fill") }
                        }
                    }
                    Section("生成的脚本行") {
                        Text(line).scaledFont(10, design: .monospaced).textSelection(.enabled)
                    }
                }
            }
            .navigationTitle(item == nil ? "新建脚本" : "编辑脚本")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { if dirty { confirmDiscard = true } else { dismiss() } } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") { save(); dismiss() }.disabled(rawMode ? rawLine.isEmpty : (pattern.isEmpty || (source == 1 && path.isEmpty)))
                }
            }
            .confirmationDialog("放弃修改？", isPresented: $confirmDiscard, titleVisibility: .visible) {
                Button("放弃修改", role: .destructive) { dismiss() }
            }
            .onAppear(perform: load)
        }
        .interactiveDismissDisabled(dirty)
    }

    func load() {
        guard !loaded else { return }
        defer { loaded = true; initial = fingerprint }
        if item == nil && code.isEmpty {
            code = """
            // $response.body 是字符串（binary-body-mode 时为 Uint8Array）
            let body = $response.body;
            try {
              const obj = JSON.parse(body);
              // obj.ad = null;
              body = JSON.stringify(obj);
            } catch (e) { console.log('not json: ' + e); }
            $done({ body });
            """
        }
        guard let item else { return }
        // Parse "name = type=...,k=v" back into the form; other syntaxes edit as raw text.
        let l = item.line
        guard let eq = l.range(of: "="), l[eq.upperBound...].trimmingCharacters(in: .whitespaces).hasPrefix("type=") else {
            rawMode = true; rawLine = l; return
        }
        name = l[..<eq.lowerBound].trimmingCharacters(in: .whitespaces)
        let params = String(l[eq.upperBound...]).trimmingCharacters(in: .whitespaces)
        let keys = ["type", "pattern", "requires-body", "binary-body-mode", "max-size", "script-path", "argument", "timeout", "script-update-interval", "debug", "engine"]
        var dict: [String: String] = [:]
        var current = ""
        var key = ""
        for part in params.components(separatedBy: ",") {
            if let k = keys.first(where: { part.trimmingCharacters(in: .whitespaces).hasPrefix($0 + "=") }) {
                if !key.isEmpty { dict[key] = current }
                key = k
                current = String(part.trimmingCharacters(in: .whitespaces).dropFirst(k.count + 1))
            } else {
                current += "," + part
            }
        }
        if !key.isEmpty { dict[key] = current }
        type = dict["type"] ?? "http-response"
        pattern = dict["pattern"] ?? ""
        requiresBody = ["1", "true"].contains(dict["requires-body"] ?? "")
        binary = ["1", "true"].contains(dict["binary-body-mode"] ?? "")
        maxSize = dict["max-size"] ?? ""
        timeout = dict["timeout"] ?? "10"
        argument = (dict["argument"] ?? "").trimmingCharacters(in: CharacterSet(charactersIn: "\""))
        let p = dict["script-path"] ?? ""
        if p.hasPrefix("http") { source = 1; path = p } else { source = 0; path = p; code = store.readScript(p) }
    }

    func save() {
        let final: String
        if rawMode {
            final = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
        } else {
            if source == 0 { store.writeScript(scriptPath, code) }
            final = line
        }
        if let item, let i = store.config.scripts.firstIndex(where: { $0.id == item.id }) {
            store.config.scripts[i].line = final
        } else {
            store.config.scripts.append(EngineItem(line: final))
            if !store.config.scriptsEnabled { store.config.scriptsEnabled = true }
        }
        store.save()
    }
}

struct LocalScriptsView: View {
    @ObservedObject var store = EngineStore.shared
    @State private var files: [String] = []
    /// Review 5: deleting a script file asks first (script lines may still point at it) and saves a snapshot.
    @State private var pendingDelete: [String]?
    var body: some View {
        List {
            ForEach(files, id: \.self) { f in
                NavigationLink { ScriptWorkbenchView(target: .local(f)) } label: { Text(f).font(.system(.callout, design: .monospaced)) }
            }
            .onDelete { idx in pendingDelete = idx.map { files[$0] } }
            .listRowBackground(Theme.card)
            if files.isEmpty { EmptyStateRow(icon: "curlybraces", title: "暂无本地脚本").listRowBackground(Theme.card) }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("本地脚本")
        .onAppear { files = store.localScripts() }
        .deleteConfirmation({ l in l.count == 1 ? Text("删除「\(l[0])」？") : Text("删除 \(l.count) 个脚本？") }, item: $pendingDelete,
                            message: { l in
                                let used = l.filter { f in store.config.scripts.contains { $0.line.contains(f) } }
                                return used.isEmpty ? DeleteText.recoverable : Text("仍有脚本行引用：\(used.joined(separator: "、"))。删除后这些脚本无法运行。")
                            }) { l in
            Task {
                await SnapshotStore.shared.captureAsync(String(localized: "删除本地脚本前"))
                for f in l { try? FileManager.default.removeItem(at: EnginePaths.scriptURL(f)) }
                files = store.localScripts()
            }
        }
    }
}

struct ScriptLogsView: View {
    @EnvironmentObject var vpn: VPNManager
    @State private var lines: [ScriptLogLine] = []
    @State private var filter = ""
    @State private var timer: Task<Void, Never>?
    /// v0.19.21 (quieter, like Quantumult X): routine DEBUG lines (「执行完成，用时 N ms」, 排队 …) are hidden
    /// unless 显示调试 is on; WARN / ERROR / console lines always show. Repeats are folded by the core (×N).
    @AppStorage("scriptLogShowDebug") private var showDebug = false

    var shown: [ScriptLogLine] {
        let base = showDebug ? lines : lines.filter { $0.level != "debug" }
        guard !filter.isEmpty else { return base }
        return base.filter { $0.script.localizedCaseInsensitiveContains(filter) || $0.msg.localizedCaseInsensitiveContains(filter) }
    }

    var body: some View {
        Group {
            if !vpn.isConnected { NotConnectedPlaceholder(text: "连接后可查看脚本日志") } else {
                List(shown.reversed()) { l in
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(l.level.uppercased()).scaledFont(9, weight: .bold).foregroundStyle(color(l.level))
                            Text(l.script).font(.caption2.weight(.semibold)).foregroundStyle(Theme.accent)
                            if let n = l.count, n > 1 {
                                Text(verbatim: "×\(n)").scaledFont(9, weight: .bold, monospacedDigit: true).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Text(Date(timeIntervalSince1970: l.time).formatted(date: .omitted, time: .standard)).scaledFont(9, monospacedDigit: true).foregroundStyle(.secondary)
                        }
                        Text(l.msg).scaledFont(11, design: .monospaced).textSelection(.enabled)
                    }
                    .listRowBackground(Theme.card)
                }
                .listStyle(.plain)
                .scrollContentBackground(.hidden)
                .searchable(text: $filter, placement: .navigationBarDrawer(displayMode: .always), prompt: "过滤脚本名或内容")
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("脚本日志")
        .toolbar {
            Toggle(isOn: $showDebug) { Label("显示调试", systemImage: "ladybug") }
                .toggleStyle(.button)
            Button { Task { try? await ControllerClient.shared.mitmClearLogs(); lines = [] } } label: { Image(systemName: "trash") }
        }
        .onAppear {
            // v0.19.2: onAppear runs again when a pushed page / sheet closes; the old loop was overwritten without
            // being cancelled and kept polling the core every 1.5 s for the rest of the session.
            timer?.cancel()
            timer = Task {
                while !Task.isCancelled {
                    if vpn.isConnected, let l = try? await ControllerClient.shared.mitmLogs() { lines = l }
                    try? await Task.sleep(nanoseconds: 1_500_000_000)
                }
            }
        }
        .onDisappear { timer?.cancel() }
    }

    func color(_ l: String) -> Color {
        switch l {
        case "error": return Theme.bad
        case "warn": return Theme.warn
        case "notify": return Theme.good
        case "debug": return .secondary
        default: return Theme.accent
        }
    }
}

struct StoreView: View {
    @ObservedObject var store = EngineStore.shared
    @State private var items: [(String, String)] = []
    @State private var editKey: String?
    @State private var editValue = ""
    @State private var newKey = ""
    @State private var adding = false
    // Loon gap: 导出 / 导入 / 清空全部
    @State private var share: ShareItem?
    @State private var confirmExport = false
    @State private var importing = false
    @State private var confirmClear = false
    @State private var message: String?

    func reload() {
        Task {
            let m = await Task.detached(priority: .userInitiated) { () -> [String: String] in
                guard let d = try? Data(contentsOf: EnginePaths.storeURL),
                      let m = try? JSONDecoder().decode([String: String].self, from: d) else { return [:] }
                return m
            }.value
            items = m.sorted { $0.key < $1.key }.map { ($0.key, $0.value) }
        }
    }

    func exportStore() {
        Task {
            let url = await Task.detached(priority: .userInitiated) { EngineStore.storeExportFile() }.value
            if let url { share = ShareItem(url: url, temporary: true) } else { message = String(localized: "导出失败") }
        }
    }

    func importStore(_ url: URL) {
        let ok = url.startAccessingSecurityScopedResource()
        let data = try? Data(contentsOf: url)
        if ok { url.stopAccessingSecurityScopedResource() }
        guard let data else { message = String(localized: "无法读取文件"); return }
        Task {
            let n = await Task.detached(priority: .userInitiated) { EngineStore.storeImport(data) }.value
            if let n { message = String(localized: "已导入 \(n) 项") } else { message = String(localized: "文件不是有效的 JSON 对象") }
            reload()
        }
    }

    func clearStore() {
        Task {
            let ok = await Task.detached(priority: .userInitiated) { EngineStore.storeClear() }.value
            if !ok { message = String(localized: "清空失败") }
            reload()
        }
    }

    var body: some View {
        List {
            if items.isEmpty { EmptyStateRow(icon: "tray", title: "暂无数据").listRowBackground(Theme.card) }
            ForEach(items, id: \.0) { kv in
                let k = kv.0
                let v = kv.1
                VStack(alignment: .leading, spacing: 3) {
                    Text(k).font(.caption.weight(.semibold))
                    Text(v).scaledFont(11, design: .monospaced).foregroundStyle(.secondary).lineLimit(4)
                }
                .contentShape(Rectangle())
                .onTapGesture { editKey = k; editValue = v }
                .contextMenu { Button("复制值") { UIPasteboard.general.string = v } }
                .listRowBackground(Theme.card)
            }
            .onDelete { idx in for i in idx { store.storeSet(items[i].0, nil) }; items = store.storeItems() }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("持久化存储")
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                Menu {
                    Button { confirmExport = true } label: { Label("导出", systemImage: "square.and.arrow.up") }
                        .disabled(items.isEmpty)
                    Button { importing = true } label: { Label("导入", systemImage: "square.and.arrow.down") }
                    Divider()
                    Button(role: .destructive) { confirmClear = true } label: { Label("清空全部", systemImage: "trash") }
                        .disabled(items.isEmpty)
                } label: { Image(systemName: "ellipsis.circle") }
                .accessibilityLabel(Text("更多"))
                .accessibilityIdentifier("store.menu")
                Button { adding = true } label: { Image(systemName: "plus") }
                    .accessibilityIdentifier("store.add")
            }
        }
        .onAppear { reload() }
        .sheet(item: $share, onDismiss: { try? FileManager.default.removeItem(at: EngineStore.storeExportURL) }) {
            ActivityView(items: [$0.url], cleanup: $0.temporary ? $0.url : nil)
        }
        .confirmationDialog("导出持久化存储？", isPresented: $confirmExport, titleVisibility: .visible) {
            Button("导出") { exportStore() }
            Button("取消", role: .cancel) {}
        } message: { Text("文件可能包含脚本保存的 Cookie、Token 等数据，请勿分享给他人。") }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.json, .data]) { r in
            if case .success(let url) = r { importStore(url) }
        }
        .confirmationDialog("清空全部 \(items.count) 项？", isPresented: $confirmClear, titleVisibility: .visible) {
            Button("清空全部", role: .destructive) { clearStore() }
            Button("取消", role: .cancel) {}
        } message: { Text("脚本保存的数据（如 BoxJS 设置、登录信息）都会被删除，无法恢复。") }
        .alert("持久化存储", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好") { message = nil }
        } message: { Text(message ?? "") }
        .sheet(isPresented: Binding(get: { editKey != nil || adding }, set: { if !$0 { editKey = nil; adding = false } })) {
            NavigationStack {
                Form {
                    if adding { TextField("键", text: $newKey).textInputAutocapitalization(.never).autocorrectionDisabled() }
                    Section("值") {
                        TextEditor(text: $editValue).scaledFont(12, design: .monospaced).frame(minHeight: 200)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                    }
                }
                .navigationTitle(adding ? "新建" : (editKey ?? ""))
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) { Button("取消") { editKey = nil; adding = false } }
                    ToolbarItem(placement: .confirmationAction) {
                        Button("保存") {
                            let k = adding ? newKey : (editKey ?? "")
                            if !k.isEmpty { store.storeSet(k, editValue) }
                            items = store.storeItems(); editKey = nil; adding = false; newKey = ""; editValue = ""
                        }
                    }
                }
            }
        }
    }
}

// MARK: - Modules

struct PasteModuleSheet: View {
    @Environment(\.dismiss) var dismiss
    @ObservedObject var store = EngineStore.shared
    @State private var text = ""
    @State private var name = ""
    var body: some View {
        NavigationStack {
            Form {
                TextField("名称", text: $name)
                TextEditor(text: $text).scaledFont(12, design: .monospaced).frame(minHeight: 260)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
            }
            .navigationTitle("粘贴模块").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("添加") { store.addModule(text: text, name: name.isEmpty ? "本地模块" : name); dismiss() }.disabled(text.isEmpty)
                }
            }
        }
    }
}

struct ModuleDetailView: View {
    let moduleID: String
    @ObservedObject var store = EngineStore.shared
    @State private var showText = false
    @State private var args: [String: String] = [:]
    @State private var unresolved: [String] = []
    @State private var groups: [String] = []
    @StateObject private var debounce = Debouncer()

    /// v0.15.4: module arguments apply on change (debounced) instead of a 保存参数 button.
    func applyArgs() {
        guard !args.isEmpty, let i = store.config.modules.firstIndex(where: { $0.id == moduleID }) else { return }
        var merged = store.config.modules[i].args ?? [:]
        for (k, v) in args { merged[k] = v }
        guard merged != (store.config.modules[i].args ?? [:]) else { return }
        store.config.modules[i].args = merged
        store.reparseModules()
        store.save()
        loadPolicies()
    }

    func policyNames(_ m: EngineModule) -> [String] {
        var out = unresolved
        for k in (m.policies ?? [:]).keys.sorted() where !out.contains(k) { out.append(k) }
        return out
    }

    func setPolicy(_ name: String, _ group: String) {
        guard let i = store.config.modules.firstIndex(where: { $0.id == moduleID }) else { return }
        var p = store.config.modules[i].policies ?? [:]
        if group.isEmpty { p.removeValue(forKey: name) } else { p[name] = group }
        store.config.modules[i].policies = p.isEmpty ? nil : p
        store.save()
    }

    /// Unknown policy names in the module's [Rule] lines, and the active profile's groups to pick from.
    func loadPolicies() {
        guard let m = module, let profile = AppShared.activeProfileURL?.path else { unresolved = []; groups = []; return }
        let home = AppShared.homeURL.path
        let text = store.moduleText(m)
        let argsJSON = (try? JSONEncoder().encode(m.args ?? [:])).flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
        Task {
            let (u, g) = await Task.detached(priority: .userInitiated) { () -> ([String], [String]) in
                let uj = LibmihomoModuleUnresolved(home, profile, text, argsJSON)
                let gj = LibmihomoProfileGroups(home, profile)
                let u = (try? JSONDecoder().decode([String].self, from: Data(uj.utf8))) ?? []
                let g = (try? JSONDecoder().decode([String].self, from: Data(gj.utf8))) ?? []
                return (u.sorted(), g)
            }.value
            unresolved = u
            groups = g
        }
    }

    var module: EngineModule? { store.config.modules.first { $0.id == moduleID } }

    var body: some View {
        let info = store.moduleInfo[moduleID]
        List {
            if let m = module {
                Section {
                    LabeledContent("名称", value: m.name)
                    if let f = info?.format, !f.isEmpty { LabeledContent("格式") { SourceFormatBadge(format: f) } }
                    Button { showText = true } label: { Label("查看内容", systemImage: "doc.text") }
                }
                .listRowBackground(Theme.card)
                ResourceUpdateSection(key: "module:" + m.id)
                if let info, !info.arguments.isEmpty {
                    Section(info.format == "loon" ? "参数（[Argument]）" : info.format == "egern" ? "参数（compat_arguments）" : "参数（#!arguments）") {
                        ForEach(info.arguments, id: \.key) { a in
                            ModuleArgRow(arg: a, value: Binding(get: { args[a.key] ?? (m.args?[a.key] ?? a.default) }, set: { args[a.key] = $0 }))
                        }
                        // v0.15.4: 参数 apply on change (debounced), no 保存参数 button.
                    }
                    .listRowBackground(Theme.card)
                }
                if !unresolved.isEmpty || !(m.policies ?? [:]).isEmpty {
                    Section {
                        ForEach(policyNames(m), id: \.self) { name in
                            Picker(selection: Binding(get: { m.policies?[name] ?? "" }, set: { setPolicy(name, $0) })) {
                                Text("自动（第一个手动组）").tag("")
                                ForEach(groups, id: \.self) { Text($0).tag($0) }
                            } label: {
                                HStack(spacing: 6) {
                                    if unresolved.contains(name) && m.policies?[name] == nil {
                                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Theme.warn).font(.caption)
                                    }
                                    Text(name).font(.callout)
                                }
                            }
                        }
                    } header: { Text("策略映射") } footer: {
                        Text("模块规则里的这些策略名在当前配置中不存在。为每个名称选择一个策略组；未选择时使用第一个手动选择组。")
                    }
                    .listRowBackground(Theme.card)
                }
                if let info {
                    if !info.hostnames.isEmpty {
                        Section("MitM 主机名 \(info.hostnames.count)") {
                            Text(info.hostnames.joined(separator: ", ")).scaledFont(11, design: .monospaced)
                        }.listRowBackground(Theme.card)
                    }
                    Section("规则 / 脚本 \(info.rules.count)") {
                        ForEach(Array(info.rules.enumerated()), id: \.offset) { e in
                            let r = e.element
                            VStack(alignment: .leading, spacing: 3) {
                                HStack { KindBadge(kind: r.kind, phase: r.phase); Text(verbatim: GoText.localize(r.desc)).font(.caption.weight(.semibold)).lineLimit(1) }
                                Text(r.pattern).scaledFont(10, design: .monospaced).foregroundStyle(.secondary).lineLimit(2)
                            }
                        }
                    }.listRowBackground(Theme.card)
                    if let tasks = info.tasks, !tasks.isEmpty {
                        Section("定时 / 事件 / 通用脚本 \(tasks.count)") {
                            ForEach(Array(tasks.enumerated()), id: \.offset) { e in
                                VStack(alignment: .leading, spacing: 3) {
                                    HStack { KindBadge(kind: e.element.kind); Text(e.element.name).font(.caption.weight(.semibold)).lineLimit(1) }
                                    Text(e.element.desc).scaledFont(10, design: .monospaced).foregroundStyle(.secondary).lineLimit(2)
                                }
                            }
                            NavigationLink { ScriptTasksView() } label: { Label("查看运行状态", systemImage: "clock.arrow.circlepath").font(.caption) }
                        }.listRowBackground(Theme.card)
                    }
                    if let panels = info.panels, !panels.isEmpty {
                        Section("面板 \(panels.count)") {
                            ForEach(Array(panels.enumerated()), id: \.offset) { e in
                                HStack { FormatBadge(format: e.element.format); Text(e.element.title).font(.caption.weight(.semibold)).lineLimit(1) }
                            }
                            NavigationLink { PanelsView() } label: { Label("打开面板", systemImage: "square.grid.2x2").font(.caption) }
                        }.listRowBackground(Theme.card)
                    }
                    if !info.coreRules.isEmpty {
                        Section("内核规则 \(info.coreRules.count)") {
                            ForEach(info.coreRules.prefix(200), id: \.self) { Text($0).scaledFont(10, design: .monospaced) }
                        }.listRowBackground(Theme.card)
                    }
                    if !info.errors.isEmpty || !info.unsupported.isEmpty {
                        Section("未导入 \(info.errors.count + info.unsupported.count)") {
                            ForEach(info.errors, id: \.self) { Text($0).font(.caption2).foregroundStyle(Theme.bad) }
                            ForEach(info.unsupported.prefix(100), id: \.self) { Text($0).scaledFont(10, design: .monospaced).foregroundStyle(.secondary) }
                        }.listRowBackground(Theme.card)
                    }
                }
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle(module?.name ?? String(localized: "模块"))
        .onAppear { loadPolicies(); ResourceStore.shared.reload() }
        .onChange(of: args) { _ in debounce.schedule { applyArgs() } }
        .onDisappear { debounce.flush() }
        .sheet(isPresented: $showText) {
            NavigationStack {
                ScrollView {
                    Text(module.map { store.moduleText($0) } ?? "").scaledFont(11, design: .monospaced).textSelection(.enabled).padding()
                }
                .navigationTitle("内容").navigationBarTitleDisplayMode(.inline)
                .toolbar { Button("完成") { showText = false } }
            }
        }
    }
}

// MARK: - HTTP requests (请求 → HTTP)

@MainActor
final class HTTPLogModel: ObservableObject {
    @Published var items: [HTTPRequestSummary] = []
    @Published var hosts: [String: [String]] = [:]
    private var task: Task<Void, Never>?

    func start() {
        task?.cancel()
        task = Task { [weak self] in
            while !Task.isCancelled {
                await self?.poll()
                try? await Task.sleep(nanoseconds: 1_500_000_000)
            }
        }
    }

    func stop() { task?.cancel(); task = nil }

    func poll() async {
        if let r = try? await ControllerClient.shared.mitmRequests() { items = r }
        if let h = try? await ControllerClient.shared.mitmHosts() { hosts = h }
    }

    func clear() async {
        try? await ControllerClient.shared.mitmClearRequests()
        items = []
    }
}

struct HTTPRequestRow: View {
    let r: HTTPRequestSummary
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                Text(r.method).scaledFont(9, weight: .bold)
                    .padding(.horizontal, 5).padding(.vertical, 2)
                    .lineLimit(1) // v0.19.8: a capsule tag never wraps (tall grey box with large text)
                    .background(Capsule().fill(Theme.accent.opacity(0.2)))
                if r.mitm { Text("MitM").scaledFont(9, weight: .bold).foregroundStyle(Theme.warn) }
                Text(r.host).font(.system(.footnote, design: .monospaced)).lineLimit(1)
                Spacer()
                Text(r.status > 0 ? "\(r.status)" : (r.done ? "—" : "…"))
                    .font(.caption.monospacedDigit().weight(.semibold))
                    .foregroundStyle(r.status >= 400 || r.status == 0 && r.done ? Theme.bad : (r.status >= 300 ? Theme.warn : Theme.good))
            }
            Text(r.path).scaledFont(11, design: .monospaced).foregroundStyle(.secondary).lineLimit(2).truncationMode(.middle)
            if let m = r.matched, !m.isEmpty {
                Text(m.joined(separator: " · ")).font(.caption2).foregroundStyle(Theme.accent).lineLimit(2)
            }
            if let n = r.notes, !n.isEmpty { Text(n.joined(separator: " · ")).font(.caption2).foregroundStyle(Theme.warn).lineLimit(2) }
            HStack {
                Text(r.date.formatted(date: .omitted, time: .standard))
                if let d = r.duration { Text("\(Int(d)) ms") }
                Text(Fmt.bytes(r.bytes))
                if r.local == true { Text("本地响应") }
            }
            .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
    }
}

struct HTTPRequestDetailView: View {
    let id: Int64
    @State private var d: HTTPRequestDetail?
    @State private var tab = 0
    @State private var replaying = false
    @State private var replay: ReplayResult?
    @State private var replayError: String?
    @State private var editing = false
    @State private var copied = false
    @State private var harShare: ShareItem?

    var body: some View {
        List {
            if let d {
                Section {
                    Text(d.url).scaledFont(11, design: .monospaced).textSelection(.enabled)
                    LabeledContent("方法 / 状态", value: "\(d.method) · \(d.status)")
                    if let du = d.duration { LabeledContent("耗时", value: "\(Int(du)) ms") }
                    LabeledContent("大小", value: Fmt.bytes(d.bytes))
                    LabeledContent("HTTPS 解密", value: d.mitm ? String(localized: "是") : String(localized: "否（明文 HTTP）"))
                }
                .listRowBackground(Theme.card)
                Section {
                    Button { UIPasteboard.general.string = d.curl; copied = true } label: {
                        Label(copied ? "已复制 cURL" : "复制为 cURL", systemImage: copied ? "checkmark" : "terminal")
                    }
                    if d.method != "TLS" {
                        Button { shareHAR(d) } label: { Label("导出 HAR", systemImage: "square.and.arrow.up") }
                    }
                    Button { runReplay(nil) } label: { Label("重放", systemImage: "arrow.uturn.forward") }
                        .disabled(!d.canReplay || replaying)
                    Button { editing = true } label: { Label("编辑后重放", systemImage: "square.and.pencil") }
                        .disabled(!d.canReplay || replaying)
                    if d.method != "TLS" {
                        NavigationLink { ScriptWorkbenchView(target: .scratch, sample: .from(d)) } label: {
                            Label("用此请求调试脚本", systemImage: "play.rectangle")
                        }
                    }
                    if !d.canReplay && d.method != "TLS" {
                        Text("请求体是二进制或超过 32 KB，没有完整记录，无法重放。").font(.caption2).foregroundStyle(.secondary)
                    }
                    if replaying { LoadingRow(text: "发送中…") }
                    if let e = replayError { Text(e).font(.caption).foregroundStyle(Theme.bad) }
                    if let r = replay { ReplayResultView(r: r) }
                } header: { Text("操作") } footer: {
                    Text("重放经内核按你的规则与策略发出，不再经过重写与脚本；结果也会出现在请求列表里。")
                }
                .listRowBackground(Theme.card)
                if let m = d.matched, !m.isEmpty {
                    Section("命中规则 / 脚本") { ForEach(m, id: \.self) { Text($0).font(.caption) } }.listRowBackground(Theme.card)
                }
                if let n = d.notes, !n.isEmpty {
                    Section("备注") { ForEach(n, id: \.self) { Text($0).font(.caption).foregroundStyle(Theme.warn).textSelection(.enabled) } }.listRowBackground(Theme.card)
                }
                Picker("", selection: $tab) {
                    Text("请求").tag(0)
                    Text("响应").tag(1)
                }
                .pickerStyle(.segmented)
                .listRowBackground(Color.clear)
                let headers = (tab == 0 ? d.reqHeaders : d.respHeaders) ?? [:]
                Section("头部 \(headers.count)") {
                    ForEach(headers.keys.sorted(), id: \.self) { k in
                        VStack(alignment: .leading, spacing: 1) {
                            Text(k).font(.caption2.weight(.semibold)).foregroundStyle(.secondary)
                            Text(headers[k] ?? "").scaledFont(11, design: .monospaced).textSelection(.enabled)
                        }
                    }
                }
                .listRowBackground(Theme.card)
                Section("内容") {
                    let content = tab == 0 ? d.reqBody : d.respBody
                    let bin = tab == 0 ? d.reqBodyBinary : d.respBodyBinary
                    if let content, !content.isEmpty {
                        Text(Self.pretty(content)).scaledFont(11, design: .monospaced).textSelection(.enabled)
                        Button { UIPasteboard.general.string = content } label: { Label("复制", systemImage: "doc.on.doc") }
                    } else if let bin, bin > 0 {
                        Text("二进制或压缩内容（\(Fmt.bytes(Int64(bin)))\(d.respEncoding.map { "，\($0)" } ?? "")）").font(.caption).foregroundStyle(.secondary)
                    } else {
                        Text("无内容或未记录（仅记录前 32 KB）").font(.caption).foregroundStyle(.secondary)
                    }
                }
                .listRowBackground(Theme.card)
            } else {
                ProgressView().listRowBackground(Color.clear)
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("请求详情")
        .navigationBarTitleDisplayMode(.inline)
        .task { d = try? await ControllerClient.shared.mitmRequest(id) }
        .sheet(item: $harShare) { ActivityView(items: [$0.url]) }
        .sheet(isPresented: $editing) {
            if let d { ReplayEditor(detail: d) { edit in runReplay(edit) } }
        }
    }

    func shareHAR(_ d: HTTPRequestDetail) {
        guard let data = try? HARExport.document([d]) else { return }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("Tern-request-\(d.id).har")
        if (try? data.write(to: url, options: .atomic)) != nil { harShare = ShareItem(url: url) }
    }

    func runReplay(_ edit: [String: Any]?) {
        replaying = true; replayError = nil; replay = nil
        Task {
            defer { replaying = false }
            do {
                let r = try await ControllerClient.shared.mitmReplay(id, edit: edit)
                if let e = r.error { replayError = e } else { replay = r }
            } catch ControllerClient.APIError.http(_, let msg) {
                replayError = msg.trimmingCharacters(in: .whitespacesAndNewlines)
            } catch { replayError = error.localizedDescription }
        }
    }

    static func pretty(_ s: String) -> String {
        guard s.count < 200_000, let data = s.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data),
              let out = try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .withoutEscapingSlashes]),
              let str = String(data: out, encoding: .utf8) else { return s }
        return str
    }
}

struct ReplayResultView: View {
    let r: ReplayResult
    @State private var showBody = false
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text("HTTP \(r.status)").font(.subheadline.weight(.bold).monospacedDigit())
                    .foregroundStyle((200..<400).contains(r.status) ? Theme.good : Theme.bad)
                Text("\(Int(r.duration)) ms · \(Fmt.bytes(Int64(r.length)))").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button(showBody ? "收起" : "查看响应") { showBody.toggle() }.font(.caption).buttonStyle(.borderless)
            }
            if r.truncated == true {
                Text("响应体过大，只显示开头部分").font(.caption).foregroundStyle(Theme.warn)
            }
            if let e = r.error, !e.isEmpty { Text(verbatim: e).font(.caption).foregroundStyle(Theme.bad) }
            if showBody {
                ForEach(r.headers.keys.sorted(), id: \.self) { k in
                    Text("\(k): \(r.headers[k] ?? "")").scaledFont(10, design: .monospaced).foregroundStyle(.secondary).textSelection(.enabled)
                }
                if let b = r.body, !b.isEmpty {
                    Text(HTTPRequestDetailView.pretty(b)).scaledFont(11, design: .monospaced).textSelection(.enabled)
                } else if let bin = r.binary, bin > 0 {
                    Text("二进制内容（\(Fmt.bytes(Int64(bin)))）").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }
}

struct ReplayEditor: View {
    let detail: HTTPRequestDetail
    var onSend: ([String: Any]) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var method = ""
    @State private var url = ""
    @State private var headers = ""
    @State private var bodyText = ""

    var form: some View {
        Form {
            Section("请求行") {
                TextField("方法", text: $method).textInputAutocapitalization(.characters).autocorrectionDisabled()
                TextField("URL", text: $url, axis: .vertical).scaledFont(12, design: .monospaced)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
            }
            Section {
                TextEditor(text: $headers).scaledFont(11, design: .monospaced).frame(minHeight: 140)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
            } header: { Text("头部（每行 名称: 值）") }
            Section("内容") {
                TextEditor(text: $bodyText).scaledFont(11, design: .monospaced).frame(minHeight: 120)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
            }
        }
    }

    var body: some View {
        NavigationStack {
            form
                .navigationTitle("编辑后重放")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                    ToolbarItem(placement: .confirmationAction) { Button("发送") { send() }.disabled(url.isEmpty) }
                }
                .onAppear {
                    method = detail.method
                    url = detail.url
                    headers = (detail.reqHeaders ?? [:]).keys.sorted().map { "\($0): \(detail.reqHeaders?[$0] ?? "")" }.joined(separator: "\n")
                    bodyText = detail.reqBody ?? ""
                }
        }
    }

    func send() {
        var h: [String: String] = [:]
        for line in headers.split(separator: "\n") {
            guard let i = line.firstIndex(of: ":") else { continue }
            let k = line[..<i].trimmingCharacters(in: .whitespaces)
            let v = line[line.index(after: i)...].trimmingCharacters(in: .whitespaces)
            if !k.isEmpty { h[k] = v }
        }
        onSend(["method": method.trimmingCharacters(in: .whitespaces).uppercased(), "url": url.trimmingCharacters(in: .whitespacesAndNewlines), "headers": h, "body": bodyText])
        dismiss()
    }
}

/// One module argument: Loon switch → toggle, select → picker, anything else → text field.
struct ModuleArgRow: View {
    let arg: ParsedEngineText.Arg
    @Binding var value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            switch arg.type ?? "" {
            case "switch":
                Toggle(arg.key, isOn: Binding(get: { ["true", "1", "on", "yes"].contains(value.lowercased()) }, set: { value = $0 ? "true" : "false" }))
            case "select":
                Picker(arg.key, selection: $value) {
                    ForEach(choices, id: \.self) { Text($0).tag($0) }
                }
            default:
                HStack {
                    Text(arg.key).font(.callout)
                    TextField(arg.default, text: $value)
                        .multilineTextAlignment(.trailing).textInputAutocapitalization(.never).autocorrectionDisabled()
                }
            }
            if let d = arg.desc, !d.isEmpty { Text(d).font(.caption2).foregroundStyle(.secondary) }
        }
    }

    var choices: [String] {
        var c = arg.options ?? []
        if !c.contains(value) { c.insert(value, at: 0) }
        return c
    }
}
