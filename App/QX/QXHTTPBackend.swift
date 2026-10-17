import SwiftUI
import Libmihomo

// QX preview 5: HTTP Backend (frame 35). A local HTTP server inside the tunnel (bridge/mitm/backend.go):
// each backend is a script with a path regex; http://127.0.0.1:<port>/<path> runs the first enabled match
// with $request and answers with $done({status, headers, body}). Capsule [⚙ 端口 | 开关 | +], rows with a
// checkbox, tag, script and path; long-press 编辑 / 更新脚本 / 拷贝 / 删除.

struct HTTPBackendStatus: Decodable {
    var running: Bool?
    var port: Int?
    var backends: Int?
    var error: String?
}

extension ControllerClient {
    func mitmHTTPBackend() async throws -> HTTPBackendStatus { try await get(HTTPBackendStatus.self, "/mitm/http-backend") }
}

@MainActor
enum QXHTTPBackendStore {
    static var config: HTTPBackendConfig { EngineStore.shared.config.httpBackend ?? HTTPBackendConfig() }

    static func update(_ f: (inout HTTPBackendConfig) -> Void) {
        var c = config
        f(&c)
        EngineStore.shared.config.httpBackend = c
        EngineStore.shared.save()
    }

    /// Adds QX [http_backend] lines from an imported configuration; same script + path is skipped.
    @discardableResult
    static func importConf(_ text: String) -> Int {
        guard text.range(of: "[http_backend]", options: .caseInsensitive) != nil else { return 0 }
        let json = LibmihomoQXHTTPBackends(text)
        guard let list = try? JSONDecoder().decode([HTTPBackendItem].self, from: Data(json.utf8)), !list.isEmpty else { return 0 }
        var added = 0
        update { c in
            for it in list where !c.items.contains(where: { $0.script == it.script && $0.path == it.path }) {
                c.items.append(it)
                added += 1
            }
        }
        return added
    }
}

struct QXHTTPBackendView: View {
    @EnvironmentObject var vpn: VPNManager
    @ObservedObject private var engine = EngineStore.shared
    @State private var status: HTTPBackendStatus?
    @State private var editing: HTTPBackendItem?
    @State private var adding = false
    @State private var portSheet = false
    @State private var updatingID: String?
    @State private var message: String?

    private var cfg: HTTPBackendConfig { engine.config.httpBackend ?? HTTPBackendConfig() }

    var body: some View {
        QXPage {
            QXCapsuleBar {
                QXBarIcon(systemName: "gearshape") { portSheet = true }
                    .accessibilityLabel(Text("端口"))
                QXBarIcon(systemName: cfg.enabled ? "server.rack" : "xserve", tint: cfg.enabled ? QXColor.switchOn : .secondary) {
                    QXHaptics.toggle()
                    QXHTTPBackendStore.update { $0.enabled.toggle() }
                    refreshSoon()
                }
                .overlay { if !cfg.enabled { Image(systemName: "line.diagonal").font(.system(size: 22, weight: .bold)).foregroundStyle(.secondary).allowsHitTesting(false) } }
                .accessibilityLabel(Text("HTTP Backend"))
                .accessibilityValue(Text(cfg.enabled ? LocalizedStringKey("已开启") : LocalizedStringKey("已关闭")))
                QXBarIcon(systemName: "plus") { adding = true }
                    .accessibilityLabel(Text("添加"))
            }
        } content: {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    QXLargeTitle(title: "HTTP Backend").padding(.bottom, 12)
                    statusCard.padding(.bottom, 12)
                    if cfg.items.isEmpty {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("还没有后端").font(.headline)
                            Text("点右上角 + 添加，或粘贴 QX 的 [http_backend] 行，例如：").font(.footnote).foregroundStyle(.secondary)
                            Text(verbatim: "https://raw.githubusercontent.com/chavyleung/scripts/master/chavy.box.js, tag=BoxJS, path=^/, enabled=true")
                                .font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
                        }
                        .padding(.vertical, 14)
                    }
                    ForEach(cfg.items) { it in
                        row(it)
                        Divider().overlay(QXPalette.separator)
                    }
                    Text("搭建一个本地的 HTTP 服务器，并使用 JavaScript 来进行数据处理，您可以使用 http://127.0.0.1:\(String(cfg.effectivePort))/path/ 或 http://localhost:\(String(cfg.effectivePort))/path/ 来访问。按顺序使用第一个路径正则匹配的已勾选后端；脚本通过 $request 读取请求，用 $done({status, headers, body}) 回应。")
                        .font(.system(size: 14)).foregroundStyle(.secondary).lineSpacing(3)
                        .padding(.top, 14)
                    Text("HTTP Backend 需要 VPN 已连接，并且右上角的开关为开启状态。http://quantumult-x:9999 这种主机名写法暂不支持，请改用 127.0.0.1。")
                        .font(.system(size: 14)).foregroundStyle(.secondary).lineSpacing(3)
                        .padding(.top, 6)
                }
                .padding(.horizontal, QXMetrics.inset)
                .padding(.bottom, 40)
            }
        }
        .task(id: "\(vpn.isConnected)-\(cfg.enabled)-\(cfg.effectivePort)") { await refresh() }
        .sheet(isPresented: $adding) { QXHTTPBackendEditor(item: nil) }
        .sheet(item: $editing) { it in QXHTTPBackendEditor(item: it) }
        .sheet(isPresented: $portSheet) { QXHTTPBackendPortSheet().presentationDetents([.height(280)]) }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
    }

    private var statusCard: some View {
        let running = status?.running == true
        let url = "http://127.0.0.1:\(status?.port ?? cfg.effectivePort)/"
        return HStack(spacing: 12) {
            Circle().fill(running ? QXColor.success : (cfg.enabled && vpn.isConnected ? QXColor.warning : Color.secondary.opacity(0.5)))
                .frame(width: 10, height: 10)
            VStack(alignment: .leading, spacing: 2) {
                Text(running ? LocalizedStringKey("正在运行") : (!cfg.enabled ? LocalizedStringKey("已关闭") : (vpn.isConnected ? LocalizedStringKey("未运行") : LocalizedStringKey("连接后运行"))))
                    .font(.system(size: 16, weight: .semibold))
                Text(verbatim: running ? url + " · " + String(localized: "\(status?.backends ?? 0) 个后端") : (status?.error?.isEmpty == false ? status!.error! : url))
                    .font(.system(size: 13).monospaced()).foregroundStyle(status?.error?.isEmpty == false ? QXColor.danger : .secondary).lineLimit(2)
            }
            Spacer(minLength: 6)
            if running, let u = URL(string: url) {
                Link(destination: u) {
                    Text("打开").font(.system(size: 15, weight: .semibold)).foregroundStyle(QXColor.switchOn)
                        .padding(.horizontal, 14).padding(.vertical, 5)
                        .background(Capsule().fill(QXPalette.cardHi))
                }
            }
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(QXPalette.card))
    }

    private func row(_ it: HTTPBackendItem) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Button {
                QXHaptics.toggle()
                QXHTTPBackendStore.update { c in
                    if let i = c.items.firstIndex(where: { $0.id == it.id }) { c.items[i].enabled.toggle() }
                }
                refreshSoon()
            } label: {
                Image(systemName: it.enabled ? "checkmark.square.fill" : "square")
                    .font(.system(size: 24, weight: .regular))
                    .foregroundStyle(it.enabled ? QXColor.switchOn : Color.secondary.opacity(0.5))
                    .frame(width: 30, height: 30)
            }
            .buttonStyle(QXPressStyle(scale: 0.88))
            .accessibilityLabel(Text(verbatim: it.tag))
            .accessibilityValue(Text(it.enabled ? LocalizedStringKey("已开启") : LocalizedStringKey("已关闭")))
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(verbatim: it.tag).font(.system(size: 18)).lineLimit(1)
                    Spacer()
                    if updatingID == it.id { ProgressView().controlSize(.small) }
                    else if it.script.hasPrefix("http"), !ScriptCache.isCached(it.script) {
                        Text("需要更新").font(.system(size: 14)).foregroundStyle(.secondary)
                    }
                }
                Text(verbatim: it.script).font(.system(size: 15)).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                HStack(spacing: 6) {
                    QXChip(text: "PATH", color: QXColor.rules)
                    Text(verbatim: it.path).font(.system(size: 13, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1)
                }
            }
        }
        .padding(.vertical, 12)
        .contentShape(Rectangle())
        .onTapGesture { editing = it }
        .contextMenu {
            Button { editing = it } label: { Label("编辑", systemImage: "square.and.pencil") }
            if it.script.hasPrefix("http") {
                Button { update(it) } label: { Label("更新脚本", systemImage: "arrow.clockwise") }
            }
            Button { UIPasteboard.general.string = it.line } label: { Label("拷贝", systemImage: "doc.on.doc") }
            Button(role: .destructive) {
                QXHTTPBackendStore.update { $0.items.removeAll { $0.id == it.id } }
            } label: { Label("删除", systemImage: "trash") }
        }
    }

    private func update(_ it: HTTPBackendItem) {
        updatingID = it.id
        Task {
            defer { updatingID = nil }
            if let e = await ScriptCache.download(it.script) { message = e } else { QXHaptics.success() }
            if vpn.isConnected { try? await ControllerClient.shared.mitmRefresh(url: it.script) }
        }
    }

    private func refreshSoon() {
        Task {
            try? await Task.sleep(nanoseconds: 1_500_000_000)
            await refresh()
        }
    }

    private func refresh() async {
        guard vpn.isConnected else { status = nil; return }
        status = try? await ControllerClient.shared.mitmHTTPBackend()
    }
}

/// Script cache shared with the engine (mitm CachePath = <engine home>/cache/<sha1>.js); the app fills it so
/// a backend works on the first request.
enum ScriptCache {
    static func isCached(_ url: String) -> Bool {
        let p = LibmihomoEngineCachePath(AppShared.homeURL.path, url)
        return !p.isEmpty && FileManager.default.fileExists(atPath: p)
    }

    static func download(_ url: String) async -> String? {
        guard let u = URL(string: url) else { return String(localized: "地址无效") }
        do {
            let (data, resp) = try await URLSession.shared.data(from: u)
            if let h = resp as? HTTPURLResponse, !(200..<300).contains(h.statusCode) { return String(localized: "下载失败：HTTP \(h.statusCode)") }
            guard !data.isEmpty else { return String(localized: "下载失败：内容为空") }
            let p = LibmihomoEngineCachePath(AppShared.homeURL.path, url)
            guard !p.isEmpty else { return String(localized: "下载失败") }
            let fu = URL(fileURLWithPath: p)
            try? FileManager.default.createDirectory(at: fu.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: fu, options: .atomic)
            return nil
        } catch { return error.localizedDescription }
    }
}

struct QXHTTPBackendEditor: View {
    let item: HTTPBackendItem?
    @Environment(\.dismiss) private var dismiss
    @State private var tag = ""
    @State private var script = ""
    @State private var path = "^/"
    @State private var img = ""
    @State private var enabled = true
    @State private var paste = ""
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                if item == nil {
                    Section {
                        TextField("粘贴 QX [http_backend] 行", text: $paste, axis: .vertical)
                            .font(.footnote.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled()
                            .onChange(of: paste) { t in
                                if let p = HTTPBackendItem.parse(t) {
                                    tag = p.tag; script = p.script; path = p.path; img = p.imgURL ?? ""; enabled = p.enabled
                                }
                            }
                    } footer: { Text("格式：脚本地址, tag=名称, path=路径正则, enabled=true") }
                }
                Section {
                    TextField("名称", text: $tag)
                    TextField("脚本地址（https://… 或脚本文件名）", text: $script)
                        .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                    TextField("路径正则，例如 ^/api/", text: $path)
                        .font(.body.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled()
                    TextField("图标地址（可选）", text: $img)
                        .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                    Toggle("启用", isOn: $enabled)
                } footer: {
                    if let error { Text(verbatim: error).foregroundStyle(QXColor.danger) }
                }
            }
            .scrollContentBackground(.hidden)
            .background(QXPalette.bg.ignoresSafeArea())
            .navigationTitle(item == nil ? LocalizedStringKey("添加后端") : LocalizedStringKey("编辑后端"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) { Button("保存") { save() }.disabled(script.isEmpty || path.isEmpty) }
            }
            .onAppear {
                if let it = item { tag = it.tag; script = it.script; path = it.path; img = it.imgURL ?? ""; enabled = it.enabled }
            }
        }
        .presentationDetents([.large])
    }

    private func save() {
        if (try? NSRegularExpression(pattern: path)) == nil { error = String(localized: "路径正则无效"); return }
        let s = script.trimmingCharacters(in: .whitespaces)
        var it = item ?? HTTPBackendItem(tag: "", script: s, path: path)
        it.tag = tag.isEmpty ? ((s.split(separator: "/").last.map(String.init) ?? s).replacingOccurrences(of: ".js", with: "")) : tag
        it.script = s
        it.path = path
        it.imgURL = img.isEmpty ? nil : img
        it.enabled = enabled
        QXHTTPBackendStore.update { c in
            if let i = c.items.firstIndex(where: { $0.id == it.id }) { c.items[i] = it } else { c.items.append(it) }
        }
        QXHaptics.success()
        if s.hasPrefix("http") { Task { _ = await ScriptCache.download(s) } }
        dismiss()
    }
}

struct QXHTTPBackendPortSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var port = ""
    @State private var invalid = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("9999", text: $port).keyboardType(.numberPad).font(.body.monospacedDigit())
                } header: { Text("监听端口（127.0.0.1）") } footer: {
                    Text(invalid ? LocalizedStringKey("端口无效") : LocalizedStringKey("默认 9999，与 Quantumult X 相同。只监听本机地址，其他设备无法访问。"))
                        .foregroundStyle(invalid ? QXColor.danger : .secondary)
                }
            }
            .scrollContentBackground(.hidden)
            .background(QXPalette.bg.ignoresSafeArea())
            .navigationTitle("HTTP Backend")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") {
                        let t = port.trimmingCharacters(in: .whitespaces)
                        if t.isEmpty { QXHTTPBackendStore.update { $0.port = nil }; dismiss(); return }
                        guard let p = Int(t), (1024...65535).contains(p) else { invalid = true; return }
                        QXHTTPBackendStore.update { $0.port = p == HTTPBackendConfig.defaultPort ? nil : p }
                        dismiss()
                    }
                }
            }
            .onAppear { port = String(QXHTTPBackendStore.config.effectivePort) }
        }
    }
}
