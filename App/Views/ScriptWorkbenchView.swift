import SwiftUI
import Libmihomo

// MARK: - Model

/// The sample a debug run executes against (edited in the 调试运行 panel; filled from a captured request).
struct ScriptDebugSample: Equatable {
    var type = "http-response"
    var url = "https://api.example.com/v1/feed"
    var method = "GET"
    var requestHeaders = "User-Agent: Mozilla/5.0\nAccept: application/json"
    var requestBody = ""
    var status = "200"
    var responseHeaders = "Content-Type: application/json"
    var responseBody = #"{"ad":true,"data":[1,2,3]}"#
    var argument = ""
    var useArgument = false
    var timeout = 10
    var binary = false

    static func headerText(_ h: [String: String]?) -> String {
        (h ?? [:]).sorted { $0.key.lowercased() < $1.key.lowercased() }.map { "\($0.key): \($0.value)" }.joined(separator: "\n")
    }

    static func headers(_ text: String) -> [String: String] {
        var out: [String: String] = [:]
        for line in text.components(separatedBy: .newlines) {
            guard let i = line.firstIndex(of: ":") else { continue }
            let k = line[..<i].trimmingCharacters(in: .whitespaces)
            let v = line[line.index(after: i)...].trimmingCharacters(in: .whitespaces)
            if !k.isEmpty { out[k] = v }
        }
        return out
    }

    /// Sample from a request captured by the engine (请求 → 详情 → 用此请求调试脚本).
    static func from(_ d: HTTPRequestDetail) -> ScriptDebugSample {
        var s = ScriptDebugSample()
        s.url = d.url
        s.method = d.method
        s.requestHeaders = headerText(d.reqHeaders)
        s.requestBody = d.reqBody ?? ""
        s.status = String(d.status > 0 ? d.status : 200)
        s.responseHeaders = headerText(d.respHeaders)
        s.responseBody = d.respBody ?? ""
        s.type = (d.respBody?.isEmpty == false || d.status > 0) ? "http-response" : "http-request"
        return s
    }
}

struct DebugHTTPPayload: Codable, Hashable {
    var url: String?
    var method: String?
    var status: Int?
    var headers: [String: String]?
    var body: String?
    var bodyBase64: Bool?
}

private struct DebugInputPayload: Encodable {
    var code: String
    var path: String?
    var name: String?
    var type: String
    var argument: String?
    var timeout: Int
    var binary: Bool
    var request: DebugHTTPPayload?
    var response: DebugHTTPPayload?
}

struct DebugOutput: Decodable {
    struct Log: Decodable, Hashable { var t: Int64; var level: String; var msg: String }
    var ok: Bool
    var error: String?
    var durationMs: Int64
    var done: Bool
    var doneJSON: String?
    var summary: [String]
    var result: DebugHTTPPayload?
    var mock: DebugHTTPPayload?
    var logs: [Log]
    var notifications: [[String: String]]
}

enum ScriptDebugger {
    /// Runs in the app process through the Go bridge (no tunnel needed).
    static func run(code: String, path: String?, name: String, sample s: ScriptDebugSample) async -> DebugOutput? {
        var input = DebugInputPayload(code: code, path: path, name: name, type: s.type,
                                      argument: s.useArgument ? s.argument : nil, timeout: s.timeout, binary: s.binary)
        if s.type == "http-request" || s.type == "http-response" {
            input.request = DebugHTTPPayload(url: s.url, method: s.method, headers: ScriptDebugSample.headers(s.requestHeaders), body: s.requestBody)
        }
        if s.type == "http-response" {
            input.response = DebugHTTPPayload(status: Int(s.status) ?? 200, headers: ScriptDebugSample.headers(s.responseHeaders), body: s.responseBody)
        }
        guard let data = try? JSONEncoder().encode(input), let json = String(data: data, encoding: .utf8) else { return nil }
        let home = AppShared.homeURL.path
        let out = await Task.detached(priority: .userInitiated) { LibmihomoScriptDebugRun(home, json) }.value
        guard let d = out.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(DebugOutput.self, from: d)
    }
}

// MARK: - Workbench

/// 脚本调试台: JS editor with highlighting + 调试运行 against a sample or a captured request.
struct ScriptWorkbenchView: View {
    enum Target: Hashable {
        case scratch
        case local(String)          // file in engine/scripts
        case item(EngineItem)       // a script line (local or remote script-path)
    }

    @ObservedObject var store = EngineStore.shared
    @State var target: Target
    @State var sample: ScriptDebugSample
    @State private var code = ""
    @State private var saved = ""
    @State private var path: String?
    @State private var remote = false
    @State private var loadError: String?
    @State private var showDebug = false
    @State private var saveAsName = ""
    @State private var askSaveAs = false
    @State private var note: String?

    init(target: Target, sample: ScriptDebugSample? = nil) {
        _target = State(initialValue: target)
        _sample = State(initialValue: sample ?? ScriptDebugSample())
    }

    static let scratchTemplate = """
    // 脚本调试台：编辑后点「调试运行」，用样本或抓到的请求执行一次。
    // $request / $response / $done 与线上一致；console.log 的输出会显示在结果里。
    let body = $response.body;
    try {
      const obj = JSON.parse(body);
      obj.ad = false;
      body = JSON.stringify(obj);
      console.log('modified');
    } catch (e) {
      console.log('not json: ' + e);
    }
    $done({ body });
    """

    var title: String {
        switch target {
        case .scratch: return String(localized: "脚本调试台")
        case .local(let n): return n
        case .item: return path.map { URL(string: $0)?.lastPathComponent ?? $0 } ?? String(localized: "脚本")
        }
    }

    var dirty: Bool { !remote && path != nil && code != saved }

    var body: some View {
        VStack(spacing: 0) {
            if let loadError {
                ErrorRow(message: loadError).padding(10)
            } else if remote {
                HStack(spacing: 6) {
                    Image(systemName: "icloud")
                    Text("远程脚本（缓存副本）只读；可在此调试，或另存为本地脚本后修改。")
                }
                .font(.caption).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 12).padding(.vertical, 8)
                .background(Theme.cardHi)
            }
            CodeEditor(text: $code, language: .javascript, editable: !remote)
            debugBar
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                pickerMenu
                if path != nil && !remote {
                    Button(dirty ? "保存" : "已保存") { save() }.disabled(!dirty)
                } else {
                    Button("另存为") { saveAsName = suggestedName(); askSaveAs = true }
                }
            }
        }
        .onAppear(perform: load)
        .sheet(isPresented: $showDebug) {
            ScriptDebugPanel(code: code, path: remote ? path : nil, name: title, sample: $sample)
                .presentationDetents([.medium, .large])
        }
        .alert("另存为本地脚本", isPresented: $askSaveAs) {
            TextField("文件名.js", text: $saveAsName).textInputAutocapitalization(.never).autocorrectionDisabled()
            Button("保存") { saveAs() }
            Button("取消", role: .cancel) {}
        }
        .alert("提示", isPresented: Binding(get: { note != nil }, set: { if !$0 { note = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(note ?? "") }
    }

    var debugBar: some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 1) {
                Text(LocalizedStringKey(Self.typeTitle(sample.type))).font(.caption.weight(.semibold))
                Text(sample.type.hasPrefix("http") ? sample.url : String(localized: "无请求上下文")).font(.caption2.monospaced()).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            Button { showDebug = true } label: {
                Label("调试运行", systemImage: "play.fill").font(.subheadline.weight(.semibold))
                    .padding(.horizontal, 14).padding(.vertical, 8)
                    .background(Capsule().fill(Theme.accent))
                    .foregroundStyle(.black)
            }
            .disabled(code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
        .background(Theme.card)
    }

    static func typeTitle(_ t: String) -> String {
        switch t {
        case "http-request": return "请求脚本（http-request）"
        case "http-response": return "响应脚本（http-response）"
        default: return "通用 / 定时脚本（generic / cron）"
        }
    }

    var pickerMenu: some View {
        Menu {
            Button { switchTo(.scratch) } label: { Label("空白脚本", systemImage: "doc") }
            let files = store.localScripts()
            if !files.isEmpty {
                Section("本地脚本") {
                    ForEach(files, id: \.self) { f in Button(f) { switchTo(.local(f)) } }
                }
            }
            let items = store.config.scripts
            if !items.isEmpty {
                Section("脚本行") {
                    ForEach(items) { it in
                        Button(Self.scriptInfo(it.line).name) { switchTo(.item(it)) }
                    }
                }
            }
        } label: { Image(systemName: "doc.text.magnifyingglass") }
        .accessibilityLabel(Text("选择脚本"))
    }

    /// name / path / type of a script line, through the engine parser.
    static func scriptInfo(_ line: String) -> (name: String, path: String?, type: String?) {
        guard let p = ParsedEngineText.parse(LibmihomoEngineParseLine(line, "script")) else { return (line, nil, nil) }
        if let r = p.rules.first(where: { $0.kind == "script" }) {
            return (r.script ?? r.path ?? line, r.path, r.phase == "request" ? "http-request" : "http-response")
        }
        if let t = p.tasks?.first { return (t.name, t.path, "generic") }
        return (line, nil, nil)
    }

    func switchTo(_ t: Target) {
        if dirty { save() }
        target = t
        load()
    }

    func load() {
        loadError = nil; remote = false; path = nil
        switch target {
        case .scratch:
            if code.isEmpty { code = Self.scratchTemplate }
            saved = code
        case .local(let name):
            path = name
            code = store.readScript(name); saved = code
        case .item(let it):
            let info = Self.scriptInfo(it.line)
            if let t = info.type { sample.type = t }
            guard let p = info.path else { loadError = String(localized: "无法从这一行解析出 script-path"); return }
            path = p
            if p.hasPrefix("http://") || p.hasPrefix("https://") {
                remote = true
                let home = AppShared.homeURL.path
                code = String(localized: "// 正在读取…")
                Task {
                    let src = await Task.detached { (LibmihomoScriptSource(home, p), LibmihomoLastError()) }.value
                    if src.0.isEmpty { loadError = String(localized: "读取远程脚本失败：\(src.1)"); code = "" } else { code = src.0 }
                    saved = code
                }
            } else {
                code = store.readScript(p); saved = code
            }
        }
    }

    func save() {
        guard let p = path, !remote else { return }
        store.writeScript(p, code)
        saved = code
    }

    func suggestedName() -> String {
        if let p = path { return EnginePaths.safe(URL(string: p)?.lastPathComponent ?? p) }
        return "script.js"
    }

    func saveAs() {
        var n = EnginePaths.safe(saveAsName.trimmingCharacters(in: .whitespaces))
        if n.isEmpty { return }
        if !n.hasSuffix(".js") { n += ".js" }
        store.writeScript(n, code)
        note = String(localized: "已保存为本地脚本 \(n)。在脚本行里把 script-path 改成 \(n) 即可使用。")
        target = .local(n)
        path = n; remote = false; saved = code
    }
}

// MARK: - Debug panel

struct ScriptDebugPanel: View {
    let code: String
    let path: String?
    let name: String
    @Binding var sample: ScriptDebugSample
    var body: some View {
        NavigationStack {
            ScriptDebugForm(code: code, path: path, name: name, sample: $sample)
                .navigationTitle("调试运行")
                .navigationBarTitleDisplayMode(.inline)
        }
    }
}

/// The run settings, sample and results (sheet from the workbench, or pushed from the script form).
struct ScriptDebugForm: View {
    let code: String
    let path: String?
    let name: String
    @Binding var sample: ScriptDebugSample
    @State private var running = false
    @State private var out: DebugOutput?
    @State private var showSample = true

    var isHTTP: Bool { sample.type == "http-request" || sample.type == "http-response" }

    var body: some View {
            Form {
                Section {
                    Picker("脚本类型", selection: $sample.type) {
                        Text("请求（http-request）").tag("http-request")
                        Text("响应（http-response）").tag("http-response")
                        Text("通用 / 定时（generic）").tag("generic")
                    }
                    Button(action: run) {
                        HStack {
                            if running { ProgressView().controlSize(.small) } else { Image(systemName: "play.fill") }
                            Text(running ? "运行中…" : "运行").bold()
                            Spacer()
                            if let out { Text("\(out.durationMs) ms").font(.caption.monospacedDigit()).foregroundStyle(.secondary) }
                        }
                    }
                    .disabled(running)
                } footer: {
                    Text("在本机执行一次，环境与线上相同（$httpClient 直接联网，$persistentStore 是真实存储）。通知只显示在这里，不会弹出。")
                }
                .listRowBackground(Theme.card)

                if let out { results(out) }

                Section {
                    DisclosureGroup(isExpanded: $showSample) {
                        sampleFields
                    } label: { Text("样本").font(.subheadline.weight(.semibold)) }
                }
                .listRowBackground(Theme.card)
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
    }

    @ViewBuilder
    var sampleFields: some View {
        if isHTTP {
            TextField("URL", text: $sample.url).font(.footnote.monospaced())
                .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
            Picker("方法", selection: $sample.method) {
                ForEach(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"], id: \.self) { Text($0).tag($0) }
                if !["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].contains(sample.method) { Text(sample.method).tag(sample.method) }
            }
            labeledEditor("请求头（每行 名称: 值）", $sample.requestHeaders, 60)
            if sample.type == "http-request" || !sample.requestBody.isEmpty {
                labeledEditor("请求体", $sample.requestBody, 60)
            }
            if sample.type == "http-response" {
                HStack { Text("状态码"); TextField("200", text: $sample.status).keyboardType(.numberPad).multilineTextAlignment(.trailing) }
                labeledEditor("响应头（每行 名称: 值）", $sample.responseHeaders, 60)
                labeledEditor("响应体", $sample.responseBody, 100)
            }
        }
        Toggle("传入 $argument", isOn: $sample.useArgument)
        if sample.useArgument {
            TextField("argument", text: $sample.argument).font(.footnote.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled()
        }
        Toggle("binary-body-mode", isOn: $sample.binary)
        Stepper(value: $sample.timeout, in: 1...60) { HStack { Text("超时"); Spacer(); Text("\(sample.timeout) 秒").monospacedDigit().foregroundStyle(.secondary) } }
    }

    func labeledEditor(_ title: String, _ text: Binding<String>, _ h: CGFloat) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(LocalizedStringKey(title)).font(.caption2).foregroundStyle(.secondary)
            TextEditor(text: text)
                .scaledFont(11, design: .monospaced)
                .frame(minHeight: h)
                .textInputAutocapitalization(.never).autocorrectionDisabled()
        }
    }

    @ViewBuilder
    func results(_ o: DebugOutput) -> some View {
        Section {
            HStack(spacing: 8) {
                Image(systemName: o.ok ? "checkmark.circle.fill" : "xmark.octagon.fill").foregroundStyle(o.ok ? Theme.good : Theme.bad)
                Text(o.ok ? (o.done ? "成功 · 已调用 $done" : "成功 · 未调用 $done") : "出错").font(.subheadline.weight(.semibold))
                Spacer()
                Text("\(o.durationMs) ms").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
            }
            if let e = o.error { Text(e).font(.caption.monospaced()).foregroundStyle(Theme.bad).textSelection(.enabled) }
            ForEach(o.summary, id: \.self) { Text($0).font(.caption) }
        } header: { Text("结果") }
        .listRowBackground(Theme.card)

        Section {
            if o.logs.isEmpty {
                Text("没有输出").font(.caption).foregroundStyle(.secondary)
            }
            ForEach(Array(o.logs.enumerated()), id: \.offset) { _, l in
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text("+\(l.t)ms").scaledFont(9, monospacedDigit: true).foregroundStyle(.secondary)
                    Text(l.msg).scaledFont(11, design: .monospaced).foregroundStyle(logColor(l.level)).textSelection(.enabled)
                }
            }
            if !o.logs.isEmpty {
                Button { UIPasteboard.general.string = o.logs.map { "[\($0.level)] \($0.msg)" }.joined(separator: "\n") } label: {
                    Label("复制输出", systemImage: "doc.on.doc")
                }
            }
        } header: { Text("控制台 \(o.logs.count)") }
        .listRowBackground(Theme.card)

        if !o.notifications.isEmpty {
            Section("通知 \(o.notifications.count)") {
                ForEach(Array(o.notifications.enumerated()), id: \.offset) { _, n in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(n["title"] ?? "").font(.caption.weight(.semibold))
                        if let s = n["subtitle"], !s.isEmpty { Text(s).font(.caption2) }
                        if let b = n["body"], !b.isEmpty { Text(b).font(.caption2).foregroundStyle(.secondary) }
                    }
                }
            }
            .listRowBackground(Theme.card)
        }

        if let j = o.doneJSON, o.done {
            Section("$done 参数") {
                Text(j).scaledFont(11, design: .monospaced).textSelection(.enabled)
            }
            .listRowBackground(Theme.card)
        }

        if let m = o.mock { httpSection("本地应答", m) }
        if let r = o.result { httpSection(sample.type == "http-request" ? "修改后的请求" : "修改后的响应", r) }
    }

    func httpSection(_ title: String, _ h: DebugHTTPPayload) -> some View {
        Section(LocalizedStringKey(title)) {
            if let u = h.url, !u.isEmpty { Text("\(h.method ?? "") \(u)").scaledFont(11, design: .monospaced).textSelection(.enabled) }
            if let s = h.status, s > 0 { LabeledContent("状态码", value: String(s)) }
            if let hs = h.headers, !hs.isEmpty {
                Text(ScriptDebugSample.headerText(hs)).scaledFont(10, design: .monospaced).foregroundStyle(.secondary).textSelection(.enabled)
            }
            if let b = h.body, !b.isEmpty {
                if h.bodyBase64 == true {
                    Text("二进制内容（base64，\(b.count) 字符）").font(.caption).foregroundStyle(.secondary)
                } else {
                    Text(HTTPRequestDetailView.pretty(String(b.prefix(20_000)))).scaledFont(11, design: .monospaced).textSelection(.enabled)
                }
                Button { UIPasteboard.general.string = b } label: { Label("复制内容", systemImage: "doc.on.doc") }
            }
        }
        .listRowBackground(Theme.card)
    }

    func logColor(_ l: String) -> Color {
        switch l {
        case "error": return Theme.bad
        case "warn", "warning": return Theme.warn
        case "debug": return .secondary
        default: return .primary
        }
    }

    func run() {
        running = true
        let c = code, p = path, n = name, s = sample
        Task {
            let r = await ScriptDebugger.run(code: p == nil ? c : "", path: p, name: n, sample: s)
            running = false
            out = r ?? DebugOutput(ok: false, error: String(localized: "调试结果无法解析"), durationMs: 0, done: false, doneJSON: nil, summary: [], result: nil, mock: nil, logs: [], notifications: [])
            showSample = false
        }
    }
}
