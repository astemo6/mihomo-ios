import SwiftUI
import Libmihomo

/// Form model shared with the Go side (mitm.RewriteForm): one form <-> one canonical Surge-syntax line.
struct RewriteForm: Codable, Equatable {
    var type: String = "reject"
    var pattern: String = ""
    var phase: String? = "request"
    var action: String? = "reject"
    var target: String? = nil
    var headerOp: String? = "add"
    var headerName: String? = nil
    var headerValue: String? = nil
    var headerRegex: String? = nil
    var regex: String? = nil
    var replacement: String? = nil
    var data: String? = nil
    var dataType: String? = "text"
    var status: Int? = nil
    var contentType: String? = nil
    var headers: String? = nil
    var line: String? = nil
    var error: String? = nil
    var desc: String? = nil

    static func fromLine(_ line: String) -> RewriteForm {
        guard let d = LibmihomoRewriteFormFromLine(line).data(using: .utf8),
              let f = try? JSONDecoder().decode(RewriteForm.self, from: d) else { return RewriteForm(type: "raw", line: line) }
        return f
    }

    /// Canonical line + validation through the engine parser.
    func validated() -> RewriteForm {
        guard let d = try? JSONEncoder().encode(self), let json = String(data: d, encoding: .utf8),
              let out = LibmihomoRewriteLineFromForm(json).data(using: .utf8),
              let f = try? JSONDecoder().decode(RewriteForm.self, from: out) else { return self }
        return f
    }
}

/// 本地模块: the user's own rewrite rules and MitM hostnames (engine.json `rules` / `hostnames`, the same
/// store the engine reads), edited through forms or as text. Shown pinned at the top of 模块与资源 and
/// opened from 更多 → 重写.
struct LocalModuleView: View {
    @ObservedObject var store = EngineStore.shared
    @State private var editing: EditTarget?
    @State private var rawMode = false
    @State private var rawText = ""
    @State private var rawIssues: [String] = []
    @State private var search = ""
    @State private var newHost = ""

    struct EditTarget: Identifiable {
        let id = UUID()
        let item: EngineItem?
        let type: String
        var phase: String = "request"
    }

    var items: [EngineItem] {
        guard !search.isEmpty else { return store.config.rules }
        return store.config.rules.filter { $0.line.localizedCaseInsensitiveContains(search) || ($0.note ?? "").localizedCaseInsensitiveContains(search) }
    }

    var body: some View {
        Group {
            if rawMode { rawEditor } else { formList }
        }
        .toolbar {
            if rawMode {
                ToolbarItem(placement: .navigationBarLeading) { Button("放弃修改") { rawMode = false; rawIssues = [] } }
            }
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("本地模块")
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                Button {
                    if rawMode { applyRaw() } else { rawText = Self.text(store.config); rawIssues = []; rawMode = true }
                } label: { Text(rawMode ? "完成" : "文本") }
                if !rawMode {
                    EditButton()
                    addMenu
                }
            }
        }
        .sheet(item: $editing) { t in RewriteRuleEditor(target: t) }
    }

    var addMenu: some View {
        Menu {
            Button { editing = EditTarget(item: nil, type: "reject") } label: { Label("拒绝请求（reject）", systemImage: "nosign") }
            Button { editing = EditTarget(item: nil, type: "redirect") } label: { Label("重定向（302 / 307）", systemImage: "arrowshape.turn.up.right") }
            Button { editing = EditTarget(item: nil, type: "header", phase: "request") } label: { Label("修改请求头", systemImage: "list.bullet.indent") }
            Button { editing = EditTarget(item: nil, type: "header", phase: "response") } label: { Label("修改响应头", systemImage: "list.bullet.indent") }
            Button { editing = EditTarget(item: nil, type: "body", phase: "response") } label: { Label("正则替换响应体", systemImage: "text.magnifyingglass") }
            Button { editing = EditTarget(item: nil, type: "body", phase: "request") } label: { Label("正则替换请求体", systemImage: "text.magnifyingglass") }
            Button { editing = EditTarget(item: nil, type: "maplocal") } label: { Label("本地映射（Map Local）", systemImage: "doc.richtext") }
            Divider()
            Button { editing = EditTarget(item: nil, type: "raw") } label: { Label("粘贴规则文本", systemImage: "doc.on.clipboard") }
        } label: { Image(systemName: "plus") }
        .accessibilityIdentifier("localmodule.add")
    }

    var formList: some View {
        List {
            Section {
                Toggle(isOn: Binding(get: { store.config.enabled }, set: { store.config.enabled = $0; store.save() })) {
                    Label("启用重写与脚本", systemImage: "arrow.triangle.swap")
                }
                NavigationLink { AllRewritesView() } label: {
                    Label("全部重写规则（含模块）", systemImage: "list.bullet.rectangle.portrait")
                }
                .accessibilityIdentifier("localmodule.allRewrites")
            } footer: {
                VStack(alignment: .leading, spacing: 4) {
                    Text("本地模块是你自己的重写规则和 MitM 主机名，与导入的模块一起生效、优先于它们。点 + 用表单添加，或点「文本」直接编辑；Surge、Quantumult X、Loon 写法都能识别。")
                    EngineSwitchFooter()
                }
            }
            .listRowBackground(Theme.card)

            Section {
                if store.config.rules.isEmpty {
                    EmptyStateRow(icon: "arrow.triangle.swap", title: "还没有重写规则", message: "点右上角 + 选择类型。")
                }
                ForEach(items) { it in
                    RuleRow(item: it) { on in
                        if let i = store.config.rules.firstIndex(where: { $0.id == it.id }) { store.config.rules[i].enabled = on; store.save() }
                    }
                    .contentShape(Rectangle())
                    .onTapGesture { editing = EditTarget(item: it, type: "") }
                }
                .onDelete { idx in
                    let ids = idx.map { items[$0].id }
                    store.config.rules.removeAll { ids.contains($0.id) }
                    store.save()
                }
                .onMove { from, to in
                    guard search.isEmpty else { return }
                    store.config.rules.move(fromOffsets: from, toOffset: to); store.save()
                }
            } header: { Text("重写 \(store.config.rules.count)") } footer: {
                if store.config.rules.count > 1 { Text("按顺序匹配，拖动调整先后（点右上角「编辑」）。") }
            }
            .listRowBackground(Theme.card)

            Section {
                ForEach(store.config.hostnames, id: \.self) { h in
                    HStack {
                        Text(h).font(.system(.callout, design: .monospaced))
                        Spacer()
                        if h.hasPrefix("-") { Text("排除").font(.caption2).foregroundStyle(.secondary) }
                    }
                }
                .onDelete { idx in store.config.hostnames.remove(atOffsets: idx); store.save() }
                .onMove { from, to in store.config.hostnames.move(fromOffsets: from, toOffset: to); store.save() }
                HStack {
                    TextField("example.com、*.example.com、-排除.com", text: $newHost)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .font(.system(.callout, design: .monospaced))
                        .onSubmit(addHost)
                    Button("添加", action: addHost).disabled(newHost.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            } header: { Text("MitM 主机名 \(store.config.hostnames.count)") } footer: {
                Text("HTTPS 重写需要解密对应主机：在 MitM 页开启解密并信任证书。支持 * 和 ? 通配、前缀 - 表示排除、:端口（默认 443）。")
            }
            .listRowBackground(Theme.card)

            Section("语法速查") { SyntaxHelp() }
                .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .searchable(text: $search, placement: .navigationBarDrawer(displayMode: .always), prompt: "搜索规则")
    }

    var rawEditor: some View {
        VStack(spacing: 0) {
            if !rawIssues.isEmpty {
                VStack(alignment: .leading, spacing: 3) {
                    ForEach(rawIssues.prefix(6), id: \.self) { Text($0.hasPrefix("!") ? String($0.dropFirst()) : $0).font(.caption2) }
                    if rawIssues.count > 6 { Text("…还有 \(rawIssues.count - 6) 条").font(.caption2) }
                }
                .foregroundStyle(Theme.bad)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
                .background(Theme.bad.opacity(0.12))
            }
            CodeEditor(text: $rawText, language: .conf)
            Text("每行一条规则；hostname = 行是 MitM 主机名；以 #off 开头的行是停用的规则。点「完成」校验并保存。")
                .font(.caption2).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
                .background(Theme.card)
        }
        .onChange(of: rawText) { _ in rawIssues = [] }
    }

    func addHost() {
        let hosts = newHost.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces).lowercased() }.filter { !$0.isEmpty }
        for h in hosts where !store.config.hostnames.contains(h) { store.config.hostnames.append(h) }
        newHost = ""
        store.save()
    }

    // MARK: text <-> store

    static func text(_ c: EngineConfig) -> String {
        var out = ["# 本地模块"]
        if !c.hostnames.isEmpty { out.append("hostname = " + c.hostnames.joined(separator: ", ")) }
        for r in c.rules {
            if let n = r.note, !n.isEmpty { out.append("# " + n.replacingOccurrences(of: "\n", with: " ")) }
            out.append((r.enabled ? "" : "#off ") + r.line)
        }
        return out.joined(separator: "\n") + "\n"
    }

    /// Parses the text back; validation through the engine (EngineParseText). Errors block saving.
    func applyRaw() {
        var hosts: [String] = []
        var rules: [EngineItem] = []
        var scripts: [EngineItem] = []
        var pendingNote: String?
        var issues: [String] = []
        let old = store.config.rules
        var used = Set<String>()
        for raw in rawText.components(separatedBy: .newlines) {
            var line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty { pendingNote = nil; continue }
            var enabled = true
            if line.lowercased().hasPrefix("#off ") {
                enabled = false
                line = String(line.dropFirst(5)).trimmingCharacters(in: .whitespaces)
            } else if line.hasPrefix("#") || line.hasPrefix(";") || line.hasPrefix("//") {
                let n = line.drop(while: { "#;/ ".contains($0) }).trimmingCharacters(in: .whitespaces)
                if n != "本地模块" && !n.isEmpty { pendingNote = n }
                continue
            } else if line.hasPrefix("[") {
                continue
            }
            if line.lowercased().hasPrefix("hostname"), let eq = line.firstIndex(of: "=") {
                for h in line[line.index(after: eq)...].split(separator: ",") {
                    let v = h.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: "%APPEND%", with: "").replacingOccurrences(of: "%INSERT%", with: "").trimmingCharacters(in: .whitespaces)
                    if !v.isEmpty && !hosts.contains(v) { hosts.append(v) }
                }
                continue
            }
            let d = EngineStore.describe(line)
            if let e = d.error { issues.append("!" + e + "：" + String(line.prefix(80))) }
            // Keep id / note of an unchanged line.
            var item = EngineItem(enabled: enabled, line: line, note: pendingNote)
            if let o = old.first(where: { $0.line == line && !used.contains($0.id) }) {
                item.id = o.id
                if item.note == nil { item.note = o.note }
                used.insert(o.id)
            }
            pendingNote = nil
            if d.kind == "script" { scripts.append(item) } else { rules.append(item) }
        }
        if !issues.isEmpty { rawIssues = issues; return }
        store.config.rules = rules
        store.config.hostnames = hosts
        if !scripts.isEmpty { store.config.scripts.append(contentsOf: scripts) }
        store.save()
        rawMode = false
    }
}

/// Form editor for one rewrite rule; validation through the Go parsers.
struct RewriteRuleEditor: View {
    @Environment(\.dismiss) var dismiss
    @ObservedObject var store = EngineStore.shared
    let target: LocalModuleView.EditTarget
    @State private var form = RewriteForm()
    @State private var checked = RewriteForm()
    @State private var note = ""
    @State private var loaded = false

    static let rejectActions: [(String, String)] = [
        ("reject", "reject（断开，返回 404）"), ("reject-200", "reject-200（空 200）"), ("reject-img", "reject-img（1×1 GIF）"),
        ("reject-dict", "reject-dict（空 JSON 对象 {}）"), ("reject-array", "reject-array（空 JSON 数组 []）"), ("reject-drop", "reject-drop（直接丢弃）"),
    ]

    var title: String {
        switch form.type {
        case "reject": return "拒绝请求"
        case "redirect": return "重定向"
        case "header": return form.phase == "response" ? "修改响应头" : "修改请求头"
        case "body": return form.phase == "response" ? "正则替换响应体" : "正则替换请求体"
        case "maplocal": return "本地映射"
        default: return "规则文本"
        }
    }

    var body: some View {
        NavigationStack {
            Form {
                if form.type != "raw" {
                    Section {
                        TextField("^https?://api\\.example\\.com/v1/ad", text: $form.pattern, axis: .vertical)
                            .font(.footnote.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled()
                    } header: { Text("URL 正则") } footer: { Text("匹配完整 URL（含 https://），JavaScript 正则语法。") }
                    .listRowBackground(Theme.card)
                }
                fields
                Section("备注") { TextField("可选", text: $note) }.listRowBackground(Theme.card)
                Section {
                    if let e = checked.error {
                        Label(e, systemImage: "exclamationmark.triangle.fill").font(.caption).foregroundStyle(Theme.bad)
                    } else if let d = checked.desc {
                        Label(GoText.localize(d), systemImage: "checkmark.circle.fill").font(.caption).foregroundStyle(Theme.good)
                    }
                    if form.type != "raw", let l = checked.line, !l.isEmpty {
                        Text(l).scaledFont(10, design: .monospaced).foregroundStyle(.secondary).textSelection(.enabled)
                    }
                } header: { Text("校验") }
                .listRowBackground(Theme.card)
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle(LocalizedStringKey(title))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") { save(); dismiss() }.disabled(checked.error != nil || (checked.line ?? "").isEmpty)
                }
            }
            .onAppear(perform: load)
            .onChange(of: form) { _ in checked = form.validated() }
        }
    }

    @ViewBuilder
    var fields: some View {
        switch form.type {
        case "reject":
            Section("动作") {
                Picker("动作", selection: Binding(get: { form.action ?? "reject" }, set: { form.action = $0 })) {
                    ForEach(Self.rejectActions, id: \.0) { Text(LocalizedStringKey($0.1)).tag($0.0) }
                }
                .pickerStyle(.inline).labelsHidden()
            }
            .listRowBackground(Theme.card)
        case "redirect":
            Section {
                Picker("状态码", selection: Binding(get: { form.action == "307" ? "307" : "302" }, set: { form.action = $0 })) {
                    Text("302 临时跳转").tag("302")
                    Text("307 保留方法和请求体").tag("307")
                }
                .pickerStyle(.segmented)
                TextField("https://new.example.com/$1", text: opt(\.target))
                    .font(.footnote.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
            } header: { Text("跳转到") } footer: { Text("可用 $1、$2 引用 URL 正则里的分组。") }
            .listRowBackground(Theme.card)
        case "header":
            Section {
                Picker("阶段", selection: Binding(get: { form.phase ?? "request" }, set: { form.phase = $0 })) {
                    Text("请求").tag("request")
                    Text("响应").tag("response")
                }
                .pickerStyle(.segmented)
                Picker("操作", selection: Binding(get: { form.headerOp ?? "add" }, set: { form.headerOp = $0 })) {
                    Text("添加").tag("add")
                    Text("替换").tag("replace")
                    Text("删除").tag("del")
                    Text("正则替换").tag("replace-regex")
                }
                TextField("头名，如 User-Agent", text: opt(\.headerName)).textInputAutocapitalization(.never).autocorrectionDisabled()
                if form.headerOp == "replace-regex" {
                    TextField("要替换的正则", text: opt(\.headerRegex)).font(.footnote.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled()
                }
                if form.headerOp != "del" {
                    TextField("值", text: opt(\.headerValue)).textInputAutocapitalization(.never).autocorrectionDisabled()
                }
            } header: { Text("头部") } footer: { Text("添加会追加一个同名头；替换只改已有的头（没有则不加）。") }
            .listRowBackground(Theme.card)
        case "body":
            Section {
                Picker("阶段", selection: Binding(get: { form.phase ?? "response" }, set: { form.phase = $0 })) {
                    Text("请求体").tag("request")
                    Text("响应体").tag("response")
                }
                .pickerStyle(.segmented)
                TextField("正则，如 \"ad\":\\s?true", text: opt(\.regex), axis: .vertical).font(.footnote.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled()
                TextField("替换为（可用 $1）", text: opt(\.replacement), axis: .vertical).font(.footnote.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled()
            } header: { Text("替换") } footer: { Text("对整个内容做正则替换（自动解压 gzip / br），最大 2 MB。") }
            .listRowBackground(Theme.card)
        case "maplocal":
            Section {
                Picker("内容类型", selection: Binding(get: { form.dataType ?? "text" }, set: { form.dataType = $0 })) {
                    Text("文本").tag("text")
                    Text("Base64").tag("base64")
                    Text("文件 / URL").tag("file")
                    Text("1×1 GIF").tag("tiny-gif")
                }
                if form.dataType != "tiny-gif" {
                    TextField(form.dataType == "file" ? "本地脚本目录里的文件名或 https://…" : "{\"ok\":true}", text: opt(\.data), axis: .vertical)
                        .font(.footnote.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled()
                }
                TextField("Content-Type，如 application/json", text: opt(\.contentType)).textInputAutocapitalization(.never).autocorrectionDisabled()
                HStack {
                    Text("状态码")
                    TextField("200", text: Binding(get: { form.status.map(String.init) ?? "" }, set: { form.status = Int($0) }))
                        .keyboardType(.numberPad).multilineTextAlignment(.trailing)
                }
                TextField("其他响应头：A:1|B:2", text: opt(\.headers)).font(.footnote.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled()
            } header: { Text("返回内容") } footer: { Text("命中后直接由本机应答，不会请求服务器。") }
            .listRowBackground(Theme.card)
        default:
            Section {
                TextField("规则", text: opt(\.line), axis: .vertical)
                    .font(.footnote.monospaced()).textInputAutocapitalization(.never).autocorrectionDisabled()
                    .lineLimit(3...10)
                if target.item == nil {
                    Button { form.line = UIPasteboard.general.string ?? "" } label: { Label("粘贴", systemImage: "doc.on.clipboard") } // clipboard-read: explicit 粘贴 tap only (see ClipboardRuleTests)
                }
            } header: { Text("规则文本") } footer: {
                Text(target.item == nil ? "一条 Surge / Quantumult X / Loon 重写行。多行请用「文本」模式。" : "这条规则的写法没有对应的表单（例如 JSON 操作或 jq），可以直接编辑文本。")
            }
            .listRowBackground(Theme.card)
        }
    }

    func opt(_ kp: WritableKeyPath<RewriteForm, String?>) -> Binding<String> {
        Binding(get: { form[keyPath: kp] ?? "" }, set: { form[keyPath: kp] = $0 })
    }

    func load() {
        guard !loaded else { return }
        loaded = true
        if let it = target.item {
            form = RewriteForm.fromLine(it.line)
            note = it.note ?? ""
        } else {
            form = RewriteForm(type: target.type, phase: target.phase)
            if target.type == "redirect" { form.action = "302" }
            if target.type == "body" { form.regex = ""; form.replacement = "" }
        }
        checked = form.validated()
    }

    func save() {
        guard checked.error == nil, let line = checked.line, !line.isEmpty else { return }
        let n = note.trimmingCharacters(in: .whitespaces)
        if let it = target.item, let i = store.config.rules.firstIndex(where: { $0.id == it.id }) {
            store.config.rules[i].line = line
            store.config.rules[i].note = n.isEmpty ? nil : n
        } else {
            store.config.rules.append(EngineItem(line: line, note: n.isEmpty ? nil : n))
            if !store.config.enabled { store.config.enabled = true }
        }
        store.save()
    }
}
