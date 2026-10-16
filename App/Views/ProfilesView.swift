import SwiftUI
import UniformTypeIdentifiers

struct ProfilesView: View {
    @EnvironmentObject var store: ProfileStore
    @State private var showAddRemote = false
    @State private var showNewLocal = false
    @State private var showImporter = false
    @State private var message: String?
    @State private var busy = false
    @State private var editing: Profile?
    @State private var showManual = false

    var body: some View {
        NavigationStack {
            List {
                if store.profiles.isEmpty {
                    Section {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("还没有配置").font(.headline)
                            Text("点右上角 + 添加订阅链接，或从文件 / 剪贴板导入 mihomo（Clash Meta）YAML 配置。也支持 ss/vmess/vless/trojan/hysteria2/tuic 分享链接列表。")
                                .font(.footnote).foregroundStyle(.secondary)
                        }
                        .padding(.vertical, 6)
                    }
                    .listRowBackground(Theme.card)
                }
                Section {
                    NavigationLink { ManualNodesView() } label: {
                        Label("手动节点（粘贴链接 / 扫码 / 手动填写）", systemImage: "plus.viewfinder")
                    }
                }
                .listRowBackground(Theme.card)
                Section {
                    ForEach(store.profiles) { p in
                        ProfileRow(profile: p, active: p.id == store.activeID, updating: store.updating.contains(p.id))
                            .contentShape(Rectangle())
                            .onTapGesture { select(p) }
                            .swipeActions(edge: .trailing) {
                                Button(role: .destructive) { store.delete(p) } label: { Label("删除", systemImage: "trash") }
                                Button { editing = p } label: { Label("编辑", systemImage: "pencil") }.tint(.indigo)
                            }
                            .swipeActions(edge: .leading) {
                                if p.kind == .remote {
                                    Button { refresh(p) } label: { Label("更新", systemImage: "arrow.clockwise") }.tint(.blue)
                                }
                            }
                            .contextMenu {
                                Button { select(p) } label: { Label("设为当前配置", systemImage: "checkmark.circle") }
                                if p.kind == .remote {
                                    Button { refresh(p) } label: { Label("更新订阅", systemImage: "arrow.clockwise") }
                                    Button { UIPasteboard.general.string = p.url } label: { Label("复制订阅链接", systemImage: "doc.on.doc") }
                                }
                                Button { editing = p } label: { Label("编辑 YAML", systemImage: "pencil") }
                                Button(role: .destructive) { store.delete(p) } label: { Label("删除", systemImage: "trash") }
                            }
                            .listRowBackground(Theme.card)
                    }
                } footer: {
                    if !store.profiles.isEmpty { Text("轻点切换当前配置；左滑编辑或删除，右滑更新订阅。") }
                }
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("配置")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button { updateAll() } label: { Label("全部更新", systemImage: "arrow.triangle.2.circlepath") }
                        .disabled(busy || !store.profiles.contains { $0.kind == .remote })
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Menu {
                        Button { showAddRemote = true } label: { Label("添加订阅链接", systemImage: "link.badge.plus") }
                        Button { importClipboard() } label: { Label("从剪贴板导入", systemImage: "doc.on.clipboard") }
                        Button { showImporter = true } label: { Label("从文件导入", systemImage: "folder") }
                        Button { showNewLocal = true } label: { Label("新建本地配置", systemImage: "square.and.pencil") }
                        Button { showManual = true } label: { Label("添加单个节点", systemImage: "plus.viewfinder") }
                    } label: { Image(systemName: "plus.circle.fill").font(.title3) }
                }
            }
            .navigationDestination(isPresented: $showManual) { ManualNodesView() }
            .overlay { if busy { ProgressView().padding(20).background(RoundedRectangle(cornerRadius: 12).fill(Theme.cardHi)) } }
            .sheet(isPresented: $showAddRemote) { AddRemoteSheet { msg in message = msg } }
            .sheet(isPresented: $showNewLocal) {
                YAMLEditorView(title: "新建本地配置", initialName: "本地配置", initialText: YAMLEditorView.template, profile: nil)
            }
            .sheet(item: $editing) { p in
                YAMLEditorView(title: "编辑配置", initialName: p.name, initialText: store.content(of: p), profile: p)
            }
            .fileImporter(isPresented: $showImporter, allowedContentTypes: [UTType(filenameExtension: "yaml") ?? .plainText, UTType(filenameExtension: "yml") ?? .plainText, .plainText, .text, .data]) { result in
                importFile(result)
            }
            .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
                Button("好", role: .cancel) {}
            } message: { Text(message ?? "") }
        }
    }

    func select(_ p: Profile) {
        Task {
            if let err = await store.setActive(p) { message = "已切换，但重载失败：\(err)" }
        }
    }

    func refresh(_ p: Profile) {
        Task { if let e = await store.refresh(p) { message = e } }
    }

    func updateAll() {
        busy = true
        Task {
            let errs = await store.refreshAll()
            busy = false
            message = errs.isEmpty ? "全部订阅已更新" : errs.joined(separator: "\n")
        }
    }

    func importClipboard() {
        guard let s = UIPasteboard.general.string?.trimmingCharacters(in: .whitespacesAndNewlines), !s.isEmpty else {
            message = "剪贴板为空"; return
        }
        busy = true
        Task {
            defer { busy = false }
            do {
                if (s.hasPrefix("http://") || s.hasPrefix("https://")) && !s.contains("\n") && !s.contains("@") {
                    _ = try await store.addRemote(url: s, name: "", userAgent: "clash.meta", intervalHours: 24)
                    message = "已添加订阅"
                } else if s.contains("proxies:") || s.contains("proxy-providers:") {
                    _ = try await store.addLocal(name: "剪贴板导入", text: s)
                    message = "已导入配置"
                } else {
                    let n = try await store.addManualNodes(text: s)
                    message = "已添加 \(n) 个节点到「手动节点」"
                }
            } catch { message = error.localizedDescription }
        }
    }

    func importFile(_ result: Result<URL, Error>) {
        switch result {
        case .failure(let e): message = e.localizedDescription
        case .success(let url):
            let ok = url.startAccessingSecurityScopedResource()
            defer { if ok { url.stopAccessingSecurityScopedResource() } }
            guard let text = try? String(contentsOf: url, encoding: .utf8) else { message = "无法读取文件"; return }
            let name = url.deletingPathExtension().lastPathComponent
            busy = true
            Task {
                defer { busy = false }
                do { _ = try await store.addLocal(name: name, text: text); message = "已导入 \(name)" }
                catch { message = error.localizedDescription }
            }
        }
    }
}

struct ProfileRow: View {
    let profile: Profile
    let active: Bool
    let updating: Bool

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: active ? "checkmark.circle.fill" : "circle")
                .font(.title3)
                .foregroundStyle(active ? Theme.good : .secondary)
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text(profile.name).font(.headline).lineLimit(1)
                    Text(profile.kind == .remote ? "订阅" : "本地")
                        .font(.caption2.weight(.semibold))
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Capsule().fill((profile.kind == .remote ? Theme.accent : Color.orange).opacity(0.2)))
                    Spacer()
                    if updating { ProgressView().controlSize(.small) }
                }
                if let info = profile.userInfo {
                    if info.total > 0 {
                        ProgressView(value: info.fraction)
                            .tint(info.fraction > 0.9 ? Theme.bad : Theme.accent)
                        Text("已用 \(Fmt.bytes(info.used)) / \(Fmt.bytes(info.total))  ·  剩余 \(Fmt.bytes(max(info.total - info.used, 0)))")
                            .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                    }
                    if let exp = info.expireDate {
                        Text("到期 \(exp.formatted(date: .abbreviated, time: .omitted))" + (exp < Date() ? "（已过期）" : ""))
                            .font(.caption2).foregroundStyle(exp < Date() ? Theme.bad : .secondary)
                    }
                }
                if let d = profile.lastUpdated {
                    Text("更新于 \(d.formatted(.relative(presentation: .named)))")
                        .font(.caption2).foregroundStyle(.secondary)
                }
            }
        }
        .padding(.vertical, 4)
    }
}

struct AddRemoteSheet: View {
    @EnvironmentObject var store: ProfileStore
    @Environment(\.dismiss) var dismiss
    var onDone: (String) -> Void
    @State private var url = ""
    @State private var name = ""
    @State private var ua = "clash.meta"
    @State private var interval = 24
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("订阅") {
                    TextField("订阅链接 https://…", text: $url)
                        .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                    TextField("名称（留空自动获取）", text: $name)
                }
                Section("选项") {
                    Picker("User-Agent", selection: $ua) {
                        Text("clash.meta").tag("clash.meta")
                        Text("mihomo").tag("mihomo")
                        Text("clash-verge/v2").tag("clash-verge/v2")
                    }
                    Picker("自动更新", selection: $interval) {
                        Text("关闭").tag(0)
                        Text("每 6 小时").tag(6)
                        Text("每 12 小时").tag(12)
                        Text("每天").tag(24)
                        Text("每周").tag(168)
                    }
                }
                if let error { Section { Text(error).foregroundStyle(Theme.bad).font(.footnote) } }
            }
            .navigationTitle("添加订阅")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    if busy { ProgressView() } else {
                        Button("添加") { add() }.disabled(url.isEmpty)
                    }
                }
            }
            .onAppear {
                if url.isEmpty, let s = UIPasteboard.general.string, s.hasPrefix("http") { url = s }
            }
        }
    }

    func add() {
        busy = true; error = nil
        Task {
            defer { busy = false }
            do {
                let p = try await store.addRemote(url: url, name: name, userAgent: ua, intervalHours: interval)
                onDone("已添加「\(p.name)」")
                dismiss()
            } catch { self.error = error.localizedDescription }
        }
    }
}

struct YAMLEditorView: View {
    @EnvironmentObject var store: ProfileStore
    @Environment(\.dismiss) var dismiss
    let title: String
    @State var name: String
    @State var text: String
    let profile: Profile?
    @State private var error: String?
    @State private var busy = false

    init(title: String, initialName: String, initialText: String, profile: Profile?) {
        self.title = title
        _name = State(initialValue: initialName)
        _text = State(initialValue: initialText)
        self.profile = profile
    }

    static let template = """
    # mihomo 配置示例（请替换为你自己的节点）
    mode: rule
    proxies: []
    proxy-groups:
      - name: 节点选择
        type: select
        proxies: [DIRECT]
    rules:
      - MATCH,节点选择
    """

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                TextField("名称", text: $name)
                    .padding(12)
                    .background(Theme.cardHi)
                if let error {
                    Text(error).font(.caption).foregroundStyle(Theme.bad).padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                TextEditor(text: $text)
                    .font(.system(size: 13, design: .monospaced))
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .scrollContentBackground(.hidden)
                    .background(Theme.bg)
            }
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    if busy { ProgressView() } else { Button("校验并保存") { save() } }
                }
            }
        }
    }

    func save() {
        busy = true; error = nil
        Task {
            defer { busy = false }
            do {
                if let p = profile {
                    try await store.saveLocalEdit(p, text: text)
                    if name != p.name { store.rename(p, to: name) }
                } else {
                    _ = try await store.addLocal(name: name, text: text)
                }
                dismiss()
            } catch { self.error = error.localizedDescription }
        }
    }
}
