import SwiftUI
import Libmihomo

// QX-4: 仓库 (galleries). QX keeps two kinds of gallery URLs: icon galleries (JSON {name, icons:[{name,url}]})
// and task galleries (JSON {name, description, task:["<cron|event-…> <script>, tag=…, img-url=…"]}).
// Both arrive through quantumult-x:///ui?module=gallery&type=task|icon&action=add&content=<JSON array of URLs>
// (or are added by hand). Task lines are added as ordinary script lines (the engine already parses QX
// task_local); nothing runs until the user taps +, and an icon is only a URL saved in the form.

@MainActor
final class QXGalleryStore: ObservableObject {
    static let shared = QXGalleryStore()
    static let taskKey = "qx.taskGalleries"
    static let iconKey = "qx.iconGalleries"

    @Published private(set) var taskGalleries: [String]
    @Published private(set) var iconGalleries: [String]

    init() {
        taskGalleries = UserDefaults.standard.stringArray(forKey: Self.taskKey) ?? []
        iconGalleries = UserDefaults.standard.stringArray(forKey: Self.iconKey) ?? []
    }

    /// Adds the http(s) URLs that are new; returns how many were added.
    @discardableResult
    func add(_ urls: [String], kind: String) -> Int {
        var list = kind == "icon" ? iconGalleries : taskGalleries
        var n = 0
        for raw in urls {
            let u = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard u.hasPrefix("http://") || u.hasPrefix("https://"), URL(string: u) != nil, !list.contains(u) else { continue }
            list.append(u)
            n += 1
        }
        set(list, kind: kind)
        return n
    }

    func remove(_ url: String, kind: String) {
        set((kind == "icon" ? iconGalleries : taskGalleries).filter { $0 != url }, kind: kind)
    }

    private func set(_ list: [String], kind: String) {
        if kind == "icon" {
            iconGalleries = list
            UserDefaults.standard.set(list, forKey: Self.iconKey)
        } else {
            taskGalleries = list
            UserDefaults.standard.set(list, forKey: Self.taskKey)
        }
    }

    /// `content` of a QX gallery link: a JSON array of URLs, a JSON string, or a bare URL.
    nonisolated static func urls(fromContent raw: String) -> [String] {
        let t = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if let d = t.data(using: .utf8), let any = try? JSONSerialization.jsonObject(with: d, options: [.fragmentsAllowed]) {
            if let a = any as? [Any] { return a.compactMap { $0 as? String } }
            if let s = any as? String { return [s] }
        }
        return t.hasPrefix("http") ? [t] : []
    }
}

struct QXTaskGallery: Decodable {
    var name: String?
    var description: String?
    var task: [String]?
}

/// One line of a task gallery, with what our engine makes of it.
struct QXGalleryTask: Identifiable, Hashable {
    var id: String { line }
    let line: String
    let name: String
    let kind: String      // cron | event | generic | "" (not a task)
    let schedule: String
    let path: String
    let icon: String?
    let error: String?
}

enum QXGalleryParse {
    static func tasks(_ g: QXTaskGallery) -> [QXGalleryTask] {
        (g.task ?? []).compactMap { raw in
            let line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !line.isEmpty, !line.hasPrefix("#"), !line.hasPrefix(";") else { return nil }
            let icon = param(line, "img-url")
            if let p = ParsedEngineText.parse(LibmihomoEngineParseLine(line, "task_local")), let t = p.tasks?.first {
                return QXGalleryTask(line: line, name: t.name, kind: t.kind, schedule: t.cron ?? t.event ?? "", path: t.path, icon: icon, error: nil)
            }
            return QXGalleryTask(line: line, name: param(line, "tag") ?? line, kind: "", schedule: "", path: "", icon: icon,
                                 error: String(localized: "不是可识别的任务行"))
        }
    }

    static func param(_ line: String, _ key: String) -> String? {
        for part in line.split(separator: ",") {
            let kv = part.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            if kv.count == 2, kv[0].lowercased() == key { return kv[1] }
        }
        return nil
    }
}

// MARK: - 任务仓库

struct QXTaskGalleryView: View {
    @ObservedObject private var store = QXGalleryStore.shared
    @State private var adding = false
    @State private var newURL = ""
    @State private var message: String?

    static let suggested = "https://raw.githubusercontent.com/KOP-XIAO/QuantumultX/master/Scripts/UI-Action.json"

    var body: some View {
        QXPage {
            QXCapsuleBar {
                QXBarIcon(systemName: "plus") {
                    let clip = UIPasteboard.general.hasStrings ? (UIPasteboard.general.string ?? "") : ""
                    newURL = clip.hasPrefix("http") ? clip.trimmingCharacters(in: .whitespacesAndNewlines) : ""
                    adding = true
                }
                .accessibilityLabel(Text("添加仓库"))
            }
        } content: {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    QXLargeTitle(title: String(localized: "任务仓库"), count: "\(store.taskGalleries.count)",
                                 caption: String(localized: "任务仓库是一份列出若干任务的 JSON（Quantumult X 格式）。打开仓库后逐条添加：定时任务按 cron 运行，event-network 在网络变化时运行，event-interaction 可在请求列表中手动运行。添加前不会下载或运行任何脚本。"))
                    if store.taskGalleries.isEmpty {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("还没有仓库").font(.headline)
                            Text("点右上角 + 粘贴仓库地址，或在 Safari 打开 quantumult-x:///ui?module=gallery&type=task… 链接。").font(.footnote).foregroundStyle(.secondary)
                            QXPill(title: String(localized: "添加示例仓库（UI 脚本合集）")) { store.add([Self.suggested], kind: "task") }
                        }
                        .padding(.vertical, 8)
                    }
                    ForEach(store.taskGalleries, id: \.self) { u in
                        NavigationLink {
                            QXTaskGalleryRepoView(url: u)
                        } label: {
                            QXCard {
                                HStack(spacing: 14) {
                                    Image(systemName: "square.stack.3d.up.fill").font(.system(size: 20, weight: .semibold)).foregroundStyle(.white)
                                        .frame(width: 44, height: 44)
                                        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(QXColor.tools))
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(verbatim: URL(string: u)?.lastPathComponent ?? u).font(.system(size: 17, weight: .semibold)).lineLimit(1)
                                        Text(verbatim: u).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                                    }
                                    Spacer(minLength: 4)
                                    Image(systemName: "chevron.right").font(.footnote.weight(.semibold)).foregroundStyle(.tertiary)
                                }
                                .padding(.horizontal, 16).padding(.vertical, 12)
                            }
                        }
                        .buttonStyle(.plain)
                        .contextMenu {
                            Button { UIPasteboard.general.string = u } label: { Label("拷贝链接", systemImage: "doc.on.doc") }
                            Button(role: .destructive) { store.remove(u, kind: "task") } label: { Label("删除", systemImage: "trash") }
                        }
                    }
                }
                .padding(.horizontal, QXMetrics.inset)
                .padding(.bottom, 40)
            }
        }
        .alert("添加任务仓库", isPresented: $adding) {
            TextField("https://…/gallery.json", text: $newURL).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
            Button("添加") {
                if store.add([newURL], kind: "task") == 0 { message = String(localized: "地址无效或已存在") }
            }
            Button("取消", role: .cancel) {}
        }
        .alert("提示", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好", role: .cancel) {}
        } message: { Text(message ?? "") }
    }
}

struct QXTaskGalleryRepoView: View {
    let url: String
    @ObservedObject private var engine = EngineStore.shared
    @State private var gallery: QXTaskGallery?
    @State private var tasks: [QXGalleryTask] = []
    @State private var error: String?
    @State private var loading = true

    func added(_ t: QXGalleryTask) -> Bool {
        engine.config.scripts.contains { $0.line == t.line } || engine.config.rules.contains { $0.line == t.line }
    }

    var body: some View {
        QXPage(title: gallery?.name) {
            QXCapsuleBar {
                QXBarIcon(systemName: "arrow.triangle.2.circlepath") { Task { await load() } }
                    .accessibilityLabel(Text("刷新"))
                QXBarIcon(systemName: "plus.square.on.square") {
                    let new = tasks.filter { $0.error == nil && !added($0) }
                    if !new.isEmpty { engine.addLines(new.map(\.line).joined(separator: "\n"), toScripts: true) }
                }
                .disabled(tasks.allSatisfy { $0.error != nil || added($0) })
                .accessibilityLabel(Text("全部添加"))
            }
        } content: {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    QXLargeTitle(title: gallery?.name ?? String(localized: "任务仓库"), count: tasks.isEmpty ? nil : "\(tasks.count)",
                                 caption: gallery?.description)
                        .padding(.bottom, 10)
                    if loading && tasks.isEmpty { ProgressView().frame(maxWidth: .infinity).padding(.vertical, 30) }
                    if let error { Text(verbatim: error).font(.footnote).foregroundStyle(Theme.bad).padding(.vertical, 8) }
                    ForEach(tasks) { t in
                        row(t)
                        Divider().padding(.leading, 70)
                    }
                }
                .padding(.horizontal, QXMetrics.inset)
                .padding(.bottom, 40)
            }
        }
        .task { await load() }
    }

    func row(_ t: QXGalleryTask) -> some View {
        HStack(alignment: .top, spacing: 14) {
            QXTaskIcon(icon: t.icon, kind: t.kind)
            VStack(alignment: .leading, spacing: 4) {
                Text(verbatim: t.name).font(.system(size: 17)).lineLimit(1)
                HStack(spacing: 6) {
                    Image(systemName: t.kind == "event" ? "network" : (t.kind == "generic" ? "hand.tap" : "clock")).font(.system(size: 12))
                    Text(verbatim: t.error ?? (t.schedule.isEmpty ? (t.kind == "generic" ? String(localized: "手动运行") : "—") : t.schedule))
                        .font(.system(size: 14, design: .monospaced))
                }
                .foregroundStyle(t.error == nil ? Color.secondary : Theme.bad)
                if !t.path.isEmpty {
                    Text(verbatim: t.path).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                }
            }
            Spacer(minLength: 4)
            if t.error == nil {
                if added(t) {
                    Image(systemName: "checkmark.circle.fill").font(.title3).foregroundStyle(QXColor.mitm)
                        .accessibilityLabel(Text("已添加"))
                } else {
                    Button { engine.addLines(t.line, toScripts: true) } label: {
                        Image(systemName: "plus.circle.fill").font(.title3).foregroundStyle(QXColor.switchOn)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(Text("添加"))
                }
            }
        }
        .padding(.vertical, 12)
        .contextMenu {
            Button { UIPasteboard.general.string = t.line } label: { Label("拷贝任务行", systemImage: "doc.on.doc") }
        }
    }

    func load() async {
        loading = true
        defer { loading = false }
        do {
            guard let u = URL(string: IconCache.mirrored(url)) ?? URL(string: url) else { throw URLError(.badURL) }
            let (data, _) = try await URLSession.shared.data(for: URLRequest(url: u, timeoutInterval: 20))
            guard data.count < 4 << 20 else { throw URLError(.dataLengthExceedsMaximum) }
            let g = try JSONDecoder().decode(QXTaskGallery.self, from: data)
            gallery = g
            tasks = QXGalleryParse.tasks(g)
            error = tasks.isEmpty ? String(localized: "这个仓库里没有任务") : nil
        } catch {
            self.error = String(localized: "仓库加载失败：\(error.localizedDescription)")
        }
    }
}

/// Task tile: img-url as an image, "name.system" as an SF Symbol (QX convention), else a coloured glyph.
struct QXTaskIcon: View {
    let icon: String?
    let kind: String
    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 12, style: .continuous).fill(kind == "event" ? QXColor.rewrite : QXColor.activity)
            if let i = icon, i.hasSuffix(".system") {
                Image(systemName: String(i.dropLast(".system".count))).font(.system(size: 20, weight: .semibold)).foregroundStyle(.white)
            } else if let i = icon, i.hasPrefix("http") {
                RemoteIcon(url: i, size: 30)
            } else {
                Image(systemName: kind == "event" ? "network" : (kind == "generic" ? "hand.tap.fill" : "clock.fill"))
                    .font(.system(size: 20, weight: .semibold)).foregroundStyle(.white)
            }
        }
        .frame(width: 48, height: 48)
    }
}

// MARK: - Icon browser (policy editor 浏览; works for new policies too)

/// Picks an icon URL from the built-in galleries and the user's own (QX icon-gallery JSON).
struct QXIconBrowser: View {
    let onPick: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @ObservedObject private var store = QXGalleryStore.shared
    @State private var adding = false
    @State private var newURL = ""

    var sources: [IconSetSource] {
        IconSetSource.popular + store.iconGalleries.map {
            IconSetSource(name: URL(string: $0)?.deletingPathExtension().lastPathComponent ?? $0, author: URL(string: $0)?.host ?? "", index: $0)
        }
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(sources) { set in
                        NavigationLink {
                            IconSetGrid(source: set) { url in onPick(url); dismiss() }
                        } label: {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(verbatim: set.name)
                                Text(verbatim: set.author).font(.caption2).foregroundStyle(.secondary)
                            }
                        }
                        .swipeActions {
                            if store.iconGalleries.contains(set.index) {
                                Button(role: .destructive) { store.remove(set.index, kind: "icon") } label: { Label("删除", systemImage: "trash") }
                            }
                        }
                    }
                } header: { Text("图标库") } footer: {
                    Text("图标库是 Quantumult X 格式的 JSON（name + icons）。点右上角 + 添加自己的图标库地址。")
                }
                .listRowBackground(Theme.card)
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("浏览图标")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("关闭") { dismiss() } }
                ToolbarItem(placement: .primaryAction) {
                    Button { newURL = ""; adding = true } label: { Image(systemName: "plus") }.accessibilityLabel(Text("添加图标库"))
                }
            }
            .alert("添加图标库", isPresented: $adding) {
                TextField("https://…/icons.json", text: $newURL).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                Button("添加") { store.add([newURL], kind: "icon") }
                Button("取消", role: .cancel) {}
            }
        }
    }
}

struct QXIconBrowseTarget: Identifiable { let id = UUID() }
