import SwiftUI

// v0.10 配置快照 and 存储空间 (更多 → 工具与数据).

struct SnapshotsView: View {
    @ObservedObject var snaps = SnapshotStore.shared
    @State private var message: String?
    // v0.19.8 multi-select delete (device report: 47 snapshots, deleting them one swipe at a time).
    @State private var selecting = false
    @State private var selected: Set<String> = []
    @State private var confirmDelete = false
    /// A single swipe on a pinned snapshot asks first (review 5); the multi-select path already warns.
    @State private var pendingPinned: SnapshotMeta?

    private var allSelected: Bool { !snaps.list.isEmpty && selected.count == snaps.list.count }
    private var selectedPinned: Int { snaps.list.filter { selected.contains($0.id) && $0.pinned }.count }

    var body: some View {
        List {
            if !selecting {
                Section {
                    Toggle("自动快照", isOn: $snaps.autoEnabled).tint(Theme.accent)
                    Button { Task { if await snaps.captureAsync(String(localized: "手动快照"), manual: true) == nil { message = String(localized: "和最近一个快照相同，没有新建") } } } label: {
                        Label("立即创建快照", systemImage: "camera.on.rectangle")
                    }
                    .accessibilityIdentifier("snapshots.create")
                } footer: {
                    Text("导入、编辑、更新或删除配置，添加或删除模块，编辑策略组和恢复备份之前自动保存。内容没有变化时不重复保存；最多保留 \(SnapshotStore.maxCount) 个（已固定的除外）。不含 MitM 证书。")
                }
                .listRowBackground(Theme.card)
            }

            Section {
                if snaps.list.isEmpty {
                    EmptyStateRow(icon: "clock.arrow.circlepath", title: "还没有快照", message: "下次修改配置前会自动保存一个。")
                }
                ForEach(snaps.list) { m in
                    if selecting {
                        Button { toggle(m.id) } label: {
                            HStack(spacing: 10) {
                                Image(systemName: selected.contains(m.id) ? "checkmark.circle.fill" : "circle")
                                    .font(.title3)
                                    .foregroundStyle(selected.contains(m.id) ? Theme.accent : Color.secondary)
                                SnapshotRow(m: m)
                                Spacer(minLength: 0)
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityElement(children: .combine)
                        .accessibilityAddTraits(selected.contains(m.id) ? .isSelected : [])
                        .accessibilityIdentifier("snapshots.row")
                    } else {
                        NavigationLink { SnapshotDetailView(meta: m) } label: { SnapshotRow(m: m) }
                            .accessibilityIdentifier("snapshots.row")
                            .swipeActions {
                                Button(role: .destructive) { if m.pinned { pendingPinned = m } else { snaps.delete(m) } } label: { Label("删除", systemImage: "trash") }
                                Button { snaps.togglePin(m) } label: { Label(m.pinned ? "取消固定" : "固定", systemImage: m.pinned ? "pin.slash" : "pin") }
                                    .tint(Theme.warn)
                            }
                    }
                }
            } header: {
                Text("快照 \(snaps.list.count) · \(Fmt.bytes(Int64(snaps.totalBytes)))")
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("配置快照")
        .navigationBarTitleDisplayMode(.large) // fix/app-policy-ui #5b: pushed page keeps its large title
        .navigationBarBackButtonHidden(selecting)
        .deleteConfirmation({ _ in Text("删除已固定的快照？") }, item: $pendingPinned,
                            message: { m in Text(verbatim: m.reason) }) { m in snaps.delete(m) }
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                if !snaps.list.isEmpty || selecting {
                    Button(selecting ? "完成" : "选择") {
                        selecting.toggle()
                        selected = []
                    }
                    .accessibilityIdentifier("snapshots.select")
                }
            }
            ToolbarItem(placement: .navigationBarLeading) {
                if selecting {
                    Button(allSelected ? "取消全选" : "全选") {
                        selected = allSelected ? [] : Set(snaps.list.map(\.id))
                    }
                    .accessibilityIdentifier("snapshots.selectAll")
                }
            }
        }
        .safeAreaInset(edge: .bottom) {
            if selecting {
                Button(role: .destructive) { confirmDelete = true } label: {
                    Text("删除 (\(selected.count))")
                        .font(.body.weight(.semibold))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 12)
                }
                .buttonStyle(.borderedProminent)
                .tint(Theme.bad)
                .disabled(selected.isEmpty)
                .padding(.horizontal, 16).padding(.vertical, 8)
                .background(.bar)
                .accessibilityIdentifier("snapshots.deleteSelected")
            }
        }
        .confirmationDialog("删除 \(selected.count) 个快照？", isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("删除", role: .destructive) {
                let freed = snaps.delete(ids: selected)
                selected = []
                selecting = false
                message = String(localized: "已释放 \(Fmt.bytes(Int64(freed)))")
            }
            .accessibilityIdentifier("snapshots.confirmDelete")
        } message: {
            if selectedPinned > 0 {
                Text("其中 \(selectedPinned) 个已固定，也会被删除。删除后无法恢复。")
            } else {
                Text("删除后无法恢复。")
            }
        }
        .onChange(of: snaps.list) { l in
            let ids = Set(l.map(\.id))
            selected = selected.intersection(ids)
        }
        .alert("快照", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好") { message = nil }
        } message: { Text(message ?? "") }
    }

    private func toggle(_ id: String) {
        if selected.contains(id) { selected.remove(id) } else { selected.insert(id) }
    }
}

struct SnapshotRow: View {
    let m: SnapshotMeta
    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                if m.pinned { Image(systemName: "pin.fill").font(.caption2).foregroundStyle(Theme.warn) }
                Text(m.reason).font(.subheadline).lineLimit(1)
            }
            HStack(spacing: 8) {
                Text(m.date, format: .dateTime.month().day().hour().minute())
                Text("\(m.files) 个文件")
                Text(Fmt.bytes(Int64(m.bytes)))
            }
            .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
        }
    }
}

struct SnapshotDetailView: View {
    let meta: SnapshotMeta
    @Environment(\.dismiss) private var dismiss
    @State private var diff: SnapshotDiff?
    @State private var loaded = false
    @State private var confirm = false
    @State private var message: String?

    var body: some View {
        List {
            Section {
                SnapshotRow(m: meta)
            }
            .listRowBackground(Theme.card)
            Section {
                if !loaded {
                    LoadingRow(text: "正在比较…")
                } else if let d = diff {
                    if d.isEmpty {
                        Label("和当前配置完全相同", systemImage: "checkmark.circle").foregroundStyle(Theme.good)
                    }
                    ForEach(d.changes) { c in
                        HStack(spacing: 8) {
                            Image(systemName: icon(c.kind)).foregroundStyle(color(c.kind)).frame(width: 18)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(c.title).font(.footnote).lineLimit(2)
                                Text(kindText(c.kind)).font(.caption2).foregroundStyle(.secondary)
                            }
                            Spacer()
                            if c.plus > 0 { Text("+\(c.plus)").foregroundStyle(Theme.good) }
                            if c.minus > 0 { Text("−\(c.minus)").foregroundStyle(Theme.bad) }
                        }
                        .font(.caption.monospacedDigit())
                    }
                } else {
                    ErrorRow(message: String(localized: "快照文件不存在"))
                }
            } header: {
                Text("恢复后的变化")
            } footer: {
                Text("行数按「恢复后 相对 当前」统计。恢复只写回快照里的文件，之后新增的配置会保留在列表之外。恢复前会先给当前状态保存一个快照。")
            }
            .listRowBackground(Theme.card)
            Section {
                Button(role: .destructive) { confirm = true } label: { Label("恢复此快照", systemImage: "arrow.uturn.backward") }
                    .disabled(diff == nil || diff?.isEmpty == true)
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("快照详情")
        .navigationBarTitleDisplayMode(.large) // fix/app-policy-ui #5b: pushed page keeps its large title
        .task {
            diff = await SnapshotStore.shared.diffAsync(meta)
            loaded = true
        }
        .confirmationDialog("用这个快照覆盖当前配置？", isPresented: $confirm, titleVisibility: .visible) {
            Button("恢复", role: .destructive) {
                Task {
                    do {
                        let n = try await SnapshotStore.shared.restoreAsync(meta)
                        message = String(localized: "已恢复 \(n) 个文件")
                    } catch {
                        message = error.localizedDescription
                    }
                }
            }
        }
        .alert("快照", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil; dismiss() } })) {
            Button("好") { message = nil; dismiss() }
        } message: { Text(message ?? "") }
    }

    func icon(_ k: SnapshotDiff.FileChange.Kind) -> String {
        switch k { case .added: return "plus.circle"; case .removed: return "minus.circle"; case .changed: return "pencil.circle" }
    }
    func color(_ k: SnapshotDiff.FileChange.Kind) -> Color {
        switch k { case .added: return Theme.good; case .removed: return Theme.neutral; case .changed: return Theme.accent }
    }
    func kindText(_ k: SnapshotDiff.FileChange.Kind) -> String {
        switch k {
        case .added: return String(localized: "恢复后重新出现")
        case .removed: return String(localized: "快照中没有（恢复后保留现状）")
        case .changed: return String(localized: "内容不同")
        }
    }
}

// MARK: - 存储空间

struct StorageCategory: Identifiable {
    enum Action { case none, clear, unusedProviders, oldSnapshots, leftovers }
    var id: String
    var title: String
    var icon: String
    var bytes: Int64
    var note: String
    var action: Action
    var actionTitle: String = ""
    var destructive = false
}

@MainActor
final class StorageModel: ObservableObject {
    @Published var categories: [StorageCategory] = []
    @Published var total: Int64 = 0
    @Published var unusedProviders: [URL] = []
    /// fix/nc-storage-other: the largest subpaths inside 其他 (container-relative), for the expandable row.
    @Published var otherTop: [StorageScan.PathUsage] = []
    @Published var loading = false

    /// Allocated bytes under `url` (symlinks skipped, hard links once). Kept for callers that size one path.
    nonisolated static func size(_ url: URL) -> Int64 { StorageScan.Walker().size(url) }

    nonisolated static var providerDirs: [String] { StorageScan.providerDirs }
    nonisolated static var geoExt: Set<String> { StorageScan.geoExt }
    nonisolated static var logFiles: [URL] {
        let c = AppShared.containerURL
        return [c.appendingPathComponent("startup-log.txt"), c.appendingPathComponent("startup-log.prev.txt"),
                c.appendingPathComponent("tunnel-last-error.txt"), c.appendingPathComponent("tunnel-last-stop.txt"),
                AppShared.homeURL.appendingPathComponent("diag")]
    }
    nonisolated static var statsFiles: [URL] {
        let c = AppShared.containerURL
        return [c.appendingPathComponent("traffic-history.json"), c.appendingPathComponent("analytics-history.json"),
                AppShared.homeURL.appendingPathComponent("probe-results.json")]
    }

    func reload() async {
        loading = true
        defer { loading = false }
        let profiles = ProfileStore.shared.profiles.map { $0.fileURL.path }
        let r = await Task.detached(priority: .userInitiated) { () -> ([StorageCategory], Int64, [URL], [StorageScan.PathUsage]) in
            let fm = FileManager.default
            let c = AppShared.containerURL, home = AppShared.homeURL
            // Provider files referenced by any profile (as the core would resolve them).
            var used = Set<String>()
            for p in profiles {
                let json = NCProviderPorts.providerPlan(home: home.path, profilePath: p)
                if let arr = try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [[String: Any]] {
                    for t in arr { if let path = t["path"] as? String { used.insert(URL(fileURLWithPath: path).standardizedFileURL.path) } }
                }
            }
            // fix/nc-storage-other: one walk, allocated bytes, symlinks skipped, hard links once; every file lands in
            // exactly one category, so 其他 is an exact sum (it was size(container) + size(tmp) − Σ categories of
            // logical sizes).
            let s = StorageScan.scan(container: c, tmp: fm.temporaryDirectory)
            let unused = s.providerFiles.filter { !used.contains($0.standardizedFileURL.path) }
            let unusedBytes = unused.reduce(Int64(0)) { $0 + Self.size($1) }
            func b(_ k: StorageScan.Kind) -> Int64 { s.bytes[k] ?? 0 }
            let leftover = s.leftoverBytes
            var cats: [StorageCategory] = [
                .init(id: "profiles", title: String(localized: "配置与节点订阅"), icon: "doc.text", bytes: b(.profiles), note: String(localized: "你的配置文件，不能在这里清理。"), action: .none),
                .init(id: "providers", title: String(localized: "规则集 / 节点集缓存"), icon: "shippingbox", bytes: b(.providers),
                      note: unused.isEmpty ? String(localized: "都被配置引用。") : String(localized: "\(unused.count) 个文件（\(Fmt.bytes(unusedBytes))）不再被任何配置引用。"),
                      action: unused.isEmpty ? .none : .unusedProviders, actionTitle: String(localized: "清除未引用的缓存")),
                .init(id: "geo", title: String(localized: "地理数据库"), icon: "globe.asia.australia", bytes: b(.geo), note: String(localized: "在 更多 → 高级设置 → 地理数据库 中管理。"), action: .none),
                .init(id: "snapshots", title: String(localized: "配置快照"), icon: "clock.arrow.circlepath", bytes: b(.snapshots), note: String(localized: "保留最近 3 个和已固定的。"), action: .oldSnapshots, actionTitle: String(localized: "删除旧快照")),
                .init(id: "logs", title: String(localized: "日志与诊断"), icon: "text.alignleft", bytes: b(.logs), note: String(localized: "启动日志、最近错误、内核诊断文件。"), action: .clear, actionTitle: String(localized: "清除日志")),
                .init(id: "icons", title: String(localized: "图标缓存"), icon: "photo.on.rectangle", bytes: b(.icons), note: String(localized: "策略组图标，需要时重新下载。"), action: .clear, actionTitle: String(localized: "清除图标缓存")),
                .init(id: "tmp", title: String(localized: "临时文件"), icon: "tray", bytes: s.tmpBytes, note: String(localized: "导出的备份、诊断包、HAR 等。"), action: .clear, actionTitle: String(localized: "清除临时文件")),
                .init(id: "stats", title: String(localized: "流量与分析记录"), icon: "chart.bar.xaxis", bytes: b(.stats), note: String(localized: "每日流量、连接分析历史、节点探测结果。"), action: .clear, actionTitle: String(localized: "清除记录"), destructive: true),
            ]
            let otherNote = leftover > 0
                ? String(localized: "内核运行文件、设置、MitM 证书等。其中 \(Fmt.bytes(leftover)) 是可安全删除的残留文件。")
                : String(localized: "内核运行文件、设置、MitM 证书等。")
            cats.append(.init(id: "other", title: String(localized: "其他"), icon: "ellipsis.circle", bytes: b(.other), note: otherNote,
                              action: leftover > 0 ? .leftovers : .none, actionTitle: String(localized: "清除残留文件")))
            return (cats, s.total, unused, StorageScan.topPaths(s.other))
        }.value
        categories = r.0
        total = r.1
        unusedProviders = r.2
        otherTop = r.3
    }

    /// Runs a category's cleanup; returns a message.
    func clean(_ c: StorageCategory) async -> String {
        let fm = FileManager.default
        let before = c.bytes
        switch c.id {
        case "providers":
            for f in unusedProviders { try? fm.removeItem(at: f) }
        case "snapshots":
            SnapshotStore.shared.deleteOld(keep: 3)
        case "logs":
            for f in Self.logFiles { try? fm.removeItem(at: f) }
        case "icons":
            try? fm.removeItem(at: AppShared.containerURL.appendingPathComponent("icon-cache"))
        case "tmp":
            for n in (try? fm.contentsOfDirectory(atPath: fm.temporaryDirectory.path)) ?? [] {
                try? fm.removeItem(at: fm.temporaryDirectory.appendingPathComponent(n))
            }
        case "stats":
            for f in Self.statsFiles { try? fm.removeItem(at: f) }
        case "other":
            await Self.removeLeftovers(under: "")
        default: break
        }
        await reload()
        let after = categories.first { $0.id == c.id }?.bytes ?? 0
        return String(localized: "已释放 \(Fmt.bytes(max(before - after, 0)))")
    }

    /// Clears the leftovers of one 其他 subpath (rows marked clearable); returns a message.
    func clean(path: StorageScan.PathUsage) async -> String {
        let before = categories.first { $0.id == "other" }?.bytes ?? 0
        await Self.removeLeftovers(under: path.path)
        await reload()
        let after = categories.first { $0.id == "other" }?.bytes ?? 0
        return String(localized: "已释放 \(Fmt.bytes(max(before - after, 0)))")
    }

    /// Off the main thread, under the runtime prep's lock (never races a prepare deleting its own staging).
    nonisolated static func removeLeftovers(under prefix: String) async {
        await Task.detached(priority: .userInitiated) {
            let key = (AppShared.homeURL.path as NSString).appendingPathComponent(".nativecore-prepare.lock")
            NCPathLock.shared.withLock(for: key) {
                _ = StorageScan.removeLeftovers(container: AppShared.containerURL, under: prefix)
            }
        }.value
    }
}

struct StorageView: View {
    @StateObject private var model = StorageModel()
    @State private var pending: StorageCategory?
    @State private var pendingPath: StorageScan.PathUsage?
    @State private var message: String?

    var body: some View {
        List {
            Section {
                HStack {
                    Text("共占用").font(.subheadline)
                    Spacer()
                    if model.loading && model.categories.isEmpty { ProgressView() } else {
                        Text(Fmt.bytes(model.total)).font(.title3.monospacedDigit().weight(.semibold)).foregroundStyle(Theme.accent)
                    }
                }
                if model.total > 0 { StorageBar(categories: model.categories, total: model.total).frame(height: 10) }
            }
            .listRowBackground(Theme.card)
            Section {
                ForEach(model.categories) { c in
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Label(c.title, systemImage: c.icon).font(.subheadline)
                            Spacer()
                            Text(Fmt.bytes(c.bytes)).font(.footnote.monospacedDigit()).foregroundStyle(.secondary)
                        }
                        Text(c.note).font(.caption2).foregroundStyle(.secondary)
                        if c.action != .none && c.bytes > 0 {
                            Button(role: c.destructive ? .destructive : nil) { pending = c } label: { Text(c.actionTitle).font(.caption.weight(.semibold)) }
                                .buttonStyle(.borderless)
                        }
                        // fix/nc-storage-other: what 其他 is made of (largest subpaths, container-relative).
                        if c.id == "other" && !model.otherTop.isEmpty {
                            DisclosureGroup {
                                ForEach(model.otherTop) { p in
                                    VStack(alignment: .leading, spacing: 2) {
                                        HStack(alignment: .firstTextBaseline) {
                                            Image(systemName: p.isDirectory ? "folder" : "doc").font(.caption2).foregroundStyle(.secondary)
                                            Text(p.path).font(.caption.monospaced()).lineLimit(2).truncationMode(.middle)
                                            Spacer(minLength: 8)
                                            Text(Fmt.bytes(p.bytes)).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                                        }
                                        if p.clearable {
                                            Button { pendingPath = p } label: { Text("清除").font(.caption2.weight(.semibold)) }
                                                .buttonStyle(.borderless)
                                        }
                                    }
                                }
                            } label: {
                                Text("占用最多的位置").font(.caption.weight(.semibold))
                            }
                        }
                    }
                    .padding(.vertical, 2)
                }
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("存储空间")
        .navigationBarTitleDisplayMode(.large) // fix/app-policy-ui #5b: pushed page keeps its large title
        .refreshable { await model.reload() }
        .task { await model.reload() }
        .confirmationDialog(pending.map { String(localized: "\($0.actionTitle)？") } ?? "", isPresented: Binding(get: { pending != nil }, set: { if !$0 { pending = nil } }), titleVisibility: .visible) {
            Button(pending?.actionTitle ?? "", role: .destructive) {
                if let c = pending { Task { message = await model.clean(c) } }
                pending = nil
            }
        } message: {
            if pending?.id == "providers" { Text("下次连接或更新资源时会重新下载仍需要的文件。") }
            if pending?.id == "stats" { Text("每日流量和连接分析的历史会被删除，无法恢复。") }
            if pending?.id == "other" { Text("只删除中断后留下的临时文件、旧版内核的缓存和系统缓存，不影响配置与设置。") }
        }
        .confirmationDialog(pendingPath.map { String(localized: "清除 \($0.path)？") } ?? "", isPresented: Binding(get: { pendingPath != nil }, set: { if !$0 { pendingPath = nil } }), titleVisibility: .visible) {
            Button("清除", role: .destructive) {
                if let p = pendingPath { Task { message = await model.clean(path: p) } }
                pendingPath = nil
            }
        } message: {
            Text("只删除中断后留下的临时文件、旧版内核的缓存和系统缓存，不影响配置与设置。")
        }
        .alert("存储空间", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好") { message = nil }
        } message: { Text(message ?? "") }
    }
}

struct StorageBar: View {
    let categories: [StorageCategory]
    let total: Int64
    static let palette: [Color] = [Theme.accent, Theme.up, Theme.good, Theme.warn, Theme.tone(0.6, 0.45, 0.95), Theme.tone(0.95, 0.4, 0.6), Theme.tone(0.4, 0.75, 0.75), Theme.bad, Theme.neutral]
    var body: some View {
        GeometryReader { g in
            HStack(spacing: 1) {
                ForEach(Array(categories.enumerated()), id: \.element.id) { i, c in
                    if c.bytes > 0 {
                        Rectangle().fill(Self.palette[i % Self.palette.count])
                            .frame(width: max(2, g.size.width * CGFloat(Double(c.bytes) / Double(max(total, 1)))))
                    }
                }
                Spacer(minLength: 0)
            }
            .clipShape(Capsule())
        }
    }
}
