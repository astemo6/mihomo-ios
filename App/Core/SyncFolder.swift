import Foundation
import UIKit
import SwiftUI
import UniformTypeIdentifiers

// v0.10 同步文件夹: profiles, modules, overrides and the rest of a backup (no MitM CA) kept in one file,
// Mihomo-sync.json, in a folder the user picks once in the Files picker — typically iCloud Drive. Works
// without an iCloud container entitlement (re-signed builds have none): access goes through a
// security-scoped bookmark. Optional: push automatically when the app goes to the background and the
// configuration changed since the last push.

@MainActor
final class SyncFolder: ObservableObject {
    static let shared = SyncFolder()
    static let fileName = "Mihomo-sync.json"

    @Published private(set) var folderName: String?
    @Published private(set) var lastPush: Date?
    @Published private(set) var remoteDate: Date?
    @Published private(set) var remoteDevice: String?
    @Published var autoPush: Bool { didSet { AppShared.defaults.set(autoPush, forKey: "sync.autoPush") } }

    private let bookmarkKey = "sync.folderBookmark"
    private let hashKey = "sync.lastHash"

    init() {
        autoPush = AppShared.defaults.bool(forKey: "sync.autoPush")
        lastPush = AppShared.defaults.object(forKey: "sync.lastPush") as? Date
        if let u = resolve() { folderName = u.lastPathComponent }
    }

    var isSet: Bool { AppShared.defaults.data(forKey: bookmarkKey) != nil }

    /// Stores a bookmark for a folder chosen with the Files picker (.folder).
    func choose(_ url: URL) throws {
        let ok = url.startAccessingSecurityScopedResource()
        defer { if ok { url.stopAccessingSecurityScopedResource() } }
        let data = try url.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil)
        AppShared.defaults.set(data, forKey: bookmarkKey)
        AppShared.defaults.removeObject(forKey: hashKey)
        folderName = url.lastPathComponent
        refreshRemote()
    }

    func forget() {
        AppShared.defaults.removeObject(forKey: bookmarkKey)
        AppShared.defaults.removeObject(forKey: hashKey)
        folderName = nil
        remoteDate = nil
        remoteDevice = nil
    }

    private func resolve() -> URL? {
        guard let data = AppShared.defaults.data(forKey: bookmarkKey) else { return nil }
        var stale = false
        guard let u = try? URL(resolvingBookmarkData: data, options: [], relativeTo: nil, bookmarkDataIsStale: &stale) else { return nil }
        if stale, let fresh = try? u.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil) {
            AppShared.defaults.set(fresh, forKey: bookmarkKey)
        }
        return u
    }

    enum SyncError: LocalizedError {
        case noFolder, noAccess, noFile
        var errorDescription: String? {
            switch self {
            case .noFolder: return String(localized: "还没有选择同步文件夹")
            case .noAccess: return String(localized: "无法访问同步文件夹，请重新选择")
            case .noFile: return String(localized: "同步文件夹里还没有 Mihomo-sync.json")
            }
        }
    }

    /// Runs body with the folder's security scope open and file coordination around the sync file.
    private func withFile<T>(writing: Bool, _ body: (URL) throws -> T) throws -> T {
        guard let folder = resolve() else { throw SyncError.noFolder }
        guard folder.startAccessingSecurityScopedResource() else { throw SyncError.noAccess }
        defer { folder.stopAccessingSecurityScopedResource() }
        let file = folder.appendingPathComponent(Self.fileName)
        var coordErr: NSError?
        var result: Result<T, Error>?
        let c = NSFileCoordinator()
        if writing {
            c.coordinate(writingItemAt: file, options: .forReplacing, error: &coordErr) { u in result = Result { try body(u) } }
        } else {
            try? FileManager.default.startDownloadingUbiquitousItem(at: file)
            c.coordinate(readingItemAt: file, options: [], error: &coordErr) { u in result = Result { try body(u) } }
        }
        if let coordErr { throw coordErr }
        guard let result else { throw SyncError.noAccess }
        return try result.get()
    }

    /// Writes the current configuration to the folder. Returns the number of files.
    @discardableResult
    func push() throws -> Int {
        let (tmp, n) = try BackupManager.make(includeCA: false)
        var data = try Data(contentsOf: tmp)
        try? FileManager.default.removeItem(at: tmp)
        // Tag the device so the other side can show where the copy came from.
        if var obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] {
            var d = obj["defaults"] as? [String: String] ?? [:]
            d["syncDevice"] = UIDevice.current.name
            obj["defaults"] = d
            data = try JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])
        }
        try withFile(writing: true) { u in try data.write(to: u, options: .atomic) }
        let now = Date()
        lastPush = now
        AppShared.defaults.set(now, forKey: "sync.lastPush")
        AppShared.defaults.set(SnapshotStore.hash(SnapshotStore.currentFiles()), forKey: hashKey)
        refreshRemote()
        return n
    }

    /// Reads the folder's copy (for restoring through the usual backup path).
    func pullData() throws -> Data {
        try withFile(writing: false) { u in
            guard FileManager.default.fileExists(atPath: u.path) else { throw SyncError.noFile }
            return try Data(contentsOf: u)
        }
    }

    func refreshRemote() {
        guard isSet else { return }
        let r: (Date?, String?)? = try? withFile(writing: false) { u in
            guard let d = try? Data(contentsOf: u), let obj = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { return (nil, nil) }
            let f = ISO8601DateFormatter()
            let date = (obj["created"] as? String).flatMap { f.date(from: $0) }
            return (date, (obj["defaults"] as? [String: String])?["syncDevice"])
        }
        remoteDate = r?.0
        remoteDevice = r?.1
    }

    /// Called when the app goes to the background: push if enabled and something changed.
    func autoPushIfNeeded() {
        guard autoPush, isSet else { return }
        let h = SnapshotStore.hash(SnapshotStore.currentFiles())
        guard h != AppShared.defaults.string(forKey: hashKey) else { return }
        _ = try? push()
    }
}


struct SyncFolderView: View {
    @ObservedObject var sync = SyncFolder.shared
    @State private var picking = false
    @State private var confirmPull = false
    @State private var message: String?

    var body: some View {
        List {
            Section {
                if let n = sync.folderName {
                    LabeledContent("文件夹", value: n)
                    Button { picking = true } label: { Label("更换文件夹…", systemImage: "folder.badge.gearshape") }
                    Button(role: .destructive) { sync.forget() } label: { Label("停止同步", systemImage: "xmark.circle") }
                } else {
                    Button { picking = true } label: { Label("选择文件夹…", systemImage: "folder.badge.plus") }
                }
            } footer: {
                Text("在「文件」中选择一个文件夹（例如 iCloud 云盘里新建的 Mihomo 文件夹）。另一台设备选择同一个文件夹即可同步。不需要 iCloud 权限，重签后也能用。")
            }
            .listRowBackground(Theme.card)

            if sync.isSet {
                Section {
                    Button { run { let n = try sync.push(); return String(localized: "已上传 \(n) 个文件") } } label: {
                        Label("上传本机配置", systemImage: "icloud.and.arrow.up")
                    }
                    Button { confirmPull = true } label: { Label("用文件夹中的配置覆盖本机", systemImage: "icloud.and.arrow.down") }
                    Toggle("退到后台时自动上传", isOn: $sync.autoPush).tint(Theme.accent)
                } header: { Text("同步") } footer: {
                    Text("包含配置与订阅、手动节点、模块、脚本、覆写、DNS、自定义规则、策略组编辑；不含 MitM 证书和缓存。自动上传只在内容有变化时进行；下载需要手动确认，覆盖前会自动保存快照。")
                }
                .listRowBackground(Theme.card)

                Section("状态") {
                    LabeledContent("本机上次上传", value: sync.lastPush.map { $0.formatted(date: .abbreviated, time: .shortened) } ?? "—")
                    LabeledContent("文件夹中的副本", value: sync.remoteDate.map { $0.formatted(date: .abbreviated, time: .shortened) } ?? "—")
                    if let d = sync.remoteDevice { LabeledContent("来自设备", value: d) }
                }
                .listRowBackground(Theme.card)
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("同步文件夹")
        .onAppear { sync.refreshRemote() }
        .fileImporter(isPresented: $picking, allowedContentTypes: [.folder]) { r in
            guard case .success(let url) = r else { return }
            do { try sync.choose(url) } catch { message = error.localizedDescription }
        }
        .confirmationDialog("用文件夹中的配置覆盖本机的同名配置与设置？", isPresented: $confirmPull, titleVisibility: .visible) {
            Button("覆盖", role: .destructive) {
                run {
                    let d = try sync.pullData()
                    SnapshotStore.shared.capture(String(localized: "从同步文件夹恢复前"), manual: true)
                    let n = try BackupManager.restore(d)
                    SnapshotStore.reloadStores()
                    return String(localized: "已恢复 \(n) 个文件")
                }
            }
        }
        .alert("同步文件夹", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好") { message = nil }
        } message: { Text(message ?? "") }
    }

    func run(_ f: () throws -> String) {
        do { message = try f() } catch { message = error.localizedDescription }
    }
}
