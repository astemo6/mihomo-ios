import SwiftUI
import UniformTypeIdentifiers

// 备份与恢复: one JSON file with every user file (profiles + saved selections, manual nodes, overrides,
// DNS, custom rules, MitM / rewrite / scripts / modules). Caches and geo databases are left out.

struct BackupFile: Codable {
    var app = "mihomo-ios"
    var version = 1
    var created: Date = Date()
    var appVersion: String = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
    /// Path relative to the App Group container → base64 content.
    var files: [String: String] = [:]
    var defaults: [String: String] = [:]
}

enum BackupManager {
    /// Directories / files (relative to the container) that make up a backup.
    static func items(includeCA: Bool) -> [String] {
        var out = ["profiles.json", "profiles", "mihomo/overrides.json", "mihomo/dns.json", "mihomo/rules.json",
                   "mihomo/engine/engine.json", "mihomo/engine/store.json", "mihomo/engine/modules", "mihomo/engine/scripts"]
        if includeCA { out.append("mihomo/engine/ca") }
        return out
    }

    static let defaultsKeys = ["activeProfileID"]

    static func make(includeCA: Bool) throws -> (URL, Int) {
        let root = AppShared.containerURL
        let fm = FileManager.default
        var b = BackupFile()
        for rel in items(includeCA: includeCA) {
            let u = root.appendingPathComponent(rel)
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: u.path, isDirectory: &isDir) else { continue }
            if isDir.boolValue {
                let names = (try? fm.contentsOfDirectory(atPath: u.path)) ?? []
                for n in names where !n.hasPrefix(".") {
                    let f = u.appendingPathComponent(n)
                    var sub: ObjCBool = false
                    if fm.fileExists(atPath: f.path, isDirectory: &sub), !sub.boolValue, let d = try? Data(contentsOf: f) {
                        b.files[rel + "/" + n] = d.base64EncodedString()
                    }
                }
            } else if let d = try? Data(contentsOf: u) {
                b.files[rel] = d.base64EncodedString()
            }
        }
        for k in defaultsKeys { if let v = AppShared.defaults.string(forKey: k) { b.defaults[k] = v } }
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .iso8601
        enc.outputFormatting = [.sortedKeys]
        let data = try enc.encode(b)
        let f = DateFormatter()
        f.dateFormat = "yyyyMMdd-HHmm"
        let url = fm.temporaryDirectory.appendingPathComponent("Mihomo-备份-\(f.string(from: Date())).json")
        try data.write(to: url, options: .atomic)
        return (url, b.files.count)
    }

    /// Restores a backup. Only paths under the known items are written. Returns the number of files.
    @discardableResult
    static func restore(_ data: Data) throws -> Int {
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        let b = try dec.decode(BackupFile.self, from: data)
        guard b.app == "mihomo-ios" else { throw NSError(domain: "Backup", code: 1, userInfo: [NSLocalizedDescriptionKey: "不是 Mihomo 备份文件"]) }
        let root = AppShared.containerURL
        let allowed = items(includeCA: true)
        var n = 0
        for (rel, b64) in b.files {
            guard !rel.contains(".."), allowed.contains(where: { rel == $0 || rel.hasPrefix($0 + "/") }),
                  let d = Data(base64Encoded: b64) else { continue }
            let u = root.appendingPathComponent(rel)
            AppShared.ensureDir(u.deletingLastPathComponent())
            try d.write(to: u, options: .atomic)
            if rel.hasSuffix("ca.key") { try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: u.path) }
            n += 1
        }
        for (k, v) in b.defaults where defaultsKeys.contains(k) { AppShared.defaults.set(v, forKey: k) }
        return n
    }

    /// iCloud Documents folder, only when the signature carries an iCloud container entitlement.
    static var iCloudFolder: URL? {
        guard let u = FileManager.default.url(forUbiquityContainerIdentifier: nil) else { return nil }
        return AppShared.ensureDir(u.appendingPathComponent("Documents/Backups", isDirectory: true))
    }
}

struct JSONFileDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.json] }
    var data: Data
    init(data: Data) { self.data = data }
    init(configuration: ReadConfiguration) throws { data = configuration.file.regularFileContents ?? Data() }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: data) }
}

struct BackupView: View {
    @EnvironmentObject var vpn: VPNManager
    @EnvironmentObject var store: ProfileStore
    @State private var includeCA = false
    @State private var share: ShareItem?
    @State private var exportDoc: JSONFileDocument?
    @State private var exportName = "Mihomo-备份.json"
    @State private var exporting = false
    @State private var importing = false
    @State private var pendingRestore: Data?
    @State private var message: String?
    @State private var cloudFiles: [URL] = []

    var body: some View {
        List {
            Section {
                VStack(alignment: .leading, spacing: 6) {
                    Text("包含").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                    Text("配置与订阅（含离线选择的节点）· 手动节点 · 内核覆写 · DNS · 自定义规则 · MitM 主机名 · 重写 · 脚本 · 模块").font(.footnote)
                    Text("不含：规则集 / 节点集缓存、地理数据库、连接记录。").font(.caption2).foregroundStyle(.secondary)
                }
                Toggle("包含 MitM 根证书和私钥", isOn: $includeCA)
            } footer: {
                Text(includeCA ? "私钥能解密你信任它的设备上的 HTTPS 流量，请只保存在自己的位置。" : "不含证书时，在新设备上需要重新生成并信任证书。")
            }
            .listRowBackground(Theme.card)

            Section("导出") {
                Button { export(toFiles: true) } label: { Label("保存到「文件」（可选 iCloud 云盘）", systemImage: "folder") }
                Button { export(toFiles: false) } label: { Label("分享…", systemImage: "square.and.arrow.up") }
                if BackupManager.iCloudFolder != nil {
                    Button { backupToICloud() } label: { Label("备份到 iCloud", systemImage: "icloud.and.arrow.up") }
                }
            }
            .listRowBackground(Theme.card)

            Section {
                Button { importing = true } label: { Label("从文件恢复…", systemImage: "arrow.down.doc") }
                ForEach(cloudFiles, id: \.self) { u in
                    Button {
                        if let d = try? Data(contentsOf: u) { pendingRestore = d } else { message = "无法读取 iCloud 文件（可能尚未下载）" }
                    } label: {
                        Label(u.deletingPathExtension().lastPathComponent, systemImage: "icloud.and.arrow.down")
                    }
                }
            } header: { Text("恢复") } footer: {
                Text(BackupManager.iCloudFolder == nil ? "当前签名没有 iCloud 容器权限，可以在「保存到文件」时选择 iCloud 云盘，恢复时从那里选择文件。恢复会覆盖同名配置与设置。" : "恢复会覆盖同名配置与设置。")
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("备份与恢复")
        .onAppear { loadCloud() }
        .sheet(item: $share) { ActivityView(items: [$0.url]) }
        .fileExporter(isPresented: $exporting, document: exportDoc, contentType: .json, defaultFilename: exportName) { r in
            if case .failure(let e) = r { message = "保存失败：\(e.localizedDescription)" } else { message = "已保存" }
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.json, .data]) { r in
            guard case .success(let url) = r else { return }
            let ok = url.startAccessingSecurityScopedResource()
            defer { if ok { url.stopAccessingSecurityScopedResource() } }
            if let d = try? Data(contentsOf: url) { pendingRestore = d } else { message = "无法读取文件" }
        }
        .confirmationDialog("恢复备份会覆盖当前的同名配置与设置", isPresented: Binding(get: { pendingRestore != nil }, set: { if !$0 { pendingRestore = nil } }), titleVisibility: .visible) {
            Button("恢复", role: .destructive) { if let d = pendingRestore { restore(d) }; pendingRestore = nil }
            Button("取消", role: .cancel) { pendingRestore = nil }
        }
        .alert("备份", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好") { message = nil }
        } message: { Text(message ?? "") }
    }

    func export(toFiles: Bool) {
        do {
            let (url, _) = try BackupManager.make(includeCA: includeCA)
            if toFiles {
                exportDoc = JSONFileDocument(data: try Data(contentsOf: url))
                exportName = url.lastPathComponent
                exporting = true
            } else {
                share = ShareItem(url: url)
            }
        } catch {
            message = "导出失败：\(error.localizedDescription)"
        }
    }

    func backupToICloud() {
        guard let folder = BackupManager.iCloudFolder else { return }
        do {
            let (url, n) = try BackupManager.make(includeCA: includeCA)
            let dst = folder.appendingPathComponent(url.lastPathComponent)
            try? FileManager.default.removeItem(at: dst)
            try FileManager.default.copyItem(at: url, to: dst)
            message = "已备份 \(n) 个文件到 iCloud"
            loadCloud()
        } catch {
            message = "iCloud 备份失败：\(error.localizedDescription)"
        }
    }

    func loadCloud() {
        guard let folder = BackupManager.iCloudFolder else { cloudFiles = []; return }
        let items = (try? FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil)) ?? []
        cloudFiles = items.filter { $0.pathExtension == "json" }.sorted { $0.lastPathComponent > $1.lastPathComponent }
    }

    func restore(_ data: Data) {
        do {
            let n = try BackupManager.restore(data)
            store.load()
            store.activeID = AppShared.activeProfileID
            EngineStore.shared.config = EngineConfig.load()
            EngineStore.shared.reparseModules()
            CustomRulesStore.shared.load()
            message = "已恢复 \(n) 个文件"
            Task { if vpn.isConnected { _ = await vpn.reload() } }
        } catch {
            message = "恢复失败：\(error.localizedDescription)"
        }
    }
}
