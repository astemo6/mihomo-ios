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
    /// r7 (review7 R7A-11): settings that live in defaults (按需连接, 实时活动, 首页 layout, 出口信息, WebDAV address,
    /// notifications, appearance, start tab, unlock checks …), so a backup → restore migration to a re-signed app
    /// (new bundle id) keeps them. "g:<key>" = App Group defaults, "s:<key>" = the app's own defaults; the value is
    /// a base64 binary plist [value]. Full backups only (not snapshots / the sync folder). nil in older backups.
    var prefs: [String: String]? = nil

    init() {}

    /// v0.19.5: only `app` and `files` are required. The synthesized decoder also required created / version /
    /// appVersion / defaults, so a backup missing one of them (hand-edited, or written by another tool) was
    /// refused although every file in it was intact.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        app = try c.decode(String.self, forKey: .app)
        files = try c.decode([String: String].self, forKey: .files)
        version = (try? c.decodeIfPresent(Int.self, forKey: .version)) ?? 1
        created = (try? c.decodeIfPresent(Date.self, forKey: .created)) ?? Date(timeIntervalSince1970: 0)
        appVersion = (try? c.decodeIfPresent(String.self, forKey: .appVersion)) ?? "?"
        defaults = (try? c.decodeIfPresent([String: String].self, forKey: .defaults)) ?? [:]
        prefs = try? c.decodeIfPresent([String: String].self, forKey: .prefs)
    }
}

enum BackupManager {
    /// Directories / files (relative to the container) that make up a backup.
    /// Review 5 P2-1: the scripts' key-value store (BoxJS / Sub-Store / check-in cookies and session tokens).
    static let scriptStore = "mihomo/engine/store.json"
    static let secretsItem = "mihomo/secrets.json"

    /// `includeStore`: false for every copy that leaves the device unencrypted (Files / share / iCloud exports,
    /// plain WebDAV, the sync folder).
    static func items(includeCA: Bool, includeStore: Bool = true) -> [String] {
        var out = ["profiles.json", "profiles", "mihomo/overrides.json", "mihomo/dns.json", "mihomo/localdns.json", "mihomo/group-icons.json", "mihomo/rules.json", "mihomo/subscriptions.json", "mihomo/groups.json", "mihomo/netpolicy.json", "mihomo/node-subscriptions.json", "mihomo/group-edits.json", "mihomo/provider-overrides.json",
                   "mihomo/node-settings.json", // r7 R7A-11: per-node 测速地址 / 备注
                   "mihomo/engine/engine.json", "mihomo/engine/store.json", "mihomo/engine/modules", "mihomo/engine/scripts",
                   "mihomo/override-scripts"] // v0.19 覆写脚本 (index.json + <id>.js)
        if includeCA { out.append("mihomo/engine/ca") }
        // r7 (backlog B01): the secrets (controller secret, LAN passwords) travel only where the scripts' store does —
        // encrypted copies and local snapshots; plain exports, plain WebDAV and the sync folder keep usernames only.
        out.append(secretsItem)
        if !includeStore { out.removeAll { $0 == scriptStore || $0 == secretsItem } }
        return out
    }

    static let defaultsKeys = ["activeProfileID"]

    /// r7 R7A-11: files only full backups carry (a snapshot restore must not roll the traffic statistics back).
    static let fullBackupOnlyItems = ["traffic-history.json"]

    /// r7 R7A-11: defaults keys (prefixes) a full backup carries, from either domain. Device state (sync bookmarks,
    /// widget / Live Activity caches, onboarding, the remembered App Group, paused on-demand) stays out.
    static let prefPrefixes = ["onDemandSettings", "liveActivity.enabled", "home.", "panels.", "geo.checker", "switch.closeConnections",
                               "unlock.", "policy.", "nodes.", "rules.sortByHits", "analytics.range", "webdav.settings", "notify.",
                               "usageAlerts.rules", "appearance", "ui.launchTab", "moduleGallery.sources", "qx.resourceParserURL"]

    static func isBackedUpPref(_ k: String) -> Bool { prefPrefixes.contains { k.hasPrefix($0) } }

    static func collectPrefs(group: UserDefaults = AppShared.defaults, groupName: String = AppShared.appGroup, standard: UserDefaults = .standard) -> [String: String] {
        var out: [String: String] = [:]
        func add(_ tag: String, _ dict: [String: Any]?) {
            for (k, v) in dict ?? [:] where isBackedUpPref(k) {
                if let d = try? PropertyListSerialization.data(fromPropertyList: [v], format: .binary, options: 0) { out[tag + k] = d.base64EncodedString() }
            }
        }
        add("g:", group.persistentDomain(forName: groupName))
        add("s:", Bundle.main.bundleIdentifier.flatMap { standard.persistentDomain(forName: $0) })
        return out
    }

    static func applyPrefs(_ prefs: [String: String], group: UserDefaults = AppShared.defaults, standard: UserDefaults = .standard) {
        for (tagged, b64) in prefs {
            let tag = tagged.prefix(2), key = String(tagged.dropFirst(2))
            guard isBackedUpPref(key), let d = Data(base64Encoded: b64),
                  let arr = try? PropertyListSerialization.propertyList(from: d, format: nil) as? [Any], let v = arr.first else { continue }
            if tag == "g:" { group.set(v, forKey: key) } else if tag == "s:" { standard.set(v, forKey: key) }
        }
    }

    static func make(includeCA: Bool, includeStore: Bool) throws -> (URL, Int) {
        let (data, n) = try makeData(includeCA: includeCA, includeStore: includeStore, fullBackup: true)
        let f = DateFormatter()
        f.dateFormat = "yyyyMMdd-HHmm"
        purgeTempExports()
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("Tern-备份-\(f.string(from: Date())).json")
        try data.write(to: url, options: [.atomic, .completeFileProtection])
        return (url, n)
    }

    /// Review 5 P2-9: removes leftover plaintext backup exports from tmp.
    static func purgeTempExports() {
        let fm = FileManager.default
        let tmp = fm.temporaryDirectory
        for n in (try? fm.contentsOfDirectory(atPath: tmp.path)) ?? [] where (n.hasPrefix("Tern-备份-") || n.hasPrefix("Mihomo-备份-")) && n.hasSuffix(".json") {
            try? fm.removeItem(at: tmp.appendingPathComponent(n))
        }
    }

    /// The backup JSON of `root` (the App Group container; a scratch directory in unit tests).
    /// fullBackup (r7 R7A-11): also the defaults settings and the traffic statistics (exports, WebDAV, iCloud).
    static func makeData(includeCA: Bool, includeStore: Bool = true, fullBackup: Bool = false, root: URL = AppShared.containerURL, defaults: UserDefaults = AppShared.defaults) throws -> (Data, Int) {
        let fm = FileManager.default
        var b = BackupFile()
        if fullBackup { b.prefs = collectPrefs() }
        for rel in items(includeCA: includeCA, includeStore: includeStore) + (fullBackup ? fullBackupOnlyItems : []) {
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
        for k in defaultsKeys { if let v = defaults.string(forKey: k) { b.defaults[k] = v } }
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .iso8601
        enc.outputFormatting = [.sortedKeys]
        return (try enc.encode(b), b.files.count)
    }

    /// Restores a backup. Only paths under the known items are written. Returns the number of files.
    @discardableResult
    static func restore(_ data: Data, root: URL = AppShared.containerURL, defaults: UserDefaults = AppShared.defaults) throws -> Int {
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        let b: BackupFile
        do { b = try dec.decode(BackupFile.self, from: data) } catch {
            throw NSError(domain: "Backup", code: 1, userInfo: [NSLocalizedDescriptionKey: String(localized: "不是 Tern 备份文件")])
        }
        guard b.app == "mihomo-ios" else { throw NSError(domain: "Backup", code: 1, userInfo: [NSLocalizedDescriptionKey: String(localized: "不是 Tern 备份文件")]) }
        let allowed = items(includeCA: true) + fullBackupOnlyItems
        // v0.19.1: decode every entry first. A damaged entry (bad base64, e.g. a truncated download) stops the
        // restore before anything is written, instead of leaving a half-restored mix of old and new files.
        var decoded: [(String, Data)] = []
        for (rel, b64) in b.files {
            guard !rel.contains(".."), allowed.contains(where: { rel == $0 || rel.hasPrefix($0 + "/") }) else { continue }
            guard let d = Data(base64Encoded: b64) else {
                throw NSError(domain: "Backup", code: 2, userInfo: [NSLocalizedDescriptionKey: String(localized: "备份文件已损坏：\(rel)")])
            }
            decoded.append((rel, d))
        }
        var n = 0
        for (rel, d) in decoded {
            let u = root.appendingPathComponent(rel)
            AppShared.ensureDir(u.deletingLastPathComponent())
            try d.write(to: u, options: .atomic)
            if rel.hasSuffix("ca.key") { try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: u.path) }
            n += 1
        }
        for (k, v) in b.defaults where defaultsKeys.contains(k) { defaults.set(v, forKey: k) }
        if let p = b.prefs, root == AppShared.containerURL { applyPrefs(p) } // r7 R7A-11 (unit tests use a scratch root)
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
    @State private var exportName = "Tern-备份.json"
    @State private var exporting = false
    @State private var importing = false
    @State private var pendingRestore: Data?
    @State private var message: String?
    @State private var cloudFiles: [URL] = []
    @State private var encryptedRestore: EncryptedData?

    var body: some View {
        List {
            Section {
                VStack(alignment: .leading, spacing: 6) {
                    Text("包含").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                    Text("配置与订阅（含离线选择的节点）· 本地节点 · 内核覆写 · DNS · 自定义规则 · MitM 主机名 · 重写 · 脚本 · 模块").font(.footnote)
                    Text("不含：规则集 / 节点集缓存、地理数据库、连接记录。").font(.caption2).foregroundStyle(.secondary)
                }
                Toggle("包含 MitM 根证书和私钥", isOn: $includeCA)
            } footer: {
                Text(includeCA ? "私钥能解密你信任它的设备上的 HTTPS 流量，请只保存在自己的位置。" : "不含证书时，在新设备上需要重新生成并信任证书。")
            }
            .listRowBackground(Theme.card)

            Section {
                NavigationLink { WebDAVView() } label: {
                    Label("WebDAV 备份", systemImage: "externaldrive.connected.to.line.below")
                }
                .accessibilityIdentifier("backup.webdav")
                NavigationLink { SyncFolderView() } label: {
                    Label("同步文件夹（iCloud 云盘）", systemImage: "arrow.triangle.2.circlepath.icloud")
                }
            } footer: {
                Text("WebDAV：备份到坚果云、Nextcloud、群晖等，保留多个版本，可加密。同步文件夹：选一个 iCloud 云盘文件夹，在多台设备间同步配置、模块和覆写。")
            }
            .listRowBackground(Theme.card)

            // User 2026-10-21 18:54 (exported 「配置」 came out as JSON): this is the full backup bundle, not one profile.
            Section {
                Button { export(toFiles: true) } label: { Label("保存完整备份到「文件」（可选 iCloud 云盘）", systemImage: "folder") }
                    .accessibilityIdentifier("backup.exportFiles")
                Button { export(toFiles: false) } label: { Label("分享完整备份…", systemImage: "square.and.arrow.up") }
                if BackupManager.iCloudFolder != nil {
                    Button { backupToICloud() } label: { Label("备份到 iCloud", systemImage: "icloud.and.arrow.up") }
                }
            } header: { Text("导出完整备份（.json，含全部配置 / 模块 / 设置）") } footer: {
                Text("只要导出某一个配置的 YAML 文件：更多 → 配置 → 长按该配置 → 导出。")
            }
            .listRowBackground(Theme.card)

            Section {
                Button { importing = true } label: { Label("从文件恢复…", systemImage: "arrow.down.doc") }
                ForEach(cloudFiles, id: \.self) { u in
                    Button {
                        if let d = try? Data(contentsOf: u) { pendingRestore = d } else { message = String(localized: "无法读取 iCloud 文件（可能尚未下载）") }
                    } label: {
                        Label(u.deletingPathExtension().lastPathComponent, systemImage: "icloud.and.arrow.down")
                    }
                }
            } header: { Text("恢复") } footer: {
                VStack(alignment: .leading, spacing: 6) {
                    Text(BackupManager.iCloudFolder == nil ? "当前签名没有 iCloud 容器权限，可以在「保存到文件」时选择 iCloud 云盘，恢复时从那里选择文件。恢复会覆盖同名配置与设置。" : "恢复会覆盖同名配置与设置。")
                    // r7 R7A-11: migration to a re-signed build (new bundle id) while the old app is still installed.
                    Text("换用重新签名的新 App 时：先在旧 App 里关闭按需连接再导出备份；在新 App 恢复后删除旧 App，否则「设置 → VPN」里两个 Tern 的 VPN 配置会互相抢连接，链接和文件也可能被旧 App 打开。")
                }
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("备份与恢复")
        .navigationBarTitleDisplayMode(.large) // fix/app-policy-ui #5b: pushed page keeps its large title
        .onAppear { loadCloud() }
        .sheet(item: $share, onDismiss: { BackupManager.purgeTempExports() }) { ActivityView(items: [$0.url], cleanup: $0.temporary ? $0.url : nil) }
        .fileExporter(isPresented: $exporting, document: exportDoc, contentType: .json, defaultFilename: exportName) { r in
            if case .failure(let e) = r { message = String(localized: "保存失败：\(e.localizedDescription)") } else { message = String(localized: "已保存") }
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.json, .data]) { r in
            guard case .success(let url) = r else { return }
            let ok = url.startAccessingSecurityScopedResource()
            defer { if ok { url.stopAccessingSecurityScopedResource() } }
            if let d = try? Data(contentsOf: url) { pendingRestore = d } else { message = String(localized: "无法读取文件") }
        }
        .confirmationDialog("恢复备份会覆盖当前的同名配置与设置", isPresented: Binding(get: { pendingRestore != nil }, set: { if !$0 { pendingRestore = nil } }), titleVisibility: .visible) {
            Button("恢复", role: .destructive) { if let d = pendingRestore { restore(d) }; pendingRestore = nil }
            Button("取消", role: .cancel) { pendingRestore = nil }
        }
        .sheet(item: $encryptedRestore) { e in
            BackupPasswordSheet(data: e.data) { n in
                encryptedRestore = nil
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.7) { message = String(localized: "已恢复 \(n) 个文件") }
            }
        }
        .alert("备份", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好") { message = nil }
        } message: { Text(message ?? "") }
    }

    func export(toFiles: Bool) {
        do {
            // Review 5 P2-1: Files / share exports are never encrypted, so the scripts' store (cookies, tokens) stays out.
            let (url, _) = try BackupManager.make(includeCA: includeCA, includeStore: false)
            if toFiles {
                exportDoc = JSONFileDocument(data: try Data(contentsOf: url))
                try? FileManager.default.removeItem(at: url) // P2-9: the exporter holds the bytes now
                exportName = url.lastPathComponent
                exporting = true
            } else {
                share = ShareItem(url: url, temporary: true)
            }
        } catch {
            message = String(localized: "导出失败：\(error.localizedDescription)")
        }
    }

    func backupToICloud() {
        guard let folder = BackupManager.iCloudFolder else { return }
        do {
            let (url, n) = try BackupManager.make(includeCA: includeCA, includeStore: false)
            defer { try? FileManager.default.removeItem(at: url) } // P2-9
            let dst = folder.appendingPathComponent(url.lastPathComponent)
            try? FileManager.default.removeItem(at: dst)
            try FileManager.default.copyItem(at: url, to: dst)
            message = String(localized: "已备份 \(n) 个文件到 iCloud")
            loadCloud()
        } catch {
            message = String(localized: "iCloud 备份失败：\(error.localizedDescription)")
        }
    }

    func loadCloud() {
        guard let folder = BackupManager.iCloudFolder else { cloudFiles = []; return }
        let items = (try? FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil)) ?? []
        cloudFiles = items.filter { $0.pathExtension == "json" }.sorted { $0.lastPathComponent > $1.lastPathComponent }
    }

    func restore(_ data: Data) {
        // v0.19: password-encrypted backups (WebDAV 备份 option) ask for the password first.
        if BackupCrypto.isEncrypted(data) { encryptedRestore = EncryptedData(data: data); return }
        Task {
            do {
                let n = try await BackupRestore.apply(data)
                message = String(localized: "已恢复 \(n) 个文件")
            } catch {
                message = String(localized: "恢复失败：\(error.localizedDescription)")
            }
        }
    }
}

/// v0.19: restoring a backup file (local, iCloud, WebDAV) and reloading every store that reads it.
@MainActor
enum BackupRestore {
    /// Review 5 P2-13: the capture and the file writes run off the main actor.
    static func apply(_ data: Data) async throws -> Int {
        await SnapshotStore.shared.captureAsync(String(localized: "恢复备份前"))
        let n = try await Task.detached(priority: .userInitiated) { try BackupManager.restore(data) }.value
        SnapshotStore.reloadStores() // the same stores as a snapshot restore (incl. override scripts)
        return n
    }
}

struct EncryptedData: Identifiable {
    let data: Data
    let id = UUID()
}

/// Password prompt for an encrypted backup; decrypts off the main thread (PBKDF2), then restores.
struct BackupPasswordSheet: View {
    let data: Data
    let done: (Int) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecureField("备份密码", text: $password)
                        .textContentType(.password)
                        .accessibilityIdentifier("backup.password")
                } footer: {
                    Text("这个备份用密码加密过（AES-256-GCM）。恢复会覆盖同名配置与设置。")
                }
                .listRowBackground(Theme.card)
                if let error { Section { ErrorRow(message: error) }.listRowBackground(Theme.card) }
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("加密的备份")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    if busy { ProgressView() } else {
                        Button("恢复") { restore() }.disabled(password.isEmpty).accessibilityIdentifier("backup.password.restore")
                    }
                }
            }
        }
    }

    func restore() {
        busy = true
        error = nil
        let d = data, pw = password
        Task {
            defer { busy = false }
            do {
                let plain = try await Task.detached(priority: .userInitiated) { try BackupCrypto.decrypt(d, password: pw) }.value
                let n = try await BackupRestore.apply(plain)
                dismiss()
                done(n)
            } catch {
                self.error = error.localizedDescription
            }
        }
    }
}
