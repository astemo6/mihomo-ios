import Foundation

/// Tern complete backup (.conf QuanX-style sectioned format) engine.
///
/// Format v1:
/// - Comment header
/// - [general] metadata
/// - [profile] current profile YAML verbatim
/// - [file <relPath>] repeating file sections with sha256, size, folded base64
/// - [prefs] optional group/standard user defaults base64 plists
/// - [defaults] optional activeProfileID etc.
/// - [end] mandatory terminating marker
public enum Mode: String, CaseIterable, Codable {
    case overwrite
    case merge
}

public enum TernBackupError: LocalizedError, Equatable {
    case notABackup
    case unsupportedVersion(Int)
    case corrupt(String)
    case readFailed(String)

    public var errorDescription: String? {
        switch self {
        case .notABackup:
            return String(localized: "不是有效的 Tern 备份文件")
        case .unsupportedVersion(let v):
            return String(localized: "不支持的备份版本：\(v)")
        case .corrupt(let msg):
            return String(localized: "备份文件已损坏：\(msg)")
        case .readFailed(let msg):
            return String(localized: "读取备份失败：\(msg)")
        }
    }
}

public struct BackupCategory: Identifiable, Hashable {
    public let id: String
    public let name: String
    public let detail: String
    public let isVirtual: Bool

    public init(id: String, name: String, detail: String, isVirtual: Bool = false) {
        self.id = id
        self.name = name
        self.detail = detail
        self.isVirtual = isVirtual
    }
}

public enum TernBackup {
    public static let currentFormat = 1

    public static let categories: [BackupCategory] = [
        BackupCategory(
            id: "profiles",
            name: String(localized: "配置"),
            detail: String(localized: "配置索引与 profiles/ 目录下所有配置文件")
        ),
        BackupCategory(
            id: "subscriptions",
            name: String(localized: "订阅与节点设置"),
            detail: String(localized: "节点订阅、分组、图标与节点设置")
        ),
        BackupCategory(
            id: "overrides",
            name: String(localized: "覆写与 DNS"),
            detail: String(localized: "内核覆写、DNS、本地 DNS 与规则配置")
        ),
        BackupCategory(
            id: "engine",
            name: String(localized: "模块/重写/MitM 设置"),
            detail: String(localized: "engine.json（远程重写、模块列表、MitM 开关与主机名）")
        ),
        BackupCategory(
            id: "resources",
            name: String(localized: "远程资源缓存与本地脚本"),
            detail: String(localized: "本地脚本、已下载模块正文与覆写脚本")
        ),
        BackupCategory(
            id: "ca",
            name: String(localized: "MitM 根证书与私钥"),
            detail: String(localized: "ca.pem 与 ca.key（明文导出，导入时权限 0600）")
        ),
        BackupCategory(
            id: "settings",
            name: String(localized: "App 设置"),
            detail: String(localized: "偏好设置与当前选中配置 ID"),
            isVirtual: true
        ),
    ]

    // MARK: - Paths constants

    public static let subscriptionsPaths: Set<String> = [
        "mihomo/subscriptions.json",
        "mihomo/node-subscriptions.json",
        "mihomo/groups.json",
        "mihomo/group-edits.json",
        "mihomo/provider-overrides.json",
        "mihomo/node-settings.json",
        "mihomo/netpolicy.json",
        "mihomo/group-icons.json"
    ]

    public static let overridesPaths: Set<String> = [
        "mihomo/overrides.json",
        "mihomo/dns.json",
        "mihomo/localdns.json",
        "mihomo/rules.json"
    ]

    public static let engineConfigPath = "mihomo/engine/engine.json"

    public static let resourceDirectoryPrefixes: [String] = [
        "mihomo/engine/modules/",
        "mihomo/engine/scripts/",
        "mihomo/override-scripts/"
    ]

    public static let caDirectoryPrefix = "mihomo/engine/ca/"

    /// Maps a relative path to its backup category ID, or nil if not backed up.
    public static func category(forPath path: String) -> String? {
        if path == "profiles.json" || path.hasPrefix("profiles/") {
            return "profiles"
        }
        if subscriptionsPaths.contains(path) {
            return "subscriptions"
        }
        if overridesPaths.contains(path) {
            return "overrides"
        }
        if path == engineConfigPath {
            return "engine"
        }
        if resourceDirectoryPrefixes.contains(where: { path.hasPrefix($0) }) {
            return "resources"
        }
        if path.hasPrefix(caDirectoryPrefix) {
            return "ca"
        }
        return nil
    }

    // MARK: - Parsed Result

    public struct Parsed: Equatable {
        public let format: Int
        public let created: String
        public let appVersion: String
        public let profileName: String?
        public let files: [String: Data]
        public let prefs: [String: String]
        public let defaults: [String: String]
        public let profileText: String
        public let categoryFiles: [String: [String]]

        public init(
            format: Int,
            created: String,
            appVersion: String,
            profileName: String?,
            files: [String: Data],
            prefs: [String: String],
            defaults: [String: String],
            profileText: String,
            categoryFiles: [String: [String]]
        ) {
            self.format = format
            self.created = created
            self.appVersion = appVersion
            self.profileName = profileName
            self.files = files
            self.prefs = prefs
            self.defaults = defaults
            self.profileText = profileText
            self.categoryFiles = categoryFiles
        }
    }

    // MARK: - ISO8601 Formatter

    private static let isoFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    // MARK: - Helpers

    public static func hexSHA256(_ data: Data) -> String {
        NCSHA256.hash(data).map { String(format: "%02x", $0) }.joined()
    }

    private static func foldBase64(_ b64: String, length: Int = 76) -> String {
        guard !b64.isEmpty else { return "" }
        var result = ""
        result.reserveCapacity(b64.count + (b64.count / length) + 2)
        var index = b64.startIndex
        while index < b64.endIndex {
            let nextIndex = b64.index(index, offsetBy: length, limitedBy: b64.endIndex) ?? b64.endIndex
            result.append(contentsOf: b64[index..<nextIndex])
            result.append("\n")
            index = nextIndex
        }
        return result
    }

    // MARK: - containsBackup

    public static func containsBackup(_ text: String) -> Bool {
        var inGeneral = false
        for rawLine in text.components(separatedBy: .newlines) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("[") && line.hasSuffix("]") {
                if line == "[general]" {
                    inGeneral = true
                } else if inGeneral {
                    return false
                }
                continue
            }
            if inGeneral {
                let parts = line.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                if parts.count == 2 && parts[0] == "tern_backup" && parts[1] == "1" {
                    return true
                }
            }
        }
        return false
    }

    // MARK: - build

    public static func build(
        profileText: String?,
        profileName: String?,
        includeResourceCache: Bool = true,
        root: URL,
        prefs: [String: String],
        defaults: [String: String]
    ) throws -> String {
        let fm = FileManager.default
        var collectedFiles: [String: Data] = [:]

        func addFileIfPresent(_ rel: String) {
            let u = root.appendingPathComponent(rel)
            var isDir: ObjCBool = false
            if fm.fileExists(atPath: u.path, isDirectory: &isDir), !isDir.boolValue, let d = try? Data(contentsOf: u) {
                collectedFiles[rel] = d
            }
        }

        func addDirContentsIfPresent(_ rel: String) {
            let u = root.appendingPathComponent(rel)
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: u.path, isDirectory: &isDir), isDir.boolValue else { return }
            let names = (try? fm.contentsOfDirectory(atPath: u.path)) ?? []
            for n in names where !n.hasPrefix(".") {
                let f = u.appendingPathComponent(n)
                var sub: ObjCBool = false
                if fm.fileExists(atPath: f.path, isDirectory: &sub), !sub.boolValue, let d = try? Data(contentsOf: f) {
                    collectedFiles[rel + "/" + n] = d
                }
            }
        }

        // 1. Profiles
        addFileIfPresent("profiles.json")
        addDirContentsIfPresent("profiles")

        // 2. Subscriptions
        for path in subscriptionsPaths {
            addFileIfPresent(path)
        }

        // 3. Overrides
        for path in overridesPaths {
            addFileIfPresent(path)
        }

        // 4. Engine
        addFileIfPresent(engineConfigPath)

        // 5. Resources (conditional)
        if includeResourceCache {
            addDirContentsIfPresent("mihomo/engine/modules")
            addDirContentsIfPresent("mihomo/engine/scripts")
            addDirContentsIfPresent("mihomo/override-scripts")
        }

        // 6. CA
        addDirContentsIfPresent("mihomo/engine/ca")

        let sortedFiles = collectedFiles.sorted { $0.key < $1.key }

        let appVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "1.0.0"
        let createdStr = isoFormatter.string(from: Date())

        var out = ""
        // Header
        out.append("; Tern 完整备份\n")
        out.append("#!name = Tern 完整备份\n")
        out.append("#!created = \(createdStr)\n\n")

        // [general]
        out.append("[general]\n")
        out.append("tern_backup = 1\n")
        out.append("format = \(currentFormat)\n")
        out.append("created = \(createdStr)\n")
        out.append("app_version = \(appVersion)\n")
        if let name = profileName?.trimmingCharacters(in: .whitespacesAndNewlines), !name.isEmpty {
            out.append("profile = \(name)\n")
        }
        out.append("files = \(sortedFiles.count)\n\n")

        // [profile]
        out.append("[profile]\n")
        if let text = profileText, !text.isEmpty {
            out.append(text)
            if !text.hasSuffix("\n") {
                out.append("\n")
            }
        }

        // [file <relPath>]
        for (rel, data) in sortedFiles {
            out.append("[file \(rel)]\n")
            out.append("sha256 = \(hexSHA256(data))\n")
            out.append("size = \(data.count)\n")
            let b64 = data.base64EncodedString()
            out.append(foldBase64(b64))
            out.append("\n")
        }

        // [prefs]
        if !prefs.isEmpty {
            out.append("[prefs]\n")
            for (k, v) in prefs.sorted(by: { $0.key < $1.key }) {
                out.append("\(k) = \(v)\n")
            }
            out.append("\n")
        }

        // [defaults]
        if !defaults.isEmpty {
            out.append("[defaults]\n")
            for (k, v) in defaults.sorted(by: { $0.key < $1.key }) {
                out.append("\(k) = \(v)\n")
            }
            out.append("\n")
        }

        // [end]
        out.append("[end]\n")

        return out
    }

    /// Convenience overload for app-side export.
    @MainActor
    public static func makeText(includeResourceCache: Bool = true) throws -> String {
        let root = AppShared.containerURL
        let prefs = BackupManager.collectPrefs()
        var defaults: [String: String] = [:]
        for k in BackupManager.defaultsKeys {
            if let v = AppShared.defaults.string(forKey: k) {
                defaults[k] = v
            }
        }
        let activeProfile = ProfileStore.shared.active
        let profileText = activeProfile.map { ProfileStore.shared.content(of: $0) }
        let profileName = activeProfile?.name
        return try build(
            profileText: profileText,
            profileName: profileName,
            includeResourceCache: includeResourceCache,
            root: root,
            prefs: prefs,
            defaults: defaults
        )
    }

    // MARK: - parse

    public static func parse(_ text: String) throws -> Parsed {
        guard containsBackup(text) else {
            throw TernBackupError.notABackup
        }

        enum SectionState {
            case none
            case general
            case profile
            case file(String)
            case prefs
            case defaults
            case end
        }

        var state: SectionState = .none
        var hasSeenEnd = false

        var generalKV: [String: String] = [:]
        var profileLines: [String] = []
        var fileSections: [(path: String, lines: [String])] = []
        var prefsKV: [String: String] = [:]
        var defaultsKV: [String: String] = [:]

        let lines = text.components(separatedBy: .newlines)
        var i = 0

        while i < lines.count {
            let line = lines[i]
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            // Section header check
            if trimmed.hasPrefix("[") && trimmed.hasSuffix("]") {
                if trimmed == "[general]" {
                    state = .general
                    i += 1
                    continue
                } else if trimmed == "[profile]" {
                    state = .profile
                    i += 1
                    continue
                } else if trimmed.hasPrefix("[file ") {
                    let rel = String(trimmed.dropFirst(6).dropLast(1)).trimmingCharacters(in: .whitespaces)
                    guard !rel.isEmpty, !rel.contains(".."), !rel.hasPrefix("/") else {
                        throw TernBackupError.corrupt("非法文件路径：\(rel)")
                    }
                    state = .file(rel)
                    fileSections.append((path: rel, lines: []))
                    i += 1
                    continue
                } else if trimmed == "[prefs]" {
                    state = .prefs
                    i += 1
                    continue
                } else if trimmed == "[defaults]" {
                    state = .defaults
                    i += 1
                    continue
                } else if trimmed == "[end]" {
                    state = .end
                    hasSeenEnd = true
                    i += 1
                    continue
                }
            }

            switch state {
            case .none:
                break
            case .general:
                if !trimmed.isEmpty && !trimmed.hasPrefix(";") && !trimmed.hasPrefix("#") {
                    let parts = trimmed.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                    if parts.count == 2 {
                        generalKV[parts[0]] = parts[1]
                    }
                }
            case .profile:
                profileLines.append(line)
            case .file:
                if let lastIdx = fileSections.indices.last {
                    fileSections[lastIdx].lines.append(trimmed)
                }
            case .prefs:
                if !trimmed.isEmpty && !trimmed.hasPrefix(";") && !trimmed.hasPrefix("#") {
                    let parts = trimmed.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                    if parts.count == 2 {
                        prefsKV[parts[0]] = parts[1]
                    }
                }
            case .defaults:
                if !trimmed.isEmpty && !trimmed.hasPrefix(";") && !trimmed.hasPrefix("#") {
                    let parts = trimmed.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                    if parts.count == 2 {
                        defaultsKV[parts[0]] = parts[1]
                    }
                }
            case .end:
                break
            }
            i += 1
        }

        // 1. Mandatory [end] marker
        guard hasSeenEnd else {
            throw TernBackupError.corrupt("缺少 [end] 结束标记")
        }

        // 2. Format version check
        guard let formatStr = generalKV["format"], let format = Int(formatStr) else {
            throw TernBackupError.notABackup
        }
        guard format == currentFormat else {
            throw TernBackupError.unsupportedVersion(format)
        }

        let created = generalKV["created"] ?? ""
        let appVersion = generalKV["app_version"] ?? "?"
        let profileName = generalKV["profile"]

        guard let filesCountStr = generalKV["files"], let expectedFilesCount = Int(filesCountStr) else {
            throw TernBackupError.corrupt("缺少 files 计数")
        }

        guard fileSections.count == expectedFilesCount else {
            throw TernBackupError.corrupt("文件数量不匹配：声明 \(expectedFilesCount) 节，实际 \(fileSections.count) 节")
        }

        // 3. Decode each file section and verify size and sha256
        var parsedFiles: [String: Data] = [:]
        for section in fileSections {
            let path = section.path
            var declaredSHA256: String?
            var declaredSize: Int?
            var b64Parts: [String] = []

            for line in section.lines where !line.isEmpty {
                if declaredSHA256 == nil && line.hasPrefix("sha256") {
                    let parts = line.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                    if parts.count == 2 && parts[0] == "sha256" {
                        declaredSHA256 = parts[1]
                        continue
                    }
                }
                if declaredSize == nil && line.hasPrefix("size") {
                    let parts = line.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                    if parts.count == 2 && parts[0] == "size", let sz = Int(parts[1]) {
                        declaredSize = sz
                        continue
                    }
                }
                b64Parts.append(line)
            }

            guard let expectedHash = declaredSHA256, let expectedSize = declaredSize else {
                throw TernBackupError.corrupt("缺少文件元数据：\(path)")
            }

            let fullB64 = b64Parts.joined()
            guard let data = Data(base64Encoded: fullB64) else {
                throw TernBackupError.corrupt("Base64 解码失败：\(path)")
            }

            guard data.count == expectedSize else {
                throw TernBackupError.corrupt("文件大小不匹配：\(path)，预期 \(expectedSize)，实际 \(data.count)")
            }

            let actualHash = hexSHA256(data)
            guard actualHash.lowercased() == expectedHash.lowercased() else {
                throw TernBackupError.corrupt("文件哈希不匹配：\(path)，预期 \(expectedHash)，实际 \(actualHash)")
            }

            parsedFiles[path] = data
        }

        // 4. Compute profileText
        let profileText: String
        if profileLines.isEmpty {
            profileText = ""
        } else {
            var joined = profileLines.joined(separator: "\n")
            if !joined.hasSuffix("\n") {
                joined.append("\n")
            }
            profileText = joined
        }

        // 5. Category classification
        var categoryFiles: [String: [String]] = [
            "profiles": [],
            "subscriptions": [],
            "overrides": [],
            "engine": [],
            "resources": [],
            "ca": [],
            "settings": []
        ]

        for path in parsedFiles.keys.sorted() {
            guard let cat = category(forPath: path) else {
                throw TernBackupError.corrupt("未知文件分类：\(path)")
            }
            categoryFiles[cat, default: []].append(path)
        }

        return Parsed(
            format: format,
            created: created,
            appVersion: appVersion,
            profileName: profileName,
            files: parsedFiles,
            prefs: prefsKV,
            defaults: defaultsKV,
            profileText: profileText,
            categoryFiles: categoryFiles
        )
    }
}
