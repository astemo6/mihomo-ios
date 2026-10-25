import Foundation

/// Tern complete backup (.conf QuanX-style sectioned format) engine.
///
/// Format v3-final:
/// - Comment header
/// - [general] metadata
/// - [profile] active profile YAML verbatim
/// - [profile <fileName>] remaining profiles YAML verbatim
/// - [json <relPath>] JSON files verbatim
/// - [text <relPath>] text / script / PEM files verbatim
/// - [prefs] optional group/standard user defaults JSON object
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
        )
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
        public let profileText: String?
        public let otherProfiles: [(fileName: String, text: String)]
        public let files: [String: Data]
        public let prefs: [String: Any]?
        public let defaults: [String: String]
        public let categoryFiles: [String: [String]]

        public init(
            format: Int,
            created: String,
            appVersion: String,
            profileName: String?,
            profileText: String?,
            otherProfiles: [(fileName: String, text: String)],
            files: [String: Data],
            prefs: [String: Any]?,
            defaults: [String: String],
            categoryFiles: [String: [String]]
        ) {
            self.format = format
            self.created = created
            self.appVersion = appVersion
            self.profileName = profileName
            self.profileText = profileText
            self.otherProfiles = otherProfiles
            self.files = files
            self.prefs = prefs
            self.defaults = defaults
            self.categoryFiles = categoryFiles
        }

        public static func == (lhs: Parsed, rhs: Parsed) -> Bool {
            if lhs.format != rhs.format ||
                lhs.created != rhs.created ||
                lhs.appVersion != rhs.appVersion ||
                lhs.profileName != rhs.profileName ||
                lhs.profileText != rhs.profileText ||
                lhs.files != rhs.files ||
                lhs.defaults != rhs.defaults ||
                lhs.categoryFiles != rhs.categoryFiles {
                return false
            }
            if lhs.otherProfiles.count != rhs.otherProfiles.count {
                return false
            }
            for i in 0..<lhs.otherProfiles.count {
                if lhs.otherProfiles[i].fileName != rhs.otherProfiles[i].fileName ||
                    lhs.otherProfiles[i].text != rhs.otherProfiles[i].text {
                    return false
                }
            }
            switch (lhs.prefs, rhs.prefs) {
            case (nil, nil):
                return true
            case (let p1?, let p2?):
                return NSDictionary(dictionary: p1).isEqual(to: p2)
            default:
                return false
            }
        }
    }

    // MARK: - ISO8601 Formatter

    private static let isoFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    // MARK: - Prefs Value Wrapping / Unwrapping

    /// Wraps plist property values into JSON-compatible values ($data and $date wrappers).
    public static func wrapToJSONValue(_ val: Any) -> Any? {
        if let str = val as? String {
            return str
        } else if let num = val as? NSNumber {
            return num
        } else if let data = val as? Data {
            return ["$data": data.base64EncodedString()]
        } else if let date = val as? Date {
            return ["$date": isoFormatter.string(from: date)]
        } else if let arr = val as? [Any] {
            return arr.compactMap { wrapToJSONValue($0) }
        } else if let dict = val as? [String: Any] {
            var out: [String: Any] = [:]
            for (k, v) in dict {
                if let wv = wrapToJSONValue(v) {
                    out[k] = wv
                }
            }
            return out
        }
        return nil
    }

    /// Unwraps JSON values back into plist property values ($data and $date unwrapping).
    public static func unwrapJSONValue(_ val: Any) -> Any {
        if let dict = val as? [String: Any] {
            if dict.count == 1, let b64 = dict["$data"] as? String, let d = Data(base64Encoded: b64) {
                return d
            }
            if dict.count == 1, let dateStr = dict["$date"] as? String, let d = isoFormatter.date(from: dateStr) {
                return d
            }
            var unwrappedDict: [String: Any] = [:]
            for (k, v) in dict {
                unwrappedDict[k] = unwrapJSONValue(v)
            }
            return unwrappedDict
        } else if let arr = val as? [Any] {
            return arr.map { unwrapJSONValue($0) }
        }
        return val
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
        otherProfiles: [(fileName: String, text: String)] = [],
        includeResourceCache: Bool = true,
        root: URL,
        defaults: UserDefaults,
        prefs: [String: Any]? = nil
    ) throws -> String {
        let fm = FileManager.default
        var collectedFiles: [String: String] = [:]

        func readFileAsUTF8(_ rel: String) throws {
            let u = root.appendingPathComponent(rel)
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: u.path, isDirectory: &isDir), !isDir.boolValue else { return }
            guard let data = try? Data(contentsOf: u) else {
                throw TernBackupError.readFailed(String(localized: "无法读取文件：\(rel)"))
            }
            guard let str = String(data: data, encoding: .utf8) else {
                throw TernBackupError.readFailed(String(localized: "文件不是有效 UTF-8 文本：\(rel)"))
            }
            collectedFiles[rel] = str
        }

        func readDirContentsAsUTF8(_ rel: String) throws {
            let u = root.appendingPathComponent(rel)
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: u.path, isDirectory: &isDir), isDir.boolValue else { return }
            let names = (try? fm.contentsOfDirectory(atPath: u.path)) ?? []
            for n in names where !n.hasPrefix(".") {
                let f = u.appendingPathComponent(n)
                var sub: ObjCBool = false
                if fm.fileExists(atPath: f.path, isDirectory: &sub), !sub.boolValue {
                    let childRel = rel + "/" + n
                    guard let data = try? Data(contentsOf: f) else {
                        throw TernBackupError.readFailed(String(localized: "无法读取文件：\(childRel)"))
                    }
                    guard let str = String(data: data, encoding: .utf8) else {
                        throw TernBackupError.readFailed(String(localized: "文件不是有效 UTF-8 文本：\(childRel)"))
                    }
                    collectedFiles[childRel] = str
                }
            }
        }

        // 1. Profiles json
        try readFileAsUTF8("profiles.json")

        // 2. Subscriptions
        for path in subscriptionsPaths {
            try readFileAsUTF8(path)
        }

        // 3. Overrides
        for path in overridesPaths {
            try readFileAsUTF8(path)
        }

        // 4. Engine config
        try readFileAsUTF8(engineConfigPath)

        // 5. Resources (conditional)
        if includeResourceCache {
            for dirPrefix in ["mihomo/engine/modules", "mihomo/engine/scripts", "mihomo/override-scripts"] {
                try readDirContentsAsUTF8(dirPrefix)
            }
        }

        // 6. CA (ca.pem, ca.key)
        try readDirContentsAsUTF8("mihomo/engine/ca")

        // Defaults
        var collectedDefaults: [String: String] = [:]
        for k in BackupManager.defaultsKeys {
            if let v = defaults.string(forKey: k) {
                collectedDefaults[k] = v
            }
        }

        // Prefs
        var effectivePrefs: [String: Any]? = prefs
        if effectivePrefs == nil {
            var extracted: [String: Any] = [:]
            if defaults == AppShared.defaults {
                let rawPrefs = BackupManager.collectPrefs(group: AppShared.defaults)
                for (tagKey, b64) in rawPrefs {
                    if let d = Data(base64Encoded: b64),
                       let arr = try? PropertyListSerialization.propertyList(from: d, format: nil) as? [Any],
                       let first = arr.first,
                       let wrapped = wrapToJSONValue(first) {
                        extracted[tagKey] = wrapped
                    }
                }
            } else {
                for (k, v) in defaults.dictionaryRepresentation() where BackupManager.isBackedUpPref(k) {
                    if let wrapped = wrapToJSONValue(v) {
                        extracted["g:" + k] = wrapped
                    }
                }
            }
            if !extracted.isEmpty {
                effectivePrefs = extracted
            }
        }

        let appVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "1.0.0"
        let createdStr = isoFormatter.string(from: Date())

        var out = ""
        // Header
        out.append("; Tern 完整备份\n")
        out.append("; 格式版本：v3-final。已知约束：节体中若有独占一行形如 [section]，会被误判为节头。\n")
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
        out.append("\n")

        // [profile]
        if let text = profileText, !text.isEmpty {
            out.append("[profile]\n")
            out.append(text)
            if !text.hasSuffix("\n") {
                out.append("\n")
            }
            out.append("\n")
        }

        // [profile <fileName>]
        for item in otherProfiles {
            let fileName = item.fileName.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !fileName.isEmpty else { continue }
            out.append("[profile \(fileName)]\n")
            out.append(item.text)
            if !item.text.hasSuffix("\n") {
                out.append("\n")
            }
            out.append("\n")
        }

        // [json <relPath>] and [text <relPath>] sorted
        for (relPath, content) in collectedFiles.sorted(by: { $0.key < $1.key }) {
            let isJSON = relPath.hasSuffix(".json")
            let header = isJSON ? "[json \(relPath)]" : "[text \(relPath)]"
            out.append("\(header)\n")
            out.append(content)
            if !content.hasSuffix("\n") {
                out.append("\n")
            }
            out.append("\n")
        }

        // [prefs]
        if let prefs = effectivePrefs, !prefs.isEmpty {
            let jsonData = try JSONSerialization.data(withJSONObject: prefs, options: [.prettyPrinted, .sortedKeys])
            if let jsonStr = String(data: jsonData, encoding: .utf8) {
                out.append("[prefs]\n")
                out.append(jsonStr)
                if !jsonStr.hasSuffix("\n") {
                    out.append("\n")
                }
                out.append("\n")
            }
        }

        // [defaults]
        if !collectedDefaults.isEmpty {
            out.append("[defaults]\n")
            for (k, v) in collectedDefaults.sorted(by: { $0.key < $1.key }) {
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
        let activeProfile = ProfileStore.shared.active
        let profileText = activeProfile.map { ProfileStore.shared.content(of: $0) }
        let profileName = activeProfile?.name

        var otherProfiles: [(fileName: String, text: String)] = []
        for p in ProfileStore.shared.profiles where p.id != activeProfile?.id {
            let fileName = p.fileURL.lastPathComponent
            let text = ProfileStore.shared.content(of: p)
            if !text.isEmpty {
                otherProfiles.append((fileName: fileName, text: text))
            }
        }

        let rawPrefs = BackupManager.collectPrefs(group: AppShared.defaults)
        var jsonPrefs: [String: Any] = [:]
        for (tagKey, b64) in rawPrefs {
            if let d = Data(base64Encoded: b64),
               let arr = try? PropertyListSerialization.propertyList(from: d, format: nil) as? [Any],
               let first = arr.first,
               let wrapped = wrapToJSONValue(first) {
                jsonPrefs[tagKey] = wrapped
            }
        }

        return try build(
            profileText: profileText,
            profileName: profileName,
            otherProfiles: otherProfiles,
            includeResourceCache: includeResourceCache,
            root: root,
            defaults: AppShared.defaults,
            prefs: jsonPrefs.isEmpty ? nil : jsonPrefs
        )
    }

    // MARK: - parse

    public static func parse(_ text: String) throws -> Parsed {
        guard containsBackup(text) else {
            throw TernBackupError.notABackup
        }

        struct SectionRecord {
            let header: String
            var lines: [String]
        }

        var sections: [SectionRecord] = []
        var currentSection: SectionRecord?
        var hasSeenEnd = false

        for rawLine in text.components(separatedBy: .newlines) {
            let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("[") && trimmed.hasSuffix("]") {
                let isKnownHeader = trimmed == "[general]" ||
                    trimmed == "[profile]" ||
                    trimmed.hasPrefix("[profile ") ||
                    trimmed.hasPrefix("[json ") ||
                    trimmed.hasPrefix("[text ") ||
                    trimmed == "[prefs]" ||
                    trimmed == "[defaults]" ||
                    trimmed == "[end]"

                if isKnownHeader {
                    if let cur = currentSection {
                        sections.append(cur)
                    }
                    if trimmed == "[end]" {
                        hasSeenEnd = true
                        currentSection = SectionRecord(header: trimmed, lines: [])
                    } else {
                        currentSection = SectionRecord(header: trimmed, lines: [])
                    }
                    continue
                }
            }

            if currentSection != nil {
                currentSection?.lines.append(rawLine)
            }
        }

        if let cur = currentSection {
            sections.append(cur)
        }

        // 1. Mandatory [end] marker
        guard hasSeenEnd else {
            throw TernBackupError.corrupt(String(localized: "缺少 [end] 结束标记"))
        }

        // 2. [general] section
        guard let generalSec = sections.first(where: { $0.header == "[general]" }) else {
            throw TernBackupError.notABackup
        }

        var generalKV: [String: String] = [:]
        for line in generalSec.lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix(";") || trimmed.hasPrefix("#") { continue }
            let parts = trimmed.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            if parts.count == 2 {
                generalKV[parts[0]] = parts[1]
            }
        }

        guard generalKV["tern_backup"] == "1" else {
            throw TernBackupError.notABackup
        }

        guard let formatStr = generalKV["format"], let format = Int(formatStr) else {
            throw TernBackupError.notABackup
        }

        guard format == currentFormat else {
            throw TernBackupError.unsupportedVersion(format)
        }

        let created = generalKV["created"] ?? ""
        let appVersion = generalKV["app_version"] ?? "?"
        let profileName = generalKV["profile"]

        var profileText: String?
        var otherProfiles: [(fileName: String, text: String)] = []
        var files: [String: Data] = [:]
        var parsedPrefs: [String: Any]?
        var defaultsKV: [String: String] = [:]

        // Check if [general] declared profile name, then [profile] must exist
        let hasDeclaredProfile = profileName != nil && !profileName!.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        var foundProfileSection = false

        for sec in sections {
            let header = sec.header
            // Strip at most one trailing blank line separating sections
            var bodyLines = sec.lines
            var strippedTrailingEmpty = false
            if bodyLines.last?.isEmpty == true {
                bodyLines.removeLast()
                strippedTrailingEmpty = true
            }
            var body = bodyLines.joined(separator: "\n")
            let isByteSection = header == "[profile]" ||
                header.hasPrefix("[profile ") ||
                header.hasPrefix("[json ") ||
                header.hasPrefix("[text ")
            if isByteSection && strippedTrailingEmpty && !body.isEmpty {
                body += "\n"
            }

            if header == "[profile]" {
                foundProfileSection = true
                profileText = body
            } else if header.hasPrefix("[profile ") {
                let fileName = String(header.dropFirst(9).dropLast(1)).trimmingCharacters(in: .whitespaces)
                guard !fileName.isEmpty, !fileName.contains(".."), !fileName.hasPrefix("/") else {
                    throw TernBackupError.corrupt(String(localized: "非法配置路径：\(fileName)"))
                }
                otherProfiles.append((fileName: fileName, text: body))
            } else if header.hasPrefix("[json ") {
                let rel = String(header.dropFirst(6).dropLast(1)).trimmingCharacters(in: .whitespaces)
                guard !rel.isEmpty, !rel.contains(".."), !rel.hasPrefix("/") else {
                    throw TernBackupError.corrupt(String(localized: "非法文件路径：\(rel)"))
                }
                guard let data = body.data(using: .utf8), (try? JSONSerialization.jsonObject(with: data)) != nil else {
                    throw TernBackupError.corrupt(String(localized: "JSON 解析失败：\(rel)"))
                }
                files[rel] = data
            } else if header.hasPrefix("[text ") {
                let rel = String(header.dropFirst(6).dropLast(1)).trimmingCharacters(in: .whitespaces)
                guard !rel.isEmpty, !rel.contains(".."), !rel.hasPrefix("/") else {
                    throw TernBackupError.corrupt(String(localized: "非法文件路径：\(rel)"))
                }
                guard let data = body.data(using: .utf8) else {
                    throw TernBackupError.corrupt(String(localized: "文本编码失败：\(rel)"))
                }
                files[rel] = data
            } else if header == "[prefs]" {
                guard let data = body.data(using: .utf8),
                      let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                    throw TernBackupError.corrupt(String(localized: "prefs 节不是有效的 JSON 对象"))
                }
                parsedPrefs = json
            } else if header == "[defaults]" {
                for line in bodyLines {
                    let trimmed = line.trimmingCharacters(in: .whitespaces)
                    if trimmed.isEmpty || trimmed.hasPrefix(";") || trimmed.hasPrefix("#") { continue }
                    let parts = trimmed.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                    if parts.count == 2 {
                        defaultsKV[parts[0]] = parts[1]
                    }
                }
            }
        }

        if hasDeclaredProfile && !foundProfileSection {
            throw TernBackupError.corrupt(String(localized: "声明了活动配置但缺少 [profile] 节"))
        }

        // Category classification
        var categoryFiles: [String: [String]] = [
            "profiles": [],
            "subscriptions": [],
            "overrides": [],
            "engine": [],
            "resources": [],
            "ca": [],
            "settings": []
        ]

        if files["profiles.json"] != nil {
            categoryFiles["profiles"]?.append("profiles.json")
        }

        if profileText != nil {
            var activeFileName: String?
            if let pData = files["profiles.json"],
               let pList = try? JSONDecoder().decode([Profile].self, from: pData) {
                let targetID = defaultsKV["activeProfileID"]
                if let targetID = targetID, let found = pList.first(where: { $0.id == targetID }) {
                    activeFileName = found.fileURL.lastPathComponent
                } else if let first = pList.first {
                    activeFileName = first.fileURL.lastPathComponent
                }
            }
            if let afn = activeFileName {
                categoryFiles["profiles"]?.append("profiles/\(afn)")
            }
        }

        for (fn, _) in otherProfiles {
            categoryFiles["profiles"]?.append("profiles/\(fn)")
        }

        for path in files.keys.sorted() {
            guard let cat = category(forPath: path) else {
                throw TernBackupError.corrupt(String(localized: "未知文件分类：\(path)"))
            }
            if cat != "profiles" {
                categoryFiles[cat, default: []].append(path)
            }
        }

        return Parsed(
            format: format,
            created: created,
            appVersion: appVersion,
            profileName: profileName,
            profileText: profileText,
            otherProfiles: otherProfiles,
            files: files,
            prefs: parsedPrefs,
            defaults: defaultsKV,
            categoryFiles: categoryFiles
        )
    }

    // MARK: - apply

    @discardableResult
    public static func apply(
        _ parsed: Parsed,
        selection: [String: Mode],
        root: URL,
        defaults: UserDefaults
    ) throws -> Int {
        let fm = FileManager.default
        var writtenCount = 0

        // 1. Overwrite cleanup: delete existing files not in package for selected categories
        for (catId, mode) in selection where mode == .overwrite {
            let packageFiles = Set(parsed.categoryFiles[catId] ?? [])

            switch catId {
            case "profiles":
                let profilesJsonURL = root.appendingPathComponent("profiles.json")
                if fm.fileExists(atPath: profilesJsonURL.path) && !packageFiles.contains("profiles.json") {
                    try? fm.removeItem(at: profilesJsonURL)
                }
                let profilesDir = root.appendingPathComponent("profiles")
                if let names = try? fm.contentsOfDirectory(atPath: profilesDir.path) {
                    for n in names where !n.hasPrefix(".") {
                        let rel = "profiles/" + n
                        if !packageFiles.contains(rel) {
                            try? fm.removeItem(at: root.appendingPathComponent(rel))
                        }
                    }
                }

            case "subscriptions":
                for rel in subscriptionsPaths {
                    if !packageFiles.contains(rel) {
                        let u = root.appendingPathComponent(rel)
                        if fm.fileExists(atPath: u.path) {
                            try? fm.removeItem(at: u)
                        }
                    }
                }

            case "overrides":
                for rel in overridesPaths {
                    if !packageFiles.contains(rel) {
                        let u = root.appendingPathComponent(rel)
                        if fm.fileExists(atPath: u.path) {
                            try? fm.removeItem(at: u)
                        }
                    }
                }

            case "engine":
                if !packageFiles.contains(engineConfigPath) {
                    let u = root.appendingPathComponent(engineConfigPath)
                    if fm.fileExists(atPath: u.path) {
                        try? fm.removeItem(at: u)
                    }
                }

            case "resources":
                for prefix in resourceDirectoryPrefixes {
                    let dir = root.appendingPathComponent(prefix)
                    if let names = try? fm.contentsOfDirectory(atPath: dir.path) {
                        for n in names where !n.hasPrefix(".") {
                            let rel = prefix + n
                            if !packageFiles.contains(rel) {
                                try? fm.removeItem(at: root.appendingPathComponent(rel))
                            }
                        }
                    }
                }

            case "ca":
                let dir = root.appendingPathComponent(caDirectoryPrefix)
                if let names = try? fm.contentsOfDirectory(atPath: dir.path) {
                    for n in names where !n.hasPrefix(".") {
                        let rel = caDirectoryPrefix + n
                        if !packageFiles.contains(rel) {
                            try? fm.removeItem(at: root.appendingPathComponent(rel))
                        }
                    }
                }

            default:
                break
            }
        }

        // 2. Write profiles category
        if selection["profiles"] != nil {
            if let pData = parsed.files["profiles.json"] {
                let u = root.appendingPathComponent("profiles.json")
                AppShared.ensureDir(u.deletingLastPathComponent())
                try pData.write(to: u, options: .atomic)
                writtenCount += 1
            }

            if let pText = parsed.profileText, let textData = pText.data(using: .utf8) {
                var activeFileName: String?
                if let pData = parsed.files["profiles.json"],
                   let pList = try? JSONDecoder().decode([Profile].self, from: pData) {
                    let targetID = parsed.defaults["activeProfileID"] ?? defaults.string(forKey: "activeProfileID")
                    if let targetID = targetID, let found = pList.first(where: { $0.id == targetID }) {
                        activeFileName = found.fileURL.lastPathComponent
                    } else if let first = pList.first {
                        activeFileName = first.fileURL.lastPathComponent
                    }
                }
                if let fileName = activeFileName {
                    let u = root.appendingPathComponent("profiles/" + fileName)
                    AppShared.ensureDir(u.deletingLastPathComponent())
                    try textData.write(to: u, options: .atomic)
                    writtenCount += 1
                }
            }

            for item in parsed.otherProfiles {
                if let textData = item.text.data(using: .utf8) {
                    let u = root.appendingPathComponent("profiles/" + item.fileName)
                    AppShared.ensureDir(u.deletingLastPathComponent())
                    try textData.write(to: u, options: .atomic)
                    writtenCount += 1
                }
            }
        }

        // 3. Write non-profile file categories
        for (relPath, data) in parsed.files {
            guard let cat = category(forPath: relPath) else { continue }
            if cat == "profiles" { continue }
            if selection[cat] != nil {
                let u = root.appendingPathComponent(relPath)
                AppShared.ensureDir(u.deletingLastPathComponent())
                try data.write(to: u, options: .atomic)
                if relPath.hasSuffix("ca.key") {
                    try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: u.path)
                }
                writtenCount += 1
            }
        }

        // 4. Apply settings category
        if selection["settings"] != nil {
            for (k, v) in parsed.defaults where BackupManager.defaultsKeys.contains(k) {
                defaults.set(v, forKey: k)
            }
            if let prefs = parsed.prefs {
                for (tagged, val) in prefs {
                    let tag = tagged.prefix(2)
                    let key = (tagged.hasPrefix("g:") || tagged.hasPrefix("s:")) ? String(tagged.dropFirst(2)) : tagged
                    guard BackupManager.isBackedUpPref(key) else { continue }
                    let unwrapped = unwrapJSONValue(val)
                    if defaults == AppShared.defaults {
                        if tag == "g:" {
                            defaults.set(unwrapped, forKey: key)
                        } else if tag == "s:" {
                            UserDefaults.standard.set(unwrapped, forKey: key)
                        } else {
                            defaults.set(unwrapped, forKey: key)
                        }
                    } else {
                        defaults.set(unwrapped, forKey: key)
                    }
                }
            }
        }

        return writtenCount
    }
}
