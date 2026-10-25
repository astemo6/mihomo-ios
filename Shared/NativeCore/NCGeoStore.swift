import Foundation
import JavaScriptCore
#if canImport(Darwin)
import Darwin
#endif

/// NCGeoFile represents one geo database entry matching Go's geoFile JSON structure.
public struct NCGeoFile: Codable, Equatable, Identifiable {
    public var id: String { kind }
    public var kind: String
    public var file: String
    public var remote: String
    public var exists: Bool
    public var size: Int64
    public var modified: Double?
    public var buildDate: Double?
    public var dbType: String?
    public var error: String?

    public init(
        kind: String,
        file: String,
        remote: String,
        exists: Bool = false,
        size: Int64 = 0,
        modified: Double? = nil,
        buildDate: Double? = nil,
        dbType: String? = nil,
        error: String? = nil
    ) {
        self.kind = kind
        self.file = file
        self.remote = remote
        self.exists = exists
        self.size = size
        self.modified = modified
        self.buildDate = buildDate
        self.dbType = dbType
        self.error = error
    }
}

/// Errors thrown by NCGeoStore operations.
public enum NCGeoError: LocalizedError, Equatable {
    case unknownKind(String)
    case fileTooSmall(Int)
    case invalidMMDB(String)
    case invalidDat(String)
    case custom(String)

    public var errorDescription: String? {
        switch self {
        case .unknownKind(let kind):
            return "未知的数据库 \(kind)"
        case .fileTooSmall(let bytes):
            return "文件过小（\(bytes) 字节），可能被拦截"
        case .invalidMMDB(let reason):
            return "不是有效的 MMDB：\(reason)"
        case .invalidDat(let name):
            return "不是有效的 \(name)"
        case .custom(let msg):
            return msg
        }
    }
}

/// Result returned by locationRun matching Go's geoResult JSON structure.
public struct NCGeoLocationResult: Codable, Equatable {
    public var title: String?
    public var subtitle: String?
    public var ip: String?
    public var description: String?
    public var error: String?

    public init(
        title: String? = nil,
        subtitle: String? = nil,
        ip: String? = nil,
        description: String? = nil,
        error: String? = nil
    ) {
        self.title = title
        self.subtitle = subtitle
        self.ip = ip
        self.description = description
        self.error = error
    }
}

/// Pure Swift implementation of geo database info, download mirror URLs, file installation,
/// and exit IP location checking script execution. Pure Swift replacement for legacy Go bridge Geo calls.
public enum NCGeoStore {
    public static let knownKinds: [NCGeoFile] = [
        NCGeoFile(kind: "mmdb", file: "geoip.metadb", remote: "geoip.metadb"),
        NCGeoFile(kind: "geosite", file: "GeoSite.dat", remote: "geosite.dat"),
        NCGeoFile(kind: "asn", file: "ASN.mmdb", remote: "GeoLite2-ASN.mmdb"),
        NCGeoFile(kind: "geoip", file: "GeoIP.dat", remote: "geoip.dat")
    ]

    /// Finds file in dir case-insensitively, matching mihomo's findCI behavior.
    public static func findCI(dir: String, name: String) -> String {
        let fm = FileManager.default
        if let entries = try? fm.contentsOfDirectory(atPath: dir) {
            for entry in entries {
                if entry.caseInsensitiveCompare(name) == .orderedSame {
                    let full = (dir as NSString).appendingPathComponent(entry)
                    var isDir: ObjCBool = false
                    if fm.fileExists(atPath: full, isDirectory: &isDir), !isDir.boolValue {
                        return full
                    }
                }
            }
        }
        return (dir as NSString).appendingPathComponent(name)
    }

    /// Inspects home directory for database file presence, size, modification timestamp,
    /// and MMDB metadata.
    public static func describe(homeDir: String, template: NCGeoFile) -> NCGeoFile {
        var g = template
        let p = findCI(dir: homeDir, name: g.file)
        let fm = FileManager.default
        guard let attrs = try? fm.attributesOfItem(atPath: p),
              let size = attrs[.size] as? NSNumber else {
            return g
        }
        g.exists = true
        g.size = size.int64Value
        if let modDate = attrs[.modificationDate] as? Date {
            g.modified = modDate.timeIntervalSince1970
        }
        if g.file.hasSuffix("mmdb") || g.file.hasSuffix("metadb") {
            if let mmdb = NCMMDB(contentsOfFile: p) {
                g.buildDate = mmdb.buildEpoch
                g.dbType = mmdb.databaseType
            } else {
                g.error = "不是有效的 MMDB"
            }
        }
        return g
    }

    /// Returns list of all geo database files described in homeDir.
    public static func files(homeDir: String) -> [NCGeoFile] {
        knownKinds.map { describe(homeDir: homeDir, template: $0) }
    }

    /// Returns JSON array string matching Go's GeoInfo(homeDir).
    public static func info(homeDir: String) -> String {
        let list = files(homeDir: homeDir)
        let encoder = JSONEncoder()
        encoder.outputFormatting = []
        if let data = try? encoder.encode(list), let s = String(data: data, encoding: .utf8) {
            return s
        }
        return "[]"
    }

    public static let defaultMirrorBase = "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/"

    /// Returns download base URL for meta-rules-dat files for a mirror name.
    public static func baseURL(for mirror: String) -> String {
        switch mirror {
        case "fastly":
            return "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/"
        case "github":
            return "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/"
        default:
            return defaultMirrorBase
        }
    }

    /// Normalises a user mirror base for GeoMirror "custom": https only, with a host, ending in "/".
    /// Returns nil when base is not usable (the jsDelivr default is used then).
    public static func customBase(_ base: String) -> String? {
        let trimmed = base.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              !trimmed.contains(" "),
              !trimmed.contains("\t"),
              let u = URLComponents(string: trimmed),
              u.scheme?.caseInsensitiveCompare("https") == .orderedSame,
              let host = u.host, !host.isEmpty,
              u.query == nil, u.fragment == nil else {
            return nil
        }
        return trimmed.hasSuffix("/") ? trimmed : trimmed + "/"
    }

    /// Computes effective base URL based on mirror mode and custom base.
    public static func effectiveBase(mirror: String, base: String) -> String {
        if mirror == "custom" {
            if let b = customBase(base), !b.isEmpty {
                return b
            }
            return defaultMirrorBase
        }
        return baseURL(for: mirror)
    }

    /// Remote file name for database kind in meta-rules-dat.
    public static func remoteFileName(for kind: String) -> String? {
        switch kind {
        case "mmdb": return "geoip.metadb"
        case "geosite": return "geosite.dat"
        case "asn": return "GeoLite2-ASN.mmdb"
        case "geoip": return "geoip.dat"
        default: return nil
        }
    }

    /// Constructs mirror download URL for kind, mirror mode, and custom base. Matches Go's GeoMirrorURL.
    public static func mirrorURL(kind: String, mirror: String, base: String) -> String {
        guard let remote = remoteFileName(for: kind) else { return "" }
        return effectiveBase(mirror: mirror, base: base) + remote
    }

    /// Validates downloaded file content before installation.
    public static func validate(name: String, data: Data) throws {
        if data.count < 1024 {
            throw NCGeoError.fileTooSmall(data.count)
        }
        if name.hasSuffix("mmdb") || name.hasSuffix("metadb") {
            guard let _ = NCMMDB(data: data) else {
                throw NCGeoError.invalidMMDB("无法解析元数据")
            }
            return
        }
        // .dat files are protobuf lists (field 1, length-delimited) — reject HTML error pages.
        guard let firstByte = data.first else {
            throw NCGeoError.invalidDat(name)
        }
        let prefix64 = data.prefix(64)
        let trimmedPrefix = prefix64.drop(while: { $0 == 0x20 || $0 == 0x09 || $0 == 0x0a || $0 == 0x0d })
        if firstByte != 0x0a || trimmedPrefix.first == 0x3c /* '<' */ {
            throw NCGeoError.invalidDat(name)
        }
    }

    /// Validates a downloaded database file at path and atomically moves it into homeDir.
    /// Matches Go's GeoInstallFile. Always deletes path before returning.
    @discardableResult
    public static func installFile(homeDir: String, kind: String, path: String) throws -> String {
        guard let target = knownKinds.first(where: { $0.kind == kind }) else {
            throw NCGeoError.unknownKind(kind)
        }
        let fm = FileManager.default
        let fileURL = URL(fileURLWithPath: path)
        let data: Data
        do {
            data = try Data(contentsOf: fileURL)
        } catch {
            try? fm.removeItem(at: fileURL)
            throw error
        }
        try? fm.removeItem(at: fileURL)

        try validate(name: target.file, data: data)

        let dst = findCI(dir: homeDir, name: target.file)
        let tmp = dst + ".download"
        let tmpURL = URL(fileURLWithPath: tmp)

        do {
            try data.write(to: tmpURL, options: .atomic)
        } catch {
            throw error
        }

        let renameSuccess = tmp.withCString { oldP in
            dst.withCString { newP in
                rename(oldP, newP) == 0
            }
        }

        if !renameSuccess {
            try? fm.removeItem(at: tmpURL)
            let msg = String(cString: strerror(errno))
            throw NCGeoError.custom("安装失败：\(msg)")
        }

        let described = describe(homeDir: homeDir, template: target)
        let encoder = JSONEncoder()
        encoder.outputFormatting = []
        if let resData = try? encoder.encode(described), let s = String(data: resData, encoding: .utf8) {
            return s
        }
        return "{}"
    }

    /// Runs a QX geo_location_checker script on an API reply body using JavaScriptCore.
    /// Returns geoResult as JSON matching Go's GeoLocationRun.
    public static func locationRun(homeDir: String, code: String, apiURL: String, body: String) -> String {
        let trimmedCode = code.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmedCode.isEmpty {
            return encodeResult(NCGeoLocationResult(error: "没有脚本内容"))
        }

        guard let context = JSContext() else {
            return encodeResult(NCGeoLocationResult(error: "无法创建脚本引擎"))
        }

        var executionError: String? = nil
        context.exceptionHandler = { _, exception in
            if let exc = exception {
                executionError = exc.toString()
            }
        }

        var doneCalled = false
        var donePayload: [String: Any]? = nil
        var parseError: String? = nil

        let doneBlock: @convention(block) (JSValue?) -> Void = { val in
            doneCalled = true
            guard let val = val else { return }
            if val.isNull || val.isUndefined {
                donePayload = [:]
            } else if val.isObject {
                if let dict = val.toDictionary() as? [String: Any] {
                    donePayload = dict
                } else {
                    parseError = "脚本结果无法解析"
                }
            } else {
                parseError = "脚本结果无法解析"
            }
        }
        context.setObject(doneBlock, forKeyedSubscript: "$done" as NSString)

        let effectiveURL = apiURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "http://ip-api.com/json" : apiURL
        let requestObj: [String: Any] = [
            "url": effectiveURL,
            "method": "GET",
            "headers": [String: String]()
        ]
        context.setObject(requestObj, forKeyedSubscript: "$request" as NSString)

        let responseObj: [String: Any] = [
            "status": 200,
            "statusCode": 200,
            "headers": ["Content-Type": "application/json"],
            "body": body
        ]
        context.setObject(responseObj, forKeyedSubscript: "$response" as NSString)

        // Safe standard dummies for common QX/Surge scripts
        let noopBlock: @convention(block) () -> Void = {}
        let consoleObj: [String: Any] = [
            "log": noopBlock,
            "warn": noopBlock,
            "error": noopBlock,
            "info": noopBlock
        ]
        context.setObject(consoleObj, forKeyedSubscript: "console" as NSString)

        let readBlock: @convention(block) (String?) -> String? = { _ in nil }
        let writeBlock: @convention(block) (String?, String?) -> Bool = { _, _ in true }
        let persistentStoreObj: [String: Any] = [
            "read": readBlock,
            "write": writeBlock
        ]
        context.setObject(persistentStoreObj, forKeyedSubscript: "$persistentStore" as NSString)
        context.setObject(persistentStoreObj, forKeyedSubscript: "$prefs" as NSString)

        context.setObject(noopBlock, forKeyedSubscript: "$notify" as NSString)
        context.setObject(noopBlock, forKeyedSubscript: "$notification" as NSString)

        let setTimeoutBlock: @convention(block) (JSValue?, Double) -> Int = { fn, _ in
            fn?.call(withArguments: [])
            return 1
        }
        let clearTimeoutBlock: @convention(block) (Int) -> Void = { _ in }
        context.setObject(setTimeoutBlock, forKeyedSubscript: "setTimeout" as NSString)
        context.setObject(clearTimeoutBlock, forKeyedSubscript: "clearTimeout" as NSString)

        // Run the script
        context.evaluateScript(code)

        if let err = executionError {
            return encodeResult(NCGeoLocationResult(error: err))
        }

        if !doneCalled {
            return encodeResult(NCGeoLocationResult(error: "脚本没有调用 $done"))
        }

        if let pe = parseError {
            return encodeResult(NCGeoLocationResult(error: pe))
        }

        guard let payload = donePayload else {
            return encodeResult(NCGeoLocationResult(error: "脚本没有调用 $done"))
        }

        func strVal(_ key: String) -> String? {
            guard let v = payload[key] else { return nil }
            if let s = v as? String {
                let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
                return t.isEmpty ? nil : t
            }
            if let n = v as? NSNumber {
                return n.stringValue
            }
            return nil
        }

        let title = strVal("title")
        let subtitle = strVal("subtitle")
        let ip = strVal("ip")
        let description = strVal("description")

        if (title == nil || title?.isEmpty == true) && (subtitle == nil || subtitle?.isEmpty == true) {
            return encodeResult(NCGeoLocationResult(error: "脚本结果没有 title / subtitle"))
        }

        return encodeResult(NCGeoLocationResult(
            title: title,
            subtitle: subtitle,
            ip: ip,
            description: description,
            error: nil
        ))
    }

    private static func encodeResult(_ res: NCGeoLocationResult) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = []
        if let data = try? encoder.encode(res), let s = String(data: data, encoding: .utf8) {
            return s
        }
        return "{}"
    }
}
