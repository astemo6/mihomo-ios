import CryptoKit
import Foundation

/// E-B1 stage 2 (foundation): the runtime builder's tree helpers and
/// store readers — ports of the bridge's small accessors (str / strList
/// / boolOf / intOf / asList / asMap in bridge/bridge.go) and of the
/// per-profile store readers buildRuntimeWith consults
/// (provider-overrides.json, group-edits.json, subscriptions.json,
/// groups.json, proxy-chains.json, rules.json). The config tree is
/// [String: NCJSONValue], the same representation NCGroupEditing
/// (B5) already builds group edits against.

// MARK: - Tree accessors (bridge str / strList / boolOf / intOf)

extension Dictionary where Key == String, Value == NCJSONValue {
    func str(_ key: String) -> String {
        if case .string(let s)? = self[key] { return s }
        return ""
    }
    func boolOf(_ key: String) -> Bool {
        if case .bool(let b)? = self[key] { return b }
        return false
    }
    func intOf(_ key: String) -> Int {
        if case .number(let n)? = self[key] { return Int(n) }
        if case .string(let s)? = self[key] { return Int(s) ?? 0 }
        return 0
    }
    func list(_ key: String) -> [NCJSONValue] {
        if case .array(let a)? = self[key] { return a }
        return []
    }
    func map(_ key: String) -> [String: NCJSONValue] {
        if case .object(let o)? = self[key] { return o }
        return [:]
    }
    func strList(_ key: String) -> [String] {
        list(key).compactMap { if case .string(let s) = $0 { return s }; return nil }
    }
}

extension NCJSONValue {
    var strValue: String {
        if case .string(let s) = self { return s }
        return ""
    }
    var boolValue: Bool {
        if case .bool(let b) = self { return b }
        return false
    }
    /// JSON-shaped Any tree (for JSONSerialization / NCYAMLEmitter).
    var anyTree: Any {
        switch self {
        case .null: return NSNull()
        case .bool(let b): return b
        case .number(let n): return n
        case .string(let s): return s
        case .array(let a): return a.map { $0.anyTree }
        case .object(let o): return o.mapValues { $0.anyTree }
        }
    }
    static func fromAny(_ v: Any) -> NCJSONValue {
        switch v {
        case is NSNull: return .null
        case let b as Bool: return .bool(b)
        case let n as NSNumber: return .number(n.doubleValue)
        case let s as String: return .string(s)
        case let a as [Any]: return .array(a.map { fromAny($0) })
        case let o as [String: Any]: return .object(o.mapValues { fromAny($0) })
        case let v as NCJSONValue: return v
        default: return .null
        }
    }
}

// MARK: - provider-overrides.json (bridge provideroverrides.go)

struct NCProfileRuleOverride: Codable {
    var rule: String = ""
    var index: Int = 0
    var line: String? = nil
    var disabled: Bool? = nil
    var deleted: Bool? = nil
}

struct NCProviderOverride: Codable {
    var disabled: Bool? = nil
    var deleted: Bool? = nil
    var name: String? = nil
    var icon: String? = nil
    var url: String? = nil
    var interval: Int? = nil
    var filter: String? = nil
    var excludeFilter: String? = nil
    /// rule-provider overrides only (key "rule:<name>").
    var policy: String? = nil
    /// only on the rule-order entry.
    var order: [String]? = nil
    /// only on the profile-rules entry.
    var rules: [NCProfileRuleOverride]? = nil
}

// MARK: - subscriptions.json (bridge subrules.go SubRules)

struct NCSubRules: Codable {
    struct RenameRule: Codable {
        var pattern: String = ""
        var replace: String = ""
        var enabled: Bool? = nil
    }
    var enabled: Bool = false
    var include: String? = nil
    var exclude: String? = nil
    var regex: Bool? = nil
    var stripPrefixes: [String]? = nil
    var stripFlags: Bool? = nil
    var renames: [RenameRule]? = nil
    var addFlag: Bool? = nil
    var prefix: String? = nil
    var dedupe: Bool? = nil
    /// "" keep | name | region
    var sort: String? = nil
}

// MARK: - proxy-chains.json (bridge proxychains.go)

struct NCProxyChain: Codable {
    var id: String = ""
    var name: String = ""
    var udp: Bool = false
    var enabled: Bool = false
    var members: [String] = []
}

// MARK: - Store readers

enum NCRuntimeFiles {
    static func profileID(fromPath path: String) -> String {
        let base = (path as NSString).lastPathComponent
        return (base as NSString).deletingPathExtension
    }

    static func homeURL(_ home: String) -> URL { URL(fileURLWithPath: home) }

    static func readJSON<T: Decodable>(_ type: T.Type, home: String, file: String) -> T? {
        if home.isEmpty { return nil }
        guard let data = try? Data(contentsOf: homeURL(home).appendingPathComponent(file)) else { return nil }
        return try? JSONDecoder().decode(type, from: data)
    }

    /// bridge readProviderOverrides: nil unless home/profile are set.
    static func readProviderOverrides(home: String, profileID: String) -> [String: NCProviderOverride]? {
        if home.isEmpty || profileID.isEmpty { return nil }
        let all = readJSON([String: [String: NCProviderOverride]].self,
                           home: home, file: "provider-overrides.json") ?? [:]
        return all[profileID]
    }

    /// bridge readGroupEdits.
    static func readGroupEdits(home: String, profileID: String) -> GroupEdits? {
        if home.isEmpty || profileID.isEmpty { return nil }
        let all = readJSON([String: GroupEdits].self, home: home, file: "group-edits.json") ?? [:]
        return all[profileID]
    }

    /// bridge readAllSubRules.
    static func readAllSubRules(home: String) -> [String: NCSubRules] {
        if home.isEmpty { return [:] }
        return readJSON([String: NCSubRules].self, home: home, file: "subscriptions.json") ?? [:]
    }

    /// bridge readGroupChains: groups.json[profileID].dialer.
    static func readGroupChains(home: String, profilePath: String) -> [String: String] {
        struct GroupSettings: Decodable { var dialer: [String: String]? }
        if home.isEmpty { return [:] }
        let all = readJSON([String: GroupSettings].self, home: home, file: "groups.json") ?? [:]
        return all[profileID(fromPath: profilePath)]?.dialer ?? [:]
    }

    /// bridge readProxyChains.
    static func readProxyChains(home: String) -> [NCProxyChain] {
        if home.isEmpty { return [] }
        return readJSON([NCProxyChain].self, home: home, file: "proxy-chains.json") ?? []
    }

    /// bridge scriptedFor / readRuntimeProfile: the stored override-
    /// script output for a profile, used only when its recorded
    /// SHA-256 matches the current profile bytes. Returns the profile
    /// bytes themselves when safe mode, no output, or stale output.
    static func readRuntimeProfile(home: String, path: String, safe: Bool) -> Data? {
        guard let source = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        if safe || home.isEmpty { return source }
        let id = profileID(fromPath: path)
        let dir = homeURL(home).appendingPathComponent("scripted")
        struct Meta: Decodable { var source: String }
        guard let metaData = try? Data(contentsOf: dir.appendingPathComponent(id + ".json")),
              let meta = try? JSONDecoder().decode(Meta.self, from: metaData),
              !meta.source.isEmpty,
              meta.source == sha256Hex(source),
              let out = try? Data(contentsOf: dir.appendingPathComponent(id + ".yaml")),
              !out.isEmpty else { return source }
        return out
    }

    static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// Atomic write (write to <path>.tmp, then rename), the bridge's
    /// writeAtomicFile.
    static func writeAtomic(_ data: Data, to path: String) throws {
        let tmp = path + ".tmp"
        try data.write(to: URL(fileURLWithPath: tmp))
        let fm = FileManager.default
        if fm.fileExists(atPath: path) { try fm.removeItem(atPath: path) }
        try fm.moveItem(atPath: tmp, toPath: path)
    }
}
