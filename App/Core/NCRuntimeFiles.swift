import CryptoKit
import Foundation

/// E-B1 stage 2 (foundation): the runtime builder's tree helpers and
/// store readers — ports of the bridge's small accessors (str / strList
/// / boolOf / intOf / asList / asMap in the retired bridge) and of the
/// per-profile store readers buildRuntimeWith consults
/// (provider-overrides.json, group-edits.json, subscriptions.json,
/// groups.json, proxy-chains.json, rules.json). The config tree is
/// [String: NCJSONValue], the same representation NCGroupEditing
/// (B5) already builds group edits against.

// MARK: - Tree accessors (bridge str / strList / boolOf / intOf)
//
// Review R-4: these follow the old core's inspect.go semantics on the go.yaml.in/yaml/v3
// tree exactly. yaml v3 keeps `yes` / `on` / `no` / `off` as STRINGS (only
// true/false are bools), so the old core helpers coerce:
//   str(v)     string as-is; nil -> ""; anything else fmt.Sprint(v)
//              (so `name: 123` reads "123", `name: true` reads "true")
//   boolOf(v)  bool as-is; string -> truthy (1/true/yes/on, trimmed, any case)
//   intOf(v)   int/float truncated; string -> strconv.Atoi(trimmed) else 0
//   strList(v) str() of every element of a list, empty results dropped

enum NCValueCoercion {
    /// fmt.Sprint-style rendering of a yaml-decoded value (NCYAML numbers are
    /// Doubles; integral scalars print as integers, and float64 prints without
    /// an exponent below 1e21).
    static func sprint(_ v: NCJSONValue) -> String {
        switch v {
        case .null: return "<nil>"
        case .bool(let b): return b ? "true" : "false"
        case .string(let s): return s
        case .number(let d):
            if d.isFinite, d == d.rounded(.towardZero), abs(d) < 9.0e18 {
                return String(Int64(d))
            }
            if d.isNaN { return "NaN" }
            if d.isInfinite { return d < 0 ? "-Inf" : "+Inf" }
            return "\(d)"
        case .array(let a): return "[" + a.map { sprint($0) }.joined(separator: " ") + "]"
        case .object(let o):
            return "map[" + o.keys.sorted().map { "\($0):\(sprint(o[$0]!))" }.joined(separator: " ") + "]"
        }
    }

    /// bridge str(v any): nil (absent or YAML null) -> "".
    static func str(_ v: NCJSONValue?) -> String {
        guard let v else { return "" }
        if case .null = v { return "" }
        return sprint(v)
    }

    /// bridge truthy (nodes.go).
    static func truthy(_ s: String) -> Bool {
        switch s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "1", "true", "yes", "on": return true
        default: return false
        }
    }

    /// bridge boolOf.
    static func boolOf(_ v: NCJSONValue?) -> Bool {
        switch v {
        case .bool(let b)?: return b
        case .string(let s)?: return truthy(s)
        default: return false
        }
    }

    /// bridge intOf (int(float64) truncates; out-of-range / NaN -> 0 instead of trapping).
    static func intOf(_ v: NCJSONValue?) -> Int {
        switch v {
        case .number(let n)?:
            guard n.isFinite, n > -9.0e18, n < 9.0e18 else { return 0 }
            return Int(n)
        case .string(let s)?:
            return Int(s.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
        default:
            return 0
        }
    }

    /// bridge strList.
    static func strList(_ v: NCJSONValue?) -> [String] {
        guard case .array(let a)? = v else { return [] }
        return a.map { str($0) }.filter { !$0.isEmpty }
    }
}

extension Dictionary where Key == String, Value == NCJSONValue {
    func str(_ key: String) -> String { NCValueCoercion.str(self[key]) }
    func boolOf(_ key: String) -> Bool { NCValueCoercion.boolOf(self[key]) }
    func intOf(_ key: String) -> Int { NCValueCoercion.intOf(self[key]) }
    func list(_ key: String) -> [NCJSONValue] {
        if case .array(let a)? = self[key] { return a }
        return []
    }
    func map(_ key: String) -> [String: NCJSONValue] {
        if case .object(let o)? = self[key] { return o }
        return [:]
    }
    func strList(_ key: String) -> [String] { NCValueCoercion.strList(self[key]) }
}

extension NCJSONValue {
    /// bridge str(x) on one element.
    var strValue: String { NCValueCoercion.str(self) }
    /// bridge boolOf(x) on one element.
    var boolValue: Bool { NCValueCoercion.boolOf(self) }
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

// MARK: - provider-overrides.json

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

// MARK: - subscriptions.json

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

// MARK: - proxy-chains.json

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
        SHA256.hash(data: data).ncHex
    }

    /// The bridge's writeAtomic (grouporder.go), review R-2: write to a UNIQUE
    /// temp file in the same directory (".<base>.tmp<uuid>", O_EXCL), fsync,
    /// chmod 0644, then rename(2) over the target. rename is atomic on the same
    /// volume, so a reader (the tunnel) sees either the old or the new file —
    /// never a missing or half-written one — and two concurrent writers never
    /// share a temp path. The previous version removed the target first and
    /// used a fixed "<path>.tmp".
    static func writeAtomic(_ data: Data, to path: String) throws {
        let ns = path as NSString
        let dir = ns.deletingLastPathComponent
        let tmp = ((dir.isEmpty ? "." : dir) as NSString)
            .appendingPathComponent("." + ns.lastPathComponent + ".tmp" + UUID().uuidString)
        func posixError(_ code: Int32, _ p: String) -> NSError {
            NSError(domain: NSPOSIXErrorDomain, code: Int(code),
                    userInfo: [NSFilePathErrorKey: p,
                               NSLocalizedDescriptionKey: p + ": " + String(cString: strerror(code))])
        }
        let fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o644)
        if fd < 0 { throw posixError(errno, tmp) }
        var werr: Int32 = 0
        data.withUnsafeBytes { (buf: UnsafeRawBufferPointer) in
            guard let base = buf.baseAddress else { return }
            var off = 0
            while off < buf.count {
                let n = Darwin.write(fd, base + off, buf.count - off)
                if n < 0 {
                    if errno == EINTR { continue }
                    werr = errno
                    return
                }
                off += n
            }
        }
        if werr == 0 && fsync(fd) != 0 { werr = errno }
        if close(fd) != 0 && werr == 0 { werr = errno }
        if werr != 0 {
            unlink(tmp)
            throw posixError(werr, tmp)
        }
        _ = chmod(tmp, 0o644)
        if rename(tmp, path) != 0 {
            let e = errno
            unlink(tmp)
            throw posixError(e, path)
        }
    }
}
