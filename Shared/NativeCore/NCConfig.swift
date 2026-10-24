import Foundation

/// Flexible JSON value: mihomo configs are loosely typed maps (a proxy's fields
/// differ per protocol), so the native core decodes into this tree and reads
/// typed views from it — the same shape the Go side keeps as map[string]any.
enum NCJSONValue: Equatable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([NCJSONValue])
    case object([String: NCJSONValue])

    init(_ any: Any) {
        switch any {
        case is NSNull: self = .null
        case let n as NSNumber:
            // JSONSerialization numbers 0/1 happily cast to Bool on Darwin;
            // only a genuine CFBoolean may become .bool.
            if CFGetTypeID(n) == CFBooleanGetTypeID() { self = .bool(n.boolValue) }
            else { self = .number(n.doubleValue) }
        case let b as Bool: self = .bool(b)
        case let s as String: self = .string(s)
        case let a as [Any]: self = .array(a.map(NCJSONValue.init))
        case let o as [String: Any]: self = .object(o.mapValues(NCJSONValue.init))
        default: self = .null
        }
    }

    var string: String? { if case .string(let s) = self { return s }; return nil }
    var number: Double? { if case .number(let n) = self { return n }; return nil }
    var bool: Bool? { if case .bool(let b) = self { return b }; return nil }
    var int: Int? {
        switch self {
        case .number(let n): return Int(n)
        case .string(let s): return Int(s)
        default: return nil
        }
    }
    var array: [NCJSONValue]? { if case .array(let a) = self { return a }; return nil }
    var object: [String: NCJSONValue]? { if case .object(let o) = self { return o }; return nil }
    subscript(_ key: String) -> NCJSONValue? { object?[key] }
}

/// One proxy (node) entry. Protocol-specific fields stay in `fields`.
struct NCProxy: Equatable {
    let name: String
    let type: String
    let fields: [String: NCJSONValue]

    var server: String? { fields["server"]?.string }
    var port: Int? { fields["port"]?.int }
    var password: String? { fields["password"]?.string }
    var cipher: String? { fields["cipher"]?.string }
    var uuid: String? { fields["uuid"]?.string }
    var udp: Bool { fields["udp"]?.bool ?? false }
}

struct NCProxyGroup: Equatable {
    let name: String
    let type: String // select | url-test | fallback | load-balance | relay
    let proxies: [String]
    let fields: [String: NCJSONValue]

    var url: String? { fields["url"]?.string }
    var interval: Int { fields["interval"]?.int ?? 300 }
    var tolerance: Int { fields["tolerance"]?.int ?? 0 }
    var lazy: Bool { fields["lazy"]?.bool ?? true }
    var use: [String] { fields["use"]?.array?.compactMap { $0.string } ?? [] }
}

struct NCDNSConfig: Equatable {
    let fields: [String: NCJSONValue]
    var enable: Bool { fields["enable"]?.bool ?? true }
    var fakeIPRange: String { fields["fake-ip-range"]?.string ?? "198.18.0.1/16" }
    var fakeIPFilter: [String] { fields["fake-ip-filter"]?.array?.compactMap { $0.string } ?? [] }
    var nameservers: [String] { fields["nameserver"]?.array?.compactMap { $0.string } ?? [] }
    var enhancedMode: String { fields["enhanced-mode"]?.string ?? "fake-ip" }
}

/// The runtime config the native core runs. Decoded from the JSON form of
/// runtime.yaml (see bridge/nativecore.go: NativeConfigJSON).
struct NCConfig: Equatable {
    var mode: String // rule | global | direct
    var logLevel: String
    var ipv6: Bool
    var proxies: [NCProxy]
    var groups: [NCProxyGroup]
    var rules: [String]
    var dns: NCDNSConfig
    var raw: [String: NCJSONValue]

    var proxyMap: [String: NCProxy] { Dictionary(proxies.map { ($0.name, $0) }, uniquingKeysWith: { a, _ in a }) }
    var groupMap: [String: NCProxyGroup] { Dictionary(groups.map { ($0.name, $0) }, uniquingKeysWith: { a, _ in a }) }

    static func decode(jsonData: Data) throws -> NCConfig {
        let any = try JSONSerialization.jsonObject(with: jsonData)
        guard let root = any as? [String: Any] else {
            throw NSError(domain: "NativeCore", code: 1, userInfo: [NSLocalizedDescriptionKey: "config root is not an object"])
        }
        return decode(root: root.mapValues(NCJSONValue.init))
    }

    static func decode(root: [String: NCJSONValue]) -> NCConfig {
        func objects(_ key: String) -> [[String: NCJSONValue]] {
            root[key]?.array?.compactMap { $0.object } ?? []
        }
        let proxies = objects("proxies").compactMap { o -> NCProxy? in
            guard let name = o["name"]?.string, let type = o["type"]?.string else { return nil }
            return NCProxy(name: name, type: type.lowercased(), fields: o)
        }
        let groups = objects("proxy-groups").compactMap { o -> NCProxyGroup? in
            guard let name = o["name"]?.string, let type = o["type"]?.string else { return nil }
            let members = o["proxies"]?.array?.compactMap { $0.string } ?? []
            return NCProxyGroup(name: name, type: type.lowercased(), proxies: members, fields: o)
        }
        let rules = root["rules"]?.array?.compactMap { $0.string } ?? []
        let dns = NCDNSConfig(fields: root["dns"]?.object ?? [:])
        return NCConfig(
            mode: (root["mode"]?.string ?? "rule").lowercased(),
            logLevel: root["log-level"]?.string ?? "info",
            ipv6: root["ipv6"]?.bool ?? false,
            proxies: proxies,
            groups: groups,
            rules: rules,
            dns: dns,
            raw: root)
    }
}
