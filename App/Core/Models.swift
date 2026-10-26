import Foundation

// MARK: - mihomo REST models (decoded tolerantly; unknown keys ignored)

struct DelayHistory: Decodable, Hashable {
    var time: String?
    var delay: Int
}

/// Per-test-URL history the core keeps next to `history` ("extra": {url: {alive, history}}).
struct ExtraDelay: Decodable, Hashable {
    var alive: Bool?
    var history: [DelayHistory]?
}

struct ProxyItem: Decodable, Identifiable, Hashable {
    var id: String { name }
    var name: String
    var type: String
    var now: String?
    var all: [String]?
    var history: [DelayHistory]?
    var alive: Bool?
    var udp: Bool?
    var hidden: Bool?
    var icon: String?
    var testUrl: String?
    /// url-test / fallback: the member pinned with PUT /proxies/{group} ("" = not pinned).
    var fixed: String?
    var extra: [String: ExtraDelay]?

    var lastDelay: Int? {
        guard let d = history?.last?.delay else { return nil }
        return d
    }

    /// Last result for one test URL (what 测速 measured). v0.15.2: no fallback to the overall history when
    /// the core keeps per-URL results — that history mixes other URLs (a group's own health check, an
    /// earlier 测速 URL) and showed numbers that were never measured with the current URL. Only a core
    /// that reports no "extra" at all falls back.
    func lastDelay(for url: String) -> Int? {
        guard let extra, !extra.isEmpty else { return lastDelay }
        return extra[url]?.history?.last?.delay
    }

    var isGroup: Bool { all != nil }
    var isSelectable: Bool { type == "Selector" }

    var typeLabel: String { ProxyItem.label(for: type) }

    static func label(for type: String) -> String {
        switch type.lowercased() {
        case "selector": return String(localized: "手动")
        case "urltest": return String(localized: "自动")
        case "fallback": return String(localized: "故障转移")
        case "loadbalance": return String(localized: "负载均衡")
        case "relay": return String(localized: "链式")
        case "shadowsocks", "ss": return "SS"
        case "shadowsocksr", "ssr": return "SSR"
        case "vmess": return "VMess"
        case "vless": return "VLESS"
        case "trojan": return "Trojan"
        case "hysteria2": return "Hy2"
        case "hysteria": return "Hysteria"
        case "tuic": return "TUIC"
        case "wireguard": return "WireGuard"
        case "snell": return "Snell"
        case "anytls": return "AnyTLS"
        case "mieru": return "Mieru"
        case "ssh": return "SSH"
        case "socks5": return "SOCKS5"
        case "http": return "HTTP"
        case "naive": return "Naïve"
        case "http2", "h2": return "HTTP2"
        case "http3", "h3": return "HTTP3"
        case "sudoku": return "Sudoku"
        case "masque": return "MASQUE"
        case "trusttunnel": return "TrustTunnel"
        case "shadowquic": return "ShadowQUIC"
        case "openvpn": return "OpenVPN"
        case "gost-relay", "gostrelay": return "GOST"
        case "tailscale": return "Tailscale"
        case "zerotier": return "ZeroTier"
        case "easytier": return "EasyTier"
        case "direct": return String(localized: "直连")
        case "reject", "rejectdrop": return String(localized: "拒绝")
        case "compatible", "pass": return String(localized: "兼容")
        default: return type
        }
    }
}

struct ProxiesResponse: Decodable {
    var proxies: [String: ProxyItem]
}

struct ConnectionMetadata: Decodable, Hashable {
    var network: String?
    var type: String?
    var sourceIP: String?
    var destinationIP: String?
    var sourcePort: String?
    var destinationPort: String?
    var host: String?
    var sniffHost: String?
    var process: String?
    var remoteDestination: String?

    var displayHost: String {
        let h = (host?.isEmpty == false ? host : (sniffHost?.isEmpty == false ? sniffHost : destinationIP)) ?? "?"
        if let p = destinationPort, !p.isEmpty { return "\(h):\(p)" }
        return h
    }
}

struct ConnectionItem: Decodable, Identifiable, Hashable {
    var id: String
    var metadata: ConnectionMetadata
    var upload: Int64
    var download: Int64
    var start: String?
    var chains: [String]?
    var rule: String?
    var rulePayload: String?
    var closedAt: Date? = nil

    enum CodingKeys: String, CodingKey { case id, metadata, upload, download, start, chains, rule, rulePayload }

    var startDate: Date? {
        guard let s = start else { return nil }
        return ConnectionItem.iso.date(from: s) ?? ConnectionItem.isoNoFrac.date(from: s)
    }

    var chainText: String { (chains ?? []).reversed().joined(separator: " → ") }

    var ruleText: String {
        guard let r = rule else { return "" }
        if let p = rulePayload, !p.isEmpty { return "\(r)(\(p))" }
        return r
    }

    static let iso: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()
    static let isoNoFrac = ISO8601DateFormatter()
}

struct ConnectionsResponse: Decodable {
    var downloadTotal: Int64?
    var uploadTotal: Int64?
    var connections: [ConnectionItem]?
    var memory: Int64?
}

struct RuleItem: Decodable, Identifiable, Hashable {
    var id: String { "\(index ?? 0)-\(type)-\(payload)" }
    var index: Int?
    var type: String
    var payload: String
    var proxy: String
    var size: Int?
    /// v0.14: mihomo's per-rule counters for the running session (top-level rules only).
    var extra: RuleExtraItem?
}

struct RuleExtraItem: Decodable, Hashable {
    var disabled: Bool?
    var hitCount: Int?
}

struct RulesResponse: Decodable { var rules: [RuleItem] }

struct ProviderItem: Decodable, Identifiable, Hashable {
    var id: String { name }
    var name: String
    var type: String?
    var vehicleType: String?
    var behavior: String?
    var format: String?
    var ruleCount: Int?
    var updatedAt: String?
    var proxies: [ProxyItem]?
    var subscriptionInfo: SubscriptionInfoAPI?
}

struct SubscriptionInfoAPI: Decodable, Hashable {
    var Upload: Int64?
    var Download: Int64?
    var Total: Int64?
    var Expire: Int64?
}

struct ProvidersResponse: Decodable { var providers: [String: ProviderItem] }

struct MemorySample: Decodable { var inuse: Int64; var oslimit: Int64? }

struct LogLine: Identifiable, Hashable {
    let id = UUID()
    let level: String
    let message: String
    let time: Date
}

struct LogPayload: Decodable { var type: String; var payload: String }

/// v0.19.8 GET /hark/logs.
struct HarkLogEntry: Decodable { var seq: UInt64; var time: Int64; var type: String; var payload: String }
struct HarkLogHistory: Decodable { var seq: UInt64; var logs: [HarkLogEntry]? }

/// Joins the history read from /hark/logs with the live /logs stream: the stream is attached right after the
/// history read, so the first few streamed lines can repeat its newest entries. A streamed line whose payload is
/// one of the history's last entries is skipped once, only during the first seconds after attaching.
struct LogJoin {
    private var pending: [String: Int] = [:]
    private let until: Date
    init(history: [HarkLogEntry], window: TimeInterval = 5, now: Date = Date()) {
        for e in history.suffix(64) { pending[e.payload, default: 0] += 1 }
        until = now.addingTimeInterval(window)
    }
    /// true when the streamed payload is a repeat of a history entry.
    mutating func isDuplicate(_ payload: String, now: Date = Date()) -> Bool {
        guard now <= until, let n = pending[payload], n > 0 else { return false }
        pending[payload] = n - 1
        return true
    }
}

// MARK: - Formatting helpers

enum Fmt {
    static func bytes(_ v: Int64) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var d = Double(max(v, 0)); var i = 0
        while d >= 1024 && i < units.count - 1 { d /= 1024; i += 1 }
        return i == 0 ? "\(Int(d)) B" : String(format: d >= 100 ? "%.0f %@" : "%.1f %@", d, units[i])
    }
    static func speed(_ v: Int64) -> String { bytes(v) + "/s" }
    /// v0.14: compact counts (1234 → 1.2K) in the user's locale.
    static func count(_ v: Int) -> String { v.formatted(.number.notation(.compactName)) }
    static func duration(_ t: TimeInterval) -> String {
        let s = Int(max(t, 0))
        if s < 60 { return "\(s)s" }
        if s < 3600 { return "\(s / 60)m\(s % 60)s" }
        return "\(s / 3600)h\(s % 3600 / 60)m"
    }
}


// MARK: - MitM engine

struct MitMStatus: Decodable {
    var running: Bool
    var port: Int
    var enabled: Bool
    var mitm: Bool
    var caLoaded: Bool
    var hostnames: [String]
    var rules: Int
    var scripts: Int
    var coreRules: Int
    var errors: [String]
    var unsupported: Int
    var pinned: [String]
}

struct HTTPRequestSummary: Decodable, Identifiable, Hashable {
    var id: Int64
    var time: Double
    var method: String
    var url: String
    var host: String
    var mitm: Bool
    var status: Int
    var matched: [String]?
    var notes: [String]?
    var local: Bool?
    var done: Bool
    var duration: Double?
    var bytes: Int64

    var date: Date { Date(timeIntervalSince1970: time) }
    var path: String {
        guard let u = URL(string: url) else { return url }
        var p = u.path.isEmpty ? "/" : u.path
        if let q = u.query { p += "?" + q }
        return p
    }
}

struct HTTPRequestDetail: Decodable {
    var id: Int64
    var time: Double
    var method: String
    var url: String
    var host: String
    var mitm: Bool
    var status: Int
    var matched: [String]?
    var notes: [String]?
    var local: Bool?
    var done: Bool
    var duration: Double?
    var bytes: Int64
    var reqHeaders: [String: String]?
    var respHeaders: [String: String]?
    var reqBody: String?
    var respBody: String?
    var reqBodyBinary: Int?
    var respBodyBinary: Int?
    var respEncoding: String?
    var reqBodyLength: Int?
    var respBodyLength: Int?

    /// curl command for the captured request (headers + text body).
    var curl: String {
        func q(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }
        var parts = ["curl"]
        if method != "GET" { parts.append("-X \(method)") }
        parts.append(q(url))
        for k in (reqHeaders ?? [:]).keys.sorted() {
            let lk = k.lowercased()
            if ["content-length", "connection", "proxy-connection", "keep-alive", "transfer-encoding"].contains(lk) { continue }
            parts.append("-H " + q("\(k): \(reqHeaders?[k] ?? "")"))
        }
        if let b = reqBody, !b.isEmpty { parts.append("--data-raw " + q(b)) }
        if (reqHeaders ?? [:]).keys.contains(where: { $0.lowercased() == "accept-encoding" }) { parts.append("--compressed") }
        return parts.joined(separator: " \\\n  ")
    }

    /// Replay is possible when the body (if any) was captured in full as text.
    var canReplay: Bool {
        method != "TLS" && (reqBodyBinary ?? 0) == 0 && (reqBodyLength ?? 0) <= (reqBody?.utf8.count ?? 0)
    }
}

struct ScriptLogLine: Decodable, Identifiable, Hashable {
    var id: Int64
    var time: Double
    var script: String
    var level: String
    var msg: String
    /// v0.19.21: > 1 when the core folded repeats of this line (same script, nothing in between) into it.
    var count: Int?
}

/// Result of the module text parser (NCEngineParser, formerly the Go
/// bridge's EngineParseText / EngineParseLine).
struct ParsedEngineText: Decodable {
    struct Rule: Decodable, Hashable {
        var kind: String
        var phase: String
        var pattern: String
        var desc: String
        var line: String
        var script: String?
        var path: String?
    }
    struct Arg: Decodable, Hashable {
        var key: String
        var `default`: String
        var desc: String?
        /// Loon [Argument]: switch / select / input / text (nil = Surge #!arguments text field).
        var type: String?
        var options: [String]?
    }
    var name: String
    var desc: String
    /// #!author / #!category (Surge) or #!tag (Loon); nil when the module does not say.
    var author: String?
    var category: String?
    var format: String
    var rules: [Rule]
    var hostnames: [String]
    var coreRules: [String]
    var errors: [String]
    var unsupported: [String]
    var arguments: [Arg]
    struct Task: Decodable, Hashable {
        var kind: String
        var name: String
        var cron: String?
        var event: String?
        var path: String
        var format: String?
        var desc: String
        var line: String
    }
    struct Panel: Decodable, Hashable {
        var name: String
        var title: String
        var script: String?
        var format: String
    }
    /// One Loon [Plugin] reference line: the plugin URL plus every
    /// key=value parameter on the line (nc-compat; previously these lines
    /// were only kept as raw `unsupported` text). `line` is the original
    /// line, retained verbatim so the reference can be written back
    /// exactly as imported.
    struct PluginRef: Decodable, Hashable {
        var url: String
        var params: [String: String]
        var line: String
    }
    var tasks: [Task]?
    var panels: [Panel]?
    var plugins: [PluginRef]?
    /// All `#!key = value` header fields of the module / plugin file,
    /// first occurrence wins (nc-compat). The dedicated name / desc /
    /// author / category fields above carry the subset the UI has
    /// always shown; homepage / icon / system / system_version /
    /// loon_version / date / type and friends live only here and used
    /// to be dropped at import.
    var metadata: [String: String]?

    static func parse(_ json: String) -> ParsedEngineText? {
        guard let d = json.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(ParsedEngineText.self, from: d)
    }
}
