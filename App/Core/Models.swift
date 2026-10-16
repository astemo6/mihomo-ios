import Foundation

// MARK: - mihomo REST models (decoded tolerantly; unknown keys ignored)

struct DelayHistory: Decodable, Hashable {
    var time: String?
    var delay: Int
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

    var lastDelay: Int? {
        guard let d = history?.last?.delay else { return nil }
        return d
    }

    var isGroup: Bool { all != nil }
    var isSelectable: Bool { type == "Selector" }

    var typeLabel: String {
        switch type {
        case "Selector": return "手动"
        case "URLTest": return "自动"
        case "Fallback": return "故障转移"
        case "LoadBalance": return "负载均衡"
        case "Relay": return "链式"
        case "Shadowsocks": return "SS"
        case "ShadowsocksR": return "SSR"
        case "Vmess": return "VMess"
        case "Vless": return "VLESS"
        case "Trojan": return "Trojan"
        case "Hysteria2": return "Hy2"
        case "Hysteria": return "Hy"
        case "Tuic": return "TUIC"
        case "WireGuard": return "WG"
        case "Direct": return "直连"
        case "Reject", "RejectDrop": return "拒绝"
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

struct TrafficSample: Decodable { var up: Int64; var down: Int64 }
struct MemorySample: Decodable { var inuse: Int64; var oslimit: Int64? }

struct LogLine: Identifiable, Hashable {
    let id = UUID()
    let level: String
    let message: String
    let time: Date
}

struct LogPayload: Decodable { var type: String; var payload: String }

// MARK: - Formatting helpers

enum Fmt {
    static func bytes(_ v: Int64) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var d = Double(max(v, 0)); var i = 0
        while d >= 1024 && i < units.count - 1 { d /= 1024; i += 1 }
        return i == 0 ? "\(Int(d)) B" : String(format: d >= 100 ? "%.0f %@" : "%.1f %@", d, units[i])
    }
    static func speed(_ v: Int64) -> String { bytes(v) + "/s" }
    static func duration(_ t: TimeInterval) -> String {
        let s = Int(max(t, 0))
        if s < 60 { return "\(s)s" }
        if s < 3600 { return "\(s / 60)m\(s % 60)s" }
        return "\(s / 3600)h\(s % 3600 / 60)m"
    }
}
