import Foundation

/// What the native core can dial today (feat/native-core-eval). Nodes it cannot are kept in the config — the App
/// still lists them — but marked unsupported: groups skip them, the controller reports them dead, and the startup
/// log / 诊断 say why. There is no fallback to another core; later kernel iterations add the missing protocols.
enum NCSupport {
    /// Proxy types the connector (PacketTunnel/NativeCore/NCConnector.swift) implements.
    static let types: Set<String> = [
        "direct", "reject", "socks5", "http", "https", "ss", "ssr", "snell", "trojan", "vless", "vmess",
        "hysteria2", "hy2", "anytls",
    ]
    /// Stream transports (`network:`) the connector implements.
    static let transports: Set<String> = ["tcp", "ws", "grpc", "h2", "http"]

    /// nil = supported; else a short reason (Chinese, shown in 诊断 / the startup log).
    static func unsupportedReason(_ p: NCProxy) -> String? {
        let t = p.type.lowercased()
        guard types.contains(t) else {
            switch t {
            case "tuic": return "TUIC 尚未接入（需要 QUIC 单向流与 TLS exporter）"
            case "wireguard": return "WireGuard 尚未接入"
            case "tailscale": return "Tailscale 尚未接入"
            case "mieru": return "Mieru 尚未接入"
            case "hysteria": return "Hysteria v1 尚未接入"
            case "ssh": return "SSH 尚未接入"
            default: return "类型 \(t) 尚未接入"
            }
        }
        if let n = p.fields["network"]?.string?.lowercased(), !n.isEmpty, !transports.contains(n) {
            return "传输 \(n) 尚未接入"
        }
        switch t {
        case "ss":
            // Stream plugins the connector wraps via NCSSPluginStream:
            // simple-obfs (http/tls) and v2ray-plugin (websocket). Same parse
            // as the connector, so the gate and the dial never disagree.
            let plugin = p.fields["plugin"]?.string ?? ""
            if !plugin.isEmpty {
                if plugin != "obfs", plugin != "v2ray-plugin" {
                    return "Shadowsocks 插件 \(plugin) 尚未接入"
                }
                if NCSSPluginOptions(pluginName: plugin,
                                     opts: p.fields["plugin-opts"]?.object ?? [:]) == nil {
                    return "Shadowsocks 插件 \(plugin) 的 plugin-opts 不受支持（obfs: mode=http/tls；v2ray-plugin: mode=websocket）"
                }
            }
        case "ssr":
            let cipher = p.cipher?.lowercased()
            if !NCSSStreamCipher.isStreamMethod(cipher) { return "SSR 加密 \(cipher ?? "-") 尚未接入" }
            let proto = (p.fields["protocol"]?.string ?? "origin").lowercased()
            if proto != "origin" && proto != "auth_sha1_v4" { return "SSR 协议 \(proto) 尚未接入" }
            let obfs = (p.fields["obfs"]?.string ?? "plain").lowercased()
            if obfs != "plain" && obfs != "http_simple" { return "SSR 混淆 \(obfs) 尚未接入" }
        case "vless":
            if let enc = p.fields["encryption"]?.string?.lowercased(), !enc.isEmpty, enc != "none" {
                return "VLESS encryption 尚未接入"
            }
        default:
            break
        }
        return nil
    }

    /// Group types the group engine evaluates as written; anything else (smart, …) is evaluated like select.
    static let groupTypes: Set<String> = ["select", "url-test", "fallback", "load-balance", "relay"]

    /// One line per unsupported node / group type / rule, for the startup log and 诊断.
    static func report(config: NCConfig, unparsedRules: [String]) -> [String] {
        var out: [String] = []
        for p in config.proxies {
            if let why = unsupportedReason(p) { out.append("节点「\(p.name)」不可用：\(why)") }
        }
        for g in config.groups where !groupTypes.contains(g.type.lowercased()) {
            out.append("策略组「\(g.name)」类型 \(g.type) 暂按手动选择处理")
        }
        for r in unparsedRules { out.append("规则未识别，已忽略：\(r)") }
        return out
    }
}
