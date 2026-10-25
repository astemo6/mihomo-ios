import Foundation

/// What the native core can dial today (feat/native-core-eval). Nodes it cannot are kept in the config — the App
/// still lists them — but marked unsupported: groups skip them, the controller reports them dead, and the startup
/// log / 诊断 say why. There is no fallback to another core; later kernel iterations add the missing protocols.
enum NCSupport {
    /// Proxy types the connector (PacketTunnel/NativeCore/NCConnector.swift) implements.
    static let types: Set<String> = [
        "direct", "reject", "socks5", "http", "https", "ss", "ssr", "snell", "trojan", "vless", "vmess",
        "hysteria2", "hy2", "anytls", "hysteria", "ssh", "tuic", "wireguard",
    ]
    /// Stream transports (`network:`) the connector implements.
    static let transports: Set<String> = ["tcp", "ws", "grpc", "h2", "http"]

    /// nil = supported; else a short reason (Chinese, shown in 诊断 / the startup log).
    static func unsupportedReason(_ p: NCProxy) -> String? {
        let t = p.type.lowercased()
        guard types.contains(t) else {
            switch t {
            case "tailscale": return "Tailscale 尚未接入"
            case "mieru": return "Mieru 尚未接入"
            default: return "类型 \(t) 尚未接入"
            }
        }
        if t != "wireguard", let n = p.fields["network"]?.string?.lowercased(), !n.isEmpty, !transports.contains(n) {
            return "传输 \(n) 尚未接入"
        }
        switch t {
        case "ss":
            if let why = ssPluginUnsupported(p) {
                return "Shadowsocks 插件 \(why) 尚未接入"
            }
        case "ssr":
            if let why = ssrUnsupported(p) { return why }
        case "hysteria":
            if let why = hysteriaUnsupported(p) { return why + " 尚未接入" }
        case "ssh":
            if let why = sshUnsupported(p) { return why }
        case "wireguard":
            if let why = wireguardUnsupported(p) { return why }
        case "tuic":
            let hasToken = !(p.fields["token"]?.string ?? "").isEmpty
            if !hasToken && (p.uuid ?? "").isEmpty { return "TUIC 缺少 uuid / token" }
        case "vless":
            if let enc = p.fields["encryption"]?.string, !enc.isEmpty, enc != "none" {
                // feat/nc-proto A6: mlkem768x25519plus.<native|xorpub|random>.<1rtt|0rtt>.<keys> (NCVLESSEncryption).
                let parts = enc.split(separator: ".").map(String.init)
                guard parts.count >= 4, parts[0] == "mlkem768x25519plus",
                      ["native", "xorpub", "random"].contains(parts[1]), ["1rtt", "0rtt"].contains(parts[2]) else {
                    return "VLESS encryption \(enc.prefix(24)) 不是有效的 mlkem768x25519plus 值"
                }
                if p.fields["flow"]?.string == "xtls-rprx-vision" { return "VLESS encryption + Vision 尚未接入" }
            }
        default:
            break
        }
        return nil
    }

    /// nil = plugin supported; else the reason (mirrors mihomo NewShadowSocks' option checks;
    /// obfs http/tls, v2ray-plugin websocket (+tls, mux), shadow-tls v2/v3 are implemented in NCSSPlugins).
    static func ssPluginUnsupported(_ proxy: NCProxy) -> String? {
        guard let plugin = proxy.fields["plugin"]?.string, !plugin.isEmpty else { return nil }
        let opts = proxy.fields["plugin-opts"]?.object ?? [:]
        switch plugin {
        case "obfs":
            let mode = opts["mode"]?.string ?? ""
            return mode == "http" || mode == "tls" ? nil : "obfs mode \(mode)"
        case "v2ray-plugin":
            if (opts["mode"]?.string ?? "") != "websocket" { return "v2ray-plugin mode \(opts["mode"]?.string ?? "")" }
            if opts["v2ray-http-upgrade"]?.bool == true { return "v2ray-plugin http-upgrade" }
            return nil
        case "shadow-tls":
            let v = opts["version"]?.int ?? 2
            return v == 2 || v == 3 ? nil : "shadow-tls v\(v)"
        default:
            return plugin
        }
    }

    /// SSR: stream ciphers + none/dummy; every protocol and obfs mihomo v1.19.33 registers (feat/nc-proto A5).
    static let ssrProtocols: Set<String> = ["origin", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1",
                                            "auth_chain_a", "auth_chain_b"]
    static let ssrObfs: Set<String> = ["plain", "http_simple", "http_post", "random_head", "tls1.2_ticket_auth",
                                       "tls1.2_ticket_fastauth"]

    static func ssrUnsupported(_ p: NCProxy) -> String? {
        let cipher = p.cipher?.lowercased()
        if cipher != "none" && cipher != "dummy" && !NCSSStreamCipher.isStreamMethod(cipher) {
            return "SSR 加密 \(cipher ?? "-") 尚未接入"
        }
        let proto = (p.fields["protocol"]?.string ?? "origin").lowercased()
        if !ssrProtocols.contains(proto) { return "SSR 协议 \(proto) 尚未接入" }
        let obfs = (p.fields["obfs"]?.string ?? "plain").lowercased()
        if !ssrObfs.contains(obfs) { return "SSR 混淆 \(obfs) 尚未接入" }
        return nil
    }

    /// Hysteria v1 (NCHysteria1, feat/nc-proto A3): nil = supported; else why not.
    static func hysteriaUnsupported(_ p: NCProxy) -> String? {
        if let o = p.fields["obfs"]?.string, !o.isEmpty { return "Hysteria v1 obfs" }
        let proto = (p.fields["obfs-protocol"]?.string ?? p.fields["protocol"]?.string ?? "udp").lowercased()
        if !proto.isEmpty && proto != "udp" { return "Hysteria v1 protocol \(proto)" }
        if p.port == nil { return "Hysteria v1 port hopping (ports)" }
        return nil
    }

    /// SSH (NCSSH, feat/nc-proto A3): private keys must be inline PEM (a file path cannot be read in the tunnel)
    /// and unencrypted.
    static func sshUnsupported(_ p: NCProxy) -> String? {
        if let pk = p.fields["private-key"]?.string, !pk.isEmpty, !pk.contains("PRIVATE KEY") {
            return "SSH 私钥文件路径尚未接入（请内联 PEM）"
        }
        if let pp = p.fields["private-key-passphrase"]?.string, !pp.isEmpty { return "SSH 加密私钥尚未接入" }
        return nil
    }

    /// WireGuard (NCWireGuard, feat/nc-wg): same checks as NCWGConfig.parse in the tunnel. AmneziaWG 1.0
    /// (jc/jmin/jmax/s1/s2/h1–h4) is supported; AWG 2.0 header ranges and s3/s4 are not (i1–i5 are ignored).
    static func wireguardUnsupported(_ p: NCProxy) -> String? {
        let f = p.fields
        if (f["private-key"]?.string ?? "").isEmpty { return "WireGuard 缺少 private-key" }
        if (f["ip"]?.string ?? "").isEmpty && (f["ipv6"]?.string ?? "").isEmpty { return "WireGuard 缺少 ip / ipv6" }
        if let peers = f["peers"]?.array, !peers.isEmpty {
            for (i, pv) in peers.enumerated() {
                let o = pv.object ?? [:]
                if (o["server"]?.string ?? "").isEmpty || o["port"]?.int == nil || (o["public-key"]?.string ?? "").isEmpty {
                    return "WireGuard peers[\(i)] 缺少 server / port / public-key"
                }
            }
        } else if p.server == nil || p.port == nil || (f["public-key"]?.string ?? "").isEmpty {
            return "WireGuard 缺少 server / port / public-key"
        }
        if let o = f["amnezia-wg-option"]?.object {
            for k in ["h1", "h2", "h3", "h4"] where (o[k]?.string ?? "").contains("-") {
                return "AmneziaWG 2.0 头部范围 \(k) 尚未接入"
            }
            if (o["s3"]?.int ?? 0) != 0 || (o["s4"]?.int ?? 0) != 0 { return "AmneziaWG 2.0 s3 / s4 尚未接入" }
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
