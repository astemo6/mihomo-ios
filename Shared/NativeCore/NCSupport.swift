import Foundation

/// What the native core can dial today (feat/native-core-eval). Nodes it cannot are kept in the config — the App
/// still lists them — but marked unsupported: groups skip them, the controller reports them dead, and the startup
/// log / 诊断 say why. There is no fallback to another core; later kernel iterations add the missing protocols.
///
/// ECH 说明（lane E6）：
/// Hysteria2 与 TUIC 基于系统 Network.framework QUIC（NWProtocolQUIC），已开启系统实验性 ECH 开关
/// （sec_protocol_options_set_enable_encrypted_client_hello）。其 ECH 能力定位为「系统 ECH（尽力而为）」：
/// 生效前提为系统 DNS 解析可自动获取 HTTPS/SVCB 记录中的 ECHConfig；系统 QUIC 无法注入外部或静态配置。
/// 因此 NCSupport 不将其标为「完全支持 ECH」，节点若显式配置静态 ech-opts.config，在 report/StartupLog 中给出
/// 可区分提示（静态配置无法生效，仅依赖系统 DNS 尽力而为），避免静默假装生效。
enum NCSupport {
    /// Proxy types the connector (PacketTunnel/NativeCore/NCConnector.swift) implements.
    static let types: Set<String> = [
        "direct", "reject", "socks5", "http", "https", "ss", "ssr", "snell", "trojan", "vless", "vmess",
        "hysteria2", "hy2", "anytls", "hysteria", "ssh", "tuic", "wireguard", "mieru", "tailscale",
    ]
    /// Stream transports (`network:`) the connector implements.
    static let transports: Set<String> = ["tcp", "ws", "grpc", "h2", "http"]

    /// nil = supported; else a short reason (Chinese, shown in 诊断 / the startup log).
    static func unsupportedReason(_ p: NCProxy) -> String? {
        let t = p.type.lowercased()
        guard types.contains(t) else {
            return "类型 \(t) 尚未接入"
        }
        if t != "wireguard", let n = p.fields["network"]?.string?.lowercased(), !n.isEmpty, !transports.contains(n) {
            return "传输 \(n) 尚未接入"
        }
        // ECH (RFC 9849), one judgement for every layer, read from p.echOpts (mihomo semantics: enable must be true).
        // TCP/TLS nodes (trojan / vless / vmess / anytls / https) do ECH in the native TLS stack (static
        // ech-opts.config, else the HTTPS RR via the kernel DNS); hy2 / tuic use the system QUIC ECH switch
        // (best effort, DNS only — see report()). REALITY is exclusive; Vision and SS plugins are not wired.
        if let ech = p.echOpts, ech.enable {
            let sec = p.fields["security"]?.string?.lowercased()
            if p.fields["reality-opts"] != nil || sec == "reality" {
                return "REALITY 与 ECH 互斥，不能同时启用"
            }
            if t == "ss" {
                return "Shadowsocks 插件不支持 ECH"
            }
            if t == "vless" {
                let flow = (p.fields["flow"]?.string ?? "").lowercased()
                if flow.hasPrefix("xtls-rprx-vision") {
                    return "VLESS Vision 不支持 ECH"
                }
            }
            if !Self.echTypes.contains(t) {
                return "\(t) 不支持 ECH（ech-opts）"
            }
        }
        switch t {
        case "ss":
            // One gate for every SS plugin (ssPluginUnsupported): simple-obfs / v2ray-plugin use #101's
            // NCSSPluginOptions parse (same as the connector), gost-plugin / shadow-tls / restls the nc-proto rules.
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
        case "mieru":
            if let why = mieruUnsupported(p) { return why }
        case "tuic":
            let hasToken = !(p.fields["token"]?.string ?? "").isEmpty
            if !hasToken && (p.uuid ?? "").isEmpty { return "TUIC 缺少 uuid / token" }
        case "vless":
            if let enc = p.fields["encryption"]?.string, !enc.isEmpty, enc != "none" {
                // feat/nc-proto A6: mlkem768x25519plus.<native|xorpub|random>.<1rtt|0rtt>.<keys> (NCVLESSEncryption).
                // TCP and UDP alike: a UDP association opens its own connection through the same
                // shared encryption instance (NCUDPVLESSSession), so udp:true nodes work encrypted too.
                let parts = enc.split(separator: ".").map(String.init)
                guard parts.count >= 4, parts[0] == "mlkem768x25519plus",
                      ["native", "xorpub", "random"].contains(parts[1]), ["1rtt", "0rtt"].contains(parts[2]) else {
                    return "VLESS encryption \(enc.prefix(24)) 不是有效的 mlkem768x25519plus 值"
                }
            }
        default:
            break
        }
        return nil
    }

    /// nil = plugin supported; else the reason (mirrors mihomo NewShadowSocks' option checks;
    /// obfs http/tls, v2ray-plugin websocket / http-upgrade (+tls, mux), shadow-tls v1/v2/v3, gost-plugin websocket (+tls, smux) are implemented in NCSSPlugins; restls in NCRestls).
    static func ssPluginUnsupported(_ proxy: NCProxy) -> String? {
        guard let plugin = proxy.fields["plugin"]?.string, !plugin.isEmpty else { return nil }
        let opts = proxy.fields["plugin-opts"]?.object ?? [:]
        switch plugin {
        case "obfs", "v2ray-plugin":
            // #101 (astemo6) NCSSPluginOptions: obfs mode=http/tls; v2ray-plugin mode=websocket /
            // http-upgrade (or empty), v2ray-http-upgrade(+fast-open) — the exact parse the dialer uses.
            guard NCSSPluginOptions(pluginName: plugin, opts: opts) == nil else { return nil }
            return plugin == "obfs"
                ? "obfs 的 plugin-opts（mode=\(opts["mode"]?.string ?? "")；支持 http/tls）"
                : "v2ray-plugin 的 plugin-opts（mode=\(opts["mode"]?.string ?? "")；支持 websocket / http-upgrade）"
        case "gost-plugin":
            let mode = opts["mode"]?.string ?? ""
            return mode == "websocket" ? nil : "gost-plugin mode \(mode)"
        case "shadow-tls":
            let v = opts["version"]?.int ?? 2
            return (1...3).contains(v) ? nil : "shadow-tls v\(v)"
        case "restls":
            // NCRestls: version-hint tls12 / tls13 (any other value — tls11, empty, … — is an explicit
            // error at dial time, mirroring restls-client-go; it is never silently mapped), restls-script,
            // client-fingerprint, skip-cert-verify, fingerprint (SHA-256 pinning) and name-cert-verify.
            let hint = (opts["version-hint"]?.string ?? "").lowercased()
            if hint != "tls12" && hint != "tls13" { return "restls version-hint \(hint.isEmpty ? "(空)" : hint)（仅 tls12 / tls13）" }
            return nil
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

    /// Hysteria v1 (NCHysteria1 + NCHysteria1UDP, feat/nc-proto A3 / feat/nc-proto2): TCP, UDP, obfs (XPlus),
    /// protocol udp / wechat-video, port hopping (`ports`). nil = supported; else why not.
    static func hysteriaUnsupported(_ p: NCProxy) -> String? {
        let proto = (p.fields["obfs-protocol"]?.string ?? p.fields["protocol"]?.string ?? "udp").lowercased()
        if !proto.isEmpty && proto != "udp" && proto != "wechat-video" { return "Hysteria v1 protocol \(proto)" }
        if p.port == nil && !hysteriaPortsValid(p.fields["ports"]?.string) { return "Hysteria v1 缺少 port / ports" }
        if let ports = p.fields["ports"]?.string, !ports.isEmpty, !hysteriaPortsValid(ports) {
            return "Hysteria v1 ports \(ports.prefix(24)) 无效"
        }
        return nil
    }

    /// mihomo parsePorts syntax: "443,1000-2000".
    static func hysteriaPortsValid(_ s: String?) -> Bool {
        guard let s, !s.trimmingCharacters(in: .whitespaces).isEmpty else { return false }
        for part in s.split(separator: ",") {
            let r = part.split(separator: "-", omittingEmptySubsequences: false)
                .map { $0.trimmingCharacters(in: .whitespaces) }
            guard (1...2).contains(r.count), r.allSatisfy({ UInt16($0) != nil }) else { return false }
        }
        return true
    }

    /// SSH (NCSSH, feat/nc-proto A3): private keys inline as PEM or as a file path (absolute,
    /// ~, or relative to the profile home — nc-perf, read in NCConnector.sshStream);
    /// passphrase-protected OpenSSH keys (bcrypt + aes256-ctr/cbc) are decrypted natively
    /// (feat/nc-proto3). Nothing left to gate here.
    static func sshUnsupported(_ p: NCProxy) -> String? {
        return nil
    }

    /// Mieru (NCMieru, feat/nc-proto3): transport TCP (stream underlay) + UDP (packet underlay),
    /// TCP + UDP-over-session traffic, traffic-pattern applied (except explicit lowEntropy).
    static func mieruUnsupported(_ p: NCProxy) -> String? {
        let transport = (p.fields["transport"]?.string ?? "").uppercased()
        if transport != "TCP" && transport != "UDP" { return "Mieru transport 必须为 TCP 或 UDP" }
        if (p.fields["username"]?.string ?? "").isEmpty || (p.password ?? "").isEmpty { return "Mieru 缺少 username / password" }
        if (p.port ?? 0) == 0 && (p.fields["port-range"]?.string ?? "").isEmpty { return "Mieru 缺少 port / port-range" }
        if let tp = p.fields["traffic-pattern"]?.string, !tp.isEmpty {
            // Decoded + applied in NCMieru (nonce / padding / TCP fragment); an explicit
            // lowEntropy mode (mieru's low-entropy data codec) is the one unimplemented piece.
            guard let pattern = NCMieruTrafficPattern.decode(tp) else { return "Mieru traffic-pattern 无效" }
            if pattern.lowEntropyMode != 0 { return "Mieru traffic-pattern lowEntropy 尚未接入" }
        }
        return nil
    }

    /// WireGuard (NCWireGuard, feat/nc-wg): same checks as NCWGConfig.parse in the tunnel. AmneziaWG 1.0
    /// (jc/jmin/jmax/s1/s2/h1–h4) and 2.0 (h1–h4 header ranges, s3/s4 padding) are supported;
    /// i1–i5 signature packets are ignored (standard packets are sent instead).
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
        return nil
    }

    /// Group types the group engine evaluates as written; anything else (smart, …) is evaluated like select.
    static let groupTypes: Set<String> = ["select", "url-test", "fallback", "load-balance", "relay"]

    /// Proxy types whose dial honours ech-opts (native TLS stack, or the system QUIC switch for hy2 / tuic).
    static let echTypes: Set<String> = ["trojan", "vless", "vmess", "anytls", "https", "hysteria2", "hy2", "tuic"]

    /// hy2 / tuic: whether the system QUIC ECH switch is turned on — only for an explicit `ech-opts.enable: true`
    /// (nodes without ech-opts stay byte-for-byte unchanged; review #150 item 1).
    static func systemQUICECHEnabled(_ p: NCProxy) -> Bool {
        p.echOpts?.enable == true
    }

    /// Whether the proxy explicitly configures `ech-opts` with a non-empty static `config`.
    /// System QUIC (NWProtocolQUIC) ECH can only discover ECHConfig dynamically via system DNS (HTTPS/SVCB records),
    /// so static configs cannot be injected into the system QUIC stack.
    static func hasStaticECHConfig(_ p: NCProxy) -> Bool {
        guard let opts = p.echOpts, opts.enable else { return false }
        return opts.config != nil
    }

    /// One line per unsupported node / group type / rule, for the startup log and 诊断.
    static func report(config: NCConfig, unparsedRules: [String]) -> [String] {
        var out: [String] = []
        for p in config.proxies {
            if let why = unsupportedReason(p) {
                out.append("节点「\(p.name)」不可用：\(why)")
            } else if ["hysteria2", "hy2", "tuic"].contains(p.type.lowercased()),
                      hasStaticECHConfig(p) {
                out.append("节点「\(p.name)」带静态 ech-opts.config：系统 QUIC 无法注入静态 ECH 配置（系统 ECH 仅依赖系统 DNS 自动解析 HTTPS 记录尽力而为，静态配置将被忽略）")
            }
        }
        for g in config.groups where !groupTypes.contains(g.type.lowercased()) {
            out.append("策略组「\(g.name)」类型 \(g.type) 暂按手动选择处理")
        }
        for r in unparsedRules { out.append("规则未识别，已忽略：\(r)") }
        return out
    }
}
