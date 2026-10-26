import Foundation

/// What the native core can dial today (feat/native-core-eval). Nodes it cannot are kept in the config — the App
/// still lists them — but marked unsupported: groups skip them, the controller reports them dead, and the startup
/// log / 诊断 say why. There is no fallback to another core; later kernel iterations add the missing protocols.
enum NCSupport {
    /// Proxy types the connector (PacketTunnel/NativeCore/NCConnector.swift) implements.
    static let types: Set<String> = [
        "direct", "reject", "socks5", "http", "https", "ss", "ssr", "snell", "trojan", "vless", "vmess",
        "hysteria2", "hy2", "anytls", "hysteria", "ssh", "tuic", "juicity", "wireguard", "mieru", "tailscale",
        "brook",
        "gost-relay",
    ]
    /// Stream transports (`network:`) the connector implements.
    /// "xhttp" (feat/nc-xhttp, NCXHTTP / NCXHTTPStream): VLESS / VMess / Trojan over HTTP/2, all three modes.
    /// mihomo registers no alias for it ("splithttp" is only accepted by the share-link import, as Xray's old name).
    static let transports: Set<String> = ["tcp", "ws", "grpc", "h2", "http", "xhttp"]

    /// nil = supported; else a short reason (Chinese, shown in 诊断 / the startup log).
    static func unsupportedReason(_ p: NCProxy) -> String? {
        let t = p.type.lowercased()
        guard types.contains(t) else {
            return "类型 \(t) 尚未接入"
        }
        if t != "wireguard", t != "brook", let n = p.fields["network"]?.string?.lowercased(), !n.isEmpty, !transports.contains(n) {
            return "传输 \(n) 尚未接入"
        }
        if p.fields["network"]?.string?.lowercased() == "xhttp", let why = NCXHTTPConfig.unsupportedReason(p) {
            return why
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
        case "brook":
            if let why = brookUnsupported(p) { return why }
        case "gost-relay":
            // feat/nc-gost-relay: mihomo `gost-relay` (NCGostRelay) — not the `relay` chain group (groupTypes).
            // TCP + UDP, tls / mux / forward / auth; Tern extension network: ws (+tls = wss).
            if let why = NCGostRelay.options(p).1 { return why }
        case "tuic":
            let hasToken = !(p.fields["token"]?.string ?? "").isEmpty
            if !hasToken && (p.uuid ?? "").isEmpty { return "TUIC 缺少 uuid / token" }
        case "juicity":
            let u = (p.uuid ?? "").trimmingCharacters(in: .whitespaces)
            let pwd = (p.password ?? "").trimmingCharacters(in: .whitespaces)
            if u.isEmpty || pwd.isEmpty { return "Juicity 缺少 uuid / password" }
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
    /// obfs http/tls, v2ray-plugin websocket / http-upgrade (+tls, mux), shadow-tls v1/v2/v3, gost-plugin websocket (+tls with pinning / name-cert-verify, smux) are implemented in NCSSPlugins; restls in NCRestls).
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
            // NCGostPluginOptions: mihomo's only mode (websocket) with tls / mux / fingerprint /
            // name-cert-verify; client certificates and ECH are explicit gaps.
            return NCGostPluginOptions.parse(opts).1
        case "kcptun":
            // Not implemented natively (feat/nc-ss-plugins2 decision): KCP ARQ + Reed-Solomon FEC + 13 block
            // ciphers + snappy + a shared multi-stream smux session over UDP — see docs/nc-ss-kcptun.md.
            return "kcptun（KCP/UDP 插件）"
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

    /// Brook (NCBrook, feat/nc-brook): brook server (TCP + UDP packets / udp-over-tcp), wsserver, wssserver
    /// (TLS, ca, client-fingerprint) and quicserver (streams + datagrams / udp-over-stream), with or without
    /// the brook protocol (without-brook-protocol). The brook GUI user system (`token`) is not implemented.
    static func brookUnsupported(_ p: NCProxy) -> String? {
        guard NCBrookOptions.kind(p) != nil else {
            return "Brook transport \(NCBrookOptions.string(p, "transport", "brook-transport", "kind", "mode") ?? "") 无效（server / wsserver / wssserver / quicserver）"
        }
        if (p.server ?? "").isEmpty || (p.port ?? 0) == 0 { return "Brook 缺少 server / port" }
        if (NCBrookOptions.string(p, "password") ?? "").isEmpty { return "Brook 缺少 password" }
        if let t = NCBrookOptions.string(p, "token"), !t.isEmpty { return "Brook token（用户系统）尚未接入" }
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
