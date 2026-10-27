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
        "hysteria2", "hy2", "anytls", "hysteria", "ssh", "tuic", "juicity", "wireguard", "mieru", "tailscale",
        "brook",
        "gost-relay",
        // feat/nc-naive-h2h3 (NCNaive / NCH2ProxySession / NCH3ProxySession): NaïveProxy (h2, or h3 with
        // quic: true) and Shadowrocket-style HTTP/2 / HTTP/3 CONNECT proxies.
        "naive", "http2", "h2", "http3", "h3",
        "lua",
        "openconnect", "anyconnect",
        "trusttunnel", "trust-tunnel",
        "masque",
        "sudoku",
    ]
    /// Stream transports (`network:`) the connector implements.
    /// "xhttp" (feat/nc-xhttp, NCXHTTP / NCXHTTPStream): VLESS / VMess / Trojan over HTTP/2, all three modes.
    /// Clash.Meta registers no alias for it ("splithttp" is only accepted by the share-link import, as Xray's old name).
    static let transports: Set<String> = ["tcp", "ws", "grpc", "h2", "http", "xhttp"]

    /// nil = supported; else a short reason (Chinese, shown in 诊断 / the startup log).
    static func unsupportedReason(_ p: NCProxy) -> String? {
        let t = p.type.lowercased()
        guard types.contains(t) else {
            return "类型 \(t) 尚未接入"
        }
        if t != "wireguard", t != "brook", t != "trusttunnel", t != "trust-tunnel", t != "masque", let n = p.fields["network"]?.string?.lowercased(), !n.isEmpty, !transports.contains(n) {
            return "传输 \(n) 尚未接入"
        }
        if p.fields["network"]?.string?.lowercased() == "xhttp", let why = NCXHTTPConfig.unsupportedReason(p) {
            return why
        }
        // ECH (RFC 9849), one judgement for every layer, read from p.echOpts (Clash.Meta semantics: enable must be true).
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
        case "snell":
            if let why = snellUnsupported(p) { return why }
        case "vmess":
            // fix/nc-silent-fail: alterId > 0 is the legacy MD5 header auth (Clash.Meta IsAead = alterId == 0); only
            // AEAD is implemented, so these nodes are marked here rather than failing every dial.
            if let aid = p.fields["alterId"]?.int, aid > 0 {
                return "VMess alterId \(aid)（旧版 MD5 认证）尚未接入，请改为 alterId: 0"
            }
        case "lua":
            // feat/nc-lua S2: the connector runs the backend in NCLuaSession; a node without any
            // script source can never dial, so say so at import/display time already.
            let hasScript = !(p.fields["script"]?.string ?? "").isEmpty
            let hasFile = !(p.fields["file"]?.string ?? "").isEmpty
            if !hasScript && !hasFile { return "Lua 后端缺少脚本 (file/script)" }
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
        case "masque":
            if let why = masqueUnsupported(p) { return why }
            // fix/nc-masque-ip: CONNECT-IP stays unavailable until the real RFC 9484 loopback is green
            // (the connector still dials, so the loopback can run).
            if NCMASQUE.Config(proxy: p)?.mode == .connectIP, !NCMASQUE.connectIPVerified {
                return NCMASQUE.connectIPUnverified
            }
        case "mieru":
            if let why = mieruUnsupported(p) { return why }
        case "brook":
            if let why = brookUnsupported(p) { return why }
        case "gost-relay":
            // feat/nc-gost-relay: Clash.Meta `gost-relay` (NCGostRelay) — not the `relay` chain group (groupTypes).
            // TCP + UDP, tls / mux / forward / auth; Tern extension network: ws (+tls = wss).
            if let why = NCGostRelay.options(p).1 { return why }
        case "naive", "http2", "h2", "http3", "h3":
            if NCH2H3ProxyOptions(proxy: p) == nil { return "\(t) 缺少 server / port" }
        case "openconnect", "anyconnect":
            if let why = NCOpenConnect.unsupportedReason(p) { return why }
            return NCOpenConnect.dataPlaneUnavailable
        case "sudoku":
            if let why = sudokuUnsupported(p) { return why }
            return NCSudoku.interopUnavailable
        case "tuic":
            let hasToken = !(p.fields["token"]?.string ?? "").isEmpty
            if !hasToken && (p.uuid ?? "").isEmpty { return "TUIC 缺少 uuid / token" }
        case "juicity":
            let u = (p.uuid ?? "").trimmingCharacters(in: .whitespaces)
            let pwd = (p.password ?? "").trimmingCharacters(in: .whitespaces)
            if u.isEmpty || pwd.isEmpty { return "Juicity 缺少 uuid / password" }
        case "trusttunnel", "trust-tunnel":
            if let why = trusttunnelUnsupported(p) { return why }
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

    /// nil = plugin supported; else the reason (mirrors Clash.Meta NewShadowSocks' option checks;
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
            // NCGostPluginOptions: Clash.Meta's only mode (websocket) with tls / mux / fingerprint /
            // name-cert-verify; client certificates and ECH are explicit gaps.
            return NCGostPluginOptions.parse(opts).1
        case "cloak", "ck-client":
            return NCCloakPluginOptions.parse(opts, fallbackHost: proxy.fields["server"]?.string).1
        case "kcptun":
            return NCKcptunOptions.parse(opts).1
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

    /// Snell obfs-opts (fix/nc-silent-fail): simple-obfs http / tls are implemented (NCConnector.snellObfsOptions →
    /// NCSSPluginStream, TCP and UDP); Clash.Meta's other modes (shadow-tls / restls / jls) are not yet.
    static func snellUnsupported(_ p: NCProxy) -> String? {
        let mode = p.fields["obfs-opts"]?.object?["mode"]?.string ?? ""
        if mode.isEmpty || mode == "http" || mode == "tls" { return nil }
        return "Snell obfs-opts mode \(mode) 尚未接入（支持 http / tls）"
    }

    /// SSR: stream ciphers + none/dummy; every protocol and obfs Clash.Meta v1.19.33 registers (feat/nc-proto A5).
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

    /// Clash.Meta parsePorts syntax: "443,1000-2000".
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

    /// TrustTunnel (NCTrustTunnel, feat/nc-trusttunnel): HTTP/2 and HTTP/3 tunnel proxy.
    static func trusttunnelUnsupported(_ p: NCProxy) -> String? {
        if (p.server ?? "").isEmpty { return "TrustTunnel 缺少 server" }
        if (p.port ?? 0) == 0 { return "TrustTunnel 缺少 port" }
        let username = p.fields["username"]?.string ?? ""
        if username.isEmpty { return "TrustTunnel 缺少 username" }
        let password = p.password ?? p.fields["password"]?.string ?? ""
        if password.isEmpty { return "TrustTunnel 缺少 password" }
        if p.fields["anti-dpi"]?.bool == true
            || !(p.fields["client-random-prefix"]?.string ?? "").isEmpty
            || !(p.fields["client_random_prefix"]?.string ?? "").isEmpty {
            return "TrustTunnel anti-dpi / client-random-prefix 尚未接入"
        }
        if !(p.fields["client-random-auth-key"]?.string ?? "").isEmpty
            || !(p.fields["client_random_auth_key"]?.string ?? "").isEmpty {
            return "TrustTunnel client-random-auth-key 尚未接入"
        }
        if p.fields["icmp"]?.bool == true {
            return "TrustTunnel icmp 尚未接入"
        }
        // fix/nc-proto-trusttunnel-int (review of #161): the HTTP/3 track sends no control stream / SETTINGS,
        // writes payload raw instead of in HTTP/3 DATA frames, and its stream object is not retained during
        // the handshake (dial completes with neither stream nor error). Unavailable until that is redone.
        let quic = p.fields["quic"]?.bool ?? false
        let net = (p.fields["network"]?.string ?? "").lowercased()
        if quic || net == "h3" || net == "quic" { return "TrustTunnel HTTP/3（quic: true）尚未接入，请用 HTTP/2" }
        if !net.isEmpty && net != "h2" && net != "tcp" { return "TrustTunnel network \(net) 尚未接入" }
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

    /// MASQUE (RFC 9298 CONNECT-UDP / RFC 9484 CONNECT-IP):
    /// Requires server, port, and either (private-key, public-key, ip/ipv6) for WARP/CONNECT-IP
    /// or (username/password) for RFC 9298 HTTP/3 proxying.
    static func masqueUnsupported(_ p: NCProxy) -> String? {
        if p.server == nil || (p.server ?? "").isEmpty || (p.port ?? 0) <= 0 {
            return "MASQUE 缺少 server / port"
        }
        let f = p.fields
        if let explicit = f["unsupported"]?.string, !explicit.isEmpty {
            return explicit
        }
        let priv = f["private-key"]?.string ?? f["privateKey"]?.string ?? ""
        let pub = f["public-key"]?.string ?? f["publicKey"]?.string ?? ""
        let user = f["username"]?.string ?? ""
        let pass = p.password ?? f["password"]?.string ?? ""
        let hasKeys = !priv.isEmpty && !pub.isEmpty
        let hasCreds = !user.isEmpty || !pass.isEmpty
        let explicitIP = (f["mode"]?.string?.lowercased() == "connect-ip")
        if !hasKeys && !hasCreds && !explicitIP {
            return "MASQUE 缺少 private-key / public-key 或认证凭据"
        }
        if hasKeys && (f["ip"]?.string ?? "").isEmpty && (f["ipv6"]?.string ?? "").isEmpty && (f["network"]?.string ?? "") != "h3-l4proxy" {
            return "MASQUE CONNECT-IP 缺少 ip / ipv6"
        }
        if let net = f["network"]?.string?.lowercased(), !net.isEmpty {
            if net != "h3" && net != "quic" && net != "h2" && net != "h3-l4proxy" {
                return "MASQUE network \(net) 尚未接入（仅支持 h3 / quic / h2 / h3-l4proxy）"
            }
        }
        if let stack = f["ip-stack"]?.object?["mode"]?.string?.lowercased() ?? f["ip-stack"]?.string?.lowercased(), !stack.isEmpty {
            if stack != "lwip" && stack != "system" {
                return "MASQUE ip-stack \(stack) 尚未接入（仅支持 lwip / system）"
            }
        }
        if let hopping = f["port-hopping"]?.string, !hopping.isEmpty {
            return "MASQUE port-hopping 尚未接入"
        }
        // fix/nc-proto-masque-int: only RFC 9298 CONNECT-UDP (mode: connect-udp, QUIC) is wired, and only for UDP
        // (NCUDPMASQUESession). WARP / CONNECT-IP keys and h3-l4proxy were shown available but every dial refused.
        guard let cfg = NCMASQUE.Config(proxy: p) else { return "MASQUE 配置无效" }
        switch cfg.mode {
        case .connectUDP:
            if cfg.network == "h2" { return "MASQUE over HTTP/2 尚未接入（仅 HTTP/3）" }
        case .connectIP:
            // fix/nc-masque-ip: RFC 9484 CONNECT-IP over HTTP/3 with a lwIP netif (PacketTunnel). WARP profiles
            // (key pair → Cloudflare cf-connect-ip + mTLS) are not wired.
            if hasKeys { return NCMASQUE.warpUnavailable }
            if cfg.network == "h2" { return "MASQUE CONNECT-IP over HTTP/2 尚未接入（仅 HTTP/3）" }
        case .l4Proxy:
            return "MASQUE h3-l4proxy 尚未接入"
        }
        return nil
    }

    /// Sudoku (NCSudoku, feat/nc-sudoku): validation and unsupported marker checks.
    static func sudokuUnsupported(_ p: NCProxy) -> String? {
        NCSudoku.unsupportedReason(p)
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
