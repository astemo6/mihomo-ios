import SwiftUI

/// Declarative per-protocol form (Shadowrocket style). Keys are mihomo proxy keys; dots = nested maps.
struct FieldSpec: Identifiable {
    enum Kind { case text, secure, int, bool, choice([String]), list, pem }
    var id: String { key }
    let key: String
    let label: String
    var kind: Kind = .text
    var placeholder: String = ""
}

enum NodeProtocols {
    static let all: [(type: String, title: String)] = [
        ("ss", "Shadowsocks"), ("ssr", "ShadowsocksR"), ("vmess", "VMess"), ("vless", "VLESS"),
        ("trojan", "Trojan"), ("hysteria2", "Hysteria2"), ("hysteria", "Hysteria"), ("tuic", "TUIC v5"),
        ("wireguard", "WireGuard"), ("snell", "Snell"), ("anytls", "AnyTLS"), ("mieru", "Mieru"),
        ("ssh", "SSH"), ("socks5", "SOCKS5"), ("http", "HTTP(S)"),
        // v0.13: protocols added to mihomo after v1.19.0 (all in v1.19.32).
        ("sudoku", "Sudoku"), ("masque", "MASQUE"), ("trusttunnel", "TrustTunnel"), ("shadowquic", "ShadowQUIC"),
        ("openvpn", "OpenVPN"), ("gost-relay", "GOST Relay"),
        // v0.18: experimental — tsnet runs inside the 50 MB tunnel extension.
        ("tailscale", "Tailscale"),
    ]

    /// v0.18: protocols shown with 实验性 (memory not yet measured on device).
    static let experimental: Set<String> = ["tailscale"]

    /// Overlay networks joined through a control plane: no server / port fields.
    static func serverless(_ type: String) -> Bool { ["tailscale", "zerotier", "easytier"].contains(type) }

    /// Protocols that are new in this release (shown with a short note in the editor).
    static let newer: Set<String> = ["sudoku", "masque", "trusttunnel", "shadowquic", "openvpn", "gost-relay"]

    /// One-line explanation under the protocol section for the newer protocols.
    static func note(for type: String) -> LocalizedStringKey? {
        switch type {
        case "sudoku": return "Sudoku：以数独编码伪装流量的 TCP 协议。密钥与服务端相同；HTTP 伪装可穿过只放行 HTTP 的网络或 CDN。"
        case "masque": return "MASQUE：基于 HTTP/3 的隧道（如 Cloudflare WARP 的 MASQUE 模式）。私钥与对端公钥来自服务端提供的参数。"
        case "trusttunnel": return "TrustTunnel：AdGuard 的 HTTP/2 · HTTP/3 隧道协议，用户名与密码由服务端分配。"
        case "shadowquic": return "ShadowQUIC：伪装成普通 QUIC（TLS 1.3）的代理协议，SNI 填被伪装的网站。"
        case "openvpn": return "OpenVPN：由内核在用户态完成连接，不会创建系统 VPN。CA 证书必填；把 .ovpn 中 <ca> 等段的 PEM 内容粘贴进来。"
        case "gost-relay": return "GOST Relay：GOST v3 的 relay 协议，可选 TLS 与多路复用。"
        case "tailscale": return "Tailscale：由内核在隧道扩展里加入你的 tailnet（不创建系统 VPN）。建议填写 Auth Key；目标不在 tailnet 路由内时连接会失败，访问公网需要设置出口节点。状态保存在 App Group 内核目录下。"
        default: return nil
        }
    }

    static let ssCiphers = ["aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
                            "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
                            "aes-128-cfb", "aes-256-cfb", "aes-128-ctr", "aes-256-ctr", "rc4-md5", "chacha20-ietf", "none"]

    static let transport: [FieldSpec] = [
        FieldSpec(key: "network", label: "传输", kind: .choice(["tcp", "ws", "grpc", "h2", "httpupgrade"])),
        FieldSpec(key: "ws-opts.path", label: "WS 路径", placeholder: "/"),
        FieldSpec(key: "ws-opts.headers.Host", label: "WS Host"),
        FieldSpec(key: "grpc-opts.grpc-service-name", label: "gRPC 服务名"),
    ]

    /// VLESS also speaks Xray's XHTTP (v0.13).
    static let vlessTransport: [FieldSpec] = [
        FieldSpec(key: "network", label: "传输", kind: .choice(["tcp", "ws", "grpc", "h2", "httpupgrade", "xhttp"])),
        FieldSpec(key: "ws-opts.path", label: "WS 路径", placeholder: "/"),
        FieldSpec(key: "ws-opts.headers.Host", label: "WS Host"),
        FieldSpec(key: "grpc-opts.grpc-service-name", label: "gRPC 服务名"),
        FieldSpec(key: "xhttp-opts.path", label: "XHTTP 路径", placeholder: "/"),
        FieldSpec(key: "xhttp-opts.host", label: "XHTTP Host"),
        FieldSpec(key: "xhttp-opts.mode", label: "XHTTP 模式", kind: .choice(["", "auto", "packet-up", "stream-up", "stream-one"])),
    ]

    /// Hides transport sub-fields that don't belong to the chosen network.
    static func visible(_ f: FieldSpec, values: [String: String]) -> Bool {
        let net = values["network"] ?? ""
        if f.key.hasPrefix("ws-opts.") { return net == "ws" || net == "httpupgrade" }
        if f.key.hasPrefix("grpc-opts.") { return net == "grpc" }
        if f.key.hasPrefix("xhttp-opts.") { return net == "xhttp" }
        if f.key.hasPrefix("http-mask-") || f.key == "path-root" { return (values["http-mask"] ?? "") == "true" }
        if f.key.hasPrefix("amnezia-wg-option.") { return (values["x-awg"] ?? "") == "true" }
        return true
    }

    static let tlsCommon: [FieldSpec] = [
        FieldSpec(key: "skip-cert-verify", label: "跳过证书验证", kind: .bool),
        FieldSpec(key: "client-fingerprint", label: "TLS 指纹", kind: .choice(["", "chrome", "firefox", "safari", "ios", "edge", "random"])),
    ]

    static func fields(for type: String) -> [FieldSpec] {
        switch type {
        case "ss":
            return [
                FieldSpec(key: "cipher", label: "加密", kind: .choice(ssCiphers)),
                FieldSpec(key: "password", label: "密码", kind: .secure),
                FieldSpec(key: "plugin", label: "插件", kind: .choice(["", "obfs", "v2ray-plugin", "shadow-tls"])),
                FieldSpec(key: "plugin-opts.mode", label: "插件模式", placeholder: "http / tls / websocket"),
                FieldSpec(key: "plugin-opts.host", label: "插件 Host"),
                FieldSpec(key: "plugin-opts.path", label: "插件路径（v2ray-plugin）"),
                FieldSpec(key: "plugin-opts.password", label: "shadow-tls 密码", kind: .secure),
                FieldSpec(key: "plugin-opts.version", label: "shadow-tls 版本", kind: .int, placeholder: "3"),
                FieldSpec(key: "udp", label: "UDP", kind: .bool),
            ]
        case "ssr":
            return [
                FieldSpec(key: "cipher", label: "加密", kind: .choice(ssCiphers)),
                FieldSpec(key: "password", label: "密码", kind: .secure),
                FieldSpec(key: "obfs", label: "混淆", kind: .choice(["plain", "http_simple", "http_post", "tls1.2_ticket_auth", "random_head"])),
                FieldSpec(key: "obfs-param", label: "混淆参数"),
                FieldSpec(key: "protocol", label: "协议", kind: .choice(["origin", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a", "auth_chain_b"])),
                FieldSpec(key: "protocol-param", label: "协议参数"),
                FieldSpec(key: "udp", label: "UDP", kind: .bool),
            ]
        case "vmess":
            return [
                FieldSpec(key: "uuid", label: "UUID"),
                FieldSpec(key: "alterId", label: "alterId", kind: .int, placeholder: "0"),
                FieldSpec(key: "cipher", label: "加密", kind: .choice(["auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"])),
                FieldSpec(key: "tls", label: "TLS", kind: .bool),
                FieldSpec(key: "servername", label: "SNI"),
                FieldSpec(key: "udp", label: "UDP", kind: .bool),
            ] + transport + tlsCommon
        case "vless":
            return [
                FieldSpec(key: "uuid", label: "UUID"),
                FieldSpec(key: "flow", label: "Flow", kind: .choice(["", "xtls-rprx-vision"])),
                FieldSpec(key: "encryption", label: "加密", placeholder: "none / mlkem768x25519plus…"),
                FieldSpec(key: "tls", label: "TLS", kind: .bool),
                FieldSpec(key: "servername", label: "SNI"),
                FieldSpec(key: "alpn", label: "ALPN", kind: .list, placeholder: "h2,http/1.1"),
                FieldSpec(key: "reality-opts.public-key", label: "Reality 公钥"),
                FieldSpec(key: "reality-opts.short-id", label: "Reality Short ID"),
                FieldSpec(key: "udp", label: "UDP", kind: .bool),
                FieldSpec(key: "packet-encoding", label: "UDP 封装", kind: .choice(["", "xudp", "packetaddr"])),
            ] + vlessTransport + tlsCommon
        case "trojan":
            return [
                FieldSpec(key: "password", label: "密码", kind: .secure),
                FieldSpec(key: "sni", label: "SNI"),
                FieldSpec(key: "udp", label: "UDP", kind: .bool),
            ] + transport + tlsCommon
        case "hysteria2":
            return [
                FieldSpec(key: "password", label: "密码", kind: .secure),
                FieldSpec(key: "sni", label: "SNI"),
                FieldSpec(key: "obfs", label: "混淆", kind: .choice(["", "salamander"])),
                FieldSpec(key: "obfs-password", label: "混淆密码", kind: .secure),
                FieldSpec(key: "ports", label: "端口跳跃", placeholder: "20000-30000"),
                FieldSpec(key: "hop-interval", label: "跳跃间隔（秒）", placeholder: "30"),
                FieldSpec(key: "alpn", label: "ALPN", kind: .list, placeholder: "h3"),
                FieldSpec(key: "up", label: "上行带宽", placeholder: "50 Mbps"),
                FieldSpec(key: "down", label: "下行带宽", placeholder: "200 Mbps"),
                FieldSpec(key: "skip-cert-verify", label: "跳过证书验证", kind: .bool),
            ]
        case "hysteria":
            return [
                FieldSpec(key: "auth-str", label: "认证", kind: .secure),
                FieldSpec(key: "protocol", label: "协议", kind: .choice(["udp", "wechat-video", "faketcp"])),
                FieldSpec(key: "up", label: "上行", placeholder: "50 Mbps"),
                FieldSpec(key: "down", label: "下行", placeholder: "200 Mbps"),
                FieldSpec(key: "sni", label: "SNI"),
                FieldSpec(key: "obfs", label: "混淆"),
                FieldSpec(key: "alpn", label: "ALPN", kind: .list, placeholder: "h3"),
                FieldSpec(key: "skip-cert-verify", label: "跳过证书验证", kind: .bool),
            ]
        case "tuic":
            return [
                FieldSpec(key: "uuid", label: "UUID"),
                FieldSpec(key: "password", label: "密码", kind: .secure),
                FieldSpec(key: "sni", label: "SNI"),
                FieldSpec(key: "alpn", label: "ALPN", kind: .list, placeholder: "h3"),
                FieldSpec(key: "congestion-controller", label: "拥塞控制", kind: .choice(["bbr", "cubic", "new_reno"])),
                FieldSpec(key: "udp-relay-mode", label: "UDP 转发", kind: .choice(["native", "quic"])),
                FieldSpec(key: "skip-cert-verify", label: "跳过证书验证", kind: .bool),
            ]
        case "wireguard":
            return [
                FieldSpec(key: "private-key", label: "私钥", kind: .secure),
                FieldSpec(key: "public-key", label: "对端公钥"),
                FieldSpec(key: "pre-shared-key", label: "预共享密钥", kind: .secure),
                FieldSpec(key: "ip", label: "本地 IPv4", placeholder: "172.16.0.2"),
                FieldSpec(key: "ipv6", label: "本地 IPv6"),
                FieldSpec(key: "reserved", label: "Reserved", placeholder: "1,2,3"),
                FieldSpec(key: "mtu", label: "MTU", kind: .int, placeholder: "1408"),
                FieldSpec(key: "udp", label: "UDP", kind: .bool),
                FieldSpec(key: "x-awg", label: "AmneziaWG", kind: .bool),
                FieldSpec(key: "amnezia-wg-option.jc", label: "Jc", kind: .int, placeholder: "4"),
                FieldSpec(key: "amnezia-wg-option.jmin", label: "Jmin", kind: .int, placeholder: "40"),
                FieldSpec(key: "amnezia-wg-option.jmax", label: "Jmax", kind: .int, placeholder: "70"),
                FieldSpec(key: "amnezia-wg-option.s1", label: "S1", kind: .int, placeholder: "0"),
                FieldSpec(key: "amnezia-wg-option.s2", label: "S2", kind: .int, placeholder: "0"),
                FieldSpec(key: "amnezia-wg-option.h1", label: "H1", kind: .int, placeholder: "1"),
                FieldSpec(key: "amnezia-wg-option.h2", label: "H2", kind: .int, placeholder: "2"),
                FieldSpec(key: "amnezia-wg-option.h3", label: "H3", kind: .int, placeholder: "3"),
                FieldSpec(key: "amnezia-wg-option.h4", label: "H4", kind: .int, placeholder: "4"),
            ]
        case "snell":
            return [
                FieldSpec(key: "psk", label: "PSK", kind: .secure),
                FieldSpec(key: "version", label: "版本", kind: .int, placeholder: "4"),
                FieldSpec(key: "obfs-opts.mode", label: "混淆", kind: .choice(["", "http", "tls"])),
                FieldSpec(key: "obfs-opts.host", label: "混淆 Host"),
                FieldSpec(key: "udp", label: "UDP", kind: .bool),
            ]
        case "anytls":
            return [
                FieldSpec(key: "password", label: "密码", kind: .secure),
                FieldSpec(key: "sni", label: "SNI"),
                FieldSpec(key: "alpn", label: "ALPN", kind: .list, placeholder: "h2,http/1.1"),
                FieldSpec(key: "udp", label: "UDP", kind: .bool),
                FieldSpec(key: "idle-session-timeout", label: "空闲会话超时（秒）", kind: .int, placeholder: "30"),
                FieldSpec(key: "min-idle-session", label: "最少空闲会话", kind: .int, placeholder: "0"),
            ] + tlsCommon
        case "sudoku":
            return [
                FieldSpec(key: "key", label: "密钥", kind: .secure),
                FieldSpec(key: "aead-method", label: "加密", kind: .choice(["", "chacha20-poly1305", "aes-128-gcm", "none"])),
                FieldSpec(key: "table-type", label: "编码表", kind: .choice(["", "prefer_ascii", "prefer_entropy", "up_ascii_down_entropy", "up_entropy_down_ascii"])),
                FieldSpec(key: "padding-min", label: "最小填充", kind: .int, placeholder: "2"),
                FieldSpec(key: "padding-max", label: "最大填充", kind: .int, placeholder: "7"),
                FieldSpec(key: "enable-pure-downlink", label: "纯下行", kind: .bool),
                FieldSpec(key: "multiplex", label: "多路复用", kind: .choice(["", "off", "auto", "on"])),
                FieldSpec(key: "http-mask", label: "HTTP 伪装", kind: .bool),
                FieldSpec(key: "http-mask-mode", label: "伪装模式", kind: .choice(["", "legacy", "stream", "poll", "auto", "ws"])),
                FieldSpec(key: "http-mask-tls", label: "伪装使用 TLS", kind: .bool),
                FieldSpec(key: "http-mask-host", label: "伪装 Host"),
                FieldSpec(key: "path-root", label: "路径前缀", placeholder: "/api"),
            ]
        case "masque":
            return [
                FieldSpec(key: "private-key", label: "私钥", kind: .secure),
                FieldSpec(key: "public-key", label: "对端公钥"),
                FieldSpec(key: "ip", label: "本地 IPv4", placeholder: "172.16.0.2"),
                FieldSpec(key: "ipv6", label: "本地 IPv6"),
                FieldSpec(key: "sni", label: "SNI"),
                FieldSpec(key: "uri", label: "URI", placeholder: "https://cloudflareaccess.com"),
                FieldSpec(key: "mtu", label: "MTU", kind: .int, placeholder: "1280"),
                FieldSpec(key: "udp", label: "UDP", kind: .bool),
                FieldSpec(key: "remote-dns-resolve", label: "远端解析 DNS", kind: .bool),
                FieldSpec(key: "dns", label: "DNS", kind: .list, placeholder: "1.1.1.1"),
                FieldSpec(key: "congestion-controller", label: "拥塞控制", kind: .choice(["", "bbr", "cubic", "new_reno"])),
                FieldSpec(key: "skip-cert-verify", label: "跳过证书验证", kind: .bool),
            ]
        case "trusttunnel":
            return [
                FieldSpec(key: "username", label: "用户名"),
                FieldSpec(key: "password", label: "密码", kind: .secure),
                FieldSpec(key: "sni", label: "SNI"),
                FieldSpec(key: "alpn", label: "ALPN", kind: .list, placeholder: "h2"),
                FieldSpec(key: "quic", label: "使用 HTTP/3（QUIC）", kind: .bool),
                FieldSpec(key: "congestion-controller", label: "拥塞控制", kind: .choice(["", "bbr", "cubic", "new_reno"])),
                FieldSpec(key: "udp", label: "UDP", kind: .bool),
                FieldSpec(key: "health-check", label: "健康检查", kind: .bool),
                FieldSpec(key: "max-connections", label: "最大连接数", kind: .int, placeholder: "8"),
            ] + tlsCommon
        case "shadowquic":
            return [
                FieldSpec(key: "username", label: "用户名"),
                FieldSpec(key: "password", label: "密码", kind: .secure),
                FieldSpec(key: "sni", label: "SNI（伪装站点）", placeholder: "www.example.com"),
                FieldSpec(key: "alpn", label: "ALPN", kind: .list, placeholder: "h3"),
                FieldSpec(key: "congestion-controller", label: "拥塞控制", kind: .choice(["", "bbr", "cubic", "new_reno"])),
                FieldSpec(key: "zero-rtt", label: "0-RTT", kind: .bool),
                FieldSpec(key: "udp-over-stream", label: "UDP 走流", kind: .bool),
                FieldSpec(key: "up", label: "上行带宽", placeholder: "50 Mbps"),
                FieldSpec(key: "down", label: "下行带宽", placeholder: "200 Mbps"),
            ]
        case "openvpn":
            return [
                FieldSpec(key: "proto", label: "传输", kind: .choice(["udp", "tcp"])),
                FieldSpec(key: "username", label: "用户名"),
                FieldSpec(key: "password", label: "密码", kind: .secure),
                FieldSpec(key: "cipher", label: "加密", kind: .choice(["", "AES-128-GCM", "AES-256-GCM", "CHACHA20-POLY1305", "AES-256-CBC", "AES-128-CBC"])),
                FieldSpec(key: "auth", label: "HMAC", kind: .choice(["", "SHA1", "SHA256", "SHA512"])),
                FieldSpec(key: "ca", label: "CA 证书", kind: .pem),
                FieldSpec(key: "cert", label: "客户端证书", kind: .pem),
                FieldSpec(key: "key", label: "客户端私钥", kind: .pem),
                FieldSpec(key: "tls-auth", label: "tls-auth 密钥", kind: .pem),
                FieldSpec(key: "key-direction", label: "key-direction", kind: .choice(["", "0", "1"])),
                FieldSpec(key: "tls-crypt", label: "tls-crypt 密钥", kind: .pem),
                FieldSpec(key: "mtu", label: "MTU", kind: .int, placeholder: "1400"),
                FieldSpec(key: "udp", label: "UDP", kind: .bool),
                FieldSpec(key: "remote-dns-resolve", label: "远端解析 DNS", kind: .bool),
                FieldSpec(key: "dns", label: "DNS", kind: .list, placeholder: "10.8.0.1"),
            ]
        case "gost-relay":
            return [
                FieldSpec(key: "username", label: "用户名"),
                FieldSpec(key: "password", label: "密码", kind: .secure),
                FieldSpec(key: "tls", label: "TLS", kind: .bool),
                FieldSpec(key: "sni", label: "SNI"),
                FieldSpec(key: "mux", label: "多路复用", kind: .bool),
                FieldSpec(key: "udp", label: "UDP", kind: .bool),
                FieldSpec(key: "skip-cert-verify", label: "跳过证书验证", kind: .bool),
            ]
        case "tailscale":
            return [
                FieldSpec(key: "auth-key", label: "Auth Key", kind: .secure, placeholder: "tskey-auth-…"),
                FieldSpec(key: "hostname", label: "设备名", placeholder: "mihomo-ios"),
                FieldSpec(key: "control-url", label: "控制服务器（Headscale）", placeholder: "https://controlplane.tailscale.com"),
                FieldSpec(key: "state-dir", label: "状态目录", placeholder: "留空为 tailscale/节点名"),
                FieldSpec(key: "ephemeral", label: "临时设备（Ephemeral）", kind: .bool),
                FieldSpec(key: "udp", label: "UDP", kind: .bool),
                FieldSpec(key: "accept-routes", label: "接受子网路由", kind: .bool),
                FieldSpec(key: "exit-node", label: "出口节点", placeholder: "100.64.0.1 / auto:any"),
                FieldSpec(key: "exit-node-allow-lan-access", label: "使用出口节点时允许访问局域网", kind: .bool),
            ]
        case "mieru":
            return [
                FieldSpec(key: "username", label: "用户名"),
                FieldSpec(key: "password", label: "密码", kind: .secure),
                FieldSpec(key: "transport", label: "传输", kind: .choice(["TCP", "UDP"])),
                FieldSpec(key: "port-range", label: "端口范围", placeholder: "2090-2099"),
                FieldSpec(key: "multiplexing", label: "多路复用", kind: .choice(["", "MULTIPLEXING_OFF", "MULTIPLEXING_LOW", "MULTIPLEXING_MIDDLE", "MULTIPLEXING_HIGH"])),
            ]
        case "ssh":
            return [
                FieldSpec(key: "username", label: "用户名"),
                FieldSpec(key: "password", label: "密码", kind: .secure),
                FieldSpec(key: "private-key", label: "私钥（可选）", kind: .secure),
            ]
        case "socks5":
            return [
                FieldSpec(key: "username", label: "用户名"),
                FieldSpec(key: "password", label: "密码", kind: .secure),
                FieldSpec(key: "tls", label: "TLS", kind: .bool),
                FieldSpec(key: "udp", label: "UDP", kind: .bool),
                FieldSpec(key: "skip-cert-verify", label: "跳过证书验证", kind: .bool),
            ]
        case "http":
            return [
                FieldSpec(key: "username", label: "用户名"),
                FieldSpec(key: "password", label: "密码", kind: .secure),
                FieldSpec(key: "tls", label: "HTTPS（TLS）", kind: .bool),
                FieldSpec(key: "sni", label: "SNI"),
                FieldSpec(key: "skip-cert-verify", label: "跳过证书验证", kind: .bool),
            ]
        default:
            return []
        }
    }

    // v0.8 高级: only where mihomo v1.19.32 reads the key for that protocol.
    static let echTypes: Set<String> = ["vmess", "vless", "trojan", "hysteria", "hysteria2", "tuic", "anytls", "trusttunnel"]
    static let pinTypes: Set<String> = ["vmess", "vless", "trojan", "hysteria", "hysteria2", "tuic", "anytls", "http", "socks5", "trusttunnel", "gost-relay"]
    static let smuxTypes: Set<String> = ["ss", "vmess", "vless", "trojan"]
    /// QUIC / UDP-based protocols: TCP Fast Open and MPTCP don't apply.
    static let udpOnlyTypes: Set<String> = ["hysteria", "hysteria2", "tuic", "wireguard", "masque", "shadowquic"]

    static func advanced(for type: String) -> [FieldSpec] {
        var f: [FieldSpec] = []
        if serverless(type) {
            return [FieldSpec(key: "ip-version", label: "IP 版本", kind: .choice(["", "dual", "ipv4", "ipv6", "ipv4-prefer", "ipv6-prefer"]))]
        }
        if echTypes.contains(type) {
            f.append(FieldSpec(key: "ech-opts.enable", label: "ECH", kind: .bool))
            f.append(FieldSpec(key: "ech-opts.config", label: "ECHConfig", placeholder: "Base64（留空则查询 DNS）"))
        }
        if pinTypes.contains(type) {
            f.append(FieldSpec(key: "fingerprint", label: "证书指纹", placeholder: "SHA-256（十六进制）"))
        }
        if smuxTypes.contains(type) {
            f.append(FieldSpec(key: "smux.enabled", label: "多路复用（smux）", kind: .bool))
            f.append(FieldSpec(key: "smux.protocol", label: "复用协议", kind: .choice(["", "h2mux", "smux", "yamux"])))
            f.append(FieldSpec(key: "smux.max-connections", label: "最大连接数", kind: .int, placeholder: "4"))
            f.append(FieldSpec(key: "smux.padding", label: "填充", kind: .bool))
        }
        if !udpOnlyTypes.contains(type) {
            f.append(FieldSpec(key: "tfo", label: "TCP Fast Open", kind: .bool))
            f.append(FieldSpec(key: "mptcp", label: "MPTCP", kind: .bool))
        }
        f.append(FieldSpec(key: "ip-version", label: "IP 版本", kind: .choice(["", "dual", "ipv4", "ipv6", "ipv4-prefer", "ipv6-prefer"])))
        return f
    }

    static func defaults(for type: String) -> [String: String] {
        switch type {
        case "ss": return ["cipher": "aes-128-gcm", "udp": "true"]
        case "ssr": return ["cipher": "aes-256-cfb", "obfs": "plain", "protocol": "origin"]
        case "vmess": return ["cipher": "auto", "alterId": "0", "network": "tcp", "udp": "true"]
        case "vless": return ["network": "tcp", "tls": "true", "udp": "true"]
        case "trojan", "anytls": return ["udp": "true", "network": "tcp"]
        case "tuic": return ["alpn": "h3", "congestion-controller": "bbr", "udp-relay-mode": "native"]
        case "wireguard": return ["udp": "true", "ip": "172.16.0.2"]
        case "snell": return ["version": "4", "udp": "true"]
        case "mieru": return ["transport": "TCP"]
        case "socks5": return ["udp": "true"]
        case "sudoku": return ["aead-method": "chacha20-poly1305", "table-type": "prefer_ascii"]
        case "masque": return ["udp": "true", "ip": "172.16.0.2", "mtu": "1280"]
        case "trusttunnel": return ["udp": "true", "alpn": "h2"]
        case "shadowquic": return ["alpn": "h3", "congestion-controller": "bbr"]
        case "openvpn": return ["proto": "udp", "udp": "true"]
        case "gost-relay": return ["udp": "true"]
        case "tailscale": return ["udp": "true"]
        default: return [:]
        }
    }

    // MARK: dict <-> flat

    static func flatten(_ d: [String: Any], prefix: String = "", into out: inout [String: String]) {
        for (k, v) in d {
            let key = prefix.isEmpty ? k : "\(prefix).\(k)"
            switch v {
            case let m as [String: Any]: flatten(m, prefix: key, into: &out)
            case let a as [Any]: out[key] = a.map { "\($0)" }.joined(separator: ",")
            case let n as NSNumber:
                if CFGetTypeID(n) == CFBooleanGetTypeID() { out[key] = n.boolValue ? "true" : "false" } else { out[key] = n.stringValue }
            default: out[key] = "\(v)"
            }
        }
    }

    static func setNested(_ d: inout [String: Any], _ path: [String], _ value: Any) {
        guard let first = path.first else { return }
        if path.count == 1 { d[first] = value; return }
        var child = d[first] as? [String: Any] ?? [:]
        setNested(&child, Array(path.dropFirst()), value)
        d[first] = child
    }

    static func removeNested(_ d: inout [String: Any], _ path: [String]) {
        guard let first = path.first else { return }
        if path.count == 1 { d.removeValue(forKey: first); return }
        guard var child = d[first] as? [String: Any] else { return }
        removeNested(&child, Array(path.dropFirst()))
        d[first] = child.isEmpty ? nil : child
    }
}

struct NodeEditorView: View {
    @EnvironmentObject var store: ProfileStore
    @Environment(\.dismiss) var dismiss

    let original: [String: Any]?
    /// v0.15.4: the node lives in this profile file (节点管理 → 配置); saving writes it back there.
    var profile: Profile? = nil
    @State private var type: String
    @State private var name: String
    @State private var server: String
    @State private var port: String
    @State private var values: [String: String]
    @State private var error: String?
    @State private var busy = false
    @State private var dialer: String
    @State private var showAdvanced = false

    /// v0.16 添加节点: a new node of a given protocol with optional preset fields (same as the QX preview's).
    init(newType t: String, preset: [String: String] = [:]) {
        original = nil
        _type = State(initialValue: t)
        _name = State(initialValue: "")
        _server = State(initialValue: "")
        _port = State(initialValue: "")
        var flat = NodeProtocols.defaults(for: t)
        for (k, v) in preset { flat[k] = v }
        _values = State(initialValue: flat)
        _dialer = State(initialValue: "")
    }

    init(node: [String: Any]?, profile: Profile? = nil) {
        original = node
        self.profile = profile
        let t = node?["type"] as? String ?? "ss"
        _type = State(initialValue: t)
        _name = State(initialValue: node?["name"] as? String ?? "")
        _server = State(initialValue: node?["server"] as? String ?? "")
        _port = State(initialValue: node.flatMap { ($0["port"] as? NSNumber)?.stringValue ?? $0["port"] as? String } ?? "")
        var flat: [String: String] = [:]
        if let node { NodeProtocols.flatten(node, into: &flat) } else { flat = NodeProtocols.defaults(for: t) }
        if node?["amnezia-wg-option"] != nil { flat["x-awg"] = "true" }
        _values = State(initialValue: flat)
        _dialer = State(initialValue: node?["dialer-proxy"] as? String ?? "")
    }

    /// Where the node's 前置代理 is resolved: the active profile when manual nodes are merged into it,
    /// otherwise the 手动节点 profile itself.
    var chainProfilePath: String {
        if let profile { return profile.fileURL.path }
        if CoreOverrides.load().mergeManual, let a = AppShared.activeProfileURL, AppShared.activeProfileID != ProfileStore.manualID {
            return a.path
        }
        return AppShared.profileURL(id: ProfileStore.manualID).path
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("基本") {
                    Picker("协议", selection: $type) {
                        ForEach(NodeProtocols.all, id: \.type) { p in
                            Text(NodeProtocols.experimental.contains(p.type) ? "\(p.title) · " + String(localized: "实验性")
                                 : NodeProtocols.newer.contains(p.type) ? "\(p.title) · " + String(localized: "新") : p.title).tag(p.type)
                        }
                    }
                    TextField("名称", text: $name)
                    if !NodeProtocols.serverless(type) {
                        TextField("服务器", text: $server).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                        TextField("端口", text: $port).keyboardType(.numberPad)
                    }
                }
                .listRowBackground(Theme.card)
                if NodeProtocols.experimental.contains(type) {
                    Section {
                        ExperimentalMemoryWarning()
                    }
                    .listRowBackground(Theme.card)
                }
                Section {
                    ForEach(NodeProtocols.fields(for: type).filter { NodeProtocols.visible($0, values: values) }) { f in field(f) }
                } header: {
                    Text(protoTitle + " " + String(localized: "参数"))
                } footer: {
                    if let n = NodeProtocols.note(for: type) { Text(n) }
                }
                .listRowBackground(Theme.card)
                Section {
                    DisclosureGroup("高级", isExpanded: $showAdvanced) {
                        ForEach(NodeProtocols.advanced(for: type)) { f in field(f) }
                    }
                } footer: {
                    if showAdvanced {
                        Text("ECH 与证书指纹需要服务端配合；多路复用要求服务端开启 sing-mux。「IP 版本」留空时使用「连接方式 → 节点 IP 优先」。")
                    }
                }
                .listRowBackground(Theme.card)
                Section {
                    NavigationLink {
                        ChainPickerView(kind: "node", name: (original?["name"] as? String) ?? name, profilePath: chainProfilePath,
                                        selected: dialer.isEmpty ? nil : dialer) { dialer = $0 ?? "" }
                    } label: {
                        LabeledContent("前置代理", value: dialer.isEmpty ? String(localized: "无") : dialer)
                    }
                } footer: {
                    Text("先经过另一个节点或策略组再连接这个节点（代理链）。开启「把手动节点加入每个配置」后，也可以选择当前订阅里的策略组。")
                }
                .listRowBackground(Theme.card)
                if let error {
                    Section { Text(error).font(.footnote).foregroundStyle(Theme.bad) }.listRowBackground(Theme.card)
                }
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle(original == nil ? "添加节点" : "编辑节点")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    if busy { ProgressView() } else { Button("保存") { save() }.disabled(!NodeProtocols.serverless(type) && (server.isEmpty || port.isEmpty)) }
                }
            }
            .onChange(of: type) { t in
                if (original?["type"] as? String) != t {
                    values = NodeProtocols.defaults(for: t)
                }
            }
            .onAppear {
                showAdvanced = NodeProtocols.advanced(for: type).contains { !(values[$0.key] ?? "").isEmpty && values[$0.key] != "false" }
            }
        }
    }

    var protoTitle: String { NodeProtocols.all.first(where: { $0.type == type })?.title ?? type }

    @ViewBuilder
    func field(_ f: FieldSpec) -> some View {
        let binding = Binding<String>(get: { values[f.key] ?? "" }, set: { values[f.key] = $0 })
        switch f.kind {
        case .text, .list:
            HStack {
                Text(LocalizedStringKey(f.label)).foregroundStyle(.secondary)
                TextField(LocalizedStringKey(f.placeholder.isEmpty ? f.label : f.placeholder), text: binding)
                    .multilineTextAlignment(.trailing).textInputAutocapitalization(.never).autocorrectionDisabled()
            }
        case .secure:
            HStack {
                Text(LocalizedStringKey(f.label)).foregroundStyle(.secondary)
                SecureField(LocalizedStringKey(f.placeholder.isEmpty ? f.label : f.placeholder), text: binding).multilineTextAlignment(.trailing)
            }
        case .int:
            HStack {
                Text(LocalizedStringKey(f.label)).foregroundStyle(.secondary)
                TextField(LocalizedStringKey(f.placeholder), text: binding).keyboardType(.numberPad).multilineTextAlignment(.trailing)
            }
        case .pem:
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text(LocalizedStringKey(f.label)).foregroundStyle(.secondary)
                    Spacer()
                    if !(values[f.key] ?? "").isEmpty {
                        Text("\((values[f.key] ?? "").split(separator: "\n").count) 行").font(.caption).foregroundStyle(.secondary)
                    }
                    Button("粘贴") {
                        if let s = UIPasteboard.general.string { values[f.key] = s.trimmingCharacters(in: .whitespacesAndNewlines) } // clipboard-read: explicit 粘贴 tap only (see ClipboardRuleTests)
                    }
                    .font(.caption.weight(.semibold)).buttonStyle(.borderless)
                }
                TextField("-----BEGIN …-----", text: binding, axis: .vertical)
                    .font(.caption.monospaced()).lineLimit(2...6)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
            }
        case .bool:
            Toggle(LocalizedStringKey(f.label), isOn: Binding(get: { (values[f.key] ?? "") == "true" }, set: { values[f.key] = $0 ? "true" : "false" }))
        case .choice(let opts):
            Picker(LocalizedStringKey(f.label), selection: binding) {
                ForEach(opts, id: \.self) { o in (o.isEmpty ? Text("无") : Text(verbatim: o)).tag(o) }
                if let v = values[f.key], !v.isEmpty, !opts.contains(v) { Text(verbatim: v).tag(v) }
            }
        }
    }

    func build() -> [String: Any] {
        var d: [String: Any] = [:]
        // Keep keys the form does not know about when editing the same protocol.
        if let o = original, (o["type"] as? String) == type { d = o }
        let specs = NodeProtocols.fields(for: type) + NodeProtocols.advanced(for: type)
        for f in specs { NodeProtocols.removeNested(&d, f.key.split(separator: ".").map(String.init)) }
        d["type"] = type
        let fallbackName = NodeProtocols.serverless(type) ? ProxyItem.label(for: type) : "\(ProxyItem.label(for: type)) \(server)"
        d["name"] = name.trimmingCharacters(in: .whitespaces).isEmpty ? fallbackName : name.trimmingCharacters(in: .whitespaces)
        if NodeProtocols.serverless(type) {
            d.removeValue(forKey: "server")
            d.removeValue(forKey: "port")
        } else {
            d["server"] = server.trimmingCharacters(in: .whitespaces)
            d["port"] = Int(port) ?? 0
        }
        for f in specs {
            if f.key == "x-awg" { continue }
            if f.key.hasPrefix("amnezia-wg-option."), values["x-awg"] != "true" { continue }
            if f.key.hasPrefix("xhttp-opts."), values["network"] != "xhttp" { continue }
            guard let raw = values[f.key]?.trimmingCharacters(in: .whitespaces), !raw.isEmpty else { continue }
            let path = f.key.split(separator: ".").map(String.init)
            let v: Any
            switch f.kind {
            case .int: v = Int(raw) ?? raw
            case .bool:
                if raw != "true" { continue }
                v = true
            case .list: v = raw.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            default:
                if f.key == "reserved", raw.contains(",") {
                    v = raw.split(separator: ",").compactMap { Int($0.trimmingCharacters(in: .whitespaces)) }
                } else { v = raw }
            }
            NodeProtocols.setNested(&d, path, v)
        }
        if (d["network"] as? String) == "tcp" { d.removeValue(forKey: "network") }
        let via = dialer.trimmingCharacters(in: .whitespaces)
        if via.isEmpty { d.removeValue(forKey: "dialer-proxy") } else { d["dialer-proxy"] = via }
        return d
    }

    func save() {
        busy = true; error = nil
        let node = build()
        Task {
            defer { busy = false }
            do {
                if let profile {
                    try await store.upsertProfileNode(profile, node, oldName: original?["name"] as? String)
                } else {
                    try await store.upsertManualNode(node, oldName: original?["name"] as? String)
                }
                dismiss()
            } catch { self.error = error.localizedDescription }
        }
    }
}

/// v0.18: the warning shown with the experimental Tailscale node (editor, node detail).
struct ExperimentalMemoryWarning: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("实验性：内存占用未经真机验证", systemImage: "exclamationmark.triangle.fill")
                .font(.subheadline.weight(.semibold)).foregroundStyle(Theme.warn)
            Text("iOS 只给 VPN 扩展约 50 MB 内存，Tailscale 会在扩展里额外运行一套网络栈。首次使用时如果剩余内存不足 14 MB 会拒绝启动；运行中剩余不足 5 MB 会自动停止 Tailscale，以免 VPN 被系统终止。在 更多 → 诊断 → 隧道内存 查看实际占用。")
                .font(.footnote).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("node.experimentalWarning")
    }
}
