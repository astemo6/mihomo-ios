import SwiftUI

/// Declarative per-protocol form (Shadowrocket style). Keys are mihomo proxy keys; dots = nested maps.
struct FieldSpec: Identifiable {
    enum Kind { case text, secure, int, bool, choice([String]), list }
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
    ]

    static let ssCiphers = ["aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
                            "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
                            "aes-128-cfb", "aes-256-cfb", "aes-128-ctr", "aes-256-ctr", "rc4-md5", "chacha20-ietf", "none"]

    static let transport: [FieldSpec] = [
        FieldSpec(key: "network", label: "传输", kind: .choice(["tcp", "ws", "grpc", "h2", "httpupgrade"])),
        FieldSpec(key: "ws-opts.path", label: "WS 路径", placeholder: "/"),
        FieldSpec(key: "ws-opts.headers.Host", label: "WS Host"),
        FieldSpec(key: "grpc-opts.grpc-service-name", label: "gRPC 服务名"),
    ]

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
                FieldSpec(key: "tls", label: "TLS", kind: .bool),
                FieldSpec(key: "servername", label: "SNI"),
                FieldSpec(key: "reality-opts.public-key", label: "Reality 公钥"),
                FieldSpec(key: "reality-opts.short-id", label: "Reality Short ID"),
                FieldSpec(key: "udp", label: "UDP", kind: .bool),
            ] + transport + tlsCommon
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
                FieldSpec(key: "udp", label: "UDP", kind: .bool),
            ] + tlsCommon
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
    static let echTypes: Set<String> = ["vmess", "vless", "trojan", "hysteria", "hysteria2", "tuic", "anytls"]
    static let pinTypes: Set<String> = ["vmess", "vless", "trojan", "hysteria", "hysteria2", "tuic", "anytls", "http", "socks5"]
    static let smuxTypes: Set<String> = ["ss", "vmess", "vless", "trojan"]
    /// QUIC / UDP-based protocols: TCP Fast Open and MPTCP don't apply.
    static let udpOnlyTypes: Set<String> = ["hysteria", "hysteria2", "tuic", "wireguard"]

    static func advanced(for type: String) -> [FieldSpec] {
        var f: [FieldSpec] = []
        if echTypes.contains(type) {
            f.append(FieldSpec(key: "ech-opts.enable", label: "ECH", kind: .bool))
            f.append(FieldSpec(key: "ech-opts.config", label: "ECH 配置", placeholder: "Base64（留空则查询 DNS）"))
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
    @State private var type: String
    @State private var name: String
    @State private var server: String
    @State private var port: String
    @State private var values: [String: String]
    @State private var error: String?
    @State private var busy = false
    @State private var dialer: String
    @State private var showAdvanced = false

    /// qx/rebuild: a new node of a given protocol, with optional preset fields (e.g. VLESS Reality Vision).
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

    init(node: [String: Any]?) {
        original = node
        let t = node?["type"] as? String ?? "ss"
        _type = State(initialValue: t)
        _name = State(initialValue: node?["name"] as? String ?? "")
        _server = State(initialValue: node?["server"] as? String ?? "")
        _port = State(initialValue: node.flatMap { ($0["port"] as? NSNumber)?.stringValue ?? $0["port"] as? String } ?? "")
        var flat: [String: String] = [:]
        if let node { NodeProtocols.flatten(node, into: &flat) } else { flat = NodeProtocols.defaults(for: t) }
        _values = State(initialValue: flat)
        _dialer = State(initialValue: node?["dialer-proxy"] as? String ?? "")
    }

    /// Where the node's 前置代理 is resolved: the active profile when manual nodes are merged into it,
    /// otherwise the 手动节点 profile itself.
    var chainProfilePath: String {
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
                        ForEach(NodeProtocols.all, id: \.type) { Text($0.title).tag($0.type) }
                    }
                    TextField("名称", text: $name)
                    TextField("服务器", text: $server).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                    TextField("端口", text: $port).keyboardType(.numberPad)
                }
                .listRowBackground(Theme.card)
                Section(protoTitle + " 参数") {
                    ForEach(NodeProtocols.fields(for: type)) { f in field(f) }
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
                    if busy { ProgressView() } else { Button("保存") { save() }.disabled(server.isEmpty || port.isEmpty) }
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
                Text(f.label).foregroundStyle(.secondary)
                TextField(f.placeholder.isEmpty ? f.label : f.placeholder, text: binding)
                    .multilineTextAlignment(.trailing).textInputAutocapitalization(.never).autocorrectionDisabled()
            }
        case .secure:
            HStack {
                Text(f.label).foregroundStyle(.secondary)
                SecureField(f.placeholder.isEmpty ? f.label : f.placeholder, text: binding).multilineTextAlignment(.trailing)
            }
        case .int:
            HStack {
                Text(f.label).foregroundStyle(.secondary)
                TextField(f.placeholder, text: binding).keyboardType(.numberPad).multilineTextAlignment(.trailing)
            }
        case .bool:
            Toggle(f.label, isOn: Binding(get: { (values[f.key] ?? "") == "true" }, set: { values[f.key] = $0 ? "true" : "false" }))
        case .choice(let opts):
            Picker(f.label, selection: binding) {
                ForEach(opts, id: \.self) { Text($0.isEmpty ? "无" : $0).tag($0) }
                if let v = values[f.key], !v.isEmpty, !opts.contains(v) { Text(v).tag(v) }
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
        d["name"] = name.trimmingCharacters(in: .whitespaces).isEmpty ? "\(ProxyItem.label(for: type)) \(server)" : name.trimmingCharacters(in: .whitespaces)
        d["server"] = server.trimmingCharacters(in: .whitespaces)
        d["port"] = Int(port) ?? 0
        for f in specs {
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
                try await store.upsertManualNode(node, oldName: original?["name"] as? String)
                dismiss()
            } catch { self.error = error.localizedDescription }
        }
    }
}
