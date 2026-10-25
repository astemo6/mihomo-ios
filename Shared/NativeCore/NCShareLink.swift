import Foundation

/// Error thrown during share link encoding.
enum ShareLinkError: LocalizedError {
    case message(String)

    var errorDescription: String? {
        switch self {
        case .message(let msg): return msg
        }
    }
}

/// Pure Swift share link encoder and converter matching bridge/share.go specifications.
enum NCShareLink {

    // MARK: - Encode (Proxy Dictionary -> Share URI)

    /// Encode one proxy dictionary into a share URI (ss/vmess/vless/trojan/hy2/etc.).
    static func encode(_ m: [String: Any]) throws -> String {
        let name = sStr(m, "name")
        let typ = sStr(m, "type").lowercased()
        let server = sStr(m, "server")

        if server.isEmpty && typ != "wireguard" {
            throw ShareLinkError.message("节点缺少服务器地址")
        }

        switch typ {
        case "ss":
            let cipher = sStr(m, "cipher")
            let pass = sStr(m, "password")
            let userRaw = "\(cipher):\(pass)"
            let user = base64URLNoPadding(Data(userRaw.utf8))
            var q = KVList()
            let plugin = sStr(m, "plugin")
            switch plugin {
            case "obfs", "simple-obfs":
                let o = sMap(m, "plugin-opts")
                q.add("plugin", "obfs-local;obfs=\(sStr(o, "mode"));obfs-host=\(sStr(o, "host"))")
            case "v2ray-plugin":
                let o = sMap(m, "plugin-opts")
                var p = "v2ray-plugin;mode=\(sStr(o, "mode"));host=\(sStr(o, "host"));path=\(sStr(o, "path"))"
                if sBool(o, "tls") { p += ";tls" }
                q.add("plugin", p)
            case "":
                break
            default:
                throw ShareLinkError.message("ss 插件 \(plugin) 没有通用分享格式")
            }
            if sBool(m, "udp-over-tcp") {
                q.add("uot", "1")
            }
            return "ss://\(user)@\(hostPort(m))\(q.queryString)#\(frag(name))"

        case "ssr":
            let b64 = { (s: String) -> String in base64URLNoPadding(Data(s.utf8)) }
            var body = [
                sStr(m, "server"),
                sStr(m, "port"),
                sStr(m, "protocol"),
                sStr(m, "cipher"),
                sStr(m, "obfs"),
                b64(sStr(m, "password"))
            ].joined(separator: ":")
            body += "/?obfsparam=\(b64(sStr(m, "obfs-param")))&protoparam=\(b64(sStr(m, "protocol-param")))&remarks=\(b64(name))"
            return "ssr://\(b64(body))"

        case "vmess":
            var v: [String: Any] = [
                "v": "2",
                "ps": name,
                "add": sStr(m, "server"),
                "port": sStr(m, "port"),
                "id": sStr(m, "uuid"),
                "aid": sStr(m, "alterId").isEmpty ? "0" : sStr(m, "alterId"),
                "scy": sStr(m, "cipher").isEmpty ? "auto" : sStr(m, "cipher"),
                "net": "tcp",
                "type": "none",
                "host": "",
                "path": "",
                "tls": ""
            ]
            let netw = sStr(m, "network").lowercased()
            switch netw {
            case "ws", "httpupgrade":
                let o = sMap(m, "ws-opts")
                v["net"] = netw
                v["path"] = sStr(o, "path")
                v["host"] = sStr(sMap(o, "headers"), "Host", "host")
            case "grpc":
                v["net"] = "grpc"
                v["path"] = sStr(sMap(m, "grpc-opts"), "grpc-service-name")
            case "h2":
                let o = sMap(m, "h2-opts")
                v["net"] = "h2"
                v["path"] = sStr(o, "path")
                let h = sList(o, "host")
                if let first = h.first { v["host"] = first }
            case "http":
                let o = sMap(m, "http-opts")
                v["type"] = "http"
                let p = sList(o, "path")
                if let first = p.first { v["path"] = first }
                let h = sList(sMap(o, "headers"), "Host")
                if let first = h.first { v["host"] = first }
            default:
                break
            }
            if sBool(m, "tls") {
                v["tls"] = "tls"
                v["sni"] = sStr(m, "servername")
                let a = sList(m, "alpn")
                if !a.isEmpty { v["alpn"] = a.joined(separator: ",") }
                let fp = sStr(m, "client-fingerprint")
                if !fp.isEmpty { v["fp"] = fp }
            }
            let data = try JSONSerialization.data(withJSONObject: v, options: [])
            return "vmess://\(data.base64EncodedString())"

        case "vless":
            var q = KVList()
            let enc = sStr(m, "encryption")
            q.add("encryption", enc.isEmpty ? "none" : enc)
            q.add("flow", sStr(m, "flow"))
            let ro = sMap(m, "reality-opts")
            if !sStr(ro, "public-key").isEmpty {
                q.add("security", "reality")
                q.add("pbk", sStr(ro, "public-key"))
                q.add("sid", sStr(ro, "short-id"))
            } else if sBool(m, "tls") {
                q.add("security", "tls")
            } else {
                q.add("security", "none")
            }
            q.add("sni", sStr(m, "servername"))
            transportQuery(m, &q, trojan: false)
            if sBool(m, "skip-cert-verify") {
                q.add("allowInsecure", "1")
            }
            return "vless://\(escapePath(sStr(m, "uuid")))@\(hostPort(m))\(q.queryString)#\(frag(name))"

        case "trojan":
            var q = KVList()
            q.add("sni", sStr(m, "sni", "servername"))
            transportQuery(m, &q, trojan: true)
            let ro = sMap(m, "reality-opts")
            if !sStr(ro, "public-key").isEmpty {
                q.add("security", "reality")
                q.add("pbk", sStr(ro, "public-key"))
                q.add("sid", sStr(ro, "short-id"))
            }
            if sBool(m, "skip-cert-verify") {
                q.add("allowInsecure", "1")
            }
            return "trojan://\(escapePath(sStr(m, "password")))@\(hostPort(m))\(q.queryString)#\(frag(name))"

        case "hysteria2", "hy2":
            var q = KVList()
            q.add("sni", sStr(m, "sni"))
            if sBool(m, "skip-cert-verify") { q.add("insecure", "1") }
            q.add("obfs", sStr(m, "obfs"))
            q.add("obfs-password", sStr(m, "obfs-password"))
            let a = sList(m, "alpn")
            if !a.isEmpty { q.add("alpn", a.joined(separator: ",")) }
            q.add("pinSHA256", sStr(m, "fingerprint"))
            q.add("up", sStr(m, "up"))
            q.add("down", sStr(m, "down"))
            var hp = hostPort(m)
            let ports = sStr(m, "ports")
            if !ports.isEmpty {
                hp = joinHostPort(sStr(m, "server"), ports)
            }
            var user = ""
            let pw = sStr(m, "password")
            if !pw.isEmpty { user = escapePath(pw) + "@" }
            return "hysteria2://\(user)\(hp)/\(q.queryString)#\(frag(name))"

        case "hysteria":
            var q = KVList()
            q.add("peer", sStr(m, "sni"))
            q.add("auth", sStr(m, "auth-str", "auth_str"))
            q.add("obfs", sStr(m, "obfs"))
            q.add("protocol", sStr(m, "protocol"))
            q.add("upmbps", sStr(m, "up"))
            q.add("downmbps", sStr(m, "down"))
            let a = sList(m, "alpn")
            if !a.isEmpty { q.add("alpn", a.joined(separator: ",")) }
            if sBool(m, "skip-cert-verify") { q.add("insecure", "1") }
            return "hysteria://\(hostPort(m))\(q.queryString)#\(frag(name))"

        case "tuic":
            var q = KVList()
            q.add("congestion_control", sStr(m, "congestion-controller"))
            let a = sList(m, "alpn")
            if !a.isEmpty { q.add("alpn", a.joined(separator: ",")) }
            q.add("sni", sStr(m, "sni"))
            if sBool(m, "disable-sni") { q.add("disable_sni", "1") }
            q.add("udp_relay_mode", sStr(m, "udp-relay-mode"))
            var user = escapePath(sStr(m, "token"))
            let u = sStr(m, "uuid")
            if !u.isEmpty {
                user = escapePath(u) + ":" + escapePath(sStr(m, "password"))
            }
            return "tuic://\(user)@\(hostPort(m))\(q.queryString)#\(frag(name))"

        case "anytls":
            var q = KVList()
            q.add("sni", sStr(m, "sni"))
            if sBool(m, "skip-cert-verify") { q.add("insecure", "1") }
            q.add("hpkp", sStr(m, "fingerprint"))
            return "anytls://\(escapePath(sStr(m, "password")))@\(hostPort(m))/\(q.queryString)#\(frag(name))"

        case "socks5", "http":
            var scheme = "socks5"
            if typ == "http" {
                scheme = sBool(m, "tls") ? "https" : "http"
            }
            var user = ""
            let u = sStr(m, "username")
            if !u.isEmpty {
                // Go: url.UserPassword(u, pw).String() — colon even when pw == "".
                user = userPassword(u, sStr(m, "password")) + "@"
            }
            var q = KVList()
            if scheme == "https" {
                q.add("sni", sStr(m, "sni"))
            }
            return "\(scheme)://\(user)\(hostPort(m))\(q.queryString)#\(frag(name))"

        case "wireguard":
            var server = sStr(m, "server")
            var port = sStr(m, "port")
            var pub = ""
            var psk = ""
            var reserved = ""
            if let peers = m["peers"] as? [[String: Any]], let first = peers.first {
                if !sStr(first, "server").isEmpty { server = sStr(first, "server") }
                if !sStr(first, "port").isEmpty { port = sStr(first, "port") }
                pub = sStr(first, "public-key")
                psk = sStr(first, "pre-shared-key")
                reserved = sList(first, "reserved").joined(separator: ",")
            }
            if pub.isEmpty { pub = sStr(m, "public-key") }
            if psk.isEmpty { psk = sStr(m, "pre-shared-key") }
            if reserved.isEmpty { reserved = sList(m, "reserved").joined(separator: ",") }
            if server.isEmpty { throw ShareLinkError.message("节点缺少服务器地址") }
            var q = KVList()
            q.add("publickey", pub)
            var addrs: [String] = []
            let ip = sStr(m, "ip")
            if !ip.isEmpty { addrs.append(ip + "/32") }
            let ipv6 = sStr(m, "ipv6")
            if !ipv6.isEmpty { addrs.append(ipv6 + "/128") }
            q.add("address", addrs.joined(separator: ","))
            q.add("presharedkey", psk)
            q.add("reserved", reserved)
            q.add("mtu", sStr(m, "mtu"))
            if port.isEmpty { port = "51820" }
            return "wireguard://\(escapePath(sStr(m, "private-key")))@\(joinHostPort(server, port))\(q.queryString)#\(frag(name))"

        case "snell":
            var q = KVList()
            q.add("version", sStr(m, "version"))
            let o = sMap(m, "obfs-opts")
            q.add("obfs", sStr(o, "mode"))
            q.add("obfs-host", sStr(o, "host"))
            return "snell://\(escapePath(sStr(m, "psk")))@\(hostPort(m))\(q.queryString)#\(frag(name))"

        case "mieru":
            // Go: url.UserPassword(username, password) unconditionally.
            let user = userPassword(sStr(m, "username"), sStr(m, "password"))
            var q = KVList()
            q.add("profile", name)
            let pr = sStr(m, "port-range")
            q.add("port", pr.isEmpty ? sStr(m, "port") : pr)
            let tr = sStr(m, "transport")
            q.add("protocol", (tr.isEmpty ? "TCP" : tr).uppercased())
            q.add("multiplexing", sStr(m, "multiplexing"))
            q.add("handshake-mode", sStr(m, "handshake-mode"))
            return "mierus://\(user)@\(sStr(m, "server"))\(q.queryString)#\(frag(name))"

        case "ssh":
            // Go: url.User(u) when no password (no colon), else UserPassword.
            let u = sStr(m, "username")
            let pw = sStr(m, "password")
            let user = pw.isEmpty ? goEscape(u, mode: .userPassword) : userPassword(u, pw)
            var q = KVList()
            q.add("private-key", sStr(m, "private-key"))
            q.add("private-key-passphrase", sStr(m, "private-key-passphrase"))
            let hk = sList(m, "host-key")
            if !hk.isEmpty { q.add("host-key", hk.joined(separator: "|")) }
            return "ssh://\(user)@\(hostPort(m))\(q.queryString)#\(frag(name))"

        default:
            throw ShareLinkError.message("\(typ) 类型没有通用的分享链接格式")
        }
    }

    /// Encode one NCProxy into a share URI.
    static func encode(_ proxy: NCProxy) throws -> String {
        try encode(proxy.dictionary)
    }

    /// Encode one node given as a JSON string.
    /// Matches bridge/share.go NodeShareLink semantics.
    static func encode(jsonString: String) throws -> String {
        guard let data = jsonString.data(using: .utf8),
              let dict = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            throw ShareLinkError.message("节点数据无效")
        }
        return try encode(dict)
    }

    /// Encode a node of a profile by name (after script overrides if present).
    /// Matches bridge/share.go NodeShareLinkByName semantics.
    static func encodeByName(homeDir: String, profilePath: String, name: String) throws -> String {
        let profileURL = URL(fileURLWithPath: profilePath)
        var data: Data?
        if !homeDir.isEmpty {
            let id = profileURL.deletingPathExtension().lastPathComponent
            let scriptedDir = URL(fileURLWithPath: homeDir).appendingPathComponent("scripted")
            let metaURL = scriptedDir.appendingPathComponent("\(id).json")
            let yamlURL = scriptedDir.appendingPathComponent("\(id).yaml")
            if let srcData = try? Data(contentsOf: profileURL),
               let metaData = try? Data(contentsOf: metaURL),
               let meta = try? JSONSerialization.jsonObject(with: metaData) as? [String: Any],
               let srcHash = meta["source"] as? String {
                let actualHash = NCSHA256.hash(srcData).map { String(format: "%02x", $0) }.joined()
                if !srcHash.isEmpty && srcHash == actualHash,
                   let out = try? Data(contentsOf: yamlURL), !out.isEmpty {
                    data = out
                } else {
                    data = srcData
                }
            } else {
                data = try? Data(contentsOf: profileURL)
            }
        } else {
            data = try? Data(contentsOf: profileURL)
        }

        guard let rawData = data, let text = String(data: rawData, encoding: .utf8) else {
            throw ShareLinkError.message("在配置里找不到这个节点（节点集里的节点请到提供者页查看）")
        }

        guard let root = NCYAML.parse(text), let proxies = root.object?["proxies"]?.array else {
            throw ShareLinkError.message("在配置里找不到这个节点（节点集里的节点请到提供者页查看）")
        }

        for item in proxies {
            guard let p = item.object?.mapValues({ $0.rawAny }) else { continue }
            if sStr(p, "name") == name {
                return try encode(p)
            }
        }

        throw ShareLinkError.message("在配置里找不到这个节点（节点集里的节点请到提供者页查看）")
    }

    // MARK: - Manual Subscription Export

    /// Export manual nodes as a base64 subscription (one link per line, v2rayN style).
    /// Returns JSON {"text": "...", "skipped": [...], "count": n}.
    static func manualSubscription(path: String) -> String {
        var links: [String] = []
        var skipped: [String] = []

        let url = URL(fileURLWithPath: path)
        if let data = try? Data(contentsOf: url), let text = String(data: data, encoding: .utf8),
           let root = NCYAML.parse(text), let proxies = root.object?["proxies"]?.array {
            for item in proxies {
                guard let p = item.object?.mapValues({ $0.rawAny }) else { continue }
                do {
                    let link = try encode(p)
                    links.append(link)
                } catch {
                    let nodeName = sStr(p, "name")
                    let reason = error.localizedDescription
                    skipped.append("\(nodeName)：\(reason)")
                }
            }
        }

        let body = links.joined(separator: "\n")
        let b64 = Data(body.utf8).base64EncodedString()
        let out: [String: Any] = [
            "text": b64,
            "count": links.count,
            "skipped": skipped
        ]

        if let json = try? JSONSerialization.data(withJSONObject: out),
           let s = String(data: json, encoding: .utf8) {
            return s
        }
        return "{\"text\":\"\",\"count\":0,\"skipped\":[]}"
    }

    // MARK: - Convert Share Links (ProfileStore.normalize)

    /// Convert a list of share links (or base64 subscription) into a minimal mihomo YAML config.
    /// Returns "" on failure.
    static func convertShareLinks(_ text: String) -> String {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)

        // Check for full QX / Surge config format
        if let confYaml = convertConfIfApplicable(trimmed) {
            return confYaml
        }

        let nodes = NCSubscriptionParser.parse(trimmed)
        guard !nodes.isEmpty else { return "" }

        let proxies = nodes.map { $0.dictionary }
        return buildConfigFromProxies(proxies)
    }

    /// Build a minimal mihomo config with "节点选择" and "自动选择" proxy-groups.
    static func buildConfigFromProxies(_ proxies: [[String: Any]]) -> String {
        guard !proxies.isEmpty else { return "" }
        let names = proxies.compactMap { $0["name"] as? String }

        let autoGroup: [String: Any] = [
            "name": "自动选择",
            "type": "url-test",
            "proxies": names,
            "url": "https://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 50
        ]
        var selProxies: [Any] = ["自动选择", "DIRECT"]
        selProxies.append(contentsOf: names)
        let selGroup: [String: Any] = [
            "name": "节点选择",
            "type": "select",
            "proxies": selProxies
        ]
        let defaultRules: [String] = [
            "DOMAIN-SUFFIX,local,DIRECT",
            "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
            "GEOIP,CN,DIRECT",
            "MATCH,节点选择"
        ]
        let cfg: [String: Any] = [
            "mode": "rule",
            "proxies": proxies,
            "proxy-groups": [selGroup, autoGroup],
            "rules": defaultRules
        ]

        return NCYAMLEmitter.emit(cfg)
    }

    private static func convertConfIfApplicable(_ text: String) -> String? {
        guard text.contains("[") else { return nil }
        var hasQx = false
        var hasSurge = false
        for line in text.components(separatedBy: .newlines) {
            let t = line.trimmingCharacters(in: .whitespaces).lowercased()
            if t == "[filter_local]" || t == "[filter_remote]" || t == "[policy]" { hasQx = true }
            if t == "[rule]" || t == "[proxy group]" { hasSurge = true }
        }
        guard hasQx || hasSurge else { return nil }

        // feat/nc-integrate: was LibmihomoImportConf (Go). This file is in Shared/, which the Go-free PacketTunnel
        // compiles too, so it must not import Libmihomo. Swift path: the NativeCore importers (NCQXImport /
        // NCConfImport, the same ones the tunnel uses) → NCConfig → mihomo YAML via NCYAMLEmitter.
        // Covers proxies, proxy groups, rules, rule-providers and DNS servers; Surge/QX MitM / rewrite / script
        // sections are not part of a share-link conversion.
        let lower = text.lowercased()
        let isLoon = !hasQx && (lower.contains("[remote rule]") || lower.contains("[remote proxy]") || lower.contains("[plugin]"))
        let canonical: NCCanonicalConfig = hasQx ? NCQXImport.quantumultx(text)
            : (isLoon ? NCConfImport.loon(text) : NCConfImport.surge(text))
        let cfg = canonical.legacyConfig()
        guard !cfg.proxies.isEmpty || !cfg.groups.isEmpty else { return nil }
        var root: [String: Any] = ["mode": cfg.mode]
        root["proxies"] = cfg.proxies.map { p -> [String: Any] in
            var d = p.fields.mapValues { $0.rawAny }
            d["name"] = p.name; d["type"] = p.type
            return d
        }
        root["proxy-groups"] = cfg.groups.map { g -> [String: Any] in
            var d = g.fields.mapValues { $0.rawAny }
            d["name"] = g.name; d["type"] = g.type; d["proxies"] = g.proxies
            return d
        }
        root["rules"] = cfg.rules
        if let provs = cfg.raw["rule-providers"] { root["rule-providers"] = provs.rawAny }
        if !cfg.dns.fields.isEmpty { root["dns"] = cfg.dns.fields.mapValues { $0.rawAny } }
        let yaml = NCYAMLEmitter.emit(root)
        let formatName = hasQx ? "Quantumult X" : (isLoon ? "Loon" : "Surge")
        // bridge confsource.go confAsProfile: the import report rides as
        // leading comments — what conversion left out is listed, never
        // dropped silently. (Go also prints a skipped-rules count; Swift's
        // NCImportReport has no such field, sections/warnings are carried.)
        var head = "# Tern: converted from a \(formatName) config (\(formatName) 配置转换)\n"
        func reportLine(_ s: String) {
            let clean = s.replacingOccurrences(of: "\r", with: " ")
                .replacingOccurrences(of: "\n", with: " ")
            head += "#   \(clean)\n"
        }
        if !canonical.rewrites.isEmpty || !canonical.scripts.isEmpty
            || canonical.mitm.enabled || !canonical.mitm.hostnames.isEmpty {
            reportLine("重写 / MitM / 脚本段不随配置订阅导入；需要时请用「导入配置」导入该文件")
        }
        for n in canonical.report.warnings { reportLine("说明：" + n) }
        for s in canonical.report.skippedSections { reportLine("未转换：" + s) }
        return head + yaml
    }

    // MARK: - Internal Helpers

    private static func transportQuery(_ m: [String: Any], _ q: inout KVList, trojan: Bool) {
        let netw = sStr(m, "network").lowercased()
        switch netw {
        case "", "tcp":
            if !trojan { q.add("type", "tcp") }
        case "ws":
            q.add("type", "ws")
            let o = sMap(m, "ws-opts")
            q.add("path", sStr(o, "path"))
            q.add("host", sStr(sMap(o, "headers"), "Host", "host"))
        case "httpupgrade":
            q.add("type", "httpupgrade")
            let o = sMap(m, "ws-opts")
            q.add("path", sStr(o, "path"))
            q.add("host", sStr(sMap(o, "headers"), "Host", "host"))
        case "grpc":
            q.add("type", "grpc")
            q.add("serviceName", sStr(sMap(m, "grpc-opts"), "grpc-service-name"))
        case "h2":
            q.add("type", "http")
            let o = sMap(m, "h2-opts")
            q.add("path", sStr(o, "path"))
            let h = sList(o, "host")
            if let first = h.first { q.add("host", first) }
        case "http":
            q.add("type", "tcp")
            q.add("headerType", "http")
            let o = sMap(m, "http-opts")
            let p = sList(o, "path")
            if let first = p.first { q.add("path", first) }
            let h = sList(sMap(o, "headers"), "Host")
            if let first = h.first { q.add("host", first) }
        case "xhttp":
            q.add("type", "xhttp")
            let o = sMap(m, "xhttp-opts")
            q.add("path", sStr(o, "path"))
            q.add("host", sStr(o, "host"))
            q.add("mode", sStr(o, "mode"))
        default:
            q.add("type", netw)
        }
        let fp = sStr(m, "client-fingerprint")
        if !fp.isEmpty { q.add("fp", fp) }
        let a = sList(m, "alpn")
        if !a.isEmpty { q.add("alpn", a.joined(separator: ",")) }
    }

    private static func sStr(_ m: [String: Any], _ keys: String...) -> String {
        for k in keys {
            if let v = m[k] {
                switch v {
                case let s as String:
                    if !s.isEmpty { return s }
                case let b as Bool:
                    if b { return "true" }
                case let num as NSNumber:
                    if CFGetTypeID(num) == CFBooleanGetTypeID() {
                        if num.boolValue { return "true" }
                    } else if num.doubleValue.isFinite && num.doubleValue == floor(num.doubleValue) {
                        return String(num.int64Value)
                    } else {
                        return num.stringValue
                    }
                case let num as Int:
                    return String(num)
                case let num as Double:
                    // Double(Int64.max) is 2^63, which Int64() traps on: keep it strictly below.
                    if num.isFinite && num == floor(num) && num >= Double(Int64.min) && num < Double(Int64.max) {
                        return String(Int64(num))
                    }
                    return String(num)
                default:
                    break
                }
            }
        }
        return ""
    }

    private static func sBool(_ m: [String: Any], _ k: String) -> Bool {
        // bridge share.go sBool: bool → itself; string → only exactly "true"/"1"
        // (case-sensitive); int → != 0. JSON/YAML floating numbers hit no case
        // in Go (float64 is not in the switch) and are false — gate NSNumber to
        // integer-typed values so 1.0 does not silently become true.
        guard let v = m[k] else { return false }
        switch v {
        case let b as Bool: return b
        case let s as String:
            return s == "true" || s == "1"
        case let i as Int: return i != 0
        case is Double, is Float: return false
        case let num as NSNumber:
            if CFGetTypeID(num) == CFBooleanGetTypeID() { return num.boolValue }
            switch String(cString: num.objCType) {
            case "c", "s", "i", "l", "q", "C", "S", "I", "L", "Q":
                return num.intValue != 0
            default: return false
            }
        default: return false
        }
    }

    private static func sList(_ m: [String: Any], _ k: String) -> [String] {
        guard let v = m[k] else { return [] }
        if let list = v as? [Any] {
            return list.map { String(describing: $0) }
        }
        if let s = v as? String, !s.isEmpty {
            // bridge share.go sList: strings.Split(t, ",") — no trimming.
            return s.components(separatedBy: ",")
        }
        return []
    }

    private static func sMap(_ m: [String: Any], _ k: String) -> [String: Any] {
        if let d = m[k] as? [String: Any] { return d }
        return [:]
    }

    private static func hostPort(_ m: [String: Any]) -> String {
        joinHostPort(sStr(m, "server"), sStr(m, "port"))
    }

    private static func joinHostPort(_ host: String, _ port: String) -> String {
        if host.contains(":") && !host.hasPrefix("[") {
            return "[\(host)]:\(port)"
        }
        return "\(host):\(port)"
    }

    /// The fragment body only: every call site already writes the "#"
    /// separator (`…#\(frag(name))`); prefixing it here too produced
    /// `##name`, which re-parses as the name "#name".
    private static func frag(_ name: String) -> String {
        escapePath(name)
    }

    /// Go net/url shouldEscape byte table: unreserved [A-Za-z0-9-_.~] plus the
    /// reserved set each mode leaves alone; everything else is %XX (uppercase
    /// hex, over the UTF-8 bytes).
    private static func goEscape(_ s: String, mode: GoEscapeMode) -> String {
        var out = ""
        out.reserveCapacity(s.utf8.count)
        for b in s.utf8 {
            let unreserved = (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A)
                || (b >= 0x30 && b <= 0x39) || b == 0x2D || b == 0x5F || b == 0x2E || b == 0x7E
            var keep = unreserved
            if !keep {
                switch mode {
                case .pathSegment: // url.PathEscape: $ & + : = @ stay; / ; , ? escape
                    keep = b == 0x24 || b == 0x26 || b == 0x2B || b == 0x3A || b == 0x3D || b == 0x40
                case .userPassword: // url.UserPassword: $ & + , ; = stay; @ / ? : escape
                    keep = b == 0x24 || b == 0x26 || b == 0x2B || b == 0x2C || b == 0x3B || b == 0x3D
                case .query: // url.QueryEscape: nothing else stays, space → +
                    keep = false
                }
            }
            if keep {
                out.append(Character(UnicodeScalar(b)))
            } else if mode == .query && b == 0x20 {
                out.append("+")
            } else {
                out += String(format: "%%%02X", b)
            }
        }
        return out
    }

    private enum GoEscapeMode { case pathSegment, userPassword, query }

    /// bridge share.go: url.PathEscape (fragment names, uuid, passwords, keys).
    private static func escapePath(_ s: String) -> String { goEscape(s, mode: .pathSegment) }

    /// bridge share.go: url.QueryEscape (kvList keys and values).
    private static func escapeQuery(_ s: String) -> String { goEscape(s, mode: .query) }

    /// bridge share.go: url.UserPassword(u, pw).String() — always carries the
    /// colon, even with an empty password.
    private static func userPassword(_ u: String, _ pw: String) -> String {
        goEscape(u, mode: .userPassword) + ":" + goEscape(pw, mode: .userPassword)
    }

    private static func base64URLNoPadding(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
    }

    private struct KVList {
        private var pairs: [(String, String)] = []

        mutating func add(_ k: String, _ v: String) {
            if !v.isEmpty { pairs.append((k, v)) }
        }

        var queryString: String {
            guard !pairs.isEmpty else { return "" }
            let parts = pairs.map { "\(escapeQuery($0.0))=\(escapeQuery($0.1))" }
            return "?" + parts.joined(separator: "&")
        }
    }
}

extension NCProxy {
    var dictionary: [String: Any] {
        var d = fields.mapValues { $0.rawAny }
        d["name"] = name
        d["type"] = type
        return d
    }
}
