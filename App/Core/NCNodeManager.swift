import Foundation

/// nc-integrate B2: the retired bridge / NodeConfigIn / NodeSummaryJSON in Swift.
/// The runtime tree comes from NCRuntimeBuilder (bridge runtimeRawWithHome = buildRuntime(readRuntimeProfile(…),
/// overridesFor(…), 0)); provider nodes are read from the inline payload or the provider cache file
/// (ncProviderCachePath = bridge providerCache), parsed as YAML `proxies:` or, failing that, as a node list
/// (NCSubscriptionParser = bridge parseNodeText).
///
/// Divergences: the old core kept a 30 s runtime cache only for NodeSummary / NodeConfig (name-only) — the *In variants
/// the app calls always rebuilt, so does this. the old core's recover() on panic has no Swift counterpart (nothing here traps).
enum NCNodeManager {

    /// bridge runtimeRawWithHome: the runtime tree, or [:] when the profile cannot be read / built.
    static func runtimeRaw(home: String, profilePath: String) -> [String: NCJSONValue] {
        guard let b = NCRuntimeFiles.readRuntimeProfile(home: home, path: profilePath, safe: false) else { return [:] }
        let req = NCRuntimeBuilder.Request.load(home: home, profilePath: profilePath)
        return (try? NCRuntimeBuilder.build(profile: b, req: req, fd: 0))?.raw ?? [:]
    }

    /// bridge providerNodes.
    static func providerNodes(home: String, _ m: [String: NCJSONValue]) -> [[String: NCJSONValue]] {
        if ncStr(m["type"]).lowercased() == "inline" {
            return ncProxiesOf(["proxies": m["payload"] ?? .null])
        }
        let cp = ncProviderCachePath(home: home, kind: "proxy", m)
        if cp.isEmpty { return [] }
        guard let b = FileManager.default.contents(atPath: cp) else { return [] }
        let text = String(decoding: b, as: UTF8.self)
        if case .object(let pr)? = NCYAML.parse(text) {
            let n = ncProxiesOf(pr)
            if !n.isEmpty { return n }
        }
        return NCSubscriptionParser.parse(text).map { p in
            var f = p.fields
            f["name"] = .string(p.name)
            f["type"] = .string(p.type)
            return f
        }
    }

    /// bridge findRuntimeNodeIn: provider "" = the profile's own proxies, else that proxy-provider.
    static func findIn(home: String, raw: [String: NCJSONValue], provider: String, name: String) -> [String: NCJSONValue]? {
        if provider.isEmpty {
            return ncProxiesOf(raw).first { ncStr($0["name"]) == name }
        }
        guard case .object(let m)? = raw.map("proxy-providers")[provider] else { return nil }
        return providerNodes(home: home, m).first { ncStr($0["name"]) == name }
    }

    static let credentialKeys = ["password", "uuid", "username", "private-key", "pre-shared-key", "public-key", "psk",
                                 "auth", "auth-str", "auth_str", "token", "auth-key", "obfs-password",
                                 "private-key-passphrase", "short-id"]

    /// bridge nestedCredentialKeys.
    static func nestedCredentialKeys(_ m: [String: NCJSONValue]) -> [String] {
        var out: [String] = []
        if case .object(let ro)? = m["reality-opts"] {
            for k in ["public-key", "short-id"] where !ncStr(ro[k]).isEmpty { out.append("reality-opts." + k) }
        }
        if case .object(let po)? = m["plugin-opts"], !ncStr(po["password"]).isEmpty {
            out.append("plugin-opts.password")
        }
        if case .array(let peers)? = m["peers"] {
            for (i, p) in peers.enumerated() {
                guard case .object(let pm) = p else { continue }
                for k in ["public-key", "pre-shared-key"] where !ncStr(pm[k]).isEmpty { out.append("peers.\(i).\(k)") }
            }
        }
        return out
    }

    /// bridge nodeSummary: protocol, address, transport / TLS options and which credentials exist — never values.
    static func summary(_ m: [String: NCJSONValue], source: String) -> [String: Any] {
        let typ = ncStr(m["type"]).lowercased()
        var out: [String: Any] = ["name": ncStr(m["name"]), "type": typ, "server": ncStr(m["server"]),
                                  "port": ncInt(m["port"]), "udp": ncBool(m["udp"]), "source": source]
        func set(_ k: String, _ v: String) { if !v.isEmpty { out[k] = v } }
        func first(_ a: String, _ b: String) -> String { a.isEmpty ? b : a }
        set("network", ncStr(m["network"]).lowercased())
        var tls = ncBool(m["tls"])
        switch typ {
        case "trojan", "hysteria", "hysteria2", "tuic", "juicity", "anytls", "shadowquic", "masque", "trusttunnel": tls = true
        default: break
        }
        var security = ""
        if case .object(let ro)? = m["reality-opts"], !ro.isEmpty {
            security = "reality"; tls = true
        } else if tls {
            security = "tls"
        }
        set("security", security)
        set("sni", first(ncStr(m["servername"]), ncStr(m["sni"])))
        let alpn = ncStrList(m["alpn"])
        if !alpn.isEmpty { out["alpn"] = alpn.joined(separator: ",") }
        set("fingerprint", ncStr(m["client-fingerprint"]))
        if ncBool(m["skip-cert-verify"]) { out["skipCertVerify"] = true }
        set("cipher", ncStr(m["cipher"]))
        set("flow", ncStr(m["flow"]))
        set("plugin", ncStr(m["plugin"]))
        if case .object(let po)? = m["plugin-opts"] {
            set("pluginMode", ncStr(po["mode"]))
            let v = ncInt(po["version"])
            if v > 0 { out["pluginVersion"] = v }
        }
        set("obfs", ncStr(m["obfs"]))
        set("protocolParam", ncStr(m["protocol"]))
        set("congestion", first(ncStr(m["congestion-controller"]), ncStr(m["congestion-control"])))
        set("dialerProxy", ncStr(m["dialer-proxy"]))
        set("ipVersion", ncStr(m["ip-version"]))
        if ncBool(m["tfo"]) { out["tfo"] = true }
        if ncBool(m["mptcp"]) { out["mptcp"] = true }
        if case .object(let sm)? = m["smux"], ncBool(sm["enabled"]) {
            out["smux"] = first(ncStr(sm["protocol"]), "smux")
        }
        set("up", ncStr(m["up"]))
        set("down", ncStr(m["down"]))
        if m["amnezia-wg-option"] != nil { out["amnezia"] = true }
        if typ == "tailscale" {
            var ts: [String: Any] = ["ephemeral": ncBool(m["ephemeral"])]
            for k in ["hostname", "control-url", "state-dir", "exit-node"] {
                let v = ncStr(m[k]); if !v.isEmpty { ts[k] = v }
            }
            for k in ["accept-routes", "exit-node-allow-lan-access"] {
                if let v = m[k] { ts[k] = ncBool(v) }
            }
            out["tailscale"] = ts
        }
        var creds: [String] = credentialKeys.filter { m[$0] != nil && !ncStr(m[$0]).isEmpty }
        if typ == "wireguard", case .array(let peers)? = m["peers"], !peers.isEmpty { out["peers"] = peers.count }
        creds += nestedCredentialKeys(m)
        out["credentials"] = creds
        out["shareable"] = (try? NCShareLink.encode(m.mapValues { $0.rawAny })) != nil
        return out
    }

    private static let notFound = #"{"error":"在当前配置里找不到这个节点"}"#

    /// bridge NodeSummaryIn.
    static func nodeSummaryIn(home: String, profilePath: String, provider: String, name: String) -> String {
        let raw = runtimeRaw(home: home, profilePath: profilePath)
        guard let m = findIn(home: home, raw: raw, provider: provider, name: name) else { return notFound }
        return ncJSONString(summary(m, source: provider))
    }

    /// bridge NodeConfigIn: the node's full config as JSON, secrets included; "" when not found.
    static func nodeConfigIn(home: String, profilePath: String, provider: String, name: String) -> String {
        let raw = runtimeRaw(home: home, profilePath: profilePath)
        guard let m = findIn(home: home, raw: raw, provider: provider, name: name) else { return "" }
        return ncJSONString(m.mapValues { $0.rawAny })
    }

    /// bridge NodeSummaryJSON: the summary of a node given as JSON (manual nodes not merged into the profile).
    static func nodeSummaryJSON(_ nodeJSON: String) -> String {
        guard let o = try? JSONSerialization.jsonObject(with: Data(nodeJSON.utf8)) as? [String: Any] else {
            return ncJSONString(["error": "节点 JSON 无效"])
        }
        return ncJSONString(summary(o.mapValues { NCJSONValue($0) }, source: ""))
    }
}
