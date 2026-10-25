// DIVERGENCES:
// None. Runtime config building delegates to NCRuntimeBuilder (#112).
// Inspect-specific statistics, provider cache inspection, group member
// expansion (via NCGroupEditing.previewGroup), and result JSON shapes
// mirror bridge/inspect.go exactly.

import Foundation
import CryptoKit

/// Pure Swift port of bridge/inspect.go InspectProfile.
/// Provides offline inspection of profile proxies, groups, rules, providers,
/// and selections without starting the engine.
enum NCProfileInspectorPort {

    // MARK: - Public API

    /// InspectProfile returns JSON (proxies, groups, rules, providers, saved selections)
    /// for the profile at path as the core would see it with current overrides.
    static func inspectProfileJSON(home: String, path: String) -> String {
        let res = inspectProfile(home: home, path: path)
        let enc = JSONEncoder()
        if let data = try? enc.encode(res), let str = String(data: data, encoding: .utf8) {
            return str
        }
        return "{\"error\":\"内部编码错误\"}"
    }

    /// InspectProfile returning the native typed InspectResult model.
    static func inspectProfile(home: String, path: String) -> InspectResult {
        var res = InspectResult()
        res.selected = readSelections(path)

        guard let profileData = NCRuntimeFiles.readRuntimeProfile(home: home, path: path, safe: false) else {
            res.error = "无法读取配置文件"
            return res
        }

        let req = NCRuntimeBuilder.Request.load(home: home, profilePath: path)
        let buildResult: (data: Data, isJSON: Bool, raw: [String: NCJSONValue])
        do {
            buildResult = try NCRuntimeBuilder.build(profile: profileData, req: req, fd: 0)
        } catch {
            res.error = error.localizedDescription
            return res
        }

        let raw = buildResult.raw
        var mode = raw["mode"]?.string?.trimmingCharacters(in: .whitespaces).lowercased() ?? ""
        if mode.isEmpty { mode = "rule" }
        res.mode = mode

        // Proxies
        if let proxiesArr = raw["proxies"]?.array {
            for pVal in proxiesArr {
                if let pObj = pVal.object {
                    res.proxies.append(toInspectProxy(pObj, source: ""))
                }
            }
        }

        // Proxy providers
        res.proxyProviders = inspectProviders(homeDir: home, kind: "proxy", raw: raw["proxy-providers"])

        // Member pool for evaluating group members
        var pool = NCGroupEditing.MemberPool()
        for p in res.proxies {
            pool.proxies.append(p.name)
            pool.types[p.name] = p.type
        }
        if let groupsArr = raw["proxy-groups"]?.array {
            for gVal in groupsArr {
                if let gObj = gVal.object,
                   let name = gObj["name"]?.string,
                   let type = gObj["type"]?.string {
                    pool.types[name] = type
                }
            }
        }
        for pv in res.proxyProviders {
            var names: [String] = []
            for p in pv.proxies ?? [] {
                names.append(p.name)
                if pool.types[p.name] == nil {
                    pool.types[p.name] = p.type
                }
            }
            pool.providers[pv.name] = names
        }

        // Groups
        let probeGroup = "MIHOMO-PROBE"
        if let gl = raw["proxy-groups"]?.array {
            for x in gl {
                guard let m = x.object else { continue }
                let name = m["name"]?.string ?? ""
                if name.isEmpty || name == probeGroup {
                    continue
                }
                let type = m["type"]?.string?.trimmingCharacters(in: .whitespaces).lowercased() ?? "select"
                let proxies = m["proxies"]?.array?.compactMap { $0.string } ?? []
                let use = m["use"]?.array?.compactMap { $0.string } ?? []
                let url = m["url"]?.string
                let interval = m["interval"]?.int
                let hidden = m["hidden"]?.bool
                let icon = m["icon"]?.string
                let filter = m["filter"]?.string
                let excludeFilter = m["exclude-filter"]?.string
                let excludeType = m["exclude-type"]?.string
                let includeAll = (m["include-all"]?.bool == true) || (m["include-all-proxies"]?.bool == true)

                var spec = GroupSpec(name: name)
                spec.type = type
                spec.proxies = proxies
                spec.use = use
                spec.filter = filter
                spec.excludeFilter = excludeFilter
                spec.excludeType = excludeType
                spec.includeAll = m["include-all"]?.bool
                spec.includeAllProxies = m["include-all-proxies"]?.bool
                spec.includeAllProviders = m["include-all-providers"]?.bool

                let previewItem = NCGroupEditing.previewGroup(spec: spec, pool: pool)

                var g = InspectGroup(
                    name: name,
                    type: type,
                    proxies: proxies,
                    use: use,
                    url: url,
                    interval: interval,
                    hidden: hidden,
                    icon: icon,
                    filter: filter,
                    selected: nil,
                    members: previewItem.members,
                    membersError: previewItem.error,
                    excludeFilter: excludeFilter,
                    excludeType: excludeType,
                    includeAll: includeAll
                )
                if type == "select", let s = res.selected[name] {
                    g.selected = s
                }
                res.groups.append(g)
            }
        }

        // Rules
        if let rulesArr = raw["rules"]?.array {
            for rVal in rulesArr {
                if let rStr = rVal.string {
                    res.rules.append(splitRule(rStr))
                }
            }
        }

        // Rule providers
        res.ruleProviders = inspectProviders(homeDir: home, kind: "rule", raw: raw["rule-providers"])

        // Strip generated chain providers (prefix "tern.chain/")
        let generatedPrefix = "tern.chain/"
        res.proxyProviders.removeAll { $0.name.hasPrefix(generatedPrefix) }

        return res
    }

    // MARK: - Selections

    static func selectionsPath(for profilePath: String) -> String {
        let ns = profilePath as NSString
        return ns.deletingPathExtension + ".selected.json"
    }

    static func readSelections(_ profilePath: String) -> [String: String] {
        let p = selectionsPath(for: profilePath)
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: p)),
              let m = try? JSONDecoder().decode([String: String].self, from: data) else {
            return [:]
        }
        return m
    }

    // MARK: - Rule Splitting

    static func splitRule(_ line0: String) -> InspectRule {
        let line = line0.trimmingCharacters(in: .whitespaces)
        guard let i = line.firstIndex(of: ",") else {
            return InspectRule(type: line, payload: "", proxy: "", options: nil)
        }
        let typ = String(line[..<i]).trimmingCharacters(in: .whitespaces).uppercased()
        let rest = String(line[line.index(after: i)...])
        switch typ {
        case "AND", "OR", "NOT", "SUB-RULE":
            if let j = rest.lastIndex(of: ",") {
                let payload = String(rest[..<j]).trimmingCharacters(in: .whitespaces)
                let proxy = String(rest[rest.index(after: j)...]).trimmingCharacters(in: .whitespaces)
                return InspectRule(type: typ, payload: payload, proxy: proxy, options: nil)
            }
            return InspectRule(type: typ, payload: rest, proxy: "", options: nil)
        case "MATCH", "FINAL":
            return InspectRule(type: "MATCH", payload: "", proxy: rest.trimmingCharacters(in: .whitespaces), options: nil)
        default:
            // Go strings.Split keeps empty fields; options = TrimSpace(Join(parts[2:], ",")).
            let parts = rest.split(separator: ",", omittingEmptySubsequences: false).map { String($0) }
            let payload = parts.first?.trimmingCharacters(in: .whitespaces) ?? ""
            let proxy = parts.count > 1 ? parts[1].trimmingCharacters(in: .whitespaces) : ""
            let options = parts.count > 2 ? parts.dropFirst(2).joined(separator: ",").trimmingCharacters(in: .whitespaces) : nil
            return InspectRule(type: typ, payload: payload, proxy: proxy, options: options?.isEmpty == true ? nil : options)
        }
    }

    // MARK: - Provider Helpers

    static func providerCache(homeDir: String, kind: String, pathVal: String?, urlVal: String?) -> String {
        if let p = pathVal, !p.isEmpty {
            if p.hasPrefix("/") { return p }
            return (homeDir as NSString).appendingPathComponent(p)
        }
        if let u = urlVal, !u.isEmpty {
            let prefix = (kind == "rule") ? "rules" : "proxies"
            let digest = Insecure.SHA1.hash(data: Data(u.utf8))
            let hex = digest.map { String(format: "%02x", $0) }.joined()
            let dir = (homeDir as NSString).appendingPathComponent(prefix)
            return (dir as NSString).appendingPathComponent(hex)
        }
        return ""
    }

    static func inspectProviders(homeDir: String, kind: String, raw: NCJSONValue?) -> [InspectProvider] {
        var out: [InspectProvider] = []
        guard let obj = raw?.object else { return out }

        for (name, v) in obj {
            guard let m = v.object else { continue }
            let vehicle = m["type"]?.string?.trimmingCharacters(in: .whitespaces).lowercased() ?? ""
            let behavior = m["behavior"]?.string
            let format = m["format"]?.string
            let urlVal = m["x-source"]?.string ?? m["url"]?.string
            let pathVal = m["path"]?.string
            let interval = m["interval"]?.int

            var p = InspectProvider(
                name: name,
                kind: kind,
                vehicle: vehicle,
                behavior: behavior,
                format: format,
                url: urlVal,
                path: pathVal,
                interval: interval,
                cached: false,
                cachedAt: nil,
                size: nil,
                count: -1,
                proxies: nil,
                preview: nil,
                cachePath: nil
            )

            if vehicle == "inline" {
                if kind == "proxy" {
                    var proxies: [InspectProxy] = []
                    if let pxArr = m["payload"]?.array {
                        for pxVal in pxArr {
                            if let pxObj = pxVal.object {
                                proxies.append(toInspectProxy(pxObj, source: name))
                            }
                        }
                    }
                    p.proxies = proxies
                    p.count = proxies.count
                } else {
                    let pl = m["payload"]?.array?.compactMap { $0.string } ?? []
                    p.count = pl.count
                    p.preview = Array(pl.prefix(50))
                }
                p.cached = true
                out.append(p)
                continue
            }

            // nc-integrate: Go providerCache hashes the runtime `url` with MD5 (mihomo GetPathByHash), not x-source/SHA1.
            let cp = ncProviderCachePath(home: homeDir, kind: kind, m)
            p.cachePath = cp
            if !cp.isEmpty,
               let attr = try? FileManager.default.attributesOfItem(atPath: cp),
               let size = attr[.size] as? Int64, size > 0,
               let fileType = attr[.type] as? FileAttributeType, fileType == .typeRegular {
                p.cached = true
                p.size = size
                if let modDate = attr[.modificationDate] as? Date {
                    p.cachedAt = modDate.timeIntervalSince1970
                }
                if size <= 8 << 20, let data = try? Data(contentsOf: URL(fileURLWithPath: cp)) {
                    if kind == "proxy" {
                        let parsedNodes = parseProviderNodes(data: data, source: name)
                        p.proxies = parsedNodes
                        p.count = parsedNodes.count
                    } else {
                        let (preview, count) = parseRuleCache(data: data, format: format)
                        p.preview = preview
                        p.count = count
                    }
                }
            }
            out.append(p)
        }

        out.sort { $0.name < $1.name }
        return out
    }

    static func parseRuleCache(data: Data, format: String?) -> (preview: [String], count: Int) {
        if let format = format, format.caseInsensitiveCompare("mrs") == .orderedSame {
            return ([], -1)
        }
        if data.count >= 4 {
            let prefix = data.prefix(4)
            if prefix == Data([0x4D, 0x52, 0x53, 0x01]) {
                return ([], -1)
            }
        }
        let text = String(decoding: data, as: UTF8.self)
        if let parsed = NCYAML.parse(text), case .object(let obj) = parsed,
           let pl = obj["payload"]?.array?.compactMap({ $0.string }), !pl.isEmpty {
            return (Array(pl.prefix(50)), pl.count)
        }
        var lines: [String] = []
        let normalized = text.replacingOccurrences(of: "\r", with: "")
        for rawLine in normalized.split(separator: "\n", omittingEmptySubsequences: false) {
            var l = rawLine.trimmingCharacters(in: .whitespaces)
            if l.isEmpty || l.hasPrefix("#") || l.hasPrefix("//") || l == "payload:" {
                continue
            }
            if l.hasPrefix("- ") { l = String(l.dropFirst(2)).trimmingCharacters(in: .whitespaces) }
            lines.append(l)
        }
        return (Array(lines.prefix(50)), lines.count)
    }

    static func parseProviderNodes(data: Data, source: String) -> [InspectProxy] {
        let text = String(decoding: data, as: UTF8.self)
        if let parsed = NCYAML.parse(text), case .object(let obj) = parsed,
           let proxies = obj["proxies"]?.array {
            var out: [InspectProxy] = []
            for pVal in proxies {
                if let pObj = pVal.object {
                    out.append(toInspectProxy(pObj, source: source))
                }
            }
            if !out.isEmpty { return out }
        }
        let nodes = NCSubscriptionParser.parse(text)
        return nodes.map { p in
            toInspectProxy(p.dictionary, source: source)
        }
    }

    // MARK: - Node Converters

    static func toInspectProxy(_ m: [String: NCJSONValue], source: String = "") -> InspectProxy {
        let name = m["name"]?.string ?? ""
        let type = m["type"]?.string ?? ""
        let server = m["server"]?.string
        let port = m["port"]?.int
        let udp = m["udp"]?.bool
        return InspectProxy(
            name: name,
            type: type,
            server: server,
            port: port,
            udp: udp,
            source: source.isEmpty ? nil : source
        )
    }

    static func toInspectProxy(_ m: [String: Any], source: String = "") -> InspectProxy {
        let name = m["name"] as? String ?? ""
        let type = m["type"] as? String ?? ""
        let server = m["server"] as? String
        var port: Int? = nil
        if let p = m["port"] as? Int { port = p }
        else if let p = m["port"] as? Double { port = p.isFinite && p >= Double(Int.min) && p < Double(Int.max) ? Int(p) : nil }
        else if let p = m["port"] as? String { port = Int(p) }
        let udp = m["udp"] as? Bool
        return InspectProxy(
            name: name,
            type: type,
            server: server,
            port: port,
            udp: udp,
            source: source.isEmpty ? nil : source
        )
    }
}
