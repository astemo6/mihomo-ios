import Foundation

/// Rule-provider store: owns the downloaded rule lists behind RULE-SET
/// rules, their on-disk cache, freshness and the in-memory match indexes.
///
/// Sources, unified:
/// - mihomo `rule-providers:` entries (behavior classical/domain/ipcidr,
///   type http/file/inline)
/// - RULE-SET rules whose payload is itself a URL (Surge/Loon/QX style:
///   `RULE-SET,https://…,Policy`) — registered keyed by that URL with
///   per-line dialect auto-detection
///
/// Fetching is injected (`fetcher`) so tests never touch the network; the
/// production default is a plain URLSession data task (the extension's own
/// traffic does not loop through its tunnel). A failed refresh keeps the
/// previous index — a stale list beats an empty one (QX/Surge behavior).
///
/// Payload caps (memory budget, docs/nativecore-memory-budget.md): a
/// provider body over `maxPayloadBytes`, or a parsed list over
/// `maxEntries`, is a refresh/load failure — the previous index and the
/// on-disk cache are kept, exactly like a network failure, with the gate
/// named in the log line so the two are distinguishable.
enum NCRuleProviderGateError: Error, CustomStringConvertible {
    case payloadTooLarge(name: String, bytes: Int, limit: Int)
    case tooManyEntries(name: String, count: Int, limit: Int)

    var description: String {
        switch self {
        case .payloadTooLarge(let name, let bytes, let limit):
            return "rule provider '\(name)' payload is \(bytes) bytes, over the \(limit)-byte cap"
        case .tooManyEntries(let name, let count, let limit):
            return "rule provider '\(name)' parsed to \(count) entries, over the \(limit)-entry cap"
        }
    }
}

final class NCRuleProviderStore {
    /// Hard caps on one provider payload / parsed list. Well above the
    /// ~50k-entry lists seen in the wild, low enough that a hostile or
    /// broken provider cannot blow the extension's memory budget.
    static let maxPayloadBytes = 32 * 1024 * 1024
    static let maxEntries = 300_000

    struct Provider: Equatable {
        var name: String // lookup key: provider name, or the URL itself
        var behavior: String = "classical" // classical | domain | ipcidr
        var format: String = "yaml" // yaml | text | mrs
        var url: String? = nil
        var filePath: String? = nil // local file (type=file), absolute or home-relative
        var inlinePayload: [String] = []
        var interval: Int = 86400
        /// Other keys this provider answers to: a RULE-SET / DOMAIN-SET line
        /// whose payload is the URL of a declared provider shares that
        /// provider's index instead of downloading and indexing the same
        /// list twice (the .conf importers declare a named provider AND keep
        /// the URL in the rule line).
        var aliases: [String] = []

        init(
            name: String,
            behavior: String = "classical",
            format: String = "yaml",
            url: String? = nil,
            filePath: String? = nil,
            inlinePayload: [String] = [],
            interval: Int = 86400
        ) {
            self.name = name
            self.behavior = behavior
            self.format = format
            self.url = url
            self.filePath = filePath
            self.inlinePayload = inlinePayload
            self.interval = interval
        }

        var isMRS: Bool {
            format.lowercased() == "mrs" ||
            (filePath?.hasSuffix(".mrs") == true) ||
            (url?.hasSuffix(".mrs") == true)
        }

        var flavor: NCRuleSetFlavor {
            switch behavior {
            case "domain": return .domainSet
            case "ipcidr", "classical": return .classical
            default: return .auto
            }
        }
    }

    private let dir: URL
    private let lock = NSLock()
    private var indexes: [String: NCRuleSetIndex] = [:]
    private var aliasMap: [String: String] = [:]
    private var fetchedAt: [String: TimeInterval] = [:]

    /// (urlString, completion) — completion gets the body or nil on failure.
    var fetcher: (String, @escaping (Data?) -> Void) -> Void = { urlString, done in
        guard let url = URL(string: urlString) else { done(nil); return }
        URLSession.shared.dataTask(with: url) { data, _, _ in done(data) }.resume()
    }

    init(dir: URL) {
        self.dir = dir
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        if let data = try? Data(contentsOf: dir.appendingPathComponent("meta.json")),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Double] {
            fetchedAt = obj
        }
    }

    // MARK: provider discovery

    /// Providers declared in a mihomo-shaped config, plus implicit URL
    /// providers from RULE-SET rules that carry a URL payload.
    static func providers(from cfg: NCConfig) -> [Provider] {
        var out: [Provider] = []
        if let providers = cfg.raw["rule-providers"]?.object {
            for name in providers.keys.sorted() {
                guard let o = providers[name]?.object else { continue }
                var p = Provider(name: name)
                // No behavior (QX filter_remote / Loon remote rules lowered
                // without one): per-line dialect detection, which also
                // handles classical lines and YAML payload documents.
                p.behavior = o["behavior"]?.string?.lowercased() ?? "auto"
                p.url = o["url"]?.string
                p.filePath = o["path"]?.string
                p.format = o["format"]?.string ?? (
                    (p.filePath?.hasSuffix(".mrs") == true || p.url?.hasSuffix(".mrs") == true) ? "mrs" : "yaml"
                )
                p.interval = o["interval"]?.int ?? 86400
                if (o["type"]?.string ?? "") == "inline" {
                    p.inlinePayload = o["payload"]?.array?.compactMap { $0.string } ?? []
                }
                out.append(p)
            }
        }
        var declared = Set(out.map { $0.name })
        var declaredByURL: [String: Int] = [:]
        for (i, p) in out.enumerated() { if let u = p.url, declaredByURL[u] == nil { declaredByURL[u] = i } }
        // URL payloads of RULE-SET / DOMAIN-SET lines (top level, inside
        // logic rules and in sub-rule sets).
        var refs: [(kind: String, payload: String)] = []
        func collect(_ r: NCRule) {
            if r.kind == "RULE-SET" || r.kind == "DOMAIN-SET" { refs.append((r.kind, r.payload)) }
            for sub in r.subRules { collect(sub) }
        }
        for line in cfg.rules { if let r = NCRule.parse(line) { collect(r) } }
        for name in cfg.subRules.keys.sorted() { for r in cfg.subRules[name] ?? [] { collect(r) } }
        for (kind, payload) in refs {
            guard payload.hasPrefix("http://") || payload.hasPrefix("https://"), !declared.contains(payload) else { continue }
            if let i = declaredByURL[payload] {
                if !out[i].aliases.contains(payload) { out[i].aliases.append(payload) }
                continue
            }
            let fmt = payload.hasSuffix(".mrs") ? "mrs" : (kind == "DOMAIN-SET" ? "text" : "auto")
            out.append(Provider(name: payload, behavior: kind == "DOMAIN-SET" ? "domain" : "auto",
                                format: fmt, url: payload))
            declared.insert(payload)
        }
        return out
    }

    // MARK: loading

    private func cacheFile(for name: String) -> URL {
        // Provider names/URLs → stable file names (FNV-1a, no crypto needed).
        var hash: UInt64 = 0xcbf29ce484222325
        for b in name.utf8 { hash = (hash ^ UInt64(b)) &* 0x100000001b3 }
        return dir.appendingPathComponent(String(format: "set-%016llx.txt", hash))
    }

    /// Populate an in-memory index from raw data (either text/yaml or binary .mrs).
    /// Both payload gates live here because every load path funnels through
    /// this one function: network refresh, cold-start disk cache and local
    /// `type=file` payloads (the last two never pass the refresh path, and a
    /// cache file may predate the gates — so they are checked again here).
    static func populateIndex(idx: inout NCRuleSetIndex, data: Data, provider: Provider) throws {
        guard data.count <= maxPayloadBytes else {
            throw NCRuleProviderGateError.payloadTooLarge(
                name: provider.name, bytes: data.count, limit: maxPayloadBytes)
        }
        if provider.isMRS || NCMRS.isMRS(data: data) {
            try idx.addMRS(data: data, behavior: provider.behavior)
        } else if let text = String(data: data, encoding: .utf8) {
            idx.addText(text, flavor: provider.flavor)
        } else {
            throw NCMRSError.corrupted("rule provider '\(provider.name)' payload is neither UTF-8 text nor recognized MRS binary format")
        }
        try checkEntryGate(idx, provider: provider)
    }

    /// The single entry-count gate. Every load path — populateIndex (network
    /// refresh, disk cache, local file) and the inline-payload branch of
    /// loadCached, which has no Data body to hand populateIndex — calls this
    /// one function, so the limit (`maxEntries`) and the comparison live in
    /// exactly one place and the paths cannot drift apart.
    static func checkEntryGate(_ idx: NCRuleSetIndex, provider: Provider) throws {
        guard idx.entryCount <= maxEntries else {
            throw NCRuleProviderGateError.tooManyEntries(
                name: provider.name, count: idx.entryCount, limit: maxEntries)
        }
    }

    /// Build indexes from inline payloads, local files and the disk cache.
    /// Returns the providers that still need a network refresh.
    @discardableResult
    func loadCached(providers: [Provider], home: String) -> [Provider] {
        var stale: [Provider] = []
        lock.lock()
        aliasMap = [:]
        for p in providers { for a in p.aliases { aliasMap[a] = p.name } }
        lock.unlock()
        for p in providers {
            var idx = NCRuleSetIndex()
            var loaded = false
            if !p.inlinePayload.isEmpty {
                for line in p.inlinePayload { idx.addLine(line, flavor: p.flavor) }
                // Inline payloads have no Data body for populateIndex; they
                // go through the same entry gate function it uses.
                do {
                    try Self.checkEntryGate(idx, provider: p)
                    loaded = idx.entryCount > 0
                } catch {
                    NSLog("[NCRuleProviderStore] failed loading inline payload for %@: %@", p.name, String(describing: error))
                }
            } else if let path = p.filePath {
                let url = path.hasPrefix("/") ? URL(fileURLWithPath: path)
                    : URL(fileURLWithPath: home).appendingPathComponent(path)
                if let data = try? Data(contentsOf: url) {
                    do {
                        try Self.populateIndex(idx: &idx, data: data, provider: p)
                        loaded = idx.entryCount > 0
                    } catch {
                        NSLog("[NCRuleProviderStore] failed loading local file %@ for %@: %@", path, p.name, String(describing: error))
                    }
                }
            }
            if !loaded, let data = try? Data(contentsOf: cacheFile(for: p.name)) {
                do {
                    try Self.populateIndex(idx: &idx, data: data, provider: p)
                    loaded = idx.entryCount > 0
                } catch {
                    NSLog("[NCRuleProviderStore] failed loading cache for %@: %@", p.name, String(describing: error))
                }
            }
            if loaded {
                lock.lock(); indexes[p.name] = idx; lock.unlock()
            }
            if p.url != nil, needsRefresh(p) { stale.append(p) }
        }
        return stale
    }

    func needsRefresh(_ p: Provider) -> Bool {
        lock.lock(); let at = fetchedAt[p.name]; lock.unlock()
        guard let at else { return true }
        return Date().timeIntervalSince1970 - at > Double(max(p.interval, 60))
    }

    /// Fetch one provider and swap its index on success. Failures keep the
    /// old index and do not update the timestamp (retry next cycle).
    func refresh(_ p: Provider, completion: (() -> Void)? = nil) {
        guard let url = p.url else { completion?(); return }
        fetcher(url) { [weak self] data in
            guard let self, let data else {
                completion?()
                return
            }
            var idx = NCRuleSetIndex()
            do {
                try Self.populateIndex(idx: &idx, data: data, provider: p)
            } catch {
                NSLog("[NCRuleProviderStore] refresh failed for %@: %@", p.name, String(describing: error))
                completion?()
                return
            }
            guard idx.entryCount > 0 else { completion?(); return }
            try? data.write(to: self.cacheFile(for: p.name), options: .atomic)
            self.lock.lock()
            self.indexes[p.name] = idx
            self.fetchedAt[p.name] = Date().timeIntervalSince1970
            let meta = self.fetchedAt
            self.lock.unlock()
            if let mdata = try? JSONSerialization.data(withJSONObject: meta) {
                try? mdata.write(to: self.dir.appendingPathComponent("meta.json"), options: .atomic)
            }
            completion?()
        }
    }

    func refreshAll(_ providers: [Provider]) {
        for p in providers where p.url != nil { refresh(p) }
    }

    // MARK: matching

    func contains(name: String, ctx: NCMatchContext) -> Bool {
        lock.lock(); let idx = indexes[aliasMap[name] ?? name]; lock.unlock()
        return idx?.contains(ctx) ?? false
    }

    /// Domain-only membership (DNS nameserver-policy `rule-set:` keys,
    /// fake-ip-filter `rule-set:` entries): mihomo matches only the
    /// provider's domain entries there.
    func containsDomain(name: String, domain: String) -> Bool {
        contains(name: name, ctx: NCMatchContext(domain: domain))
    }

    /// mihomo RuleSet.ShouldResolveIP: the set holds IP entries.
    func needsIP(name: String) -> Bool {
        lock.lock(); let idx = indexes[aliasMap[name] ?? name]; lock.unlock()
        return idx?.needsIP ?? false
    }

    /// Whether a provider (or alias) by this key is configured and loaded.
    func isLoaded(name: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return indexes[aliasMap[name] ?? name] != nil
    }

}
