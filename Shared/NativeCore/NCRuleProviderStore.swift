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
final class NCRuleProviderStore {
    struct Provider: Equatable {
        var name: String // lookup key: provider name, or the URL itself
        var behavior: String = "classical" // classical | domain | ipcidr
        var url: String? = nil
        var filePath: String? = nil // local file (type=file), absolute or home-relative
        var inlinePayload: [String] = []
        var interval: Int = 86400

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
                p.behavior = o["behavior"]?.string ?? "classical"
                p.url = o["url"]?.string
                p.filePath = o["path"]?.string
                p.interval = o["interval"]?.int ?? 86400
                if (o["type"]?.string ?? "") == "inline" {
                    p.inlinePayload = o["payload"]?.array?.compactMap { $0.string } ?? []
                }
                out.append(p)
            }
        }
        let declared = Set(out.map { $0.name })
        for rule in cfg.rules {
            let fields = NCRule.splitTopLevel(rule)
            guard fields.count >= 2, fields[0].uppercased() == "RULE-SET" else { continue }
            let payload = fields[1]
            if payload.hasPrefix("http://") || payload.hasPrefix("https://"), !declared.contains(payload) {
                out.append(Provider(name: payload, behavior: "auto", url: payload))
            }
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

    /// Build indexes from inline payloads, local files and the disk cache.
    /// Returns the providers that still need a network refresh.
    @discardableResult
    func loadCached(providers: [Provider], home: String) -> [Provider] {
        var stale: [Provider] = []
        for p in providers {
            var idx = NCRuleSetIndex()
            var loaded = false
            if !p.inlinePayload.isEmpty {
                for line in p.inlinePayload { idx.addLine(line, flavor: p.flavor) }
                loaded = idx.entryCount > 0
            } else if let path = p.filePath {
                let url = path.hasPrefix("/") ? URL(fileURLWithPath: path)
                    : URL(fileURLWithPath: home).appendingPathComponent(path)
                if let text = try? String(contentsOf: url, encoding: .utf8) {
                    idx.addText(text, flavor: p.flavor)
                    loaded = idx.entryCount > 0
                }
            }
            if !loaded, let text = try? String(contentsOf: cacheFile(for: p.name), encoding: .utf8) {
                idx.addText(text, flavor: p.flavor)
                loaded = idx.entryCount > 0
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
            guard let self, let data, let text = String(data: data, encoding: .utf8) else {
                completion?()
                return
            }
            var idx = NCRuleSetIndex()
            idx.addText(text, flavor: p.flavor)
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
        lock.lock(); let idx = indexes[name]; lock.unlock()
        return idx?.contains(ctx) ?? false
    }

    func loadedNames() -> [String] {
        lock.lock(); defer { lock.unlock() }
        return Array(indexes.keys)
    }
}
