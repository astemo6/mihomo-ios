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
/// Fetching is injected (`fetcher` / `downloader` / `httpDownloader`) so tests
/// never touch the network; the production default is a conditional URLSession
/// download task (the extension's own traffic does not loop through its tunnel). A failed refresh keeps the
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

    /// Test hook: (urlString, completion) — completion gets the body or nil on failure. When set it replaces the
    /// production download (`downloader`) and the body is parsed from memory as before.
    var fetcher: ((String, @escaping (Data?) -> Void) -> Void)? = nil

    /// fix/nc-mem-3 test hook: a plain download (no validators) — `done` gets the temporary file or nil. When set it
    /// replaces `httpDownloader`.
    var downloader: ((String, @escaping (URL?) -> Void) -> Void)? = nil

    /// Result of one production download.
    enum Download {
        /// The body, streamed to a temporary file (valid only until the callback returns — the store moves it
        /// synchronously), with the response's validators.
        case file(URL, etag: String?, lastModified: String?)
        /// HTTP 304 to the `If-None-Match` / `If-Modified-Since` the store sent.
        case notModified
        case failed
    }

    /// fix/nc-mem-3 + fix/nc-ruleset-fast: production fetch — URLSession *download* task (the body is streamed to a
    /// temporary file by the networking stack, never accumulated in a growing Data in the extension's heap), sent
    /// with the cached list's validators (headers; empty for a first download). Completes on `session`'s serial
    /// delegate queue; the store only moves the file there and parses on `parseQueue`.
    var httpDownloader: (String, [String: String], @escaping (Download) -> Void) -> Void = { urlString, headers, done in
        guard let url = URL(string: urlString) else { done(.failed); return }
        var req = URLRequest(url: url)
        for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
        NCRuleProviderStore.session.downloadTask(with: req) { file, resp, err in
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            if err == nil, code == 304 { done(.notModified); return }
            guard err == nil, (200..<300).contains(code), let file else {
                StartupLog.write("rule set: fetch failed \(NCRuleProviderStore.logName(urlString)) — " +
                                 (err.map { $0.localizedDescription } ?? "HTTP \(code)"))
                done(.failed)
                return
            }
            let (etag, lm) = NCFetchValidators.headers(of: resp)
            done(.file(file, etag: etag, lastModified: lm))
        }.resume()
    }

    /// fix/nc-ruleset-fast: every downloaded list is parsed here, one list at a time process-wide (each in its own
    /// autorelease pool) — downloads no longer wait for parses, parses never overlap (memory first).
    static let parseQueue = DispatchQueue(label: "nc.ruleprovider.parse", qos: .utility)

    /// Test hook: called on `parseQueue` with true before / false after each list parse.
    var parseObserver: ((Bool) -> Void)? = nil

    /// fix/nc-mem-3: per-list `[nc-mem]` lines around fetch / parse (footprint before, after the download, after the
    /// parse, and the kernel's lifetime peak). Debug builds (E2E replay) only.
    #if DEBUG
    static var memLog = true
    #else
    static var memLog = false
    #endif

    static func memLine(_ name: String, _ text: String) {
        guard memLog else { return }
        let fp = Double(ProcessMemory.footprintBytes()) / 1_048_576
        let pk = Double(ProcessMemory.peakBytes()) / 1_048_576
        NSLog("[nc-mem] scene=rule-set %@ %@ footprint=%.1fMB peak=%.1fMB", logName(name), text, fp, pk)
    }

    /// fix/nc-mem-providers: rule-list downloads skip URLSession.shared's in-memory URLCache (a cached copy of every
    /// list body next to the parsed index; it would also answer our own 304s with its copy). Completions run on one
    /// serial queue and only move the downloaded file; parsing is on `parseQueue`. The on-disk cache file
    /// (cacheFile) is the only copy kept.
    static let session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.urlCache = nil
        c.requestCachePolicy = .reloadIgnoringLocalCacheData
        c.httpMaximumConnectionsPerHost = 6 // fix/nc-ruleset-fast: = maxConcurrentFetches (most lists share one host)
        let q = OperationQueue()
        q.maxConcurrentOperationCount = 1
        q.name = "nc.ruleprovider.fetch"
        return URLSession(configuration: c, delegate: nil, delegateQueue: q)
    }()

    /// Go-era configs point remote QX/Surge/Loon rule lists at the bridge's own converter
    /// (http://127.0.0.1:<port>/rules/convert?url=<src>&kind=<kind>). NativeCore has no converter:
    /// its parser reads every dialect itself, so fetch the source list directly.
    static func unwrapLoopbackConvert(_ urlString: String) -> String {
        guard let c = URLComponents(string: urlString),
              let host = c.host, host == "127.0.0.1" || host == "localhost" || host == "::1",
              c.path.hasSuffix("/rules/convert"),
              let src = c.queryItems?.first(where: { $0.name == "url" })?.value,
              src.hasPrefix("http://") || src.hasPrefix("https://") else { return urlString }
        return src
    }

    static func loopbackConvertKind(_ urlString: String) -> String? {
        guard let c = URLComponents(string: urlString), c.path.hasSuffix("/rules/convert") else { return nil }
        return c.queryItems?.first(where: { $0.name == "kind" })?.value
    }

    static func logName(_ urlString: String) -> String {
        guard let c = URLComponents(string: urlString), let h = c.host else { return "?" }
        return h + "/…" + (c.path.split(separator: "/").last.map(String.init) ?? "")
    }

    init(dir: URL) {
        self.dir = dir
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        if let data = try? Data(contentsOf: dir.appendingPathComponent("meta.json")),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Double] {
            fetchedAt = obj
        }
        // fix/nc-ruleset-fast: downloads interrupted by a crash / kill leave `<cache>.<n>.part` files; drop old ones
        // (not fresh ones: a replaced store's download may still be finishing in the same directory).
        let fm = FileManager.default
        for n in (try? fm.contentsOfDirectory(atPath: dir.path)) ?? [] where n.hasSuffix(".part") {
            let u = dir.appendingPathComponent(n)
            let m = (try? fm.attributesOfItem(atPath: u.path))?[.modificationDate] as? Date ?? .distantPast
            if Date().timeIntervalSince(m) > 600 { try? fm.removeItem(at: u) }
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
                p.url = o["url"]?.string.map(Self.unwrapLoopbackConvert)
                if let raw = o["url"]?.string, raw != p.url, o["behavior"] == nil,
                   Self.loopbackConvertKind(raw) == "domainset" {
                    p.behavior = "domain"
                }
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
        } else if !idx.addData(data, flavor: provider.flavor) {
            // fix/nc-mem-providers: streamed line by line out of the body (no whole-body String copy)
            throw NCMRSError.corrupted("rule provider '\(provider.name)' payload is neither UTF-8 text nor recognized MRS binary format")
        }
        try checkEntryGate(idx, provider: provider)
        idx.finalize()
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
                idx.finalize()
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
                if let data = try? Data(contentsOf: url, options: .mappedIfSafe) {
                    do {
                        try Self.populateIndex(idx: &idx, data: data, provider: p)
                        loaded = idx.entryCount > 0
                    } catch {
                        NSLog("[NCRuleProviderStore] failed loading local file %@ for %@: %@", path, p.name, String(describing: error))
                    }
                }
            }
            // fix/nc-mem-3: cache files are mapped, not read into the heap (cold start parses ~1.5 MB of lists)
            if !loaded, let data = try? Data(contentsOf: cacheFile(for: p.name), options: .mappedIfSafe) {
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
    /// A 304, or a body byte-identical to the cache (size + SHA-256), keeps the index and the cache without parsing.
    func refresh(_ p: Provider, completion: (() -> Void)? = nil) {
        fetch(p, downloaded: nil, completion: completion)
    }

    /// fix/nc-ruleset-fast: `downloaded` fires once the network part is over (the body is on disk, or 304, or a
    /// failure) — refreshAll starts the next download then; `completion` fires after the parse / publish.
    /// The escaping callbacks hold the store only weakly and never across `downloaded` / `completion` (a store
    /// dropped by a reload must stop its chain), and use no dynamic `Self`.
    private func fetch(_ p: Provider, downloaded: (() -> Void)?, completion: (() -> Void)?) {
        guard let url = p.url else { downloaded?(); completion?(); return }
        let t0 = Date()
        NCRuleProviderStore.memLine(p.name, "fetch-start")
        if let fetcher {
            fetcher(url) { [weak self] data in
                if let data { self?.applyFetched(p, data: data, t0: t0) }
                downloaded?()
                completion?()
            }
            return
        }
        let cache = cacheFile(for: p.name)
        // Validators only when the index they describe is loaded: a 304 must have something to keep.
        let prev = isLoaded(name: p.name) ? NCFetchValidators.load(for: cache, url: url) : nil
        let handle: (Download) -> Void = { [weak self] result in
            switch result {
            case .failed:
                break
            case .notModified:
                self?.keepNotModified(p, cache: cache, sentValidators: prev != nil, t0: t0)
            case .file(let file, let etag, let lm):
                // The temporary file is deleted once this callback returns: move it next to the cache file first.
                guard let part = self?.moveToPart(file, cache: cache, name: p.name) else { break }
                downloaded?()
                NCRuleProviderStore.parseQueue.async { [weak self] in
                    let ok = self?.loadDownloaded(p, url: url, part: part, cache: cache, t0: t0,
                                                  etag: etag, lastModified: lm, prev: prev) ?? false
                    if !ok { try? FileManager.default.removeItem(at: part) }
                    completion?()
                }
                return
            }
            downloaded?()
            completion?()
        }
        if let downloader {
            downloader(url) { file in
                if let file { handle(.file(file, etag: nil, lastModified: nil)) } else { handle(.failed) }
            }
        } else {
            httpDownloader(url, prev?.requestHeaders ?? [:], handle)
        }
    }

    /// The test-hook (in-memory body) path: parse, write the cache, publish.
    private func applyFetched(_ p: Provider, data: Data, t0: Date) {
        Self.memLine(p.name, "fetched bytes=\(data.count) ms=\(Self.ms(t0))")
        var idx = NCRuleSetIndex()
        do {
            try Self.populateIndex(idx: &idx, data: data, provider: p)
        } catch {
            NSLog("[NCRuleProviderStore] refresh failed for %@: %@", p.name, String(describing: error))
            return
        }
        guard idx.entryCount > 0 else { return }
        let cache = cacheFile(for: p.name)
        try? data.write(to: cache, options: .atomic)
        NCFetchValidators.remove(for: cache) // written without validators
        publish(p, idx)
    }

    /// HTTP 304: the loaded index and the cache stay; the list is stamped fresh.
    private func keepNotModified(_ p: Provider, cache: URL, sentValidators: Bool, t0: Date) {
        guard sentValidators, isLoaded(name: p.name) else {
            NSLog("[NCRuleProviderStore] refresh failed for %@: unexpected HTTP 304", p.name)
            return
        }
        Self.memLine(p.name, "not-modified ms=\(Self.ms(t0))")
        NCFetchValidators.touch(cache)
        publish(p, nil)
    }

    private func moveToPart(_ file: URL, cache: URL, name: String) -> URL? {
        let part = partFile(for: cache)
        do {
            try FileManager.default.moveItem(at: file, to: part)
            return part
        } catch {
            NSLog("[NCRuleProviderStore] refresh failed for %@: %@", name, String(describing: error))
            return nil
        }
    }

    private static var partSeq: UInt64 = 0
    private static let partLock = NSLock()

    /// `<cache>.<n>.part` — unique per download, so two refreshes of one list never share a temp file.
    private func partFile(for cache: URL) -> URL {
        Self.partLock.lock(); Self.partSeq &+= 1; let n = Self.partSeq; Self.partLock.unlock()
        return cache.appendingPathExtension("\(n).part")
    }

    /// Parse a downloaded list straight from its file (memory-mapped: clean, file-backed pages that do not count
    /// toward the extension's footprint the way a heap copy of the body does) and, when it parses to entries,
    /// make that file the cache file (a rename — the body is never copied or rewritten). One pool per list.
    /// A body byte-identical to the cache file (size, then SHA-256 over the mapped bytes) is not parsed: the
    /// loaded index already is that list. Returns true when the cache is current (renamed or identical).
    private func loadDownloaded(_ p: Provider, url: String, part: URL, cache: URL, t0: Date,
                                etag: String?, lastModified: String?, prev: NCFetchValidators?) -> Bool {
        var ok = false
        Self.withPool {
            let size = NCFetchValidators.fileSize(part) ?? 0
            Self.memLine(p.name, "fetched bytes=\(size) ms=\(Self.ms(t0))")
            guard size > 0 else { return }
            guard size <= Self.maxPayloadBytes else {
                NSLog("[NCRuleProviderStore] refresh failed for %@: %@", p.name, String(describing:
                    NCRuleProviderGateError.payloadTooLarge(name: p.name, bytes: size, limit: Self.maxPayloadBytes)))
                return
            }
            guard let data = try? Data(contentsOf: part, options: .alwaysMapped) else {
                NSLog("[NCRuleProviderStore] refresh failed for %@: cannot map the download", p.name)
                return
            }
            let hash = NCContentHash.hex(data)
            var v = NCFetchValidators(url: url, etag: etag, lastModified: lastModified,
                                      bodySize: size, bodyHash: hash, cacheSize: size)
            if self.isLoaded(name: p.name), NCFetchValidators.fileSize(cache) == size {
                let cachedHash = (prev?.bodySize == size ? prev?.bodyHash : nil) ?? NCContentHash.file(cache)?.hash
                if cachedHash == hash {
                    Self.memLine(p.name, "unchanged bytes=\(size)")
                    try? FileManager.default.removeItem(at: part)
                    NCFetchValidators.touch(cache)
                    v.save(for: cache)
                    self.publish(p, nil)
                    ok = true
                    return
                }
            }
            let t1 = Date()
            self.parseObserver?(true)
            defer { self.parseObserver?(false) }
            var idx = NCRuleSetIndex()
            do {
                try Self.populateIndex(idx: &idx, data: data, provider: p)
            } catch {
                NSLog("[NCRuleProviderStore] refresh failed for %@: %@", p.name, String(describing: error))
                return
            }
            Self.memLine(p.name, "parsed entries=\(idx.entryCount) ms=\(Self.ms(t1))")
            guard idx.entryCount > 0 else { return }
            // rename(2) replaces the old cache file atomically (same directory)
            guard rename(part.path, cache.path) == 0 else {
                NSLog("[NCRuleProviderStore] cache rename failed for %@ (errno %d)", p.name, errno)
                return
            }
            v.cacheSize = size
            v.save(for: cache)
            self.publish(p, idx)
            ok = true
        }
        return ok
    }

    /// Swap in a new index (nil: the loaded one stays — 304 / identical body) and stamp the list fresh.
    private func publish(_ p: Provider, _ idx: NCRuleSetIndex?) {
        lock.lock()
        if let idx { indexes[p.name] = idx }
        fetchedAt[p.name] = Date().timeIntervalSince1970
        let meta = fetchedAt
        lock.unlock()
        if let mdata = try? JSONSerialization.data(withJSONObject: meta) {
            try? mdata.write(to: dir.appendingPathComponent("meta.json"), options: .atomic)
        }
    }

    private static func ms(_ since: Date) -> Int { Int(Date().timeIntervalSince(since) * 1000) }

    @inline(__always)
    private static func withPool(_ body: () -> Void) {
        #if canImport(ObjectiveC)
        autoreleasepool { body() }
        #else
        body()
        #endif
    }

    /// fix/nc-mem-2: lists in flight at once during refreshAll. It used to start every stale list together, each
    /// URLSession task buffering its whole body in the heap while the serial parse worked through them.
    /// fix/nc-ruleset-fast: since fix/nc-mem-3 a body is streamed to a file, not held in the heap, so six downloads
    /// cost little memory (HTTP/2 multiplexes lists of one host on one connection) and the slot is released when the
    /// download ends, not when its parse does; parsing stays one list at a time on `parseQueue`.
    static let maxConcurrentFetches = 6

    func refreshAll(_ providers: [Provider]) {
        let pending = FetchQueue(providers.filter { $0.url != nil })
        guard pending.count > 0 else { return }
        for _ in 0..<min(Self.maxConcurrentFetches, pending.count) { Self.pump(self, pending) }
    }

    /// Starts the next pending fetch when one's download finishes. The store is held weakly: a store replaced by a
    /// reload stops fetching for itself instead of being kept alive (with its indexes) by its own refresh chain.
    private static func pump(_ store: NCRuleProviderStore?, _ pending: FetchQueue) {
        guard let store, let p = pending.pop() else { return }
        store.fetch(p, downloaded: { [weak store] in pump(store, pending) }, completion: nil)
    }

    private final class FetchQueue {
        private let lock = NSLock()
        private var items: [Provider]
        let count: Int
        init(_ items: [Provider]) { self.items = items.reversed(); count = items.count }
        func pop() -> Provider? { lock.lock(); defer { lock.unlock() }; return items.popLast() }
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

    func loadedNames() -> [String] {
        lock.lock(); defer { lock.unlock() }
        return Array(indexes.keys)
    }
}
