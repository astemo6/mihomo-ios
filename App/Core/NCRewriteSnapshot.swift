// App/Core/NCRewriteSnapshot.swift
// E-B1b stage 2: Port of rewritesnap.go + bodysnap.go + exportsnap.go + config.go (:280, :436) + resources.go to Swift.
//
// Sources:
//   - bridge/mitm/rewritesnap.go (RewriteSnapshot, SnapRule, SnapLocal, SnapFile, SnapHeaderOp, SnapHost, snapRule, snapMapLocal, snapFile)
//   - bridge/mitm/bodysnap.go (SnapBodyOp, SnapReplPart, SnapJSONOp, SnapJQStep, SnapJQCond, snapBody, snapBodyOp, icuFromRE2, snapJQ)
//   - bridge/mitm/exportsnap.go (ExportRewriteSnapshot)
//   - bridge/mitm/config.go (NewHostMatcher, splitHostPort, payloadFor, appendPayload)
//   - bridge/mitm/resources.go (NCResources: Get, cachePath, localPath, isRemote)
//   - bridge/mitm/ipglob.go (isIPv4Glob, ipv4GlobPrefixes, appendRangePrefixes)
//
// Snapshot Runtime Cache Note:
//   In Go (bridge/mitm/rewritesnap.go), the Engine maintains a runtime snapshot cache (snapCache, snapCaches,
//   RewriteSnapshotGen, snapState) to poll generations on live request flows and retain previous states across reloads.
//   In the native Go-free architecture, NativeRuntimePrep builds and exports the snapshot ahead of tunnel
//   start/reload in a single stateless pass with gen = 1. Consequently, runtime snapshot caching is omitted here.
//
// DIVERGENCES:
//   1. Pre-compiled Regexp Objects vs Pure Text Derivation:
//      - Go behavior: Go stores pre-compiled regexp2.Regexp (r.re, r.hre, op.re) and regexp.Regexp (r.fre, op.fast)
//        on Rule structs. snapRule passes these compiled objects to snapRegexOf and snapTemplate.
//      - Swift behavior: NCEngineRule carries only pattern strings. All patterns are compiled and translated on the
//        fly via NCRewriteICU.snapRegex and NCRewriteICU.snapTemplate. The re2 flag is auto-detected via isCompileURLRe
//        for URL patterns, and false for header gate/ops. The replace flag is true for redirects and header ops,
//        false for header gates and non-redirect URL matchers, exactly matching parse.go compilation paths.
//      - Impact: Produces identical regex portability verdicts and ICU translations without holding native regexp handles.
//
//   2. Engine Snapshot Cache Omission:
//      - Go behavior: Engine manages generation counters (snapGen atomic.Int64) and snapCache maps for live reloading.
//      - Swift behavior: NCRewriteSnapshotBuilder.export is stateless and exports snapshot with gen = 1 per invocation.
//      - Impact: No runtime cache overhead in the App process; generation is fixed to 1 as required by native runtime prep.
//
//   3. RE2 AST & ICU Translation for Body Rewrites:
//      - Go behavior: icuFromRE2 uses Go standard library regexp/syntax.Parse(p, syntax.Perl) to produce an AST,
//        which is re-emitted into an explicit ICU pattern with explicit \x{...} runes, sorted character classes,
//        simple-fold orbit classes, and anchored lookarounds.
//      - Swift behavior: Swift implements a dedicated RE2/Perl syntax parser and AST generator matching Go's syntax.Parse
//        semantics, unicode.SimpleFold orbit expansion (foldOrbit), and reNullable / reHasRepeatOrAlt rejections.
//      - Impact: Produces bit-for-bit identical ICU strings, capture counts, and bodyWhy rejection reasons on all rules.
//
//   4. jq (fix/nc-jq-full):
//      - The whole filter text (inline, or read from a jq-path= / Egern filter URL through NCResources) is checked with
//        the native interpreter (NativeJQ.compile) and exported as `jqx`; the tunnel runs it with NativeJQ. A filter
//        that does not compile is exported non-portable (bodyWhy "jq: <reason>") and logged as a warning; its bodies
//        pass through. The legacy step-list parser below (snapJQ) is kept only for old snapshots / fixtures.
//
//   5. Remote Map Local & Script Resource Management (NCResources):
//      - Go behavior: Resources downloads remote scripts/resources using Go net/http through the core client,
//        caching files in <home>/engine/cache/<sha1>.
//      - Swift behavior: NCResources performs synchronous downloads using URLSession during the detached background
//        preparation pass, writing atomically to <home>/engine/cache/<sha1>. If download fails and no cached copy
//        exists, it throws or returns nil, degrading as Go does when resources are unavailable.
//      - Impact: Static and remote resources are pre-cached on disk so the native tunnel can read them locally.

import Foundation
import CommonCrypto

// MARK: - Snapshot Models (PacketTunnel/NativeMitM/Rewrite/RewriteSnapshot.swift alignment)

/// NCSnapHeaderOp is one header operation. JSON keys align with Go SnapHeaderOp and PacketTunnel RWSnapHeaderOp.
struct NCSnapHeaderOp: Codable, Equatable {
    var op: String
    var name: String?
    var value: String?
    var re: NCSnapRegex?
    var tp: NCSnapTemplate?
    var tperr: Bool?

    enum CodingKeys: String, CodingKey {
        case op, name, value, re, tp, tperr
    }

    init(
        op: String,
        name: String? = nil,
        value: String? = nil,
        re: NCSnapRegex? = nil,
        tp: NCSnapTemplate? = nil,
        tperr: Bool? = nil
    ) {
        self.op = op
        self.name = name
        self.value = value
        self.re = re
        self.tp = tp
        self.tperr = tperr
    }
}

/// NCSnapFile is a Map Local answer read from disk at request time.
/// JSON keys align with Go SnapFile and PacketTunnel RWSnapFile.
struct NCSnapFile: Codable, Equatable {
    var path: String
    var remote: Bool?
    var ctype: String?
    var maxAge: Int?
    var large: Int

    enum CodingKeys: String, CodingKey {
        case path, remote, ctype, maxAge, large
    }

    init(
        path: String,
        remote: Bool? = nil,
        ctype: String? = nil,
        maxAge: Int? = nil,
        large: Int
    ) {
        self.path = path
        self.remote = remote
        self.ctype = ctype
        self.maxAge = maxAge
        self.large = large
    }
}

/// NCSnapLocal is a Map Local answer. JSON keys align with Go SnapLocal and PacketTunnel RWSnapLocal.
struct NCSnapLocal: Codable, Equatable {
    var status: Int
    var headers: [[String]] = []
    var body: Data?
    var file: NCSnapFile?

    enum CodingKeys: String, CodingKey {
        case status, headers, body, file
    }

    init(status: Int, headers: [[String]] = [], body: Data? = nil, file: NCSnapFile? = nil) {
        self.status = status
        self.headers = headers
        self.body = body
        self.file = file
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        status = try container.decode(Int.self, forKey: .status)
        headers = try container.decodeIfPresent([[String]].self, forKey: .headers) ?? []
        body = try container.decodeIfPresent(Data.self, forKey: .body)
        file = try container.decodeIfPresent(NCSnapFile.self, forKey: .file)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(status, forKey: .status)
        try container.encode(headers, forKey: .headers)
        if let body = body {
            try container.encode(body, forKey: .body)
        } else {
            try container.encodeNil(forKey: .body)
        }
        try container.encodeIfPresent(file, forKey: .file)
    }
}

/// NCSnapScript names a script rule. JSON keys align with Go SnapScript and PacketTunnel RWSnapScript.
struct NCSnapScript: Codable, Equatable {
    var name: String
    var type: String
    var requiresBody: Bool?

    enum CodingKeys: String, CodingKey {
        case name, type, requiresBody
    }

    init(name: String, type: String, requiresBody: Bool? = nil) {
        self.name = name
        self.type = type
        self.requiresBody = requiresBody
    }
}

/// NCSnapHost is one MitM hostname pattern. JSON keys align with Go SnapHost and PacketTunnel RWSnapHost.
struct NCSnapHost: Codable, Equatable {
    var pat: String
    var port: Int?

    enum CodingKeys: String, CodingKey {
        case pat, port
    }

    init(pat: String, port: Int? = nil) {
        self.pat = pat
        self.port = port
    }
}

/// NCSnapReplPart is a literal run (g < 0) or a capture group index.
struct NCSnapReplPart: Codable, Equatable {
    var l: String?
    var g: Int

    enum CodingKeys: String, CodingKey {
        case l, g
    }

    init(l: String? = nil, g: Int) {
        self.l = l
        self.g = g
    }
}

/// NCSnapBodyOp is one regex body replacement operation.
struct NCSnapBodyOp: Codable, Equatable {
    var icu: String?
    var parts: [NCSnapReplPart]?
    var skip: Bool?
    /// lane regexp2 (Go-zero): the source of an op not spelled as explicit ICU — regexp2's path (p + raw repl) or,
    /// with re2, Go's RE2 fast path (p + parts). The tunnel translates it with RX2ICU (RWSnapBodyOp).
    var p: String?
    var repl: String?
    var re2: Bool?

    enum CodingKeys: String, CodingKey {
        case icu, parts, skip, p, repl, re2
    }

    init(icu: String? = nil, parts: [NCSnapReplPart]? = nil, skip: Bool? = nil, p: String? = nil, repl: String? = nil, re2: Bool? = nil) {
        self.icu = icu
        self.parts = parts
        self.skip = skip
        self.p = p
        self.repl = repl
        self.re2 = re2
    }
}

/// NCBodyJSONKey represents one JSON path component (string key or array index).
enum NCBodyJSONKey: Codable, Equatable {
    case key(String)
    case index(Int)

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let i = try? container.decode(Int.self) {
            self = .index(i)
        } else {
            self = .key(try container.decode(String.self))
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .key(let s):
            try container.encode(s)
        case .index(let i):
            try container.encode(i)
        }
    }
}

/// NCSnapJSONOp is one Loon JSON modification op.
struct NCSnapJSONOp: Codable, Equatable {
    var op: String
    var path: [NCBodyJSONKey] = []
    var v: String

    enum CodingKeys: String, CodingKey {
        case op, path, v
    }

    init(op: String, path: [NCBodyJSONKey] = [], v: String) {
        self.op = op
        self.path = path
        self.v = v
    }
}

/// NCSnapJQCond is a select() condition in a jq filter step.
final class NCSnapJQCond: Codable, Equatable {
    var k: String
    var a: NCSnapJQCond?
    var b: NCSnapJQCond?
    var p: [NCBodyJSONKey]?
    var v: String?
    var key: String?

    enum CodingKeys: String, CodingKey {
        case k, a, b, p, v, key
    }

    init(k: String, a: NCSnapJQCond? = nil, b: NCSnapJQCond? = nil, p: [NCBodyJSONKey]? = nil, v: String? = nil, key: String? = nil) {
        self.k = k
        self.a = a
        self.b = b
        self.p = (p?.isEmpty ?? true) ? nil : p
        self.v = (v?.isEmpty ?? true) ? nil : v
        self.key = (key?.isEmpty ?? true) ? nil : key
    }

    static func == (lhs: NCSnapJQCond, rhs: NCSnapJQCond) -> Bool {
        lhs.k == rhs.k && lhs.a == rhs.a && lhs.b == rhs.b && lhs.p == rhs.p && lhs.v == rhs.v && lhs.key == rhs.key
    }
}

/// NCSnapJQStep is one step of a jq pipeline.
struct NCSnapJQStep: Codable, Equatable {
    var op: String
    var path: [NCBodyJSONKey]?
    var paths: [[NCBodyJSONKey]]?
    var v: String?
    var cond: NCSnapJQCond?

    enum CodingKeys: String, CodingKey {
        case op, path, paths, v, cond
    }

    init(op: String, path: [NCBodyJSONKey]? = nil, paths: [[NCBodyJSONKey]]? = nil, v: String? = nil, cond: NCSnapJQCond? = nil) {
        self.op = op
        self.path = (path?.isEmpty ?? true) ? nil : path
        self.paths = (paths?.isEmpty ?? true) ? nil : paths
        self.v = (v?.isEmpty ?? true) ? nil : v
        self.cond = cond
    }
}

/// NCSnapRule is one rule of the Ruleset. JSON keys align with Go SnapRule and PacketTunnel RWSnapRule.
struct NCSnapRule: Codable, Equatable {
    var i: Int
    var kind: String
    var phase: String
    var re: NCSnapRegex?
    var hgate: Bool?
    var hre: NCSnapRegex?
    var action: String?
    var target: String?
    var targetOK: Bool?
    var tp: NCSnapTemplate?
    var tperr: Bool?
    var headers: [NCSnapHeaderOp]?
    var opsOK: Bool?
    var local: NCSnapLocal?
    var script: NCSnapScript?
    var body: [NCSnapBodyOp]?
    var jsonOps: [NCSnapJSONOp]?
    var jq: [NCSnapJQStep]?
    /// fix/nc-jq-full: the full jq filter text (run by NativeJQ in the tunnel)
    var jqx: String?
    var bodyOK: Bool?
    var bodyWhy: String?

    enum CodingKeys: String, CodingKey {
        case i, kind, phase, re, hgate, hre, action, target, targetOK, tp, tperr, headers, opsOK, local, script, body, jsonOps, jq, jqx, bodyOK, bodyWhy
    }

    init(
        i: Int,
        kind: String,
        phase: String,
        re: NCSnapRegex? = nil,
        hgate: Bool? = nil,
        hre: NCSnapRegex? = nil,
        action: String? = nil,
        target: String? = nil,
        targetOK: Bool? = nil,
        tp: NCSnapTemplate? = nil,
        tperr: Bool? = nil,
        headers: [NCSnapHeaderOp]? = nil,
        opsOK: Bool? = nil,
        local: NCSnapLocal? = nil,
        script: NCSnapScript? = nil,
        body: [NCSnapBodyOp]? = nil,
        jsonOps: [NCSnapJSONOp]? = nil,
        jq: [NCSnapJQStep]? = nil,
        bodyOK: Bool? = nil,
        bodyWhy: String? = nil
    ) {
        self.i = i
        self.kind = kind
        self.phase = phase
        self.re = re
        self.hgate = hgate
        self.hre = hre
        self.action = action
        self.target = target
        self.targetOK = targetOK
        self.tp = tp
        self.tperr = tperr
        self.headers = headers
        self.opsOK = opsOK
        self.local = local
        self.script = script
        self.body = body
        self.jsonOps = jsonOps
        self.jq = jq
        self.bodyOK = bodyOK
        self.bodyWhy = bodyWhy
    }
}

/// NCRewriteSnapshot is the full rewrite snapshot evaluated by the native rewrite engine.
struct NCRewriteSnapshot: Codable, Equatable {
    static let supportedVersion = 1

    var version: Int = 1
    var gen: Int64? = 1
    var on: Bool = false
    var capture: Bool = false
    var inc: [NCSnapHost] = []
    var exc: [NCSnapHost] = []
    var rules: [NCSnapRule] = []
    var total: Int = 0
    var portable: Int = 0

    enum CodingKeys: String, CodingKey {
        case version, gen, on, capture, inc, exc, rules, total, portable
    }

    init(
        version: Int = 1,
        gen: Int64? = 1,
        on: Bool = false,
        capture: Bool = false,
        inc: [NCSnapHost] = [],
        exc: [NCSnapHost] = [],
        rules: [NCSnapRule] = [],
        total: Int = 0,
        portable: Int = 0
    ) {
        self.version = version
        self.gen = gen
        self.on = on
        self.capture = capture
        self.inc = inc
        self.exc = exc
        self.rules = rules
        self.total = total
        self.portable = portable
    }
}

// MARK: - Resources Manager (bridge/mitm/resources.go)

final class NCResources {
    let home: String
    private var memCache: [String: (data: Data, time: Date)] = [:]
    private let lock = NSLock()

    static let memCacheMax = 512 << 10
    static let maxResourceBytes = 8 << 20

    /// fix/nc-open-6-10 #8: request timeout of a download. 30 s for the debug / workbench callers; the runtime
    /// prepare (VPN start / reload) sets a shorter one — it blocks the connect.
    var fetchTimeout: TimeInterval = 30
    /// fix/nc-open-6-10 #8: URLs that already failed in this instance are not downloaded again (the same remote
    /// script is often referenced by several rules: a dead URL cost one full timeout per rule, sequentially).
    private var failed: [String: Error] = [:]
    /// Counters for the prepare timing line.
    private(set) var fetchedCount = 0
    private(set) var failedCount = 0
    private(set) var skippedRecentFailure = 0

    /// fix/nc-open-6-10 #8: cross-prepare negative cache — a remote resource whose download failed (other than
    /// "offline") is not retried by another prepare for `failureTTL`; its rules report the error as before. File
    /// `<home>/engine/cache/.fetch-failures.json` {url: unix time}, ≤ 256 entries; NativeRuntimePrepCache ignores it.
    static let failureFile = "engine/cache/.fetch-failures.json"
    static let failureTTL: TimeInterval = 600
    private var recentFailures: [String: Double]? = nil

    init(home: String) {
        self.home = home
    }

    private func failurePath() -> String { (home as NSString).appendingPathComponent(Self.failureFile) }

    /// Call with `lock` held.
    private func loadFailuresLocked() -> [String: Double] {
        if let r = recentFailures { return r }
        var m: [String: Double] = [:]
        if let d = FileManager.default.contents(atPath: failurePath()),
           let o = try? JSONDecoder().decode([String: Double].self, from: d) {
            let now = Date().timeIntervalSince1970
            m = o.filter { now - $0.value < Self.failureTTL && $0.value <= now + 60 }
        }
        recentFailures = m
        return m
    }

    private func recordFailure(_ url: String, _ err: Error) {
        let ns = err as NSError
        // Offline / no route: the next prepare may well have network — never cache those.
        if ns.domain == NSURLErrorDomain, [NSURLErrorNotConnectedToInternet, NSURLErrorNetworkConnectionLost,
                                           NSURLErrorDataNotAllowed, NSURLErrorInternationalRoamingOff,
                                           NSURLErrorCancelled].contains(ns.code) { return }
        lock.lock()
        var m = loadFailuresLocked()
        m[url] = Date().timeIntervalSince1970
        if m.count > 256 { for k in m.sorted(by: { $0.value < $1.value }).prefix(m.count - 256).map({ $0.key }) { m.removeValue(forKey: k) } }
        recentFailures = m
        lock.unlock()
        persistFailures(m)
    }

    private func clearFailure(_ url: String) {
        lock.lock()
        var m = loadFailuresLocked()
        let had = m.removeValue(forKey: url) != nil
        recentFailures = m
        lock.unlock()
        if had { persistFailures(m) }
    }

    private func persistFailures(_ m: [String: Double]) {
        let p = failurePath()
        if m.isEmpty { unlink(p); return }
        guard let d = try? JSONEncoder().encode(m) else { return }
        try? FileManager.default.createDirectory(atPath: (p as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try? d.write(to: URL(fileURLWithPath: p), options: .atomic)
    }

    /// fix/nc-open-6-10 #8: download every distinct remote resource in `paths` that has no cached copy yet, up to
    /// `maxConcurrent` at once (was: one at a time, inside the sequential manifest / snapshot build). Returns once
    /// all finished or `deadline` passed (stragglers keep running and land in the cache for the next prepare; the
    /// build then reads whatever is cached and fetches nothing it already saw fail).
    func prefetch(_ paths: [String], maxConcurrent: Int = 6, deadline: TimeInterval = 15) {
        var seen = Set<String>()
        var todo: [String] = []
        for p in paths where Self.isRemote(p) && seen.insert(p).inserted {
            if FileManager.default.fileExists(atPath: cachePath(p)) { continue }
            lock.lock(); let known = memCache[p] != nil || failed[p] != nil; lock.unlock()
            if !known { todo.append(p) }
        }
        guard !todo.isEmpty else { return }
        let group = DispatchGroup()
        let gate = DispatchSemaphore(value: max(1, maxConcurrent))
        let q = DispatchQueue(label: "nc.prep.prefetch", attributes: .concurrent)
        for u in todo {
            group.enter()
            q.async {
                gate.wait()
                defer { gate.signal(); group.leave() }
                _ = try? self.fetch(u)
            }
        }
        _ = group.wait(timeout: .now() + deadline)
    }

    static func isRemote(_ p: String) -> Bool {
        p.hasPrefix("http://") || p.hasPrefix("https://")
    }

    static func cachePath(home: String, _ u: String) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        let bytes = Array(u.utf8)
        CC_SHA1(bytes, CC_LONG(bytes.count), &digest)
        let hex = digest.ncHex
        return ((home as NSString).appendingPathComponent("engine/cache") as NSString).appendingPathComponent(hex)
    }

    func cachePath(_ u: String) -> String {
        Self.cachePath(home: home, u)
    }

    func localPath(_ p: String) -> String {
        var path = p
        if path.hasPrefix("file://") {
            path = String(path.dropFirst("file://".count))
        }
        if (path as NSString).isAbsolutePath {
            return path
        }
        let cleanP = ("/" + path as NSString).standardizingPath
        return ((home as NSString).appendingPathComponent("engine/scripts") as NSString).appendingPathComponent(cleanP)
    }

    func get(path: String, maxAge: Int = 0) throws -> Data {
        if !Self.isRemote(path) {
            let fullPath = localPath(path)
            return try Data(contentsOf: URL(fileURLWithPath: fullPath))
        }
        lock.lock()
        if let entry = memCache[path] {
            lock.unlock()
            refreshIfStale(path: path, maxAge: maxAge)
            return entry.data
        }
        lock.unlock()

        let cp = cachePath(path)
        let fm = FileManager.default
        if fm.fileExists(atPath: cp),
           let attrs = try? fm.attributesOfItem(atPath: cp),
           let mtime = attrs[.modificationDate] as? Date,
           let data = try? Data(contentsOf: URL(fileURLWithPath: cp)) {
            if maxAge > 0 && Date().timeIntervalSince(mtime) > Double(maxAge) {
                refreshIfStale(path: path, maxAge: maxAge)
            }
            if data.count < Self.memCacheMax {
                lock.lock()
                memCache[path] = (data, Date())
                lock.unlock()
            }
            return data
        }
        return try fetch(path)
    }

    private func refreshIfStale(path: String, maxAge: Int) {
        guard maxAge > 0 else { return }
        let cp = cachePath(path)
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: cp),
              let mtime = attrs[.modificationDate] as? Date else { return }
        if Date().timeIntervalSince(mtime) > Double(maxAge) {
            DispatchQueue.global(qos: .utility).async { [weak self] in
                _ = try? self?.fetch(path)
            }
        }
    }

    func fetch(_ urlString: String) throws -> Data {
        guard let url = URL(string: urlString) else {
            throw NSError(domain: "NCResources", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid URL: \(urlString)"])
        }
        lock.lock()
        if let e = failed[urlString] { lock.unlock(); throw e }
        let recent = loadFailuresLocked()[urlString]
        lock.unlock()
        if let t = recent {
            let mins = max(1, Int((Self.failureTTL - (Date().timeIntervalSince1970 - t)) / 60))
            let e = NSError(domain: "NCResources", code: -2, userInfo: [NSLocalizedDescriptionKey: "最近下载失败，\(mins) 分钟内不重试"])
            lock.lock(); failed[urlString] = e; skippedRecentFailure += 1; lock.unlock()
            throw e
        }
        var req = URLRequest(url: url, timeoutInterval: fetchTimeout)
        req.setValue("Surge iOS/3000 Mihomo-iOS", forHTTPHeaderField: "User-Agent")
        var resultData: Data?
        var resultError: Error?
        let sem = DispatchSemaphore(value: 0)
        let task = URLSession.shared.dataTask(with: req) { data, resp, err in
            if let err = err {
                resultError = err
            } else if let http = resp as? HTTPURLResponse, http.statusCode != 200 {
                resultError = NSError(domain: "NCResources", code: http.statusCode, userInfo: [NSLocalizedDescriptionKey: "HTTP \(http.statusCode)"])
            } else if let data = data {
                if data.count > Self.maxResourceBytes {
                    resultError = NSError(domain: "NCResources", code: -1, userInfo: [NSLocalizedDescriptionKey: "Resource exceeds 8 MB"])
                } else {
                    resultData = data
                }
            }
            sem.signal()
        }
        task.resume()
        sem.wait()

        if let data = resultData {
            let cp = cachePath(urlString)
            let dir = (cp as NSString).deletingLastPathComponent
            try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            try? data.write(to: URL(fileURLWithPath: cp), options: .atomic)
            lock.lock()
            if data.count < Self.memCacheMax { memCache[urlString] = (data, Date()) }
            fetchedCount += 1
            lock.unlock()
            clearFailure(urlString)
            return data
        }
        let err = resultError ?? NSError(domain: "NCResources", code: -1, userInfo: [NSLocalizedDescriptionKey: "Download failed: \(urlString)"])
        lock.lock(); failed[urlString] = err; failedCount += 1; lock.unlock()
        recordFailure(urlString, err)
        throw err
    }
}

// MARK: - Host Matcher & SnapHost Payload (bridge/mitm/config.go:280, 436)

struct NCHostPat: Equatable {
    var pat: String
    var port: Int
}

final class NCHostMatcher {
    var inc: [NCHostPat] = []
    var exc: [NCHostPat] = []

    init() {}

    static func splitHostPort(_ h: String) -> (String, Int) {
        if let idx = h.lastIndex(of: ":"), idx > h.startIndex {
            let hostPart = String(h[..<idx])
            if !hostPart.contains(":") {
                let portPart = String(h[h.index(after: idx)...])
                if let p = Int(portPart), p > 0 {
                    return (hostPart, p)
                }
            }
        }
        return (h, 0)
    }

    static func build(_ list: [String]) -> NCHostMatcher {
        let m = NCHostMatcher()
        for raw in list {
            var h = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if h.isEmpty { continue }
            let ex = h.hasPrefix("-")
            if ex {
                h = String(h.dropFirst())
            }
            let (host, port) = splitHostPort(h)
            let p = NCHostPat(pat: host, port: port)
            if ex {
                m.exc.append(p)
            } else {
                m.inc.append(p)
            }
        }
        return m
    }

    static func payloadFor(_ p: NCHostPat) -> [String] {
        if let ip = NCIP(p.pat) {
            switch ip {
            case .v4:
                return ["IP-CIDR,\(p.pat)/32,no-resolve"]
            case .v6:
                return ["IP-CIDR6,\(p.pat)/128,no-resolve"]
            }
        }
        if let prefixes = ipv4GlobPrefixes(p.pat) {
            return prefixes.map { "IP-CIDR,\($0),no-resolve" }
        }
        if p.pat.contains("*") || p.pat.contains("?") {
            return ["DOMAIN-WILDCARD,\(p.pat)"]
        }
        return ["DOMAIN,\(p.pat)"]
    }

    // MARK: - IPv4 Glob Prefix Expansion (bridge/mitm/ipglob.go)

    static let ipGlobMaxPrefixes = 1024

    static func isIPv4Glob(_ p: String) -> Bool {
        guard p.contains("*") || p.contains("?") else { return false }
        guard p.rangeOfCharacter(from: CharacterSet.decimalDigits) != nil else { return false }
        for c in p.utf8 {
            if !((c >= UInt8(ascii: "0") && c <= UInt8(ascii: "9")) || c == UInt8(ascii: ".") || c == UInt8(ascii: "*") || c == UInt8(ascii: "?")) {
                return false
            }
        }
        return true
    }

    static func ipv4GlobPrefixes(_ pat: String) -> [String]? {
        guard isIPv4Glob(pat) else { return nil }
        let patBytes = Array(pat.utf8)
        var memo: [String: Int8] = [:]

        func closure(_ inStates: [Int]) -> [Int] {
            var seen = Set<Int>()
            var out: [Int] = []
            func add(_ p: Int) {
                if seen.contains(p) { return }
                seen.insert(p)
                out.append(p)
                if p < patBytes.count && patBytes[p] == UInt8(ascii: "*") {
                    add(p + 1)
                }
            }
            for p in inStates {
                add(p)
            }
            out.sort()
            return out
        }

        func step(_ s: [Int], _ c: UInt8) -> [Int] {
            var next: [Int] = []
            for p in s {
                if p >= patBytes.count { continue }
                let ch = patBytes[p]
                if ch == UInt8(ascii: "*") {
                    next.append(p)
                } else if ch == UInt8(ascii: "?") {
                    next.append(p + 1)
                } else if ch == c {
                    next.append(p + 1)
                }
            }
            if next.isEmpty { return [] }
            return closure(next)
        }

        func feed(_ s: [Int], _ octet: Int, _ first: Bool) -> [Int] {
            var cur = s
            if !first {
                cur = step(cur, UInt8(ascii: "."))
            }
            let octetStr = String(octet)
            for b in octetStr.utf8 {
                if cur.isEmpty { return [] }
                cur = step(cur, b)
            }
            return cur
        }

        func accepts(_ s: [Int]) -> Bool {
            s.contains(patBytes.count)
        }

        func classDepth(_ s: [Int], _ depth: Int) -> Int8 {
            if s.isEmpty { return 0 }
            if depth == 4 {
                return accepts(s) ? 1 : 0
            }
            let k = s.map(String.init).joined(separator: ",") + "|" + String(depth)
            if let v = memo[k] { return v }
            var full = true
            var empty = true
            for v in 0..<256 {
                let r = classDepth(feed(s, v, depth == 0), depth + 1)
                if r == 0 { full = false }
                else if r == 1 { empty = false }
                else { full = false; empty = false }
            }
            var res: Int8 = 2
            if full { res = 1 }
            else if empty { res = 0 }
            memo[k] = res
            return res
        }

        var ranges: [(lo: UInt32, hi: UInt32)] = []
        func walk(_ s: [Int], _ depth: Int, _ base: UInt32) -> Bool {
            let cls = classDepth(s, depth)
            if cls == 0 { return true }
            if cls == 1 {
                let size = UInt32(1) << (8 * (4 - depth))
                if depth == 0 {
                    ranges.append((0, ~UInt32(0)))
                    return true
                }
                if let last = ranges.last, last.hi &+ 1 == base {
                    ranges[ranges.count - 1] = (last.lo, base &+ size &- 1)
                } else {
                    ranges.append((base, base &+ size &- 1))
                }
                return ranges.count <= ipGlobMaxPrefixes
            }
            let shift = 8 * (3 - depth)
            for v in 0..<256 {
                if !walk(feed(s, v, depth == 0), depth + 1, base | (UInt32(v) << shift)) {
                    return false
                }
            }
            return true
        }

        let start = closure([0])
        guard walk(start, 0, 0), !ranges.isEmpty else { return nil }

        func appendRangePrefixes(_ loIn: UInt32, _ hi: UInt32) -> [String] {
            var lo = UInt64(loIn)
            let hi64 = UInt64(hi)
            var out: [String] = []
            while true {
                var bits = 32
                while bits > 0 {
                    let size = UInt64(1) << (32 - (bits - 1))
                    if lo % size != 0 || lo + size - 1 > hi64 {
                        break
                    }
                    bits -= 1
                }
                let a = "\((lo >> 24) & 0xff).\((lo >> 16) & 0xff).\((lo >> 8) & 0xff).\(lo & 0xff)"
                out.append("\(a)/\(bits)")
                let next = lo + (UInt64(1) << (32 - bits))
                if next > hi64 {
                    return out
                }
                lo = next
            }
        }

        var out: [String] = []
        for r in ranges {
            out.append(contentsOf: appendRangePrefixes(r.lo, r.hi))
            if out.count > ipGlobMaxPrefixes { return nil }
        }
        return out
    }
}

// MARK: - Map Local & Header Ops Constants & Helpers (bridge/mitm/rewritesnap.go)

private let snapLocalMax = 64 << 10
private let memCacheMax = 512 << 10
private let tinyGIF = Data([
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x01, 0x44, 0x00, 0x3b
])

private func snapExtKnown(_ p: String) -> Bool {
    var p = p
    if let idx = p.firstIndex(where: { $0 == "?" || $0 == "#" }) {
        p = String(p[..<idx])
    }
    let ext = (p as NSString).pathExtension.lowercased()
    switch ext {
    case "json", "html", "htm", "js", "gif", "png", "jpg", "jpeg", "txt":
        return true
    default:
        return false
    }
}

private func guessType(_ p: String, _ b: Data?) -> String {
    var p = p
    if let idx = p.firstIndex(where: { $0 == "?" || $0 == "#" }) {
        p = String(p[..<idx])
    }
    let ext = (p as NSString).pathExtension.lowercased()
    switch ext {
    case "json":
        return "application/json"
    case "html", "htm":
        return "text/html; charset=utf-8"
    case "js":
        return "application/javascript"
    case "gif":
        return "image/gif"
    case "png":
        return "image/png"
    case "jpg", "jpeg":
        return "image/jpeg"
    case "txt":
        return "text/plain; charset=utf-8"
    default:
        return "application/octet-stream"
    }
}

private func guessTextType(_ s: String) -> String {
    let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
    if t.hasPrefix("{") || t.hasPrefix("[") {
        return "application/json"
    }
    if t.hasPrefix("<") {
        return "text/html; charset=utf-8"
    }
    return "text/plain; charset=utf-8"
}

private func isTokenByte(_ c: UInt8) -> Bool {
    switch c {
    case UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "0")...UInt8(ascii: "9"):
        return true
    case UInt8(ascii: "!"), UInt8(ascii: "#"), UInt8(ascii: "$"), UInt8(ascii: "%"), UInt8(ascii: "&"), UInt8(ascii: "'"),
         UInt8(ascii: "*"), UInt8(ascii: "+"), UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: "^"), UInt8(ascii: "_"),
         UInt8(ascii: "`"), UInt8(ascii: "|"), UInt8(ascii: "~"):
        return true
    default:
        return false
    }
}

private func canonicalHeaderKey(_ s: String) -> String {
    let b = Array(s.utf8)
    for c in b where !isTokenByte(c) { return s }
    var out = [UInt8]()
    out.reserveCapacity(b.count)
    var upper = true
    for var c in b {
        if upper && c >= 0x61 && c <= 0x7A { c -= 32 }
        else if !upper && c >= 0x41 && c <= 0x5A { c += 32 }
        out.append(c)
        upper = c == UInt8(ascii: "-")
    }
    return String(decoding: out, as: UTF8.self)
}

private func unescapeCRLF(_ s: String) -> String {
    s.replacingOccurrences(of: "\\r", with: "\r").replacingOccurrences(of: "\\n", with: "\n")
}

private func snapFile(r: NCEngineRule, home: String, res: NCResources) -> NCSnapFile? {
    if r.dataType != "" && r.dataType != "file" {
        return nil
    }
    var remote: Bool? = nil
    var maxAge: Int? = nil
    let filePath: String
    if NCResources.isRemote(r.data) {
        filePath = NCResources.cachePath(home: home, r.data)
        remote = true
        maxAge = 86400
        _ = try? res.get(path: r.data, maxAge: 86400)
    } else {
        filePath = res.localPath(r.data)
    }
    var ctype: String? = nil
    let guessed = guessType(r.data, nil)
    if guessed != "application/octet-stream" || snapExtKnown(r.data) {
        ctype = guessed
    }
    return NCSnapFile(
        path: filePath,
        remote: remote,
        ctype: ctype,
        maxAge: maxAge,
        large: memCacheMax
    )
}

private func snapMapLocal(r: NCEngineRule, home: String, res: NCResources) -> NCSnapLocal? {
    var body: Data?
    var ctype = ""
    var file: NCSnapFile?
    switch r.dataType {
    case "tiny-gif":
        body = tinyGIF
        ctype = "image/gif"
    case "base64":
        guard let b = Data(base64Encoded: r.data) else {
            return nil
        }
        body = b
        ctype = "application/octet-stream"
    case "text":
        body = Data(r.data.utf8)
        ctype = guessTextType(r.data)
    case "json":
        body = Data(r.data.utf8)
        ctype = "application/json"
    default:
        if r.data.isEmpty {
            ctype = "text/plain"
            break
        }
        file = snapFile(r: r, home: home, res: res)
        if file == nil {
            return nil
        }
    }
    if let b = body, b.count > snapLocalMax {
        return nil
    }
    var hMap: [String: String] = [:]
    var seen = Set<String>()
    for (k, v) in r.respHeaders {
        let ck = canonicalHeaderKey(k)
        if seen.contains(ck) {
            return nil
        }
        seen.insert(ck)
        hMap[ck] = v
    }
    if file == nil && hMap["Content-Type"] == nil && !ctype.isEmpty {
        hMap["Content-Type"] = ctype
    }
    var st = r.status
    if st == 0 {
        st = 200
    }
    if st < 100 || st > 999 {
        return nil
    }
    let headers = hMap.keys.sorted(by: { $0.utf8.lexicographicallyPrecedes($1.utf8) }).map { k in
        [k, hMap[k]!]
    }
    return NCSnapLocal(status: st, headers: headers, body: body, file: file)
}

// MARK: - Bodysnap RE2/ICU/Repl/JQ (bridge/mitm/bodysnap.go)

private func foldOrbit(_ r: UnicodeScalar) -> [UnicodeScalar] {
    let val = r.value
    switch val {
    case 0x4b, 0x6b, 0x212a:
        return [UnicodeScalar(0x4b)!, UnicodeScalar(0x6b)!, UnicodeScalar(0x212a)!]
    case 0x53, 0x73, 0x17f:
        return [UnicodeScalar(0x53)!, UnicodeScalar(0x73)!, UnicodeScalar(0x17f)!]
    case 0xb5, 0x39c, 0x3bc:
        return [UnicodeScalar(0xb5)!, UnicodeScalar(0x39c)!, UnicodeScalar(0x3bc)!]
    case 0xc5, 0xe5, 0x212b:
        return [UnicodeScalar(0xc5)!, UnicodeScalar(0xe5)!, UnicodeScalar(0x212b)!]
    case 0x1c4, 0x1c5, 0x1c6:
        return [UnicodeScalar(0x1c4)!, UnicodeScalar(0x1c5)!, UnicodeScalar(0x1c6)!]
    case 0x1c7, 0x1c8, 0x1c9:
        return [UnicodeScalar(0x1c7)!, UnicodeScalar(0x1c8)!, UnicodeScalar(0x1c9)!]
    case 0x1ca, 0x1cb, 0x1cc:
        return [UnicodeScalar(0x1ca)!, UnicodeScalar(0x1cb)!, UnicodeScalar(0x1cc)!]
    case 0x1f1, 0x1f2, 0x1f3:
        return [UnicodeScalar(0x1f1)!, UnicodeScalar(0x1f2)!, UnicodeScalar(0x1f3)!]
    case 0x345, 0x399, 0x3b9, 0x1fbe:
        return [UnicodeScalar(0x345)!, UnicodeScalar(0x399)!, UnicodeScalar(0x3b9)!, UnicodeScalar(0x1fbe)!]
    case 0x392, 0x3b2, 0x3d0:
        return [UnicodeScalar(0x392)!, UnicodeScalar(0x3b2)!, UnicodeScalar(0x3d0)!]
    case 0x395, 0x3b5, 0x3f5:
        return [UnicodeScalar(0x395)!, UnicodeScalar(0x3b5)!, UnicodeScalar(0x3f5)!]
    case 0x398, 0x3b8, 0x3d1, 0x3f4:
        return [UnicodeScalar(0x398)!, UnicodeScalar(0x3b8)!, UnicodeScalar(0x3d1)!, UnicodeScalar(0x3f4)!]
    case 0x39a, 0x3ba, 0x3f0:
        return [UnicodeScalar(0x39a)!, UnicodeScalar(0x3ba)!, UnicodeScalar(0x3f0)!]
    case 0x3a0, 0x3c0, 0x3d6:
        return [UnicodeScalar(0x3a0)!, UnicodeScalar(0x3c0)!, UnicodeScalar(0x3d6)!]
    case 0x3a1, 0x3c1, 0x3f1:
        return [UnicodeScalar(0x3a1)!, UnicodeScalar(0x3c1)!, UnicodeScalar(0x3f1)!]
    case 0x3a3, 0x3c2, 0x3c3:
        return [UnicodeScalar(0x3a3)!, UnicodeScalar(0x3c2)!, UnicodeScalar(0x3c3)!]
    case 0x3a6, 0x3c6, 0x3d5:
        return [UnicodeScalar(0x3a6)!, UnicodeScalar(0x3c6)!, UnicodeScalar(0x3d5)!]
    case 0x3a9, 0x3c9, 0x2126:
        return [UnicodeScalar(0x3a9)!, UnicodeScalar(0x3c9)!, UnicodeScalar(0x2126)!]
    case 0x412, 0x432, 0x1c80:
        return [UnicodeScalar(0x412)!, UnicodeScalar(0x432)!, UnicodeScalar(0x1c80)!]
    case 0x414, 0x434, 0x1c81:
        return [UnicodeScalar(0x414)!, UnicodeScalar(0x434)!, UnicodeScalar(0x1c81)!]
    case 0x41e, 0x43e, 0x1c82:
        return [UnicodeScalar(0x41e)!, UnicodeScalar(0x43e)!, UnicodeScalar(0x1c82)!]
    case 0x421, 0x441, 0x1c83:
        return [UnicodeScalar(0x421)!, UnicodeScalar(0x441)!, UnicodeScalar(0x1c83)!]
    case 0x422, 0x442, 0x1c84, 0x1c85:
        return [UnicodeScalar(0x422)!, UnicodeScalar(0x442)!, UnicodeScalar(0x1c84)!, UnicodeScalar(0x1c85)!]
    case 0x42a, 0x44a, 0x1c86:
        return [UnicodeScalar(0x42a)!, UnicodeScalar(0x44a)!, UnicodeScalar(0x1c86)!]
    case 0x462, 0x463, 0x1c87:
        return [UnicodeScalar(0x462)!, UnicodeScalar(0x463)!, UnicodeScalar(0x1c87)!]
    case 0x1c88, 0xa64a, 0xa64b:
        return [UnicodeScalar(0x1c88)!, UnicodeScalar(0xa64a)!, UnicodeScalar(0xa64b)!]
    case 0x1e60, 0x1e61, 0x1e9b:
        return [UnicodeScalar(0x1e60)!, UnicodeScalar(0x1e61)!, UnicodeScalar(0x1e9b)!]
    case 0xdf, 0x1e9e:
        return [UnicodeScalar(0xdf)!, UnicodeScalar(0x1e9e)!]
    default:
        let s = String(Character(r))
        let up = s.uppercased()
        let low = s.lowercased()
        if up == low {
            return [r]
        }
        var set = Set<UnicodeScalar>()
        set.insert(r)
        if up.count == 1, let u = up.unicodeScalars.first { set.insert(u) }
        if low.count == 1, let l = low.unicodeScalars.first { set.insert(l) }
        return Array(set).sorted(by: { $0.value < $1.value })
    }
}

private func icuRune(_ b: inout String, _ r: UnicodeScalar) {
    b.append(String(format: "\\x{%x}", r.value))
}

private func icuClass(_ b: inout String, _ ranges: [(lo: UnicodeScalar, hi: UnicodeScalar)]) {
    if ranges.isEmpty {
        b.append("(?!)")
        return
    }
    b.append("[")
    for r in ranges {
        icuRune(&b, r.lo)
        if r.lo != r.hi {
            b.append("-")
            icuRune(&b, r.hi)
        }
    }
    b.append("]")
}

private func compileFastRe(_ p: String) -> Bool {
    var esc = false
    for c in p {
        if esc {
            if c == "b" || c == "B" {
                return false
            }
            esc = false
            continue
        }
        if c == "\\" {
            esc = true
            continue
        }
        if c == "$" {
            return false
        }
    }
    guard (try? NSRegularExpression(pattern: p, options: [])) != nil else {
        return false
    }
    return true
}

// MARK: - RE2 AST and ICU Generator (bodysnap.go icuFromRE2)

private indirect enum RE2AST {
    case noMatch
    case emptyMatch
    case literal([UnicodeScalar], Bool) // scalars, foldCase
    case charClass([(lo: UnicodeScalar, hi: UnicodeScalar)]) // positive ranges
    case anyCharNotNL
    case anyChar
    case beginLine(Bool) // multiline
    case endLine(Bool) // multiline
    case wordBoundary
    case noWordBoundary
    case capture(Int, RE2AST) // group index, sub
    case star(RE2AST, Bool) // sub, nonGreedy
    case plus(RE2AST, Bool) // sub, nonGreedy
    case quest(RE2AST, Bool) // sub, nonGreedy
    case repeatCount(RE2AST, Int, Int, Bool) // sub, min, max, nonGreedy
    case concat([RE2AST])
    case alternate([RE2AST])
}

private func reNullable(_ ast: RE2AST) -> Bool {
    switch ast {
    case .noMatch, .charClass, .anyCharNotNL, .anyChar:
        return false
    case .literal(let runes, _):
        return runes.isEmpty
    case .emptyMatch, .beginLine, .endLine, .wordBoundary, .noWordBoundary, .star, .quest:
        return true
    case .capture(_, let sub), .plus(let sub, _):
        return reNullable(sub)
    case .repeatCount(let sub, let min, _, _):
        return min == 0 || reNullable(sub)
    case .concat(let subs):
        for s in subs {
            if !reNullable(s) { return false }
        }
        return true
    case .alternate(let subs):
        for s in subs {
            if reNullable(s) { return true }
        }
        return false
    }
}

private func reHasRepeatOrAlt(_ ast: RE2AST) -> Bool {
    switch ast {
    case .star, .plus, .quest, .repeatCount, .alternate:
        return true
    case .capture(_, let sub):
        return reHasRepeatOrAlt(sub)
    case .concat(let subs):
        return subs.contains(where: reHasRepeatOrAlt)
    default:
        return false
    }
}

private func emitICU(_ b: inout String, _ ast: RE2AST) -> String {
    switch ast {
    case .noMatch:
        b.append("(?!)")
    case .emptyMatch:
        b.append("(?:)")
    case .literal(let runes, let fold):
        for r in runes {
            if fold {
                let orbit = foldOrbit(r)
                if orbit.count > 1 {
                    let ranges = orbit.map { (lo: $0, hi: $0) }
                    icuClass(&b, ranges)
                    continue
                }
            }
            icuRune(&b, r)
        }
    case .charClass(let ranges):
        icuClass(&b, ranges)
    case .anyCharNotNL:
        b.append("[\\x{0}-\\x{9}\\x{b}-\\x{10ffff}]")
    case .anyChar:
        b.append("[\\x{0}-\\x{10ffff}]")
    case .beginLine(let multiline):
        if multiline {
            b.append("(?:(?<![\\x{0}-\\x{10ffff}])|(?<=\\x{a}))")
        } else {
            b.append("(?<![\\x{0}-\\x{10ffff}])")
        }
    case .endLine(let multiline):
        if multiline {
            b.append("(?=\\x{a}|(?![\\x{0}-\\x{10ffff}]))")
        } else {
            b.append("(?![\\x{0}-\\x{10ffff}])")
        }
    case .wordBoundary, .noWordBoundary:
        return "word boundary"
    case .capture(_, let sub):
        b.append("(")
        let w = emitICU(&b, sub)
        if !w.isEmpty { return w }
        b.append(")")
    case .star(let sub, let nonGreedy):
        if reNullable(sub) { return "repeat of nullable" }
        if reHasRepeatOrAlt(sub) { return "nested repeat" }
        b.append("(?:")
        let w = emitICU(&b, sub)
        if !w.isEmpty { return w }
        b.append(")*")
        if nonGreedy { b.append("?") }
    case .plus(let sub, let nonGreedy):
        if reNullable(sub) { return "repeat of nullable" }
        if reHasRepeatOrAlt(sub) { return "nested repeat" }
        b.append("(?:")
        let w = emitICU(&b, sub)
        if !w.isEmpty { return w }
        b.append(")+")
        if nonGreedy { b.append("?") }
    case .quest(let sub, let nonGreedy):
        if reNullable(sub) { return "repeat of nullable" }
        b.append("(?:")
        let w = emitICU(&b, sub)
        if !w.isEmpty { return w }
        b.append(")?")
        if nonGreedy { b.append("?") }
    case .repeatCount(let sub, let min, let max, let nonGreedy):
        if reNullable(sub) { return "repeat of nullable" }
        let unbounded = max < 0
        if unbounded && reHasRepeatOrAlt(sub) { return "nested repeat" }
        if min > 1000 || max > 1000 { return "repeat count" }
        b.append("(?:")
        let w = emitICU(&b, sub)
        if !w.isEmpty { return w }
        b.append(")")
        if max < 0 {
            b.append("{\(min),}")
        } else if min == max {
            b.append("{\(min)}")
        } else {
            b.append("{\(min),\(max)}")
        }
        if nonGreedy { b.append("?") }
    case .concat(let subs):
        for s in subs {
            let w = emitICU(&b, s)
            if !w.isEmpty { return w }
        }
    case .alternate(let subs):
        b.append("(?:")
        for (i, s) in subs.enumerated() {
            if i > 0 { b.append("|") }
            let w = emitICU(&b, s)
            if !w.isEmpty { return w }
        }
        b.append(")")
    }
    return ""
}

private final class RE2Parser {
    let scalars: [UnicodeScalar]
    var pos = 0
    var captureIndex = 0
    var foldCase = false
    var multiline = false
    var dotMatchesAll = false

    init(pattern: String) {
        self.scalars = Array(pattern.unicodeScalars)
    }

    func parse() -> (RE2AST?, String) {
        let (ast, why) = parseAlternate()
        if !why.isEmpty { return (nil, why) }
        guard pos == scalars.count else {
            return (nil, "re2 parse")
        }
        return (ast, "")
    }

    private func peek() -> UnicodeScalar? {
        pos < scalars.count ? scalars[pos] : nil
    }

    private func advance() -> UnicodeScalar {
        let s = scalars[pos]
        pos += 1
        return s
    }

    private func parseAlternate() -> (RE2AST, String) {
        var branches: [RE2AST] = []
        while true {
            let (branch, why) = parseConcat()
            if !why.isEmpty { return (.emptyMatch, why) }
            branches.append(branch)
            if peek() == "|" {
                pos += 1
            } else {
                break
            }
        }
        if branches.count == 1 {
            return (branches[0], "")
        }
        return (.alternate(branches), "")
    }

    private func parseConcat() -> (RE2AST, String) {
        var subs: [RE2AST] = []
        while let ch = peek(), ch != "|" && ch != ")" {
            let (atom, why) = parsePiece()
            if !why.isEmpty { return (.emptyMatch, why) }
            subs.append(atom)
        }
        if subs.isEmpty {
            return (.emptyMatch, "")
        }
        if subs.count == 1 {
            return (subs[0], "")
        }
        return (.concat(subs), "")
    }

    private func parsePiece() -> (RE2AST, String) {
        let (atom, why) = parseAtom()
        if !why.isEmpty { return (.emptyMatch, why) }
        guard let ch = peek() else { return (atom, "") }

        var nonGreedy = false
        switch ch {
        case "*":
            pos += 1
            if peek() == "?" { pos += 1; nonGreedy = true }
            return (.star(atom, nonGreedy), "")
        case "+":
            pos += 1
            if peek() == "?" { pos += 1; nonGreedy = true }
            return (.plus(atom, nonGreedy), "")
        case "?":
            pos += 1
            if peek() == "?" { pos += 1; nonGreedy = true }
            return (.quest(atom, nonGreedy), "")
        case "{":
            let saved = pos
            pos += 1
            var minStr = ""
            while let d = peek(), d >= "0" && d <= "9" {
                minStr.append(Character(advance()))
            }
            if minStr.isEmpty {
                pos = saved
                return (atom, "")
            }
            let minVal = Int(minStr) ?? 0
            var maxVal = minVal
            if peek() == "," {
                pos += 1
                var maxStr = ""
                while let d = peek(), d >= "0" && d <= "9" {
                    maxStr.append(Character(advance()))
                }
                if maxStr.isEmpty {
                    maxVal = -1
                } else {
                    maxVal = Int(maxStr) ?? -1
                }
            }
            if peek() == "}" {
                pos += 1
                if peek() == "?" { pos += 1; nonGreedy = true }
                return (.repeatCount(atom, minVal, maxVal, nonGreedy), "")
            }
            pos = saved
            return (atom, "")
        default:
            return (atom, "")
        }
    }

    private func parseAtom() -> (RE2AST, String) {
        guard let ch = peek() else { return (.emptyMatch, "re2 parse") }

        if ch == "(" {
            pos += 1
            if peek() == "?" {
                pos += 1
                guard let opt = peek() else { return (.emptyMatch, "re2 parse") }
                if opt == ":" {
                    pos += 1
                    let (sub, why) = parseAlternate()
                    if !why.isEmpty { return (.emptyMatch, why) }
                    if peek() == ")" { pos += 1 } else { return (.emptyMatch, "re2 parse") }
                    return (sub, "")
                }
                if opt == "P" || opt == "<" {
                    while let c = peek(), c != ">" && c != ")" { pos += 1 }
                    if peek() == ">" { pos += 1 }
                    captureIndex += 1
                    let idx = captureIndex
                    let (sub, why) = parseAlternate()
                    if !why.isEmpty { return (.emptyMatch, why) }
                    if peek() == ")" { pos += 1 } else { return (.emptyMatch, "re2 parse") }
                    return (.capture(idx, sub), "")
                }
                // Inline flags (?i) (?m) (?s) or (?i:...)
                var neg = false
                while let f = peek(), f != ")" && f != ":" {
                    pos += 1
                    if f == "-" { neg = true; continue }
                    if f == "i" { foldCase = !neg }
                    if f == "m" { multiline = !neg }
                    if f == "s" { dotMatchesAll = !neg }
                }
                if peek() == ":" {
                    pos += 1
                    let (sub, why) = parseAlternate()
                    if !why.isEmpty { return (.emptyMatch, why) }
                    if peek() == ")" { pos += 1 } else { return (.emptyMatch, "re2 parse") }
                    return (sub, "")
                }
                if peek() == ")" {
                    pos += 1
                    return (.emptyMatch, "")
                }
                return (.emptyMatch, "re2 parse")
            }
            captureIndex += 1
            let idx = captureIndex
            let (sub, why) = parseAlternate()
            if !why.isEmpty { return (.emptyMatch, why) }
            if peek() == ")" { pos += 1 } else { return (.emptyMatch, "re2 parse") }
            return (.capture(idx, sub), "")
        }

        if ch == "[" {
            pos += 1
            var negated = false
            if peek() == "^" {
                negated = true
                pos += 1
            }
            var rawRanges: [(lo: UnicodeScalar, hi: UnicodeScalar)] = []
            while let c = peek() {
                if c == "]" && !rawRanges.isEmpty {
                    pos += 1
                    break
                }
                let (lo, hi) = parseClassChar()
                if peek() == "-" {
                    pos += 1
                    if peek() == "]" {
                        rawRanges.append((lo, hi))
                        rawRanges.append((UnicodeScalar(0x2d)!, UnicodeScalar(0x2d)!))
                        pos += 1
                        break
                    }
                    let (_, endHi) = parseClassChar()
                    rawRanges.append((lo, endHi))
                } else {
                    rawRanges.append((lo, hi))
                }
            }
            let ranges = normalizeRanges(rawRanges, negated: negated)
            return (.charClass(ranges), "")
        }

        if ch == "." {
            pos += 1
            return (dotMatchesAll ? .anyChar : .anyCharNotNL, "")
        }

        if ch == "^" {
            pos += 1
            return (.beginLine(multiline), "")
        }

        if ch == "$" {
            pos += 1
            return (.endLine(multiline), "")
        }

        if ch == "\\" {
            pos += 1
            guard let esc = peek() else { return (.emptyMatch, "re2 parse") }
            pos += 1
            switch esc {
            case "d":
                return (.charClass([(UnicodeScalar(0x30)!, UnicodeScalar(0x39)!)]), "")
            case "D":
                return (.charClass([(UnicodeScalar(0)!, UnicodeScalar(0x2f)!), (UnicodeScalar(0x3a)!, UnicodeScalar(0x10ffff)!)]), "")
            case "w":
                return (.charClass([
                    (UnicodeScalar(0x30)!, UnicodeScalar(0x39)!),
                    (UnicodeScalar(0x41)!, UnicodeScalar(0x5a)!),
                    (UnicodeScalar(0x5f)!, UnicodeScalar(0x5f)!),
                    (UnicodeScalar(0x61)!, UnicodeScalar(0x7a)!)
                ]), "")
            case "W":
                let wRanges = [
                    (lo: UnicodeScalar(0x30)!, hi: UnicodeScalar(0x39)!),
                    (lo: UnicodeScalar(0x41)!, hi: UnicodeScalar(0x5a)!),
                    (lo: UnicodeScalar(0x5f)!, hi: UnicodeScalar(0x5f)!),
                    (lo: UnicodeScalar(0x61)!, hi: UnicodeScalar(0x7a)!)
                ]
                return (.charClass(invertRanges(wRanges)), "")
            case "s":
                return (.charClass([
                    (UnicodeScalar(0x9)!, UnicodeScalar(0xa)!),
                    (UnicodeScalar(0xc)!, UnicodeScalar(0xd)!),
                    (UnicodeScalar(0x20)!, UnicodeScalar(0x20)!)
                ]), "")
            case "S":
                let sRanges = [
                    (lo: UnicodeScalar(0x9)!, hi: UnicodeScalar(0xa)!),
                    (lo: UnicodeScalar(0xc)!, hi: UnicodeScalar(0xd)!),
                    (lo: UnicodeScalar(0x20)!, hi: UnicodeScalar(0x20)!)
                ]
                return (.charClass(invertRanges(sRanges)), "")
            case "b":
                return (.wordBoundary, "")
            case "B":
                return (.noWordBoundary, "")
            case "n":
                return (.literal([UnicodeScalar(0xa)!], foldCase), "")
            case "r":
                return (.literal([UnicodeScalar(0xd)!], foldCase), "")
            case "t":
                return (.literal([UnicodeScalar(0x9)!], foldCase), "")
            case "f":
                return (.literal([UnicodeScalar(0xc)!], foldCase), "")
            case "a":
                return (.literal([UnicodeScalar(0x7)!], foldCase), "")
            case "x":
                if peek() == "{" {
                    pos += 1
                    var hexStr = ""
                    while let h = peek(), h != "}" {
                        hexStr.append(Character(advance()))
                    }
                    if peek() == "}" { pos += 1 }
                    if let val = UInt32(hexStr, radix: 16), let u = UnicodeScalar(val) {
                        return (.literal([u], foldCase), "")
                    }
                }
                var hexStr = ""
                for _ in 0..<2 {
                    if let h = peek() { hexStr.append(Character(advance())) }
                }
                if let val = UInt32(hexStr, radix: 16), let u = UnicodeScalar(val) {
                    return (.literal([u], foldCase), "")
                }
                return (.literal([UnicodeScalar(UInt8(ascii: "x"))], foldCase), "")
            case "u":
                var hexStr = ""
                for _ in 0..<4 {
                    if let h = peek() { hexStr.append(Character(advance())) }
                }
                if let val = UInt32(hexStr, radix: 16), let u = UnicodeScalar(val) {
                    return (.literal([u], foldCase), "")
                }
                return (.literal([UnicodeScalar(UInt8(ascii: "u"))], foldCase), "")
            default:
                return (.literal([esc], foldCase), "")
            }
        }

        let lit = advance()
        return (.literal([lit], foldCase), "")
    }

    private func parseClassChar() -> (UnicodeScalar, UnicodeScalar) {
        guard let ch = peek() else { return (UnicodeScalar(0)!, UnicodeScalar(0)!) }
        pos += 1
        if ch == "\\" {
            guard let esc = peek() else { return (UnicodeScalar(0)!, UnicodeScalar(0)!) }
            pos += 1
            switch esc {
            case "d":
                return (UnicodeScalar(0x30)!, UnicodeScalar(0x39)!)
            case "n":
                return (UnicodeScalar(0xa)!, UnicodeScalar(0xa)!)
            case "r":
                return (UnicodeScalar(0xd)!, UnicodeScalar(0xd)!)
            case "t":
                return (UnicodeScalar(0x9)!, UnicodeScalar(0x9)!)
            case "x":
                if peek() == "{" {
                    pos += 1
                    var hexStr = ""
                    while let h = peek(), h != "}" {
                        hexStr.append(Character(advance()))
                    }
                    if peek() == "}" { pos += 1 }
                    if let val = UInt32(hexStr, radix: 16), let u = UnicodeScalar(val) {
                        return (u, u)
                    }
                }
                var hexStr = ""
                for _ in 0..<2 {
                    if let h = peek() { hexStr.append(Character(advance())) }
                }
                if let val = UInt32(hexStr, radix: 16), let u = UnicodeScalar(val) {
                    return (u, u)
                }
            default:
                return (esc, esc)
            }
        }
        return (ch, ch)
    }

    private func normalizeRanges(_ inRanges: [(lo: UnicodeScalar, hi: UnicodeScalar)], negated: Bool) -> [(lo: UnicodeScalar, hi: UnicodeScalar)] {
        if inRanges.isEmpty { return [] }
        let sorted = inRanges.sorted(by: { $0.lo.value < $1.lo.value })
        var merged: [(lo: UnicodeScalar, hi: UnicodeScalar)] = []
        for r in sorted {
            if merged.isEmpty {
                merged.append(r)
                continue
            }
            let lastIdx = merged.count - 1
            if r.lo.value <= merged[lastIdx].hi.value &+ 1 {
                if r.hi.value > merged[lastIdx].hi.value {
                    merged[lastIdx].hi = r.hi
                }
            } else {
                merged.append(r)
            }
        }
        if !negated {
            return merged
        }
        return invertRanges(merged)
    }

    private func invertRanges(_ inRanges: [(lo: UnicodeScalar, hi: UnicodeScalar)]) -> [(lo: UnicodeScalar, hi: UnicodeScalar)] {
        var out: [(lo: UnicodeScalar, hi: UnicodeScalar)] = []
        var cur: UInt32 = 0
        for r in inRanges {
            if r.lo.value > cur {
                if let lo = UnicodeScalar(cur), let hi = UnicodeScalar(r.lo.value - 1) {
                    out.append((lo, hi))
                }
            }
            cur = max(cur, r.hi.value &+ 1)
            if cur > 0x10ffff { break }
        }
        if cur <= 0x10ffff {
            if let lo = UnicodeScalar(cur), let hi = UnicodeScalar(0x10ffff) {
                out.append((lo, hi))
            }
        }
        return out
    }
}

private func icuFromRE2(_ p: String) -> (String, String) {
    // RE2Parser / emitICU recurse per group level: refuse pathological input instead of risking the stack.
    if p.unicodeScalars.count > 16 << 10 {
        return ("", "pattern too long")
    }
    var depth = 0
    var maxDepth = 0
    var esc = false
    for c in p.unicodeScalars {
        if esc { esc = false; continue }
        if c == "\\" { esc = true } else if c == "(" { depth += 1; maxDepth = max(maxDepth, depth) } else if c == ")" { depth -= 1 }
    }
    if maxDepth > 64 {
        return ("", "nesting too deep")
    }
    let parser = RE2Parser(pattern: p)
    let (ast, parseWhy) = parser.parse()
    guard let ast = ast, parseWhy.isEmpty else {
        return ("", "re2 parse")
    }
    if reNullable(ast) {
        return ("", "nullable")
    }
    var b = ""
    let why = emitICU(&b, ast)
    if !why.isEmpty {
        return ("", why)
    }
    let n1 = (try? NSRegularExpression(pattern: p, options: []))?.numberOfCaptureGroups ?? 0
    let n2 = parser.captureIndex
    if n1 != n2 {
        return ("", "captures")
    }
    return (b, "")
}

private func countSubexp(_ pattern: String) -> Int {
    (try? NSRegularExpression(pattern: pattern, options: []))?.numberOfCaptureGroups ?? 0
}

/// Absolute capture-group number of the named group `name` (review H1):
/// groups are numbered by the position of their opening '(' among ALL
/// capturing groups, named or not, exactly as Go regexp / ICU number them
/// (so `(a)(?P<x>b)` gives x == 2, not 1). Skipped while scanning: escaped
/// characters (`\(`), `\Q...\E` quoted runs, anything inside a character
/// class (nesting-aware, leading `]` literal), and every `(?` construct
/// that does not capture: `(?:`, flag groups `(?i)` / `(?i:`, lookarounds
/// `(?=` `(?!` `(?<=` `(?<!`, atomic `(?>`, comments `(?#...)`.
/// Named groups `(?<n>...)` and `(?P<n>...)` count as capturing.
private func namedGroupIndex(pattern: String, name: String) -> Int? {
    let c = Array(pattern.unicodeScalars)
    let n = c.count
    var i = 0
    var group = 0
    var classDepth = 0
    while i < n {
        let ch = c[i]
        if ch == "\\" {
            if i + 1 < n && c[i + 1] == "Q" {
                // \Q ... \E: literal run.
                var j = i + 2
                while j < n && !(c[j] == "\\" && j + 1 < n && c[j + 1] == "E") { j += 1 }
                i = j + 2
            } else {
                i += 2
            }
            continue
        }
        if classDepth > 0 {
            if ch == "[" {
                classDepth += 1
                i += 1
                if i < n && c[i] == "^" { i += 1 }
                if i < n && c[i] == "]" { i += 1 }
                continue
            }
            if ch == "]" { classDepth -= 1 }
            i += 1
            continue
        }
        if ch == "[" {
            classDepth = 1
            i += 1
            if i < n && c[i] == "^" { i += 1 }
            if i < n && c[i] == "]" { i += 1 } // leading ']' is a literal
            continue
        }
        if ch == "(" {
            if i + 1 < n && c[i + 1] == "?" {
                // (?P<name>  or  (?<name>  (but not the lookbehinds (?<= / (?<!)
                var nameStart = -1
                if i + 3 < n && c[i + 2] == "P" && c[i + 3] == "<" {
                    nameStart = i + 4
                } else if i + 3 < n && c[i + 2] == "<" && c[i + 3] != "=" && c[i + 3] != "!" {
                    nameStart = i + 3
                }
                if nameStart >= 0 {
                    group += 1
                    var j = nameStart
                    var gname = ""
                    while j < n && c[j] != ">" { gname.unicodeScalars.append(c[j]); j += 1 }
                    if gname == name { return group }
                    i = j + 1
                    continue
                }
                if i + 2 < n && c[i + 2] == "#" {
                    // (?# comment ) — no nesting, ends at the first ')'.
                    var j = i + 3
                    while j < n && c[j] != ")" { j += 1 }
                    i = j + 1
                    continue
                }
                i += 2 // non-capturing / flags / lookaround / atomic
                continue
            }
            group += 1
            i += 1
            continue
        }
        i += 1
    }
    return nil
}

private func parseRepl(_ rePattern: String, _ repl: String) -> (parts: [NCSnapReplPart], ok: Bool) {
    let numSubexp = countSubexp(rePattern)
    var parts: [NCSnapReplPart] = []
    var lit = ""
    func flush() {
        if !lit.isEmpty {
            parts.append(NCSnapReplPart(l: lit, g: -1))
            lit = ""
        }
    }
    let chars = Array(repl)
    var i = 0
    while i < chars.count {
        let c = chars[i]
        if c != "$" || i + 1 >= chars.count {
            lit.append(c)
            i += 1
            continue
        }
        let d = chars[i + 1]
        switch d {
        case "$":
            lit.append("$")
            i += 2
        case "&":
            flush()
            parts.append(NCSnapReplPart(l: nil, g: 0))
            i += 2
        case "0"..."9":
            var j = i + 1
            while j < chars.count && chars[j] >= "0" && chars[j] <= "9" {
                j += 1
            }
            let numStr = String(chars[(i + 1)..<j])
            if let g = Int(numStr), g <= numSubexp {
                flush()
                parts.append(NCSnapReplPart(l: nil, g: g))
            } else {
                lit.append(contentsOf: chars[i..<j])
            }
            i = j
        case "{":
            guard let endIdx = chars[(i + 2)...].firstIndex(of: "}") else {
                lit.append("$")
                i += 1
                continue
            }
            let name = String(chars[(i + 2)..<endIdx])
            if let g = Int(name) {
                if g <= numSubexp {
                    flush()
                    parts.append(NCSnapReplPart(l: nil, g: g))
                } else {
                    lit.append(contentsOf: chars[i...endIdx])
                }
            } else if let g = namedGroupIndex(pattern: rePattern, name: name) {
                flush()
                parts.append(NCSnapReplPart(l: nil, g: g))
            } else {
                lit.append(contentsOf: chars[i...endIdx])
            }
            i = endIdx + 1
        case "`", "'", "+", "_":
            return ([], false)
        default:
            lit.append("$")
            i += 1
        }
    }
    flush()
    return (parts, true)
}

private func snapBodyOp(regex: String, repl: String) -> (NCSnapBodyOp, String) {
    // lane regexp2 (Go-zero): an op on regexp2's path (Go: op.fast == nil — \b, $, look-around, back-references, a
    // pattern that matches empty, a replacement Go's template parser refuses) is exported as its source when RX2ICU
    // translates it and regexp2 accepts the replacement; the tunnel runs regexp2.Replace's semantics on it.
    func regexp2Path() -> (NCSnapBodyOp, String) {
        guard let t = RX2ICU.translate(regex).0 else { return (NCSnapBodyOp(), "regexp2") }
        guard (try? NSRegularExpression(pattern: t.icu, options: [])) != nil else { return (NCSnapBodyOp(), "regexp2") }
        let (tp, tperr) = RX2ICU.template(repl, t)
        if tp == nil || tperr { return (NCSnapBodyOp(), "regexp2 replacement") }
        return (NCSnapBodyOp(p: regex, repl: repl), "")
    }
    if !compileFastRe(regex) {
        if (try? NSRegularExpression(pattern: regex, options: [])) == nil {
            return (NCSnapBodyOp(skip: true), "")
        }
        return regexp2Path()
    }
    guard regex.utf8.allSatisfy({ _ in true }), repl.utf8.allSatisfy({ _ in true }) else {
        return (NCSnapBodyOp(), "not utf-8")
    }
    let (icu, why) = icuFromRE2(regex)
    if why == "nullable" {
        return regexp2Path() // Go's fastBodyRe refuses a pattern that matches "" → regexp2's path
    }
    let (parts, ok) = parseRepl(regex, repl)
    if !ok {
        return regexp2Path() // fastBodyRe refuses the replacement → regexp2's path
    }
    if !why.isEmpty {
        // still Go's RE2 path (nested repeats, …): RE2 semantics re-stated by RX2ICU's RE2 dialect; leftmost-first
        // matches are the same in a backtracking engine (the tunnel's time budget hands a runaway back)
        guard let t = RX2ICU.translate(regex, dialect: .re2).0, (try? NSRegularExpression(pattern: t.icu, options: [])) != nil else {
            return (NCSnapBodyOp(), why)
        }
        return (NCSnapBodyOp(parts: parts.isEmpty ? nil : parts, p: regex, re2: true), "")
    }
    return (NCSnapBodyOp(icu: icu, parts: parts.isEmpty ? nil : parts), "")
}

private func splitJSONPath(_ p: String) -> [NCBodyJSONKey] {
    var out: [NCBodyJSONKey] = []
    var s = p
    if s.hasPrefix("$.") {
        s = String(s.dropFirst(2))
    }
    let parts = s.components(separatedBy: ".")
    for var part in parts {
        while !part.isEmpty {
            guard let i = part.firstIndex(of: "[") else {
                out.append(.key(part))
                break
            }
            if i > part.startIndex {
                out.append(.key(String(part[..<i])))
            }
            guard let j = part.firstIndex(of: "]"), j > i else {
                out.append(.key(part))
                break
            }
            let inner = String(part[part.index(after: i)..<j])
            if let n = Int(inner) {
                out.append(.index(n))
            } else {
                let trimmed = inner.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                out.append(.key(trimmed))
            }
            part = String(part[part.index(after: j)...])
        }
    }
    return out
}

private func parseJSONValueAndEncode(_ s: String) -> (String?, String?) {
    let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
    if trimmed.isEmpty {
        return ("\"\"", nil)
    }
    if let data = trimmed.data(using: .utf8),
       let obj = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) {
        if let outData = try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys, .withoutEscapingSlashes]) {
            let str = String(decoding: outData, as: UTF8.self)
            return (str, nil)
        }
        return (trimmed, nil)
    }
    // Bare string literal (e.g. hello -> "hello")
    if let outData = try? JSONSerialization.data(withJSONObject: s, options: [.withoutEscapingSlashes]) {
        let str = String(decoding: outData, as: UTF8.self)
        return (str, nil)
    }
    return (nil, "json value")
}

// MARK: - JQ Subset Parser (bodysnap.go snapJQ)

private func snapJQ(_ expr: String) -> ([NCSnapJQStep], String) {
    let stepsRaw = splitTopLevel(expr, separator: "|")
    var steps: [NCSnapJQStep] = []
    for raw in stepsRaw {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if s == "." { continue }

        if s.hasPrefix("del(") && s.hasSuffix(")") {
            let inner = String(s.dropFirst(4).dropLast())
            let pathStrings = splitTopLevel(inner, separator: ",")
            var paths: [[NCBodyJSONKey]] = []
            for ps in pathStrings {
                let (path, why) = parseJQPath(ps.trimmingCharacters(in: .whitespacesAndNewlines))
                if !why.isEmpty { return ([], why) }
                paths.append(path)
            }
            steps.append(NCSnapJQStep(op: "del", paths: paths))
            continue
        }

        if let modRange = s.range(of: "|=") {
            let leftStr = String(s[..<modRange.lowerBound]).trimmingCharacters(in: .whitespacesAndNewlines)
            let rightStr = String(s[modRange.upperBound...]).trimmingCharacters(in: .whitespacesAndNewlines)
            let (path, whyP) = parseJQPath(leftStr)
            if !whyP.isEmpty { return ([], whyP) }
            guard rightStr.hasPrefix("map(select(") && rightStr.hasSuffix("))") else {
                return ([], "jq modify")
            }
            let condStr = String(rightStr.dropFirst(11).dropLast(2)).trimmingCharacters(in: .whitespacesAndNewlines)
            let (cond, whyC) = parseJQCond(condStr)
            if !whyC.isEmpty { return ([], whyC) }
            steps.append(NCSnapJQStep(op: "filter", path: path, cond: cond))
            continue
        }

        if let eqRange = s.range(of: "="), !s.contains("=="), !s.contains("!=") {
            let leftStr = String(s[..<eqRange.lowerBound]).trimmingCharacters(in: .whitespacesAndNewlines)
            let rightStr = String(s[eqRange.upperBound...]).trimmingCharacters(in: .whitespacesAndNewlines)
            let (path, whyP) = parseJQPath(leftStr)
            if !whyP.isEmpty { return ([], whyP) }
            let (v, whyV) = parseJQConst(rightStr)
            if !whyV.isEmpty { return ([], whyV) }
            steps.append(NCSnapJQStep(op: "set", path: path, v: v))
            continue
        }

        return ([], "jq form")
    }
    return (steps, "")
}

private func splitTopLevel(_ s: String, separator: Character) -> [String] {
    var out: [String] = []
    var cur = ""
    var parenDepth = 0
    var bracketDepth = 0
    var braceDepth = 0
    var inQuote = false
    var quoteChar: Character = "\""
    var esc = false

    for c in s {
        if inQuote {
            cur.append(c)
            if esc {
                esc = false
            } else if c == "\\" {
                esc = true
            } else if c == quoteChar {
                inQuote = false
            }
            continue
        }
        if c == "\"" || c == "'" {
            inQuote = true
            quoteChar = c
            cur.append(c)
            continue
        }
        if c == "(" { parenDepth += 1 }
        else if c == ")" { parenDepth -= 1 }
        else if c == "[" { bracketDepth += 1 }
        else if c == "]" { bracketDepth -= 1 }
        else if c == "{" { braceDepth += 1 }
        else if c == "}" { braceDepth -= 1 }
        else if c == separator && parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 {
            out.append(cur)
            cur = ""
            continue
        }
        cur.append(c)
    }
    if !cur.isEmpty {
        out.append(cur)
    }
    return out
}

private func parseJQPath(_ sIn: String) -> ([NCBodyJSONKey], String) {
    var s = sIn.trimmingCharacters(in: .whitespacesAndNewlines)
    if s == "." {
        return ([], "")
    }
    if s.hasPrefix(".") {
        s = String(s.dropFirst())
    }
    if s.contains("[]") {
        return ([], "jq path term")
    }
    var out: [NCBodyJSONKey] = []
    var i = s.startIndex
    while i < s.endIndex {
        if s[i] == "." {
            i = s.index(after: i)
            continue
        }
        if s[i] == "[" {
            guard let endIdx = s[i...].firstIndex(of: "]") else {
                return ([], "jq path form")
            }
            let inner = String(s[s.index(after: i)..<endIdx]).trimmingCharacters(in: .whitespacesAndNewlines)
            if inner.contains(":") {
                return ([], "jq slice")
            }
            if let n = Int(inner) {
                out.append(.index(n))
            } else {
                let trimmed = inner.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                out.append(.key(trimmed))
            }
            i = s.index(after: endIdx)
            continue
        }
        let start = i
        while i < s.endIndex && s[i] != "." && s[i] != "[" {
            i = s.index(after: i)
        }
        let comp = String(s[start..<i]).trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
        if !comp.isEmpty {
            out.append(.key(comp))
        }
    }
    return (out, "")
}

private func parseJQConst(_ sIn: String) -> (String, String) {
    let s = sIn.trimmingCharacters(in: .whitespacesAndNewlines)
    if s == "null" || s == "true" || s == "false" || s == "[]" {
        return (s, "")
    }
    if let data = s.data(using: .utf8),
       let obj = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) {
        if let out = try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys, .withoutEscapingSlashes]) {
            return (String(decoding: out, as: UTF8.self), "")
        }
    }
    return (s, "")
}

private func parseJQCond(_ sIn: String) -> (NCSnapJQCond?, String) {
    var s = sIn.trimmingCharacters(in: .whitespacesAndNewlines)
    while s.hasPrefix("(") && s.hasSuffix(")") {
        var depth = 0
        var ok = true
        for (idx, c) in s.enumerated() {
            if c == "(" { depth += 1 }
            else if c == ")" {
                depth -= 1
                if depth == 0 && idx < s.count - 1 {
                    ok = false
                    break
                }
            }
        }
        if ok && depth == 0 {
            s = String(s.dropFirst().dropLast()).trimmingCharacters(in: .whitespacesAndNewlines)
        } else {
            break
        }
    }

    // Split on ' or '
    let orParts = splitTopLevel(s, separator: " ")
    var orIndices: [Int] = []
    for (idx, p) in orParts.enumerated() {
        if p == "or" { orIndices.append(idx) }
    }
    if !orIndices.isEmpty {
        let leftParts = orParts[..<orIndices[0]].joined(separator: " ")
        let rightParts = orParts[(orIndices[0] + 1)...].joined(separator: " ")
        let (leftCond, whyL) = parseJQCond(leftParts)
        if !whyL.isEmpty { return (nil, whyL) }
        let (rightCond, whyR) = parseJQCond(rightParts)
        if !whyR.isEmpty { return (nil, whyR) }
        return (NCSnapJQCond(k: "or", a: leftCond, b: rightCond), "")
    }

    // Split on ' and '
    var andIndices: [Int] = []
    for (idx, p) in orParts.enumerated() {
        if p == "and" { andIndices.append(idx) }
    }
    if !andIndices.isEmpty {
        let leftParts = orParts[..<andIndices[0]].joined(separator: " ")
        let rightParts = orParts[(andIndices[0] + 1)...].joined(separator: " ")
        let (leftCond, whyL) = parseJQCond(leftParts)
        if !whyL.isEmpty { return (nil, whyL) }
        let (rightCond, whyR) = parseJQCond(rightParts)
        if !whyR.isEmpty { return (nil, whyR) }
        return (NCSnapJQCond(k: "and", a: leftCond, b: rightCond), "")
    }

    // Split on ' | '
    let pipeParts = splitTopLevel(s, separator: "|")
    if pipeParts.count == 2 {
        let left = pipeParts[0].trimmingCharacters(in: .whitespacesAndNewlines)
        let right = pipeParts[1].trimmingCharacters(in: .whitespacesAndNewlines)
        if right == "not" {
            let (subCond, whySub) = parseJQCond(left)
            if !whySub.isEmpty { return (nil, whySub) }
            return (NCSnapJQCond(k: "not", a: subCond), "")
        }
        if right.hasPrefix("has(") && right.hasSuffix(")") {
            let inner = String(right.dropFirst(4).dropLast()).trimmingCharacters(in: .whitespacesAndNewlines)
            let key = inner.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            let (path, whyP) = parseJQPath(left)
            if !whyP.isEmpty { return (nil, whyP) }
            return (NCSnapJQCond(k: "has", p: path, key: key), "")
        }
        return (nil, "jq cond pipe")
    }

    if s.hasPrefix("has(") && s.hasSuffix(")") {
        let inner = String(s.dropFirst(4).dropLast()).trimmingCharacters(in: .whitespacesAndNewlines)
        let key = inner.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
        return (NCSnapJQCond(k: "has", key: key), "")
    }

    if s == "not" {
        return (NCSnapJQCond(k: "not", a: NCSnapJQCond(k: "truthy")), "")
    }

    if let eqRange = s.range(of: "==") {
        let left = String(s[..<eqRange.lowerBound]).trimmingCharacters(in: .whitespacesAndNewlines)
        let right = String(s[eqRange.upperBound...]).trimmingCharacters(in: .whitespacesAndNewlines)
        let (path, constVal, why) = resolvePathAndConst(left, right)
        if !why.isEmpty { return (nil, why) }
        return (NCSnapJQCond(k: "eq", p: path, v: constVal), "")
    }

    if let neRange = s.range(of: "!=") {
        let left = String(s[..<neRange.lowerBound]).trimmingCharacters(in: .whitespacesAndNewlines)
        let right = String(s[neRange.upperBound...]).trimmingCharacters(in: .whitespacesAndNewlines)
        let (path, constVal, why) = resolvePathAndConst(left, right)
        if !why.isEmpty { return (nil, why) }
        return (NCSnapJQCond(k: "ne", p: path, v: constVal), "")
    }

    let (path, whyP) = parseJQPath(s)
    if !whyP.isEmpty { return (nil, whyP) }
    return (NCSnapJQCond(k: "truthy", p: path), "")
}

private func resolvePathAndConst(_ a: String, _ b: String) -> ([NCBodyJSONKey], String, String) {
    var pathStr = a
    var constStr = b
    if !b.hasPrefix(".") && a.hasPrefix(".") {
        pathStr = a
        constStr = b
    } else if !a.hasPrefix(".") && b.hasPrefix(".") {
        pathStr = b
        constStr = a
    }
    let (path, whyP) = parseJQPath(pathStr)
    if !whyP.isEmpty { return ([], "", whyP) }

    if constStr != "null" && constStr != "true" && constStr != "false" && !constStr.hasPrefix("\"") {
        return ([], "", "jq cond value")
    }
    return (path, constStr, "")
}

private func snapBody(_ sr: inout NCSnapRule, _ r: NCEngineRule, res: NCResources? = nil) {
    var why = ""
    switch r.kind {
    case "body":
        var ops: [NCSnapBodyOp] = []
        for op in r.body {
            let (so, w) = snapBodyOp(regex: op.regex, repl: op.repl)
            if !w.isEmpty && why.isEmpty {
                why = w
            }
            ops.append(so)
        }
        if !ops.isEmpty {
            sr.body = ops
        }
    case "json":
        var ops = r.jsonOps
        if ops.isEmpty && !r.line.isEmpty {
            ops = parseLoonJSONLine(r.line)
        }
        var jsonOps: [NCSnapJSONOp] = []
        for op in ops {
            let (enc, err) = parseJSONValueAndEncode(op.value)
            if let err = err {
                why = err
                break
            }
            let keys = splitJSONPath(op.path)
            jsonOps.append(NCSnapJSONOp(op: op.op, path: keys, v: enc ?? "\"\""))
        }
        if !jsonOps.isEmpty {
            sr.jsonOps = jsonOps
        }
    case "jq":
        // fix/nc-jq-full: the full filter, inline or from jq-path= / an Egern filter URL (prefetched with the other
        // remote resources: NativeRuntimePrep.remoteResources lists r.data)
        var src = r.jq
        if src.isEmpty, !r.data.isEmpty, let res,
           let d = try? res.get(path: r.data, maxAge: 86400), let text = String(data: d, encoding: .utf8) {
            src = text
        }
        if src.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            why = "jq file"
            NSLog("[Mihomo] WARN jq rule %@: filter file %@ not available, bodies pass through", r.pattern, r.data)
            break
        }
        do {
            _ = try NativeJQ.compile(src)
        } catch {
            why = "jq: \(error)"
            NSLog("[Mihomo] WARN jq rule %@ does not compile (%@), bodies pass through", r.pattern, "\(error)")
            break
        }
        sr.jqx = src
    default:
        return
    }
    sr.bodyOK = why.isEmpty ? true : nil
    sr.bodyWhy = why.isEmpty ? nil : why
}

private func parseLoonJSONLine(_ line: String) -> [(op: String, path: String, value: String)] {
    let toks = line.components(separatedBy: .whitespacesAndNewlines).filter { !$0.isEmpty }
    guard let idx = toks.firstIndex(where: { $0.contains("-body-json-") }) else { return [] }
    let opTok = toks[idx]
    let verb = opTok.components(separatedBy: "-body-json-").last ?? ""
    let args = Array(toks[(idx + 1)...])
    var out: [(op: String, path: String, value: String)] = []
    if verb == "del" {
        for a in args {
            out.append((op: "del", path: a, value: ""))
        }
    } else {
        var i = 0
        while i + 1 < args.count {
            out.append((op: verb, path: args[i], value: args[i + 1]))
            i += 2
        }
    }
    return out
}

// MARK: - Rule & Snapshot Construction (rewritesnap.go)

private func isCompileURLRe(_ p: String) -> Bool {
    if p.isEmpty || p.contains("-[") {
        return false
    }
    var esc = false
    for c in p.utf8 {
        if esc {
            if c == UInt8(ascii: "b") || c == UInt8(ascii: "B") {
                return false
            }
            esc = false
            continue
        }
        if c == UInt8(ascii: "\\") {
            esc = true
        }
    }
    if p.contains("(?=") || p.contains("(?!") || p.contains("(?<=") || p.contains("(?<!") ||
       p.contains("(?>") || p.contains("(?(") || p.contains("\\Z") || p.contains("\\G") ||
       p.contains("\\k") {
        return false
    }
    var inClass = false
    let bytes = Array(p.utf8)
    var i = 0
    while i < bytes.count {
        let b = bytes[i]
        if inClass {
            if b == UInt8(ascii: "\\") {
                i += 2
                continue
            }
            if b == UInt8(ascii: "]") {
                inClass = false
            }
            i += 1
            continue
        }
        if b == UInt8(ascii: "[") {
            inClass = true
            i += 1
            continue
        }
        if b == UInt8(ascii: "\\") && i + 1 < bytes.count {
            let next = bytes[i + 1]
            if next >= UInt8(ascii: "1") && next <= UInt8(ascii: "9") {
                return false
            }
            i += 2
            continue
        }
        i += 1
    }
    guard (try? NSRegularExpression(pattern: p, options: [])) != nil else {
        return false
    }
    return true
}

private func snapRulePortable(_ sr: NCSnapRule) -> Bool {
    if let re = sr.re, !re.ok {
        return false
    }
    switch sr.kind {
    case "url":
        return (sr.action != "302" && sr.action != "307" && sr.action != "header") || (sr.targetOK == true)
    case "header":
        return sr.opsOK == true
    case "maplocal":
        return sr.local != nil
    default:
        break
    }
    if sr.hgate == true && (sr.hre == nil || sr.hre?.ok != true) {
        return false
    }
    return true
}

private func snapRule(i: Int, r: NCEngineRule, home: String, res: NCResources) -> NCSnapRule {
    var sr = NCSnapRule(
        i: i,
        kind: r.kind,
        phase: r.phase,
        hgate: !r.headerPattern.isEmpty ? true : nil,
        action: r.action.isEmpty ? nil : r.action,
        target: r.target.isEmpty ? nil : r.target
    )
    let redirect = r.kind == "url" && (r.action == "302" || r.action == "307" || r.action == "header")
    if !r.pattern.isEmpty {
        sr.re = NCRewriteICU.snapRegex(pattern: r.pattern, re2: isCompileURLRe(r.pattern), replace: redirect)
    }
    if !r.headerPattern.isEmpty {
        sr.hre = NCRewriteICU.snapRegex(pattern: r.headerPattern, re2: false, replace: false)
    }
    switch r.kind {
    case "url":
        if sr.re != nil && redirect {
            let (tp, tperr) = NCRewriteICU.snapTemplate(pattern: r.pattern, repl: r.target)
            sr.tp = tp
            sr.tperr = tperr ? true : nil
            sr.targetOK = (sr.re?.ok == true && (tp != nil || tperr)) ? true : nil
        }
    case "header":
        var opsOK = true
        var ops: [NCSnapHeaderOp] = []
        for op in r.headers {
            var so = NCSnapHeaderOp(
                op: op.op,
                name: op.name.isEmpty ? nil : op.name,
                value: op.value.isEmpty ? nil : op.value
            )
            switch op.op {
            case "add", "del", "replace":
                break
            case "replace-regex", "raw":
                if op.regex.isEmpty {
                    break
                }
                let opRe = NCRewriteICU.snapRegex(pattern: op.regex, re2: false, replace: true)
                so.re = opRe
                var v = op.value
                if op.op == "raw" {
                    v = unescapeCRLF(v)
                }
                let (tp, tperr) = NCRewriteICU.snapTemplate(pattern: op.regex, repl: v)
                so.tp = tp
                so.tperr = tperr ? true : nil
                if !opRe.ok || (tp == nil && !tperr) {
                    opsOK = false
                }
            default:
                opsOK = false
            }
            ops.append(so)
        }
        if !ops.isEmpty {
            sr.headers = ops
        }
        sr.opsOK = opsOK ? true : nil
    case "maplocal":
        sr.local = snapMapLocal(r: r, home: home, res: res)
    case "script":
        if let sc = r.script {
            sr.script = NCSnapScript(
                name: sc.name,
                type: sc.type,
                requiresBody: sc.requiresBody ? true : nil
            )
        }
    case "body", "jq", "json":
        snapBody(&sr, r, res: res)
    default:
        break
    }
    return sr
}

private func buildRewriteSnapshot(home: String, cfg: NCEngineConfig, rs: NCEngineRuleset, matcher: NCHostMatcher, res: NCResources) -> NCRewriteSnapshot {
    var s = NCRewriteSnapshot(
        version: NCRewriteSnapshot.supportedVersion,
        gen: 1,
        on: cfg.anyOn,
        capture: cfg.captureOn,
        inc: [],
        exc: [],
        rules: [],
        total: 0,
        portable: 0
    )
    for p in matcher.inc {
        s.inc.append(NCSnapHost(pat: p.pat, port: p.port == 0 ? nil : p.port))
    }
    for p in matcher.exc {
        s.exc.append(NCSnapHost(pat: p.pat, port: p.port == 0 ? nil : p.port))
    }
    for (i, r) in rs.rules.enumerated() {
        let sr = snapRule(i: i, r: r, home: home, res: res)
        s.total += 1
        if snapRulePortable(sr) {
            s.portable += 1
        }
        s.rules.append(sr)
    }
    return s
}

// MARK: - Snapshot Builder (bridge/mitm/exportsnap.go ExportRewriteSnapshot)

enum NCRewriteSnapshotBuilder {
    /// Export rewrite snapshot JSON and MitM host count.
    /// Aligns with bridge/mitm/exportsnap.go: ExportRewriteSnapshot(home, cfg, rs).
    /// When cfg.mitm is false, hostnames are treated as nil and hostCount returns 0; snapshot gen is 1.
    static func export(home: String, cfg: NCEngineConfig, rs: NCEngineRuleset) -> (json: String, hostCount: Int) {
        guard let r = try? exportData(home: home, cfg: cfg, rs: rs),
              let jsonStr = String(data: r.data, encoding: .utf8) else {
            return ("", 0)
        }
        return (jsonStr, r.hostCount)
    }

    /// rv2: like `export`, but an encode failure is thrown instead of collapsing into "" (NativeRuntimePrep used
    /// to write the empty snapshot and still report rewrite=true).
    static func exportData(home: String, cfg: NCEngineConfig, rs: NCEngineRuleset, res res0: NCResources? = nil) throws -> (data: Data, hostCount: Int) {
        let res = res0 ?? NCResources(home: home)
        let hostnames: [String] = cfg.mitm ? rs.hostnames : []
        let hostCount = cfg.mitm ? rs.hostnames.count : 0
        let matcher = NCHostMatcher.build(hostnames)
        let snap = buildRewriteSnapshot(home: home, cfg: cfg, rs: rs, matcher: matcher, res: res)
        let data = try JSONEncoder().encode(snap)
        return (data, hostCount)
    }
}
