// NativeCore (feat/native-core-eval, gap C4) — the native-only tunnel's request log and log stream
// (astemo6/Muse NativeCore, 2026-10-25).
//
// NativeRequestLogStore is the NativeRequestRecorder's sink in the native tunnel: it folds the recorder's events into entries
// with the semantics of the retired bridge (drop / local / forward open an entry; response /
// end / cancel / upstream / error / abort finish it), keeps the OPEN entries (≤ 256, with headers) and the last 200
// summaries (no headers) in memory, and appends every finished entry to the App Group ring
// (NativeRequestLogFile, 2 × 256 KB on disk). The controller serves /mitm/requests from it; the app falls back to
// the file when the tunnel is not reachable.
//
// NativeLogRing keeps the last general log lines (StartupLog.tap) and script console lines in memory for
// /hark/logs, /mitm/logs and the live /logs websocket (NCController polls `since(seq)` once a second).
import Foundation

final class NativeRequestLogStore: NativeRequestLogSink {
    static let shared = NativeRequestLogStore()

    let pendingMax = 256
    let recentMax = 200
    private let lock = NSLock()
    private var pending: [Int64: NativeRequestLogEntry] = [:]   // recorder key → entry
    private var pendingOrder: [Int64] = []
    private var recent: [NativeRequestLogEntry] = []            // finished, summaries, oldest first
    private var idSeq: Int64
    private var labelGen: Int64 = -1
    private var labels: [Int: String] = [:]

    init() {
        // ids grow across tunnel runs (unix ms base), so the app's file view and `since` stay ordered
        idSeq = Int64(Date().timeIntervalSince1970 * 1000) * 16
    }

    /// The recorder hands encoded batches; decoded once here (off the request path, the recorder's queue).
    func record(_ json: String) -> Int {
        guard let evs = try? JSONDecoder().decode([Event].self, from: Data(json.utf8)) else { return -1 }
        var n = 0
        for e in evs where apply(e) { n += 1 }
        return n
    }

    /// NativeRequestEvent is Encodable only; the store's own decodable mirror of its JSON.
    private struct Event: Decodable {
        var k: Int64
        var ev: String
        var t: Double?
        var ms: Double
        var gen: Int64?
        var rules: [Int]?
        var method: String?
        var url: String?
        var host: String?
        var status: Int?
        var headers: [[String]]?
        var len: Int64?
        var body: Data?
        var sent: Int64?
        var resp: Bool?
        var why: String?
        var notes: [String]?
        var rmethod: String?
    }

    // MARK: queries (controller)

    /// Summaries: finished (recent) + open, oldest first, id > since.
    func summaries(since: Int64 = 0) -> [NativeRequestLogEntry] {
        lock.lock(); defer { lock.unlock() }
        var out = recent.filter { $0.id > since }
        out += pendingOrder.compactMap { pending[$0] }.filter { $0.id > since }.map { $0.summary }
        out.sort { $0.id < $1.id }
        return out
    }

    func detail(id: Int64) -> NativeRequestLogEntry? {
        lock.lock()
        let open = pending.values.first { $0.id == id }
        lock.unlock()
        return open ?? NativeRequestLogFile.entry(id: id)
    }

    func clear() {
        lock.lock()
        recent.removeAll()
        lock.unlock()
        NativeRequestLogFile.clear()
    }

    /// Hosts seen in the recent entries (GET /mitm/hosts: host → paths).
    func hosts() -> [String: [String]] {
        lock.lock(); defer { lock.unlock() }
        var out: [String: [String]] = [:]
        for e in recent.suffix(100) {
            var paths = out[e.host] ?? []
            let p = URL(string: e.url)?.path ?? "/"
            if !paths.contains(p) && paths.count < 20 { paths.append(p) }
            out[e.host] = paths
        }
        return out
    }

    // MARK: events (nativerecord applyNative)

    private func apply(_ r: Event) -> Bool {
        switch r.ev {
        case "drop", "local", "forward":
            lock.lock()
            idSeq += 1
            var e = NativeRequestLogEntry(id: idSeq, time: r.t ?? Date().timeIntervalSince1970, method: r.method ?? "GET",
                                          url: r.url ?? "", host: r.host ?? "")
            let ls = labelsLocked(r.gen, r.rules)
            lock.unlock()
            if !ls.isEmpty { e.matched = ls }
            for n in r.notes ?? [] { Self.note(&e, n) }
            switch r.ev {
            case "drop":
                Self.note(&e, r.why?.isEmpty == false ? r.why! : "拒绝（断开）")
                finish(e, status: 0, ms: r.ms)
            case "local":
                e.local = true
                e.status = r.status ?? 200
                e.respHeaders = Self.flat(r.headers)
                e.bytes = r.len ?? Int64(r.body?.count ?? 0)
                if let b = r.body, b.count <= 16 << 10, let s = String(data: b, encoding: .utf8) {
                    e.respBody = s
                    e.respBodyLength = b.count
                }
                finish(e, status: -1, ms: r.ms)
            default:
                if let m = r.rmethod, !m.isEmpty { e.method = m }
                e.reqHeaders = Self.flat(r.headers)
                lock.lock()
                pending[r.k] = e
                pendingOrder.append(r.k)
                while pending.count > pendingMax, !pendingOrder.isEmpty {
                    pending.removeValue(forKey: pendingOrder.removeFirst())
                }
                if pendingOrder.count > 4 * pendingMax { pendingOrder = pendingOrder.filter { pending[$0] != nil } }
                lock.unlock()
            }
            return true
        case "response", "end", "cancel", "upstream", "error", "abort":
            lock.lock()
            guard var e = pending[r.k] else { lock.unlock(); return false }
            if r.ev != "response" {
                pending.removeValue(forKey: r.k)
                if let i = pendingOrder.firstIndex(of: r.k) { pendingOrder.remove(at: i) }
            }
            let ls = (r.ev == "response" && r.status != 101) || r.ev == "abort" ? labelsLocked(r.gen, r.rules) : []
            lock.unlock()
            for l in ls where !(e.matched ?? []).contains(l) { e.matched = (e.matched ?? []) + [l] }
            for n in r.notes ?? [] { Self.note(&e, n) }
            switch r.ev {
            case "response":
                e.status = r.status ?? e.status
                e.respHeaders = Self.flat(r.headers)
                if let l = r.len, l > e.bytes { e.bytes = l }
                if r.status == 101 {
                    Self.note(&e, "WebSocket / Upgrade")
                    lock.lock()
                    pending.removeValue(forKey: r.k)
                    if let i = pendingOrder.firstIndex(of: r.k) { pendingOrder.remove(at: i) }
                    lock.unlock()
                    finish(e, status: 101, ms: r.ms)
                } else {
                    lock.lock()
                    if pending[r.k] != nil { pending[r.k] = e }
                    lock.unlock()
                }
            case "end":
                if let s = r.sent, s > 0 { e.bytes += s }
                if let w = r.why, !w.isEmpty, r.resp == true { Self.note(&e, w) }
                finish(e, status: -1, ms: r.ms)
            case "cancel":
                let why = r.why?.isEmpty == false ? r.why! : "客户端取消"
                Self.note(&e, why)
                finish(e, status: r.resp == true ? -1 : 0, ms: r.ms)
            case "upstream":
                Self.note(&e, "上游错误：" + (r.why ?? ""))
                finish(e, status: 502, ms: r.ms)
            case "error":
                Self.note(&e, "内部错误")
                finish(e, status: 502, ms: r.ms)
            default: // abort
                Self.note(&e, "上游错误：" + (r.why ?? ""))
                finish(e, status: 502, ms: r.ms)
            }
            return true
        default:
            return false
        }
    }

    /// status -1 keeps the entry's status (the old core finishAt).
    private func finish(_ entry: NativeRequestLogEntry, status: Int, ms: Double) {
        var e = entry
        if status >= 0 { e.status = status }
        e.done = true
        e.duration = ms
        NativeRequestLogFile.append(e)
        lock.lock()
        recent.append(e.summary)
        if recent.count > recentMax { recent.removeFirst(recent.count - recentMax) }
        lock.unlock()
    }

    private static func note(_ e: inout NativeRequestLogEntry, _ n: String) {
        guard !n.isEmpty else { return }
        var ns = e.notes ?? []
        if ns.count < 16 { ns.append(n) }
        e.notes = ns
    }

    private static func flat(_ pairs: [[String]]?) -> [String: String]? {
        guard let pairs, !pairs.isEmpty else { return nil }
        var out: [String: String] = [:]
        for p in pairs where p.count == 2 {
            if let old = out[p[0]] { out[p[0]] = old + ", " + p[1] } else { out[p[0]] = p[1] }
        }
        return out
    }

    /// fix/nc-mitm-live: labels for the [REWRITE] diagnostics line.
    func ruleLabels(_ rules: [Int]) -> [String] {
        lock.lock(); defer { lock.unlock() }
        return labelsLocked(nil, rules)
    }

    /// Rule labels of the current snapshot (script name, else kind + pattern), cached per generation.
    private func labelsLocked(_ gen: Int64?, _ rules: [Int]?) -> [String] {
        guard let rules, !rules.isEmpty else { return [] }
        let src = NativeRewriteSnapshotSource.shared
        let g = src.generation()
        if g != labelGen {
            labels.removeAll()
            labelGen = g
            for r in src.currentSnapshot()?.rules ?? [] {
                if let s = r.script { labels[r.i] = s.name } else {
                    labels[r.i] = r.kind + (r.re.map { " " + String($0.p.prefix(80)) } ?? "")
                }
            }
        }
        return rules.map { labels[$0] ?? "#\($0)" }
    }
}

/// In-memory log lines for the controller's history endpoints and live stream (no the old core log ring in NativeCore).
final class NativeLogRing {
    static let shared = NativeLogRing()

    struct Line { var seq: UInt64; var time: Int64; var type: String; var payload: String }
    struct ScriptLine { var id: Int64; var time: Double; var script: String; var level: String; var msg: String; var count: Int = 1 }

    let generalMax = 400
    let scriptMax = 300
    private let lock = NSLock()
    private var general: [Line] = []
    private var scripts: [ScriptLine] = []
    private var seq: UInt64 = 0
    private var scriptSeq: Int64 = 0
    /// fix/nc-e2e-real: GET /mitm/notifications (脚本通知 page answered 404 on the native core) — the last
    /// `noticeMax` $notification.post / $notify calls, newest last.
    struct Notice { var time: Double; var script: String; var title: String; var subtitle: String; var body: String; var url: String }
    private var notices: [Notice] = []
    private let noticeMax = 100

    /// feat/session-records: [DNS] lines also land in a session archive on disk, so the
    /// 域名解析记录 page keeps the whole connection's queries (the 400-line general ring
    /// rotates them out within minutes). Truncated at install (tunnel start = new session)
    /// and by clearGeneral (the DNS page's 清空).
    private var dnsArchive: NCSessionArchive?

    /// The session's DNS history in /hark/logs shape (oldest first), when archiving is on.
    func dnsHistory() -> (seq: UInt64, lines: [[String: Any]])? {
        guard let a = dnsArchive else { return nil }
        return (UInt64(max(0, a.newestSeq)), a.readAll())
    }

    /// Wires StartupLog into the ring (once, at tunnel start).
    static func install() {
        NativeLogRing.shared.dnsArchive = NCSessionArchive(
            url: AppShared.homeURL.appendingPathComponent("diag/session-dns.jsonl"))
        // fix/nc-mitm-live: the per-flow diagnostics limiter writes here
        NCDiagLimiter.shared.sink = { type, payload in NativeLogRing.shared.add(type: type, payload: payload) }
        StartupLog.tap = { tag, msg in
            let lvl = msg.contains("失败") || msg.lowercased().contains("error") ? "error"
                : (msg.contains("跳过") || msg.lowercased().contains("warn") ? "warning" : "info")
            NativeLogRing.shared.add(type: lvl, payload: tag == "ext" ? msg : "[\(tag)] \(msg)")
        }
    }

    func add(type: String, payload: String) {
        let p = payload.count > 2000 ? String(payload.prefix(2000)) + "…" : payload
        lock.lock()
        seq += 1
        let line = Line(seq: seq, time: Int64(Date().timeIntervalSince1970 * 1000), type: type, payload: p)
        general.append(line)
        if general.count > generalMax { general.removeFirst(general.count - generalMax) }
        lock.unlock()
        if p.hasPrefix("[DNS]") {
            dnsArchive?.append(["seq": Int64(line.seq), "time": line.time, "type": type, "payload": p])
        }
    }

    /// console.log & co from a script (also mirrored as a general line).
    func addScript(script: String, level: String, msg: String) {
        let m = msg.count > 2000 ? String(msg.prefix(2000)) + "…" : msg
        lock.lock()
        scriptSeq += 1
        if let last = scripts.last, last.script == script, last.level == level, last.msg == m {
            // fix/nc-mitm-live: repeats fold into the last line (×N on the 脚本日志 page); the new id makes `since` pollers see it
            var l = last
            l.count += 1
            l.id = scriptSeq
            l.time = Date().timeIntervalSince1970
            scripts[scripts.count - 1] = l
        } else {
            scripts.append(ScriptLine(id: scriptSeq, time: Date().timeIntervalSince1970, script: script, level: level, msg: m))
        }
        if scripts.count > scriptMax { scripts.removeFirst(scripts.count - scriptMax) }
        lock.unlock()
        add(type: level == "warn" ? "warning" : (level == "log" ? "info" : level), payload: "[Script] \(script): \(m)")
    }

    func since(_ s: UInt64) -> (seq: UInt64, lines: [Line]) {
        lock.lock(); defer { lock.unlock() }
        return (seq, general.filter { $0.seq > s })
    }

    func scriptLines(since s: Int64) -> [ScriptLine] {
        lock.lock(); defer { lock.unlock() }
        return scripts.filter { $0.id > s }
    }

    /// fix/nc-ctrl-bsd: writes the ring (≤ generalMax lines, oldest first) to `<home>/diag/core-log.txt`, plus the
    /// memory snapshot to `diag/memory.txt` when given — what 诊断包 reads. Nothing wrote these files in the native core
    /// (the old core's diag dump went away with it), so both sections were always empty. Returns the line count.
    @discardableResult
    func dumpDiagnostics(home: URL, memory: String? = nil) -> Int {
        let dir = home.appendingPathComponent("diag", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        lock.lock()
        let lines = general
        lock.unlock()
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "HH:mm:ss.SSS"
        var text = ""
        text.reserveCapacity(lines.count * 120)
        for l in lines {
            text += "\(f.string(from: Date(timeIntervalSince1970: Double(l.time) / 1000))) [\(l.type)] \(l.payload)\n"
        }
        try? Data(text.utf8).write(to: dir.appendingPathComponent("core-log.txt"), options: .atomic)
        if let memory { try? Data(memory.utf8).write(to: dir.appendingPathComponent("memory.txt"), options: .atomic) }
        return lines.count
    }

    func clearGeneral() { lock.lock(); general.removeAll(); lock.unlock(); dnsArchive?.reset() }
    func clearScripts() { lock.lock(); scripts.removeAll(); lock.unlock() }

    func addNotice(script: String, title: String, subtitle: String, body: String, url: String) {
        func cap(_ v: String) -> String { v.count > 1000 ? String(v.prefix(1000)) + "…" : v }
        lock.lock()
        notices.append(Notice(time: Date().timeIntervalSince1970, script: script, title: cap(title), subtitle: cap(subtitle),
                              body: cap(body), url: String(url.prefix(2000))))
        if notices.count > noticeMax { notices.removeFirst(notices.count - noticeMax) }
        lock.unlock()
    }

    /// Newest first, the App's ScriptNotice shape (subtitle / body / url omitted when empty).
    func noticesJSON() -> [[String: Any]] {
        lock.lock(); let list = notices; lock.unlock()
        return list.reversed().map { n in
            var o: [String: Any] = ["time": n.time, "script": n.script, "title": n.title]
            if !n.subtitle.isEmpty { o["subtitle"] = n.subtitle }
            if !n.body.isEmpty { o["body"] = n.body }
            if !n.url.isEmpty { o["url"] = n.url }
            return o
        }
    }
}
