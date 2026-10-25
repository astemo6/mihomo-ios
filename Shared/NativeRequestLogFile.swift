// NativeCore (feat/native-core-eval, gap C4) — MitM request records in the App Group (astemo6/Muse NativeCore,
// 2026-10-25).
//
// The Go-free tunnel has no Go request log for the app to query, so the tunnel appends each FINISHED request as one
// JSON line to a two-segment ring in the App Group container: mitm-requests.jsonl (current) and
// mitm-requests.prev.jsonl (the segment before). When the current segment passes `segmentMax` it becomes .prev
// (the old .prev is dropped), so the ring holds at most 2 × segmentMax on disk and nothing in memory.
// One write(2) with O_APPEND per line (the StartupLog pattern), so a reader in the app never sees half a line
// replaced — at worst a final partial line, which is skipped.
//
// Line format = the controller's /mitm/requests/{id} detail (keys of the app's HTTPRequestDetail, which decodes
// HTTPRequestSummary from the same object). The app reads this file when the controller is not reachable (tunnel
// off / restarting); while it runs the tunnel's controller serves the same records plus the open ones.
//
// Shared by the app and the tunnel; pure Foundation.

import Foundation
import Darwin

struct NativeRequestLogEntry: Codable {
    var id: Int64
    var time: Double
    var method: String
    var url: String
    var host: String
    var mitm: Bool = true
    var status: Int = 0
    var matched: [String]?
    var notes: [String]?
    var local: Bool?
    var done: Bool = false
    var duration: Double?
    var bytes: Int64 = 0
    var reqHeaders: [String: String]?
    var respHeaders: [String: String]?
    var respBody: String?
    var respBodyLength: Int?

    /// The list form (no headers / body): what /mitm/requests returns.
    var summary: NativeRequestLogEntry {
        var s = self
        s.reqHeaders = nil
        s.respHeaders = nil
        s.respBody = nil
        s.respBodyLength = nil
        return s
    }
}

enum NativeRequestLogFile {
    static let segmentMax: off_t = 256 * 1024
    static var url: URL { AppShared.containerURL.appendingPathComponent("mitm-requests.jsonl") }
    static var previousURL: URL { AppShared.containerURL.appendingPathComponent("mitm-requests.prev.jsonl") }
    private static let lock = NSLock()

    /// Appends one finished entry (tunnel).
    static func append(_ e: NativeRequestLogEntry) {
        guard var line = try? JSONEncoder().encode(e) else { return }
        line.append(0x0A)
        lock.lock(); defer { lock.unlock() }
        let path = url.path
        var st = stat()
        if stat(path, &st) == 0, st.st_size + off_t(line.count) > segmentMax {
            unlink(previousURL.path)
            rename(path, previousURL.path)
        }
        let fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0o644)
        guard fd >= 0 else { return }
        defer { close(fd) }
        _ = line.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
    }

    /// Removes both segments (the request page's 清空).
    static func clear() {
        lock.lock(); defer { lock.unlock() }
        unlink(url.path)
        unlink(previousURL.path)
    }

    /// Every complete line, oldest first, as raw JSON objects (both segments).
    static func lines() -> [Data] {
        var out: [Data] = []
        for u in [previousURL, url] {
            guard let d = try? Data(contentsOf: u, options: .mappedIfSafe), !d.isEmpty else { continue }
            var start = d.startIndex
            while start < d.endIndex, let nl = d[start...].firstIndex(of: 0x0A) {
                if nl > start { out.append(Data(d[start..<nl])) }
                start = d.index(after: nl)
            }
        }
        return out
    }

    /// Entries with id > since, oldest first, at most `limit` (the newest are kept).
    static func entries(since: Int64 = 0, limit: Int = 500) -> [NativeRequestLogEntry] {
        let dec = JSONDecoder()
        var out = lines().compactMap { try? dec.decode(NativeRequestLogEntry.self, from: $0) }.filter { $0.id > since }
        if out.count > limit { out.removeFirst(out.count - limit) }
        return out
    }

    /// One entry's full record (newest line wins).
    static func entry(id: Int64) -> NativeRequestLogEntry? {
        let dec = JSONDecoder()
        let needle = Data("{\"id\":\(id),".utf8)
        for l in lines().reversed() where l.starts(with: needle) || l.range(of: Data("\"id\":\(id),".utf8)) != nil {
            if let e = try? dec.decode(NativeRequestLogEntry.self, from: l), e.id == id { return e }
        }
        return nil
    }
}
