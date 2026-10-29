import Foundation

/// feat/session-records (user 2026-10-29: 「连接/拦截记录、DNS 解析记录，单次连接一直保留待查，
/// 重连后才会归0」): an append-only JSONL archive for ONE connection session. The in-memory
/// rings (NCStatsRecorder's 300 closed connections, NativeLogRing's 400 lines) rotate within
/// minutes on a busy session, which made session totals outlive their own records (a rule's
/// hit count stayed while every connection behind it had rotated out of the drill-in list).
/// The archive keeps every record on disk for the whole session instead; it is truncated
/// only when a new session starts (fresh tunnel process / provider start, or the user's
/// 清零 reset) — reconnecting is what zeroes the records, exactly as specified.
///
/// One JSON object per line; every object carries its `seq` (Int64). An in-memory offset
/// index makes `read(afterSeq:)` a seek, not a scan. A hard size fuse stops appending on a
/// pathological session rather than filling the disk; the live rings still serve recent
/// records in that case.
final class NCSessionArchive {
    private let url: URL
    private let lock = NSLock()
    private var handle: FileHandle?
    private var offsets: [Int64] = [] // byte offset of each line, in append order
    private var endOffset: Int64 = 0
    private var lastSeq: Int64 = 0
    static let fuseBytes: Int64 = 256 * 1024 * 1024

    /// Creating an archive starts a fresh session: any previous session's file is truncated.
    init(url: URL) {
        self.url = url
        reset()
    }

    var count: Int { lock.lock(); defer { lock.unlock() }; return offsets.count }
    var newestSeq: Int64 { lock.lock(); defer { lock.unlock() }; return lastSeq }

    /// Start over (new session / user reset): truncate the file and the index.
    func reset() {
        lock.lock(); defer { lock.unlock() }
        handle?.closeFile()
        handle = nil
        offsets = []
        endOffset = 0
        lastSeq = 0
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: url.path, contents: nil)
        handle = try? FileHandle(forWritingTo: url)
        handle?.seekToEndOfFile()
    }

    /// Append one record. The record's `seq` must be non-decreasing across appends.
    func append(_ dict: [String: Any]) {
        guard let seq = (dict["seq"] as? NSNumber)?.int64Value,
              let data = try? JSONSerialization.data(withJSONObject: dict) else { return }
        lock.lock(); defer { lock.unlock() }
        guard let h = handle, endOffset < Self.fuseBytes else { return }
        var line = data
        line.append(0x0A)
        offsets.append(endOffset)
        h.write(line)
        endOffset += Int64(line.count)
        lastSeq = seq
    }

    /// Records with `seq > afterSeq`, NEWEST first, at most `limit`.
    func read(afterSeq: Int64, limit: Int) -> [[String: Any]] {
        lock.lock(); defer { lock.unlock() }
        guard limit > 0, let h = try? FileHandle(forReadingFrom: url) else { return [] }
        defer { h.closeFile() }
        var out: [[String: Any]] = []
        var i = offsets.count - 1
        while i >= 0, out.count < limit {
            let start = offsets[i]
            let end = (i + 1 < offsets.count) ? offsets[i + 1] : endOffset
            guard end > start else { i -= 1; continue }
            h.seek(toFileOffset: UInt64(start))
            let data = h.readData(ofLength: Int(end - start))
            if let obj = try? JSONSerialization.jsonObject(with: data), let dict = obj as? [String: Any] {
                let seq = (dict["seq"] as? NSNumber)?.int64Value ?? 0
                if seq <= afterSeq { break } // lines are seq-ordered: everything older is out too
                out.append(dict)
            }
            i -= 1
        }
        return out
    }

    /// Every record, OLDEST first (session history endpoints).
    func readAll() -> [[String: Any]] {
        read(afterSeq: 0, limit: Int.max).reversed()
    }
}
