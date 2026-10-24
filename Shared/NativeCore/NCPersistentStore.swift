import Foundation

/// Pure Swift persistent store backing $persistentStore / $prefs — Go's Store (bridge/mitm/store.go) ported:
/// a JSON object of strings in `<home>/engine/store.json` that the app can view and edit too.
///
///   - reads follow the file: when its modification date changed (the app's 持久化存储 editor, a restore) and this
///     process has no unflushed changes, it is re-read before answering;
///   - writes change memory at once and reach the file within `flushDelay` (coalesced);
///   - a flush whose file changed meanwhile re-reads it and re-applies only the keys this process changed, so
///     neither side's edits are lost;
///   - a file that exists but does not decode (twice, 50 ms apart — a writer may be mid-replace) is kept as
///     store.json.bad and never overwritten by an empty store.
public final class NCPersistentStore {
    public static let shared = NCPersistentStore()

    static var flushDelay: TimeInterval = 0.25

    private let lock = NSLock()
    private var data: [String: String]?
    private var mtime: Date?
    /// Keys changed since the last flush (nil value = deleted).
    private var pending: [String: String?] = [:]
    private var cleared = false
    private var timerArmed = false
    private let fileURL: URL
    private let queue = DispatchQueue(label: "nc.persistentstore", qos: .utility)

    init(homeURL: URL = AppShared.homeURL) {
        fileURL = homeURL.appendingPathComponent("engine/store.json")
    }

    /// Test hook: a store on any file.
    init(fileURL: URL) {
        self.fileURL = fileURL
    }

    // MARK: file

    private func modDate() -> Date? {
        (try? FileManager.default.attributesOfItem(atPath: fileURL.path)[.modificationDate]) as? Date
    }

    private enum ReadResult { case missing, ok([String: String], Date?), bad }

    private func readOnce() -> ReadResult {
        let fm = FileManager.default
        guard fm.fileExists(atPath: fileURL.path) else { return .missing }
        let mt = modDate()
        guard let raw = try? Data(contentsOf: fileURL) else { return .missing }
        if raw.isEmpty { return .ok([:], mt) }
        guard let obj = try? JSONSerialization.jsonObject(with: raw), let dict = obj as? [String: Any] else { return .bad }
        var out: [String: String] = [:]
        for (k, v) in dict {
            if let s = v as? String { out[k] = s } else if !(v is NSNull) { out[k] = "\(v)" }
        }
        return .ok(out, mt)
    }

    /// nil: the file is unreadable (quarantined); keep what is in memory.
    private func readFile() -> ReadResult {
        var r = readOnce()
        if case .bad = r {
            Thread.sleep(forTimeInterval: 0.05)
            r = readOnce()
            if case .bad = r {
                let bad = fileURL.appendingPathExtension("bad")
                try? FileManager.default.removeItem(at: bad)
                try? FileManager.default.moveItem(at: fileURL, to: bad)
            }
        }
        return r
    }

    /// Lock held. Re-reads the file when it changed and nothing of ours waits for a flush.
    private func loadLocked() {
        if data != nil && (!pending.isEmpty || cleared) { return }
        let mt = modDate()
        if data != nil && mt == mtime { return }
        switch readFile() {
        case .ok(let m, let d): data = m; mtime = d
        case .missing: if data == nil { data = [:] }; mtime = nil
        case .bad: if data == nil { data = [:] }
        }
    }

    // MARK: API

    public func read(key: String) -> String? {
        lock.lock(); defer { lock.unlock() }
        loadLocked()
        return data?[key]
    }

    @discardableResult
    public func write(key: String, value: String) -> Bool {
        lock.lock()
        loadLocked()
        data?[key] = value
        pending[key] = .some(value)
        lock.unlock()
        scheduleFlush()
        return true
    }

    @discardableResult
    public func delete(key: String) -> Bool {
        lock.lock()
        loadLocked()
        data?.removeValue(forKey: key)
        pending[key] = .some(nil)
        lock.unlock()
        scheduleFlush()
        return true
    }

    @discardableResult
    public func clear() -> Bool {
        lock.lock()
        data = [:]
        pending.removeAll()
        cleared = true
        lock.unlock()
        scheduleFlush()
        return true
    }

    /// Writes our changes, merged onto the file as it is now.
    public func flush() {
        lock.lock()
        defer { lock.unlock() }
        guard !pending.isEmpty || cleared else { return }
        var base = data ?? [:]
        if modDate() != mtime {
            // the app edited the file: its content + only the keys we changed
            switch readFile() {
            case .ok(let m, _): base = cleared ? [:] : m
            case .missing: base = [:]
            case .bad: break // keep memory; the bad file was moved aside
            }
            for (k, v) in pending {
                if let v { base[k] = v } else { base.removeValue(forKey: k) }
            }
        }
        do {
            try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            let raw = try JSONSerialization.data(withJSONObject: base, options: [.sortedKeys])
            try raw.write(to: fileURL, options: .atomic)   // unique temp file + rename (never a shared .tmp)
            data = base
            mtime = modDate()
            pending.removeAll()
            cleared = false
        } catch {
            StartupLog.write("persistent store: write failed: \(error.localizedDescription)")
        }
    }

    private func scheduleFlush() {
        lock.lock()
        let arm = !timerArmed
        timerArmed = true
        lock.unlock()
        guard arm else { return }
        queue.asyncAfter(deadline: .now() + Self.flushDelay) { [weak self] in
            guard let self else { return }
            self.lock.lock(); self.timerArmed = false; self.lock.unlock()
            self.flush()
        }
    }
}
