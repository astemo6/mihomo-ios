import Foundation

// fix/nc-ui-smooth (user 2026-10-27 「切换动作的过渡要流畅」): helpers that keep work and update storms off the frames.

/// Collects stream items (log lines, DNS answers) and hands them to the page at most every `intervalMs` (default
/// 100 ms = ≤ 10 updates a second). A debug-level /logs stream can deliver hundreds of lines a second; publishing each
/// one re-rendered a 1000–2000 row list per line, so scrolling, pushing or switching tabs while it ran dropped frames.
/// Order is kept; nothing is dropped here (the receiver keeps its own cap).
@MainActor
final class UIBatcher<T> {
    private var pending: [T] = []
    private var scheduled = false
    private let intervalNs: UInt64
    private let cap: Int
    private let flush: ([T]) -> Void
    /// Bumped by reset(); a flush scheduled before it does nothing.
    private var generation = 0

    /// `cap` bounds what waits between two flushes (the oldest are dropped first, as the receiver's own cap would).
    init(intervalMs: UInt64 = 100, cap: Int = 5000, flush: @escaping ([T]) -> Void) {
        self.intervalNs = intervalMs * 1_000_000
        self.cap = max(1, cap)
        self.flush = flush
    }

    func add(_ item: T) {
        pending.append(item)
        if pending.count > cap { pending.removeFirst(pending.count - cap) }
        guard !scheduled else { return }
        scheduled = true
        let ns = intervalNs, gen = generation
        Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: ns)
            guard let self, self.generation == gen else { return }
            self.drain()
        }
    }

    /// Hands over whatever is waiting now.
    func drain() {
        scheduled = false
        guard !pending.isEmpty else { return }
        let batch = pending
        pending = []
        flush(batch)
    }

    /// Drops whatever is waiting (清空 / stop).
    func reset() {
        generation &+= 1
        scheduled = false
        pending = []
    }

    var pendingCount: Int { pending.count }
}

/// One serial utility queue for small settings writes that used to run on the main thread inside a tap (出站模式,
/// the live node selection kept for the next connect). Serial, so two quick taps are written in tap order.
enum UIBackgroundIO {
    private static let queue = DispatchQueue(label: "tern.ui-background-io", qos: .userInitiated)

    /// Fire and forget, in call order.
    static func run(_ work: @escaping @Sendable () -> Void) {
        queue.async(execute: work)
    }

    /// Runs `work` on the serial queue and resumes when it is done (in call order with `run`).
    static func perform<R: Sendable>(_ work: @escaping @Sendable () -> R) async -> R {
        await withCheckedContinuation { (c: CheckedContinuation<R, Never>) in
            queue.async { c.resume(returning: work()) }
        }
    }
}

/// The 测速 settings every delay row needs (URL, timeout, 直连测试地址, TCP 握手延迟), cached by the stat of
/// overrides.json. Each read used to be a full CoreOverrides.load(): the cross-process flock, overrides.json and
/// secrets.json read and JSON-decoded twice, plus a re-encode for the merge base. NodeSettingsStore.testURL(for:) — called
/// for every member cell on every render of 策略 / 首页 picker / 节点 to read the delay for the right URL — paid that
/// per cell, many times a second during a streamed group 测速. A write by anyone (this app, the widget, the tunnel,
/// a restore) replaces the file atomically, which changes its inode / size / mtime, so the next read reloads.
enum TestSettingsCache {
    struct Values: Equatable {
        let url: String
        let timeoutMs: Int
        let directURL: String?
        let tcpHandshake: Bool
    }

    struct Stamp: Equatable {
        let path: String
        let exists: Bool
        let inode: UInt64
        let size: Int64
        let mtimeSec: Int
        let mtimeNsec: Int
    }

    private static let lock = NSLock()
    private static var cached: (stamp: Stamp, values: Values)?

    static func stamp(_ url: URL) -> Stamp {
        var st = stat()
        guard lstat(url.path, &st) == 0 else { // overrides.json is a plain file (atomic replace), never a symlink
            return Stamp(path: url.path, exists: false, inode: 0, size: 0, mtimeSec: 0, mtimeNsec: 0)
        }
        return Stamp(path: url.path, exists: true, inode: UInt64(st.st_ino), size: Int64(st.st_size),
                     mtimeSec: Int(st.st_mtimespec.tv_sec), mtimeNsec: Int(st.st_mtimespec.tv_nsec))
    }

    static func values(_ o: CoreOverrides) -> Values {
        let url = CoreOverrides.isValidTestURL(o.testURL) ? o.testURL.trimmingCharacters(in: .whitespaces) : CoreOverrides.defaultTestURL
        let d = o.directTestURL.trimmingCharacters(in: .whitespaces)
        return Values(url: url, timeoutMs: min(max(o.testTimeoutMs, 1000), 30000),
                      directURL: !d.isEmpty && CoreOverrides.isValidTestURL(d) ? d : nil,
                      tcpHandshake: o.tcpHandshakeDelay)
    }

    static var current: Values {
        let file = CoreOverrides.overridesFile
        let before = stamp(file)
        lock.lock()
        if let c = cached, c.stamp == before { lock.unlock(); return c.values }
        lock.unlock()
        let v = values(CoreOverrides.load())
        // Cached only when the file did not change during the load (load() itself may migrate and rewrite it once).
        let after = stamp(file)
        lock.lock()
        cached = after == before ? (after, v) : nil
        lock.unlock()
        return v
    }

    /// Unit tests.
    static func invalidate() {
        lock.lock(); cached = nil; lock.unlock()
    }
}
