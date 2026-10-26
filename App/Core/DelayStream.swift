import Foundation

// fix/app-policy-ui #2 (user 2026-10-26 「策略组测速比其他 App 慢」): a group 测速 used to hand the page one dictionary
// after EVERY member had answered, so the whole group waited for the slowest node or the timeout (and the App's
// URLSession allowed only 4 requests to the controller at once). Surge / Loon / Egern fill in each node the moment
// its probe returns. Now:
//   • DelayStream.run — sliding window (a new member starts as soon as one finishes, never more than `width` at
//     once) that reports every result in the order they land;
//   • DelayStreamBuffer — coalesces those results onto the page (one publish per ~120 ms, not one per node, so a
//     200-node group does not re-render the policy page 200 times);
//   • the previous result of a node stays on screen until its new one arrives (nothing is cleared at the start).

enum DelayStream {
    /// Members tested at once by a group 测速 through the running core (was 10 behind a 4-connection URLSession).
    static let groupWidth = 30

    /// Runs `run` for every name with at most `width` in flight and hands each result to `onResult` as it lands
    /// (finish order, not list order). Returns when every name has been run.
    static func run<R: Sendable>(_ names: [String], width: Int,
                                 run: @escaping (String) async -> R,
                                 onResult: (R) async -> Void) async {
        guard !names.isEmpty else { return }
        let w = max(1, width)
        await withTaskGroup(of: R.self) { tg in
            var next = 0
            while next < min(w, names.count) {
                let name = names[next]
                next += 1
                tg.addTask { await run(name) }
            }
            while let r = await tg.next() {
                await onResult(r)
                if next < names.count {
                    let name = names[next]
                    next += 1
                    tg.addTask { await run(name) }
                }
            }
        }
    }
}

/// Collects streamed delay results and publishes them in small batches on the main actor.
@MainActor
final class DelayStreamBuffer {
    private var pending: [String: Int] = [:]
    private var scheduled = false
    private let intervalNs: UInt64
    private let flush: ([String: Int]) -> Void

    init(intervalMs: UInt64 = 120, flush: @escaping ([String: Int]) -> Void) {
        self.intervalNs = intervalMs * 1_000_000
        self.flush = flush
    }

    /// One result; the first of a batch schedules the publish.
    func add(_ name: String, _ ms: Int) {
        pending[name] = ms
        guard !scheduled else { return }
        scheduled = true
        let ns = intervalNs
        Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: ns)
            self?.drain()
        }
    }

    /// Publishes whatever is pending now (also called once the whole test finished).
    func drain() {
        scheduled = false
        guard !pending.isEmpty else { return }
        let batch = pending
        pending = [:]
        flush(batch)
    }
}
