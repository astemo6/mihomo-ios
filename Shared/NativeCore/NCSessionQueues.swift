import Foundation
import os

/// Shared sessions (Mux / AnyTLS / SSH) each own a serial queue so every piece of session and stream state is
/// touched on exactly one queue, no matter which caller (data plane, local proxy, upstream connector, health
/// check) drives the stream. All session queues target one shared concurrent queue: a session gets its own
/// serial execution context without dedicating a thread per session (sessions are few, streams are many).
enum NCSessionQueues {
    static let target = DispatchQueue(label: "nc.session.target", attributes: .concurrent)

    static func make(_ label: String) -> DispatchQueue {
        let q = DispatchQueue(label: label, target: target)
        q.setSpecific(key: specificKey, value: q)
        return q
    }

    private static let specificKey = DispatchSpecificKey<DispatchQueue>()

    /// True when the caller is already running on `queue` itself (each session queue marks itself with its own
    /// identity — being on *another* session's queue, e.g. an SSH client chained over a mux stream, still hops).
    static func isCurrent(_ queue: DispatchQueue) -> Bool {
        DispatchQueue.getSpecific(key: specificKey) === queue
    }
}

/// Runs `work` on `queue`: inline when already on that queue, asynchronously otherwise. Session queues
/// are the only places session/stream state may change; callers on any other queue hop exactly once.
func ncOnSessionQueue(_ queue: DispatchQueue, _ work: @escaping () -> Void) {
    if NCSessionQueues.isCurrent(queue) { work() } else { queue.async(execute: work) }
}

/// A completion that fires exactly once, on whichever path reaches it first (success, failure, cancel,
/// session teardown). Send completions are a liveness contract: a caller waiting for one before reading more
/// (uplink back-pressure) hangs forever if it is dropped, and corrupts its accounting if it fires twice.
final class NCOnceCompletion {
    private let fired = OSAllocatedUnfairLock(initialState: false)
    private let body: () -> Void

    init(_ body: @escaping () -> Void) { self.body = body }

    func call() {
        let first: Bool = fired.withLock { done in
            if done { return false }
            done = true
            return true
        }
        guard first else { return }
        body()
    }
}

extension NCRelayStream {
    /// Hands `data` to this stream and calls `completion` once the stream's own send completion fires.
    /// Since the nc-sessions-flow protocol promotion, every NCRelayStream implements
    /// send(_:completion:) for real (NCStream waits for .contentProcessed), so this is a direct
    /// delegation — kept as one spelling for the session-owned streams' base writes.
    func ncSend(_ data: Data, completion: @escaping () -> Void) {
        send(data, completion: completion)
    }
}

/// Pending send-completion bookkeeping shared by the multiplexed streams: each entry covers `count` bytes of
/// the stream's pending-send buffer, in order; an entry's completion fires once those bytes have been flushed
/// to the base stream and the base send completed. Only touched on the owning session's queue.
struct NCPendingSendEntry {
    var count: Int
    let once: NCOnceCompletion?
}

enum NCPendingSends {
    /// Splits `entries` at `consumed` bytes: returns the completions whose bytes are fully flushed and the
    /// entries that remain pending (the first remaining entry shrunk by the partial flush).
    static func split(_ entries: [NCPendingSendEntry], consumed: Int) -> (done: [NCOnceCompletion], rest: [NCPendingSendEntry]) {
        var done: [NCOnceCompletion] = []
        var rest: [NCPendingSendEntry] = []
        var left = consumed
        for entry in entries {
            if left >= entry.count {
                left -= entry.count
                if let once = entry.once { done.append(once) }
            } else if left > 0 {
                var shrunk = entry
                shrunk.count -= left
                left = 0
                rest.append(shrunk)
            } else {
                rest.append(entry)
            }
        }
        return (done, rest)
    }

    static func fireAll(_ entries: [NCPendingSendEntry]) {
        for entry in entries { entry.once?.call() }
    }
}
