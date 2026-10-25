import Foundation
import os

/// rv2-life: send-side flow control for relays. `send(_:completion:)` calls `completion` once the bytes left our
/// hands (handed to the kernel socket for an NWConnection), so a pump can wait for it before reading more from the
/// other side — the back-pressure that keeps a fast sender from piling megabytes into NWConnection's send queue.
///
/// NCStream (DIRECT and MitM-front relays) conforms here. Protocol wrappers (SS / VMess / Trojan / … relay streams,
/// Shared/NativeCore) do not yet: for them `NCRelayFlow.send` completes on the next queue turn, i.e. the old
/// unbounded behaviour. A wrapper adopts it by encoding and forwarding its raw stream's completion.
protocol NCRelayFlowControl: AnyObject {
    func send(_ data: Data, completion: @escaping () -> Void)
}

extension NCStream: NCRelayFlowControl {
    func send(_ data: Data, completion: @escaping () -> Void) {
        guard !data.isEmpty else { queue.async(execute: completion); return }
        // After cancel() NWConnection completes the send with an error at once: the caller still gets its callback.
        conn.send(content: data, completion: .contentProcessed { _ in completion() })
    }
}

enum NCRelayFlow {
    /// Sends `data` on `relay`; `done` runs on `queue` once the relay accepted it (see NCRelayFlowControl).
    static func send(_ relay: NCRelayStream, _ data: Data, queue: DispatchQueue, done: @escaping () -> Void) {
        if let fc = relay as? NCRelayFlowControl {
            fc.send(data) { queue.async(execute: done) }
        } else {
            relay.send(data)
            queue.async(execute: done)
        }
    }

    /// Whether `relay` really pushes back (false: the fallback above, which only yields a queue turn).
    static func hasFlowControl(_ relay: NCRelayStream?) -> Bool { relay is NCRelayFlowControl }
}

/// rv2-life: the global budget for bytes the data plane / local proxy hold for slow peers (TUN outboxes + pre-connect
/// buffers), tied to memory pressure. With the native memory governor running its level decides; otherwise
/// os_proc_available_memory (0 = not a memory-limited process: the app / simulator → the normal budget).
/// Per-connection caps stay in force at every level; this one stops the sum from growing with the connection count.
enum NCBufferBudget {
    static let normal = 4 << 20
    static let elevated = 2 << 20
    static let high = 1 << 20
    static let critical = 256 << 10

    static func current() -> Int {
        if let g = NativeMemoryGovernor.active {
            switch g.currentLevel {
            case .normal: return normal
            case .elevated: return elevated
            case .high: return high
            case .critical: return critical
            }
        }
        let avail = os_proc_available_memory()
        guard avail > 0 else { return normal }
        // same steps as the governor's default levels (14 / 9 / 5 MB available)
        if avail < 5 << 20 { return critical }
        if avail < 9 << 20 { return high }
        if avail < 14 << 20 { return elevated }
        return normal
    }
}
