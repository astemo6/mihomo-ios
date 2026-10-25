import Foundation
import os

/// Send-side flow control for relays (rv2-life, merged into NCRelayStream by nc-sessions-flow):
/// `send(_:completion:)` calls `completion` once the bytes left our hands (handed to the kernel socket
/// for an NWConnection, encoded and accepted by the layer below for a protocol wrapper), so a pump can
/// wait for it before reading more from the other side — the back-pressure that keeps a fast sender
/// from piling megabytes into NWConnection's send queue.
extension NCStream {
    func send(_ data: Data, completion: @escaping () -> Void) {
        guard !data.isEmpty else { queue.async(execute: completion); return }
        // After cancel() NWConnection completes the send with an error at once: the caller still gets its callback.
        conn.send(content: data, completion: .contentProcessed { _ in completion() })
    }
}

enum NCRelayFlow {
    /// Sends `data` on `relay`; `done` runs on `queue` once the relay's send completion fires
    /// (every NCRelayStream now reports one — see the protocol in NCConnector.swift).
    static func send(_ relay: NCRelayStream, _ data: Data, queue: DispatchQueue, done: @escaping () -> Void) {
        relay.send(data) { queue.async(execute: done) }
    }
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
