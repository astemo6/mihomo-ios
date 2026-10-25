import Foundation
import Network

// nc-integrate merge: the stack-facing UDP session (NCUDPSession is tunnel-only) split out of Shared/NativeCore/NCTUICUDP.swift.

/// One stack UDP session over the shared TUIC connection (NCConnector.tuicShared).
final class NCUDPTUICSession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private let queue: DispatchQueue
    private var conn: NCTUICConnection?
    private var assoc: UInt16?
    private var defrag = NCTUICUDP.Defragger()
    private var queued: [(Data, NCTarget)] = []
    private var cancelled = false

    private let proxy: NCProxy
    private var acquiring = false

    init(proxy: NCProxy, queue: DispatchQueue) {
        self.queue = queue
        self.proxy = proxy
        acquire()
    }

    /// Gets (or re-gets, after the shared connection died) the TUIC connection and an association id on it.
    private func acquire() {
        guard !acquiring, !cancelled else { return }
        acquiring = true
        NCConnector.tuicShared(proxy: proxy, queue: queue) { [weak self] c in
            guard let c else { self?.queue.async { self?.acquiring = false; self?.queued = [] }; return }
            c.queue.async {
                let id = c.registerUDP { [weak self] raw in
                    // Connection queue → session queue.
                    self?.queue.async { self?.receive(raw) }
                }
                let back: () -> Void = { [weak self] in
                    guard let self, let id, !self.cancelled else {
                        if let id { c.queue.async { c.unregisterUDP(id) } }
                        self?.acquiring = false
                        return
                    }
                    self.acquiring = false
                    self.conn = c
                    self.assoc = id
                    let pending = self.queued
                    self.queued = []
                    for (d, t) in pending { self.send(d, to: t) }
                }
                self?.queue.async(execute: back)
            }
        }
    }

    private func receive(_ raw: Data) {
        guard !cancelled, let p = NCTUICUDP.decode(raw), let out = defrag.feed(p) else { return }
        onReply(out)
    }

    func send(_ data: Data, to target: NCTarget) {
        guard !cancelled else { return }
        if let c = conn, c.state == .failed || c.state == .closed {
            conn = nil; assoc = nil
            defrag.reset()
        }
        guard let c = conn, let id = assoc else {
            if queued.count < 32 { queued.append((data, target)) }
            acquire()
            return
        }
        c.queue.async { c.sendUDP(assoc: id, target: target, payload: data) }
    }

    func cancel() {
        cancelled = true
        queued = []
        defrag.reset()
        if let c = conn, let id = assoc { c.queue.async { c.unregisterUDP(id) } }
        conn = nil
    }
}
