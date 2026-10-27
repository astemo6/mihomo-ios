import CryptoKit
import Darwin
import Foundation
import Network

// nc-integrate merge: the stack-facing UDP session (NCUDPSession is tunnel-only) split out of Shared/NativeCore/NCHysteria1UDP.swift.

/// One stack UDP session over the shared Hysteria v1 connection.
final class NCUDPHysteria1Session: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private let proxy: NCProxy
    private let queue: DispatchQueue
    private var conn: NCHysteria1Connection?
    private var sid: UInt32?
    private var queued: [(Data, NCTarget)] = []
    private var acquiring = false
    private var cancelled = false

    init(proxy: NCProxy, queue: DispatchQueue) {
        self.proxy = proxy
        self.queue = queue
        acquire()
    }

    private func acquire() {
        guard !acquiring, !cancelled else { return }
        acquiring = true
        NCConnector.hysteria1Shared(proxy: proxy, queue: queue) { [weak self] c in
            guard let c else { self?.queue.async { self?.acquiring = false; self?.queued = [] }; return }
            c.queue.async {
                c.openUDP(handler: { [weak self] data in
                    self?.queue.async { if self?.cancelled == false { self?.onReply(data) } }
                }, completion: { [weak self] id in
                    self?.queue.async {
                        guard let self, let id, !self.cancelled else {
                            if let id { c.queue.async { c.closeUDP(id) } }
                            self?.acquiring = false
                            self?.queued = []
                            return
                        }
                        self.acquiring = false
                        self.conn = c
                        self.sid = id
                        let pending = self.queued
                        self.queued = []
                        for (d, t) in pending { self.send(d, to: t) }
                    }
                })
            }
        }
    }

    func send(_ data: Data, to target: NCTarget) {
        guard !cancelled else { return }
        if let c = conn, c.state == .failed || c.state == .closed { conn = nil; sid = nil }
        guard let c = conn, let id = sid else {
            if queued.count < 32 { queued.append((data, target)) }
            acquire()
            return
        }
        c.queue.async { c.sendUDP(id, target: target, payload: data) }
    }

    func cancel() {
        cancelled = true
        queued = []
        if let c = conn, let id = sid { c.queue.async { c.closeUDP(id) } }
        conn = nil
    }
}
