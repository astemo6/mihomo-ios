import Foundation
import Network

/// One stack UDP session over a Juicity UDP stream (carried on the shared NCJuicityConnection).
/// Each source address triplet (<source IP, source port, UDP>) from the tun interface is carried
/// on its own bidirectional QUIC stream, with NAT timeout lifecycle managed by NCDataPlane.
final class NCUDPJuicitySession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private let queue: DispatchQueue
    private let proxy: NCProxy
    private let target: NCTarget
    private var stream: NCJuicityUDPStream?
    private var conn: NCJuicityConnection?
    private var queued: [(Data, NCTarget)] = []
    private var cancelled = false
    private var acquiring = false

    init(proxy: NCProxy, target: NCTarget, queue: DispatchQueue) {
        self.queue = queue
        self.proxy = proxy
        self.target = target
        acquire()
    }

    /// Acquires (or re-acquires after connection death) the shared Juicity connection
    /// and opens a UDP stream with the initial target.
    private func acquire() {
        guard !acquiring, !cancelled else { return }
        acquiring = true
        NCConnector.juicityShared(proxy: proxy, queue: queue) { [weak self] c in
            guard let self else { return }
            guard let c, c.isAlive else {
                self.queue.async {
                    self.acquiring = false
                    self.queued = []
                }
                return
            }
            self.conn = c
            if let udp = c.openUDP(firstTarget: self.target, callerQueue: self.queue) {
                self.stream = udp
                udp.onReply = { [weak self] payload in
                    self?.onReply(payload)
                }
                udp.onClosed = { [weak self, weak udp] in
                    // Peer ended this triplet's stream: the next send opens a new one.
                    guard let self, let udp, self.stream === udp else { return }
                    self.stream = nil
                }
                self.acquiring = false
                let pending = self.queued
                self.queued = []
                for (d, t) in pending {
                    udp.send(d, to: t)
                }
            } else {
                self.acquiring = false
                self.queued = []
            }
        }
    }

    func send(_ data: Data, to target: NCTarget) {
        guard !cancelled else { return }
        if let c = conn, c.state == .failed || c.state == .closed {
            conn = nil
            stream = nil
        }
        guard let s = stream else {
            if queued.count < 64 { queued.append((data, target)) }
            acquire()
            return
        }
        s.send(data, to: target)
    }

    func cancel() {
        cancelled = true
        queued = []
        stream?.cancel()
        stream = nil
        conn = nil
    }
}
