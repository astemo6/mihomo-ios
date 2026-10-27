import Foundation

/// TrustTunnel UDP for one tunnel UDP flow (fix/nc-trusttunnel-h3): a `_udp2` CONNECT stream on the node's
/// shared H2 or H3 session (NCTrustTunnelSessionManager.udpStream), datagrams framed per spec §6.3 / §6.4.
/// The stream is message oriented: one send = one UDP datagram, one receive = one reply. 需同步 feat/nc-kernel.
final class NCUDPTrustTunnelSession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private var stream: NCRelayStream?
    private var pending: [Data] = []
    private var dead = false
    private var cancelled = false

    init(proxy: NCProxy, target: NCTarget, queue: DispatchQueue) {
        if NCSupport.trusttunnelUnsupported(proxy) != nil {
            dead = true
            return
        }
        NCTrustTunnelSessionManager.udpStream(proxy: proxy, target: target, queue: queue) { [weak self] s, _ in
            guard let self, !self.cancelled else { s?.cancel(); return }
            guard let s else { self.dead = true; self.pending = []; return }
            self.stream = s
            let queued = self.pending
            self.pending = []
            for d in queued { s.send(d) }
            self.receiveLoop()
        }
    }

    private func receiveLoop() {
        guard let stream else { return }
        stream.receive { [weak self] data, _ in
            guard let self, !self.cancelled else { return }
            guard let data else { self.dead = true; return }
            if !data.isEmpty { self.onReply(data) }
            self.receiveLoop()
        }
    }

    /// The flow is bound to its first target (the data plane opens one session per target).
    func send(_ data: Data, to target: NCTarget) {
        guard !dead, !cancelled, !data.isEmpty else { return }
        if let stream {
            stream.send(data)
        } else if pending.count < 32 {
            pending.append(data) // _udp2 stream still opening
        }
    }

    func cancel() {
        cancelled = true
        pending = []
        stream?.cancel()
        stream = nil
    }
}
