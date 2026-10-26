import Foundation

/// GOST v3 relay UDP (feat/nc-gost-relay; mihomo transport/gost relayPacketConn): one relay connection per
/// stack UDP session, opened with CONNECT|UDP + network=udp toward the flow's target, then datagrams ride it
/// as LEN(BE16) ‖ payload in both directions. The association is bound to that one target, which matches the
/// data plane's one-session-per-flow model. Underlying tls / ws / mux come from NCConnector.gostRelayStream.
final class NCUDPGostRelaySession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private var stream: NCRelayStream?
    private var pending: [Data] = []
    private var dead = false
    private var cancelled = false
    private var buffer = Data()
    // Read offset into `buffer`, rebased once past halfway (same scheme as NCUDPVLESSSession).
    private var bufferOffset = 0
    private var buffered: Int { buffer.count - bufferOffset }

    init(proxy: NCProxy, target: NCTarget, queue: DispatchQueue) {
        NCConnector.gostRelayStream(proxy: proxy, target: target, udp: true, queue: queue,
                                    transport: nil) { [weak self] s, _ in
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
        stream.receive { [weak self] data, error in
            guard let self, !self.cancelled else { return }
            guard let data else { self.dead = true; return }
            self.buffer.append(data)
            while let (payload, consumed) = NCGostRelay.nextUDPFrame(self.buffer, at: self.bufferOffset) {
                self.bufferOffset += consumed
                self.onReply(payload)
            }
            self.compactBuffer()
            // nc-memory: a legal frame is <= 64 KB, so past 128 KB of residue the session is dead weight.
            if self.buffered > 128 * 1024 { self.cancel(); return }
            if error == nil { self.receiveLoop() }
        }
    }

    private func compactBuffer() {
        if bufferOffset == 0 { return }
        if bufferOffset >= buffer.count { buffer = Data(); bufferOffset = 0 }
        else if bufferOffset > buffer.count / 2 { buffer = Data(buffer.dropFirst(bufferOffset)); bufferOffset = 0 }
    }

    func send(_ data: Data, to target: NCTarget) {
        guard !dead, !cancelled, let framed = NCGostRelay.udpFrame(data) else { return }
        if let stream {
            stream.send(framed)
        } else if pending.count < 64 {
            pending.append(framed) // relay connection still opening
        }
    }

    func cancel() {
        cancelled = true
        pending = []
        stream?.cancel()
        stream = nil
    }
}
