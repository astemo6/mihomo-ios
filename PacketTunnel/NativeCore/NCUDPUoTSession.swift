import Foundation

/// UDP-over-TCP v2 through any NCConnector stream (feat/nc-naive-h2h3): the association opens one proxied
/// stream to the UoT magic destination `sp.v2.udp-over-tcp.arpa:0`, writes the UoT request (isConnect = 0 +
/// the first target) and then exchanges UoT packets ([family][addr][port][len u16][payload]). Used by
/// NaïveProxy nodes with `udp-over-tcp: true` (sing-box naive `udp_over_tcp`; the sing-box naive inbound
/// routes through uot.NewRouter). The wire helpers are NCUoT (Shared/NativeCore/NCAnyTLS.swift).
final class NCUDPUoTSession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private var stream: NCRelayStream?
    private var pending: [(Data, NCTarget)] = []
    private var buffer = Data()
    private var requestWritten = false
    private var cancelled = false
    private let flowTarget: NCTarget
    private let queue: DispatchQueue

    init(proxy: NCProxy, target: NCTarget, queue: DispatchQueue) {
        flowTarget = target
        self.queue = queue
        NCConnector.connect(target: NCUoT.magicTarget, proxy: proxy, queue: queue) { [weak self] stream, _ in
            guard let self, !self.cancelled else { stream?.cancel(); return }
            guard let stream else { self.pending = []; return }
            self.stream = stream
            let queued = self.pending
            self.pending = []
            for (data, t) in queued { self.sendNow(data, to: t) }
            self.receiveLoop()
        }
    }

    private func receiveLoop() {
        stream?.receive { [weak self] data, _ in
            guard let self, !self.cancelled, let data else { return }
            self.buffer.append(data)
            while let (_, payload, consumed) = NCUoT.parsePacket(self.buffer) {
                self.buffer = consumed >= self.buffer.count ? Data() : Data(self.buffer.dropFirst(consumed))
                self.onReply(payload)
            }
            // A legal packet is <= 64 KB + header; more residue than that is a broken stream.
            if self.buffer.count > 128 * 1024 { self.cancel(); return }
            self.receiveLoop()
        }
    }

    func send(_ data: Data, to target: NCTarget) {
        guard !cancelled else { return }
        guard stream != nil else {
            if pending.count < 64 { pending.append((data, target)) }
            return
        }
        sendNow(data, to: target)
    }

    private func sendNow(_ data: Data, to target: NCTarget) {
        guard let stream else { return }
        if !requestWritten {
            requestWritten = true
            if let req = NCUoT.request(destination: flowTarget) { stream.send(req) }
        }
        if let pkt = NCUoT.packet(target: target, payload: data) { stream.send(pkt) }
    }

    func cancel() {
        cancelled = true
        pending = []
        stream?.cancel()
        stream = nil
    }
}
