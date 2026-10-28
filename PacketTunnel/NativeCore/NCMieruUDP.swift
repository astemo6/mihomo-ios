import CommonCrypto
import CryptoKit
import Foundation

// nc-integrate merge: the stack-facing UDP session (NCUDPSession is tunnel-only) split out of Shared/NativeCore/NCMieru.swift.

/// UDP over a mieru session (Clash.Meta: UDP ASSOCIATE session → PacketOverStreamTunnel → UDPAssociateWrapper):
/// each datagram = 0x00 ‖ len(2) ‖ [00 00 00 ‖ ATYP ADDR PORT ‖ payload] ‖ 0xFF.
final class NCUDPMieruSession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private var stream: NCRelayStream?
    private var pending: [(Data, NCTarget)] = []
    private var buffer = [UInt8]()
    private var cancelled = false

    init(proxy: NCProxy, target: NCTarget, queue: DispatchQueue) {
        NCConnector.mieruStream(proxy: proxy, target: target, udp: true, queue: queue, transport: nil) { [weak self] s, _ in
            guard let self else { s?.cancel(); return }
            guard let s, !self.cancelled else { s?.cancel(); return }
            self.stream = s
            for (d, t) in self.pending { self.sendNow(d, to: t) }
            self.pending = []
            self.receiveLoop()
        }
    }

    private func receiveLoop() {
        stream?.receive { [weak self] data, _ in
            guard let self, !self.cancelled, let data else { return }
            self.buffer.append(contentsOf: data)
            self.parse()
            self.receiveLoop()
        }
    }

    private func parse() {
        var off = 0
        while buffer.count - off >= 4 {
            guard buffer[off] == 0x00 else { cancel(); return }
            let len = Int(buffer[off + 1]) << 8 | Int(buffer[off + 2])
            guard buffer.count - off >= 3 + len + 1 else { break }
            guard buffer[off + 3 + len] == 0xff else { cancel(); return }
            let pkt = Array(buffer[(off + 3)..<(off + 3 + len)])
            off += 4 + len
            // UDP associate header: RSV RSV FRAG ATYP ADDR PORT (IP only from the server).
            guard pkt.count > 6, pkt[0] == 0, pkt[1] == 0, pkt[2] == 0 else { continue }
            var h: Int
            switch pkt[3] {
            case 0x01: h = 4 + 4 + 2
            case 0x04: h = 4 + 16 + 2
            default: continue
            }
            guard pkt.count >= h else { continue }
            onReply(Data(pkt[h...]))
        }
        if off > 0 { buffer.removeFirst(off) }
    }

    func send(_ data: Data, to target: NCTarget) {
        guard !cancelled else { return }
        if stream == nil { if pending.count < 32 { pending.append((data, target)) }; return }
        sendNow(data, to: target)
    }

    private func sendNow(_ data: Data, to target: NCTarget) {
        guard let addr = target.atypEncoded else { return }
        var inner = Data([0, 0, 0])
        inner.append(addr)
        inner.append(data)
        guard inner.count <= 65535 else { return }
        var frame = Data([0x00, UInt8(inner.count >> 8), UInt8(inner.count & 0xff)])
        frame.append(inner)
        frame.append(0xff)
        stream?.send(frame)
    }

    func cancel() {
        guard !cancelled else { return }
        cancelled = true
        stream?.cancel()
        stream = nil
        pending = []
    }
}
