import Foundation
import Network

// feat/nc-brook: the stack-facing UDP sessions for brook nodes (NCUDPSession is tunnel-only; the codecs and the
// dialers live in Shared/NativeCore/NCBrook.swift). One association per app flow / destination, exactly the
// path brook's own CreateExchanger takes:
//   server                     → UDP packets to the server (NCUDPBrookPacketSession)
//   server + udp-over-tcp      → a brook stream with the odd (UDP) request time, one frame per datagram
//   wsserver / wssserver       → the same stream over the upgraded ws / wss connection
//   quicserver                 → QUIC datagrams on a per-association QUIC connection (≤ 1197 bytes)
//   quicserver + udp-over-stream → the stream over a QUIC stream on the node's shared connection
enum NCUDPBrook {
    static func make(proxy: NCProxy, target: NCTarget, queue: DispatchQueue) -> NCUDPSession? {
        guard let o = NCBrookOptions(proxy: proxy), target.isWireEncodable else { return nil }
        switch o.kind {
        case .server where o.udpUsesPackets:
            return NCUDPBrookPacketSession(options: o, queue: queue)
        case .quicserver where o.udpUsesPackets:
            return NCUDPBrookQUICDatagramSession(options: o, queue: queue)
        default:
            return NCUDPBrookStreamSession(options: o, target: target, queue: queue)
        }
    }
}

/// brook server UDP: every datagram is an independent sealed packet (fresh nonce + key) to the server's UDP port.
final class NCUDPBrookPacketSession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private let options: NCBrookOptions
    private let conn: NWConnection
    private var cancelled = false
    private var dropLogged = false

    init(options: NCBrookOptions, queue: DispatchQueue) {
        self.options = options
        conn = NWConnection(to: NCStream.endpoint(options.server, port: options.port),
                            using: NCOutboundBinding.params(.udp, host: options.server))
        conn.stateUpdateHandler = { [weak self] state in
            if case .ready = state { self?.receiveLoop() }
        }
        conn.start(queue: queue)
    }

    private func receiveLoop() {
        conn.receiveMessage { [weak self] data, _, _, error in
            guard let self, !self.cancelled else { return }
            if let data {
                if let payload = self.options.decodePacket(data) {
                    self.onReply(payload)
                } else if !self.dropLogged {
                    self.dropLogged = true
                    NSLog("[NCUDPBrook] dropped undecodable brook UDP reply (%d bytes); further drops silent", data.count)
                }
            }
            if error == nil { self.receiveLoop() }
        }
    }

    func send(_ data: Data, to target: NCTarget) {
        guard !cancelled, let dst = target.atypEncoded,
              let packet = options.encodePacket(dst: dst, payload: data) else { return }
        conn.send(content: packet, completion: .idempotent)
    }

    func cancel() {
        cancelled = true
        conn.cancel()
    }
}

/// UDP over a brook stream (udp-over-tcp, ws / wss, quic + udp-over-stream): a dedicated stream whose request
/// carries the odd timestamp and this association's destination; each frame is one datagram both ways.
final class NCUDPBrookStreamSession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private let codec: NCBrookCodec?
    private var pipe: NCRelayStream?
    private var pending: [Data] = []
    private var dead = false
    private var cancelled = false

    /// nc-memory: same pre-connect queue cap as the other stream-backed UDP sessions.
    static let maxPending = 64

    init(options: NCBrookOptions, target: NCTarget, queue: DispatchQueue) {
        codec = target.atypEncoded.flatMap { options.makeCodec(udp: true, dst: $0) }
        guard codec != nil else { dead = true; return }
        NCConnector.brookPipe(options, queue: queue, transport: nil) { [weak self] p, _ in
            guard let self else { p?.cancel(); return }
            guard !self.cancelled, let p, let codec = self.codec else {
                p?.cancel()
                self.dead = true
                self.pending = []
                return
            }
            self.pipe = p
            var out = codec.head
            for d in self.pending { out.append(d) }
            self.pending = []
            p.send(out)
            self.receiveLoop()
        }
    }

    private func receiveLoop() {
        guard let pipe, let codec else { return }
        pipe.receive { [weak self] data, error in
            guard let self, !self.cancelled else { return }
            guard let data else { self.dead = true; return }
            guard let datagrams = codec.feed(data) else { self.cancel(); return }
            for d in datagrams { self.onReply(d) }
            if error == nil { self.receiveLoop() }
        }
    }

    func send(_ data: Data, to target: NCTarget) {
        guard !dead, !cancelled, let codec, let frame = codec.encode(data) else { return }
        if let pipe {
            pipe.send(frame)
        } else if pending.count < Self.maxPending {
            pending.append(frame)
        }
    }

    func cancel() {
        cancelled = true
        pending = []
        pipe?.cancel()
        pipe = nil
    }
}

/// brook quicserver UDP: sealed packets as QUIC datagrams on this association's own QUIC connection
/// (brook QUICDialUDP); datagrams above quic-go's 1197-byte limit are dropped, as the server would.
final class NCUDPBrookQUICDatagramSession: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }
    private let options: NCBrookOptions
    private let connection: NCBrookQUICConnection
    private var flow: NWConnection?
    private var pending: [Data] = []
    private var dead = false
    private var cancelled = false

    init(options: NCBrookOptions, queue: DispatchQueue) {
        self.options = options
        connection = NCBrookQUICConnection(options: options, datagram: true)
        connection.openDatagramFlow(callerQueue: queue) { [weak self] c, _ in
            guard let self, !self.cancelled, let c else {
                c?.cancel()
                self?.dead = true
                self?.pending = []
                return
            }
            self.flow = c
            let queued = self.pending
            self.pending = []
            for p in queued { c.send(content: p, completion: .idempotent) }
            self.receiveLoop()
        }
    }

    private func receiveLoop() {
        guard let flow else { return }
        flow.receiveMessage { [weak self] data, _, _, error in
            guard let self, !self.cancelled else { return }
            if let data, let payload = self.options.decodePacket(data) { self.onReply(payload) }
            if error == nil { self.receiveLoop() } else { self.dead = true }
        }
    }

    func send(_ data: Data, to target: NCTarget) {
        guard !dead, !cancelled, let dst = target.atypEncoded,
              let packet = options.encodePacket(dst: dst, payload: data),
              packet.count <= NCBrook.maxQUICDatagram else { return }
        if let flow {
            flow.send(content: packet, completion: .idempotent)
        } else if pending.count < NCUDPBrookStreamSession.maxPending {
            pending.append(packet)
        }
    }

    func cancel() {
        cancelled = true
        pending = []
        flow?.cancel()
        flow = nil
        connection.cancel()
    }
}
