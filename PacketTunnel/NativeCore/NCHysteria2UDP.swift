import Foundation

/// Hysteria2 UDP over QUIC datagrams (protocol v2).
///
/// Wire format of one datagram (RFC 9221 payload), all integers are QUIC
/// varints (see NCHy2.varintEncode):
///
///     session ID (varint) || message ID (varint) || frag ID (u8) ||
///     frag count (u8) || address length (varint) || "host:port" || payload
///
/// The client picks a random session ID per NCUDPHysteria2Session; the
/// server echoes it in replies. Oversized payloads are fragmented: every
/// fragment repeats the full header (including the address), the payload is
/// sliced in order, and frag count is the total number of fragments.
///
/// Binding caveat: the actual QUIC datagram transport goes through
/// NCHysteria2Connection.sendDatagram / setDatagramSink, whose NW binding is the
/// unverified point 4 documented in NCHysteria2.swift. The codec below is
/// pure and fully testable regardless.

// MARK: - Pure codec

enum NCHy2UDP {
    /// Conservative per-datagram budget (bytes) for one QUIC datagram,
    /// header included — comfortably under a 1200-byte path MTU assumption.
    static let maxDatagramSize = 1200

    static func encodeFrame(sessionID: UInt64, messageID: UInt64,
                            fragID: UInt8, fragCount: UInt8,
                            address: String, payload: Data) -> Data {
        var out = NCHy2.varintEncode(sessionID)
        out.append(NCHy2.varintEncode(messageID))
        out.append(fragID)
        out.append(fragCount)
        out.append(NCHy2.varintEncode(UInt64(address.utf8.count)))
        out.append(Data(address.utf8))
        out.append(payload)
        return out
    }

    struct Frame {
        var sessionID: UInt64
        var messageID: UInt64
        var fragID: UInt8
        var fragCount: UInt8
        var address: String
        var payload: Data
    }

    static func decodeFrame(_ data: Data) -> Frame? {
        guard let (sessionID, l1) = NCHy2.varintDecode(data, at: 0),
              let (messageID, l2) = NCHy2.varintDecode(data, at: l1) else { return nil }
        var idx = l1 + l2
        guard data.count - idx >= 2 else { return nil }
        let fragID = data[idx]
        let fragCount = data[idx + 1]
        idx += 2
        guard fragCount >= 1, fragID < fragCount,
              let (addrLen, l3) = NCHy2.varintDecode(data, at: idx) else { return nil }
        idx += l3
        guard data.count - idx >= Int(addrLen) else { return nil }
        let address = String(decoding: data[idx..<(idx + Int(addrLen))], as: UTF8.self)
        idx += Int(addrLen)
        return Frame(sessionID: sessionID, messageID: messageID,
                     fragID: fragID, fragCount: fragCount,
                     address: address, payload: Data(data[idx...]))
    }

    /// Split one outbound datagram into wire frames of at most
    /// `maxDatagramSize` bytes each.
    static func fragment(sessionID: UInt64, messageID: UInt64,
                         address: String, payload: Data) -> [Data] {
        // Header size without the payload (address included, frag fields
        // are single bytes, varints sized for typical IDs).
        let probe = encodeFrame(sessionID: sessionID, messageID: messageID,
                                fragID: 0, fragCount: 1, address: address, payload: Data())
        let room = max(1, maxDatagramSize - probe.count)
        if payload.count <= room {
            return [encodeFrame(sessionID: sessionID, messageID: messageID,
                                fragID: 0, fragCount: 1, address: address, payload: payload)]
        }
        let count = (payload.count + room - 1) / room
        guard count <= 255 else {
            // Absurdly large single datagram: send the first 255 fragments'
            // worth and drop the tail (callers should never do this).
            let usable = room * 255
            return fragment(sessionID: sessionID, messageID: messageID,
                            address: address, payload: Data(payload.prefix(usable)))
        }
        var frames: [Data] = []
        for i in 0..<count {
            let slice = Data(payload[(i * room)..<min(payload.count, (i + 1) * room)])
            frames.append(encodeFrame(sessionID: sessionID, messageID: messageID,
                                      fragID: UInt8(i), fragCount: UInt8(count),
                                      address: address, payload: slice))
        }
        return frames
    }

    /// Fragment reassembly for inbound messages, keyed by message ID.
    /// Feed frames; returns the reassembled payload exactly once, when the
    /// final missing fragment arrives (single-fragment messages complete
    /// immediately).
    struct Reassembler {
        private var pending: [UInt64: (count: Int, parts: [Int: Data], bytes: Int)] = [:]
        private var order: [UInt64] = []

        /// nc-memory: open-message and per-message byte caps (mirrors the TUIC defragger's
        /// 16 open packets × 64 KB). Message IDs are peer-chosen, so without these a peer can
        /// pin one partial message per ID indefinitely.
        static let maxOpenMessages = 16
        static let maxMessageBytes = 64 * 1024

        mutating func feed(_ frame: Frame) -> Data? {
            if frame.fragCount == 1 { return frame.payload }
            var entry = pending[frame.messageID] ?? (count: Int(frame.fragCount), parts: [:], bytes: 0)
            if pending[frame.messageID] == nil {
                order.append(frame.messageID)
                if order.count > Self.maxOpenMessages {
                    pending.removeValue(forKey: order.removeFirst())
                }
            }
            entry.count = Int(frame.fragCount)
            entry.bytes += frame.payload.count - (entry.parts[Int(frame.fragID)]?.count ?? 0)
            guard entry.bytes <= Self.maxMessageBytes else {
                pending.removeValue(forKey: frame.messageID)
                order.removeAll { $0 == frame.messageID }
                return nil
            }
            entry.parts[Int(frame.fragID)] = frame.payload
            if entry.parts.count == entry.count {
                pending.removeValue(forKey: frame.messageID)
                order.removeAll { $0 == frame.messageID }
                var out = Data()
                for i in 0..<entry.count {
                    guard let part = entry.parts[i] else { return nil }
                    out.append(part)
                }
                return out
            }
            pending[frame.messageID] = entry
            return nil
        }

        mutating func reset() { pending.removeAll(); order.removeAll() }
    }
}

// MARK: - Session

/// One hysteria2 UDP session (one NCUDPSession per stack UDP session, like
/// its siblings). Owns its NCHysteria2Connection when built from a proxy
/// config; sends queue until the connection authenticates.
final class NCUDPHysteria2Session: NCUDPSession {
    var onReply: (Data) -> Void = { _ in }

    private let connection: NCHysteria2Connection
    private let ownsConnection: Bool
    /// The queue this session's state lives on (the caller's queue, as with its sibling UDP sessions):
    /// sends/cancels arrive here, and datagram deliveries hop back here from the connection's session queue.
    private let queue: DispatchQueue
    private let sessionID: UInt64
    private var nextMessageID: UInt64 = 0
    private var reassembler = NCHy2UDP.Reassembler()
    private var ready = false
    private var cancelled = false
    private var queued: [(Data, NCTarget)] = []

    /// Session over an already-started shared connection (the connector's
    /// preferred shape: one QUIC connection, many sessions).
    init(connection: NCHysteria2Connection) {
        self.connection = connection
        self.ownsConnection = false
        self.queue = connection.queue
        self.ready = true
        var id: UInt64 = 0
        while id == 0 {
            id = NCConnector.randomData(4).reduce(0) { ($0 << 8) | UInt64($1) }
        }
        self.sessionID = id
        wireDatagrams()
    }

    /// Self-contained session from a proxy config, mirroring the other UDP
    /// sessions' (proxy:queue:) shape: builds and starts its own connection.
    init?(proxy: NCProxy, queue: DispatchQueue) {
        guard let connection = NCHysteria2Connection(proxy: proxy, queue: queue) else { return nil }
        self.connection = connection
        self.ownsConnection = true
        self.queue = queue
        var id: UInt64 = 0
        while id == 0 {
            id = NCConnector.randomData(4).reduce(0) { ($0 << 8) | UInt64($1) }
        }
        self.sessionID = id
        wireDatagrams()
        connection.start { [weak self] error in
            guard let self, !self.cancelled, error == nil else { return }
            self.ready = true
            let pending = self.queued
            self.queued = []
            for (data, target) in pending { self.send(data, to: target) }
        }
    }

    private func wireDatagrams() {
        // nc-races: register a per-session sink on the connection (the old single `onDatagram` slot was
        // overwritten by every session sharing the connection). The sink runs on the connection's session
        // queue; the session's own state is confined to `queue`, so deliveries hop back.
        connection.setDatagramSink(sessionID: sessionID) { [weak self] raw in
            guard let self else { return }
            self.queue.async {
                guard !self.cancelled else { return }
                self.handleDatagram(raw)
            }
        }
    }

    private func handleDatagram(_ raw: Data) {
        guard let frame = NCHy2UDP.decodeFrame(raw), frame.sessionID == sessionID else { return }
        if let payload = reassembler.feed(frame) {
            onReply(payload)
        }
    }

    func send(_ data: Data, to target: NCTarget) {
        guard !cancelled else { return }
        guard ready else {
            if queued.count < 64 { queued.append((data, target)) }
            return
        }
        // Authenticated but the server did not enable UDP: drop (queuing
        // would never drain).
        guard connection.udpEnabled else { return }
        let address = "\(target.host):\(target.port)"
        let frames = NCHy2UDP.fragment(sessionID: sessionID, messageID: nextMessageID,
                                       address: address, payload: data)
        nextMessageID &+= 1
        for frame in frames {
            connection.sendDatagram(frame)
        }
    }

    func cancel() {
        cancelled = true
        queued = []
        reassembler.reset()
        if ownsConnection {
            connection.close()
        } else {
            connection.setDatagramSink(sessionID: sessionID, nil)
        }
    }
}
