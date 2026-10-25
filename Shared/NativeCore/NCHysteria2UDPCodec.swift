import Foundation

/// Hysteria2 UDPMessage codec (apernet/hysteria PROTOCOL.md "UDP"; sing-quic hysteria2/packet.go).
/// Pure and allocation-light; shared by NCHysteria2Connection (datagram flow) and the tunnel's
/// NCUDPHysteria2Session, and unit-testable from the app-hosted test bundle (it used to live in
/// PacketTunnel/NativeCore/NCHysteria2UDP.swift, out of the tests' reach).
///
/// One QUIC datagram (RFC 9221 payload), big endian:
///
///     [uint32] Session ID
///     [uint16] Packet ID
///     [uint8]  Fragment ID
///     [uint8]  Fragment count
///     [varint] Address length        (QUIC varint, RFC 9000 §16)
///     [bytes]  Address "host:port"
///     [bytes]  Payload
///
/// (The first cut encoded Session ID and Packet ID as QUIC varints — a conforming server read a
/// garbage session / packet ID and fragment fields from the wrong offsets, so no reply ever
/// matched.) Every fragment repeats the full header including the address (hysteria does not
/// accept an empty address on fragments > 0 — sing-quic keeps it on all of them for that reason).
/// Unfragmented messages carry Fragment count 1; Packet ID / Fragment ID are then irrelevant.
enum NCHy2UDP {
    /// Largest UDPMessage (header included) sent in one QUIC datagram. sing-quic uses 1200 - 3, but
    /// it sits on quic-go, which re-fragments on DatagramTooLargeError; Network.framework gives no
    /// such size (NWProtocolQUIC.Metadata has no max datagram size) and its QUIC packets start at
    /// the 1200-byte minimum, so a 1197-byte DATAGRAM frame (+ short header, DATAGRAM frame
    /// header and the 16-byte AEAD tag) does not fit and is lost (proto-loopback run 40195786967:
    /// DNS-sized packets echoed, 3000-byte fragmented ones never did). 1100 leaves room for the
    /// worst-case short header (20-byte CID + 4-byte PN) and the frame overhead. The connection
    /// still lowers it if a send fails with EMSGSIZE.
    static let maxDatagramSize = 1100

    /// Fixed part of the header: session ID (4) + packet ID (2) + frag ID (1) + frag count (1).
    static let fixedHeaderSize = 8

    struct Frame: Equatable {
        var sessionID: UInt32
        var packetID: UInt16
        var fragID: UInt8
        var fragCount: UInt8
        var address: String
        var payload: Data
    }

    static func headerSize(address: String) -> Int {
        let n = address.utf8.count
        return fixedHeaderSize + NCHy2.varintEncode(UInt64(n)).count + n
    }

    static func encodeFrame(sessionID: UInt32, packetID: UInt16, fragID: UInt8, fragCount: UInt8,
                            address: String, payload: Data) -> Data {
        var out = Data()
        out.reserveCapacity(headerSize(address: address) + payload.count)
        out.appendBE32(sessionID)
        out.appendBE16(packetID)
        out.append(fragID)
        out.append(fragCount)
        out.append(NCHy2.varintEncode(UInt64(address.utf8.count)))
        out.append(contentsOf: address.utf8)
        out.append(payload)
        return out
    }

    /// Session ID of a raw datagram without decoding the rest (the connection demultiplexes on
    /// it before handing the datagram to its session).
    static func peekSessionID(_ data: Data) -> UInt32? {
        guard data.count >= fixedHeaderSize else { return nil }
        let s = data.startIndex
        return UInt32(data[s]) << 24 | UInt32(data[s + 1]) << 16 | UInt32(data[s + 2]) << 8 | UInt32(data[s + 3])
    }

    static func decodeFrame(_ data: Data) -> Frame? {
        guard let sessionID = peekSessionID(data) else { return nil }
        let s = data.startIndex
        let packetID = UInt16(data[s + 4]) << 8 | UInt16(data[s + 5])
        let fragID = data[s + 6]
        let fragCount = data[s + 7]
        // sing-quic drops fragID >= fragCount; a zero count is meaningless.
        guard fragCount >= 1, fragID < fragCount else { return nil }
        // NCHy2.varintDecode indexes from 0: re-base a slice (copy) only when it is not already 0-based.
        let base = data.startIndex == 0 ? data : Data(data)
        guard let (addrLen, l) = NCHy2.varintDecode(base, at: fixedHeaderSize) else { return nil }
        let addrStart = fixedHeaderSize + l
        guard addrLen <= 2048, base.count - addrStart >= Int(addrLen) else { return nil }
        let addrEnd = addrStart + Int(addrLen)
        let address = String(decoding: base[addrStart..<addrEnd], as: UTF8.self)
        return Frame(sessionID: sessionID, packetID: packetID, fragID: fragID, fragCount: fragCount,
                     address: address, payload: Data(base[addrEnd...]))
    }

    /// Split one UDP packet into wire datagrams of at most `maxDatagramSize` bytes each
    /// (sing-quic fragUDPMessage: room = max - header; count = ceil(payload / room)).
    /// Returns [] when the packet cannot be carried (header alone does not fit, or more than 255
    /// fragments would be needed) — the spec says such a packet MUST be fragmented or discarded,
    /// and truncating it would deliver corrupt data.
    static func fragment(sessionID: UInt32, packetID: UInt16, address: String, payload: Data,
                         maxDatagramSize: Int = NCHy2UDP.maxDatagramSize) -> [Data] {
        let room = maxDatagramSize - headerSize(address: address)
        guard room > 0 else { return [] }
        if payload.count <= room {
            return [encodeFrame(sessionID: sessionID, packetID: packetID, fragID: 0, fragCount: 1,
                                address: address, payload: payload)]
        }
        let count = (payload.count + room - 1) / room
        guard count <= 255 else { return [] }
        var frames: [Data] = []
        frames.reserveCapacity(count)
        let s = payload.startIndex
        for i in 0..<count {
            let lo = s + i * room
            let hi = min(payload.endIndex, lo + room)
            frames.append(encodeFrame(sessionID: sessionID, packetID: packetID,
                                      fragID: UInt8(i), fragCount: UInt8(count),
                                      address: address, payload: payload[lo..<hi]))
        }
        return frames
    }

    /// Inbound fragment reassembly, keyed by packet ID (one per UDP session, like sing-quic's
    /// per-conn udpDefragger). Returns the reassembled packet exactly once, when its last missing
    /// fragment arrives; single-fragment messages pass straight through. A fragment whose count
    /// disagrees with the packet's pending count restarts that packet (sing-quic semantics);
    /// duplicates are ignored. Lost fragments are never waited for beyond the caps: at most
    /// `maxOpenPackets` partial packets (oldest evicted) and `maxPacketBytes` per packet.
    struct Reassembler {
        private struct Pending {
            var parts: [Data?]
            var have: Int
            var bytes: Int
        }
        private var pending: [UInt16: Pending] = [:]
        private var order: [UInt16] = []

        /// nc-memory: peer-chosen packet IDs, so both caps are load-bearing (mirrors the TUIC
        /// defragger's 16 open packets × 64 KB). sing-quic ages partial packets out after 10 s;
        /// the open-packet cap bounds the same memory without a timer.
        static let maxOpenPackets = 16
        static let maxPacketBytes = 64 * 1024

        var openPackets: Int { pending.count }

        mutating func feed(_ frame: Frame) -> Data? {
            if frame.fragCount <= 1 { return frame.payload }
            guard frame.fragID < frame.fragCount else { return nil }
            let id = frame.packetID
            let count = Int(frame.fragCount)
            var entry: Pending
            if let existing = pending[id], existing.parts.count == count {
                entry = existing
            } else {
                if pending[id] == nil {
                    order.append(id)
                    if order.count > Self.maxOpenPackets {
                        pending.removeValue(forKey: order.removeFirst())
                    }
                }
                entry = Pending(parts: Array(repeating: nil, count: count), have: 0, bytes: 0)
            }
            let idx = Int(frame.fragID)
            if entry.parts[idx] != nil {
                pending[id] = entry
                return nil // duplicate fragment
            }
            entry.bytes += frame.payload.count
            guard entry.bytes <= Self.maxPacketBytes else {
                drop(id)
                return nil
            }
            entry.parts[idx] = frame.payload
            entry.have += 1
            guard entry.have == count else {
                pending[id] = entry
                return nil
            }
            drop(id)
            var out = Data()
            out.reserveCapacity(entry.bytes)
            for part in entry.parts { if let part { out.append(part) } }
            // sing-quic discards a reassembled packet of zero length.
            return out.isEmpty ? nil : out
        }

        private mutating func drop(_ id: UInt16) {
            pending.removeValue(forKey: id)
            if let i = order.firstIndex(of: id) { order.remove(at: i) }
        }

        mutating func reset() { pending.removeAll(); order.removeAll() }
    }
}
