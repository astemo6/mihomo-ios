import Foundation
import Network

/// TUIC UDP relay (feat/nc-proto2, based on astemo6/Muse NativeCore); wire format from mihomo v1.19.33
/// transport/tuic v4/v5 (protocol.go, packet.go, frag.go).
///
///   v5 Packet:     [5][2] assoc u16  pkt u16  frag_total u8  frag_id u8  size u16  ADDR  data
///   v4 Packet:     [4][2] assoc u32  len u16  ADDR  data            (no fragmentation)
///   Dissociate:    [v][3] assoc (u16 v5 / u32 v4)
///   Heartbeat:     [v][4]
///   ADDR:          0 = domain (len u8 + bytes), 1 = IPv4, 2 = IPv6, then port u16; 0xff = none (no port) —
///                  used by v5 for every fragment after the first.
///
/// native mode: each Packet is one QUIC DATAGRAM (fragmented to `udpMaxPacket`); quic mode: one unidirectional
/// stream per Packet, the server answers on its own uni streams. Memory: one shared datagram flow per TUIC
/// connection, per-session reassembly capped at 16 in-flight packets.
enum NCTUICUDP {
    static let overheadV5 = 2 + 2 + 2 + 1 + 1 + 2 + 19
    static let overheadV4 = 2 + 4 + 2 + 19

    struct Packet {
        var assoc: UInt32
        var pktID: UInt16
        var fragTotal: UInt8
        var fragID: UInt8
        var data: Data
    }

    static func address(_ t: NCTarget) -> Data { NCTUICWire.address(t) }

    /// Packet commands for one datagram, already fragmented for v5 native mode (`fragPayload` = max data bytes of
    /// the first fragment; later fragments use the same size).
    static func encode(version: Int, assoc: UInt16, pktID: UInt16, target: NCTarget, payload: Data,
                       fragPayload: Int?) -> [Data] {
        let addr = address(target)
        if version == 4 {
            var d = Data([4, 2])
            d.appendBE32(UInt32(assoc))
            d.appendBE16(UInt16(clamping: payload.count))
            d.append(addr)
            d.append(payload)
            return [d]
        }
        let room = max(64, fragPayload ?? Int.max)
        if payload.count <= room {
            return [v5Packet(assoc: assoc, pktID: pktID, total: 1, id: 0, addr: addr, data: payload)]
        }
        let count = (payload.count + room - 1) / room
        guard count <= 255 else { return [] }
        var out: [Data] = []
        out.reserveCapacity(count)
        let base = payload.startIndex
        for i in 0..<count {
            let lo = base + i * room
            let hi = min(payload.endIndex, lo + room)
            out.append(v5Packet(assoc: assoc, pktID: pktID, total: UInt8(count), id: UInt8(i),
                                addr: i == 0 ? addr : Data([0xff]), data: Data(payload[lo..<hi])))
        }
        return out
    }

    private static func v5Packet(assoc: UInt16, pktID: UInt16, total: UInt8, id: UInt8, addr: Data, data: Data) -> Data {
        var d = Data([5, 2])
        d.appendBE16(assoc)
        d.appendBE16(pktID)
        d.append(total)
        d.append(id)
        d.appendBE16(UInt16(clamping: data.count))
        d.append(addr)
        d.append(data)
        return d
    }

    static func dissociate(version: Int, assoc: UInt16) -> Data {
        var d = Data([UInt8(version), 3])
        if version == 4 { d.appendBE32(UInt32(assoc)) } else { d.appendBE16(assoc) }
        return d
    }

    /// Parses one Packet command (anything else — heartbeat, garbage — returns nil).
    static func decode(_ raw: Data) -> Packet? {
        let b = [UInt8](raw)
        guard b.count >= 2, b[1] == 2 else { return nil }
        var i = 2
        func u16() -> UInt16? {
            guard i + 2 <= b.count else { return nil }
            defer { i += 2 }
            return UInt16(b[i]) << 8 | UInt16(b[i + 1])
        }
        var p = Packet(assoc: 0, pktID: 0, fragTotal: 1, fragID: 0, data: Data())
        let size: Int
        if b[0] == 4 {
            guard i + 4 <= b.count else { return nil }
            p.assoc = UInt32(b[i]) << 24 | UInt32(b[i + 1]) << 16 | UInt32(b[i + 2]) << 8 | UInt32(b[i + 3])
            i += 4
            guard let n = u16() else { return nil }
            size = Int(n)
        } else if b[0] == 5 {
            guard let a = u16(), let pk = u16(), i + 2 <= b.count else { return nil }
            p.assoc = UInt32(a)
            p.pktID = pk
            p.fragTotal = b[i]; p.fragID = b[i + 1]
            i += 2
            guard let n = u16() else { return nil }
            size = Int(n)
        } else {
            return nil
        }
        guard i < b.count else { return nil }
        let atyp = b[i]; i += 1
        switch atyp {
        case 0:
            guard i < b.count else { return nil }
            i += 1 + Int(b[i]) + 2
        case 1: i += 4 + 2
        case 2: i += 16 + 2
        case 0xff: break
        default: return nil
        }
        guard i + size <= b.count else { return nil }
        p.data = Data(b[i..<(i + size)])
        return p
    }

    /// v5 reassembly (mihomo deFragger): per packet id, at most 16 open packets.
    struct Defragger {
        private var bags: [UInt16: [Data?]] = [:]
        private var order: [UInt16] = []
        private var bagBytes: [UInt16: Int] = [:]

        /// nc-memory: one reassembled packet can never exceed a UDP payload; a peer dripping
        /// maximal fragments for many packet ids must not pin more than this per open packet
        /// (× the 16-packet cap ≈ 1 MB per association worst case).
        static let maxPacketBytes = 64 * 1024

        mutating func feed(_ p: Packet) -> Data? {
            if p.fragTotal <= 1 { return p.data }
            guard p.fragID < p.fragTotal else { return nil }
            var bag = bags[p.pktID] ?? []
            if bag.count != Int(p.fragTotal) {
                bag = Array(repeating: nil, count: Int(p.fragTotal))
                bagBytes[p.pktID] = 0
                if bags[p.pktID] == nil {
                    order.append(p.pktID)
                    if order.count > 16 {
                        let evicted = order.removeFirst()
                        bags.removeValue(forKey: evicted)
                        bagBytes.removeValue(forKey: evicted)
                    }
                }
            }
            if bag[Int(p.fragID)] != nil { return nil }
            let bytes = (bagBytes[p.pktID] ?? 0) + p.data.count
            guard bytes <= Self.maxPacketBytes else {
                bags.removeValue(forKey: p.pktID)
                bagBytes.removeValue(forKey: p.pktID)
                order.removeAll { $0 == p.pktID }
                return nil
            }
            bagBytes[p.pktID] = bytes
            bag[Int(p.fragID)] = p.data
            if bag.contains(where: { $0 == nil }) {
                bags[p.pktID] = bag
                return nil
            }
            bags.removeValue(forKey: p.pktID)
            bagBytes.removeValue(forKey: p.pktID)
            order.removeAll { $0 == p.pktID }
            var out = Data()
            for part in bag { if let part { out.append(part) } }
            return out
        }

        mutating func reset() { bags.removeAll(); order.removeAll(); bagBytes.removeAll() }
    }
}

// MARK: - Connection side (runs on the connection's queue)

extension NCTUICConnection {
    /// Registers a UDP association; the handler gets every Packet for it (raw, undecoded fragments included).
    func registerUDP(_ handler: @escaping (Data) -> Void) -> UInt16? {
        guard state == .ready else { return nil }
        for _ in 0..<32 {
            let id = UInt16.random(in: 1...0xfffe)
            if udpHandlers[id] == nil {
                udpHandlers[id] = handler
                if udpNative { _ = ensureDatagramFlow() }
                return id
            }
        }
        return nil
    }

    func unregisterUDP(_ assoc: UInt16) {
        guard udpHandlers.removeValue(forKey: assoc) != nil, state == .ready else { return }
        sendUni(NCTUICUDP.dissociate(version: tuicVersion, assoc: assoc))
    }

    func sendUDP(assoc: UInt16, target: NCTarget, payload: Data) {
        guard state == .ready, udpHandlers[assoc] != nil, payload.count <= 0xffff else { return }
        let pktID = UInt16.random(in: 0...0xffff)
        if udpNative {
            // Fragment payload room: max datagram frame minus header (the first fragment carries the address).
            let addrLen = NCTUICUDP.address(target).count
            let header = 2 + 2 + 2 + 2 + 2 + addrLen
            let frames = NCTUICUDP.encode(version: tuicVersion, assoc: assoc, pktID: pktID, target: target,
                                          payload: payload, fragPayload: max(64, min(udpMaxPacket, 1200 - 3 - header)))
            guard let flow = ensureDatagramFlow() else { return }
            for f in frames { flow.send(content: f, completion: .idempotent) }
        } else {
            for f in NCTUICUDP.encode(version: tuicVersion, assoc: assoc, pktID: pktID, target: target,
                                      payload: payload, fragPayload: nil) {
                sendUni(f)
            }
        }
    }

    /// One command on a fresh client-initiated unidirectional stream (FIN after it).
    private func sendUni(_ cmd: Data) {
        let opts = NWProtocolQUIC.Options()
        opts.direction = .unidirectional
        guard let g = group, let c = g.extract(connectionTo: nil, using: opts) else { return }
        c.stateUpdateHandler = { st in
            switch st {
            case .ready:
                c.send(content: cmd, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { _ in
                    c.cancel()
                })
            case .failed, .waiting:
                c.cancel()
            case .cancelled:
                c.stateUpdateHandler = nil
            default:
                break
            }
        }
        c.start(queue: queue)
    }

    /// The QUIC datagram flow (RFC 9221) of this connection, created on first use.
    private func ensureDatagramFlow() -> NWConnection? {
        if let datagramFlow { return datagramFlow }
        let opts = NWProtocolQUIC.Options()
        opts.isDatagram = true
        opts.maxDatagramFrameSize = 1400
        guard let g = group, let c = g.extract(connectionTo: nil, using: opts) else { return nil }
        datagramFlow = c
        c.stateUpdateHandler = { [weak self] st in
            guard let self else { return }
            switch st {
            case .ready:
                self.readMessages(c)
            case .failed, .cancelled:
                if self.datagramFlow === c { self.datagramFlow = nil }
                c.cancel()
            default:
                break
            }
        }
        c.start(queue: queue)
        return c
    }

    /// A flow the server opened: a uni stream (quic-mode packet / heartbeat) or its datagram flow.
    func acceptIncoming(_ c: NWConnection) {
        c.stateUpdateHandler = { [weak self] st in
            guard let self else { c.cancel(); return }
            switch st {
            case .ready: self.readMessages(c)
            case .failed: c.cancel()
            case .cancelled: c.stateUpdateHandler = nil
            default: break
            }
        }
        c.start(queue: queue)
    }

    /// receiveMessage: one datagram per call on the datagram flow; the whole stream (FIN) on a uni stream.
    private func readMessages(_ c: NWConnection) {
        c.receiveMessage { [weak self] data, _, isComplete, error in
            guard let self else { c.cancel(); return }
            if let data, !data.isEmpty { self.dispatchUDP(data) }
            if error != nil || self.state != .ready { c.cancel(); return }
            if isComplete && c !== self.datagramFlow { c.cancel(); return }
            self.readMessages(c)
        }
    }

    private func dispatchUDP(_ raw: Data) {
        guard raw.count >= 6, raw[raw.startIndex + 1] == 2 else { return } // heartbeat / other commands
        let b = [UInt8](raw.prefix(6))
        let assoc: UInt16 = b[0] == 4 ? UInt16(b[4]) << 8 | UInt16(b[5]) : UInt16(b[2]) << 8 | UInt16(b[3])
        udpHandlers[assoc]?(raw)
    }
}

// MARK: - Session
