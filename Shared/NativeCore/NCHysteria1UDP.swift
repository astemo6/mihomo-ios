import CryptoKit
import Darwin
import Foundation
import Network

/// Hysteria v1 packet layer and UDP relay (feat/nc-proto2, based on astemo6/Muse NativeCore); behaviour from mihomo
/// v1.19.33 transport/hysteria (obfs/xplus.go, conns/udp/hop.go, conns/wechat/obfs.go, core/protocol.go, core/frag.go).
///
/// Network.framework's QUIC owns its UDP socket, so packet-level transforms (XPlus obfs, wechat-video header, port
/// hopping) run in a loopback shim: QUIC dials 127.0.0.1:<shim port>; the shim obfuscates each QUIC packet and sends
/// it from an NWConnection (bound like every other outbound socket) to the server, hopping to a fresh socket and a
/// random port from `ports` every `hop-interval` seconds while still reading the previous one (as hop.go does).
/// The shim is only created when obfs / wechat-video / ports are configured. faketcp needs raw sockets: unsupported.
enum NCHy1Obfs {
    static let saltLen = 16

    /// [salt 16][payload XOR SHA256(key || salt) repeated]
    static func xplusObfuscate(key: Data, _ input: Data) -> Data {
        let salt = NCConnector.randomData(saltLen)
        var out = Data(capacity: saltLen + input.count)
        out.append(salt)
        out.append(xor(input, Data(SHA256.hash(data: key + salt))))
        return out
    }

    static func xplusDeobfuscate(key: Data, _ input: Data) -> Data? {
        guard input.count > saltLen else { return nil }
        let salt = input.prefix(saltLen)
        return xor(input.dropFirst(saltLen), Data(SHA256.hash(data: key + salt)))
    }

    private static func xor<D: DataProtocol>(_ input: D, _ key: Data) -> Data {
        let k = [UInt8](key)
        var out = [UInt8](input)
        for i in 0..<out.count { out[i] ^= k[i & 31] }
        return Data(out)
    }

    /// mihomo parsePorts: "443,1000-2000"; nil when empty / invalid.
    static func parsePorts(_ s: String?) -> [UInt16]? {
        guard let s = s?.trimmingCharacters(in: .whitespaces), !s.isEmpty else { return nil }
        var out: [UInt16] = []
        for part in s.split(separator: ",") {
            let p = part.trimmingCharacters(in: .whitespaces)
            if p.contains("-") {
                let r = p.split(separator: "-").map { $0.trimmingCharacters(in: .whitespaces) }
                guard r.count == 2, var a = UInt16(r[0]), var b = UInt16(r[1]) else { return nil }
                if a > b { swap(&a, &b) }
                // Memory: a range is kept as its bounds, not expanded beyond 65536 entries (UInt16 anyway).
                out.append(contentsOf: a...b)
            } else {
                guard let v = UInt16(p) else { return nil }
                out.append(v)
            }
        }
        return out.isEmpty ? nil : out
    }
}

/// Loopback UDP shim between the system QUIC stack and the server (see file header). All work on `queue`.
final class NCHy1PacketShim {
    let localPort: UInt16
    private let fd: Int32
    private let source: DispatchSourceRead
    private let queue: DispatchQueue
    private let server: String
    private let ports: [UInt16]
    private let hopInterval: TimeInterval
    private let xplusKey: Data?
    private let wechat: Bool
    private var wechatSN: UInt32
    private var client: sockaddr_in?
    private var current: NWConnection?
    private var previous: NWConnection?
    private var hopTimer: DispatchSourceTimer?
    private let buffer: UnsafeMutableRawPointer
    private static let bufferSize = 4096
    private var closed = false

    init?(server: String, ports: [UInt16], hopInterval: TimeInterval, xplusKey: Data?, wechat: Bool,
          queue: DispatchQueue) {
        guard !ports.isEmpty else { return nil }
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return nil }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        var got = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &got) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        guard bound == 0, named == 0 else { Darwin.close(fd); return nil }
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK)
        self.fd = fd
        localPort = UInt16(bigEndian: got.sin_port)
        self.queue = queue
        self.server = server
        self.ports = ports
        self.hopInterval = max(5, hopInterval)
        self.xplusKey = xplusKey
        self.wechat = wechat
        wechatSN = UInt32.random(in: 0...0xffff)
        buffer = UnsafeMutableRawPointer.allocate(byteCount: Self.bufferSize, alignment: 8)
        source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        let buf = buffer
        source.setCancelHandler { Darwin.close(fd); buf.deallocate() }
        source.setEventHandler { [weak self] in self?.readLocal() }
        source.resume()
        current = dial()
        if ports.count > 1 {
            let t = DispatchSource.makeTimerSource(queue: queue)
            t.schedule(deadline: .now() + self.hopInterval, repeating: self.hopInterval)
            t.setEventHandler { [weak self] in self?.hop() }
            t.resume()
            hopTimer = t
        }
    }

    deinit { close() }

    func close() {
        guard !closed else { return }
        closed = true
        hopTimer?.cancel(); hopTimer = nil
        current?.cancel(); current = nil
        previous?.cancel(); previous = nil
        source.cancel()
    }

    private func dial() -> NWConnection? {
        guard let port = ports.randomElement(), let p = NWEndpoint.Port(rawValue: port) else { return nil }
        let c = NWConnection(host: NWEndpoint.Host(server), port: p,
                             using: NCOutboundBinding.params(.udp, host: server))
        c.stateUpdateHandler = { [weak self] st in
            switch st {
            case .ready: self?.readRemote(c)
            case .failed: c.cancel()
            case .cancelled: c.stateUpdateHandler = nil
            default: break
            }
        }
        c.start(queue: queue)
        return c
    }

    /// hop.go: prev is closed, prev = current, current = new socket to a random port; both keep receiving.
    private func hop() {
        guard !closed, let next = dial() else { return }
        previous?.cancel()
        previous = current
        current = next
    }

    private func readLocal() {
        while !closed {
            var from = sockaddr_in()
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            let n = withUnsafeMutablePointer(to: &from) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    recvfrom(fd, buffer, Self.bufferSize, 0, $0, &len)
                }
            }
            guard n > 0 else { return }
            client = from
            let pkt = Data(bytes: buffer, count: n)
            current?.send(content: obfuscate(pkt), completion: .idempotent)
        }
    }

    private func readRemote(_ c: NWConnection) {
        c.receiveMessage { [weak self] data, _, _, error in
            guard let self, !self.closed else { return }
            if let data, let plain = self.deobfuscate(data) { self.writeLocal(plain) }
            if error == nil, c === self.current || c === self.previous { self.readRemote(c) }
        }
    }

    private func writeLocal(_ d: Data) {
        guard let to = client else { return }
        _ = d.withUnsafeBytes { p in
            withUnsafePointer(to: to) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(fd, p.baseAddress, p.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
    }

    private func obfuscate(_ d: Data) -> Data {
        let body = xplusKey.map { NCHy1Obfs.xplusObfuscate(key: $0, d) } ?? d
        guard wechat else { return body }
        var out = Data([0xa1, 0x08])
        out.appendBE32(wechatSN)
        wechatSN &+= 1
        out.append(contentsOf: [0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30])
        out.append(body)
        return out
    }

    private func deobfuscate(_ d: Data) -> Data? {
        var body = d
        if wechat {
            guard d.count > 13 else { return nil }
            body = Data(d.dropFirst(13))
        }
        guard let key = xplusKey else { return body }
        return NCHy1Obfs.xplusDeobfuscate(key: key, body)
    }
}

// MARK: - UDP relay (core/client.go DialUDP + udpMessage)

enum NCHy1UDP {
    /// udpMessage: sessionID u32, hostLen u16, host, port u16, msgID u16, fragID u8, fragCount u8, dataLen u16, data.
    static func pack(session: UInt32, host: String, port: UInt16, msgID: UInt16, fragID: UInt8, fragCount: UInt8,
                     data: Data) -> Data {
        let h = Data(host.utf8.prefix(0xffff))
        var d = Data(capacity: 14 + h.count + data.count)
        d.appendBE32(session)
        d.appendBE16(UInt16(h.count))
        d.append(h)
        d.appendBE16(port)
        d.appendBE16(msgID)
        d.append(fragID)
        d.append(fragCount)
        d.appendBE16(UInt16(clamping: data.count))
        d.append(data)
        return d
    }

    struct Message { var session: UInt32; var msgID: UInt16; var fragID: UInt8; var fragCount: UInt8; var data: Data }

    static func unpack(_ raw: Data) -> Message? {
        let b = [UInt8](raw)
        guard b.count >= 6 else { return nil }
        let session = UInt32(b[0]) << 24 | UInt32(b[1]) << 16 | UInt32(b[2]) << 8 | UInt32(b[3])
        let hl = Int(b[4]) << 8 | Int(b[5])
        var i = 6 + hl + 2
        guard i + 6 <= b.count else { return nil }
        let msgID = UInt16(b[i]) << 8 | UInt16(b[i + 1])
        let fragID = b[i + 2], fragCount = b[i + 3]
        let n = Int(b[i + 4]) << 8 | Int(b[i + 5])
        i += 6
        guard i + n <= b.count else { return nil }
        return Message(session: session, msgID: msgID, fragID: fragID, fragCount: fragCount, data: Data(b[i..<(i + n)]))
    }

    /// Pre-fragmented (no DatagramTooLargeError feedback from Network.framework): every datagram ≤ `maxSize`.
    static func frames(session: UInt32, host: String, port: UInt16, data: Data, maxSize: Int = 1150) -> [Data] {
        let header = 14 + host.utf8.count
        if header + data.count <= maxSize {
            return [pack(session: session, host: host, port: port, msgID: 0, fragID: 0, fragCount: 1, data: data)]
        }
        let room = max(64, maxSize - header)
        let count = (data.count + room - 1) / room
        guard count <= 255 else { return [] }
        let msgID = UInt16.random(in: 1...0xffff) // must be > 0 when fragmented
        var out: [Data] = []
        let base = data.startIndex
        for i in 0..<count {
            let lo = base + i * room, hi = min(data.endIndex, lo + room)
            out.append(pack(session: session, host: host, port: port, msgID: msgID, fragID: UInt8(i),
                            fragCount: UInt8(count), data: Data(data[lo..<hi])))
        }
        return out
    }

    /// core/frag.go defragger: one message in flight per connection.
    struct Defragger {
        private var msgID: UInt16 = 0
        private var parts: [Data?] = []
        private var count = 0

        mutating func feed(_ m: Message) -> Message? {
            if m.fragCount <= 1 { return m }
            guard m.fragID < m.fragCount else { return nil }
            if m.msgID != msgID || parts.count != Int(m.fragCount) {
                msgID = m.msgID
                parts = Array(repeating: nil, count: Int(m.fragCount))
                parts[Int(m.fragID)] = m.data
                count = 1
                return nil
            }
            guard parts[Int(m.fragID)] == nil else { return nil }
            parts[Int(m.fragID)] = m.data
            count += 1
            guard count == parts.count else { return nil }
            var out = m
            out.data = Data()
            for p in parts { if let p { out.data.append(p) } }
            out.fragID = 0; out.fragCount = 1
            parts = []; count = 0
            return out
        }
    }
}

extension NCHysteria1Connection {
    /// DialUDP: a stream with ClientRequest{UDP: true}; the ServerResponse carries the UDP session id. The stream is
    /// held open for the session's lifetime (closing it ends the session server-side).
    func openUDP(handler: @escaping (Data) -> Void, completion: @escaping (UInt32?) -> Void) {
        guard state == .ready, let conn = group?.extract(connectionTo: nil, using: nil) else { completion(nil); return }
        let ch = NCHy2StreamChannel(conn: conn)
        var buf = Data()
        var done = false
        func finish(_ id: UInt32?) {
            guard !done else { return }
            done = true
            if let id { udpSessions[id] = (handler, ch); _ = ensureDatagramFlow() } else { ch.cancel() }
            completion(id)
        }
        func read() {
            ch.receive { data, _ in
                guard !done else { return }
                guard let data else { finish(nil); return }
                buf.append(data)
                guard let (ok, _, _) = NCHy1.tcpResponse(buf) else { read(); return }
                guard ok, buf.count >= 5 else { finish(nil); return }
                let s = buf.startIndex
                finish(UInt32(buf[s + 1]) << 24 | UInt32(buf[s + 2]) << 16 | UInt32(buf[s + 3]) << 8 | UInt32(buf[s + 4]))
            }
        }
        ch.start(queue: queue) { err in
            if err != nil { finish(nil); return }
            ch.send(Data([1, 0, 0, 0, 0])) // UDP, empty host, port 0
            read()
        }
        queue.asyncAfter(deadline: .now() + 10) { finish(nil) }
    }

    func closeUDP(_ id: UInt32) {
        udpSessions.removeValue(forKey: id)?.stream.cancel()
    }

    func sendUDP(_ id: UInt32, target: NCTarget, payload: Data) {
        guard state == .ready, udpSessions[id] != nil, let flow = ensureDatagramFlow() else { return }
        for f in NCHy1UDP.frames(session: id, host: target.host, port: UInt16(clamping: target.port), data: payload) {
            flow.send(content: f, completion: .idempotent)
        }
    }

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
            case .ready: self.readDatagrams(c)
            case .failed, .cancelled:
                if self.datagramFlow === c { self.datagramFlow = nil }
                c.cancel()
            default: break
            }
        }
        c.start(queue: queue)
        return c
    }

    /// Also used for flows the server opens (its datagram flow, if Network.framework surfaces it that way).
    func readDatagrams(_ c: NWConnection) {
        c.receiveMessage { [weak self] data, _, _, error in
            guard let self else { c.cancel(); return }
            if let data, let m = NCHy1UDP.unpack(data), let full = self.defragFeed(m) {
                self.udpSessions[full.session]?.handler(full.data)
            }
            if error != nil || self.state != .ready { c.cancel(); return }
            self.readDatagrams(c)
        }
    }
}
