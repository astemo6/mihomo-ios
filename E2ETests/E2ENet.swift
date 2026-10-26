import Foundation
import NetworkExtension

// Tern E2E replay, stage 2: the "device side" of the TUN. A NEPacketTunnelFlow stand-in that NCDataPlane reads from
// and writes to (exactly the object PacketTunnelProvider hands NativeTunnelCore.start), plus a minimal IPv4 TCP / UDP
// client that speaks to the lwIP stack with synthetic packets: SYN → SYN-ACK → ACK, in-order data, FIN / RST, and DNS
// queries to the tunnel DNS (198.18.0.2). The link is in-memory and lossless, so there is no retransmission.

/// The packet flow NCDataPlane drives. readPackets parks the completion until the test injects a packet;
/// writePackets hands every packet the stack emits to `onWrite` (on the lwIP queue).
final class E2EFlow: NEPacketTunnelFlow {
    private let lock = NSLock()
    private var pending: [Data] = []
    private var reader: (([Data], [NSNumber]) -> Void)?
    var onWrite: ((Data) -> Void)?
    private(set) var written = 0
    private(set) var injected = 0

    override func readPackets(completionHandler: @escaping @Sendable ([Data], [NSNumber]) -> Void) {
        lock.lock()
        if !pending.isEmpty {
            let p = pending
            pending = []
            lock.unlock()
            completionHandler(p, p.map { _ in NSNumber(value: AF_INET) })
            return
        }
        reader = completionHandler
        lock.unlock()
    }

    override func writePackets(_ packets: [Data], withProtocols protocols: [NSNumber]) -> Bool {
        lock.lock(); written += packets.count; let w = onWrite; lock.unlock()
        for p in packets { w?(p) }
        return true
    }

    func inject(_ packet: Data) {
        lock.lock()
        injected += 1
        if let r = reader {
            reader = nil
            lock.unlock()
            r([packet], [NSNumber(value: AF_INET)])
        } else {
            pending.append(packet)
            lock.unlock()
        }
    }
}

enum E2EIP {
    static func parse4(_ s: String) -> [UInt8]? {
        let p = s.split(separator: ".").compactMap { UInt8($0) }
        return p.count == 4 ? p : nil
    }

    static func str(_ b: ArraySlice<UInt8>) -> String { b.map(String.init).joined(separator: ".") }

    static func checksum(_ bytes: [UInt8], initial: UInt32 = 0) -> UInt16 {
        var sum = initial
        var i = 0
        while i + 1 < bytes.count { sum &+= UInt32(bytes[i]) << 8 | UInt32(bytes[i + 1]); i += 2 }
        if i < bytes.count { sum &+= UInt32(bytes[i]) << 8 }
        while sum >> 16 != 0 { sum = (sum & 0xffff) &+ (sum >> 16) }
        return ~UInt16(sum & 0xffff)
    }

    static func pseudo(_ src: [UInt8], _ dst: [UInt8], proto: UInt8, len: Int) -> UInt32 {
        var s: UInt32 = 0
        s &+= UInt32(src[0]) << 8 | UInt32(src[1]); s &+= UInt32(src[2]) << 8 | UInt32(src[3])
        s &+= UInt32(dst[0]) << 8 | UInt32(dst[1]); s &+= UInt32(dst[2]) << 8 | UInt32(dst[3])
        s &+= UInt32(proto)
        s &+= UInt32(len)
        return s
    }

    private static var ipID: UInt16 = 1
    private static let idLock = NSLock()

    static func ipv4(src: [UInt8], dst: [UInt8], proto: UInt8, payload: [UInt8]) -> Data {
        idLock.lock(); ipID &+= 1; let id = ipID; idLock.unlock()
        let total = 20 + payload.count
        var h: [UInt8] = [0x45, 0, UInt8(total >> 8), UInt8(total & 0xff), UInt8(id >> 8), UInt8(id & 0xff), 0x40, 0,
                          64, proto, 0, 0] + src + dst
        let c = checksum(h)
        h[10] = UInt8(c >> 8); h[11] = UInt8(c & 0xff)
        return Data(h + payload)
    }

    struct TCPFlags: OptionSet {
        let rawValue: UInt8
        static let fin = TCPFlags(rawValue: 0x01), syn = TCPFlags(rawValue: 0x02), rst = TCPFlags(rawValue: 0x04)
        static let psh = TCPFlags(rawValue: 0x08), ack = TCPFlags(rawValue: 0x10)
    }

    static func tcp(src: [UInt8], dst: [UInt8], sport: UInt16, dport: UInt16, seq: UInt32, ack: UInt32,
                    flags: TCPFlags, window: UInt16 = 65535, payload: [UInt8] = [], mss: UInt16? = nil) -> Data {
        var opts: [UInt8] = []
        if let mss { opts = [2, 4, UInt8(mss >> 8), UInt8(mss & 0xff)] }
        let hlen = 20 + opts.count
        var t: [UInt8] = [UInt8(sport >> 8), UInt8(sport & 0xff), UInt8(dport >> 8), UInt8(dport & 0xff),
                          UInt8(seq >> 24), UInt8(seq >> 16 & 0xff), UInt8(seq >> 8 & 0xff), UInt8(seq & 0xff),
                          UInt8(ack >> 24), UInt8(ack >> 16 & 0xff), UInt8(ack >> 8 & 0xff), UInt8(ack & 0xff),
                          UInt8((hlen / 4) << 4), flags.rawValue, UInt8(window >> 8), UInt8(window & 0xff), 0, 0, 0, 0]
        t += opts
        t += payload
        let c = checksum(t, initial: pseudo(src, dst, proto: 6, len: t.count))
        t[16] = UInt8(c >> 8); t[17] = UInt8(c & 0xff)
        return ipv4(src: src, dst: dst, proto: 6, payload: t)
    }

    static func udp(src: [UInt8], dst: [UInt8], sport: UInt16, dport: UInt16, payload: [UInt8]) -> Data {
        let len = 8 + payload.count
        var u: [UInt8] = [UInt8(sport >> 8), UInt8(sport & 0xff), UInt8(dport >> 8), UInt8(dport & 0xff),
                          UInt8(len >> 8), UInt8(len & 0xff), 0, 0] + payload
        var c = checksum(u, initial: pseudo(src, dst, proto: 17, len: len))
        if c == 0 { c = 0xffff }
        u[6] = UInt8(c >> 8); u[7] = UInt8(c & 0xff)
        return ipv4(src: src, dst: dst, proto: 17, payload: u)
    }

    // DNS (A query / answer)
    static func dnsQuery(id: UInt16, name: String, type: UInt16 = 1) -> [UInt8] {
        var q: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xff), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in name.split(separator: ".") {
            let b = Array(label.utf8)
            q.append(UInt8(b.count)); q += b
        }
        q += [0, UInt8(type >> 8), UInt8(type & 0xff), 0, 1]
        return q
    }

    /// (rcode, IPv4 answers) of a DNS reply.
    static func dnsAnswers(_ m: [UInt8]) -> (rcode: Int, ips: [String])? {
        guard m.count >= 12 else { return nil }
        let rcode = Int(m[3] & 0x0f)
        let qd = Int(m[4]) << 8 | Int(m[5]), an = Int(m[6]) << 8 | Int(m[7])
        var i = 12
        func skipName() -> Bool {
            while i < m.count {
                let l = Int(m[i])
                if l == 0 { i += 1; return true }
                if l & 0xc0 == 0xc0 { i += 2; return true }
                i += 1 + l
            }
            return false
        }
        for _ in 0..<qd { guard skipName() else { return nil }; i += 4 }
        var ips: [String] = []
        for _ in 0..<an {
            guard skipName(), i + 10 <= m.count else { break }
            let type = Int(m[i]) << 8 | Int(m[i + 1])
            let rdlen = Int(m[i + 8]) << 8 | Int(m[i + 9])
            i += 10
            guard i + rdlen <= m.count else { break }
            if type == 1, rdlen == 4 { ips.append(str(m[i..<(i + 4)])) }
            i += rdlen
        }
        return (rcode, ips)
    }
}

/// One synthetic TCP connection from the "device" (198.18.0.1) through the TUN.
final class E2ETCP {
    let sport: UInt16
    let dst: [UInt8]
    let dport: UInt16
    unowned let net: E2ENet
    private let lock = NSLock()
    private var sndNext: UInt32
    private var rcvNext: UInt32 = 0
    private(set) var established = false
    private(set) var synAcked = false
    private(set) var reset = false
    private(set) var finReceived = false
    private var received = Data()
    var onData: ((Data) -> Void)?
    var onEnd: ((_ reset: Bool) -> Void)?
    let openedAt = Date()
    private(set) var establishedAt: Date?

    init(net: E2ENet, sport: UInt16, dst: [UInt8], dport: UInt16) {
        self.net = net
        self.sport = sport
        self.dst = dst
        self.dport = dport
        sndNext = UInt32.random(in: 1_000_000...0x7fff_ffff)
    }

    var data: Data { lock.lock(); defer { lock.unlock() }; return received }
    var text: String { String(decoding: data, as: UTF8.self) }
    var isEnded: Bool { lock.lock(); defer { lock.unlock() }; return reset || finReceived }

    func open() {
        lock.lock(); let seq = sndNext; sndNext &+= 1; lock.unlock()
        net.flow.inject(E2EIP.tcp(src: net.src, dst: dst, sport: sport, dport: dport, seq: seq, ack: 0, flags: [.syn], mss: 1360))
    }

    func send(_ bytes: Data) {
        var off = 0
        let all = [UInt8](bytes)
        while off < all.count {
            let n = min(1300, all.count - off)
            lock.lock(); let seq = sndNext; sndNext &+= UInt32(n); let ack = rcvNext; lock.unlock()
            net.flow.inject(E2EIP.tcp(src: net.src, dst: dst, sport: sport, dport: dport, seq: seq, ack: ack,
                                      flags: [.psh, .ack], payload: Array(all[off..<(off + n)])))
            off += n
        }
    }

    func close() {
        lock.lock(); let seq = sndNext; sndNext &+= 1; let ack = rcvNext; let done = reset; lock.unlock()
        guard !done else { return }
        net.flow.inject(E2EIP.tcp(src: net.src, dst: dst, sport: sport, dport: dport, seq: seq, ack: ack, flags: [.fin, .ack]))
    }

    func abort() {
        lock.lock(); let seq = sndNext; let ack = rcvNext; lock.unlock()
        net.flow.inject(E2EIP.tcp(src: net.src, dst: dst, sport: sport, dport: dport, seq: seq, ack: ack, flags: [.rst, .ack]))
    }

    /// A segment for this connection (called on the lwIP queue).
    func handle(flags: E2EIP.TCPFlags, seq: UInt32, ack: UInt32, payload: ArraySlice<UInt8>) {
        var reply: Data?
        var deliver: Data?
        var ended: Bool?
        lock.lock()
        if flags.contains(.rst) {
            reset = true
            ended = true
        } else if flags.contains(.syn) && flags.contains(.ack) {
            synAcked = true
            if !established {
                rcvNext = seq &+ 1
                established = true
                establishedAt = Date()
            }
            reply = E2EIP.tcp(src: net.src, dst: dst, sport: sport, dport: dport, seq: sndNext, ack: rcvNext, flags: [.ack])
        } else {
            var advanced = false
            if !payload.isEmpty {
                if seq == rcvNext {
                    received.append(contentsOf: payload)
                    deliver = Data(payload)
                    rcvNext &+= UInt32(payload.count)
                    advanced = true
                }
                // duplicate / out of order: re-ACK what we have (lossless link, should not happen)
            }
            if flags.contains(.fin) && (seq &+ UInt32(payload.count)) == rcvNext && !finReceived {
                finReceived = true
                rcvNext &+= 1
                ended = false
                advanced = true
            }
            if advanced || !payload.isEmpty {
                reply = E2EIP.tcp(src: net.src, dst: dst, sport: sport, dport: dport, seq: sndNext, ack: rcvNext, flags: [.ack])
            }
        }
        let od = onData, oe = onEnd
        lock.unlock()
        if let reply { net.flow.inject(reply) }
        if let deliver { od?(deliver) }
        if let ended { oe?(ended) }
    }
}

/// The device side: demultiplexes what the stack writes to the synthetic connections / DNS waiters.
final class E2ENet {
    let flow: E2EFlow
    let src: [UInt8] = [198, 18, 0, 1]
    let dnsServer: [UInt8] = [198, 18, 0, 2]
    private let lock = NSLock()
    private var tcp: [UInt16: E2ETCP] = [:]
    private var udpWaiters: [UInt16: ([UInt8]) -> Void] = [:]
    private var nextPort: UInt16 = 40000
    private(set) var unmatched = 0

    init(flow: E2EFlow) {
        self.flow = flow
        flow.onWrite = { [weak self] p in self?.ingest(p) }
    }

    private func port() -> UInt16 {
        lock.lock(); defer { lock.unlock() }
        nextPort = nextPort >= 60000 ? 40000 : nextPort + 1
        return nextPort
    }

    func connect(_ ip: String, _ port: UInt16) -> E2ETCP? {
        guard let dst = E2EIP.parse4(ip) else { return nil }
        let c = E2ETCP(net: self, sport: self.port(), dst: dst, dport: port)
        lock.lock(); tcp[c.sport] = c; lock.unlock()
        c.open()
        return c
    }

    func forget(_ c: E2ETCP) { lock.lock(); tcp[c.sport] = nil; lock.unlock() }

    /// A DNS A query to the tunnel DNS (198.18.0.2:53); nil on timeout.
    func resolve(_ name: String, timeout: TimeInterval = 5) -> (rcode: Int, ips: [String])? {
        let sport = port()
        let box = ReplyBox()
        lock.lock()
        udpWaiters[sport] = { r in box.set(r) }
        lock.unlock()
        let id = UInt16.random(in: 1...0xfffe)
        flow.inject(E2EIP.udp(src: src, dst: dnsServer, sport: sport, dport: 53, payload: E2EIP.dnsQuery(id: id, name: name)))
        _ = Self.waitUntil(timeout) { box.get() != nil }
        lock.lock(); udpWaiters[sport] = nil; lock.unlock()
        guard let reply = box.get() else { return nil }
        return E2EIP.dnsAnswers(reply)
    }

    private func ingest(_ p: Data) {
        let b = [UInt8](p)
        guard b.count >= 20, b[0] >> 4 == 4 else { return }
        let ihl = Int(b[0] & 0x0f) * 4
        guard b.count >= ihl + 8 else { return }
        let proto = b[9]
        let l4 = ihl
        let dport = UInt16(b[l4 + 2]) << 8 | UInt16(b[l4 + 3])
        if proto == 6, b.count >= l4 + 20 {
            let seq = UInt32(b[l4 + 4]) << 24 | UInt32(b[l4 + 5]) << 16 | UInt32(b[l4 + 6]) << 8 | UInt32(b[l4 + 7])
            let ack = UInt32(b[l4 + 8]) << 24 | UInt32(b[l4 + 9]) << 16 | UInt32(b[l4 + 10]) << 8 | UInt32(b[l4 + 11])
            let off = Int(b[l4 + 12] >> 4) * 4
            let flags = E2EIP.TCPFlags(rawValue: b[l4 + 13])
            let total = min(b.count, Int(b[2]) << 8 | Int(b[3]))
            let payload = l4 + off <= total ? b[(l4 + off)..<total] : []
            lock.lock(); let c = tcp[dport]; lock.unlock()
            if let c { c.handle(flags: flags, seq: seq, ack: ack, payload: payload) } else { lock.lock(); unmatched += 1; lock.unlock() }
        } else if proto == 17 {
            let total = min(b.count, Int(b[2]) << 8 | Int(b[3]))
            guard total >= l4 + 8 else { return }
            lock.lock(); let w = udpWaiters[dport]; lock.unlock()
            w?(Array(b[(l4 + 8)..<total]))
        }
    }

    // MARK: blocking helpers for the tests

    private final class ReplyBox {
        private let lock = NSLock()
        private var value: [UInt8]?
        func set(_ v: [UInt8]) { lock.lock(); if value == nil { value = v }; lock.unlock() }
        func get() -> [UInt8]? { lock.lock(); defer { lock.unlock() }; return value }
    }

    /// Polls `cond` every `every` seconds; on the main thread the run loop keeps turning (main-queue work is never
    /// starved).
    ///
    /// fix/nc-mem-2: every evaluation of `cond` runs in its own autorelease pool. The test method runs on the main
    /// thread inside one outer run-loop iteration, so objects a poll autoreleased outside the nested `run(until:)`
    /// (URLSession tasks + their responses, NSJSONSerialization trees, bridged strings) were only released when the
    /// test returned. providers() polled GET /providers/proxies this way ~22×/s for 25 s (a 403 provider never fills)
    /// — ~575 requests whose leftovers stayed in the test process inside the memory-footprint window (run
    /// 40306946475: providers+rule-sets settled at +37.0 MB). The tunnel never runs this loop.
    static func waitUntil(_ timeout: TimeInterval, every: TimeInterval = 0.02, _ cond: () -> Bool) -> Bool {
        let end = Date().addingTimeInterval(timeout)
        while Date() < end {
            if autoreleasepool(invoking: cond) { return true }
            autoreleasepool {
                if Thread.isMainThread {
                    RunLoop.current.run(until: Date().addingTimeInterval(every))
                } else {
                    Thread.sleep(forTimeInterval: every)
                }
            }
        }
        return autoreleasepool(invoking: cond)
    }

    struct HTTPResult {
        var established: Bool
        var reset: Bool
        var finished: Bool
        var text: String
        var ms: Int
        var status: Int? {
            guard text.hasPrefix("HTTP/") else { return nil }
            let parts = text.split(separator: " ", maxSplits: 2)
            return parts.count > 1 ? Int(parts[1]) : nil
        }
    }

    /// One plain HTTP/1.1 GET over a synthetic TCP connection to ip:port with the given Host header.
    func httpGet(ip: String, port: UInt16, host: String, path: String, timeout: TimeInterval = 10) -> HTTPResult {
        let t0 = Date()
        guard let c = connect(ip, port) else { return HTTPResult(established: false, reset: false, finished: false, text: "bad ip", ms: 0) }
        defer { forget(c) }
        guard Self.waitUntil(min(timeout, 5), { c.established || c.reset }), c.established else {
            return HTTPResult(established: false, reset: c.reset, finished: false, text: "", ms: Int(Date().timeIntervalSince(t0) * 1000))
        }
        let req = "GET \(path) HTTP/1.1\r\nHost: \(host)\r\nUser-Agent: TernE2E/1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        c.send(Data(req.utf8))
        _ = Self.waitUntil(timeout) { c.isEnded }
        let ended = c.isEnded
        if !c.reset { c.close() }
        return HTTPResult(established: true, reset: c.reset, finished: ended, text: c.text, ms: Int(Date().timeIntervalSince(t0) * 1000))
    }
}
