import Foundation
import Network

// kcptun smux multi-stream session, stream multiplexer, and node-shared UDP session lifecycle.
// Reference: metacubex/smux (session.go, stream.go, frame.go), transport/kcptun (client.go).

// MARK: - Smux Stream Relay

final class NCKcptunSmuxStream: NCRelayStream {
    let sid: UInt32
    private weak var session: NCKcptunSmuxSession?
    private var inbuf: [Data] = []
    private var pendingReadHandler: ((Data?, Error?) -> Void)?
    private var peerClosed = false
    private var failure: Error?
    private var closed = false
    private let lock = NSLock()

    init(sid: UInt32, session: NCKcptunSmuxSession) {
        self.sid = sid
        self.session = session
    }

    func feedData(_ data: Data) {
        lock.lock()
        defer { lock.unlock() }
        guard !closed else { return }
        if let handler = pendingReadHandler {
            pendingReadHandler = nil
            session?.queue.async { handler(data, nil) }
        } else {
            inbuf.append(data)
        }
    }

    func feedClose(error: Error?) {
        lock.lock()
        defer { lock.unlock() }
        peerClosed = true
        failure = error
        if let handler = pendingReadHandler {
            pendingReadHandler = nil
            let payload = inbuf.isEmpty ? nil : inbuf.removeFirst()
            let err = inbuf.isEmpty ? error : nil
            session?.queue.async { handler(payload, err) }
        }
    }

    func send(_ data: Data) {
        session?.sendStreamData(sid: sid, data: data, completion: nil)
    }

    func send(_ data: Data, completion: @escaping () -> Void) {
        session?.sendStreamData(sid: sid, data: data, completion: completion)
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        lock.lock()
        defer { lock.unlock() }
        if !inbuf.isEmpty {
            let data = inbuf.removeFirst()
            session?.queue.async { handler(data, nil) }
            return
        }
        if let failure {
            session?.queue.async { handler(nil, failure) }
            return
        }
        if peerClosed {
            session?.queue.async { handler(nil, nil) }
            return
        }
        pendingReadHandler = handler
    }

    func cancel() {
        lock.lock()
        guard !closed else { lock.unlock(); return }
        closed = true
        lock.unlock()
        session?.closeStream(sid: sid)
    }
}

// MARK: - Smux Session

final class NCKcptunSmuxSession {
    let smuxVer: Int
    let maxFrameSize: Int
    let queue: DispatchQueue
    private weak var transport: NCKcptunSession?

    private var nextStreamID: UInt32 = 1 // Client streams: 1, 3, 5, 7...
    private var streams: [UInt32: NCKcptunSmuxStream] = [:]
    private var inbuf = Data()
    private var closed = false
    private let lock = NSLock()

    init(smuxVer: Int, maxFrameSize: Int, queue: DispatchQueue, transport: NCKcptunSession) {
        self.smuxVer = smuxVer
        self.maxFrameSize = maxFrameSize
        self.queue = queue
        self.transport = transport
    }

    var activeStreamCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return streams.count
    }

    func openStream() -> NCKcptunSmuxStream? {
        lock.lock()
        guard !closed else { lock.unlock(); return nil }
        let sid = nextStreamID
        nextStreamID &+= 2
        let stream = NCKcptunSmuxStream(sid: sid, session: self)
        streams[sid] = stream
        lock.unlock()

        // Send cmdSYN (cmd = 0)
        let synFrame = makeHeader(cmd: 0, sid: sid, len: 0)
        transport?.sendToKCP(synFrame)
        return stream
    }

    func sendStreamData(sid: UInt32, data: Data, completion: (() -> Void)?) {
        guard !data.isEmpty else { completion?(); return }
        var rest = data[...]
        while !rest.isEmpty {
            let chunk = Data(rest.prefix(maxFrameSize))
            rest = rest.dropFirst(chunk.count)
            var frame = makeHeader(cmd: 2, sid: sid, len: UInt16(chunk.count))
            frame.append(chunk)
            transport?.sendToKCP(frame)
        }
        completion?()
    }

    func closeStream(sid: UInt32) {
        lock.lock()
        let stream = streams.removeValue(forKey: sid)
        lock.unlock()
        guard stream != nil else { return }

        // Send cmdFIN (cmd = 1)
        let finFrame = makeHeader(cmd: 1, sid: sid, len: 0)
        transport?.sendToKCP(finFrame)
    }

    func feedBytes(_ data: Data) {
        inbuf.append(data)
        while inbuf.count >= 8 {
            let s = inbuf.startIndex
            let ver = inbuf[s]
            let cmd = inbuf[s + 1]
            let len = Int(inbuf[s + 2]) | (Int(inbuf[s + 3]) << 8)
            let sid = UInt32(inbuf[s + 4]) | UInt32(inbuf[s + 5]) << 8 | UInt32(inbuf[s + 6]) << 16 | UInt32(inbuf[s + 7]) << 24
            guard inbuf.count >= 8 + len else { break }

            let body = inbuf.subdata(in: (s + 8)..<(s + 8 + len))
            inbuf = Data(inbuf.dropFirst(8 + len))

            guard ver == smuxVer || ver == 1 else { continue }

            lock.lock()
            let stream = streams[sid]
            lock.unlock()

            switch cmd {
            case 0: // cmdSYN (server opened stream; not used in client mode)
                break
            case 1: // cmdFIN
                stream?.feedClose(error: nil)
                lock.lock()
                streams.removeValue(forKey: sid)
                lock.unlock()
            case 2: // cmdPSH
                stream?.feedData(body)
            case 3: // cmdNOP (keep-alive)
                break
            case 4: // cmdUPD (smux v2 flow control)
                break
            default:
                break
            }
        }
    }

    func sendKeepAlive() {
        guard !closed else { return }
        let nopFrame = makeHeader(cmd: 3, sid: 0, len: 0)
        transport?.sendToKCP(nopFrame)
    }

    func close(error: Error?) {
        lock.lock()
        guard !closed else { lock.unlock(); return }
        closed = true
        let all = Array(streams.values)
        streams.removeAll()
        lock.unlock()
        for stream in all {
            stream.feedClose(error: error ?? NCFramedRelay.err("kcptun: session closed"))
        }
    }

    private func makeHeader(cmd: UInt8, sid: UInt32, len: UInt16) -> Data {
        var h = Data(capacity: 8)
        h.append(UInt8(smuxVer))
        h.append(cmd)
        h.append(UInt8(len & 0xff)); h.append(UInt8((len >> 8) & 0xff))
        h.append(UInt8(sid & 0xff)); h.append(UInt8((sid >> 8) & 0xff))
        h.append(UInt8((sid >> 16) & 0xff)); h.append(UInt8((sid >> 24) & 0xff))
        return h
    }
}

// MARK: - Long-Lived Node UDP Session

final class NCKcptunSession {
    let server: String
    let port: Int
    let options: NCKcptunOptions
    let queue: DispatchQueue

    private var conn: NWConnection?
    private var blockCrypt: NCKcptunBlockCrypt?
    private var fec: NCKcptunFEC?
    private var kcp: NCKCP?
    private var snappy: NCSnappyFramedStream?
    private(set) var smux: NCKcptunSmuxSession?

    private var updateTimer: DispatchSourceTimer?
    private var keepAliveTimer: DispatchSourceTimer?
    private(set) var expiryDate: Date?
    private(set) var isClosed = false
    private var failure: Error?

    init(server: String, port: Int, options: NCKcptunOptions, queue: DispatchQueue) {
        self.server = server
        self.port = port
        self.options = options
        self.queue = queue
        if options.autoExpire > 0 {
            self.expiryDate = Date().addingTimeInterval(TimeInterval(options.autoExpire))
        }
    }

    var isExpired: Bool {
        guard let exp = expiryDate else { return false }
        return Date() > exp
    }

    func start(completion: @escaping (Error?) -> Void) {
        guard let crypt = NCKcptunBlockCrypt(crypt: options.crypt, password: options.key) else {
            completion(NCFramedRelay.err("kcptun: invalid crypt or password"))
            return
        }
        self.blockCrypt = crypt
        self.fec = NCKcptunFEC(dataShards: options.dataShard, parityShards: options.parityShard)

        let convid = UInt32.random(in: 1...UInt32.max)
        let k = NCKCP(conv: convid) { [weak self] segData in
            self?.sendKCPOut(segData)
        }
        k.setNoDelay(nodelay: options.noDelay, interval: options.interval, resend: options.resend, nc: options.nc)
        k.setWindowSize(sndwnd: options.sndWnd, rcvwnd: options.rcvWnd)
        k.setMTU(options.mtu)
        self.kcp = k

        if !options.noComp {
            self.snappy = NCSnappyFramedStream()
        }

        self.smux = NCKcptunSmuxSession(smuxVer: options.smuxVer, maxFrameSize: options.frameSize, queue: queue, transport: self)

        // Outbound UDP connection bound to physical interface
        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(server), port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any)
        let params = NCOutboundBinding.params(.udp, host: server)
        let c = NWConnection(to: endpoint, using: params)
        self.conn = c

        var startCompleted = false
        c.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                if !startCompleted {
                    startCompleted = true
                    self.startPumping()
                    completion(nil)
                }
            case .failed(let err):
                if !startCompleted {
                    startCompleted = true
                    completion(err)
                }
                self.close(error: err)
            case .cancelled:
                self.close(error: nil)
            default:
                break
            }
        }
        c.start(queue: queue)
    }

    private func startPumping() {
        readLoop()

        // KCP update timer (running at options.interval ms)
        let timer = DispatchSource.makeTimerSource(queue: queue)
        let itvMs = max(10, options.interval)
        timer.schedule(deadline: .now(), repeating: .milliseconds(itvMs), leeway: .milliseconds(5))
        timer.setEventHandler { [weak self] in
            guard let self, !self.isClosed else { return }
            self.kcp?.update(currentMs: NCKCP.currentMs())
            self.drainKCP()
        }
        timer.resume()
        self.updateTimer = timer

        // Smux keep-alive timer (every options.keepAlive seconds)
        if options.keepAlive > 0 {
            let kaTimer = DispatchSource.makeTimerSource(queue: queue)
            kaTimer.schedule(deadline: .now() + .seconds(options.keepAlive), repeating: .seconds(options.keepAlive), leeway: .seconds(1))
            kaTimer.setEventHandler { [weak self] in
                self?.smux?.sendKeepAlive()
            }
            kaTimer.resume()
            self.keepAliveTimer = kaTimer
        }
    }

    private func readLoop() {
        guard let conn, !isClosed else { return }
        conn.receiveMessage { [weak self] content, _, _, error in
            guard let self else { return }
            if let content, !content.isEmpty {
                self.handleIncomingDatagram(content)
            }
            if let error {
                self.close(error: error)
                return
            }
            if !self.isClosed {
                self.readLoop()
            }
        }
    }

    private func handleIncomingDatagram(_ datagram: Data) {
        guard let blockCrypt, let fec, let kcp else { return }
        guard let plain = blockCrypt.open(datagram) else { return }
        let kcpPackets = fec.decode(packet: plain)
        for pkt in kcpPackets {
            _ = kcp.input(data: pkt)
        }
        drainKCP()
    }

    private func drainKCP() {
        guard let kcp, let smux else { return }
        while let chunk = kcp.recv() {
            if let snappy {
                do {
                    let pieces = try snappy.decode(data: chunk)
                    for piece in pieces { smux.feedBytes(piece) }
                } catch {
                    // Snappy error drops malformed chunk
                }
            } else {
                smux.feedBytes(chunk)
            }
        }
    }

    func sendToKCP(_ bytes: Data) {
        guard let kcp, !isClosed else { return }
        if let snappy {
            let compressed = snappy.encode(data: bytes)
            kcp.send(data: compressed)
        } else {
            kcp.send(data: bytes)
        }
        kcp.flush()
    }

    private func sendKCPOut(_ segData: Data) {
        guard let conn, let blockCrypt, let fec, !isClosed else { return }
        let (dataPacket, parities) = fec.encode(packet: segData)
        let sealedData = blockCrypt.seal(dataPacket)
        conn.send(content: sealedData, completion: .contentProcessed { _ in })
        for p in parities {
            let sealedP = blockCrypt.seal(p)
            conn.send(content: sealedP, completion: .contentProcessed { _ in })
        }
    }

    func close(error: Error?) {
        guard !isClosed else { return }
        isClosed = true
        failure = error

        updateTimer?.cancel()
        updateTimer = nil
        keepAliveTimer?.cancel()
        keepAliveTimer = nil

        smux?.close(error: error)
        conn?.cancel()
        conn = nil
    }
}

// MARK: - Node-Shared Session Pool

final class NCKcptunSessionPool {
    static let shared = NCKcptunSessionPool()
    private var sessions: [String: NCKcptunSession] = [:]
    private let lock = NSLock()

    private init() {}

    /// Gets an existing active session or starts a fresh one for the given node.
    func getOrCreate(server: String, port: Int, options: NCKcptunOptions, queue: DispatchQueue,
                     completion: @escaping (NCKcptunSession?, Error?) -> Void) {
        let key = "\(server):\(port):\(options.cacheKey)"

        lock.lock()
        if let existing = sessions[key], !existing.isClosed && !existing.isExpired {
            lock.unlock()
            completion(existing, nil)
            return
        }
        let session = NCKcptunSession(server: server, port: port, options: options, queue: queue)
        sessions[key] = session
        lock.unlock()

        session.start { [weak self] err in
            if let err {
                self?.lock.lock()
                self?.sessions.removeValue(forKey: key)
                self?.lock.unlock()
                completion(nil, err)
            } else {
                completion(session, nil)
            }
        }
    }

    /// Periodic scavenge or prune of expired/idle sessions.
    func scavenge() {
        lock.lock()
        defer { lock.unlock() }
        for (k, sesh) in sessions {
            if sesh.isClosed || (sesh.isExpired && sesh.smux?.activeStreamCount == 0) {
                sesh.close(error: nil)
                sessions.removeValue(forKey: k)
            }
        }
    }

    /// Teardown all sessions on config reload / core reset.
    func reset() {
        lock.lock()
        let all = Array(sessions.values)
        sessions.removeAll()
        lock.unlock()
        for s in all { s.close(error: nil) }
    }
}
