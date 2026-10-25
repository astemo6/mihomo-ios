import Foundation
import Network
import os

// kcptun smux multi-stream session, stream multiplexer, and node-shared UDP session lifecycle.
// Reference: xtaci/smux + metacubex/smux (session.go, stream.go, frame.go), mihomo transport/kcptun (client.go).
//
// Threading: every KCP / FEC / crypt / snappy / smux-parser touch runs on the session's own serial queue
// (NCSessionQueues). Streams hand data and completions back on the queue of the caller that opened them.
//
// Memory (Network Extension budget):
//  - receive: the session stops pulling from KCP once `smuxBuf` bytes sit unread in stream buffers; KCP's
//    rcv_queue then fills, the advertised window drops to 0 and the server stops sending (smux v1 has no
//    per-stream window). smux v2 additionally sends cmdUPD only for bytes the consumer actually read, so a
//    stream never holds more than the peer window (`streamBuf`).
//  - send: a stream's send completion is held while KCP has more than `sendHighWater` segments queued, which
//    is the relay pump's uplink back-pressure signal.
//  - an idle session (no streams, nothing in flight) closes itself after `idleTimeout`, stopping its timer.

// MARK: - Smux Stream Relay

final class NCKcptunSmuxStream: NCRelayStream {
    let sid: UInt32
    private weak var session: NCKcptunSmuxSession?
    private let callerQueue: DispatchQueue
    private var inbuf: [Data] = []
    private var inbufBytes = 0
    private var pendingReadHandler: ((Data?, Error?) -> Void)?
    private var peerClosed = false
    private var failure: Error?
    private var closed = false
    // smux v2 receive-side window accounting (stream.go numRead / incr).
    private var numRead: UInt32 = 0
    private var incr: UInt32 = 0
    private let lock = NSLock()

    init(sid: UInt32, session: NCKcptunSmuxSession, callerQueue: DispatchQueue) {
        self.sid = sid
        self.session = session
        self.callerQueue = callerQueue
    }

    /// Caller holds `lock`. Returns the cumulative consumed count to announce in a cmdUPD, if one is due.
    private func consumedLocked(_ n: Int) -> UInt32? {
        let un = UInt32(truncatingIfNeeded: n)
        numRead &+= un
        incr &+= un
        guard let s = session, s.smuxVer >= 2 else { return nil }
        if incr >= s.windowUpdateThreshold || numRead == un {
            incr = 0
            return numRead
        }
        return nil
    }

    /// Session queue: one cmdPSH payload for this stream.
    func feedData(_ data: Data) {
        lock.lock()
        if closed { lock.unlock(); return }
        if let handler = pendingReadHandler {
            pendingReadHandler = nil
            let upd = consumedLocked(data.count)
            lock.unlock()
            callerQueue.async { handler(data, nil) }
            if let upd { session?.sendWindowUpdate(sid: sid, consumed: upd) }
        } else {
            inbuf.append(data)
            inbufBytes += data.count
            lock.unlock()
            session?.adjustBuffered(data.count)
        }
    }

    func feedClose(error: Error?) {
        lock.lock()
        peerClosed = true
        if failure == nil { failure = error }
        if let handler = pendingReadHandler {
            pendingReadHandler = nil
            // pendingReadHandler is only set while inbuf is empty.
            let err = failure
            lock.unlock()
            callerQueue.async { handler(nil, err) }
            return
        }
        lock.unlock()
    }

    func send(_ data: Data) {
        send(data, completion: {})
    }

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        let q = callerQueue
        guard let session else { q.async { once.call() }; return }
        session.sendStreamData(sid: sid, data: data) { q.async { once.call() } }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        lock.lock()
        if !inbuf.isEmpty {
            let data = inbuf.removeFirst()
            inbufBytes -= data.count
            let upd = consumedLocked(data.count)
            lock.unlock()
            callerQueue.async { handler(data, nil) }
            session?.adjustBuffered(-data.count)
            if let upd { session?.sendWindowUpdate(sid: sid, consumed: upd) }
            return
        }
        if peerClosed || closed {
            let err = failure
            lock.unlock()
            callerQueue.async { handler(nil, err) }
            return
        }
        pendingReadHandler = handler
        lock.unlock()
    }

    func cancel() {
        lock.lock()
        guard !closed else { lock.unlock(); return }
        closed = true
        let dropped = inbufBytes
        inbuf.removeAll()
        inbufBytes = 0
        let handler = pendingReadHandler
        pendingReadHandler = nil
        lock.unlock()
        if let handler { callerQueue.async { handler(nil, nil) } }
        if dropped > 0 { session?.adjustBuffered(-dropped) }
        session?.closeStream(sid: sid)
    }
}

// MARK: - Smux Session

final class NCKcptunSmuxSession {
    let smuxVer: Int
    let maxFrameSize: Int
    let streamBuf: Int
    let receiveBufferLimit: Int
    let windowUpdateThreshold: UInt32
    private weak var transport: NCKcptunSession?

    private var nextStreamID: UInt32 = 1 // client streams are odd: 1, 3, 5, ...
    private var streams: [UInt32: NCKcptunSmuxStream] = [:]
    private var bufferedBytes = 0
    private var closed = false
    private let lock = NSLock()

    // Session-queue only (frame parser).
    private var inbuf = Data()
    private var inOff = 0

    init(smuxVer: Int, maxFrameSize: Int, streamBuf: Int, receiveBufferLimit: Int, transport: NCKcptunSession) {
        self.smuxVer = smuxVer
        self.maxFrameSize = max(1, min(maxFrameSize, 65535))
        self.streamBuf = max(1, streamBuf)
        self.receiveBufferLimit = max(65536, receiveBufferLimit)
        self.windowUpdateThreshold = UInt32(max(1, streamBuf / 2))
        self.transport = transport
    }

    var activeStreamCount: Int {
        lock.lock(); defer { lock.unlock() }
        return streams.count
    }

    /// Bytes delivered by the server but not yet read by any stream consumer.
    var unreadBytes: Int {
        lock.lock(); defer { lock.unlock() }
        return bufferedBytes
    }

    func adjustBuffered(_ delta: Int) {
        lock.lock()
        let wasFull = bufferedBytes >= receiveBufferLimit
        bufferedBytes = max(0, bufferedBytes + delta)
        let resume = wasFull && bufferedBytes < receiveBufferLimit
        lock.unlock()
        if resume { transport?.resumeReceive() }
    }

    func openStream(callerQueue: DispatchQueue) -> NCKcptunSmuxStream? {
        lock.lock()
        guard !closed else { lock.unlock(); return nil }
        let sid = nextStreamID
        nextStreamID &+= 2
        let stream = NCKcptunSmuxStream(sid: sid, session: self, callerQueue: callerQueue)
        streams[sid] = stream
        lock.unlock()

        transport?.sendFrames([makeHeader(cmd: 0, sid: sid, len: 0)], completion: nil) // cmdSYN
        return stream
    }

    func sendStreamData(sid: UInt32, data: Data, completion: @escaping () -> Void) {
        guard !data.isEmpty, let transport else { completion(); return }
        var frames: [Data] = []
        var off = data.startIndex
        while off < data.endIndex {
            let end = min(off + maxFrameSize, data.endIndex)
            var frame = makeHeader(cmd: 2, sid: sid, len: UInt16(end - off)) // cmdPSH
            frame.append(data[off..<end])
            frames.append(frame)
            off = end
        }
        transport.sendFrames(frames, completion: completion)
    }

    /// smux v2 cmdUPD: [consumed u32 LE][window u32 LE] (stream.go sendWindowUpdate).
    func sendWindowUpdate(sid: UInt32, consumed: UInt32) {
        var frame = makeHeader(cmd: 4, sid: sid, len: 8)
        let window = UInt32(clamping: streamBuf)
        for v in [consumed, window] {
            frame.append(UInt8(v & 0xff)); frame.append(UInt8((v >> 8) & 0xff))
            frame.append(UInt8((v >> 16) & 0xff)); frame.append(UInt8((v >> 24) & 0xff))
        }
        transport?.sendFrames([frame], completion: nil)
    }

    func closeStream(sid: UInt32) {
        lock.lock()
        let stream = streams.removeValue(forKey: sid)
        lock.unlock()
        guard stream != nil else { return }
        transport?.sendFrames([makeHeader(cmd: 1, sid: sid, len: 0)], completion: nil) // cmdFIN
        transport?.noteActivity()
    }

    /// Session queue: demultiplexed bytes from KCP (after snappy).
    func feedBytes(_ data: Data) {
        inbuf.append(data)
        while inbuf.count - inOff >= 8 {
            let s = inbuf.startIndex + inOff
            let ver = inbuf[s]
            let cmd = inbuf[s + 1]
            let len = Int(inbuf[s + 2]) | (Int(inbuf[s + 3]) << 8)
            let sid = UInt32(inbuf[s + 4]) | UInt32(inbuf[s + 5]) << 8 | UInt32(inbuf[s + 6]) << 16 | UInt32(inbuf[s + 7]) << 24
            guard inbuf.count - inOff >= 8 + len else { break }
            let body = inbuf.subdata(in: (s + 8)..<(s + 8 + len))
            inOff += 8 + len

            guard ver == UInt8(truncatingIfNeeded: smuxVer) else {
                // Version mismatch = desynced stream (session.go recvLoop returns ErrInvalidProtocol).
                transport?.fail(NCFramedRelay.err("kcptun: smux version \(ver) != \(smuxVer)"))
                return
            }

            lock.lock()
            let stream = streams[sid]
            lock.unlock()

            switch cmd {
            case 1: // cmdFIN
                stream?.feedClose(error: nil)
                lock.lock()
                streams.removeValue(forKey: sid)
                lock.unlock()
            case 2: // cmdPSH
                if !body.isEmpty { stream?.feedData(body) }
            default:
                // cmdSYN (server-opened streams are not used by a client), cmdNOP keep-alive,
                // cmdUPD (peer window; the server buffers what we send beyond it).
                break
            }
        }
        if inOff >= inbuf.count {
            inbuf = Data()
            inOff = 0
        } else if inOff > 65536 && inOff > inbuf.count / 2 {
            inbuf = inbuf.subdata(in: (inbuf.startIndex + inOff)..<inbuf.endIndex)
            inOff = 0
        }
    }

    func keepAliveFrame() -> Data {
        makeHeader(cmd: 3, sid: 0, len: 0) // cmdNOP
    }

    func close(error: Error?) {
        lock.lock()
        guard !closed else { lock.unlock(); return }
        closed = true
        let all = Array(streams.values)
        streams.removeAll()
        bufferedBytes = 0
        lock.unlock()
        for stream in all {
            stream.feedClose(error: error ?? NCFramedRelay.err("kcptun: session closed"))
        }
    }

    private func makeHeader(cmd: UInt8, sid: UInt32, len: UInt16) -> Data {
        var h = Data(capacity: 8 + Int(len))
        h.append(UInt8(truncatingIfNeeded: smuxVer))
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
    let poolKey: String

    /// Idle sessions (no streams, nothing in flight) close after this long; the next dial opens a fresh one.
    static let idleTimeout: TimeInterval = 60

    private var conn: NWConnection?
    private let blockCrypt: NCKcptunBlockCrypt
    private let fec: NCKcptunFEC
    private var kcp: NCKCP?
    private let snappy: NCSnappyFramedStream?
    private(set) var smux: NCKcptunSmuxSession?

    private var updateTimer: DispatchSourceTimer?
    private var keepAliveTimer: DispatchSourceTimer?
    private var parkedCompletions: [() -> Void] = []
    private var lastActive = Date()
    private let sendHighWater: Int
    let expiryDate: Date?
    private let closedFlag = OSAllocatedUnfairLock(initialState: false)
    var isClosed: Bool { closedFlag.withLock { $0 } }

    init?(server: String, port: Int, options: NCKcptunOptions, poolKey: String) {
        guard let crypt = NCKcptunBlockCrypt(crypt: options.crypt, password: options.key) else { return nil }
        self.server = server
        self.port = port
        self.options = options
        self.poolKey = poolKey
        self.queue = NCSessionQueues.make("nc.kcptun.\(server):\(port)")
        self.blockCrypt = crypt
        self.fec = NCKcptunFEC(dataShards: options.dataShard, parityShards: options.parityShard)
        self.snappy = options.noComp ? nil : NCSnappyFramedStream()
        self.sendHighWater = max(64, 2 * options.sndWnd)
        self.expiryDate = options.autoExpire > 0 ? Date().addingTimeInterval(TimeInterval(options.autoExpire)) : nil

        // Everything a stream touches exists before the session is published in the pool.
        let k = NCKCP(conv: UInt32.random(in: 1...UInt32.max), output: nil)
        k.setNoDelay(nodelay: options.noDelay, interval: options.interval, resend: options.resend, nc: options.nc)
        k.setWindowSize(sndwnd: options.sndWnd, rcvwnd: options.rcvWnd)
        // kcp-go SetMtu: the KCP MTU excludes the crypt (nonce + crc / AEAD nonce + tag) and FEC headers.
        k.setMTU(options.mtu - blockCrypt.overhead - (options.fecEnabled ? 8 : 0))
        self.kcp = k
        self.smux = NCKcptunSmuxSession(smuxVer: options.smuxVer, maxFrameSize: options.frameSize,
                                        streamBuf: options.streamBuf, receiveBufferLimit: options.smuxBuf,
                                        transport: self)
        k.output = { [weak self] segData in self?.sendKCPOut(segData) }
    }

    var isExpired: Bool {
        guard let exp = expiryDate else { return false }
        return Date() > exp
    }

    /// Completion runs on the session queue.
    func start(completion: @escaping (Error?) -> Void) {
        ncOnSessionQueue(queue) { self.startOnQueue(completion) }
    }

    private func startOnQueue(_ completion: @escaping (Error?) -> Void) {
        guard !isClosed else { completion(NCFramedRelay.err("kcptun: session closed")); return }
        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(server),
                                           port: NWEndpoint.Port(rawValue: UInt16(clamping: port)) ?? .any)
        let params = NCOutboundBinding.params(.udp, host: server)
        let c = NWConnection(to: endpoint, using: params)
        conn = c

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
                self.fail(err)
            case .cancelled:
                if !startCompleted {
                    startCompleted = true
                    completion(NCFramedRelay.err("kcptun: connection cancelled"))
                }
                self.fail(nil)
            default:
                break
            }
        }
        c.start(queue: queue)
    }

    private func startPumping() {
        readLoop()
        lastActive = Date()

        let timer = DispatchSource.makeTimerSource(queue: queue)
        let itvMs = max(10, options.interval)
        timer.schedule(deadline: .now(), repeating: .milliseconds(itvMs), leeway: .milliseconds(5))
        timer.setEventHandler { [weak self] in self?.tick() }
        timer.resume()
        updateTimer = timer

        if options.keepAlive > 0 {
            let kaTimer = DispatchSource.makeTimerSource(queue: queue)
            kaTimer.schedule(deadline: .now() + .seconds(options.keepAlive), repeating: .seconds(options.keepAlive),
                             leeway: .seconds(1))
            kaTimer.setEventHandler { [weak self] in
                guard let self, let smux = self.smux, smux.activeStreamCount > 0 else { return }
                self.writeFramesOnQueue([smux.keepAliveFrame()])
            }
            kaTimer.resume()
            keepAliveTimer = kaTimer
        }
    }

    private func tick() {
        guard !isClosed, let kcp else { return }
        kcp.update(currentMs: NCKCP.currentMs())
        if kcp.isDeadLink {
            fail(NCFramedRelay.err("kcptun: dead link (no ACK after \(kcp.dead_link) retransmissions)"))
            return
        }
        releaseParked()
        drainKCP()
        if let smux, smux.activeStreamCount == 0, kcp.waitSnd == 0,
           Date().timeIntervalSince(lastActive) > Self.idleTimeout {
            fail(nil)
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
                self.fail(error)
                return
            }
            if !self.isClosed { self.readLoop() }
        }
    }

    private func handleIncomingDatagram(_ datagram: Data) {
        guard let kcp, let plain = blockCrypt.open(datagram) else { return }
        for pkt in fec.decode(packet: plain) {
            _ = kcp.input(data: pkt)
        }
        drainKCP()
    }

    /// Session queue. Stops pulling from KCP while consumers have `smuxBuf` bytes unread (back-pressure).
    private func drainKCP() {
        guard let kcp, let smux, !isClosed else { return }
        while smux.unreadBytes < smux.receiveBufferLimit, let chunk = kcp.recv() {
            if let snappy {
                do {
                    for piece in try snappy.decode(data: chunk) { smux.feedBytes(piece) }
                } catch {
                    // Snappy framing is a byte stream: one bad chunk desyncs everything after it.
                    fail(error)
                    return
                }
            } else {
                smux.feedBytes(chunk)
            }
            if isClosed { return }
        }
    }

    func resumeReceive() {
        ncOnSessionQueue(queue) { self.drainKCP() }
    }

    func noteActivity() {
        ncOnSessionQueue(queue) { self.lastActive = Date() }
    }

    /// Any queue. `completion` fires once the frames are queued in KCP below the high-water mark (or on close).
    func sendFrames(_ frames: [Data], completion: (() -> Void)?) {
        ncOnSessionQueue(queue) {
            guard !self.isClosed, let kcp = self.kcp else { completion?(); return }
            self.writeFramesOnQueue(frames)
            if let completion {
                if kcp.waitSnd <= self.sendHighWater { completion() } else { self.parkedCompletions.append(completion) }
            }
        }
    }

    private func writeFramesOnQueue(_ frames: [Data]) {
        guard let kcp else { return }
        lastActive = Date()
        for f in frames {
            if let snappy { kcp.send(data: snappy.encode(data: f)) } else { kcp.send(data: f) }
        }
        kcp.flush()
    }

    private func releaseParked() {
        guard !parkedCompletions.isEmpty, let kcp, kcp.waitSnd <= sendHighWater / 2 else { return }
        let parked = parkedCompletions
        parkedCompletions.removeAll()
        parked.forEach { $0() }
    }

    private func sendKCPOut(_ segData: Data) {
        guard let conn, !isClosed else { return }
        let (dataPacket, parities) = fec.encode(packet: segData)
        conn.send(content: blockCrypt.seal(dataPacket), completion: .contentProcessed { _ in })
        for p in parities {
            conn.send(content: blockCrypt.seal(p), completion: .contentProcessed { _ in })
        }
    }

    /// Any queue: tear the session down (error nil = orderly close) and drop it from the pool.
    func fail(_ error: Error?) {
        let first = closedFlag.withLock { (closed: inout Bool) -> Bool in
            if closed { return false }
            closed = true
            return true
        }
        guard first else { return }
        NCKcptunSessionPool.shared.remove(self)
        ncOnSessionQueue(queue) {
            self.updateTimer?.cancel(); self.updateTimer = nil
            self.keepAliveTimer?.cancel(); self.keepAliveTimer = nil
            let parked = self.parkedCompletions
            self.parkedCompletions.removeAll()
            parked.forEach { $0() }
            self.smux?.close(error: error)
            self.kcp?.output = nil
            self.conn?.cancel(); self.conn = nil
        }
    }

    func close(error: Error?) { fail(error) }
}

// MARK: - Node-Shared Session Pool

final class NCKcptunSessionPool {
    static let shared = NCKcptunSessionPool()
    private var sessions: [String: NCKcptunSession] = [:]
    /// Expired (autoexpire) sessions replaced in `sessions` but still serving their open streams; they close
    /// themselves once idle. Tracked so teardown closes them and the lifecycle check counts them.
    private var retired: [ObjectIdentifier: NCKcptunSession] = [:]
    private let lock = NSLock()

    private init() {}

    var count: Int {
        lock.lock(); defer { lock.unlock() }
        return sessions.count + retired.count
    }

    /// Gets an existing live session or starts a fresh one for the node. Completion runs on `queue`.
    func getOrCreate(server: String, port: Int, options: NCKcptunOptions, queue: DispatchQueue,
                     completion: @escaping (NCKcptunSession?, Error?) -> Void) {
        let key = "\(server):\(port):\(options.cacheKey)"

        lock.lock()
        if let existing = sessions[key], !existing.isClosed, !existing.isExpired {
            lock.unlock()
            queue.async { completion(existing, nil) }
            return
        }
        if let stale = sessions.removeValue(forKey: key), !stale.isClosed {
            // Expired: keeps serving its open streams, closes itself once idle.
            retired[ObjectIdentifier(stale)] = stale
        }
        guard let session = NCKcptunSession(server: server, port: port, options: options, poolKey: key) else {
            lock.unlock()
            queue.async { completion(nil, NCFramedRelay.err("kcptun: unsupported crypt \(options.crypt)")) }
            return
        }
        sessions[key] = session
        lock.unlock()

        session.start { err in
            if let err {
                session.fail(err)
                queue.async { completion(nil, err) }
            } else {
                queue.async { completion(session, nil) }
            }
        }
    }

    func remove(_ session: NCKcptunSession) {
        lock.lock()
        if sessions[session.poolKey] === session { sessions.removeValue(forKey: session.poolKey) }
        retired.removeValue(forKey: ObjectIdentifier(session))
        lock.unlock()
    }

    /// Tunnel stop / reload: close every session. Returns how many were open.
    @discardableResult
    func reset() -> Int {
        lock.lock()
        let all = Array(sessions.values) + Array(retired.values)
        sessions.removeAll()
        retired.removeAll()
        lock.unlock()
        for s in all { s.fail(nil) }
        return all.count
    }
}
