import Foundation

// XHTTP (splithttp) wire side (feat/nc-xhttp): one HTTP/2 connection per dial — the TLS / REALITY / plain
// stream the connector already opened — carrying the mode's requests as h2 streams, like Clash.Meta's per-dial
// http.Transport (transport/xhttp/client.go, no reuse-settings): stream-one = one POST whose response is the
// download; stream-up = a GET download + one streaming POST upload; packet-up = a GET download + sequential
// POSTs of at most sc-max-each-post-bytes, spaced by sc-min-posts-interval-ms, each acknowledged before the next.

/// Multi-stream HTTP/2 client core (RFC 9113) for XHTTP: client streams 1, 3, 5, …, real receive flow
/// control (windows are returned only as the consumer takes data, so memory stays bounded by the window),
/// HEADERS + CONTINUATION both ways. Pure bytes in / bytes out — the glue owns the socket.
final class NCXHTTPH2Core {
    enum Event: Equatable {
        case response(stream: UInt32, status: Int)
        /// `flow` is the DATA payload length (padding included) to hand back via consume().
        case data(stream: UInt32, body: Data, flow: Int)
        case end(stream: UInt32)
        case reset(stream: UInt32, code: UInt32)
        case goaway(lastStreamID: UInt32, code: UInt32)
        case windowIncreased
        case connectionError(String)
    }

    struct FeedResult {
        var outbound = Data()
        var events: [Event] = []
    }

    static let preface = Data("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)
    /// We never raise SETTINGS_MAX_FRAME_SIZE, so the peer must stay within 2^14.
    static let maxFrameSize = 16384
    static let maxHeaderBlock = 256 * 1024

    /// Per-stream receive window we advertise (SETTINGS_INITIAL_WINDOW_SIZE); the connection window is twice it.
    let localWindow: Int

    private struct StreamState {
        var sendWindow: Int
        var recvUnacked = 0
        var gotFinal = false
        var localClosed: Bool
        var remoteClosed = false
    }

    private var streams: [UInt32: StreamState] = [:]
    private var nextID: UInt32 = 1
    private(set) var connSendWindow = 65535
    private var peerInitialWindow = 65535
    private(set) var peerMaxFrame = 16384
    private var connRecvUnacked = 0
    private var buffer = Data()
    private let decoder = NCHPACKDecoder()
    private var headerStream: UInt32?
    private var headerBlock = Data()
    private var headerEndStream = false
    private(set) var failed = false
    private(set) var goawayLast: UInt32?

    init(localWindow: Int = 512 * 1024) {
        self.localWindow = Swift.max(65535, Swift.min(localWindow, 0x7fff_ffff / 2))
    }

    private var creditThreshold: Int { Swift.min(32 * 1024, localWindow / 2) }

    /// Connection preface + SETTINGS (ENABLE_PUSH 0, INITIAL_WINDOW_SIZE) + the connection WINDOW_UPDATE.
    func start() -> Data {
        var out = Self.preface
        var settings = Data([0x00, 0x02, 0, 0, 0, 0])
        settings.append(contentsOf: [0x00, 0x04])
        settings.append(Self.be32(localWindow))
        out.append(Self.frame(type: 0x4, flags: 0, streamID: 0, payload: settings))
        out.append(Self.frame(type: 0x8, flags: 0, streamID: 0, payload: Self.be32(2 * localWindow - 65535)))
        return out
    }

    func isOpen(_ id: UInt32) -> Bool { streams[id] != nil }
    var openStreamCount: Int { streams.count }

    /// HEADERS (+ CONTINUATION past the peer's max frame size). nil when no new stream may be opened
    /// (connection failed, GOAWAY received, or the stream-id space is exhausted).
    func openStream(headers: [(String, String)], endStream: Bool) -> (id: UInt32, frames: Data)? {
        guard !failed, goawayLast == nil, nextID <= 0x7fff_ffff else { return nil }
        let id = nextID
        nextID += 2
        let block = NCHPACK.encodeHeaders(headers)
        var out = Data()
        var off = 0
        var first = true
        repeat {
            let n = Swift.min(peerMaxFrame, block.count - off)
            let last = off + n >= block.count
            var flags: UInt8 = last ? 0x4 : 0
            if first && endStream { flags |= 0x1 }
            out.append(Self.frame(type: first ? 0x1 : 0x9, flags: flags, streamID: id,
                                  payload: block.subdata(in: off..<(off + n))))
            off += n
            first = false
        } while off < block.count
        streams[id] = StreamState(sendWindow: peerInitialWindow, localClosed: endStream)
        return (id, out)
    }

    /// DATA frames for `data` within the peer's max frame size and both send windows; `consumed` < count
    /// when a window is shut. END_STREAM rides the frame that carries the last byte (an empty DATA frame
    /// for empty input) — only once everything was consumed.
    func makeData(stream id: UInt32, _ data: Data, endStream: Bool = false) -> (frames: Data, consumed: Int) {
        guard var s = streams[id], !s.localClosed else { return (Data(), 0) }
        var out = Data()
        var off = 0
        if data.isEmpty && endStream {
            out.append(Self.frame(type: 0x0, flags: 0x1, streamID: id, payload: Data()))
            s.localClosed = true
        }
        while off < data.count {
            let allowance = Swift.min(connSendWindow, s.sendWindow, peerMaxFrame, data.count - off)
            guard allowance > 0 else { break }
            let lastChunk = off + allowance == data.count
            let flags: UInt8 = endStream && lastChunk ? 0x1 : 0
            out.append(Self.frame(type: 0x0, flags: flags, streamID: id,
                                  payload: data.subdata(in: (data.startIndex + off)..<(data.startIndex + off + allowance))))
            connSendWindow -= allowance
            s.sendWindow -= allowance
            off += allowance
            if flags & 0x1 != 0 { s.localClosed = true }
        }
        streams[id] = s
        closeIfDone(id)
        return (out, off)
    }

    /// RST_STREAM (CANCEL) and forget the stream.
    func reset(stream id: UInt32) -> Data {
        guard streams.removeValue(forKey: id) != nil else { return Data() }
        return Self.frame(type: 0x3, flags: 0, streamID: id, payload: Self.be32(8))
    }

    /// Hand `flow` received bytes back to the peer (WINDOW_UPDATE frames, batched past a threshold).
    func consume(stream id: UInt32, _ flow: Int) -> Data {
        guard flow > 0, !failed else { return Data() }
        var out = Data()
        connRecvUnacked += flow
        if connRecvUnacked >= creditThreshold {
            out.append(Self.frame(type: 0x8, flags: 0, streamID: 0, payload: Self.be32(connRecvUnacked)))
            connRecvUnacked = 0
        }
        if var s = streams[id], !s.remoteClosed {
            s.recvUnacked += flow
            if s.recvUnacked >= creditThreshold {
                out.append(Self.frame(type: 0x8, flags: 0, streamID: id, payload: Self.be32(s.recvUnacked)))
                s.recvUnacked = 0
            }
            streams[id] = s
        }
        return out
    }

    private func closeIfDone(_ id: UInt32) {
        if let s = streams[id], s.localClosed, s.remoteClosed { streams.removeValue(forKey: id) }
    }

    // MARK: inbound

    func feed(_ data: Data) -> FeedResult {
        var result = FeedResult()
        guard !failed else { return result }
        buffer.append(data)
        var off = 0
        defer {
            if failed || off >= buffer.count { buffer = Data() }
            else if off > 0 { buffer = Data(buffer[(buffer.startIndex + off)...]) }
        }
        while !failed, buffer.count - off >= 9 {
            let b = buffer.startIndex + off
            let len = Int(buffer[b]) << 16 | Int(buffer[b + 1]) << 8 | Int(buffer[b + 2])
            guard len <= Self.maxFrameSize else {
                connectionError("h2 frame too large (\(len))", into: &result)
                return result
            }
            guard buffer.count - off >= 9 + len else { break }
            let type = buffer[b + 3]
            let flags = buffer[b + 4]
            let sid = UInt32(buffer[b + 5] & 0x7f) << 24 | UInt32(buffer[b + 6]) << 16
                | UInt32(buffer[b + 7]) << 8 | UInt32(buffer[b + 8])
            let payload = buffer.subdata(in: (b + 9)..<(b + 9 + len))
            off += 9 + len
            handle(type: type, flags: flags, sid: sid, payload: payload, into: &result)
        }
        return result
    }

    private func connectionError(_ why: String, into result: inout FeedResult) {
        guard !failed else { return }
        failed = true
        // GOAWAY(PROTOCOL_ERROR); the glue tears the connection down on the event.
        var p = Self.be32(0) // last server-initiated stream: we accept none
        p.append(Self.be32(1))
        result.outbound.append(Self.frame(type: 0x7, flags: 0, streamID: 0, payload: p))
        result.events.append(.connectionError(why))
    }

    private static func unpad(_ payload: Data, padded: Bool, priority: Bool) -> Data? {
        var start = payload.startIndex
        var end = payload.endIndex
        if padded {
            guard start < end else { return nil }
            let pad = Int(payload[start])
            start += 1
            guard end - start >= pad else { return nil }
            end -= pad
        }
        if priority {
            guard end - start >= 5 else { return nil }
            start += 5
        }
        return payload.subdata(in: start..<end)
    }

    private func handle(type: UInt8, flags: UInt8, sid: UInt32, payload: Data, into result: inout FeedResult) {
        if let hs = headerStream, !(type == 0x9 && sid == hs) {
            connectionError("h2 header block interrupted", into: &result)
            return
        }
        switch type {
        case 0x0: // DATA
            guard sid != 0, let body = Self.unpad(payload, padded: flags & 0x8 != 0, priority: false) else {
                connectionError("h2 bad DATA frame", into: &result)
                return
            }
            let endStream = flags & 0x1 != 0
            if var s = streams[sid], !s.remoteClosed {
                if !payload.isEmpty || !body.isEmpty {
                    result.events.append(.data(stream: sid, body: body, flow: payload.count))
                }
                if endStream {
                    s.remoteClosed = true
                    streams[sid] = s
                    result.events.append(.end(stream: sid))
                    closeIfDone(sid)
                }
            } else if !payload.isEmpty {
                // A stream we reset / finished: the connection window still counts it.
                result.outbound.append(consume(stream: 0, payload.count))
            }
        case 0x1: // HEADERS
            guard sid != 0, let frag = Self.unpad(payload, padded: flags & 0x8 != 0, priority: flags & 0x20 != 0) else {
                connectionError("h2 bad HEADERS frame", into: &result)
                return
            }
            headerStream = sid
            headerBlock = frag
            headerEndStream = flags & 0x1 != 0
            if flags & 0x4 != 0 { finishHeaders(into: &result) }
        case 0x9: // CONTINUATION
            guard headerStream == sid, sid != 0 else {
                connectionError("h2 unexpected CONTINUATION", into: &result)
                return
            }
            guard headerBlock.count + payload.count <= Self.maxHeaderBlock else {
                connectionError("h2 header block too large", into: &result)
                return
            }
            headerBlock.append(payload)
            if flags & 0x4 != 0 { finishHeaders(into: &result) }
        case 0x3: // RST_STREAM
            guard sid != 0, payload.count == 4 else {
                connectionError("h2 bad RST_STREAM", into: &result)
                return
            }
            if streams.removeValue(forKey: sid) != nil {
                result.events.append(.reset(stream: sid, code: Self.u32(payload, 0)))
            }
        case 0x4: // SETTINGS
            if flags & 0x1 != 0 { return }
            guard sid == 0, payload.count % 6 == 0 else {
                connectionError("h2 bad SETTINGS", into: &result)
                return
            }
            var i = payload.startIndex
            while i + 6 <= payload.endIndex {
                let id = Int(payload[i]) << 8 | Int(payload[i + 1])
                let value = Int(Self.u32(payload, i + 2 - payload.startIndex))
                switch id {
                case 0x4: // INITIAL_WINDOW_SIZE
                    guard value <= 0x7fff_ffff else {
                        connectionError("h2 bad INITIAL_WINDOW_SIZE", into: &result)
                        return
                    }
                    let delta = value - peerInitialWindow
                    peerInitialWindow = value
                    for k in Array(streams.keys) { streams[k]?.sendWindow += delta }
                case 0x5: // MAX_FRAME_SIZE
                    guard value >= 16384, value <= 16_777_215 else {
                        connectionError("h2 bad MAX_FRAME_SIZE", into: &result)
                        return
                    }
                    peerMaxFrame = value
                default:
                    break
                }
                i += 6
            }
            result.outbound.append(Self.frame(type: 0x4, flags: 0x1, streamID: 0, payload: Data()))
            result.events.append(.windowIncreased)
        case 0x5: // PUSH_PROMISE — disabled by our SETTINGS
            connectionError("h2 PUSH_PROMISE with push disabled", into: &result)
        case 0x6: // PING
            if flags & 0x1 == 0 && payload.count == 8 {
                result.outbound.append(Self.frame(type: 0x6, flags: 0x1, streamID: 0, payload: payload))
            }
        case 0x7: // GOAWAY
            guard payload.count >= 8 else {
                connectionError("h2 bad GOAWAY", into: &result)
                return
            }
            let last = Self.u32(payload, 0) & 0x7fff_ffff
            goawayLast = Swift.min(goawayLast ?? last, last)
            result.events.append(.goaway(lastStreamID: last, code: Self.u32(payload, 4)))
        case 0x8: // WINDOW_UPDATE
            guard payload.count == 4 else {
                connectionError("h2 bad WINDOW_UPDATE", into: &result)
                return
            }
            let inc = Int(Self.u32(payload, 0) & 0x7fff_ffff)
            if sid == 0 { connSendWindow += inc } else { streams[sid]?.sendWindow += inc }
            result.events.append(.windowIncreased)
        default: // PRIORITY and unknown frame types are ignored
            break
        }
    }

    private func finishHeaders(into result: inout FeedResult) {
        guard let sid = headerStream else { return }
        let block = headerBlock
        let endStream = headerEndStream
        headerStream = nil
        headerBlock = Data()
        // Every block is decoded, whatever stream it is for: the HPACK dynamic table is connection state.
        guard let headers = decoder.decode(block) else {
            connectionError("h2 HPACK decode failed", into: &result)
            return
        }
        guard var s = streams[sid] else { return }
        let status = headers.first(where: { $0.0 == ":status" }).flatMap { Int($0.1) }
        if !s.gotFinal {
            if let status, (100..<200).contains(status), !endStream {
                // informational (100-continue / 103): wait for the final response
            } else {
                s.gotFinal = true
                result.events.append(.response(stream: sid, status: status ?? 0))
            }
        }
        if endStream {
            s.remoteClosed = true
            result.events.append(.end(stream: sid))
        }
        streams[sid] = s
        closeIfDone(sid)
    }

    // MARK: frame helpers

    static func frame(type: UInt8, flags: UInt8, streamID: UInt32, payload: Data) -> Data {
        var out = Data(capacity: 9 + payload.count)
        out.append(UInt8((payload.count >> 16) & 0xff))
        out.append(UInt8((payload.count >> 8) & 0xff))
        out.append(UInt8(payload.count & 0xff))
        out.append(type)
        out.append(flags)
        out.append(UInt8((streamID >> 24) & 0x7f))
        out.append(UInt8((streamID >> 16) & 0xff))
        out.append(UInt8((streamID >> 8) & 0xff))
        out.append(UInt8(streamID & 0xff))
        out.append(payload)
        return out
    }

    static func be32(_ v: Int) -> Data {
        Data([UInt8((v >> 24) & 0xff), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)])
    }

    static func u32(_ d: Data, _ offset: Int) -> UInt32 {
        let b = d.startIndex + offset
        return UInt32(d[b]) << 24 | UInt32(d[b + 1]) << 16 | UInt32(d[b + 2]) << 8 | UInt32(d[b + 3])
    }
}

/// The XHTTP relay stream over one connected byte pipe (TLS / REALITY / plain h2c).
///
/// Threading follows NCH2TunnelStream (nc-races): all state lives on this stream's own serial queue; the
/// registered receive handler is delivered on `callerQueue`.
final class NCXHTTPStream: NCRelayStream {
    enum Mode: String {
        case streamOne = "stream-one"
        case streamUp = "stream-up"
        case packetUp = "packet-up"
    }

    /// Upload bytes accepted but not yet window-cleared (stream-one / stream-up); the pumps wait on send
    /// completions, so this only overflows on a misbehaving caller.
    static let maxPendingSend = 256 * 1024
    /// packet-up: one POST body never exceeds this, whatever sc-max-each-post-bytes allows (default 1 MB):
    /// smaller posts are always accepted by the server and cap the per-connection upload buffer (memory first).
    static let maxPostBytes = 256 * 1024
    /// Clash.Meta PacketUpWriter.Close: the last batch gets this long to go out before the connection closes.
    static let closeFlushTimeout: TimeInterval = 1

    let mode: Mode
    let sessionID: String
    private let raw: NCRelayStream
    private let config: NCXHTTPConfig
    let core: NCXHTTPH2Core
    private let queue = NCSessionQueues.make("nc.xhttp.stream")
    private let callerQueue: DispatchQueue

    private var dlID: UInt32 = 0
    private var upID: UInt32 = 0

    // stream-one / stream-up upload
    private var pendingSend = Data()
    private var sendWaiters: [(end: Int, once: NCCallOnce)] = []
    private var sendAppended = 0
    private var sendConsumed = 0

    // packet-up upload
    let postLimit: Int
    private var batch = Data()
    private var batchWaiters: [NCCallOnce] = []
    private var postID: UInt32 = 0
    private var postBody = Data()
    private var postStatus: Int?
    private(set) var seq: UInt64 = 0
    private var timer: DispatchWorkItem?
    private var flushDue = false
    private var closing = false

    // download
    private var inbound: [(data: Data, flow: Int)] = []
    private var queuedBytes = 0
    private var pendingHandler: ((Data?, Error?) -> Void)?
    private var dlEnded = false
    private var dead: Error?
    private var torn = false

    init(raw: NCRelayStream, config: NCXHTTPConfig, mode: Mode, callerQueue: DispatchQueue,
         localWindow: Int = 512 * 1024) {
        self.raw = raw
        self.config = config
        self.mode = mode
        self.callerQueue = callerQueue
        self.core = NCXHTTPH2Core(localWindow: localWindow)
        self.sessionID = mode == .streamOne ? "" : config.generateSessionID()
        self.postLimit = Swift.max(1, Swift.min(config.scMaxEachPostBytes.rand(), Self.maxPostBytes))
    }

    /// Sends the preface and the mode's opening requests, then completes at once — like Clash.Meta, which
    /// returns the conn as soon as the connection is up instead of waiting for response headers (a CDN
    /// may hold those until the first body byte).
    func start(completion: @escaping (Error?) -> Void) {
        var err: Error?
        queue.sync {
            var out = self.core.start()
            switch self.mode {
            case .streamOne:
                let req = self.config.streamRequest(method: self.config.uplinkHTTPMethod, sessionID: "", hasBody: true)
                guard let o = self.core.openStream(headers: req.h2Headers(), endStream: false) else { break }
                self.dlID = o.id
                self.upID = o.id
                out.append(o.frames)
            case .streamUp:
                let dl = self.config.downloadRequest(sessionID: self.sessionID)
                let up = self.config.streamRequest(method: self.config.uplinkHTTPMethod, sessionID: self.sessionID, hasBody: true)
                guard let d = self.core.openStream(headers: dl.h2Headers(), endStream: true),
                      let u = self.core.openStream(headers: up.h2Headers(), endStream: false) else { break }
                self.dlID = d.id
                self.upID = u.id
                out.append(d.frames)
                out.append(u.frames)
            case .packetUp:
                let dl = self.config.downloadRequest(sessionID: self.sessionID)
                guard let d = self.core.openStream(headers: dl.h2Headers(), endStream: true) else { break }
                self.dlID = d.id
                out.append(d.frames)
            }
            if self.dlID == 0 {
                err = NSError(domain: "NativeCore", code: 5, userInfo: [NSLocalizedDescriptionKey: "xhttp: cannot open request"])
                self.teardown()
                return
            }
            self.raw.send(out)
            self.pump()
        }
        completion(err)
    }

    // MARK: NCRelayStream

    func send(_ data: Data) { send(data, completion: {}) }

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        ncOnSessionQueue(queue) {
            guard self.dead == nil, !self.torn else { once.call(); return }
            guard !data.isEmpty else { once.call(); return }
            if self.mode == .packetUp {
                self.enqueuePacket(data, once)
                return
            }
            guard self.pendingSend.count + data.count <= Self.maxPendingSend else {
                once.call()
                self.fail(Self.error("xhttp upload buffer overflow"))
                return
            }
            self.pendingSend.append(data)
            self.sendAppended += data.count
            self.sendWaiters.append((self.sendAppended, once))
            self.flushUpload()
        }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        ncOnSessionQueue(queue) {
            if !self.inbound.isEmpty {
                let item = self.inbound.removeFirst()
                self.queuedBytes -= item.data.count
                self.credit(item.flow)
                self.callerQueue.async { handler(item.data, nil) }
                return
            }
            if let dead = self.dead {
                self.callerQueue.async { handler(nil, dead) }
                return
            }
            if self.dlEnded {
                self.callerQueue.async { handler(nil, nil) }
                return
            }
            self.pendingHandler = handler
        }
    }

    func cancel() {
        ncOnSessionQueue(queue) {
            let wasAlive = self.dead == nil && !self.torn
            self.markDead(Self.error("xhttp stream cancelled"))
            // packet-up: the last batch still goes out (bounded by closeFlushTimeout), like PacketUpWriter.Close.
            if wasAlive, self.mode == .packetUp, self.postID != 0 || !self.batch.isEmpty {
                self.closing = true
                self.timer?.cancel()
                self.timer = nil
                self.flushDue = true
                self.tryPost()
                self.queue.asyncAfter(deadline: .now() + Self.closeFlushTimeout) { [weak self] in self?.teardown() }
                if self.postID == 0 && self.batch.isEmpty { self.teardown() }
                return
            }
            self.teardown()
        }
    }

    // MARK: stream-one / stream-up upload

    private func flushUpload() {
        guard !pendingSend.isEmpty, !torn else { return }
        guard core.isOpen(upID) else {
            fail(Self.error("xhttp upload stream closed"))
            return
        }
        let (frames, consumed) = core.makeData(stream: upID, pendingSend)
        guard consumed > 0 else { return }
        pendingSend = consumed >= pendingSend.count ? Data() : Data(pendingSend.dropFirst(consumed))
        raw.send(frames) { [weak self] in
            guard let self else { return }
            ncOnSessionQueue(self.queue) { self.noteConsumed(consumed) }
        }
    }

    private func noteConsumed(_ n: Int) {
        sendConsumed += n
        var due: [NCCallOnce] = []
        while let first = sendWaiters.first, first.end <= sendConsumed {
            due.append(first.once)
            sendWaiters.removeFirst()
        }
        due.forEach { $0.call() }
    }

    // MARK: packet-up upload

    private func enqueuePacket(_ data: Data, _ once: NCCallOnce) {
        guard batch.count + data.count <= postLimit + Self.maxPendingSend else {
            once.call()
            fail(Self.error("xhttp packet-up buffer overflow"))
            return
        }
        batch.append(data)
        // Back-pressure: the chunk that fills a whole post waits until that post leaves the batch.
        if batch.count >= postLimit { batchWaiters.append(once) } else { once.call() }
        armTimer()
    }

    private func armTimer() {
        guard timer == nil, !batch.isEmpty, !torn, !closing else { return }
        let ms = config.scMinPostsIntervalMs.rand()
        let item = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.timer = nil
            self.flushDue = true
            self.tryPost()
        }
        timer = item
        queue.asyncAfter(deadline: .now() + .milliseconds(ms), execute: item)
    }

    private func releaseBatchWaiters() {
        guard batch.count < postLimit, !batchWaiters.isEmpty else { return }
        let all = batchWaiters
        batchWaiters = []
        all.forEach { $0.call() }
    }

    private func tryPost() {
        guard flushDue, postID == 0, !batch.isEmpty, !torn, dead == nil || closing else { return }
        flushDue = false
        let n = Swift.min(postLimit, batch.count)
        let chunk = batch.prefix(n)
        let body = Data(chunk)
        batch = n >= batch.count ? Data() : Data(batch.dropFirst(n))
        releaseBatchWaiters()
        let req = config.packetRequest(sessionID: sessionID, seq: seq, data: body)
        seq += 1
        let hasBody = !(req.body?.isEmpty ?? true)
        guard let opened = core.openStream(headers: req.h2Headers(), endStream: !hasBody) else {
            fail(Self.error("xhttp packet-up: connection no longer accepts requests"))
            return
        }
        postID = opened.id
        postStatus = nil
        raw.send(opened.frames)
        if hasBody, let b = req.body {
            postBody = b
            flushPost()
        }
        armTimer()
    }

    private func flushPost() {
        guard postID != 0, !postBody.isEmpty, !torn else { return }
        let (frames, consumed) = core.makeData(stream: postID, postBody, endStream: true)
        guard consumed > 0 else { return }
        postBody = consumed >= postBody.count ? Data() : Data(postBody.dropFirst(consumed))
        raw.send(frames)
    }

    private func postFinished() {
        guard postStatus == 200 else {
            fail(Self.error("xhttp packet-up bad status: \(postStatus.map(String.init) ?? "none")"))
            return
        }
        postID = 0
        postBody = Data()
        if closing {
            if batch.isEmpty { teardown(); return }
            flushDue = true
        }
        tryPost()
        armTimer()
    }

    // MARK: download / inbound

    private func pump() {
        raw.receive { [weak self] data, error in
            guard let self else { return }
            ncOnSessionQueue(self.queue) {
                guard !self.torn else { return }
                guard let data else {
                    self.fail(error ?? Self.error("xhttp connection closed"))
                    return
                }
                let result = self.core.feed(data)
                if !result.outbound.isEmpty { self.raw.send(result.outbound) }
                for event in result.events {
                    self.handle(event)
                    if self.torn { return }
                }
                self.pump()
            }
        }
    }

    private func handle(_ event: NCXHTTPH2Core.Event) {
        switch event {
        case .response(let sid, let status):
            if sid == dlID {
                let ok = mode == .streamOne ? (200..<300).contains(status) : status == 200
                if !ok { fail(Self.error("xhttp \(mode.rawValue) download bad status: \(status)")) }
            } else if mode == .streamUp && sid == upID {
                if !(200..<300).contains(status) { fail(Self.error("xhttp stream-up upload bad status: \(status)")) }
            } else if sid == postID {
                postStatus = status
                if status != 200 { fail(Self.error("xhttp packet-up bad status: \(status)")) }
            }
        case .data(let sid, let body, let flow):
            if sid == dlID {
                deliver(body, flow: flow)
            } else {
                let wu = core.consume(stream: sid, flow) // upload responses: read and discarded
                if !wu.isEmpty { raw.send(wu) }
            }
        case .end(let sid):
            if sid == dlID {
                dlEnded = true
                if inbound.isEmpty, let h = pendingHandler {
                    pendingHandler = nil
                    callerQueue.async { h(nil, nil) }
                }
            } else if sid == postID {
                postFinished()
            }
        case .reset(let sid, let code):
            if sid == dlID || sid == upID || (sid == postID && postID != 0) {
                fail(Self.error("xhttp h2 stream reset (code \(code))"))
            }
        case .goaway(let last, _):
            if dlID > last || upID > last || postID > last {
                fail(Self.error("xhttp connection going away"))
            }
        case .windowIncreased:
            if mode == .packetUp { flushPost() } else { flushUpload() }
        case .connectionError(let why):
            fail(Self.error("xhttp: \(why)"))
        }
    }

    private func deliver(_ body: Data, flow: Int) {
        if body.isEmpty { credit(flow); return }
        if let h = pendingHandler {
            pendingHandler = nil
            credit(flow)
            callerQueue.async { h(body, nil) }
            return
        }
        // Flow control bounds this by the advertised window; anything beyond it is a peer violation.
        guard queuedBytes + body.count <= core.localWindow + 65536 else {
            fail(Self.error("xhttp download buffer overflow"))
            return
        }
        queuedBytes += body.count
        inbound.append((body, flow))
    }

    private func credit(_ flow: Int) {
        guard !torn else { return }
        let wu = core.consume(stream: dlID, flow)
        if !wu.isEmpty { raw.send(wu) }
    }

    // MARK: teardown

    private func markDead(_ error: Error) {
        guard dead == nil else { return }
        dead = error
        if let h = pendingHandler {
            pendingHandler = nil
            callerQueue.async { h(nil, error) }
        }
        let waiters = sendWaiters.map { $0.once } + batchWaiters
        sendWaiters = []
        batchWaiters = []
        waiters.forEach { $0.call() }
    }

    private func fail(_ error: Error) {
        markDead(error)
        teardown()
    }

    private func teardown() {
        guard !torn else { return }
        torn = true
        timer?.cancel()
        timer = nil
        if dead == nil { markDead(Self.error("xhttp stream closed")) }
        inbound = []
        queuedBytes = 0
        pendingSend = Data()
        batch = Data()
        postBody = Data()
        raw.cancel()
    }

    private static func error(_ msg: String) -> Error {
        NSError(domain: "NativeCore", code: 5, userInfo: [NSLocalizedDescriptionKey: msg])
    }
}
