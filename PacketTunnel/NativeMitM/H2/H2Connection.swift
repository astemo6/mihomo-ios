// Native MitM stage 3 lane s3-h2: one HTTP/2 connection over a ByteStream — the server side facing the client
// (NativeH2Session) and the client side towards an h2 origin (H2Upstream.swift) share this core.
//
// Covers RFC 9113: connection preface, SETTINGS exchange (+ ACK), HEADERS/CONTINUATION assembly with HPACK,
// DATA with connection- and stream-level flow control in both directions, WINDOW_UPDATE, RST_STREAM, GOAWAY,
// PING (answered), PRIORITY (validated, ignored), unknown frames (ignored). Not supported, by design: server push
// (we never push; as a client we send ENABLE_PUSH=0 so a PUSH_PROMISE is a connection error), extended CONNECT
// (SETTINGS_ENABLE_CONNECT_PROTOCOL is never advertised, so :protocol requests are malformed), h2c / Upgrade
// (the native front only exists behind TLS + ALPN).
//
// Memory: the receive side never buffers more than the windows we granted — DATA is delivered to the owner, and
// window credit is returned (WINDOW_UPDATE) only when the owner calls consumed(), i.e. after the bytes moved on.
// The send side queues per stream; owners check outbound(stream) and wait for .writable before queueing more.
// Header blocks are capped (maxHeaderBlock); a PING/SETTINGS flood that piles up unsent control frames is
// answered with GOAWAY(ENHANCE_YOUR_CALM).
//
// Threading: everything runs on `queue` (the owner's serial queue); events are delivered synchronously on it.

import Foundation

enum H2Event {
    /// Headers of a stream: the request (server), the final response (client; 1xx are dropped), or trailers
    /// (a second block, always with endStream).
    case headers(stream: UInt32, fields: HTTPHeaderList, endStream: Bool, trailers: Bool)
    /// A new peer stream refused before it reached the owner (concurrency cap, header list too large, going away).
    case refused(stream: UInt32, fields: HTTPHeaderList?, reason: String)
    case data(stream: UInt32, bytes: Data, endStream: Bool)
    /// The stream is gone: the peer reset it, or the connection detected a stream error (and reset it itself).
    case reset(stream: UInt32, code: H2ErrorCode, byPeer: Bool)
    /// outbound(stream) dropped to the low-water mark after wantWritable(stream).
    case writable(stream: UInt32)
    case goaway(lastStream: UInt32, code: H2ErrorCode)
    /// The connection is closed (nil: orderly). Every open stream is dead.
    case closed(H2Error?)
}

protocol H2ConnectionOwner: AnyObject {
    func h2Event(_ c: H2Connection, _ event: H2Event)
}

struct H2Limits {
    var maxConcurrentStreams = 16        // advertised (server) / own cap on opened streams (client)
    var streamWindow = H2Wire.defaultWindow
    var connectionWindow = 256 << 10
    var maxHeaderListSize = 64 << 10
    var maxHeaderBlock = 256 << 10       // assembled HEADERS+CONTINUATION bytes
    var headerTableSize = 4096
    var lowWater = 16 << 10              // .writable fires at or below this many queued bytes
    var maxControlBacklog = 1 << 20      // unsent control frames before ENHANCE_YOUR_CALM
    var writeBatch = 64 << 10
    var readChunk = 32 << 10
}

final class H2Connection {
    enum Role { case server, client }

    final class Stream {
        let id: UInt32
        var sendWindow: Int
        var recvWindow: Int
        var recvUnacked = 0
        var out: [[UInt8]] = []
        var outHead = 0                   // bytes of out[0] already sent
        var outBytes = 0
        var outEnd = false                // END_STREAM after out
        var outTrailers: HTTPHeaderList?
        var sentEnd = false
        var recvEnd = false
        var gotHeaders = false            // final (non-1xx) headers seen
        var wantWritable = false
        var resetAfterSend: H2ErrorCode?   // reset once everything queued went out (response done, request still open)
        init(id: UInt32, sendWindow: Int, recvWindow: Int) { self.id = id; self.sendWindow = sendWindow; self.recvWindow = recvWindow }
    }

    let role: Role
    let io: ByteStream
    let queue: DispatchQueue
    let limits: H2Limits
    weak var owner: H2ConnectionOwner?

    private(set) var streams: [UInt32: Stream] = [:]
    private var ready: [UInt32] = []                // streams with something to send, round-robin
    private var decoder: H2FrameDecoder
    private let hpackIn: HPACKDecoder
    private let hpackOut: HPACKEncoder
    private var inq = H2ByteQueue()
    private var prefaceSeen: Bool
    private var gotPeerSettings = false
    private var ctrl: [[UInt8]] = []
    private var ctrlBytes = 0
    private var writing = false
    private var reading = false
    private(set) var closed = false
    private var closing = false                    // flush, then close
    private var headerBlock: (stream: UInt32, bytes: [UInt8], endStream: Bool)?

    // flow control (connection level)
    private(set) var connSendWindow = H2Wire.defaultWindow
    private var connRecvWindow = H2Wire.defaultWindow
    private var connRecvUnacked = 0

    // peer settings
    private(set) var peerMaxConcurrent = Int.max
    private(set) var peerInitialWindow = H2Wire.defaultWindow
    private(set) var peerMaxFrame = H2Wire.defaultMaxFrame

    private(set) var lastPeerStream: UInt32 = 0
    private var nextStreamID: UInt32
    private(set) var goingAway = false            // we sent GOAWAY
    private(set) var peerGoAway: UInt32?           // peer's last stream id
    private(set) var lastActivity = DispatchTime.now()

    // stats
    private(set) var bytesIn = 0
    private(set) var bytesOut = 0

    init(role: Role, io: ByteStream, queue: DispatchQueue, limits: H2Limits = H2Limits()) {
        self.role = role
        self.io = io
        self.queue = queue
        self.limits = limits
        decoder = H2FrameDecoder()
        hpackIn = HPACKDecoder(maxTableSize: limits.headerTableSize, maxHeaderListSize: limits.maxHeaderListSize)
        hpackOut = HPACKEncoder(maxTableSize: limits.headerTableSize)
        prefaceSeen = role == .client
        nextStreamID = role == .client ? 1 : 2
    }

    var activeStreams: Int { streams.count }
    var bufferedOut: Int { ctrlBytes + streams.values.reduce(0) { $0 + $1.outBytes } }

    /// Client side: another stream may be opened now.
    var canOpenStream: Bool {
        !closed && !closing && !goingAway && peerGoAway == nil && streams.count < min(peerMaxConcurrent, limits.maxConcurrentStreams)
            && nextStreamID < 0x7fff_fff0
    }

    // MARK: start

    func start() {
        var out: [UInt8] = []
        if role == .client { out.append(contentsOf: H2Wire.preface) }
        var s: [H2SettingValue] = [H2SettingValue(.maxHeaderListSize, UInt32(limits.maxHeaderListSize))]
        if role == .client {
            s.insert(H2SettingValue(.enablePush, 0), at: 0)
        } else {
            s.insert(H2SettingValue(.maxConcurrentStreams, UInt32(limits.maxConcurrentStreams)), at: 0)
        }
        if limits.streamWindow != H2Wire.defaultWindow { s.append(H2SettingValue(.initialWindowSize, UInt32(limits.streamWindow))) }
        if limits.headerTableSize != 4096 { s.append(H2SettingValue(.headerTableSize, UInt32(limits.headerTableSize))) }
        H2FrameEncoder.settings(s, into: &out)
        if limits.connectionWindow > H2Wire.defaultWindow {
            H2FrameEncoder.windowUpdate(stream: 0, increment: limits.connectionWindow - H2Wire.defaultWindow, into: &out)
            connRecvWindow = limits.connectionWindow
        }
        enqueueControl(out)
        flush()
        readMore()
    }

    // MARK: owner API

    /// Client side: a new stream id (nil when no stream may be opened).
    func openStream() -> UInt32? {
        guard canOpenStream else { return nil }
        let id = nextStreamID
        nextStreamID += 2
        streams[id] = Stream(id: id, sendWindow: peerInitialWindow, recvWindow: limits.streamWindow)
        return id
    }

    /// Encodes and queues a header block now (HPACK state is order-sensitive; header blocks go out in this order).
    func sendHeaders(_ id: UInt32, _ fields: HTTPHeaderList, endStream: Bool) {
        guard !closed, let s = streams[id], !s.sentEnd else { return }
        var out: [UInt8] = []
        H2FrameEncoder.headers(stream: id, block: hpackOut.encode(fields), endStream: endStream, maxFrame: peerMaxFrame, into: &out)
        enqueueControl(out)
        if endStream { s.sentEnd = true; s.outEnd = true; maybeRemove(s) }
        flush()
    }

    func sendData(_ id: UInt32, _ data: Data) {
        guard !closed, let s = streams[id], !s.outEnd, !data.isEmpty else { return }
        s.out.append([UInt8](data))
        s.outBytes += data.count
        markReady(id)
        flush()
    }

    /// Ends the stream after the queued data: an empty END_STREAM DATA frame, or trailers.
    func endStream(_ id: UInt32, trailers: HTTPHeaderList? = nil) {
        guard !closed, let s = streams[id], !s.outEnd else { return }
        s.outEnd = true
        if let t = trailers, !t.isEmpty { s.outTrailers = t }
        markReady(id)
        flush()
    }

    func outbound(_ id: UInt32) -> Int { streams[id]?.outBytes ?? 0 }

    /// Ask for .writable(id) once outbound(id) <= lowWater.
    func wantWritable(_ id: UInt32) {
        guard let s = streams[id] else { return }
        if s.outBytes <= limits.lowWater {
            queue.async { [weak self] in self?.emitIfOpen(.writable(stream: id), id) }
        } else {
            s.wantWritable = true
        }
    }

    /// The owner moved n delivered DATA bytes on: grant the peer that much window again.
    func consumed(_ id: UInt32, _ n: Int) {
        guard !closed, n > 0 else { return }
        connRecvUnacked += n
        var out: [UInt8] = []
        if connRecvUnacked >= limits.connectionWindow / 2 {
            H2FrameEncoder.windowUpdate(stream: 0, increment: connRecvUnacked, into: &out)
            connRecvWindow += connRecvUnacked
            connRecvUnacked = 0
        }
        if let s = streams[id], !s.recvEnd {
            s.recvUnacked += n
            if s.recvUnacked >= limits.streamWindow / 2 {
                H2FrameEncoder.windowUpdate(stream: id, increment: s.recvUnacked, into: &out)
                s.recvWindow += s.recvUnacked
                s.recvUnacked = 0
            }
        }
        if !out.isEmpty { enqueueControl(out); flush() }
    }

    func resetStream(_ id: UInt32, _ code: H2ErrorCode) {
        guard !closed else { return }
        var out: [UInt8] = []
        H2FrameEncoder.rstStream(stream: id, code: code, into: &out)
        enqueueControl(out)
        drop(id)
        flush()
    }

    /// RST_STREAM after the queued output (incl. END_STREAM) is written — ends a request the peer is still
    /// sending once our complete response is out (RFC 9113 §8.1).
    func resetWhenSent(_ id: UInt32, _ code: H2ErrorCode) {
        guard !closed, let s = streams[id] else { return }
        if s.sentEnd && s.outBytes == 0 { return resetStream(id, code) }
        s.resetAfterSend = code
        markReady(id)
        flush()
    }

    /// Graceful: GOAWAY(last peer stream); open streams finish, then the connection closes. Errors: close after flush.
    func goAway(_ code: H2ErrorCode = .noError, debug: String = "") {
        guard !closed, !goingAway else { return }
        goingAway = true
        var out: [UInt8] = []
        H2FrameEncoder.goaway(lastStream: role == .server ? lastPeerStream : 0, code: code, debug: debug, into: &out)
        enqueueControl(out)
        if code != .noError || streams.isEmpty { closing = true }
        flush()
    }

    func ping(_ payload: [UInt8]) {
        var out: [UInt8] = []
        H2FrameEncoder.ping(ack: false, payload, into: &out)
        enqueueControl(out)
        flush()
    }

    /// Tear down now (idempotent).
    func close(_ error: H2Error? = nil) {
        guard !closed else { return }
        closed = true
        io.close()
        streams.removeAll(); ready.removeAll(); ctrl.removeAll(); ctrlBytes = 0
        inq.reset()
        owner?.h2Event(self, .closed(error))
    }

    // MARK: internals

    private func emitIfOpen(_ e: H2Event, _ id: UInt32) {
        guard !closed, streams[id] != nil else { return }
        owner?.h2Event(self, e)
    }

    private func enqueueControl(_ f: [UInt8]) {
        ctrl.append(f)
        ctrlBytes += f.count
    }

    private func markReady(_ id: UInt32) { if !ready.contains(id) { ready.append(id) } }

    private func drop(_ id: UInt32) {
        streams[id] = nil
        ready.removeAll { $0 == id }
        if goingAway && streams.isEmpty { closing = true }
    }

    private func maybeRemove(_ s: Stream) {
        if s.sentEnd && s.recvEnd { drop(s.id) }
    }

    private func fail(_ e: H2Error) {
        if e.isConnectionError {
            if !goingAway {
                goingAway = true
                var out: [UInt8] = []
                H2FrameEncoder.goaway(lastStream: lastPeerStream, code: e.code, debug: e.reason, into: &out)
                enqueueControl(out)
            }
            closing = true
            pendingError = e
            flush()
        } else {
            let known = streams[e.stream] != nil
            resetStream(e.stream, e.code)
            if known { owner?.h2Event(self, .reset(stream: e.stream, code: e.code, byPeer: false)) }
        }
    }
    private var pendingError: H2Error?

    // MARK: writing

    private func flush() {
        guard !closed, !writing else { return }
        var batch: [UInt8] = []
        if !ctrl.isEmpty {
            for f in ctrl { batch.append(contentsOf: f) }
            ctrl.removeAll(keepingCapacity: true)
            ctrlBytes = 0
        }
        // DATA round-robin over streams with queued output, within both windows.
        var progress = true
        while progress && batch.count < limits.writeBatch && !ready.isEmpty {
            progress = false
            for id in ready {
                guard let s = streams[id] else { continue }
                if batch.count >= limits.writeBatch { break }
                if s.outBytes > 0 {
                    let allow = min(s.sendWindow, connSendWindow, peerMaxFrame, limits.writeBatch - batch.count, s.outBytes)
                    if allow > 0 {
                        let chunk = takeOut(s, allow)
                        let end = s.outBytes == 0 && s.outEnd && s.outTrailers == nil
                        H2FrameEncoder.data(stream: id, chunk, endStream: end, into: &batch)
                        s.sendWindow -= chunk.count
                        connSendWindow -= chunk.count
                        if end { s.sentEnd = true }
                        progress = true
                    }
                }
                if s.outBytes == 0 && s.outEnd && !s.sentEnd {
                    if let t = s.outTrailers {
                        H2FrameEncoder.headers(stream: id, block: hpackOut.encode(t), endStream: true, maxFrame: peerMaxFrame, into: &batch)
                        s.outTrailers = nil
                    } else {
                        H2FrameEncoder.data(stream: id, [UInt8](), endStream: true, into: &batch)
                    }
                    s.sentEnd = true
                    progress = true
                }
            }
            // rotate + prune
            ready = ready.filter { id in
                guard let s = streams[id] else { return false }
                return s.outBytes > 0 || (s.outEnd && !s.sentEnd)
            }
            if let f = ready.first, ready.count > 1 { ready.removeFirst(); ready.append(f) }
            for (_, s) in streams where s.sentEnd {
                if let code = s.resetAfterSend, s.outBytes == 0 {
                    H2FrameEncoder.rstStream(stream: s.id, code: code, into: &batch)
                    drop(s.id)
                } else {
                    maybeRemove(s)
                }
            }
        }
        if batch.isEmpty {
            if closing { close(pendingError) }
            return
        }
        writing = true
        bytesOut += batch.count
        io.write(Data(batch)) { [weak self] err in
            guard let self else { return }
            self.queue.async {
                self.writing = false
                if self.closed { return }
                if let err { return self.close(H2Error(.internalError, "write: \(err)")) }
                self.afterWrite()
            }
        }
    }

    private func takeOut(_ s: Stream, _ n: Int) -> ArraySlice<UInt8> {
        // n <= s.outBytes; take from the head chunk only (a frame never spans two queued chunks — keeps it copy-light).
        let first = s.out[0]
        let avail = first.count - s.outHead
        let k = min(n, avail)
        let slice = first[s.outHead..<(s.outHead + k)]
        s.outHead += k
        s.outBytes -= k
        if s.outHead == first.count { s.out.removeFirst(); s.outHead = 0 }
        return slice
    }

    private func afterWrite() {
        var events: [UInt32] = []
        for (id, s) in streams where s.wantWritable && s.outBytes <= limits.lowWater {
            s.wantWritable = false
            events.append(id)
        }
        for id in events { emitIfOpen(.writable(stream: id), id) }
        flush()
        if !reading && !closed { readMore() }
    }

    // MARK: reading

    private func readMore() {
        guard !closed, !reading, !closing else { return }
        if ctrlBytes > limits.maxControlBacklog {
            fail(H2Error(.enhanceYourCalm, "control frame backlog"))
            return
        }
        reading = true
        io.read(min: 1, max: limits.readChunk) { [weak self] data, eof, err in
            guard let self else { return }
            self.queue.async {
                self.reading = false
                if self.closed { return }
                if let d = data, !d.isEmpty {
                    self.bytesIn += d.count
                    self.lastActivity = .now()
                    self.inq.append(d)
                    self.process()
                    if self.closed { return }
                }
                if let err { return self.close(H2Error(.internalError, "read: \(err)")) }
                if eof { return self.close(nil) }
                if !self.closing { self.readMore() }
            }
        }
    }

    private func process() {
        if !prefaceSeen {
            let n = min(inq.count, H2Wire.preface.count)
            for i in 0..<n where inq[i] != H2Wire.preface[i] {
                return close(H2Error(.protocolError, "not an HTTP/2 connection preface"))
            }
            if inq.count < H2Wire.preface.count { return }
            inq.skip(H2Wire.preface.count)
            prefaceSeen = true
        }
        while !closed && !closing {
            do {
                guard let f = try decoder.next(&inq) else { break }
                try handle(f)
            } catch let e as H2Error {
                fail(e)
            } catch {
                fail(H2Error(.internalError, "\(error)"))
            }
        }
    }

    private func handle(_ f: H2Frame) throws {
        if !gotPeerSettings {
            guard case .settings(false, _) = f else { throw H2Error(.protocolError, "first frame is not SETTINGS") }
        }
        if let hb = headerBlock {
            guard case .continuation(let sid, let block, let endHeaders) = f, sid == hb.stream else {
                throw H2Error(.protocolError, "expected CONTINUATION for stream \(hb.stream)")
            }
            var bytes = hb.bytes
            bytes.append(contentsOf: block)
            if bytes.count > limits.maxHeaderBlock { throw H2Error(.enhanceYourCalm, "header block too large") }
            headerBlock = nil
            if endHeaders { try finishHeaders(hb.stream, bytes, endStream: hb.endStream) }
            else { headerBlock = (hb.stream, bytes, hb.endStream) }
            return
        }
        switch f {
        case .data(let sid, let payload, let endStream, let flowSize):
            try onData(sid, payload, endStream, flowSize)
        case .headers(let sid, let block, let endStream, let endHeaders):
            if block.count > limits.maxHeaderBlock { throw H2Error(.enhanceYourCalm, "header block too large") }
            if endHeaders { try finishHeaders(sid, block, endStream: endStream) }
            else { headerBlock = (sid, block, endStream) }
        case .priority:
            break
        case .rstStream(let sid, let code):
            if streams[sid] == nil {
                if isIdle(sid) { throw H2Error(.protocolError, "RST_STREAM on idle stream \(sid)") }
                return
            }
            drop(sid)
            owner?.h2Event(self, .reset(stream: sid, code: H2ErrorCode(code: code), byPeer: true))
            flush()
        case .settings(let ack, let values):
            if ack { return }
            gotPeerSettings = true
            try applySettings(values)
            var out: [UInt8] = []
            H2FrameEncoder.settingsAck(into: &out)
            enqueueControl(out)
            flush()
        case .pushPromise:
            throw H2Error(.protocolError, "PUSH_PROMISE (push is disabled)")
        case .ping(let ack, let payload):
            if !ack {
                var out: [UInt8] = []
                H2FrameEncoder.ping(ack: true, payload, into: &out)
                enqueueControl(out)
                flush()
            }
        case .goaway(let last, let code, _):
            peerGoAway = min(peerGoAway ?? last, last)
            owner?.h2Event(self, .goaway(lastStream: last, code: H2ErrorCode(code: code)))
            if role == .client {
                for id in streams.keys.sorted() where id > last {
                    drop(id)
                    owner?.h2Event(self, .reset(stream: id, code: .refusedStream, byPeer: true))
                }
            }
            if streams.isEmpty { closing = true; flush() }
        case .windowUpdate(let sid, let inc):
            if sid == 0 {
                if inc == 0 { throw H2Error(.protocolError, "WINDOW_UPDATE of 0") }
                connSendWindow += Int(inc)
                if connSendWindow > H2Wire.maxWindow { throw H2Error(.flowControlError, "connection window overflow") }
            } else if let s = streams[sid] {
                if inc == 0 { throw H2Error(.protocolError, stream: sid, "WINDOW_UPDATE of 0") }
                s.sendWindow += Int(inc)
                if s.sendWindow > H2Wire.maxWindow { throw H2Error(.flowControlError, stream: sid, "stream window overflow") }
            } else if isIdle(sid) {
                throw H2Error(.protocolError, "WINDOW_UPDATE on idle stream \(sid)")
            }
            flush()
        case .continuation:
            throw H2Error(.protocolError, "CONTINUATION without HEADERS")
        case .unknown:
            break
        }
    }

    /// A stream id we have never seen (idle): peer-initiated ids above lastPeerStream, own ids not yet opened.
    private func isIdle(_ id: UInt32) -> Bool {
        let peerInitiated = (id % 2 == 1) == (role == .server)
        return peerInitiated ? id > lastPeerStream : id >= nextStreamID
    }

    private func applySettings(_ values: [H2SettingValue]) throws {
        for v in values {
            switch H2Setting(rawValue: v.id) {
            case .headerTableSize?:
                hpackOut.setPeerMaxTableSize(Int(v.value))
            case .enablePush?:
                if v.value > 1 { throw H2Error(.protocolError, "ENABLE_PUSH \(v.value)") }
            case .maxConcurrentStreams?:
                peerMaxConcurrent = Int(v.value)
            case .initialWindowSize?:
                if v.value > UInt32(H2Wire.maxWindow) { throw H2Error(.flowControlError, "INITIAL_WINDOW_SIZE \(v.value)") }
                let delta = Int(v.value) - peerInitialWindow
                peerInitialWindow = Int(v.value)
                for (_, s) in streams {
                    s.sendWindow += delta
                    if s.sendWindow > H2Wire.maxWindow { throw H2Error(.flowControlError, "stream window overflow") }
                }
            case .maxFrameSize?:
                if v.value < 16_384 || v.value > 16_777_215 { throw H2Error(.protocolError, "MAX_FRAME_SIZE \(v.value)") }
                peerMaxFrame = Int(v.value)
            case .maxHeaderListSize?, .enableConnectProtocol?, nil:
                break
            }
        }
    }

    private func onData(_ sid: UInt32, _ payload: [UInt8], _ endStream: Bool, _ flowSize: Int) throws {
        connRecvWindow -= flowSize
        if connRecvWindow < 0 { throw H2Error(.flowControlError, "connection window exceeded") }
        guard let s = streams[sid] else {
            // A stream already closed (or reset by us): ignore the frame, but its bytes counted against the
            // connection window, so grant them back.
            consumedConnectionOnly(flowSize)
            if isIdle(sid) { throw H2Error(.protocolError, "DATA on idle stream \(sid)") }
            return
        }
        if s.recvEnd || (role == .client && !s.gotHeaders) {
            consumedConnectionOnly(flowSize)
            throw H2Error(.streamClosed, stream: sid, s.recvEnd ? "DATA after END_STREAM" : "DATA before the response headers")
        }
        s.recvWindow -= flowSize
        if s.recvWindow < 0 {
            consumedConnectionOnly(flowSize)
            throw H2Error(.flowControlError, stream: sid, "stream window exceeded")
        }
        let padding = flowSize - payload.count
        if padding > 0 { consumed(sid, padding) }
        if endStream { s.recvEnd = true }
        if !payload.isEmpty || endStream {
            owner?.h2Event(self, .data(stream: sid, bytes: Data(payload), endStream: endStream))
        }
        if endStream, let s2 = streams[sid] { maybeRemove(s2) }
    }

    private func consumedConnectionOnly(_ n: Int) {
        connRecvUnacked += n
        if connRecvUnacked >= limits.connectionWindow / 2 {
            var out: [UInt8] = []
            H2FrameEncoder.windowUpdate(stream: 0, increment: connRecvUnacked, into: &out)
            connRecvWindow += connRecvUnacked
            connRecvUnacked = 0
            enqueueControl(out)
        }
    }

    private func finishHeaders(_ sid: UInt32, _ block: [UInt8], endStream: Bool) throws {
        var fields: HTTPHeaderList = []
        var tooLarge = false
        do {
            fields = try hpackIn.decode(block)
        } catch HPACKError.headerListTooLarge {
            tooLarge = true
        } catch {
            throw H2Error(.compressionError, "HPACK: \(error)")
        }
        if let s = streams[sid] {
            // Trailers (or, on the client side, the response after 1xx).
            if role == .client && !s.gotHeaders {
                if tooLarge { throw H2Error(.protocolError, stream: sid, "response headers too large") }
                let status = fields.first { $0.name == ":status" }?.value ?? ""
                if status.count == 3, status.hasPrefix("1"), status != "101" {
                    if endStream { throw H2Error(.protocolError, stream: sid, "1xx with END_STREAM") }
                    return // interim response
                }
                s.gotHeaders = true
                if endStream { s.recvEnd = true }
                owner?.h2Event(self, .headers(stream: sid, fields: fields, endStream: endStream, trailers: false))
                if endStream, let s2 = streams[sid] { maybeRemove(s2) }
                return
            }
            if s.recvEnd { throw H2Error(.streamClosed, stream: sid, "HEADERS after END_STREAM") }
            if !endStream { throw H2Error(.protocolError, stream: sid, "trailers without END_STREAM") }
            if tooLarge { throw H2Error(.protocolError, stream: sid, "trailers too large") }
            s.recvEnd = true
            owner?.h2Event(self, .headers(stream: sid, fields: fields, endStream: true, trailers: true))
            if let s2 = streams[sid] { maybeRemove(s2) }
            return
        }
        if role == .client {
            if isIdle(sid) || sid % 2 == 0 { throw H2Error(.protocolError, "HEADERS on stream \(sid) we did not open") }
            return // a stream we already closed / reset: ignore (the block was decoded, HPACK stays in sync)
        }
        // Server: a new request stream.
        guard sid % 2 == 1 else { throw H2Error(.protocolError, "even stream id \(sid) from the client") }
        guard sid > lastPeerStream else { return } // trailers / late headers of a stream we closed or reset
        lastPeerStream = sid
        if goingAway {
            refuse(sid, fields: nil, endStream: endStream, reason: "going away", code: .refusedStream)
            return
        }
        if tooLarge {
            refuse(sid, fields: nil, endStream: endStream, reason: "header list too large", code: nil)
            return
        }
        if streams.count >= limits.maxConcurrentStreams {
            refuse(sid, fields: fields, endStream: endStream, reason: "concurrency limit", code: .refusedStream)
            return
        }
        let s = Stream(id: sid, sendWindow: peerInitialWindow, recvWindow: limits.streamWindow)
        s.gotHeaders = true
        s.recvEnd = endStream
        streams[sid] = s
        owner?.h2Event(self, .headers(stream: sid, fields: fields, endStream: endStream, trailers: false))
    }

    /// code nil: the owner answers (e.g. 431) on a stream entry it must end (and reset when the request is open).
    private func refuse(_ sid: UInt32, fields: HTTPHeaderList?, endStream: Bool, reason: String, code: H2ErrorCode?) {
        if let code {
            var out: [UInt8] = []
            H2FrameEncoder.rstStream(stream: sid, code: code, into: &out)
            enqueueControl(out)
            flush()
            owner?.h2Event(self, .refused(stream: sid, fields: fields, reason: reason))
        } else {
            let s = Stream(id: sid, sendWindow: peerInitialWindow, recvWindow: limits.streamWindow)
            s.gotHeaders = true
            s.recvEnd = endStream
            streams[sid] = s
            owner?.h2Event(self, .refused(stream: sid, fields: nil, reason: reason))
        }
    }
}
