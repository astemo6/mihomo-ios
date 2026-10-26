import Foundation
import Network
import os

/// Incremental HTTP/3 frame reader for one request stream (RFC 9114 §7): DATA payloads are streamed out as
/// they arrive (a DATA frame may be far larger than one QUIC read), HEADERS frames are collected whole
/// (capped), anything else (reserved / unknown / PUSH_PROMISE…) is skipped. Pure, unit-tested.
struct NCH3FrameReader {
    enum Event: Equatable {
        case headers(Data)
        case data(Data)
        case malformed(String)
    }

    static let maxHeadersFrame = 64 * 1024

    private var buffer = Data()
    private var dataRemaining = 0
    private var skipRemaining = 0

    /// Bytes held waiting for a complete frame header / HEADERS frame (bounded by maxHeadersFrame + 16).
    var buffered: Int { buffer.count }

    mutating func feed(_ chunk: Data) -> [Event] {
        var events: [Event] = []
        buffer.append(chunk)
        var off = 0
        defer { buffer = off >= buffer.count ? Data() : Data(buffer[off...]) }
        while off < buffer.count {
            if dataRemaining > 0 {
                let n = min(dataRemaining, buffer.count - off)
                events.append(.data(Data(buffer[off..<(off + n)])))
                dataRemaining -= n
                off += n
                continue
            }
            if skipRemaining > 0 {
                let n = min(skipRemaining, buffer.count - off)
                skipRemaining -= n
                off += n
                continue
            }
            guard let (type, l1) = NCHy2.varintDecode(buffer, at: off),
                  let (length, l2) = NCHy2.varintDecode(buffer, at: off + l1) else {
                if buffer.count - off > 16 {
                    events.append(.malformed("bad frame header"))
                    off = buffer.count
                }
                break
            }
            let header = l1 + l2
            switch type {
            case 0x00: // DATA
                dataRemaining = Int(clamping: length)
                off += header
            case 0x01: // HEADERS
                guard length <= UInt64(Self.maxHeadersFrame) else {
                    events.append(.malformed("HEADERS frame too large"))
                    off = buffer.count
                    return events
                }
                guard buffer.count - off - header >= Int(length) else { return events }
                let s = off + header
                events.append(.headers(Data(buffer[s..<(s + Int(length))])))
                off = s + Int(length)
            default: // reserved / unknown frame types are skipped (RFC 9114 §9)
                skipRemaining = Int(clamping: length)
                off += header
            }
        }
        return events
    }

    static func dataFrame(_ payload: Data) -> Data {
        NCHy2.http3Frame(type: 0x00, payload: payload)
    }

    /// Client SETTINGS on the control stream: QPACK dynamic table off (keeps responses decodable by the
    /// static-only NCHy2 decoder). No H3_DATAGRAM: CONNECT tunnels never use datagrams.
    static func settingsFrame() -> Data {
        var payload = Data()
        payload.append(NCHy2.varintEncode(0x01)); payload.append(NCHy2.varintEncode(0)) // QPACK_MAX_TABLE_CAPACITY
        payload.append(NCHy2.varintEncode(0x07)); payload.append(NCHy2.varintEncode(0)) // QPACK_BLOCKED_STREAMS
        return NCHy2.http3Frame(type: 0x04, payload: payload)
    }
}

/// One QUIC connection to an HTTP/3 CONNECT proxy (Shadowrocket "HTTP3" / NaïveProxy over QUIC): the H3
/// control stream with our SETTINGS, the server's unidirectional streams drained, and one bidirectional
/// request stream per proxied flow. The QUIC plumbing (NWConnectionGroup + NWMultiplexGroup, stream
/// extraction after .ready, per-stream options via NCQUICStreamOptions) is the hysteria2 connection's.
final class NCH3ProxyConnection {
    enum State { case idle, connecting, ready, failed, closed }

    let queue: DispatchQueue
    let key: String
    private let options: NCH2H3ProxyOptions

    private struct Snapshot {
        var state: State = .idle
        var waiters: [(queue: DispatchQueue, completion: (Error?) -> Void)] = []
        var streams = 0
    }
    private let snapshot = OSAllocatedUnfairLock(initialState: Snapshot())
    var state: State { snapshot.withLock { $0.state } }
    var isAlive: Bool { snapshot.withLock { $0.state == .ready } }
    var load: Int { snapshot.withLock { $0.streams } }

    static var idleTimeout: TimeInterval = 90
    static let maxServerStreams = 4

    private var group: NWConnectionGroup?
    private var control: NCHy2StreamChannel?
    private var serverStreams: [NCHy2StreamChannel] = []
    private var streams: [ObjectIdentifier: NCH3ProxyStream] = [:]
    private var idleTimer: DispatchWorkItem?
    var onClosed: (() -> Void)?

    init(key: String, options: NCH2H3ProxyOptions) {
        self.key = key
        self.options = options
        self.queue = NCSessionQueues.make("nc.h3proxy.\(key)")
    }

    func whenReady(callerQueue: DispatchQueue, completion: @escaping (Error?) -> Void) {
        enum Action { case now(Error?), wait }
        let action: Action = snapshot.withLock { snap in
            switch snap.state {
            case .ready: return .now(nil)
            case .failed, .closed: return .now(NCH2ProxySession.error("h3 proxy connection failed"))
            case .idle, .connecting:
                snap.waiters.append((callerQueue, completion))
                return .wait
            }
        }
        if case .now(let e) = action { callerQueue.async { completion(e) } }
    }

    private func setState(_ s: State, error: Error?) {
        let waiters: [(queue: DispatchQueue, completion: (Error?) -> Void)] = snapshot.withLock { snap in
            snap.state = s
            if s == .connecting { return [] }
            let w = snap.waiters
            snap.waiters = []
            return w
        }
        for w in waiters { w.queue.async { w.completion(error) } }
    }

    private func makeQUICOptions() -> NWProtocolQUIC.Options {
        let q = NWProtocolQUIC.Options(alpn: ["h3"])
        let tls = q.securityProtocolOptions
        sec_protocol_options_set_tls_min_version(tls, .tlsProtocol13)
        sec_protocol_options_set_tls_server_name(tls, options.serverName)
        if options.allowInsecure {
            sec_protocol_options_set_verify_block(tls, { _, _, complete in complete(true) }, queue)
        }
        return q
    }

    func start() {
        let first: Bool = snapshot.withLock { snap in
            guard snap.state == .idle else { return false }
            snap.state = .connecting
            return true
        }
        guard first else { return }
        ncOnSessionQueue(queue) { self.startOnQueue() }
    }

    private func startOnQueue() {
        let parameters = NWParameters(quic: makeQUICOptions())
        parameters.allowLocalEndpointReuse = true
        NCOutboundBinding.apply(parameters, host: options.server)
        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(options.server),
                                           port: NWEndpoint.Port(rawValue: UInt16(clamping: options.port)) ?? .any)
        let group = NWConnectionGroup(with: NWMultiplexGroup(to: endpoint), using: parameters)
        self.group = group
        group.stateUpdateHandler = { [weak self] st in
            guard let self else { return }
            switch st {
            case .ready:
                self.openControlStream()
            case .failed(let e):
                self.teardown(e)
            case .cancelled:
                self.teardown(NCH2ProxySession.error("h3 proxy connection closed"))
            default:
                break
            }
        }
        group.newConnectionHandler = { [weak self] incoming in
            guard let self else { incoming.cancel(); return }
            self.adoptServerStream(incoming)
        }
        group.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 15) { [weak self] in
            guard let self, self.state == .connecting else { return }
            self.teardown(NCH2ProxySession.error("h3 proxy connect timeout"))
        }
    }

    private func openControlStream() {
        guard state == .connecting, let group else { return }
        guard let conn = group.extract(connectionTo: nil,
                                       using: NCQUICStreamOptions.unidirectional(from: group, fallback: makeQUICOptions)) else {
            teardown(NCH2ProxySession.error("h3 proxy: cannot open control stream"))
            return
        }
        let ch = NCHy2StreamChannel(conn: conn)
        control = ch
        ch.start(queue: queue) { [weak self] error in
            guard let self else { return }
            if let error { self.teardown(error); return }
            var flight = NCHy2.varintEncode(0x00) // stream type: control
            flight.append(NCH3FrameReader.settingsFrame())
            ch.send(flight)
            guard self.state == .connecting else { return }
            self.setState(.ready, error: nil)
            self.armIdleTimer()
        }
    }

    /// Server-initiated unidirectional streams (control, QPACK encoder / decoder): kept open and drained —
    /// cancelling a critical stream is a connection error (H3_CLOSED_CRITICAL_STREAM).
    private func adoptServerStream(_ conn: NWConnection) {
        guard serverStreams.count < Self.maxServerStreams else { conn.cancel(); return }
        let ch = NCHy2StreamChannel(conn: conn)
        serverStreams.append(ch)
        ch.start(queue: queue) { [weak self] error in
            guard let self, error == nil else { return }
            self.drain(ch)
        }
    }

    private func drain(_ ch: NCHy2StreamChannel) {
        ch.receive { [weak self] data, _ in
            guard let self, data != nil, self.state == .ready || self.state == .connecting else { return }
            self.drain(ch)
        }
    }

    /// Open one CONNECT request stream (connection must be ready; nil otherwise).
    func openStream(headers: [(String, String)], naive: Bool, callerQueue: DispatchQueue,
                    ready: @escaping (Error?) -> Void) -> NCH3ProxyStream? {
        if NCSessionQueues.isCurrent(queue) {
            return openOnQueue(headers: headers, naive: naive, callerQueue: callerQueue, ready: ready)
        }
        return queue.sync { openOnQueue(headers: headers, naive: naive, callerQueue: callerQueue, ready: ready) }
    }

    private func openOnQueue(headers: [(String, String)], naive: Bool, callerQueue: DispatchQueue,
                             ready: @escaping (Error?) -> Void) -> NCH3ProxyStream? {
        guard state == .ready, let group, let conn = group.extract(connectionTo: nil, using: nil) else { return nil }
        idleTimer?.cancel()
        idleTimer = nil
        let stream = NCH3ProxyStream(channel: NCHy2StreamChannel(conn: conn), naive: naive, queue: queue,
                                     callerQueue: callerQueue, ready: ready)
        let id = ObjectIdentifier(stream)
        streams[id] = stream
        snapshot.withLock { $0.streams = streams.count }
        stream.onFinished = { [weak self] in
            guard let self else { return }
            ncOnSessionQueue(self.queue) {
                self.streams.removeValue(forKey: id)
                self.snapshot.withLock { $0.streams = self.streams.count }
                if self.streams.isEmpty { self.armIdleTimer() }
            }
        }
        stream.begin(headers: headers)
        return stream
    }

    func close() {
        ncOnSessionQueue(queue) { self.teardown(NCH2ProxySession.error("h3 proxy connection closed")) }
    }

    private func armIdleTimer() {
        idleTimer?.cancel()
        let t = DispatchWorkItem { [weak self] in
            guard let self, self.streams.isEmpty, self.state == .ready else { return }
            self.close()
        }
        idleTimer = t
        queue.asyncAfter(deadline: .now() + Self.idleTimeout, execute: t)
    }

    /// Session queue only; idempotent.
    private func teardown(_ error: Error) {
        let s = state
        guard s != .closed && s != .failed else { return }
        setState(s == .ready ? .closed : .failed, error: error)
        idleTimer?.cancel()
        idleTimer = nil
        let all = streams.values
        streams.removeAll()
        snapshot.withLock { $0.streams = 0 }
        for st in all { st.failFromConnection(error) }
        control?.cancel()
        control = nil
        for ch in serverStreams { ch.cancel() }
        serverStreams = []
        group?.stateUpdateHandler = nil
        group?.newConnectionHandler = nil
        group?.cancel()
        group = nil
        onClosed?()
        onClosed = nil
    }
}

/// One HTTP/3 CONNECT tunnel: HEADERS out, wait for the 2xx response HEADERS, then payload bytes travel in
/// DATA frames (naive-padded for the first eight each way when negotiated). Reads are pulled: the QUIC
/// stream is only read while the inbox is below `maxQueuedInbound`, so a slow consumer back-pressures the
/// peer through QUIC flow control instead of growing a buffer.
final class NCH3ProxyStream: NCRelayStream {
    private let channel: NCHy2StreamChannel
    private let naive: Bool
    private let queue: DispatchQueue
    let callerQueue: DispatchQueue
    private var readyCallback: ((Error?) -> Void)?
    var onFinished: () -> Void = {}

    private enum Phase { case starting, awaiting, open, closed }
    private var phase: Phase = .starting
    private var reader = NCH3FrameReader()
    private var padding: NCNaivePadding?
    private var held: [(Data, NCCallOnce)] = []
    private var heldBytes = 0
    private var inbox: [Data] = []
    private var inboxBytes = 0
    private var pendingReceive: ((Data?, Error?) -> Void)?
    private var failure: Error?
    private var ended = false
    private var reading = false
    private var deadline: DispatchWorkItem?
    private var finished = false

    static let maxQueuedInbound = 128 * 1024
    static let maxHeld = 64 * 1024

    init(channel: NCHy2StreamChannel, naive: Bool, queue: DispatchQueue, callerQueue: DispatchQueue,
         ready: @escaping (Error?) -> Void) {
        self.channel = channel
        self.naive = naive
        self.queue = queue
        self.callerQueue = callerQueue
        self.readyCallback = ready
    }

    func begin(headers: [(String, String)]) {
        let t = DispatchWorkItem { [weak self] in
            guard let self, self.phase == .starting || self.phase == .awaiting else { return }
            self.fail(NCH2ProxySession.error("h3 proxy CONNECT response timeout"))
        }
        deadline = t
        queue.asyncAfter(deadline: .now() + NCConnector.proxyHandshakeTimeout, execute: t)
        channel.start(queue: queue) { [weak self] error in
            guard let self, self.phase == .starting else { return }
            if let error { self.fail(error); return }
            self.phase = .awaiting
            self.channel.send(NCHy2.http3HeadersFrame(fieldSection: NCHTTPConnect.qpackEncode(headers)))
            self.readMore()
        }
    }

    // MARK: NCRelayStream

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        ncOnSessionQueue(queue) {
            switch self.phase {
            case .starting, .awaiting:
                guard !data.isEmpty, self.heldBytes + data.count <= Self.maxHeld else {
                    once.call()
                    if !data.isEmpty { self.fail(NCH2ProxySession.error("h3 proxy stream send buffer overflow")) }
                    return
                }
                self.held.append((data, once))
                self.heldBytes += data.count
            case .open:
                self.write(data, once)
            case .closed:
                once.call()
            }
        }
    }

    private func write(_ data: Data, _ once: NCCallOnce) {
        guard !data.isEmpty else { once.call(); return }
        let payload = padding != nil ? padding!.encode(data) : data
        channel.send(NCH3FrameReader.dataFrame(payload), completion: once.call)
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        ncOnSessionQueue(queue) {
            if !self.inbox.isEmpty {
                let d = self.inbox.removeFirst()
                self.inboxBytes -= d.count
                self.callerQueue.async { handler(d, nil) }
                if self.phase == .open { self.readMore() }
                return
            }
            if self.failure != nil || self.ended || self.phase == .closed {
                let f = self.failure
                self.callerQueue.async { handler(nil, f) }
                return
            }
            self.pendingReceive = handler
            if self.phase == .open { self.readMore() }
        }
    }

    func cancel() {
        ncOnSessionQueue(queue) {
            guard self.phase != .closed else { return }
            self.phase = .closed
            self.cleanup(NCH2ProxySession.error("h3 proxy stream cancelled"), deliver: false)
        }
    }

    func failFromConnection(_ error: Error) {
        ncOnSessionQueue(queue) {
            guard self.phase != .closed else { return }
            self.finished = true // the connection already dropped it from its table
            self.fail(error)
        }
    }

    // MARK: internals (session queue)

    private func readMore() {
        guard !reading, phase == .awaiting || phase == .open, !ended,
              inboxBytes < Self.maxQueuedInbound else { return }
        reading = true
        channel.receive { [weak self] data, error in
            guard let self else { return }
            self.reading = false
            guard self.phase == .awaiting || self.phase == .open else { return }
            guard let data else {
                if self.phase == .awaiting {
                    self.fail(error ?? NCH2ProxySession.error("h3 proxy stream closed before the CONNECT response"))
                } else if let error {
                    self.fail(error)
                } else {
                    self.ended = true
                    self.settle()
                    self.finish()
                }
                return
            }
            for event in self.reader.feed(data) {
                switch event {
                case .headers(let block):
                    if self.phase == .awaiting { self.handleResponse(block) }
                case .data(let payload):
                    guard self.phase == .open else {
                        self.fail(NCH2ProxySession.error("h3 proxy DATA before the CONNECT response"))
                        return
                    }
                    let plain = self.padding != nil ? self.padding!.decode(payload) : payload
                    if !plain.isEmpty { self.deliver(plain) }
                case .malformed(let why):
                    self.fail(NCH2ProxySession.error("h3 proxy stream: \(why)"))
                    return
                }
                if self.phase == .closed { return }
            }
            self.readMore()
        }
    }

    private func handleResponse(_ block: Data) {
        guard let fields = NCHy2.qpackDecodeFieldSection(block) else {
            fail(NCH2ProxySession.error("h3 proxy: undecodable CONNECT response"))
            return
        }
        let headers = fields.map { ($0.name, $0.value) }
        guard let status = NCHTTPConnect.status(headers) else {
            fail(NCH2ProxySession.error("h3 proxy CONNECT response without :status"))
            return
        }
        if (100..<200).contains(status) { return }
        guard (200..<300).contains(status) else {
            fail(NCH2ProxySession.error("h3 proxy CONNECT rejected (status \(status))"))
            return
        }
        deadline?.cancel()
        deadline = nil
        phase = .open
        if naive && NCNaivePadding.negotiated(responseHeaders: headers) { padding = NCNaivePadding() }
        let queued = held
        held = []
        heldBytes = 0
        for (data, once) in queued { write(data, once) }
        if let cb = readyCallback {
            readyCallback = nil
            callerQueue.async { cb(nil) }
        }
    }

    private func deliver(_ data: Data) {
        if let h = pendingReceive {
            pendingReceive = nil
            callerQueue.async { h(data, nil) }
        } else {
            inbox.append(data)
            inboxBytes += data.count
        }
    }

    private func settle() {
        guard let h = pendingReceive, inbox.isEmpty else { return }
        pendingReceive = nil
        let f = failure
        callerQueue.async { h(nil, f) }
    }

    private func fail(_ error: Error) {
        guard phase != .closed else { return }
        if failure == nil { failure = error }
        phase = .closed
        cleanup(failure!, deliver: true)
    }

    private func cleanup(_ error: Error, deliver: Bool) {
        deadline?.cancel()
        deadline = nil
        for (_, once) in held { once.call() }
        held = []
        heldBytes = 0
        channel.cancel()
        if let cb = readyCallback {
            readyCallback = nil
            callerQueue.async { cb(error) }
        }
        if let h = pendingReceive {
            pendingReceive = nil
            let f: Error? = deliver ? failure : error
            callerQueue.async { h(nil, f) }
        }
        finish()
    }

    private func finish() {
        guard !finished else { return }
        finished = true
        onFinished()
    }
}
