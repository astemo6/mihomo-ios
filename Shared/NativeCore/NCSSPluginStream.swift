import Foundation

/// v2ray-plugin http-upgrade transport (mihomo transport/v2ray-plugin +
/// transport/vmess websocket.go httpUpgrade): the SAME GET as the websocket
/// handshake but without the Sec-WebSocket-* headers; once the server answers
/// 101 with `Upgrade: websocket`, the connection is a raw byte stream — no
/// RFC 6455 framing at all. With fast-open the stream is handed out before
/// the 101 arrives and the response is validated on the first reads instead.
final class NCV2RayUpgradeStream: NCRelayStream {
    private let raw: NCRelayStream
    private let hostHeader: String
    private let path: String
    private let extraHeaders: [String: String]
    private let fastOpen: Bool
    private var validated = false
    private var failure: Error?
    private var buffered = Data()
    private var waiters: [(Data?, Error?) -> Void] = []
    private var closed = false

    init(raw: NCRelayStream, hostHeader: String, path: String, headers: [String: String], fastOpen: Bool) {
        self.raw = raw
        self.hostHeader = hostHeader
        self.path = path.hasPrefix("/") ? path : "/" + path
        self.extraHeaders = headers
        self.fastOpen = fastOpen
    }

    /// Sends the upgrade request. Without fast-open, completion fires once the
    /// 101 has been validated; with fast-open it fires immediately and the
    /// validation keeps running in the background.
    func startHandshake(completion: @escaping (Error?) -> Void) {
        var req = "GET \(path) HTTP/1.1\r\nHost: \(hostHeader)\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nUser-Agent: Mozilla/5.0\r\n"
        for (k, v) in extraHeaders { req += "\(k): \(v)\r\n" }
        req += "\r\n"
        raw.send(Data(req.utf8))
        if fastOpen {
            pumpValidation()
            completion(nil)
        } else {
            pumpValidation(completion)
        }
    }

    private func pumpValidation(_ completion: ((Error?) -> Void)? = nil) {
        var head = Data()
        func pump() {
            raw.receive { [weak self] data, error in
                guard let self else { completion?(error); return }
                guard let data else {
                    let err = error ?? NCConnector.Failure.handshake("v2ray-plugin http-upgrade")
                    if completion != nil { completion?(err) } else { self.failValidation(err) }
                    return
                }
                head.append(data)
                if let end = head.range(of: Data("\r\n\r\n".utf8)) {
                    let headText = String(decoding: head[head.startIndex..<end.lowerBound], as: UTF8.self)
                    guard Self.isUpgrade101(headText) else {
                        let err = NCConnector.Failure.handshake("v2ray-plugin http-upgrade refused")
                        if completion != nil { completion?(err) } else { self.failValidation(err) }
                        return
                    }
                    self.buffered = Data(head[end.upperBound...])
                    self.validated = true
                    completion?(nil)
                    self.flushWaiters()
                    return
                }
                if head.count > 16384 {
                    let err = NCConnector.Failure.handshake("v2ray-plugin http-upgrade overflow")
                    if completion != nil { completion?(err) } else { self.failValidation(err) }
                    return
                }
                pump()
            }
        }
        pump()
    }

    /// mihomo's check (sagernet sing-shadowsocks2 / vmess websocket): a 101
    /// whose headers carry `Upgrade: websocket` and a Connection token `upgrade`.
    private static func isUpgrade101(_ head: String) -> Bool {
        let lines = head.lowercased().components(separatedBy: "\r\n")
        guard lines.first?.contains(" 101") == true else { return false }
        var upgrade = false, connection = false
        for line in lines.dropFirst() {
            if line.hasPrefix("upgrade:") && line.contains("websocket") { upgrade = true }
            if line.hasPrefix("connection:") && line.contains("upgrade") { connection = true }
        }
        return upgrade && connection
    }

    private func failValidation(_ error: Error) {
        failure = error
        let pending = waiters
        waiters = []
        for w in pending { w(nil, error) }
        // fix/nc-silent-fail: tear the refused connection down (as NCV2RayWSStream.fail does) — leaving
        // raw open let later sends complete into a connection the server already rejected.
        raw.cancel()
    }

    private func flushWaiters() {
        while validated, failure == nil, !waiters.isEmpty {
            let w = waiters.removeFirst()
            receive(w)
        }
    }

    func send(_ data: Data) { send(data, completion: {}) }

    func send(_ data: Data, completion: @escaping () -> Void) {
        // Fast-open sends go out before validation by design; a non-fast-open
        // stream only receives sends after startHandshake completed. Once
        // validation has failed the stream is dead: fire the completion
        // without writing (the NCWebSocketStream closed-send convention).
        guard !closed, failure == nil else { completion(); return }
        raw.send(data, completion: completion)
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        if !buffered.isEmpty {
            let chunk = buffered
            buffered = Data()
            handler(chunk, nil)
            return
        }
        if let failure {
            handler(nil, failure)
            return
        }
        if closed {
            handler(nil, nil)
            return
        }
        if fastOpen, !validated {
            waiters.append(handler)
            return
        }
        raw.receive { handler($0, $1) }
    }

    func cancel() {
        closed = true
        let pending = waiters
        waiters = []
        for w in pending { w(nil, nil) }
        raw.cancel()
    }
}

/// Shadowsocks stream-plugin transport (simple-obfs http/tls, v2ray-plugin
/// websocket). Wraps a connected stream to the SS server so the WHOLE SS
/// byte stream — request head included — rides inside the plugin, matching
/// mihomo's adapter/outbound/shadowsocks.go StreamConnContext, which wraps
/// the raw conn with the plugin before the SS codec sees it. TCP only; SS
/// UDP sessions never go through a plugin (mihomo parity).
///
/// Layering: the pure wire formats live in Shared/NativeCore/NCSSPlugin.swift;
/// this class only drives them over NCRelayStream (obfs rides the raw socket,
/// v2ray-plugin reuses NCWebSocketStream's RFC 6455 frame layer).
final class NCSSPluginStream: NCRelayStream {
    private let raw: NCRelayStream
    private let opts: NCSSPluginOptions
    private let serverPort: String
    private let ws: NCWebSocketStream?
    /// http-upgrade transport (raw stream after the 101) — mutually exclusive with `ws`.
    private let upgrade: NCV2RayUpgradeStream?

    /// Flips after the first send (obfs disguise / mux create frame go out
    /// with it), like mihomo's firstRequest/firstResponse flags.
    private var started = false

    // Receive-side state, one per plugin shape.
    private var httpStripper = NCSSPlugin.HTTPResponseStripper()
    private var tlsParser = NCSSPlugin.TLSResponseParser()
    private var muxParser = NCSSPlugin.V2RayMux.Parser()

    init(raw: NCRelayStream, options: NCSSPluginOptions, serverPort: String) {
        self.raw = raw
        self.opts = options
        self.serverPort = serverPort
        if case .v2rayPlugin = options.kind {
            var headers = options.headers
            // mihomo v2ray NewV2rayObfs: a Host header overrides the Host
            // used for the upgrade request (and for the TLS server name).
            let hostHeader = headers.removeValue(forKey: "Host") ?? options.host
            if options.httpUpgrade {
                self.ws = nil
                self.upgrade = NCV2RayUpgradeStream(raw: raw, hostHeader: hostHeader, path: options.path,
                                                     headers: headers, fastOpen: options.httpUpgradeFastOpen)
            } else {
                self.ws = NCWebSocketStream(raw: raw, hostHeader: hostHeader, path: options.path, headers: headers)
                self.upgrade = nil
            }
        } else {
            self.ws = nil
            self.upgrade = nil
        }
    }

    /// v2ray-plugin runs the upgrade handshake first; the obfs modes need no
    /// handshake — their disguise rides the first data packet.
    func start(completion: @escaping (Error?) -> Void) {
        if let upgrade {
            upgrade.startHandshake { err in completion(err) }
        } else if let ws {
            ws.startHandshake { err in completion(err) }
        } else {
            completion(nil)
        }
    }

    func send(_ data: Data) { send(data, completion: {}) }

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        let first = !started
        started = true
        switch opts.kind {
        case .obfs:
            if opts.mode == "http" {
                if first {
                    raw.send(NCSSPlugin.obfsHTTPRequest(host: opts.host, port: serverPort, payload: data), completion: once.call)
                } else {
                    raw.send(data, completion: once.call)
                }
            } else {
                if first {
                    raw.send(NCSSPlugin.obfsTLSClientHello(host: opts.host, payload: data), completion: once.call)
                } else {
                    raw.ncSendSequentially(NCSSPlugin.obfsTLSAppDataRecords(data), completion: once.call)
                }
            }
        case .v2rayPlugin:
            // The byte sink under the (optional) mux framing: the websocket
            // stream, or the raw post-101 stream for http-upgrade.
            let sink: NCRelayStream? = (upgrade as NCRelayStream?) ?? (ws as NCRelayStream?)
            guard let sink else { once.call(); return }
            if opts.mux {
                // mihomo mux.go NewMux pre-fills the create frame; the first
                // Write flushes create + data together.
                if first {
                    sink.send(NCSSPlugin.V2RayMux.createFrame() + NCSSPlugin.V2RayMux.dataFrame(payload: data), completion: once.call)
                } else {
                    sink.send(NCSSPlugin.V2RayMux.dataFrame(payload: data), completion: once.call)
                }
            } else {
                sink.send(data, completion: once.call)
            }
        }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        switch opts.kind {
        case .obfs:
            if opts.mode == "http" {
                raw.receive { [weak self] data, error in
                    guard let self else { handler(nil, error); return }
                    guard let data else { handler(nil, error); return }
                    guard let plain = self.httpStripper.feed(data) else {
                        handler(nil, self.pluginError("obfs http response header"))
                        return
                    }
                    if plain.isEmpty { self.receive(handler) } else { handler(plain, nil) }
                }
            } else {
                raw.receive { [weak self] data, error in
                    guard let self else { handler(nil, error); return }
                    guard let data else { handler(nil, error); return }
                    guard let plain = self.tlsParser.feed(data) else {
                        handler(nil, self.pluginError("obfs tls response record"))
                        return
                    }
                    if plain.isEmpty { self.receive(handler) } else { handler(plain, nil) }
                }
            }
        case .v2rayPlugin:
            let source: NCRelayStream? = (upgrade as NCRelayStream?) ?? (ws as NCRelayStream?)
            source?.receive { [weak self] data, error in
                guard let self else { handler(nil, error); return }
                guard let data else { handler(nil, error); return }
                if !self.opts.mux {
                    handler(data, nil)
                    return
                }
                guard let plain = self.muxParser.feed(data) else {
                    handler(nil, self.pluginError("v2ray-plugin mux frame"))
                    return
                }
                if plain.isEmpty { self.receive(handler) } else { handler(plain, nil) }
            }
        }
    }

    func cancel() {
        // Best-effort mux session end (mihomo Mux.Close), then tear the
        // transport down — the ws / upgrade streams' cancel closes the raw stream.
        if case .v2rayPlugin = opts.kind, opts.mux {
            ((upgrade as NCRelayStream?) ?? (ws as NCRelayStream?))?.send(NCSSPlugin.V2RayMux.endFrame())
        }
        if let upgrade {
            upgrade.cancel()
        } else if let ws {
            ws.cancel()
        } else {
            raw.cancel()
        }
    }

    private func pluginError(_ what: String) -> Error {
        NSError(domain: "NativeCore", code: 3,
                userInfo: [NSLocalizedDescriptionKey: "shadowsocks plugin decode failed: \(what)"])
    }
}
