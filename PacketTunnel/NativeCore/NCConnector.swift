import Foundation
import Network

/// A ready-to-relay stream: plaintext in, plaintext out. For Shadowsocks the
/// transform happens inside; callers never see wire bytes.
protocol NCRelayStream: AnyObject {
    func send(_ data: Data)
    func receive(_ handler: @escaping (Data?, Error?) -> Void)
    func cancel()
}

extension NCStream: NCRelayStream {}

/// Shadowsocks relay: encodes on send (target address is the first plaintext
/// chunk, sent at connect time), decodes on receive, swallowing chunks that
/// carry only salt/framing (receive again until real plaintext or EOF).
final class NCSSRelayStream: NCRelayStream {
    private let raw: NCStream
    private let encoder: NCSSEncoder
    private let decoder: NCSSDecoder

    init(raw: NCStream, encoder: NCSSEncoder, decoder: NCSSDecoder, target: NCTarget) {
        self.raw = raw
        self.encoder = encoder
        self.decoder = decoder
        if let head = encoder.encode(target.atypEncoded) {
            raw.send(head)
        }
    }

    func send(_ data: Data) {
        if let wire = encoder.encode(data) { raw.send(wire) }
        else { raw.cancel() }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        raw.receive { [weak self] data, error in
            guard let self else { handler(nil, error); return }
            guard let data else { handler(nil, error); return }
            guard let plain = self.decoder.feed(data) else {
                handler(nil, NSError(domain: "NativeCore", code: 3, userInfo: [NSLocalizedDescriptionKey: "shadowsocks decode failed"]))
                return
            }
            if plain.isEmpty {
                self.receive(handler)
            } else {
                handler(plain, nil)
            }
        }
    }

    func cancel() { raw.cancel() }
}

/// SS2022 relay: the request head (salt + sealed headers) goes out at
/// connect; the response decoder validates the header before payload flows.
final class NCSS2022RelayStream: NCRelayStream {
    private let raw: NCStream
    private let encoder: NCSS2022Encoder
    private let decoder: NCSS2022Decoder

    init(raw: NCStream, encoder: NCSS2022Encoder, decoder: NCSS2022Decoder, target: NCTarget) {
        self.raw = raw
        self.encoder = encoder
        self.decoder = decoder
        if let head = encoder.requestHead(target: target,
                                          timestamp: UInt64(Date().timeIntervalSince1970)) {
            raw.send(head)
        }
    }

    func send(_ data: Data) {
        if let wire = encoder.encode(data) { raw.send(wire) }
        else { raw.cancel() }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        raw.receive { [weak self] data, error in
            guard let self else { handler(nil, error); return }
            guard let data else { handler(nil, error); return }
            guard let pieces = self.decoder.feed(data) else {
                handler(nil, NSError(domain: "NativeCore", code: 3, userInfo: [NSLocalizedDescriptionKey: "shadowsocks 2022 decode failed"]))
                return
            }
            let joined = pieces.reduce(into: Data()) { $0.append($1) }
            if joined.isEmpty {
                self.receive(handler)
            } else {
                handler(joined, nil)
            }
        }
    }

    func cancel() { raw.cancel() }
}

/// Strips the one-byte Snell server reply off the start of the plaintext
/// stream; an error reply surfaces as a failure on the pending receive.
final class NCSnellReplyStripper {
    private var buffer = Data()
    private(set) var done = false
    private(set) var failure: String?

    /// Feed plaintext; returns deliverable payload (nil = need more bytes
    /// or the stream is dead — check `failure`).
    func feed(_ data: Data) -> Data? {
        if done { return data }
        buffer.append(data)
        switch NCSnell.parseReply(buffer) {
        case .ok(let consumed):
            done = true
            let rest = Data(buffer.dropFirst(consumed))
            buffer = Data()
            return rest
        case .error(let msg):
            failure = msg
            return nil
        case .pending:
            return nil
        }
    }
}

/// Snell v1–v3 relay: SS-framed AEAD stream + connect header + reply byte.
final class NCSnellStreamRelay: NCRelayStream {
    private let raw: NCStream
    private let encoder: NCSnellStreamEncoder
    private let decoder: NCSnellStreamDecoder
    private let stripper = NCSnellReplyStripper()

    init(raw: NCStream, psk: Data, version: Int, target: NCTarget) {
        self.raw = raw
        encoder = NCSnellStreamEncoder(psk: psk, version: version)
        decoder = NCSnellStreamDecoder(psk: psk, version: version)
        if let wire = encoder.encode(NCSnell.connectHeader(host: target.host, port: target.port, version: version)) {
            raw.send(wire)
        }
    }

    func send(_ data: Data) {
        if let wire = encoder.encode(data) { raw.send(wire) }
        else { raw.cancel() }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        raw.receive { [weak self] data, error in
            guard let self else { handler(nil, error); return }
            guard let data else { handler(nil, error); return }
            guard let pieces = self.decoder.feed(data) else {
                handler(nil, NSError(domain: "NativeCore", code: 4, userInfo: [NSLocalizedDescriptionKey: "snell decode failed"]))
                return
            }
            for piece in pieces {
                if let out = self.stripper.feed(piece), !out.isEmpty {
                    handler(out, nil)
                    return
                }
                if let failure = self.stripper.failure {
                    handler(nil, NSError(domain: "NativeCore", code: 4, userInfo: [NSLocalizedDescriptionKey: failure]))
                    return
                }
            }
            self.receive(handler)
        }
    }

    func cancel() { raw.cancel() }
}

/// Snell v4/v5 relay: frame-based stream + connect header + reply byte.
final class NCSnellV4Relay: NCRelayStream {
    private let raw: NCStream
    private let writer: NCSnellV4Writer
    private let reader: NCSnellV4Reader
    private let stripper = NCSnellReplyStripper()

    init(raw: NCStream, psk: Data, target: NCTarget) {
        self.raw = raw
        writer = NCSnellV4Writer(psk: psk)
        reader = NCSnellV4Reader(psk: psk)
        if let wire = writer.write(NCSnell.connectHeader(host: target.host, port: target.port, version: 4)) {
            raw.send(wire)
        }
    }

    func send(_ data: Data) {
        if let wire = writer.write(data) { raw.send(wire) }
        else { raw.cancel() }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        raw.receive { [weak self] data, error in
            guard let self else { handler(nil, error); return }
            guard let data else { handler(nil, error); return }
            guard let pieces = self.reader.feed(data) else {
                handler(nil, NSError(domain: "NativeCore", code: 4, userInfo: [NSLocalizedDescriptionKey: "snell v4 decode failed"]))
                return
            }
            for piece in pieces {
                switch piece {
                case .end:
                    handler(nil, nil)
                    return
                case .data(let plain):
                    if let out = self.stripper.feed(plain), !out.isEmpty {
                        handler(out, nil)
                        return
                    }
                    if let failure = self.stripper.failure {
                        handler(nil, NSError(domain: "NativeCore", code: 4, userInfo: [NSLocalizedDescriptionKey: failure]))
                        return
                    }
                }
            }
            self.receive(handler)
        }
    }

    func cancel() { raw.cancel() }
}

enum NCConnector {
    enum Failure: Error {
        case rejected
        case unknownPolicy(String)
        case unsupported(String)
        case handshake(String)
    }

    /// Opens a relay stream to `target` through the resolved outbound.
    /// Completion fires on `queue` exactly once.
    static func connect(target: NCTarget,
                        resolution: NCGroupEngine.Resolution,
                        queue: DispatchQueue,
                        completion: @escaping (NCRelayStream?, Error?) -> Void) {
        switch resolution {
        case .direct:
            let s = NCStream(to: target.host, port: target.port, queue: queue)
            s.start { err in completion(err == nil ? s : nil, err) }
        case .reject:
            queue.async { completion(nil, Failure.rejected) }
        case .unknown(let name):
            queue.async { completion(nil, Failure.unknownPolicy(name)) }
        case .proxy(let proxy):
            connectViaProxy(target: target, proxy: proxy, queue: queue, completion: completion)
        }
    }

    private static func connectViaProxy(target: NCTarget, proxy: NCProxy, queue: DispatchQueue,
                                        allowMux: Bool = true,
                                        completion: @escaping (NCRelayStream?, Error?) -> Void) {
        guard let server = proxy.server, let port = proxy.port else {
            queue.async { completion(nil, Failure.handshake("proxy \(proxy.name) missing server/port")) }
            return
        }
        // sing-mux (h2mux) interception: vmess/vless flows ride a shared
        // session whose own proxy connection targets the mux destination.
        if allowMux, proxy.type == "vmess" || proxy.type == "vless",
           smuxEnabled(proxy), target != NCMux.destination {
            guard smuxProtocol(proxy) == "h2mux" else {
                queue.async { completion(nil, Failure.unsupported("smux protocol \(smuxProtocol(proxy)) (h2mux only)")) }
                return
            }
            muxSession(proxy: proxy, server: server, port: port, queue: queue) { session, err in
                guard let session else { completion(nil, err); return }
                completion(session.openStream(target: target), nil)
            }
            return
        }
        switch proxy.type {
        case "socks5":
            let raw = NCStream(to: server, port: port, queue: queue)
            raw.start { err in
                guard err == nil else { completion(nil, err); return }
                socksHandshake(raw: raw, target: target, proxy: proxy, completion: completion)
            }
        case "http", "https":
            let raw = NCStream(to: server, port: port, tls: proxy.type == "https", queue: queue)
            raw.start { err in
                guard err == nil else { completion(nil, err); return }
                httpHandshake(raw: raw, target: target, proxy: proxy, completion: completion)
            }
        case "ss":
            guard let cipher = proxy.cipher, let password = proxy.password else {
                queue.async { completion(nil, Failure.handshake("bad shadowsocks cipher/password")) }
                return
            }
            let raw = NCStream(to: server, port: port, queue: queue)
            if NCSS2022.isMethod2022(cipher) {
                guard let enc = NCSS2022Encoder(method: cipher, password: password),
                      let dec = NCSS2022Decoder(method: cipher, password: password,
                                                requestSalt: enc.salt) else {
                    queue.async { completion(nil, Failure.handshake("bad shadowsocks 2022 password")) }
                    return
                }
                raw.start { err in
                    guard err == nil else { completion(nil, err); return }
                    completion(NCSS2022RelayStream(raw: raw, encoder: enc, decoder: dec, target: target), nil)
                }
                return
            }
            guard let enc = NCSSEncoder(cipher: cipher, password: password),
                  let dec = NCSSDecoder(cipher: cipher, password: password) else {
                queue.async { completion(nil, Failure.handshake("bad shadowsocks cipher/password")) }
                return
            }
            raw.start { err in
                guard err == nil else { completion(nil, err); return }
                completion(NCSSRelayStream(raw: raw, encoder: enc, decoder: dec, target: target), nil)
            }
        case "snell":
            guard let password = proxy.password else {
                queue.async { completion(nil, Failure.handshake("snell missing psk")) }
                return
            }
            let version = proxy.fields["version"]?.int ?? 1
            let psk = Data(password.utf8)
            let raw = NCStream(to: server, port: port, queue: queue)
            raw.start { err in
                guard err == nil else { completion(nil, err); return }
                if version >= 4 {
                    completion(NCSnellV4Relay(raw: raw, psk: psk, target: target), nil)
                } else {
                    completion(NCSnellStreamRelay(raw: raw, psk: psk, version: version, target: target), nil)
                }
            }
        case "trojan":
            guard let password = proxy.password else {
                queue.async { completion(nil, Failure.handshake("trojan missing password")) }
                return
            }
            if realityParams(proxy) != nil {
                dialReality(proxy: proxy, server: server, port: port, queue: queue) { base, err in
                    guard let base else { completion(nil, err); return }
                    base.send(NCTrojan.requestHead(password: password, target: target))
                    completion(base, nil)
                }
                return
            }
            let raw = NCStream(to: server, port: port,
                               tlsServerName: proxy.fields["sni"]?.string ?? server,
                               allowInsecure: proxy.fields["skip-cert-verify"]?.bool ?? false,
                               queue: queue)
            raw.start { err in
                guard err == nil else { completion(nil, err); return }
                raw.send(NCTrojan.requestHead(password: password, target: target))
                completion(raw, nil)
            }
        case "vless":
            guard let uuid = proxy.uuid else {
                queue.async { completion(nil, Failure.handshake("vless missing uuid")) }
                return
            }
            if realityParams(proxy) != nil {
                guard let head = NCVLESS.requestHead(uuid: uuid, target: target,
                                                     flow: proxy.fields["flow"]?.string ?? "") else {
                    queue.async { completion(nil, Failure.handshake("vless bad uuid")) }
                    return
                }
                dialReality(proxy: proxy, server: server, port: port, queue: queue) { base0, err in
                    guard let base0 else { completion(nil, err); return }
                    if visionFlow(proxy), let tlsClient = base0 as? NCTLSClientStream,
                       let uuidBytes = NCVLESS.uuidBytes(uuid) {
                        let vision = NCVisionStream(tls: tlsClient, uuid: uuidBytes)
                        vision.send(head)
                        completion(NCVLESSRelayStream(raw: vision), nil)
                        return
                    }
                    transportStream(raw: base0, proxy: proxy, server: server) { base, terr in
                        guard let base else { completion(nil, terr); return }
                        base.send(head)
                        completion(NCVLESSRelayStream(raw: base), nil)
                    }
                }
                return
            }
            let useTLS = proxy.fields["tls"]?.bool ?? false
            let isVision = visionFlow(proxy)
            let raw: NCStream
            if useTLS && !isVision {
                raw = NCStream(to: server, port: port,
                               tlsServerName: proxy.fields["servername"]?.string ?? proxy.fields["sni"]?.string ?? server,
                               allowInsecure: proxy.fields["skip-cert-verify"]?.bool ?? false,
                               queue: queue)
            } else {
                // Vision needs the hand-rolled TLS client over a raw socket
                // (the splice must reach the socket), so no NWConnection TLS.
                raw = NCStream(to: server, port: port, queue: queue)
            }
            raw.start { err in
                guard err == nil else { completion(nil, err); return }
                guard let head = NCVLESS.requestHead(uuid: uuid, target: target,
                                                     flow: proxy.fields["flow"]?.string ?? "") else {
                    completion(nil, Failure.handshake("vless bad uuid"))
                    return
                }
                if isVision, useTLS, let uuidBytes = NCVLESS.uuidBytes(uuid) {
                    let tls = NCTLSClientStream(raw: raw, config: .init(
                        serverName: proxy.fields["servername"]?.string ?? proxy.fields["sni"]?.string ?? server,
                        allowInsecure: proxy.fields["skip-cert-verify"]?.bool ?? false), queue: queue)
                    tls.startHandshake { herr in
                        guard herr == nil else { completion(nil, herr); return }
                        let vision = NCVisionStream(tls: tls, uuid: uuidBytes)
                        vision.send(head)
                        completion(NCVLESSRelayStream(raw: vision), nil)
                    }
                    return
                }
                transportStream(raw: raw, proxy: proxy, server: server) { base, terr in
                    guard let base else { completion(nil, terr); return }
                    base.send(head)
                    completion(NCVLESSRelayStream(raw: base), nil)
                }
            }
        case "hysteria2", "hy2":
            sharedHysteria2(proxy: proxy, server: server, port: port, queue: queue) { conn, err in
                guard let conn, let stream = conn.openTCP(target: target) else {
                    completion(nil, err ?? Failure.handshake("hysteria2 open stream failed"))
                    return
                }
                completion(stream, nil)
            }
        case "vmess":
            connectVMess(target: target, proxy: proxy, server: server, port: port, queue: queue, completion: completion)
        case "tuic":
            // Platform-blocked, see docs/native-core-design.md: TUIC auth
            // and UDP commands live on QUIC unidirectional streams, which
            // Network.framework does not expose (v5 also needs the TLS
            // keying-material exporter). Fail loudly, never silently.
            queue.async {
                completion(nil, Failure.unsupported("tuic: needs QUIC uni streams + TLS exporter, unavailable in Network.framework"))
            }
        default:
            queue.async { completion(nil, Failure.unsupported(proxy.type)) }
        }
    }

    /// xtls-rprx-vision applies only over a direct TLS 1.3 TCP stream —
    /// ws/grpc transports can't splice, so they keep the unframed behavior.
    static func visionFlow(_ proxy: NCProxy) -> Bool {
        proxy.fields["flow"]?.string == "xtls-rprx-vision"
            && (proxy.fields["network"]?.string ?? "tcp") == "tcp"
    }

    // MARK: REALITY

    /// Parse reality-opts {public-key (base64url), short-id (hex)}.
    static func realityParams(_ proxy: NCProxy) -> NCTLS13.RealityParams? {
        guard let opts = proxy.fields["reality-opts"]?.object,
              let pubB64 = opts["public-key"]?.string else { return nil }
        var b64 = pubB64.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 { b64.append("=") }
        guard let pub = Data(base64Encoded: b64), pub.count == 32 else { return nil }
        var shortID = Data()
        let shortHex = opts["short-id"]?.string ?? ""
        var idx = shortHex.startIndex
        while idx < shortHex.endIndex, shortID.count < 8 {
            let next = shortHex.index(idx, offsetBy: 2, limitedBy: shortHex.endIndex) ?? shortHex.endIndex
            guard let byte = UInt8(shortHex[idx..<next], radix: 16) else { break }
            shortID.append(byte)
            idx = next
        }
        return NCTLS13.RealityParams(publicKey: pub, shortID: shortID)
    }

    /// Dial TCP and run the hand-rolled TLS 1.3 REALITY handshake over it.
    static func dialReality(proxy: NCProxy, server: String, port: Int, queue: DispatchQueue,
                            completion: @escaping (NCRelayStream?, Error?) -> Void) {
        guard let reality = realityParams(proxy) else {
            queue.async { completion(nil, Failure.handshake("reality-opts invalid")) }
            return
        }
        let raw = NCStream(to: server, port: port, queue: queue)
        raw.start { err in
            guard err == nil else { completion(nil, err); return }
            let tls = NCTLSClientStream(raw: raw, config: .init(
                serverName: proxy.fields["servername"]?.string ?? proxy.fields["sni"]?.string ?? server,
                reality: reality), queue: queue)
            tls.startHandshake { herr in
                completion(herr == nil ? tls : nil, herr)
            }
        }
    }

    // MARK: WebSocket transport (VMess/VLESS "ws" network)

    static func wsOptions(_ proxy: NCProxy) -> (path: String, headers: [String: String]) {
        let opts = proxy.fields["ws-opts"]?.object
        var headers: [String: String] = [:]
        if let h = opts?["headers"]?.object {
            for (k, v) in h { if let str = v.string { headers[k] = str } }
        }
        return (opts?["path"]?.string ?? "/", headers)
    }

    /// Wrap the connected raw stream with the configured transport
    /// (ws / grpc / h2), or pass it through for plain tcp.
    static func transportStream(raw: NCRelayStream, proxy: NCProxy, server: String,
                                completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let network = proxy.fields["network"]?.string ?? "tcp"
        switch network {
        case "ws":
            let (path, headers) = wsOptions(proxy)
            let host = proxy.fields["ws-opts"]?.object?["headers"]?.object?["Host"]?.string ?? server
            let ws = NCWebSocketStream(raw: raw, hostHeader: host, path: path, headers: headers)
            ws.startHandshake { err in
                completion(err == nil ? ws : nil, err)
            }
        case "grpc":
            let service = proxy.fields["grpc-opts"]?.object?["grpc-service-name"]?.string ?? "GunService"
            let authority = proxy.fields["servername"]?.string ?? proxy.fields["sni"]?.string ?? server
            let tunnel = NCH2TunnelStream(raw: raw, grpc: true)
            tunnel.startHandshake(headers: [
                (":method", "POST"),
                (":path", "/\(service)/Tun"),
                (":scheme", "https"),
                (":authority", authority),
                ("content-type", "application/grpc"),
                ("user-agent", "grpc-go/1.0"),
                ("te", "trailers"),
            ]) { err in
                completion(err == nil ? tunnel : nil, err)
            }
        case "h2", "http":
            let opts = proxy.fields["h2-opts"]?.object
            let path = opts?["path"]?.string ?? "/"
            let authority = opts?["host"]?.array?.first?.string
                ?? proxy.fields["servername"]?.string ?? proxy.fields["sni"]?.string ?? server
            let tunnel = NCH2TunnelStream(raw: raw, grpc: false)
            tunnel.startHandshake(headers: [
                (":method", "POST"),
                (":path", path),
                (":scheme", "https"),
                (":authority", authority),
                ("content-type", "application/octet-stream"),
            ]) { err in
                completion(err == nil ? tunnel : nil, err)
            }
        default:
            completion(raw, nil)
        }
    }

    // MARK: sing-mux (shared h2mux session per proxy)

    static func smuxEnabled(_ proxy: NCProxy) -> Bool {
        proxy.fields["smux"]?.object?["enabled"]?.bool ?? false
    }

    static func smuxProtocol(_ proxy: NCProxy) -> String {
        proxy.fields["smux"]?.object?["protocol"]?.string ?? "h2mux"
    }

    private static var muxRegistry: [String: NCMuxSession] = [:]
    private static let muxLock = NSLock()

    static func muxSession(proxy: NCProxy, server: String, port: Int, queue: DispatchQueue,
                           completion: @escaping (NCMuxSession?, Error?) -> Void) {
        let key = "\(proxy.name)|\(server)|\(port)"
        muxLock.lock()
        if let existing = muxRegistry[key] {
            muxLock.unlock()
            if existing.isAlive {
                completion(existing, nil)
            } else if existing.state == .connecting {
                waitMuxReady(existing, key: key, queue: queue, attempts: 60, completion: completion)
            } else {
                muxLock.lock()
                muxRegistry.removeValue(forKey: key)
                muxLock.unlock()
                muxSession(proxy: proxy, server: server, port: port, queue: queue, completion: completion)
            }
            return
        }
        let session = NCMuxSession()
        muxRegistry[key] = session
        muxLock.unlock()
        connectViaProxy(target: NCMux.destination, proxy: proxy, queue: queue, allowMux: false) { base, err in
            if let base {
                session.attach(base: base)
                completion(session, nil)
            } else {
                muxLock.lock()
                muxRegistry.removeValue(forKey: key)
                muxLock.unlock()
                session.attachFailed()
                completion(nil, err ?? Failure.handshake("mux dial failed"))
            }
        }
    }

    private static func waitMuxReady(_ session: NCMuxSession, key: String, queue: DispatchQueue, attempts: Int,
                                     completion: @escaping (NCMuxSession?, Error?) -> Void) {
        switch session.state {
        case .ready:
            completion(session, nil)
        case .failed:
            muxLock.lock()
            if muxRegistry[key] === session { muxRegistry.removeValue(forKey: key) }
            muxLock.unlock()
            completion(nil, Failure.handshake("mux session failed"))
        case .connecting:
            guard attempts > 0 else {
                completion(nil, Failure.handshake("mux connect timeout"))
                return
            }
            queue.asyncAfter(deadline: .now() + 0.25) {
                waitMuxReady(session, key: key, queue: queue, attempts: attempts - 1, completion: completion)
            }
        }
    }

    // MARK: Hysteria2 (shared QUIC connection per proxy)

    private static var hy2Registry: [String: NCHysteria2Connection] = [:]
    private static let hy2Lock = NSLock()

    static func sharedHysteria2(proxy: NCProxy, server: String, port: Int, queue: DispatchQueue,
                                completion: @escaping (NCHysteria2Connection?, Error?) -> Void) {
        let key = "\(proxy.name)|\(server)|\(port)"
        hy2Lock.lock()
        if let existing = hy2Registry[key] {
            hy2Lock.unlock()
            waitHy2Ready(existing, queue: queue, attempts: 60, completion: completion)
            return
        }
        guard let conn = NCHysteria2Connection(proxy: proxy, queue: queue) else {
            hy2Lock.unlock()
            queue.async { completion(nil, Failure.handshake("hysteria2 bad config")) }
            return
        }
        hy2Registry[key] = conn
        hy2Lock.unlock()
        conn.start { err in
            if err == nil {
                completion(conn, nil)
            } else {
                hy2Lock.lock()
                hy2Registry.removeValue(forKey: key)
                hy2Lock.unlock()
                completion(nil, err)
            }
        }
    }

    private static func waitHy2Ready(_ conn: NCHysteria2Connection, queue: DispatchQueue, attempts: Int,
                                     completion: @escaping (NCHysteria2Connection?, Error?) -> Void) {
        switch conn.state {
        case .ready:
            completion(conn, nil)
        case .failed, .closed:
            completion(nil, Failure.handshake("hysteria2 connection failed"))
        default:
            guard attempts > 0 else {
                completion(nil, Failure.handshake("hysteria2 connect timeout"))
                return
            }
            queue.asyncAfter(deadline: .now() + 0.25) {
                waitHy2Ready(conn, queue: queue, attempts: attempts - 1, completion: completion)
            }
        }
    }

    // MARK: VMess (AEAD, alterId 0)

    private static func connectVMess(target: NCTarget, proxy: NCProxy, server: String, port: Int,
                                     queue: DispatchQueue,
                                     completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let alterID = proxy.fields["alterId"]?.int ?? 0
        guard alterID == 0 else {
            queue.async { completion(nil, Failure.unsupported("vmess legacy alterId \(alterID)")) }
            return
        }
        let network = proxy.fields["network"]?.string ?? "tcp"
        guard ["tcp", "ws", "grpc", "h2", "http"].contains(network) else {
            queue.async { completion(nil, Failure.unsupported("vmess network \(network)")) }
            return
        }
        guard let uuidString = proxy.uuid,
              let uuidBytes = NCVLESS.uuidBytes(uuidString).map({ Data($0) }) ?? Optional(NCSHA1.uuidV5NilNamespace(uuidString)) else {
            queue.async { completion(nil, Failure.handshake("vmess missing uuid")) }
            return
        }
        let security: UInt8
        switch (proxy.fields["cipher"]?.string ?? "auto").lowercased() {
        case "auto", "aes-128-gcm": security = NCVMess.securityAESGCM
        case "chacha20-poly1305": security = NCVMess.securityChaCha
        case "none": security = NCVMess.securityNone
        default:
            queue.async { completion(nil, Failure.unsupported("vmess cipher \(proxy.fields["cipher"]?.string ?? "?")")) }
            return
        }
        if realityParams(proxy) != nil {
            dialReality(proxy: proxy, server: server, port: port, queue: queue) { base0, err in
                guard let base0 else { completion(nil, err); return }
                transportStream(raw: base0, proxy: proxy, server: server) { base, terr in
                    guard let base else { completion(nil, terr); return }
                    finishVMess(base: base, target: target, uuidBytes: uuidBytes, security: security, completion: completion)
                }
            }
            return
        }
        let raw: NCStream
        if proxy.fields["tls"]?.bool ?? false {
            raw = NCStream(to: server, port: port,
                           tlsServerName: proxy.fields["servername"]?.string ?? proxy.fields["sni"]?.string ?? server,
                           allowInsecure: proxy.fields["skip-cert-verify"]?.bool ?? false,
                           queue: queue)
        } else {
            raw = NCStream(to: server, port: port, queue: queue)
        }
        raw.start { err in
            guard err == nil else { completion(nil, err); return }
            transportStream(raw: raw, proxy: proxy, server: server) { base, terr in
                guard let base else { completion(nil, terr); return }
                finishVMess(base: base, target: target, uuidBytes: uuidBytes, security: security, completion: completion)
            }
        }
    }

    private static func finishVMess(base: NCRelayStream, target: NCTarget, uuidBytes: Data, security: UInt8,
                                    completion: @escaping (NCRelayStream?, Error?) -> Void) {
        do {
            let reqKey = randomData(16)
            let reqNonce = randomData(16)
            let respV = randomData(1)[0]
            let option: UInt8 = security == NCVMess.securityNone ? 0
                : NCVMess.optionChunkStream | NCVMess.optionChunkMasking
            let paddingCount = Int(randomData(1)[0]) % 16
            let plain = NCVMess.plainHeader(reqNonce: reqNonce, reqKey: reqKey, respV: respV,
                                            option: option, security: security,
                                            padding: randomData(paddingCount), target: target)
            let sealed = NCVMess.sealHeader(cmdKey: NCVMess.cmdKey(uuidBytes: uuidBytes),
                                            plainHeader: plain,
                                            time: Int64(Date().timeIntervalSince1970),
                                            authRandom4: randomData(4), connNonce: randomData(8))
            completion(NCVMessRelayStream(raw: base, sealedHeader: sealed,
                                          reqKey: reqKey, reqNonce: reqNonce,
                                          respV: respV, security: security), nil)
        }
    }

    static func randomData(_ count: Int) -> Data {
        var rng = SystemRandomNumberGenerator()
        var out = Data()
        out.reserveCapacity(count)
        for _ in 0..<count { out.append(UInt8.random(in: 0...255, using: &rng)) }
        return out
    }

    // MARK: SOCKS5 handshake

    private static func socksHandshake(raw: NCStream, target: NCTarget, proxy: NCProxy,
                                       completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let username = proxy.fields["username"]?.string
        let password = proxy.fields["password"]?.string
        let buf = NCByteBuffer()
        raw.send(NCSOCKS5.greeting(username: username, password: password))
        receiveInto(raw: raw, buf: buf, atLeast: 2) { error in
            guard error == nil, buf.count >= 2 else { completion(nil, error ?? Failure.handshake("socks greeting")); return }
            let head = buf.take(2)
            guard head[0] == 0x05 else { completion(nil, Failure.handshake("socks bad version")); return }
            switch head[1] {
            case 0x00:
                socksRequest(raw: raw, target: target, buf: buf, completion: completion)
            case 0x02:
                guard let u = username else { completion(nil, Failure.handshake("socks auth required")); return }
                raw.send(NCSOCKS5.authRequest(username: u, password: password ?? ""))
                receiveInto(raw: raw, buf: buf, atLeast: 2) { error in
                    guard error == nil, buf.count >= 2 else { completion(nil, error ?? Failure.handshake("socks auth")); return }
                    let authResp = buf.take(2)
                    guard authResp[1] == 0x00 else { completion(nil, Failure.handshake("socks auth failed")); return }
                    socksRequest(raw: raw, target: target, buf: buf, completion: completion)
                }
            default:
                completion(nil, Failure.handshake("socks method \(head[1])"))
            }
        }
    }

    private static func socksRequest(raw: NCStream, target: NCTarget, buf: NCByteBuffer,
                                     completion: @escaping (NCRelayStream?, Error?) -> Void) {
        raw.send(NCSOCKS5.connectRequest(target: target))
        func step() {
            if let (need, rep) = NCSOCKS5.parseResponse(buf.data) {
                _ = buf.take(need)
                guard rep == 0 else { completion(nil, Failure.handshake("socks reply \(rep)")); return }
                // Any buffered remainder is early payload: replay it to the first receiver.
                completion(NCBufferedStream(inner: raw, prefix: buf.data), nil)
                return
            }
            raw.receive { data, error in
                guard let data else { completion(nil, error ?? Failure.handshake("socks eof")); return }
                buf.append(data)
                step()
            }
        }
        step()
    }

    // MARK: HTTP CONNECT handshake

    private static func httpHandshake(raw: NCStream, target: NCTarget, proxy: NCProxy,
                                      completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let username = proxy.fields["username"]?.string
        let password = proxy.fields["password"]?.string
        raw.send(NCHTTPProxy.connectRequest(target: target, username: username, password: password))
        let buf = NCByteBuffer()
        func step() {
            if let range = buf.data.range(of: Data("\r\n\r\n".utf8)) {
                let head = String(decoding: buf.data[buf.data.startIndex..<range.upperBound], as: UTF8.self)
                _ = buf.take(range.upperBound - buf.data.startIndex)
                guard head.contains(" 200") else { completion(nil, Failure.handshake("http connect: \(head.components(separatedBy: "\r\n").first ?? "?")")); return }
                completion(NCBufferedStream(inner: raw, prefix: buf.data), nil)
                return
            }
            raw.receive { data, error in
                guard let data else { completion(nil, error ?? Failure.handshake("http eof")); return }
                buf.append(data)
                if buf.count > 16384 { completion(nil, Failure.handshake("http header too large")); return }
                step()
            }
        }
        step()
    }

    /// Accumulate into `buf` until it holds at least `n` bytes (or EOF/error).
    private static func receiveInto(raw: NCStream, buf: NCByteBuffer, atLeast n: Int,
                                    done: @escaping (Error?) -> Void) {
        if buf.count >= n { done(nil); return }
        raw.receive { data, error in
            guard let data else { done(error ?? Failure.handshake("eof")); return }
            buf.append(data)
            receiveInto(raw: raw, buf: buf, atLeast: n, done: done)
        }
    }
}

/// Wraps a stream whose first inbound bytes were already read during the
/// handshake: they are delivered before any fresh receive.
final class NCBufferedStream: NCRelayStream {
    private let inner: NCStream
    private var prefix: Data

    init(inner: NCStream, prefix: Data) {
        self.inner = inner
        self.prefix = prefix
    }

    func send(_ data: Data) { inner.send(data) }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        if !prefix.isEmpty {
            let out = prefix
            prefix = Data()
            handler(out, nil)
            return
        }
        inner.receive(handler)
    }

    func cancel() { inner.cancel() }
}


/// VMess relay: sends the sealed header first, then chunk-encoded body frames;
/// inbound, the AEAD response header is consumed before body chunks decode.
final class NCVMessRelayStream: NCRelayStream {
    private let raw: NCRelayStream
    private let encoder: NCVMessChunkEncoder?
    private let respReader: NCVMessResponseReader
    private let respKeys: (key: Data, nonce: Data)
    private let security: UInt8
    private var decoder: NCVMessChunkDecoder?
    private var responseStarted = false

    init(raw: NCRelayStream, sealedHeader: Data, reqKey: Data, reqNonce: Data, respV: UInt8, security: UInt8) {
        self.raw = raw
        self.security = security
        self.encoder = security == NCVMess.securityNone ? nil
            : NCVMessChunkEncoder(bodyKey: reqKey, nonceBase: reqNonce, security: security)
        self.respKeys = NCVMess.responseKeys(reqKey: reqKey, reqNonce: reqNonce)
        self.respReader = NCVMessResponseReader(respKey: respKeys.key, respNonce: respKeys.nonce, expectedV: respV)
        raw.send(sealedHeader)
    }

    func send(_ data: Data) {
        if let encoder {
            raw.send(encoder.encode(data))
        } else {
            raw.send(data) // security none over TCP is a plain stream
        }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        raw.receive { [weak self] data, error in
            guard let self else { handler(nil, error); return }
            guard let data else { handler(nil, error); return }
            if !responseStarted {
                respReader.feed(data)
                switch respReader.state {
                case .failed:
                    handler(nil, NCConnector.Failure.handshake("vmess response header"))
                    return
                case .reading:
                    receive(handler)
                    return
                case .done:
                    responseStarted = true
                    if security != NCVMess.securityNone {
                        decoder = NCVMessChunkDecoder(bodyKey: respKeys.key, nonceBase: respKeys.nonce, security: security)
                    }
                    let rest = respReader.bodyRemainder
                    if rest.isEmpty {
                        receive(handler)
                    } else {
                        deliver(rest, handler)
                    }
                    return
                }
            }
            deliver(data, handler)
        }
    }

    private func deliver(_ data: Data, _ handler: @escaping (Data?, Error?) -> Void) {
        guard let decoder else {
            handler(data, nil) // security none: plaintext body
            return
        }
        guard let plain = decoder.feed(data) else {
            handler(nil, NCConnector.Failure.handshake("vmess body decode"))
            return
        }
        if plain.isEmpty && !decoder.finished {
            receive(handler)
            return
        }
        handler(plain, nil)
    }

    func cancel() { raw.cancel() }
}
