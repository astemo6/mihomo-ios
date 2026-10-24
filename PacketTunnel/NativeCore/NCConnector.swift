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
                                        completion: @escaping (NCRelayStream?, Error?) -> Void) {
        guard let server = proxy.server, let port = proxy.port else {
            queue.async { completion(nil, Failure.handshake("proxy \(proxy.name) missing server/port")) }
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
            guard let cipher = proxy.cipher, let password = proxy.password,
                  let enc = NCSSEncoder(cipher: cipher, password: password),
                  let dec = NCSSDecoder(cipher: cipher, password: password) else {
                queue.async { completion(nil, Failure.handshake("bad shadowsocks cipher/password")) }
                return
            }
            let raw = NCStream(to: server, port: port, queue: queue)
            raw.start { err in
                guard err == nil else { completion(nil, err); return }
                completion(NCSSRelayStream(raw: raw, encoder: enc, decoder: dec, target: target), nil)
            }
        case "trojan":
            guard let password = proxy.password else {
                queue.async { completion(nil, Failure.handshake("trojan missing password")) }
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
            let useTLS = proxy.fields["tls"]?.bool ?? false
            let raw: NCStream
            if useTLS {
                raw = NCStream(to: server, port: port,
                               tlsServerName: proxy.fields["servername"]?.string ?? proxy.fields["sni"]?.string ?? server,
                               allowInsecure: proxy.fields["skip-cert-verify"]?.bool ?? false,
                               queue: queue)
            } else {
                raw = NCStream(to: server, port: port, queue: queue)
            }
            raw.start { err in
                guard err == nil else { completion(nil, err); return }
                guard let head = NCVLESS.requestHead(uuid: uuid, target: target,
                                                     flow: proxy.fields["flow"]?.string ?? "") else {
                    completion(nil, Failure.handshake("vless bad uuid"))
                    return
                }
                transportStream(raw: raw, proxy: proxy, server: server) { base, terr in
                    guard let base else { completion(nil, terr); return }
                    base.send(head)
                    completion(NCVLESSRelayStream(raw: base), nil)
                }
            }
        case "vmess":
            connectVMess(target: target, proxy: proxy, server: server, port: port, queue: queue, completion: completion)
        default:
            queue.async { completion(nil, Failure.unsupported(proxy.type)) }
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

    /// If the proxy uses the ws transport, wrap the connected raw stream and
    /// run the upgrade; otherwise pass the raw stream through.
    static func transportStream(raw: NCStream, proxy: NCProxy, server: String,
                                completion: @escaping (NCRelayStream?, Error?) -> Void) {
        guard (proxy.fields["network"]?.string ?? "tcp") == "ws" else {
            completion(raw, nil)
            return
        }
        let (path, headers) = wsOptions(proxy)
        let host = proxy.fields["ws-opts"]?.object?["headers"]?.object?["Host"]?.string ?? server
        let ws = NCWebSocketStream(raw: raw, hostHeader: host, path: path, headers: headers)
        ws.startHandshake { err in
            completion(err == nil ? ws : nil, err)
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
        guard network == "tcp" || network == "ws" else {
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
