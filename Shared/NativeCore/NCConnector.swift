import Foundation
import Network

/// A ready-to-relay stream: plaintext in, plaintext out. For Shadowsocks the
/// transform happens inside; callers never see wire bytes.
protocol NCRelayStream: AnyObject {
    func send(_ data: Data)
    /// nc-sessions-flow: send with a completion that fires exactly once, when this chunk has been handed
    /// on (encoded and accepted by the layer below / the peer's window) — the uplink back-pressure signal
    /// the relay pumps wait on before reading more. Must fire on every path: success, failure, cancel,
    /// teardown; never twice (wrap it in NCCallOnce).
    func send(_ data: Data, completion: @escaping () -> Void)
    func receive(_ handler: @escaping (Data?, Error?) -> Void)
    func cancel()
}

/// Exactly-once wrapper for relay send completions: a second call is a programming error (asserted in
/// DEBUG) and is ignored in release, so a buggy path can stall a pump but never double-fire it.
final class NCCallOnce {
    private let lock = NSLock()
    private var fired = false
    private let body: () -> Void
    init(_ body: @escaping () -> Void) { self.body = body }
    func call() {
        lock.lock()
        if fired {
            lock.unlock()
            assertionFailure("NCCallOnce fired twice")
            return
        }
        fired = true
        lock.unlock()
        body()
    }
}

// No default send(_:completion:) implementation on purpose (nc-sessions-flow): every NCRelayStream
// conformer implements real send completion, so the compiler flags any stream that was missed.
extension NCRelayStream {

    /// Fire-and-forget send for call sites that don't pump (handshake heads, control frames): the wrappers only
    /// implement send(_:completion:), so the plain form forwards to it.
    func send(_ data: Data) { send(data, completion: {}) }

    /// Sends wire segments in order, firing `completion` after the last segment's own completion
    /// (earlier segments get none). For encoders that turn one chunk into several records.
    func ncSendSequentially(_ wires: [Data], completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        let wires = wires.filter { !$0.isEmpty }
        guard let first = wires.first else { once.call(); return }
        if wires.count == 1 { send(first, completion: once.call); return }
        // Strong self capture is deliberate: the chain must not lose the completion if the caller
        // drops the stream mid-send; it ends when the last segment completes.
        send(first) { self.ncSendSequentially(Array(wires.dropFirst()), completion: once.call) }
    }
}

extension NCStream: NCRelayStream {}

/// Shadowsocks relay: encodes on send (target address is the first plaintext
/// chunk, sent at connect time), decodes on receive, swallowing chunks that
/// carry only salt/framing (receive again until real plaintext or EOF).
final class NCSSRelayStream: NCRelayStream {
    private let raw: NCRelayStream
    private let encoder: NCSSEncoder
    private let decoder: NCSSDecoder

    init(raw: NCRelayStream, encoder: NCSSEncoder, decoder: NCSSDecoder, target: NCTarget) {
        self.raw = raw
        self.encoder = encoder
        self.decoder = decoder
        if let head = encoder.encode(target.atypEncoded) {
            raw.send(head)
        }
    }

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        guard !data.isEmpty else { once.call(); return }
        if let wire = encoder.encode(data) { raw.send(wire, completion: once.call) }
        else { raw.cancel(); once.call() }
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
    private let raw: NCRelayStream
    private let encoder: NCSS2022Encoder
    private let decoder: NCSS2022Decoder

    init(raw: NCRelayStream, encoder: NCSS2022Encoder, decoder: NCSS2022Decoder, target: NCTarget) {
        self.raw = raw
        self.encoder = encoder
        self.decoder = decoder
        if let head = encoder.requestHead(target: target,
                                          timestamp: UInt64(Date().timeIntervalSince1970)) {
            raw.send(head)
        }
    }

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        guard !data.isEmpty else { once.call(); return }
        if let wire = encoder.encode(data) { raw.send(wire, completion: once.call) }
        else { raw.cancel(); once.call() }
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
    private let raw: NCRelayStream
    private let encoder: NCSnellStreamEncoder
    private let decoder: NCSnellStreamDecoder
    private let stripper = NCSnellReplyStripper()

    init(raw: NCRelayStream, psk: Data, version: Int, target: NCTarget) {
        self.raw = raw
        encoder = NCSnellStreamEncoder(psk: psk, version: version)
        decoder = NCSnellStreamDecoder(psk: psk, version: version)
        if let wire = encoder.encode(NCSnell.connectHeader(host: target.host, port: target.port, version: version)) {
            raw.send(wire)
        }
    }

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        guard !data.isEmpty else { once.call(); return }
        if let wire = encoder.encode(data) { raw.send(wire, completion: once.call) }
        else { raw.cancel(); once.call() }
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
    private let raw: NCRelayStream
    private let writer: NCSnellV4Writer
    private let reader: NCSnellV4Reader
    private let stripper = NCSnellReplyStripper()

    init(raw: NCRelayStream, psk: Data, target: NCTarget) {
        self.raw = raw
        writer = NCSnellV4Writer(psk: psk)
        reader = NCSnellV4Reader(psk: psk)
        if let wire = writer.write(NCSnell.connectHeader(host: target.host, port: target.port, version: 4)) {
            raw.send(wire)
        }
    }

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        guard !data.isEmpty else { once.call(); return }
        if let wire = writer.write(data) { raw.send(wire, completion: once.call) }
        else { raw.cancel(); once.call() }
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

    /// Opens a relay stream to `target` through `proxy`.
    /// Completion fires on `queue` exactly once.
    static func connect(target: NCTarget,
                        proxy: NCProxy,
                        queue: DispatchQueue,
                        completion: @escaping (NCRelayStream?, Error?) -> Void) {
        connectViaProxy(target: target, proxy: proxy, queue: queue, completion: completion)
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
        case .chain(let proxies):
            connectChain(target: target, proxies: proxies, queue: queue, completion: completion)
        }
    }

    /// Fold a proxy chain: hop i handshakes over hop i-1's relay toward
    /// hop i+1's server; the last hop aims at the real target.
    private static func connectChain(target: NCTarget, proxies: [NCProxy], queue: DispatchQueue,
                                     completion: @escaping (NCRelayStream?, Error?) -> Void) {
        func step(_ index: Int, _ transport: NCRelayStream?) {
            let proxy = proxies[index]
            let isLast = index == proxies.count - 1
            guard isLast || (proxies[index + 1].server != nil && proxies[index + 1].port != nil) else {
                queue.async { completion(nil, Failure.handshake("chain member missing server/port")) }
                return
            }
            let hopTarget = isLast ? target
                : NCTarget(host: proxies[index + 1].server!, port: proxies[index + 1].port!)
            connectViaProxy(target: hopTarget, proxy: proxy, queue: queue,
                            allowMux: false, transport: transport) { relay, err in
                guard let relay else { completion(nil, err); return }
                if isLast { completion(relay, nil) } else { step(index + 1, relay) }
            }
        }
        step(0, nil)
    }

    /// The byte pipe for one hop: a provided chain transport when present,
    /// otherwise a freshly dialed direct stream.
    private static func obtainStream(transport: NCRelayStream?, make: () -> NCStream,
                                     completion: @escaping (NCRelayStream?, Error?) -> Void) {
        if let transport {
            completion(transport, nil)
            return
        }
        let raw = make()
        raw.start { err in completion(err == nil ? raw : nil, err) }
    }

    /// WireGuard dials through the tunnel's userspace lwIP stack (PacketTunnel/NativeCore/NCWireGuard.swift + nc_wg.c),
    /// which only the PacketTunnel target builds. The tunnel installs its dialer at start
    /// (NCConnector.installWireGuardDialer()); without it (the App's 延迟测试) a WireGuard node reports unsupported.
    /// Set once before the first dial, read-only afterwards.
    static var wireguardDialer: ((NCProxy, NCTarget, DispatchQueue, @escaping (NCRelayStream?, Error?) -> Void) -> Void)?

    /// Tailscale dials through the tunnel's userspace lwIP stack and DERP relays.
    /// Set once before the first dial via NCConnector.installTailscaleDialer().
    static var tailscaleDialer: ((NCProxy, NCTarget, DispatchQueue, @escaping (NCRelayStream?, Error?) -> Void) -> Void)?

    private static func connectViaProxy(target: NCTarget, proxy: NCProxy, queue: DispatchQueue,
                                        allowMux: Bool = true,
                                        transport: NCRelayStream? = nil,
                                        completion: @escaping (NCRelayStream?, Error?) -> Void) {
        // rv2-proto: a target no wire format can carry (domain > 255 bytes, port out of range) fails cleanly here
        // instead of trapping in a u8/u16 length conversion inside a protocol encoder.
        guard target.isWireEncodable else {
            queue.async { completion(nil, Failure.handshake("target \(target.host.prefix(64)):\(target.port) cannot be encoded")) }
            return
        }
        if proxy.type == "mieru" {
            // feat/nc-proto3: pure-Swift mieru TCP underlay (NCMieru); port may come from port-range.
            mieruStream(proxy: proxy, target: target, udp: false, queue: queue, transport: transport) { s, err in
                completion(s, err)
            }
            return
        }
        // feat/nc-wg: WireGuard (several peers may carry their own server/port, so before the guard below).
        if proxy.type == "wireguard" {
            if transport != nil {
                queue.async { completion(nil, Failure.unsupported("wireguard over a chain transport")) }
                return
            }
            guard let dial = wireguardDialer else {
                queue.async { completion(nil, Failure.unsupported("wireguard: only inside the tunnel (userspace lwIP stack)")) }
                return
            }
            dial(proxy, target, queue, completion)
            return
        }
        // feat/nc-ts: Tailscale (overlay routing via userspace lwIP and DERP relays).
        if proxy.type == "tailscale" {
            if transport != nil {
                queue.async { completion(nil, Failure.unsupported("tailscale over a chain transport")) }
                return
            }
            guard let dial = tailscaleDialer else {
                queue.async { completion(nil, Failure.unsupported("tailscale: only inside the tunnel (userspace lwIP stack)")) }
                return
            }
            dial(proxy, target, queue, completion)
            return
        }
        // Hysteria v1 may give only `ports` (port hopping, feat/nc-proto2): the first one stands in for `port`.
        let hy1Port = proxy.type == "hysteria" ? NCHy1Obfs.parsePorts(proxy.fields["ports"]?.string)?.first.map(Int.init) : nil
        guard let server = proxy.server, let port = proxy.port ?? hy1Port else {
            queue.async { completion(nil, Failure.handshake("proxy \(proxy.name) missing server/port")) }
            return
        }
        // sing-mux (h2mux) interception: vmess/vless flows ride a shared
        // session whose own proxy connection targets the mux destination.
        if allowMux, transport == nil, proxy.type == "vmess" || proxy.type == "vless",
           smuxEnabled(proxy), target != NCMux.destination {
            guard smuxProtocol(proxy) == "h2mux" else {
                queue.async { completion(nil, Failure.unsupported("smux protocol \(smuxProtocol(proxy)) (h2mux only)")) }
                return
            }
            muxSession(proxy: proxy, server: server, port: port, queue: queue) { session, err in
                guard let session else { completion(nil, err); return }
                completion(session.openStream(target: target, callerQueue: queue), nil)
            }
            return
        }
        switch proxy.type {
        case "socks5":
            obtainStream(transport: transport, make: { NCStream(to: server, port: port, queue: queue) }) { raw, err in
                guard let raw else { completion(nil, err); return }
                socksHandshake(raw: raw, target: target, proxy: proxy, queue: queue, completion: completion)
            }
        case "http", "https":
            if transport != nil && proxy.type == "https" {
                queue.async { completion(nil, Failure.unsupported("https proxy over a chain transport")) }
                return
            }
            if proxy.type == "https" && isECHEnabled(proxy) && realityParams(proxy) != nil {
                queue.async { completion(nil, Failure.handshake("REALITY 与 ECH 互斥，不能同时启用")) }
                return
            }
            if proxy.type == "https" && needsNativeTLS(proxy) {
                dialNativeTLS(proxy: proxy, server: server, port: port, defaultALPN: ["http/1.1"], queue: queue) { raw, err in
                    guard let raw else { completion(nil, err); return }
                    httpHandshake(raw: raw, target: target, proxy: proxy, queue: queue, completion: completion)
                }
                return
            }
            obtainStream(transport: transport, make: { NCStream(to: server, port: port, tls: proxy.type == "https", queue: queue) }) { raw, err in
                guard let raw else { completion(nil, err); return }
                httpHandshake(raw: raw, target: target, proxy: proxy, queue: queue, completion: completion)
            }
        case "ss":
            if isECHEnabled(proxy) {
                queue.async { completion(nil, Failure.unsupported("Shadowsocks 插件不支持 ECH")) }
                return
            }
            guard let cipher = proxy.cipher, let password = proxy.password else {
                queue.async { completion(nil, Failure.handshake("bad shadowsocks cipher/password")) }
                return
            }
            // SS stream plugins wrap the whole SS stream — request head included — and apply to TCP only
            // (mihomo StreamConnContext parity; UDP sessions never see a plugin). One implementation:
            // NCConnector.ssPluginStream (simple-obfs / v2ray-plugin = #101 NCSSPluginStream; gost-plugin /
            // shadow-tls / restls = nc-proto).
            if NCSS2022.isMethod2022(cipher) {
                guard let enc = NCSS2022Encoder(method: cipher, password: password),
                      let dec = NCSS2022Decoder(method: cipher, password: password,
                                                requestSalt: enc.salt) else {
                    queue.async { completion(nil, Failure.handshake("bad shadowsocks 2022 password")) }
                    return
                }
                ssPluginStream(proxy: proxy, server: server, port: port, queue: queue, transport: transport) { raw, err in
                    guard let raw else { completion(nil, err); return }
                    completion(NCSS2022RelayStream(raw: raw, encoder: enc, decoder: dec, target: target), nil)
                }
                return
            }
            guard let enc = NCSSEncoder(cipher: cipher, password: password),
                  let dec = NCSSDecoder(cipher: cipher, password: password) else {
                queue.async { completion(nil, Failure.handshake("bad shadowsocks cipher/password")) }
                return
            }
            ssPluginStream(proxy: proxy, server: server, port: port, queue: queue, transport: transport) { raw, err in
                guard let raw else { completion(nil, err); return }
                completion(NCSSRelayStream(raw: raw, encoder: enc, decoder: dec, target: target), nil)
            }
        case "ssr":
            // feat/nc-proto A5: every protocol / obfs mihomo registers (NCSSRProtocols); cipher none = dummy.
            guard let password = proxy.password, let cipher0 = proxy.cipher?.lowercased(),
                  NCSupport.ssrUnsupported(proxy) == nil else {
                queue.async { completion(nil, Failure.unsupported(NCSupport.ssrUnsupported(proxy) ?? "ssr missing password/cipher")) }
                return
            }
            let dummy = cipher0 == "none" || cipher0 == "dummy"
            let protoName = (proxy.fields["protocol"]?.string ?? "origin").lowercased()
            let obfsName = (proxy.fields["obfs"]?.string ?? "plain").lowercased()
            let key = NCShadowsocks.masterKey(password: password,
                                              keyLen: dummy ? 16 : NCSSStreamCipher.keyLength(for: cipher0))
            let ivSize = dummy ? 0 : (NCSSStreamCipher(method: cipher0, key: key)?.ivSize ?? 16)
            let clientIV = ivSize > 0 ? randomData(ivSize) : Data()
            let obfsParam = proxy.fields["obfs-param"]?.string
            var obfs: NCSSRObfsCodec?
            var obfsOverhead = 0
            switch obfsName {
            case "http_simple", "http_post":
                obfs = NCSSRHTTPObfs(post: obfsName == "http_post", host: server, port: port, ivSize: ivSize, param: obfsParam)
            case "random_head":
                obfs = NCSSRRandomHead()
            case "tls1.2_ticket_auth", "tls1.2_ticket_fastauth":
                obfs = NCSSRTLSTicketAuth(key: key, clientID: ssrTicketClientID(proxy: proxy), server: server, param: obfsParam)
                obfsOverhead = 5
            default:
                break
            }
            var proto: NCSSRProtocolCodec?
            switch protoName {
            case "auth_sha1_v4":
                proto = NCSSRAuthSHA1V4(key: key, iv: clientIV, auth: ssrAuthState(for: proxy.name).next())
            case "auth_aes128_md5", "auth_aes128_sha1":
                let sha1 = protoName == "auth_aes128_sha1"
                proto = NCSSRAuthAES128(sha1: sha1, key: key, iv: clientIV, overhead: obfsOverhead + 9,
                                        user: ssrUserData(proxy: proxy, key: key, sha1: sha1),
                                        auth: ssrAuthState(for: proxy.name).next())
            case "auth_chain_a", "auth_chain_b":
                proto = NCSSRAuthChain(variantB: protoName == "auth_chain_b", key: key, iv: clientIV,
                                       overhead: obfsOverhead + 4,
                                       user: ssrUserData(proxy: proxy, key: key, sha1: nil),
                                       auth: ssrAuthState(for: proxy.name).next())
            default:
                break
            }
            obtainStream(transport: transport, make: { NCStream(to: server, port: port, queue: queue) }) { raw, err in
                guard let raw else { completion(nil, err); return }
                completion(NCSSRCodecRelayStream(raw: raw, method: dummy ? nil : cipher0, key: key, clientIV: clientIV,
                                                 proto: proto, obfs: obfs, target: target), nil)
            }
        case "snell":
            guard let password = proxy.password else {
                queue.async { completion(nil, Failure.handshake("snell missing psk")) }
                return
            }
            let version = proxy.fields["version"]?.int ?? 1
            let psk = Data(password.utf8)
            obtainStream(transport: transport, make: { NCStream(to: server, port: port, queue: queue) }) { raw, err in
                guard let raw else { completion(nil, err); return }
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
            if transport != nil {
                queue.async { completion(nil, Failure.unsupported("trojan over a chain transport (TLS termination needs its own socket)")) }
                return
            }
            if isECHEnabled(proxy) && realityParams(proxy) != nil {
                queue.async { completion(nil, Failure.handshake("REALITY 与 ECH 互斥，不能同时启用")) }
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
            let trojanSNI = proxy.fields["sni"]?.string ?? server
            if needsNativeTLS(proxy) {
                dialNativeTLS(proxy: proxy, server: server, port: port, serverName: trojanSNI, queue: queue) { base, err in
                    guard let base else { completion(nil, err); return }
                    base.send(NCTrojan.requestHead(password: password, target: target))
                    completion(base, nil)
                }
                return
            }
            let raw = NCStream(to: server, port: port,
                               tlsServerName: trojanSNI,
                               allowInsecure: proxy.fields["skip-cert-verify"]?.bool ?? false,
                               queue: queue)
            raw.start { err in
                guard err == nil else { completion(nil, err); return }
                raw.send(NCTrojan.requestHead(password: password, target: target))
                completion(raw, nil)
            }
        case "vless":
            // feat/nc-proto3: encryption + xtls-rprx-vision — Vision frames ride the encryption conn and splice
            // below it (mihomo vision.NewConn over *encryption.CommonConn), whatever TLS / REALITY sits underneath.
            let isVision = visionFlow(proxy)
            let encVision = vlessEncryption(proxy) != nil && isVision
            guard let uuid = proxy.uuid else {
                queue.async { completion(nil, Failure.handshake("vless missing uuid")) }
                return
            }
            if transport != nil && realityParams(proxy) != nil {
                queue.async { completion(nil, Failure.unsupported("vless reality over a chain transport")) }
                return
            }
            if isECHEnabled(proxy) && realityParams(proxy) != nil {
                queue.async { completion(nil, Failure.handshake("REALITY 与 ECH 互斥，不能同时启用")) }
                return
            }
            if (isVision || encVision) && isECHEnabled(proxy) {
                queue.async { completion(nil, Failure.unsupported("VLESS Vision 不支持 ECH")) }
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
                    if encVision {
                        vlessEncryptedVision(base0, proxy: proxy, uuid: uuid, head: head, queue: queue, completion: completion)
                        return
                    }
                    if visionFlow(proxy), let tlsClient = base0 as? NCTLSClientStream,
                       let uuidBytes = NCVLESS.uuidBytes(uuid) {
                        let vision = NCVisionStream(tls: tlsClient, uuid: uuidBytes)
                        vision.send(head)
                        completion(NCVLESSRelayStream(raw: vision), nil)
                        return
                    }
                    transportStream(raw: base0, proxy: proxy, server: server, queue: queue) { base, terr in
                        guard let tbase = base else { completion(nil, terr); return }
                        vlessEncrypt(tbase, proxy: proxy, queue: queue) { base, eerr in
                            guard let base else { completion(nil, eerr); return }
                            base.send(head)
                            completion(NCVLESSRelayStream(raw: base), nil)
                        }
                    }
                }
                return
            }
            let useTLS = proxy.fields["tls"]?.bool ?? false
            let isVision = visionFlow(proxy)
            if let transport {
                // Over a chain pipe only the plaintext transports work:
                // TLS termination and Vision need their own socket.
                guard !useTLS, !isVision, realityParams(proxy) == nil,
                      let head = NCVLESS.requestHead(uuid: uuid, target: target,
                                                     flow: proxy.fields["flow"]?.string ?? "") else {
                    queue.async { completion(nil, Failure.unsupported("vless tls/vision/reality over a chain transport")) }
                    return
                }
                transportStream(raw: transport, proxy: proxy, server: server, queue: queue) { base, terr in
                    guard let tbase = base else { completion(nil, terr); return }
                    vlessEncrypt(tbase, proxy: proxy, queue: queue) { base, eerr in
                        guard let base else { completion(nil, eerr); return }
                        base.send(head)
                        completion(NCVLESSRelayStream(raw: base), nil)
                    }
                }
                return
            }
            if useTLS, !isVision, !encVision, needsNativeTLS(proxy) {
                guard let head = NCVLESS.requestHead(uuid: uuid, target: target,
                                                     flow: proxy.fields["flow"]?.string ?? "") else {
                    queue.async { completion(nil, Failure.handshake("vless bad uuid")) }
                    return
                }
                dialNativeTLS(proxy: proxy, server: server, port: port, queue: queue) { base0, err in
                    guard let base0 else { completion(nil, err); return }
                    transportStream(raw: base0, proxy: proxy, server: server, queue: queue) { base, terr in
                        guard let tbase = base else { completion(nil, terr); return }
                        vlessEncrypt(tbase, proxy: proxy, queue: queue) { base, eerr in
                            guard let base else { completion(nil, eerr); return }
                            base.send(head)
                            completion(NCVLESSRelayStream(raw: base), nil)
                        }
                    }
                }
                return
            }
            let raw: NCStream
            if useTLS && (!isVision || encVision) {
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
                if encVision {
                    vlessEncryptedVision(raw, proxy: proxy, uuid: uuid, head: head, queue: queue, completion: completion)
                    return
                }
                if isVision, useTLS, let uuidBytes = NCVLESS.uuidBytes(uuid) {
                    let tls = NCTLSClientStream(raw: raw, config: .init(
                        serverName: proxy.fields["servername"]?.string ?? proxy.fields["sni"]?.string ?? server,
                        allowInsecure: proxy.fields["skip-cert-verify"]?.bool ?? false,
                        profile: NCClientHelloProfile.named(proxy.fields["fingerprint"]?.string ?? proxy.fields["client-fingerprint"]?.string)), queue: queue)
                    tls.startHandshake { herr in
                        guard herr == nil else { completion(nil, herr); return }
                        let vision = NCVisionStream(tls: tls, uuid: uuidBytes)
                        vision.send(head)
                        completion(NCVLESSRelayStream(raw: vision), nil)
                    }
                    return
                }
                transportStream(raw: raw, proxy: proxy, server: server, queue: queue) { base, terr in
                    guard let tbase = base else { completion(nil, terr); return }
                    vlessEncrypt(tbase, proxy: proxy, queue: queue) { base, eerr in
                        guard let base else { completion(nil, eerr); return }
                        base.send(head)
                        completion(NCVLESSRelayStream(raw: base), nil)
                    }
                }
            }
        case "hysteria2", "hy2":
            if transport != nil {
                queue.async { completion(nil, Failure.unsupported("hysteria2 over a chain transport")) }
                return
            }
            sharedHysteria2(proxy: proxy, server: server, port: port, queue: queue) { conn, err in
                guard let conn, let stream = conn.openTCP(target: target, callerQueue: queue) else {
                    completion(nil, err ?? Failure.handshake("hysteria2 open stream failed"))
                    return
                }
                completion(stream, nil)
            }
        case "ssh":
            sshStream(proxy: proxy, server: server, port: port, target: target, queue: queue,
                      transport: transport, completion: completion)
        case "hysteria":
            if transport != nil {
                queue.async { completion(nil, Failure.unsupported("hysteria over a chain transport")) }
                return
            }
            hysteria1Stream(proxy: proxy, target: target, queue: queue, completion: completion)
        case "anytls":
            if transport != nil {
                queue.async { completion(nil, Failure.unsupported("anytls over a chain transport")) }
                return
            }
            anytlsSession(proxy: proxy, server: server, port: port, queue: queue) { session, err in
                guard let session else { completion(nil, err); return }
                completion(session.openStream(target: target, callerQueue: queue), nil)
            }
        case "vmess":
            connectVMess(target: target, proxy: proxy, server: server, port: port, queue: queue,
                         transport: transport, completion: completion)
        case "tuic":
            // feat/nc-proto A1: TUIC v5/v4 TCP over Network.framework QUIC (uni-stream auth + TLS exporter).
            if transport != nil {
                queue.async { completion(nil, Failure.unsupported("tuic over a chain transport")) }
                return
            }
            tuicStream(proxy: proxy, target: target, queue: queue, completion: completion)
        default:
            queue.async { completion(nil, Failure.unsupported(proxy.type)) }
        }
    }

    /// VLESS encryption handshake over `base`, then XTLS Vision on top of the encryption conn (feat/nc-proto3).
    static func vlessEncryptedVision(_ base: NCRelayStream, proxy: NCProxy, uuid: String, head: Data,
                                     queue: DispatchQueue, completion: @escaping (NCRelayStream?, Error?) -> Void) {
        guard let inst = vlessEncryption(proxy), let uuidBytes = NCVLESS.uuidBytes(uuid) else {
            completion(nil, Failure.handshake("vless encryption / uuid invalid"))
            return
        }
        let enc = NCVLESSEncStream(raw: base, inst: inst, queue: queue)
        enc.handshake { err in
            if let err { completion(nil, err); return }
            let vision = NCVisionStream(tls: enc, uuid: uuidBytes)
            vision.send(head)
            completion(NCVLESSRelayStream(raw: vision), nil)
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
                reality: reality,
                profile: NCClientHelloProfile.named(proxy.fields["fingerprint"]?.string ?? proxy.fields["client-fingerprint"]?.string)), queue: queue)
            tls.startHandshake { herr in
                completion(herr == nil ? tls : nil, herr)
            }
        }
    }

    // MARK: Native TLS Parity (NCTLSClient) Helpers

    /// Extract ALPN list from proxy fields (array or comma-separated string).
    static func parseALPN(_ proxy: NCProxy) -> [String]? {
        if let arr = proxy.fields["alpn"]?.array?.compactMap({ $0.string }), !arr.isEmpty {
            return arr
        }
        if let str = proxy.fields["alpn"]?.string, !str.trimmingCharacters(in: .whitespaces).isEmpty {
            let list = str.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            return list.isEmpty ? nil : list
        }
        return nil
    }

    /// Extract SHA-256 certificate pinning hash (32 bytes) from proxy fields if present.
    static func parsePinnedCertSHA256(_ proxy: NCProxy) -> Data? {
        let candidateKeys = [
            "pinned-peer-cert-sha256",
            "pinned-peer-certificate-sha256",
            "certificate-sha256",
            "pin-sha256",
            "pinSHA256",
            "hpkp",
            "fingerprint"
        ]
        for key in candidateKeys {
            guard let raw = proxy.fields[key]?.string else { continue }
            let hex = raw.replacingOccurrences(of: ":", with: "").trimmingCharacters(in: .whitespaces)
            if hex.count == 64, let bytes = hexBytes(hex) {
                return bytes
            }
        }
        return nil
    }

    /// Extract client fingerprint profile name from proxy fields if present.
    /// "none" (case-insensitive) and empty strings are treated as having no fingerprint.
    static func parseClientFingerprint(_ proxy: NCProxy) -> String? {
        if let fp = proxy.fields["client-fingerprint"]?.string {
            let trimmed = fp.trimmingCharacters(in: .whitespaces)
            if !trimmed.isEmpty && trimmed.lowercased() != "none" { return trimmed }
        }
        if let fp = proxy.fields["fingerprint"]?.string {
            let trimmed = fp.trimmingCharacters(in: .whitespaces)
            let hex = trimmed.replacingOccurrences(of: ":", with: "")
            if hex.count == 64 && hexBytes(hex) != nil {
                return nil
            }
            if !trimmed.isEmpty && trimmed.lowercased() != "none" { return trimmed }
        }
        return nil
    }

    /// Look up ech-opts dictionary.
    static func echOpts(_ proxy: NCProxy) -> [String: NCJSONValue]? {
        proxy.fields["ech-opts"]?.object ?? proxy.fields["plugin-opts"]?.object?["ech-opts"]?.object
    }

    /// Returns true if ECH is enabled for this proxy.
    static func isECHEnabled(_ proxy: NCProxy) -> Bool {
        echOpts(proxy)?["enable"]?.bool == true
    }

    /// Parse static ECHConfigList bytes from ech-opts.config (Base64), validated via NCECHConfigParser.
    static func parseStaticECHConfigList(_ proxy: NCProxy) throws -> Data? {
        guard isECHEnabled(proxy), let opts = echOpts(proxy) else { return nil }
        guard let cfgVal = opts["config"] else { return nil }
        let b64Strings: [String]
        if let s = cfgVal.string, !s.trimmingCharacters(in: .whitespaces).isEmpty {
            b64Strings = [s.trimmingCharacters(in: .whitespaces)]
        } else if let arr = cfgVal.array {
            b64Strings = arr.compactMap { $0.string?.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        } else {
            return nil
        }
        guard !b64Strings.isEmpty else { return nil }
        var combinedData = Data()
        for b64 in b64Strings {
            var standard = b64.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
            while standard.count % 4 != 0 { standard.append("=") }
            guard let data = Data(base64Encoded: standard) else {
                throw Failure.handshake("invalid base64 in ech config")
            }
            combinedData.append(data)
        }
        guard !combinedData.isEmpty else { return nil }
        do {
            _ = try NCECHConfigParser.parseList(combinedData)
        } catch {
            throw Failure.handshake("invalid ECHConfigList: \(error.localizedDescription)")
        }
        return combinedData
    }

    /// Single integration injection point for dynamic ECH resolution:
    /// 1. If static `ech-opts.config` is provided, parse and return it.
    /// 2. If ECH is enabled (`enable == true`) but no static config exists:
    ///    - In this PR: explicitly throw `Failure.handshake("ECH enabled but no config available")`.
    ///    - Later E2 integration point: perform async/dynamic DNS SVCB/HTTPS query here.
    /// Never silently fall back to plaintext SNI when ECH is requested.
    static func resolveECHConfigList(_ proxy: NCProxy) throws -> Data? {
        guard isECHEnabled(proxy) else { return nil }
        if let staticList = try parseStaticECHConfigList(proxy) {
            return staticList
        }
        // E2 resolver injection point: dynamic HTTPS/SVCB DNS resolution will hook in here.
        throw Failure.handshake("ECH enabled but no config available")
    }

    /// Determine default ALPN when the node does not explicitly specify `alpn`.
    /// - ws transport: ["http/1.1"] (never offer h2, otherwise CF/nginx selects h2 and WebSocket upgrade fails)
    /// - grpc transport: ["h2"]
    /// - tcp/other transport: ["h2", "http/1.1"]
    /// - trojan / https / anytls keep their existing defaults when unrelated to transport:
    ///   - https: ["http/1.1"]
    ///   - trojan: ["h2", "http/1.1"]
    ///   - anytls: ["h2", "http/1.1"]
    static func defaultALPN(for proxy: NCProxy) -> [String] {
        switch proxy.type.lowercased() {
        case "https":
            return ["http/1.1"]
        case "anytls":
            return ["h2", "http/1.1"]
        case "trojan":
            return ["h2", "http/1.1"]
        case "vmess", "vless":
            let network = proxy.fields["network"]?.string?.lowercased() ?? "tcp"
            switch network {
            case "ws":
                return ["http/1.1"]
            case "grpc":
                return ["h2"]
            default:
                return ["h2", "http/1.1"]
            }
        default:
            let network = proxy.fields["network"]?.string?.lowercased() ?? "tcp"
            switch network {
            case "ws":
                return ["http/1.1"]
            case "grpc":
                return ["h2"]
            default:
                return ["h2", "http/1.1"]
            }
        }
    }

    /// Whether this proxy requires the native TLS stack (NCTLSClient).
    /// Note: client-fingerprint of "none" or empty string does not trigger native TLS.
    static func needsNativeTLS(_ proxy: NCProxy) -> Bool {
        if isECHEnabled(proxy) { return true }
        if let fp = parseClientFingerprint(proxy), !fp.isEmpty, fp.lowercased() != "none" { return true }
        if parsePinnedCertSHA256(proxy) != nil { return true }
        return false
    }

    /// Dial TCP and run the hand-rolled TLS 1.3 / 1.2 handshake over it with parity parameters.
    static func dialNativeTLS(proxy: NCProxy, server: String, port: Int,
                              serverName: String? = nil,
                              defaultALPN: [String]? = nil,
                              queue: DispatchQueue, completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let serverName = serverName ?? (proxy.fields["servername"]?.string ?? proxy.fields["sni"]?.string ?? server)
        let allowInsecure = proxy.fields["skip-cert-verify"]?.bool ?? false
        let alpn = parseALPN(proxy) ?? defaultALPN ?? self.defaultALPN(for: proxy)
        let profile = NCClientHelloProfile.named(parseClientFingerprint(proxy))
        let pin = parsePinnedCertSHA256(proxy)

        let echConfig: Data?
        do {
            echConfig = try resolveECHConfigList(proxy)
        } catch {
            queue.async { completion(nil, error) }
            return
        }

        var cfg = NCTLSClientStream.Config(serverName: serverName)
        cfg.alpn = alpn
        cfg.allowInsecure = allowInsecure
        cfg.pinnedCertSHA256 = pin
        cfg.profile = profile
        cfg.echConfigList = echConfig
        if let outer = echOpts(proxy)?["outer-sni"]?.string ?? echOpts(proxy)?["public-name"]?.string {
            cfg.outerServerName = outer
        }
        if let ncv = proxy.fields["name-cert-verify"]?.string, !ncv.isEmpty {
            cfg.certVerifyName = ncv
        }
        cfg.rawDialer = { retryCompletion in
            let retryRaw = NCStream(to: server, port: port, queue: queue)
            retryRaw.start { err in
                if let err {
                    retryCompletion(nil, err)
                } else {
                    retryCompletion(retryRaw, nil)
                }
            }
        }

        let raw = NCStream(to: server, port: port, queue: queue)
        raw.start { err in
            guard err == nil else { completion(nil, err); return }
            let tls = NCTLSClientStream(raw: raw, config: cfg, queue: queue)
            tls.startHandshake { herr in
                if let herr {
                    tls.cancel()
                    completion(nil, herr)
                } else {
                    completion(tls, nil)
                }
            }
        }
    }

    private static func hexBytes(_ hex: String) -> Data? {
        var out = Data(capacity: hex.count / 2)
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            guard j <= hex.endIndex, let b = UInt8(hex[i..<j], radix: 16) else { return nil }
            out.append(b)
            i = j
        }
        return out
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
    static func transportStream(raw: NCRelayStream, proxy: NCProxy, server: String, queue: DispatchQueue,
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
            let tunnel = NCH2TunnelStream(raw: raw, grpc: true, callerQueue: queue)
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
            let tunnel = NCH2TunnelStream(raw: raw, grpc: false, callerQueue: queue)
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

    private static var ssrAuthRegistry: [String: NCSSRAuthState] = [:]
    private static let ssrAuthLock = NSLock()

    private static func ssrAuthState(for name: String) -> NCSSRAuthState {
        ssrAuthLock.lock()
        defer { ssrAuthLock.unlock() }
        if let existing = ssrAuthRegistry[name] { return existing }
        let state = NCSSRAuthState()
        ssrAuthRegistry[name] = state
        return state
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
                // nc-sessions: readiness is a one-shot waiter on the session (no 0.25 s polling); the
                // registry cleanup on failure stays here, in the waiter's callback.
                existing.whenReady(callerQueue: queue) { err in
                    if let err {
                        muxLock.lock()
                        if muxRegistry[key] === existing { muxRegistry.removeValue(forKey: key) }
                        muxLock.unlock()
                        completion(nil, err)
                    } else {
                        completion(existing, nil)
                    }
                }
            } else {
                muxLock.lock()
                muxRegistry.removeValue(forKey: key)
                muxLock.unlock()
                muxSession(proxy: proxy, server: server, port: port, queue: queue, completion: completion)
            }
            return
        }
        let session = NCMuxSession(key: key)
        muxRegistry[key] = session
        muxLock.unlock()
        // nc-sessions: the base connection is dialed on the session's own queue, so its callbacks (and with
        // them all session state) live there; the registry completion is handed back on the caller's queue.
        connectViaProxy(target: NCMux.destination, proxy: proxy, queue: session.queue, allowMux: false) { base, err in
            if let base {
                session.attach(base: base)
                queue.async { completion(session, nil) }
            } else {
                muxLock.lock()
                muxRegistry.removeValue(forKey: key)
                muxLock.unlock()
                session.attachFailed()
                queue.async { completion(nil, err ?? Failure.handshake("mux dial failed")) }
            }
        }
    }

    // MARK: AnyTLS (shared TLS session per proxy)

    private static var anytlsRegistry: [String: NCAnyTLSSession] = [:]
    private static let anytlsLock = NSLock()

    static func anytlsSession(proxy: NCProxy, server: String, port: Int, queue: DispatchQueue,
                              completion: @escaping (NCAnyTLSSession?, Error?) -> Void) {
        let key = "\(proxy.name)|\(server)|\(port)"
        anytlsLock.lock()
        if let existing = anytlsRegistry[key] {
            anytlsLock.unlock()
            if existing.isAlive {
                completion(existing, nil)
            } else if existing.state == .connecting {
                existing.whenReady(callerQueue: queue) { err in
                    if let err {
                        anytlsLock.lock()
                        if anytlsRegistry[key] === existing { anytlsRegistry.removeValue(forKey: key) }
                        anytlsLock.unlock()
                        completion(nil, err)
                    } else {
                        completion(existing, nil)
                    }
                }
            } else {
                anytlsLock.lock()
                anytlsRegistry.removeValue(forKey: key)
                anytlsLock.unlock()
                anytlsSession(proxy: proxy, server: server, port: port, queue: queue, completion: completion)
            }
            return
        }
        guard let password = proxy.password else {
            anytlsLock.unlock()
            queue.async { completion(nil, Failure.handshake("anytls missing password")) }
            return
        }
        let session = NCAnyTLSSession(key: key)
        anytlsRegistry[key] = session
        anytlsLock.unlock()

        if isECHEnabled(proxy) && realityParams(proxy) != nil {
            anytlsLock.lock()
            if anytlsRegistry[key] === session { anytlsRegistry.removeValue(forKey: key) }
            anytlsLock.unlock()
            session.attachFailed()
            queue.async { completion(nil, Failure.handshake("REALITY 与 ECH 互斥，不能同时启用")) }
            return
        }

        let anytlsSNI = proxy.fields["sni"]?.string ?? proxy.fields["servername"]?.string ?? server
        if needsNativeTLS(proxy) {
            dialNativeTLS(proxy: proxy, server: server, port: port, serverName: anytlsSNI, queue: session.queue) { tls, err in
                if let tls {
                    session.attach(tls: tls, password: password,
                                   clientMetadata: proxy.fields["client-metadata"]?.string ?? "")
                    queue.async { completion(session, nil) }
                } else {
                    anytlsLock.lock()
                    if anytlsRegistry[key] === session { anytlsRegistry.removeValue(forKey: key) }
                    anytlsLock.unlock()
                    session.attachFailed()
                    queue.async { completion(nil, err) }
                }
            }
            return
        }

        // nc-sessions: the base TLS connection runs on the session's own queue (see muxSession).
        let tls = NCStream(to: server, port: port,
                           tlsServerName: anytlsSNI,
                           allowInsecure: proxy.fields["skip-cert-verify"]?.bool ?? false,
                           queue: session.queue)
        tls.start { err in
            if err == nil {
                session.attach(tls: tls, password: password,
                               clientMetadata: proxy.fields["client-metadata"]?.string ?? "")
                queue.async { completion(session, nil) }
            } else {
                anytlsLock.lock()
                if anytlsRegistry[key] === session { anytlsRegistry.removeValue(forKey: key) }
                anytlsLock.unlock()
                session.attachFailed()
                queue.async { completion(nil, err) }
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
            if existing.isAlive {
                completion(existing, nil)
            } else if existing.state == .connecting || existing.state == .authenticating {
                // nc-races: readiness is a one-shot waiter on the connection (no 0.25 s polling, the
                // shape #116 set for mux/anytls); the registry cleanup on failure stays here.
                existing.whenReady(callerQueue: queue) { err in
                    if let err {
                        hy2Lock.lock()
                        if hy2Registry[key] === existing { hy2Registry.removeValue(forKey: key) }
                        hy2Lock.unlock()
                        completion(nil, err)
                    } else {
                        completion(existing, nil)
                    }
                }
            } else {
                hy2Lock.lock()
                hy2Registry.removeValue(forKey: key)
                hy2Lock.unlock()
                sharedHysteria2(proxy: proxy, server: server, port: port, queue: queue, completion: completion)
            }
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
                if hy2Registry[key] === conn { hy2Registry.removeValue(forKey: key) }
                hy2Lock.unlock()
                completion(nil, err)
            }
        }
    }

    // MARK: Shared session lifecycle (nc-lifecycle)

    /// Live shared-session counts per registry (mux / anytls / hy2 live here;
    /// hy1 / tuic / ssh in their own files' extensions). Read by the tunnel
    /// core's stop log and the lifecycle self-test: after a stop these must
    /// all be zero.
    static func sharedSessionCounts() -> [String: Int] {
        muxLock.lock(); let mux = muxRegistry.count; muxLock.unlock()
        anytlsLock.lock(); let anytls = anytlsRegistry.count; anytlsLock.unlock()
        hy2Lock.lock(); let hy2 = hy2Registry.count; hy2Lock.unlock()
        return ["mux": mux, "anytls": anytls, "hy2": hy2,
                "hy1": hy1SessionCount, "tuic": tuicSessionCount, "ssh": sshSessionCount]
    }

    /// Tunnel stop: drain every shared-session registry and close what it
    /// held. Before this, the registries were only ever pruned lazily (a
    /// dead entry on its next use), so a stopped core left live QUIC groups,
    /// TLS sockets and SSH clients — plus their buffers — in the extension
    /// for its remaining life, and a restart could even be vended a session
    /// dialed with the previous config's credentials (the keys carry name /
    /// server / port, not the secret). Entries are removed under the locks
    /// first (nothing new is vended), then closed outside them: each close
    /// fails its streams and notifies its waiters, whose registry-cleanup
    /// callbacks then find nothing to remove. Reload deliberately does NOT
    /// do this: live flows ride these sessions, and tearing them down would
    /// kill the flows a reload is supposed to keep (see the PR audit notes).
    /// Returns how many sessions were closed per registry.
    @discardableResult
    static func closeAllSharedSessions() -> [String: Int] {
        muxLock.lock(); let mux = Array(muxRegistry.values); muxRegistry.removeAll(); muxLock.unlock()
        anytlsLock.lock(); let anytls = Array(anytlsRegistry.values); anytlsRegistry.removeAll(); anytlsLock.unlock()
        hy2Lock.lock(); let hy2 = Array(hy2Registry.values); hy2Registry.removeAll(); hy2Lock.unlock()
        ssrAuthLock.lock(); ssrAuthRegistry.removeAll(); ssrAuthLock.unlock()
        for s in mux { s.close() }
        for s in anytls { s.close() }
        for c in hy2 { c.close() }
        let closed = ["mux": mux.count, "anytls": anytls.count, "hy2": hy2.count,
                      "hy1": closeAllHy1Sessions(), "tuic": closeAllTUICSessions(),
                      "ssh": closeAllSSHSessions()]
        clearSharedSSRState()
        return closed
    }

    // MARK: VMess (AEAD, alterId 0)

    private static func connectVMess(target: NCTarget, proxy: NCProxy, server: String, port: Int,
                                     queue: DispatchQueue,
                                     transport: NCRelayStream? = nil,
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
        if isECHEnabled(proxy) && realityParams(proxy) != nil {
            queue.async { completion(nil, Failure.handshake("REALITY 与 ECH 互斥，不能同时启用")) }
            return
        }
        if realityParams(proxy) != nil {
            guard transport == nil else {
                queue.async { completion(nil, Failure.unsupported("vmess reality over a chain transport")) }
                return
            }
            dialReality(proxy: proxy, server: server, port: port, queue: queue) { base0, err in
                guard let base0 else { completion(nil, err); return }
                transportStream(raw: base0, proxy: proxy, server: server, queue: queue) { base, terr in
                    guard let base else { completion(nil, terr); return }
                    finishVMess(base: base, target: target, uuidBytes: uuidBytes, security: security, completion: completion)
                }
            }
            return
        }
        if let transport {
            guard !(proxy.fields["tls"]?.bool ?? false) else {
                queue.async { completion(nil, Failure.unsupported("vmess tls over a chain transport")) }
                return
            }
            transportStream(raw: transport, proxy: proxy, server: server, queue: queue) { base, terr in
                guard let base else { completion(nil, terr); return }
                finishVMess(base: base, target: target, uuidBytes: uuidBytes, security: security, completion: completion)
            }
            return
        }
        let useTLS = proxy.fields["tls"]?.bool ?? false
        if useTLS && needsNativeTLS(proxy) {
            dialNativeTLS(proxy: proxy, server: server, port: port, queue: queue) { base0, err in
                guard let base0 else { completion(nil, err); return }
                transportStream(raw: base0, proxy: proxy, server: server, queue: queue) { base, terr in
                    guard let base else { completion(nil, terr); return }
                    finishVMess(base: base, target: target, uuidBytes: uuidBytes, security: security, completion: completion)
                }
            }
            return
        }
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
            transportStream(raw: raw, proxy: proxy, server: server, queue: queue) { base, terr in
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

    /// SOCKS5 / HTTP CONNECT handshake limits (rv2-proto): a stalled proxy is cut off after `proxyHandshakeTimeout`
    /// and the reply buffer is bounded (a SOCKS5 reply is at most 262 bytes).
    static var proxyHandshakeTimeout: TimeInterval = 12
    static let maxSOCKSReply = 512

    private static func socksHandshake(raw: NCRelayStream, target: NCTarget, proxy: NCProxy, queue: DispatchQueue,
                                       completion outer: @escaping (NCRelayStream?, Error?) -> Void) {
        let deadline = NCHandshakeDeadline(queue: queue, seconds: proxyHandshakeTimeout, raw: raw, what: "socks5",
                                           completion: outer)
        let completion: (NCRelayStream?, Error?) -> Void = { s, e in
            if s == nil, !deadline.isDone { raw.cancel() }
            deadline.finish(s, e)
        }
        let username = proxy.fields["username"]?.string
        let password = proxy.fields["password"]?.string
        let buf = NCByteBuffer()
        raw.send(NCSOCKS5.greeting(username: username, password: password))
        receiveInto(raw: raw, buf: buf, atLeast: 2) { error in
            guard !deadline.isDone else { return }
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
                    guard !deadline.isDone else { return }
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

    private static func socksRequest(raw: NCRelayStream, target: NCTarget, buf: NCByteBuffer,
                                     completion: @escaping (NCRelayStream?, Error?) -> Void) {
        raw.send(NCSOCKS5.connectRequest(target: target))
        func step() {
            if NCSOCKS5.isMalformedResponse(buf.data) { completion(nil, Failure.handshake("socks bad reply")); return }
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
                if buf.count > maxSOCKSReply, NCSOCKS5.parseResponse(buf.data) == nil {
                    completion(nil, Failure.handshake("socks reply too large")); return
                }
                step()
            }
        }
        step()
    }

    // MARK: HTTP CONNECT handshake

    private static func httpHandshake(raw: NCRelayStream, target: NCTarget, proxy: NCProxy, queue: DispatchQueue,
                                      completion outer: @escaping (NCRelayStream?, Error?) -> Void) {
        let deadline = NCHandshakeDeadline(queue: queue, seconds: proxyHandshakeTimeout, raw: raw, what: "http connect",
                                           completion: outer)
        let completion: (NCRelayStream?, Error?) -> Void = { s, e in
            if s == nil, !deadline.isDone { raw.cancel() }
            deadline.finish(s, e)
        }
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
                guard !deadline.isDone else { return }
                guard let data else { completion(nil, error ?? Failure.handshake("http eof")); return }
                buf.append(data)
                if buf.count > 16384 { completion(nil, Failure.handshake("http header too large")); return }
                step()
            }
        }
        step()
    }

    /// Accumulate into `buf` until it holds at least `n` bytes (or EOF/error).
    private static func receiveInto(raw: NCRelayStream, buf: NCByteBuffer, atLeast n: Int,
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
    private let inner: NCRelayStream
    private var prefix: Data

    init(inner: NCRelayStream, prefix: Data) {
        self.inner = inner
        self.prefix = prefix
    }

    func send(_ data: Data, completion: @escaping () -> Void) { inner.send(data, completion: completion) }

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

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        guard !data.isEmpty else { once.call(); return }
        if let encoder {
            raw.send(encoder.encode(data), completion: once.call)
        } else {
            raw.send(data, completion: once.call) // security none over TCP is a plain stream
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
