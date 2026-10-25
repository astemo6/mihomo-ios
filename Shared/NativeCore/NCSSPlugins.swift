import Foundation
import CryptoKit

// Shadowsocks plugins (feat/nc-proto A4, based on astemo6/Muse NativeCore), ported from mihomo v1.19.33
// transport/simple-obfs, transport/v2ray-plugin and transport/shadowtls. Each one is an NCRelayStream that carries
// the Shadowsocks byte stream; the SS relay (NCSSRelayStream / NCSS2022RelayStream) rides on top unchanged.
// Buffers are per-record (≤ 16 KB + header); nothing accumulates beyond one frame.

/// Shared one-shot receive plumbing: subclasses turn raw chunks into plaintext via `consume`.
class NCFramedRelay: NCRelayStream {
    let raw: NCRelayStream
    var inbuf = Data()
    private var out: [Data] = []
    private var failure: Error?
    private var eof = false

    init(raw: NCRelayStream) { self.raw = raw }

    func send(_ data: Data) { raw.send(data) }
    func cancel() { raw.cancel() }

    /// Parse as much of `inbuf` as possible; return plaintext pieces (may be empty) or throw on a protocol error.
    func consume() throws -> [Data] { let d = inbuf; inbuf = Data(); return d.isEmpty ? [] : [d] }

    final func feedExternal(_ data: Data) throws {
        inbuf.append(data)
        out.append(contentsOf: try consume().filter { !$0.isEmpty })
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        if !out.isEmpty { handler(out.removeFirst(), nil); return }
        if let failure { handler(nil, failure); return }
        if eof { handler(nil, nil); return }
        raw.receive { [weak self] data, error in
            guard let self else { handler(nil, error); return }
            guard let data else { self.eof = true; handler(nil, error); return }
            do {
                try self.feedExternal(data)
            } catch {
                self.failure = error
                handler(nil, error)
                self.raw.cancel()
                return
            }
            self.receive(handler)
        }
    }

    static func err(_ s: String) -> NSError {
        NSError(domain: "NativeCore", code: 41, userInfo: [NSLocalizedDescriptionKey: s])
    }
}

// simple-obfs (http/tls) and v2ray-plugin (websocket + mux) live in NCSSPlugin.swift / NCSSPluginStream.swift
// (#101, astemo6) — one implementation; nc-proto's duplicate classes were dropped at the nc-integrate merge.

// MARK: - shadow-tls (v2 / v3)

/// Sits between the handshake TLS client and the socket. v2: HMAC over every byte the TLS client reads.
/// v3: undoes the server's XOR+HMAC on handshake ApplicationData records and keeps the running read HMAC.
/// After the handshake it is detached: the TLS client is dropped and the socket belongs to the data conn.
final class NCShadowTLSWire: NCRelayStream {
    let raw: NCRelayStream
    let password: Data
    let version: Int
    var detached = false
    // v2
    var readHash: HMAC<Insecure.SHA1>
    // v3
    var frameBuf = Data()
    var serverRandom: Data?
    var readHMAC: HMAC<Insecure.SHA1>?
    var readKey = Data()
    var isTLS13 = false
    var authorized = false
    var failure: Error?
    /// Bytes received after detaching (handed to the data conn).
    var spill = Data()

    init(raw: NCRelayStream, password: String, version: Int) {
        self.raw = raw
        self.password = Data(password.utf8)
        self.version = version
        readHash = HMAC<Insecure.SHA1>(key: SymmetricKey(data: Data(password.utf8)))
    }

    func send(_ data: Data) { if !detached { raw.send(data) } }
    func cancel() { if !detached { raw.cancel() } }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        if detached { return } // the handshake client's post-handshake read: never answered
        if let failure { handler(nil, failure); return }
        raw.receive { [weak self] data, error in
            guard let self else { return }
            guard let data else { if !self.detached { handler(nil, error) }; return }
            if self.detached { self.spill.append(data); return }
            if self.version == 1 { handler(data, nil); return } // v1: the handshake passes through untouched
            if self.version == 2 {
                self.readHash.update(data: data)
                handler(data, nil)
                return
            }
            do {
                let plain = try self.v3Transform(data)
                if plain.isEmpty { self.receive(handler) } else { handler(plain, nil) }
            } catch {
                self.failure = error
                handler(nil, error)
            }
        }
    }

    private func v3Transform(_ data: Data) throws -> Data {
        frameBuf.append(data)
        var out = Data()
        while frameBuf.count >= 5 {
            let s = frameBuf.startIndex
            let len = Int(frameBuf[s + 3]) << 8 | Int(frameBuf[s + 4])
            guard frameBuf.count >= 5 + len else { break }
            var frame = [UInt8](frameBuf.prefix(5 + len))
            frameBuf = Data(frameBuf.dropFirst(5 + len))
            if frame[0] == 22, frame.count >= 11 + 32, frame[5] == 2, readHMAC == nil {
                let sr = Data(frame[11..<43])
                serverRandom = sr
                var h = HMAC<Insecure.SHA1>(key: SymmetricKey(data: password))
                h.update(data: sr)
                readHMAC = h
                readKey = Data(SHA256.hash(data: password + sr))
                isTLS13 = NCShadowTLS.serverHelloIsTLS13(frame)
                authorized = !isTLS13
            } else if frame[0] == 23 {
                authorized = false
                if frame.count > 9, var h = readHMAC {
                    h.update(data: Data(frame[9...]))
                    readHMAC = h
                    let sum = [UInt8](Data(h.finalize())).prefix(4)
                    guard Array(sum) == Array(frame[5..<9]) else {
                        throw NCFramedRelay.err("shadow-tls v3: HMAC mismatch, possible data corruption")
                    }
                    for i in 9..<frame.count { frame[i] ^= readKey[readKey.startIndex + (i - 9) % readKey.count] }
                    let payload = frame[9...]
                    var rec = Data([frame[0], frame[1], frame[2]])
                    rec.appendBE16(UInt16(payload.count))
                    rec.append(contentsOf: payload)
                    out.append(rec)
                    authorized = true
                    continue
                }
            }
            out.append(contentsOf: frame)
        }
        return out
    }
}

enum NCShadowTLS {
    static func serverHelloIsTLS13(_ frame: [UInt8]) -> Bool {
        let sidIdx = 5 + 1 + 3 + 2 + 32
        guard frame.count > sidIdx, frame[0] == 22, frame[5] == 2 else { return false }
        var off = sidIdx + 1 + Int(frame[sidIdx])
        guard off + 3 + 2 <= frame.count else { return false }
        off += 3
        let extLen = Int(frame[off]) << 8 | Int(frame[off + 1]); off += 2
        guard off + extLen <= frame.count else { return false }
        let end = off + extLen
        while off + 4 <= end {
            let t = Int(frame[off]) << 8 | Int(frame[off + 1])
            let n = Int(frame[off + 2]) << 8 | Int(frame[off + 3])
            off += 4
            guard off + n <= end else { return false }
            if t == 43 { return n == 2 && frame[off] == 3 && frame[off + 1] == 4 }
            off += n
        }
        return false
    }

    /// v3 session ID: 28 random bytes + HMAC-SHA1(password, hello with this ID and its last 4 bytes zero)[:4].
    static func sessionID(password: String, hello: Data) -> Data? {
        let start = 39
        guard hello.count >= start + 32 else { return nil }
        var sid = NCConnector.randomData(28)
        sid.append(contentsOf: [0, 0, 0, 0])
        var h = HMAC<Insecure.SHA1>(key: SymmetricKey(data: Data(password.utf8)))
        h.update(data: hello.prefix(start))
        h.update(data: sid)
        h.update(data: hello.dropFirst(start + 32))
        let mac = Data(h.finalize())
        sid.replaceSubrange(28..<32, with: mac.prefix(4))
        return sid
    }

    /// The ClientHello handshake message without extension `type` (lengths fixed up); nil if it does not parse.
    static func removingExtension(_ type: UInt16, from hello: Data) -> Data? {
        let b = [UInt8](hello)
        guard b.count > 4 + 2 + 32 + 1, b[0] == 1 else { return nil }
        var off = 4 + 2 + 32
        off += 1 + Int(b[off])                                   // session id
        guard off + 2 <= b.count else { return nil }
        off += 2 + (Int(b[off]) << 8 | Int(b[off + 1]))          // cipher suites
        guard off + 1 <= b.count else { return nil }
        off += 1 + Int(b[off])                                   // compression methods
        guard off + 2 <= b.count else { return nil }
        let extStart = off + 2
        let extEnd = extStart + (Int(b[off]) << 8 | Int(b[off + 1]))
        guard extEnd <= b.count else { return nil }
        var exts = [UInt8]()
        var p = extStart
        while p + 4 <= extEnd {
            let t = UInt16(b[p]) << 8 | UInt16(b[p + 1])
            let n = Int(b[p + 2]) << 8 | Int(b[p + 3])
            guard p + 4 + n <= extEnd else { return nil }
            if t != type { exts.append(contentsOf: b[p..<(p + 4 + n)]) }
            p += 4 + n
        }
        var body = Array(b[4..<off])
        body.append(UInt8((exts.count >> 8) & 0xff)); body.append(UInt8(exts.count & 0xff))
        body.append(contentsOf: exts)
        body.append(contentsOf: b[extEnd...])
        var out = [UInt8(1), UInt8((body.count >> 16) & 0xff), UInt8((body.count >> 8) & 0xff), UInt8(body.count & 0xff)]
        out.append(contentsOf: body)
        return Data(out)
    }

    /// shadow-tls v1: a plain TLS ≤ 1.2 handshake with the camouflage server through the shadow-tls server, then
    /// the socket itself carries the SS stream (mihomo transport/shadowtls Client.DialContextConn case 1).
    static func dialV1(raw: NCRelayStream, host: String, alpn: [String], allowInsecure: Bool, queue: DispatchQueue,
                       completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let wire = NCShadowTLSWire(raw: raw, password: "", version: 1)
        var cfg = NCTLSClientStream.Config(serverName: host)
        cfg.alpn = alpn
        cfg.allowInsecure = allowInsecure
        cfg.profile = NCClientHelloProfile.named(nil) // v1 uses the Go client hello (no uTLS fingerprint)
        cfg.maxTLS12 = true
        let tls = NCTLSClientStream(raw: wire, config: cfg, queue: queue)
        tls.startHandshake { err in
            if let err { completion(nil, err); return }
            let tail = tls.spliceOut().rawTail
            wire.detached = true
            let rest = tail + wire.spill
            completion(rest.isEmpty ? raw : NCBufferedStream(inner: raw, prefix: rest), nil)
        }
    }

    /// Runs the camouflage TLS handshake over `raw` and returns the data conn the SS stream rides on.
    static func dial(raw: NCRelayStream, version: Int, password: String, host: String, alpn: [String],
                     allowInsecure: Bool, fingerprint: String?, queue: DispatchQueue,
                     completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let wire = NCShadowTLSWire(raw: raw, password: password, version: version)
        var cfg = NCTLSClientStream.Config(serverName: host)
        cfg.alpn = alpn
        cfg.allowInsecure = allowInsecure
        cfg.profile = NCClientHelloProfile.named(fingerprint)
        if version == 3 {
            cfg.sessionIDGenerator = { hello in sessionID(password: password, hello: hello) }
        }
        let tls = NCTLSClientStream(raw: wire, config: cfg, queue: queue)
        tls.startHandshake { err in
            if let err { completion(nil, err); return }
            // Detach: unparsed socket bytes behind the last handshake record belong to the data conn.
            let tail = tls.spliceOut().rawTail
            wire.detached = true
            if version == 2 {
                let sum = Data(wire.readHash.finalize()).prefix(8)
                let conn = NCShadowTLSV2Conn(raw: raw, firstPrefix: Data(sum))
                do { try conn.feedExternal(tail + wire.spill) } catch { completion(nil, error); return }
                completion(conn, nil)
                return
            }
            guard wire.authorized, let sr = wire.serverRandom else {
                raw.cancel()
                completion(nil, NCFramedRelay.err("shadow-tls: traffic hijacked"))
                return
            }
            let pw = SymmetricKey(data: Data(password.utf8))
            var add = HMAC<Insecure.SHA1>(key: pw); add.update(data: sr + Data("C".utf8))
            var ver = HMAC<Insecure.SHA1>(key: pw); ver.update(data: sr + Data("S".utf8))
            let conn = NCShadowTLSV3Conn(raw: raw, hmacAdd: add, hmacVerify: ver, hmacIgnore: wire.readHMAC)
            do { try conn.feedExternal(tail + wire.spill) } catch { completion(nil, error); return }
            completion(conn, nil)
        }
    }
}

/// v2 data conn: ApplicationData records both ways; the first write carries the 8-byte handshake read HMAC.
final class NCShadowTLSV2Conn: NCFramedRelay {
    private var prefix: Data?
    private var remain = 0

    init(raw: NCRelayStream, firstPrefix: Data) {
        prefix = firstPrefix
        super.init(raw: raw)
    }

    override func send(_ data: Data) {
        var payload = data
        if let p = prefix { payload = p + data; prefix = nil }
        var rest = payload[...]
        repeat {
            let chunk = rest.prefix(16384)
            rest = rest.dropFirst(chunk.count)
            var rec = Data([0x17, 0x03, 0x03])
            rec.appendBE16(UInt16(chunk.count))
            rec.append(contentsOf: chunk)
            raw.send(rec)
        } while !rest.isEmpty
    }

    override func consume() throws -> [Data] {
        var out: [Data] = []
        while true {
            if remain > 0 {
                guard !inbuf.isEmpty else { break }
                let n = min(remain, inbuf.count)
                out.append(Data(inbuf.prefix(n)))
                inbuf = Data(inbuf.dropFirst(n))
                remain -= n
                continue
            }
            guard inbuf.count >= 5 else { break }
            let s = inbuf.startIndex
            guard inbuf[s] == 23 else { throw Self.err("shadow-tls: unexpected TLS record type: \(inbuf[s])") }
            remain = Int(inbuf[s + 3]) << 8 | Int(inbuf[s + 4])
            inbuf = Data(inbuf.dropFirst(5))
        }
        return out
    }
}

/// v3 data conn: every record carries a 4-byte chained HMAC (client "C", server "S"); records still signed with
/// the handshake read HMAC (the camouflage server's tickets) are skipped.
final class NCShadowTLSV3Conn: NCFramedRelay {
    private var hmacAdd: HMAC<Insecure.SHA1>
    private var hmacVerify: HMAC<Insecure.SHA1>
    private var hmacIgnore: HMAC<Insecure.SHA1>?

    init(raw: NCRelayStream, hmacAdd: HMAC<Insecure.SHA1>, hmacVerify: HMAC<Insecure.SHA1>,
         hmacIgnore: HMAC<Insecure.SHA1>?) {
        self.hmacAdd = hmacAdd
        self.hmacVerify = hmacVerify
        self.hmacIgnore = hmacIgnore
        super.init(raw: raw)
    }

    override func send(_ data: Data) {
        var rest = data[...]
        repeat {
            let chunk = Data(rest.prefix(16384))
            rest = rest.dropFirst(chunk.count)
            hmacAdd.update(data: chunk)
            let mac = Data(Data(hmacAdd.finalize()).prefix(4))
            hmacAdd.update(data: mac)
            var rec = Data([0x17, 0x03, 0x03])
            rec.appendBE16(UInt16(4 + chunk.count))
            rec.append(mac)
            rec.append(chunk)
            raw.send(rec)
        } while !rest.isEmpty
    }

    override func consume() throws -> [Data] {
        var out: [Data] = []
        while inbuf.count >= 5 {
            let s = inbuf.startIndex
            let len = Int(inbuf[s + 3]) << 8 | Int(inbuf[s + 4])
            guard inbuf.count >= 5 + len else { break }
            let frame = Data(inbuf.prefix(5 + len))
            inbuf = Data(inbuf.dropFirst(5 + len))
            let f = frame.startIndex
            switch frame[f] {
            case 21:
                throw Self.err("shadow-tls: remote alert")
            case 23:
                guard frame.count >= 9, frame[f + 1] == 3, frame[f + 2] == 3 else {
                    throw Self.err("shadow-tls: application data verification failed")
                }
                let mac = Data(frame[(f + 5)..<(f + 9)])
                let payload = Data(frame[(f + 9)...])
                if var ign = hmacIgnore {
                    ign.update(data: payload)
                    hmacIgnore = ign
                    if Data(Data(ign.finalize()).prefix(4)) == mac { continue }
                    hmacIgnore = nil
                }
                hmacVerify.update(data: payload)
                let sum = Data(Data(hmacVerify.finalize()).prefix(4))
                hmacVerify.update(data: sum)
                guard sum == mac else { throw Self.err("shadow-tls: application data verification failed") }
                if !payload.isEmpty { out.append(payload) }
            default:
                throw Self.err("shadow-tls: unexpected TLS record type: \(frame[f])")
            }
        }
        return out
    }
}

// MARK: - gost-plugin smux (feat/nc-proto3)

/// gost-plugin's mux: one smux v1 stream over the websocket (mihomo transport/gost NewGostWebsocket with
/// metacubex/smux DefaultConfig, keep-alive off). Frame: ver=1 ‖ cmd ‖ len (LE16) ‖ streamID (LE32) ‖ data;
/// cmd SYN=0 FIN=1 PSH=2 NOP=3. v1 has no flow-control frames. The client's first stream ID is 1.
final class NCGostSmuxStream: NCFramedRelay {
    private static let sid: UInt32 = 1
    private static let maxFrame = 32768
    private var opened = false
    private var finished = false

    private static func frame(_ cmd: UInt8, _ payload: Data = Data()) -> Data {
        var f = Data([1, cmd, UInt8(payload.count & 0xff), UInt8((payload.count >> 8) & 0xff)])
        f.append(contentsOf: [UInt8(sid & 0xff), UInt8((sid >> 8) & 0xff), UInt8((sid >> 16) & 0xff), UInt8(sid >> 24)])
        f.append(payload)
        return f
    }

    func open() {
        guard !opened else { return }
        opened = true
        raw.send(Self.frame(0))
    }

    override func send(_ data: Data) {
        open()
        var rest = data[...]
        var wire = Data()
        while !rest.isEmpty {
            let chunk = Data(rest.prefix(Self.maxFrame))
            rest = rest.dropFirst(chunk.count)
            wire.append(Self.frame(2, chunk))
        }
        if !wire.isEmpty { raw.send(wire) }
    }

    override func cancel() {
        if opened && !finished { finished = true; raw.send(Self.frame(1)) }
        raw.cancel()
    }

    override func consume() throws -> [Data] {
        var out: [Data] = []
        while inbuf.count >= 8 {
            let s = inbuf.startIndex
            guard inbuf[s] == 1 else { throw Self.err("gost smux: bad version \(inbuf[s])") }
            let cmd = inbuf[s + 1]
            let len = Int(inbuf[s + 2]) | Int(inbuf[s + 3]) << 8
            let sid = UInt32(inbuf[s + 4]) | UInt32(inbuf[s + 5]) << 8 | UInt32(inbuf[s + 6]) << 16 | UInt32(inbuf[s + 7]) << 24
            guard inbuf.count >= 8 + len else { break }
            let payload = Data(inbuf[(s + 8)..<(s + 8 + len)])
            inbuf = Data(inbuf.dropFirst(8 + len))
            guard sid == Self.sid else { continue }
            switch cmd {
            case 2: if !payload.isEmpty { out.append(payload) }
            case 1: throw Self.err("gost smux: stream closed by peer")
            default: break // SYN / NOP
            }
        }
        return out
    }
}

// MARK: - Connector glue

extension NCConnector {
    /// The byte pipe the Shadowsocks stream rides on: a fresh socket (or the chain transport) wrapped in the
    /// configured plugin. No plugin → plain stream.
    static func ssPluginStream(proxy: NCProxy, server: String, port: Int, queue: DispatchQueue,
                               transport: NCRelayStream?, completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let plugin = proxy.fields["plugin"]?.string ?? ""
        let opts = proxy.fields["plugin-opts"]?.object ?? [:]
        if let why = NCSupport.ssPluginUnsupported(proxy) {
            queue.async { completion(nil, Failure.unsupported("shadowsocks plugin \(why)")) }
            return
        }
        func plainRaw(_ done: @escaping (NCRelayStream?, Error?) -> Void) {
            if let transport { done(transport, nil); return }
            let s = NCStream(to: server, port: port, queue: queue)
            s.start { err in done(err == nil ? s : nil, err) }
        }
        switch plugin {
        case "obfs", "v2ray-plugin":
            // #101 (astemo6): simple-obfs http/tls and v2ray-plugin websocket (+mux) via NCSSPluginOptions /
            // NCSSPluginStream — the same parse NCSupport gates with.
            guard let popts = NCSSPluginOptions(pluginName: plugin, opts: opts) else {
                queue.async { completion(nil, Failure.unsupported("ss plugin \(plugin) shape unsupported (obfs http/tls, v2ray-plugin websocket)")) }
                return
            }
            func wrap(_ raw: NCRelayStream) {
                let stream = NCSSPluginStream(raw: raw, options: popts, serverPort: String(port))
                stream.start { err in completion(err == nil ? stream : nil, err) }
            }
            if case .v2rayPlugin = popts.kind, popts.tls {
                // v2ray-plugin tls= terminates TLS at the SS server itself (SNI = Host header, else host).
                let sni = popts.headers["Host"] ?? popts.host
                if let transport {
                    // Chain transport (kept from nc-proto): our TLS client over the hop.
                    var cfg = NCTLSClientStream.Config(serverName: sni)
                    cfg.alpn = ["http/1.1"]
                    cfg.allowInsecure = popts.skipCertVerify
                    let t = NCTLSClientStream(raw: transport, config: cfg, queue: queue)
                    t.startHandshake { err in
                        if let err { completion(nil, err) } else { wrap(t) }
                    }
                    return
                }
                let s = NCStream(to: server, port: port, tlsServerName: sni, allowInsecure: popts.skipCertVerify, queue: queue)
                s.start { err in
                    if let err { completion(nil, err) } else { wrap(s) }
                }
                return
            }
            plainRaw { raw, err in
                guard let raw else { completion(nil, err); return }
                wrap(raw)
            }
        case "gost-plugin":
            // mihomo gostObfsOption{Host: "bing.com", Mux: true}; mode must be websocket.
            let host = opts["host"]?.string ?? "bing.com"
            let path = opts["path"]?.string ?? ""
            var headers: [String: String] = [:]
            for (k, v) in opts["headers"]?.object ?? [:] { if let s = v.string { headers[k] = s } }
            let mux = opts["mux"]?.bool ?? true
            let tls = opts["tls"]?.bool ?? false
            let insecure = opts["skip-cert-verify"]?.bool ?? false
            let hostHeader = headers.first(where: { $0.key.lowercased() == "host" })?.value
            let sni = hostHeader ?? host
            func overWS(_ raw: NCRelayStream) {
                let ws = NCWebSocketStream(raw: raw, hostHeader: hostHeader ?? host, path: path.isEmpty ? "/" : path,
                                           headers: headers.filter { $0.key.lowercased() != "host" })
                ws.startHandshake { err in
                    guard err == nil else { completion(nil, err); return }
                    if mux {
                        let m = NCGostSmuxStream(raw: ws)
                        m.open()
                        completion(m, nil)
                    } else {
                        completion(ws, nil)
                    }
                }
            }
            if tls {
                if let transport {
                    var cfg = NCTLSClientStream.Config(serverName: sni)
                    cfg.alpn = ["http/1.1"]
                    cfg.allowInsecure = insecure
                    let t = NCTLSClientStream(raw: transport, config: cfg, queue: queue)
                    t.startHandshake { err in
                        if let err { completion(nil, err) } else { overWS(t) }
                    }
                    return
                }
                let s = NCStream(to: server, port: port, tlsServerName: sni, allowInsecure: insecure, queue: queue)
                s.start { err in
                    if let err { completion(nil, err) } else { overWS(s) }
                }
                return
            }
            plainRaw { raw, err in
                guard let raw else { completion(nil, err); return }
                overWS(raw)
            }
        case "shadow-tls":
            let version = opts["version"]?.int ?? 2
            let password = opts["password"]?.string ?? ""
            let host = opts["host"]?.string ?? ""
            let alpn = opts["alpn"]?.array?.compactMap { $0.string } ?? ["h2", "http/1.1"]
            plainRaw { raw, err in
                guard let raw else { completion(nil, err); return }
                if version == 1 {
                    NCShadowTLS.dialV1(raw: raw, host: host, alpn: alpn,
                                       allowInsecure: opts["skip-cert-verify"]?.bool ?? false,
                                       queue: queue, completion: completion)
                    return
                }
                NCShadowTLS.dial(raw: raw, version: version, password: password, host: host, alpn: alpn,
                                 allowInsecure: opts["skip-cert-verify"]?.bool ?? false,
                                 fingerprint: proxy.fields["client-fingerprint"]?.string,
                                 queue: queue, completion: completion)
            }
        case "restls":
            // feat/native-core-eval: restls over the hand-rolled TLS client (NCRestls.swift).
            plainRaw { raw, err in
                guard let raw else { completion(nil, err); return }
                restlsStream(raw: raw, proxy: proxy, queue: queue, completion: completion)
            }
        default:
            plainRaw(completion)
        }
    }
}
