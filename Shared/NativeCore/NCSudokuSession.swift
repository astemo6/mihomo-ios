import Foundation
import CryptoKit

/// Sudoku outbound session, wire-compatible with the official server (SUDOKU-ASCII/sudoku v0.5.2).
///
/// Layers, client side (fix/nc-sudoku-interop; first draft by astemo6, #162):
///   TCP ← [legacy HTTP mask head] ← Sudoku obfuscation (NCSudokuWire) ← AEAD records ← KIP control + payload
/// Handshake: ClientHello sealed with the directional PSK bases → ServerHello (nonce echo + X25519 pub) →
/// both sides rekey to HKDF session bases mixed with the X25519 secret → OpenTCP → raw payload.
/// Re-implemented from the documented protocol; the reference server's code was used as reference only.
enum NCSudokuSession {

    /// Starts a Sudoku outbound session over `raw`, completing with an `NCRelayStream` ready for traffic.
    static func connect(raw: NCRelayStream, proxy: NCProxy, target: NCTarget,
                        queue: DispatchQueue, completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let opts = NCSudoku.Options(proxy: proxy)
        if let why = opts.dataPlaneUnsupported {
            raw.cancel()
            queue.async { completion(nil, NCSudokuError.unsupported(why)) }
            return
        }
        let relay: NCSudokuRelay
        do {
            relay = try NCSudokuRelay(raw: raw, options: opts, target: target, queue: queue)
        } catch {
            raw.cancel()
            queue.async { completion(nil, error) }
            return
        }
        relay.handshake(completion: completion)
    }
}

enum NCSudokuError: Error, LocalizedError {
    case unsupported(String)
    case badConfig(String)
    case handshake(String)
    case serverClosed
    case authFailed
    case protocolError(String)

    var errorDescription: String? {
        switch self {
        case .unsupported(let s): return "Sudoku 不支持：\(s)"
        case .badConfig(let s): return "Sudoku 配置无效：\(s)"
        case .handshake(let s): return "Sudoku 握手失败：\(s)"
        case .serverClosed: return "Sudoku 握手失败：服务端关闭了连接（密钥 / 编码表 / 加密方式与服务端不一致？）"
        case .authFailed: return "Sudoku 握手失败：服务端回应无法认证（密钥 / 加密方式与服务端不一致）"
        case .protocolError(let s): return "Sudoku 协议错误：\(s)"
        }
    }
}

// MARK: - Keys

/// Key schedule of the official client.
enum NCSudokuKeys {
    /// The official client's key normalisation: a private key (64-hex master scalar or 128-hex split key)
    /// becomes the master public key hex, which is the PSK and table seed; the user hash is
    /// SHA-256(private key bytes)[:8]. Any other key (the public key itself, a passphrase) is used as given,
    /// with the user hash SHA-256(trimmed key)[:8].
    static func normalize(_ key: String) -> (psk: String, userHash: Data) {
        if let pub = NCSudokuEd25519.recoverPublicKeyHex(key), let raw = NCSudokuEd25519.hexBytes(key) {
            return (pub, Data(SHA256.hash(data: Data(raw)).prefix(8)))
        }
        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
        return (key, Data(SHA256.hash(data: Data(trimmed.utf8)).prefix(8)))
    }

    /// Legacy-PRNG seed of the byte table: int64(BE(SHA-256(psk)[0..8])).
    static func tableSeed(_ psk: String) -> Int64 {
        let d = Array(SHA256.hash(data: Data(psk.utf8)))
        var v: UInt64 = 0
        for i in 0..<8 { v = v << 8 | UInt64(d[i]) }
        return Int64(bitPattern: v)
    }

    /// ClientHello table hint (sent only when the node rotates between several custom tables).
    static func tableHint(psk: String, mode: String, uplinkPattern: String, downlinkPattern: String) -> UInt32 {
        let parts = ["sudoku-table-hint", psk, mode,
                     uplinkPattern.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
                     downlinkPattern.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()]
        let d = Array(SHA256.hash(data: Data(parts.joined(separator: "\u{0}").utf8)))
        return UInt32(d[0]) << 24 | UInt32(d[1]) << 16 | UInt32(d[2]) << 8 | UInt32(d[3])
    }

    static func hmac(_ key: Data, _ parts: [Data]) -> Data {
        var h = HMAC<SHA256>(key: SymmetricKey(data: key))
        for p in parts { h.update(data: p) }
        return Data(h.finalize())
    }

    /// HKDF-Expand (RFC 5869) for one 32-byte block: T(1) = HMAC(prk, info || 0x01).
    static func hkdfExpand32(prk: Data, info: String) -> Data {
        hmac(prk, [Data(info.utf8), Data([0x01])])
    }

    /// Handshake bases: HKDF-Expand(SHA-256(psk), "sudoku-psk-c2s" / "sudoku-psk-s2c").
    static func pskBases(_ psk: String) -> (c2s: Data, s2c: Data) {
        let prk = Data(SHA256.hash(data: Data(psk.utf8)))
        return (hkdfExpand32(prk: prk, info: "sudoku-psk-c2s"), hkdfExpand32(prk: prk, info: "sudoku-psk-s2c"))
    }

    /// Session bases after the hello exchange: PRK = HKDF-Extract(salt: SHA-256(psk), ikm: X25519 ‖ nonce).
    static func sessionBases(psk: String, shared: Data, nonce: Data) -> (c2s: Data, s2c: Data) {
        let salt = Data(SHA256.hash(data: Data(psk.utf8)))
        let prk = hmac(salt, [shared, nonce])
        return (hkdfExpand32(prk: prk, info: "sudoku-session-c2s"), hkdfExpand32(prk: prk, info: "sudoku-session-s2c"))
    }

    /// Per-epoch record key: HMAC-SHA256(base, "sudoku-record:" ‖ method ‖ BE32(epoch)).
    static func epochKey(base: Data, epoch: UInt32, method: String) -> Data {
        let e = Data([UInt8(epoch >> 24), UInt8((epoch >> 16) & 0xff), UInt8((epoch >> 8) & 0xff), UInt8(epoch & 0xff)])
        return hmac(base, [Data("sudoku-record:".utf8), Data(method.utf8), e])
    }
}

// MARK: - AEAD record layer

/// u16 BE body length ‖ header(epoch BE32 ‖ seq BE64) ‖ AEAD(nonce = header, aad = header). Per-direction
/// epoch keys rotate every 32 MiB of plaintext; receive enforces strict in-order seq. `none` is a raw
/// passthrough (no framing at all), like the official RecordConn.
final class NCSudokuRecordLayer {
    static let headerSize = 12
    static let tagSize = 16
    static let maxBody = 65535
    static let maxPlain = maxBody - headerSize - tagSize
    /// Plaintext bytes per send epoch (official KeyUpdateAfterBytes).
    static var keyUpdateAfterBytes: Int64 = 32 << 20

    let method: NCSudoku.AEADMethod
    private var sendBase: Data
    private var recvBase: Data
    private var sendEpoch: UInt32 = 0
    private var sendSeq: UInt64 = 0
    private var sendBytes: Int64 = 0
    private var sendUpdates: Int64 = 0
    private var sendKey: SymmetricKey?
    private var sendKeyEpoch: UInt32 = 0
    private var recvEpoch: UInt32 = 0
    private var recvSeq: UInt64 = 0
    private var recvInitialized = false
    private var recvKey: SymmetricKey?
    private var recvKeyEpoch: UInt32 = 0
    /// Decoded (obfuscation-free) bytes not yet forming a whole record.
    private var inbound = Data()

    init(method: NCSudoku.AEADMethod, send: Data, recv: Data) {
        self.method = method
        sendBase = send
        recvBase = recv
        resetCounters()
    }

    func rekey(send: Data, recv: Data) {
        sendBase = send
        recvBase = recv
        sendKey = nil
        recvKey = nil
        resetCounters()
    }

    private func resetCounters() {
        sendEpoch = Self.randomNonZero32()
        sendSeq = Self.randomNonZero64()
        sendBytes = 0
        sendUpdates = 0
        recvEpoch = 0
        recvSeq = 0
        recvInitialized = false
    }

    static func randomNonZero32() -> UInt32 {
        var g = SystemRandomNumberGenerator()
        while true {
            let v = UInt32(truncatingIfNeeded: g.next())
            if v != 0 && v != .max { return v }
        }
    }

    static func randomNonZero64() -> UInt64 {
        var g = SystemRandomNumberGenerator()
        while true {
            let v: UInt64 = g.next()
            if v != 0 && v != .max { return v }
        }
    }

    private func key(base: Data, epoch: UInt32) -> SymmetricKey {
        let k = NCSudokuKeys.epochKey(base: base, epoch: epoch, method: method.rawValue)
        return SymmetricKey(data: method == .aes128GCM ? k.prefix(16) : k)
    }

    private static func header(_ epoch: UInt32, _ seq: UInt64) -> Data {
        var h = Data(count: headerSize)
        for i in 0..<4 { h[i] = UInt8(truncatingIfNeeded: epoch >> UInt32(24 - 8 * i)) }
        for i in 0..<8 { h[4 + i] = UInt8(truncatingIfNeeded: seq >> UInt64(56 - 8 * i)) }
        return h
    }

    /// Plaintext → records (split at the 64 KiB body limit).
    func seal(_ plain: Data) throws -> Data {
        if method == .none { return plain }
        var out = Data()
        out.reserveCapacity(plain.count + (plain.count / Self.maxPlain + 1) * (2 + Self.headerSize + Self.tagSize))
        var off = plain.startIndex
        repeat {
            let n = min(Self.maxPlain, plain.endIndex - off)
            let chunk = plain[off..<(off + n)]
            if sendKey == nil || sendKeyEpoch != sendEpoch {
                sendKey = key(base: sendBase, epoch: sendEpoch)
                sendKeyEpoch = sendEpoch
            }
            let hdr = Self.header(sendEpoch, sendSeq)
            sendSeq &+= 1
            let combined: Data
            switch method {
            case .chacha20Poly1305:
                combined = try ChaChaPoly.seal(chunk, using: sendKey!, nonce: ChaChaPoly.Nonce(data: hdr),
                                               authenticating: hdr).combined
            case .aes128GCM:
                guard let c = try AES.GCM.seal(chunk, using: sendKey!, nonce: AES.GCM.Nonce(data: hdr),
                                               authenticating: hdr).combined else {
                    throw NCSudokuError.protocolError("AES-GCM nonce")
                }
                combined = c
            case .none:
                combined = Data(chunk)
            }
            out.append(UInt8(combined.count >> 8))
            out.append(UInt8(combined.count & 0xff))
            out.append(combined)
            off += n
            bumpSendEpoch(n)
        } while off < plain.endIndex
        return out
    }

    private func bumpSendEpoch(_ added: Int) {
        let ku = Self.keyUpdateAfterBytes
        guard ku > 0 else { return }
        sendBytes += Int64(added)
        if sendBytes < ku * (sendUpdates + 1) { return }
        sendEpoch &+= 1
        sendUpdates += 1
        sendSeq = Self.randomNonZero64()
    }

    func append(_ decoded: Data) {
        guard !decoded.isEmpty else { return }
        inbound.append(decoded)
    }

    /// Next whole record's plaintext, nil when more bytes are needed. For `none`, everything buffered.
    func nextRecord() throws -> Data? {
        if method == .none {
            guard !inbound.isEmpty else { return nil }
            let out = inbound
            inbound = Data()
            return out
        }
        guard inbound.count >= 2 else { return nil }
        let s = inbound.startIndex
        let bodyLen = Int(inbound[s]) << 8 | Int(inbound[s + 1])
        guard bodyLen >= Self.headerSize + Self.tagSize else {
            throw NCSudokuError.protocolError("记录过短 (\(bodyLen))")
        }
        guard inbound.count >= 2 + bodyLen else { return nil }
        let body = inbound.subdata(in: (s + 2)..<(s + 2 + bodyLen))
        if inbound.count == 2 + bodyLen {
            inbound = Data()
        } else {
            inbound = inbound.subdata(in: (s + 2 + bodyLen)..<inbound.endIndex)
        }
        var epoch: UInt32 = 0
        var seq: UInt64 = 0
        for i in 0..<4 { epoch = epoch << 8 | UInt32(body[i]) }
        for i in 4..<12 { seq = seq << 8 | UInt64(body[i]) }
        if recvInitialized {
            if epoch < recvEpoch { throw NCSudokuError.protocolError("重放的 epoch") }
            if epoch == recvEpoch && seq != recvSeq { throw NCSudokuError.protocolError("记录乱序") }
            if epoch > recvEpoch && epoch - recvEpoch > 8 { throw NCSudokuError.protocolError("epoch 跳变过大") }
        }
        if recvKey == nil || recvKeyEpoch != epoch {
            recvKey = key(base: recvBase, epoch: epoch)
            recvKeyEpoch = epoch
        }
        let hdr = body.prefix(Self.headerSize)
        let plain: Data
        do {
            switch method {
            case .chacha20Poly1305:
                plain = try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: body), using: recvKey!, authenticating: hdr)
            case .aes128GCM:
                plain = try AES.GCM.open(AES.GCM.SealedBox(combined: body), using: recvKey!, authenticating: hdr)
            case .none:
                plain = body
            }
        } catch {
            throw NCSudokuError.authFailed
        }
        recvEpoch = epoch
        recvSeq = seq &+ 1
        recvInitialized = true
        return plain
    }

    /// Every whole record's plaintext buffered so far.
    func drain() throws -> Data {
        var out = Data()
        while let r = try nextRecord() { out.append(r) }
        return out
    }
}

// MARK: - KIP control plane

enum NCSudokuKIP {
    static let magic: [UInt8] = [0x6b, 0x69, 0x70] // "kip"

    enum MessageType: UInt8 {
        case clientHello = 0x01
        case serverHello = 0x02
        case openTCP = 0x10
        case startMux = 0x11
        case startUoT = 0x12
        case startRev = 0x13
        case keepAlive = 0x14
    }

    /// OpenTCP | Mux | UoT | Reverse | KeepAlive — what the official client offers.
    static let featuresAll: UInt32 = 0x1f

    /// "kip" ‖ type ‖ u16 BE payload length ‖ payload.
    static func buildMessage(type: MessageType, payload: Data) -> Data {
        var out = Data(capacity: 6 + payload.count)
        out.append(contentsOf: magic)
        out.append(type.rawValue)
        out.append(UInt8((payload.count >> 8) & 0xff))
        out.append(UInt8(payload.count & 0xff))
        out.append(payload)
        return out
    }

    /// ClientHello payload: timestamp BE64 ‖ user hash 8 ‖ nonce 16 ‖ X25519 pub 32 ‖ features BE32
    /// [‖ table hint BE32].
    static func clientHelloPayload(timestamp: UInt64, userHash: Data, nonce: Data, clientPub: Data,
                                   features: UInt32 = featuresAll, tableHint: UInt32? = nil) -> Data {
        var p = Data(capacity: 72)
        for i in (0..<8).reversed() { p.append(UInt8(truncatingIfNeeded: timestamp >> UInt64(i * 8))) }
        p.append(userHash.prefix(8))
        p.append(nonce.prefix(16))
        p.append(clientPub.prefix(32))
        for i in (0..<4).reversed() { p.append(UInt8(truncatingIfNeeded: features >> UInt32(i * 8))) }
        if let h = tableHint {
            for i in (0..<4).reversed() { p.append(UInt8(truncatingIfNeeded: h >> UInt32(i * 8))) }
        }
        return p
    }

    /// ServerHello payload: nonce 16 ‖ X25519 pub 32 ‖ selected features BE32 — exactly 52 bytes.
    static func parseServerHello(payload: Data, expectedNonce: Data) throws -> (serverPub: Data, features: UInt32) {
        guard payload.count == 52 else { throw NCSudokuError.protocolError("ServerHello 长度 \(payload.count) ≠ 52") }
        let p = Data(payload)
        guard p.prefix(16) == expectedNonce.prefix(16) else { throw NCSudokuError.handshake("ServerHello nonce 不匹配") }
        let f = UInt32(p[48]) << 24 | UInt32(p[49]) << 16 | UInt32(p[50]) << 8 | UInt32(p[51])
        return (p.subdata(in: 16..<48), f)
    }

    /// OpenTCP: SOCKS5-style ATYP ‖ address ‖ BE16 port.
    static func openTCP(target: NCTarget) -> Data {
        buildMessage(type: .openTCP, payload: target.atypEncoded)
    }

    /// (type, payload, consumed) of the first whole message in `buffer`; nil when incomplete.
    static func unwrapMessage(from buffer: Data) throws -> (type: UInt8, payload: Data, consumed: Int)? {
        let b = Data(buffer)
        guard b.count >= 3 else { return nil }
        guard Array(b.prefix(3)) == magic else { throw NCSudokuError.protocolError("KIP magic 错误") }
        guard b.count >= 6 else { return nil }
        let len = Int(b[4]) << 8 | Int(b[5])
        guard b.count >= 6 + len else { return nil }
        return (b[3], b.subdata(in: 6..<(6 + len)), 6 + len)
    }
}

// MARK: - Legacy HTTP mask

enum NCSudokuHTTPMask {
    private static let paths = ["/api/v1/upload", "/upload", "/api/report", "/v1/collect", "/sync", "/data/push"]
    private static let agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    ]

    /// The legacy camouflage prelude: one plausible HTTP/1.1 POST head (the server consumes it up to the
    /// blank line). `host` is server:port like the official client; `pathRoot` prefixes the path.
    static func legacyRequest(host: String, pathRoot: String) -> Data {
        var path = paths.randomElement() ?? "/upload"
        let root = pathRoot.trimmingCharacters(in: CharacterSet(charactersIn: "/ \t"))
        if !root.isEmpty { path = "/" + root + path }
        let ua = agents.randomElement() ?? agents[0]
        let length = Int.random(in: 4096...(10 << 20))
        let head = "POST \(path) HTTP/1.1\r\nHost: \(host)\r\nUser-Agent: \(ua)\r\nAccept: */*\r\n"
            + "Accept-Language: en-US,en;q=0.9\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\n"
            + "Cache-Control: no-cache\r\nPragma: no-cache\r\nContent-Type: application/octet-stream\r\n"
            + "Content-Length: \(length)\r\n\r\n"
        return Data(head.utf8)
    }
}

// MARK: - Relay stream

final class NCSudokuRelay: NCRelayStream {
    /// Plaintext per encode step: bounds the transient wire buffer (≈6× expansion with padding).
    private static let sendChunk = 8 * 1024

    private let raw: NCRelayStream
    private let options: NCSudoku.Options
    private let target: NCTarget
    private let queue: DispatchQueue
    private let psk: String
    private let userHash: Data
    private let encoder: NCSudokuEncoder
    private let decoder: NCSudokuStreamDecoder
    private let records: NCSudokuRecordLayer
    private let tableHint: UInt32?
    private let ephemeral = Curve25519.KeyAgreement.PrivateKey()
    private let nonce: Data
    /// Handshake-time plaintext (none mode) not yet consumed by the ServerHello parser.
    private var handshakeBuf = Data()
    /// Payload decoded during the handshake, delivered by the first receive.
    private var early = Data()
    private var isCancelled = false

    init(raw: NCRelayStream, options: NCSudoku.Options, target: NCTarget, queue: DispatchQueue) throws {
        self.raw = raw
        self.options = options
        self.target = target
        self.queue = queue
        let norm = NCSudokuKeys.normalize(options.key)
        psk = norm.psk
        userHash = norm.userHash

        // Table selection: one table, or a random pick among custom-tables (then the ClientHello carries
        // the hint so the server can switch its downlink table).
        let patterns = options.customTables.isEmpty ? [options.customTable ?? ""] : options.customTables
        let pattern = patterns.randomElement() ?? ""
        let mode = options.mode
        let upPattern = mode.uplinkASCII ? "" : pattern
        let downPattern = mode.downlinkASCII ? "" : pattern
        func layout(ascii: Bool, pattern: String) throws -> NCSudokuLayout {
            if ascii { return .ascii() }
            if pattern.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return .entropy() }
            guard let l = NCSudokuLayout.custom(pattern) else { throw NCSudokuError.badConfig("custom-table \(pattern)") }
            return l
        }
        let core = NCSudokuTableCache.core(seed: NCSudokuKeys.tableSeed(psk))
        let up = NCSudokuTable(core: core, layout: try layout(ascii: mode.uplinkASCII, pattern: upPattern))
        let down = mode.uplinkASCII == mode.downlinkASCII
            ? up : NCSudokuTable(core: core, layout: try layout(ascii: mode.downlinkASCII, pattern: downPattern))
        encoder = NCSudokuEncoder(table: up, paddingMin: options.paddingMin, paddingMax: options.paddingMax)
        decoder = options.pureDownlink ? NCSudokuClassicDecoder(table: down) : NCSudokuPackedDecoder(layout: down.layout)
        tableHint = patterns.count > 1
            ? NCSudokuKeys.tableHint(psk: psk, mode: mode.canonical, uplinkPattern: upPattern, downlinkPattern: downPattern)
            : nil
        let bases = NCSudokuKeys.pskBases(psk)
        records = NCSudokuRecordLayer(method: options.aead, send: bases.c2s, recv: bases.s2c)
        var n = [UInt8](repeating: 0, count: 16)
        var g = SystemRandomNumberGenerator()
        for i in 0..<16 { n[i] = UInt8(truncatingIfNeeded: g.next()) }
        nonce = Data(n)
    }

    /// Legacy mask → ClientHello → ServerHello → rekey → OpenTCP.
    func handshake(completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let deadline = NCHandshakeDeadline(queue: queue, seconds: 10, raw: raw, what: "sudoku") { stream, err in
            completion(stream, err)
        }
        var first = Data()
        if options.httpMaskEnabled {
            first.append(NCSudokuHTTPMask.legacyRequest(host: options.serverHostPort, pathRoot: options.pathRoot))
        }
        let hello = NCSudokuKIP.buildMessage(type: .clientHello, payload: NCSudokuKIP.clientHelloPayload(
            timestamp: UInt64(max(0, Date().timeIntervalSince1970)), userHash: userHash, nonce: nonce,
            clientPub: ephemeral.publicKey.rawRepresentation, tableHint: tableHint))
        do {
            first.append(encoder.encode(try records.seal(hello)))
        } catch {
            deadline.finish(nil, error)
            return
        }
        raw.send(first)
        readServerHello(deadline)
    }

    private func readServerHello(_ deadline: NCHandshakeDeadline) {
        // Strong self: until the handshake finishes nothing else owns the relay (the one-shot receive callback
        // and the deadline end the cycle).
        raw.receive { data, err in
            guard !deadline.isDone else { return }
            if let err {
                deadline.finish(nil, NCSudokuError.handshake(err.localizedDescription))
                return
            }
            guard let data, !data.isEmpty else {
                deadline.finish(nil, NCSudokuError.serverClosed)
                return
            }
            do {
                self.records.append(try self.decoder.feed(data))
                guard let sh = try self.takeServerHello() else {
                    self.readServerHello(deadline)
                    return
                }
                let (serverPub, _) = try NCSudokuKIP.parseServerHello(payload: sh, expectedNonce: self.nonce)
                let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverPub)
                let secret = try self.ephemeral.sharedSecretFromKeyAgreement(with: peer)
                let shared = secret.withUnsafeBytes { Data($0) }
                let session = NCSudokuKeys.sessionBases(psk: self.psk, shared: shared, nonce: self.nonce)
                self.records.rekey(send: session.c2s, recv: session.s2c)
                // Records after the ServerHello are sealed with the session keys.
                self.early.append(try self.records.drain())
                let open = try self.records.seal(NCSudokuKIP.openTCP(target: self.target))
                self.raw.send(self.encoder.encode(open))
                deadline.finish(self, nil)
            } catch let e as NCSudokuError {
                deadline.finish(nil, e)
            } catch NCSudokuWireError.invalidPuzzle {
                deadline.finish(nil, NCSudokuError.authFailed)
            } catch {
                deadline.finish(nil, NCSudokuError.handshake(error.localizedDescription))
            }
        }
    }

    /// The ServerHello payload once a whole KIP message has arrived (AEAD: exactly one record, opened with the
    /// handshake keys; none: raw bytes). Anything after it stays for the session keys / the payload.
    private func takeServerHello() throws -> Data? {
        if records.method == .none {
            if let r = try records.nextRecord() { handshakeBuf.append(r) }
            guard let msg = try NCSudokuKIP.unwrapMessage(from: handshakeBuf) else { return nil }
            guard msg.type == NCSudokuKIP.MessageType.serverHello.rawValue else {
                throw NCSudokuError.handshake("意外的 KIP 消息 0x\(String(msg.type, radix: 16))")
            }
            early.append(handshakeBuf.subdata(in: (handshakeBuf.startIndex + msg.consumed)..<handshakeBuf.endIndex))
            handshakeBuf = Data()
            return msg.payload
        }
        guard let record = try records.nextRecord() else { return nil }
        guard let msg = try NCSudokuKIP.unwrapMessage(from: record) else {
            throw NCSudokuError.protocolError("ServerHello 不完整")
        }
        guard msg.type == NCSudokuKIP.MessageType.serverHello.rawValue else {
            throw NCSudokuError.handshake("意外的 KIP 消息 0x\(String(msg.type, radix: 16))")
        }
        if msg.consumed < record.count { early.append(record.subdata(in: msg.consumed..<record.count)) }
        return msg.payload
    }

    // MARK: NCRelayStream

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        guard !isCancelled, !data.isEmpty else { once.call(); return }
        do {
            var off = data.startIndex
            while off < data.endIndex {
                let end = min(off + Self.sendChunk, data.endIndex)
                let wire = encoder.encode(try records.seal(data.subdata(in: off..<end)))
                if end == data.endIndex {
                    raw.send(wire, completion: once.call)
                } else {
                    raw.send(wire)
                }
                off = end
            }
        } catch {
            raw.cancel()
            once.call()
        }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        guard !isCancelled else { handler(nil, nil); return }
        if !early.isEmpty {
            let out = early
            early = Data()
            handler(out, nil)
            return
        }
        raw.receive { [weak self] data, err in
            guard let self else { handler(nil, err); return }
            guard let data, !data.isEmpty else { handler(nil, err); return }
            do {
                self.records.append(try self.decoder.feed(data))
                let plain = try self.records.drain()
                if plain.isEmpty {
                    self.receive(handler)
                } else {
                    handler(plain, nil)
                }
            } catch {
                self.raw.cancel()
                handler(nil, error)
            }
        }
    }

    func cancel() {
        isCancelled = true
        raw.cancel()
    }
}
