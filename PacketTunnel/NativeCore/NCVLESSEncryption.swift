import Foundation
import CryptoKit

/// VLESS encryption client "mlkem768x25519plus.<native|xorpub|random>.<1rtt|0rtt>.<keys…>[.<padding>]"
/// (feat/nc-proto A6, based on astemo6/Muse NativeCore), ported from mihomo v1.19.33 transport/vless/encryption
/// (client.go / common.go / xor.go, itself from Xray-core). ML-KEM-768 is NCMLKEM768 (pure Swift), X25519 /
/// AES-GCM from CryptoKit, BLAKE3 derive_key from NCBlake3. AEAD is AES-256-GCM (Apple CPUs have AES + PMULL,
/// i.e. mihomo's HasAESGCMHardwareSupport = true).
final class NCVLESSEncClient {
    enum Key { case x25519(Curve25519.KeyAgreement.PublicKey), mlkem([UInt8]) }
    let keys: [Key]
    let keyBytes: [Data]
    let hash32s: [Data]
    let relaysLength: Int
    let xorMode: Int
    let zeroRTT: Bool
    let paddingLens: [[Int]]
    let paddingGaps: [[Int]]

    // 0-RTT ticket cache (ClientInstance fields)
    private let lock = NSLock()
    var expire = Date.distantPast
    var pfsKey = Data()
    var ticket = Data()

    /// nil + nil = no encryption ("" / "none"); nil + reason = unsupported value.
    static func parse(_ s: String) -> (NCVLESSEncClient?, String?) {
        if s.isEmpty || s == "none" { return (nil, nil) }
        let parts = s.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 4, parts[0] == "mlkem768x25519plus" else { return (nil, "VLESS encryption 值无效") }
        let xor: Int
        switch parts[1] {
        case "native": xor = 0
        case "xorpub": xor = 1
        case "random": xor = 2
        default: return (nil, "VLESS encryption 值无效")
        }
        let zero: Bool
        switch parts[2] {
        case "1rtt": zero = false
        case "0rtt": zero = true
        default: return (nil, "VLESS encryption 值无效")
        }
        var keys: [Key] = [], raw: [Data] = [], paddings: [String] = []
        for r in parts[3...] {
            if r.count < 20 { paddings.append(r); continue }
            guard let b = Self.rawURLBase64(r) else { return (nil, "VLESS encryption 密钥无效") }
            if b.count == 32, let k = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: b) {
                keys.append(.x25519(k))
            } else if b.count == NCMLKEM768.encapsulationKeySize {
                keys.append(.mlkem([UInt8](b)))
            } else {
                return (nil, "VLESS encryption 密钥长度无效")
            }
            raw.append(b)
        }
        guard !keys.isEmpty else { return (nil, "VLESS encryption 缺少密钥") }
        var lens: [[Int]] = [], gaps: [[Int]] = []
        if !paddings.isEmpty {
            var maxLen = 0
            for (i, p) in paddings.joined(separator: ".").split(separator: ".").enumerated() {
                let x = p.split(separator: "-", omittingEmptySubsequences: false).map { Int($0) }
                guard x.count >= 3, let a = x[0], let b = x[1], let c = x[2] else { return (nil, "VLESS encryption padding 无效") }
                if i == 0 && (a < 100 || b < 35 || c < 35) { return (nil, "VLESS encryption padding 无效") }
                if i % 2 == 0 { lens.append([a, b, c]); maxLen += max(b, c) } else { gaps.append([a, b, c]) }
            }
            if maxLen > 18 + 65535 { return (nil, "VLESS encryption padding 过长") }
        }
        let rl = keys.reduce(0) { acc, k in
            if case .x25519 = k { return acc + 64 }
            return acc + 1088 + 32
        } - 32
        let c = NCVLESSEncClient(keys: keys, keyBytes: raw, relaysLength: rl, xorMode: xor, zeroRTT: zero,
                                 paddingLens: lens, paddingGaps: gaps)
        return (c, nil)
    }

    private init(keys: [Key], keyBytes: [Data], relaysLength: Int, xorMode: Int, zeroRTT: Bool,
                 paddingLens: [[Int]], paddingGaps: [[Int]]) {
        self.keys = keys
        self.keyBytes = keyBytes
        hash32s = keyBytes.map { Data(NCBlake3.hash([UInt8]($0))) }
        self.relaysLength = relaysLength
        self.xorMode = xorMode
        self.zeroRTT = zeroRTT
        self.paddingLens = paddingLens
        self.paddingGaps = paddingGaps
    }

    static func rawURLBase64(_ s: String) -> Data? {
        var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while t.count % 4 != 0 { t += "=" }
        return Data(base64Encoded: t)
    }

    static func randBetween(_ a: Int, _ b: Int) -> Int {
        if a == b { return a }
        let lo = min(a, b), hi = max(a, b)
        return lo + Int.random(in: 0..<(hi - lo))
    }

    /// CreatPadding: (total, lens, gaps in ms).
    func createPadding() -> (Int, [Int], [Int]) {
        var pl = paddingLens, pg = paddingGaps
        if pl.isEmpty { pl = [[100, 111, 1111], [50, 0, 3333]]; pg = [[75, 0, 111]] }
        var total = 0
        var lens: [Int] = [], gaps: [Int] = []
        for y in pl {
            var l = 0
            if y[0] >= Self.randBetween(0, 100) { l = Self.randBetween(y[1], y[2]) }
            lens.append(l); total += l
        }
        for y in pg {
            var g = 0
            if y[0] >= Self.randBetween(0, 100) { g = Self.randBetween(y[1], y[2]) }
            gaps.append(g)
        }
        return (total, lens, gaps)
    }

    func ticketState() -> (Data, Data)? {
        lock.lock(); defer { lock.unlock() }
        return Date() < expire ? (pfsKey, ticket) : nil
    }
    func storeTicket(pfs: Data, ticket t: Data, seconds: Int) {
        lock.lock(); defer { lock.unlock() }
        expire = Date().addingTimeInterval(TimeInterval(seconds))
        pfsKey = pfs
        ticket = t
    }
    func expireIfPrefix(_ united: Data) {
        lock.lock(); defer { lock.unlock() }
        if !pfsKey.isEmpty && united.starts(with: pfsKey) { expire = Date() }
    }
}

/// AES-256-CTR over the BLAKE3-derived key ("VLESS" context), mirroring encryption.NewCTR.
final class NCVLESSCTR {
    private let c: NCSSStreamCipher
    init(key: Data, iv: Data) {
        let k = Data(NCBlake3.deriveKey(context: "VLESS", material: [UInt8](key)))
        c = NCSSStreamCipher(method: "aes-256-ctr", key: k)!
        c.forEncryption = true
        c.setIV(iv.prefix(16))
    }
    func xor(_ d: Data) -> Data { c.process(d) }
}

/// AEAD with an incrementing 12-byte big-endian nonce (encryption.AEAD).
final class NCVLESSAEAD {
    private let key: SymmetricKey
    private(set) var nonce = [UInt8](repeating: 0, count: 12)
    static let maxNonce = [UInt8](repeating: 0xff, count: 12)

    init(ctx: Data, key unitedKey: Data) {
        key = SymmetricKey(data: NCBlake3.deriveKey(contextBytes: [UInt8](ctx), material: [UInt8](unitedKey)))
    }

    private func next() -> [UInt8] {
        var i = 11
        while i >= 0 { nonce[i] &+= 1; if nonce[i] != 0 { break }; i -= 1 }
        return nonce
    }

    func seal(_ plain: Data, aad: Data = Data(), explicitNonce: [UInt8]? = nil) -> Data {
        let n = explicitNonce ?? next()
        guard let nn = try? AES.GCM.Nonce(data: n),
              let box = try? AES.GCM.seal(plain, using: key, nonce: nn, authenticating: aad) else { return Data() }
        return box.ciphertext + box.tag
    }

    func open(_ sealed: Data, aad: Data = Data(), explicitNonce: [UInt8]? = nil) -> Data? {
        let n = explicitNonce ?? next()
        guard sealed.count >= 16, let nn = try? AES.GCM.Nonce(data: n),
              let box = try? AES.GCM.SealedBox(nonce: nn, ciphertext: sealed.dropLast(16), tag: sealed.suffix(16)) else {
            return nil
        }
        return try? AES.GCM.open(box, using: key, authenticating: aad)
    }
}

/// The encrypted VLESS conn (CommonConn + XorConn for "random") as an NCRelayStream.
final class NCVLESSEncStream: NCRelayStream {
    private let raw: NCRelayStream
    private let inst: NCVLESSEncClient
    private let queue: DispatchQueue
    private var united = Data()
    private var preWrite: Data?
    private var aead: NCVLESSAEAD?
    private var peerAEAD: NCVLESSAEAD?
    private var peerPaddingLen: Int?
    private var zeroRTTClient = false
    // XorConn ("random" mode)
    private var outCTR: NCVLESSCTR?, inCTR: NCVLESSCTR?
    private var outSkip = 0, inSkip = 0
    private var outHeader = Data(), inHeader = Data()
    // read side
    private var inbuf = Data()
    private var outQueue: [Data] = []
    private var failure: Error?
    private var eof = false
    private var handshakeDone: ((Error?) -> Void)?
    private var hsStage = 0 // 1-RTT: 1 = server pfs key, 2 = ticket, 3 = length, 4 = done
    private var hsKey: NCMLKEM768.DecapsulationKey?
    private var hsX25519: Curve25519.KeyAgreement.PrivateKey?
    private var hsNfsAEAD: NCVLESSAEAD?
    private var hsNfsKey = Data()
    private var hsPfsPublic = Data()
    private var hsIV = Data()

    init(raw: NCRelayStream, inst: NCVLESSEncClient, queue: DispatchQueue) {
        self.raw = raw
        self.inst = inst
        self.queue = queue
    }

    static func err(_ s: String) -> NSError {
        NSError(domain: "NativeCore.VLESSEnc", code: 1, userInfo: [NSLocalizedDescriptionKey: "vless encryption: " + s])
    }

    // MARK: Handshake

    func handshake(_ done: @escaping (Error?) -> Void) {
        let iv = NCConnector.randomData(16)
        hsIV = iv
        var relays = Data(count: inst.relaysLength)
        var off = 0
        var nfsKey = Data()
        var lastCTR: NCVLESSCTR?
        for (j, k) in inst.keys.enumerated() {
            var index = 32
            switch k {
            case .x25519(let pub):
                let eph = Curve25519.KeyAgreement.PrivateKey()
                relays.replaceSubrange(off..<(off + 32), with: eph.publicKey.rawRepresentation)
                guard let s = try? eph.sharedSecretFromKeyAgreement(with: pub) else { done(Self.err("x25519")); return }
                nfsKey = s.withUnsafeBytes { Data($0) }
            case .mlkem(let ek):
                guard let (key, ct) = NCMLKEM768.encapsulate(ek: ek) else { done(Self.err("ML-KEM key")); return }
                nfsKey = Data(key)
                relays.replaceSubrange(off..<(off + 1088), with: ct)
                index = 1088
            }
            if inst.xorMode > 0 {
                let x = NCVLESSCTR(key: inst.keyBytes[j], iv: iv).xor(relays.subdata(in: off..<(off + index)))
                relays.replaceSubrange(off..<(off + index), with: x)
            }
            if let lc = lastCTR {
                relays.replaceSubrange(off..<(off + 32), with: lc.xor(relays.subdata(in: off..<(off + 32))))
            }
            if j == inst.keys.count - 1 { break }
            let lc = NCVLESSCTR(key: nfsKey, iv: iv)
            relays.replaceSubrange((off + index)..<(off + index + 32), with: lc.xor(inst.hash32s[j + 1]))
            lastCTR = lc
            off += index + 32
        }
        hsNfsKey = nfsKey
        let nfsAEAD = NCVLESSAEAD(ctx: iv, key: nfsKey)
        let head = iv + relays

        if inst.zeroRTT, let (pfs, ticket) = inst.ticketState() {
            zeroRTTClient = true
            united = pfs + nfsKey
            var pre = head
            pre += nfsAEAD.seal(Self.len2(32))
            let sealedTicket = nfsAEAD.seal(ticket)
            pre += sealedTicket
            preWrite = pre
            aead = NCVLESSAEAD(ctx: sealedTicket, key: united)
            if inst.xorMode == 2 {
                outCTR = NCVLESSCTR(key: united, iv: iv)
                outSkip = pre.count
                inSkip = 16
            }
            done(nil)
            return
        }

        // 1-RTT: PFS key exchange + padding, sent in fragments with gaps.
        let dk = NCMLKEM768.generateKey()
        let x = Curve25519.KeyAgreement.PrivateKey()
        hsKey = dk; hsX25519 = x
        let pfsPublic = Data(dk.ek) + x.publicKey.rawRepresentation
        hsPfsPublic = pfsPublic
        let pfsLen = 18 + 1184 + 32 + 16
        var hello = head
        hello += nfsAEAD.seal(Self.len2(pfsLen - 18))
        hello += nfsAEAD.seal(pfsPublic)
        let (paddingLength, lens0, gaps) = inst.createPadding()
        if paddingLength >= 34 {
            hello += nfsAEAD.seal(Self.len2(paddingLength - 18))
            hello += nfsAEAD.seal(Data(count: paddingLength - 34))
        }
        hsNfsAEAD = nfsAEAD
        var lens = lens0
        lens[0] += head.count + pfsLen
        handshakeDone = done
        hsStage = 1
        sendFragments(hello, lens: lens, gaps: gaps, index: 0)
        pumpHandshake()
    }

    private func sendFragments(_ data: Data, lens: [Int], gaps: [Int], index: Int) {
        var rest = data
        var i = index
        while i < lens.count {
            let l = min(lens[i], rest.count)
            if l > 0 { raw.send(Data(rest.prefix(l))); rest = Data(rest.dropFirst(l)) }
            if i < gaps.count, gaps[i] > 0, i + 1 < lens.count {
                let tail = rest
                let next = i + 1
                queue.asyncAfter(deadline: .now() + .milliseconds(gaps[i])) { [weak self] in
                    self?.sendFragments(tail, lens: lens, gaps: gaps, index: next)
                }
                return
            }
            i += 1
        }
        if !rest.isEmpty { raw.send(rest) }
    }

    private static func len2(_ l: Int) -> Data { Data([UInt8((l >> 8) & 0xff), UInt8(l & 0xff)]) }
    private static func readLen(_ d: Data) -> Int { Int(d[d.startIndex]) << 8 | Int(d[d.startIndex + 1]) }

    private func pumpHandshake() {
        raw.receive { [weak self] data, error in
            guard let self, let done = self.handshakeDone else { return }
            guard let data else { self.handshakeDone = nil; done(error ?? Self.err("closed during handshake")); return }
            self.inbuf.append(data)
            do {
                if try self.stepHandshake() {
                    self.handshakeDone = nil
                    done(nil)
                    return
                }
            } catch {
                self.handshakeDone = nil
                self.raw.cancel()
                done(error)
                return
            }
            self.pumpHandshake()
        }
    }

    /// true when the 1-RTT handshake finished (bytes beyond it stay in inbuf).
    private func stepHandshake() throws -> Bool {
        while true {
            switch hsStage {
            case 1:
                let n = 1088 + 32 + 16
                guard inbuf.count >= n else { return false }
                let enc = Data(inbuf.prefix(n)); inbuf = Data(inbuf.dropFirst(n))
                guard let nfs = hsNfsAEAD, let plain = nfs.open(enc, explicitNonce: NCVLESSAEAD.maxNonce),
                      let dk = hsKey, let x = hsX25519 else { throw Self.err("server key open failed") }
                guard let mk = NCMLKEM768.decapsulate(dk, ciphertext: [UInt8](plain.prefix(1088))),
                      let peer = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: plain.subdata(in: 1088..<1120)),
                      let xs = try? x.sharedSecretFromKeyAgreement(with: peer) else { throw Self.err("PFS key exchange failed") }
                let pfs = Data(mk) + xs.withUnsafeBytes { Data($0) }
                pfsKeyForTicket = pfs
                united = pfs + hsNfsKey
                aead = NCVLESSAEAD(ctx: hsPfsPublic, key: united)
                peerAEAD = NCVLESSAEAD(ctx: plain.prefix(1120), key: united)
                hsKey = nil; hsX25519 = nil
                hsStage = 2
            case 2:
                guard inbuf.count >= 32 else { return false }
                let enc = Data(inbuf.prefix(32)); inbuf = Data(inbuf.dropFirst(32))
                guard let t = peerAEAD?.open(enc) else { throw Self.err("ticket open failed") }
                let seconds = Self.readLen(t)
                if inst.zeroRTT && seconds > 0 {
                    inst.storeTicket(pfs: pfsKeyForTicket, ticket: Data(enc.prefix(16)), seconds: seconds)
                }
                ticketIV = Data(enc.prefix(16))
                hsStage = 3
            case 3:
                guard inbuf.count >= 18 else { return false }
                let enc = Data(inbuf.prefix(18)); inbuf = Data(inbuf.dropFirst(18))
                guard let l = peerAEAD?.open(enc) else { throw Self.err("length open failed") }
                let length = Self.readLen(l)
                peerPaddingLen = length
                if inst.xorMode == 2 {
                    outCTR = NCVLESSCTR(key: united, iv: hsIV)
                    inCTR = NCVLESSCTR(key: united, iv: ticketIV)
                    outSkip = 0
                    inSkip = length
                    // Bytes already buffered past the handshake go through the xor filter now.
                    if !inbuf.isEmpty { inbuf = xorIn(inbuf) }
                }
                hsStage = 4
                hsNfsAEAD = nil
                return true
            default:
                return true
            }
        }
    }

    private var pfsKeyForTicket = Data()
    private var ticketIV = Data()

    // MARK: XorConn

    private func xorOut(_ b: Data) -> Data {
        guard let ctr = outCTR else { return b }
        var out = [UInt8](b)
        var p = 0
        while true {
            let rem = out.count - p
            if rem <= outSkip { outSkip -= rem; break }
            p += outSkip
            outSkip = 0
            let need = 5 - outHeader.count
            if out.count - p < need {
                outHeader.append(contentsOf: out[p...])
                let x = ctr.xor(Data(out[p...]))
                out.replaceSubrange(p..<out.count, with: x)
                break
            }
            let hdr = outHeader + Data(out[p..<(p + need)])
            outSkip = Self.headerLength(hdr) ?? 0
            outHeader = Data()
            out.replaceSubrange(p..<(p + need), with: ctr.xor(Data(out[p..<(p + need)])))
            p += need
        }
        return Data(out)
    }

    private func xorIn(_ b: Data) -> Data {
        var out = [UInt8](b)
        var p = 0
        while true {
            let rem = out.count - p
            if rem <= inSkip { inSkip -= rem; break }
            p += inSkip
            inSkip = 0
            guard let ctr = inCTR else { break } // 0-RTT: peer CTR set once the server random arrives
            let need = 5 - inHeader.count
            if out.count - p < need {
                let x = ctr.xor(Data(out[p...]))
                out.replaceSubrange(p..<out.count, with: x)
                inHeader.append(x)
                break
            }
            let x = ctr.xor(Data(out[p..<(p + need)]))
            out.replaceSubrange(p..<(p + need), with: x)
            inSkip = Self.headerLength(inHeader + x) ?? 0
            inHeader = Data()
            p += need
        }
        return Data(out)
    }

    /// DecodeHeader: record length for a valid 23/3/3 header with 17…17000 bytes, else nil.
    static func headerLength(_ h: Data) -> Int? {
        let s = h.startIndex
        guard h.count >= 5 else { return nil }
        let l = Int(h[s + 3]) << 8 | Int(h[s + 4])
        guard h[s] == 23, h[s + 1] == 3, h[s + 2] == 3, l >= 17, l <= 17000 else { return nil }
        return l
    }

    // MARK: NCRelayStream

    func send(_ data: Data) {
        guard aead != nil, failure == nil else { return }
        var rest = data[...]
        while !rest.isEmpty {
            let chunk = Data(rest.prefix(8192))
            rest = rest.dropFirst(chunk.count)
            var header = Data([23, 3, 3])
            header += Self.len2(chunk.count + 16)
            guard let aead = self.aead else { return }
            let rollover = aead.nonce == NCVLESSAEAD.maxNonce
            var record = header + aead.seal(chunk, aad: header)
            if rollover { self.aead = NCVLESSAEAD(ctx: record, key: united) }
            if let pre = preWrite { record = pre + record; preWrite = nil }
            raw.send(xorOut(record))
        }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        if !outQueue.isEmpty { handler(outQueue.removeFirst(), nil); return }
        if let failure { handler(nil, failure); return }
        do {
            if let d = try parse() { handler(d, nil); return }
        } catch {
            failure = error
            handler(nil, error)
            return
        }
        if eof { handler(nil, nil); return }
        raw.receive { [weak self] data, error in
            guard let self else { handler(nil, error); return }
            guard let data else { self.eof = true; self.receive(handler); if error != nil { self.failure = error }; return }
            self.inbuf.append(self.inst.xorMode == 2 ? self.xorIn(data) : data)
            self.receive(handler)
        }
    }

    /// Next plaintext record, or nil when more bytes are needed.
    private func parse() throws -> Data? {
        if peerAEAD == nil { // 0-RTT: the server random comes first
            guard inbuf.count >= 16 else { return nil }
            let sr = Data(inbuf.prefix(16)); inbuf = Data(inbuf.dropFirst(16))
            peerAEAD = NCVLESSAEAD(ctx: sr, key: united)
            if inst.xorMode == 2 {
                inCTR = NCVLESSCTR(key: united, iv: sr)
                if !inbuf.isEmpty { inbuf = xorIn(inbuf) }
            }
        }
        if let pl = peerPaddingLen {
            guard inbuf.count >= pl else { return nil }
            let enc = Data(inbuf.prefix(pl)); inbuf = Data(inbuf.dropFirst(pl))
            guard peerAEAD?.open(enc) != nil else { throw Self.err("padding open failed") }
            peerPaddingLen = nil
        }
        guard inbuf.count >= 5 else { return nil }
        let header = Data(inbuf.prefix(5))
        guard let l = Self.headerLength(header) else {
            if zeroRTTClient {
                inst.expireIfPrefix(united)
                throw Self.err("new handshake needed")
            }
            throw Self.err("invalid header")
        }
        zeroRTTClient = false
        guard inbuf.count >= 5 + l else { return nil }
        let body = Data(inbuf[(inbuf.startIndex + 5)..<(inbuf.startIndex + 5 + l)])
        inbuf = Data(inbuf.dropFirst(5 + l))
        guard let peer = peerAEAD else { throw Self.err("no peer key") }
        var newAEAD: NCVLESSAEAD?
        if peer.nonce == NCVLESSAEAD.maxNonce { newAEAD = NCVLESSAEAD(ctx: header + body, key: united) }
        let plain = peer.open(body, aad: header)
        if let newAEAD { peerAEAD = newAEAD }
        guard let plain else { throw Self.err("record open failed") }
        return plain.isEmpty ? try parse() : plain
    }

    func cancel() { raw.cancel() }
}

extension NCConnector {
    private static var vlessEncCache: [String: NCVLESSEncClient] = [:]
    private static let vlessEncLock = NSLock()

    /// Shared ClientInstance per encryption string (it carries the 0-RTT ticket).
    static func vlessEncryption(_ proxy: NCProxy) -> NCVLESSEncClient? {
        guard let s = proxy.fields["encryption"]?.string, !s.isEmpty, s != "none" else { return nil }
        vlessEncLock.lock(); defer { vlessEncLock.unlock() }
        if let c = vlessEncCache[s] { return c }
        guard let c = NCVLESSEncClient.parse(s).0 else { return nil }
        vlessEncCache[s] = c
        return c
    }

    /// Wrap the transport stream in VLESS encryption when configured, then hand it on.
    static func vlessEncrypt(_ base: NCRelayStream, proxy: NCProxy, queue: DispatchQueue,
                             completion: @escaping (NCRelayStream?, Error?) -> Void) {
        guard let inst = vlessEncryption(proxy) else { completion(base, nil); return }
        let s = NCVLESSEncStream(raw: base, inst: inst, queue: queue)
        s.handshake { err in completion(err == nil ? s : nil, err) }
    }
}
