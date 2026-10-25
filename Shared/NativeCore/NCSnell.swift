import Foundation
import CryptoKit

/// Snell (Surge) protocol, versions 1–5 as mihomo implements them:
///
/// - KDF: Argon2id(psk, salt, time=3, mem=8 KiB, lanes=1, out=32), key
///   truncated to the cipher size. Salt is 16 bytes per stream direction.
/// - v1: ChaCha20-Poly1305 stream in legacy SS AEAD chunk framing.
///   v2/v3: AES-128-GCM, same framing. v2 adds connect-reuse semantics
///   (we dial a fresh connection per flow; the command byte differs).
///   v5 is v4 on the wire.
/// - v4: bespoke frame format — 7-byte sealed header
///   [0x04, 0, 0, paddingLen u16, payloadLen u16], payload sealed
///   separately, first frame carries obfuscation padding whose bytes are
///   pairwise-swapped with the payload ciphertext's leading bytes.
/// - Headers (all versions, sent inside the crypto stream):
///   [version=1][command][clientID len=0][host len][host][port u16];
///   commands: 1 = connect, 5 = connect (v2/reuse), 6 = UDP (v3+).
///   The server replies [0x00] (tunnel) or [0x02][code][msgLen][msg].
enum NCSnell {
    static func sessionKey(psk: Data, salt: Data, keySize: Int) -> Data {
        let derived = NCArgon2.idKey(password: psk, salt: salt, iterations: 3,
                                     memoryKB: 8, lanes: 1, keyLength: 32)
        return Data(derived.prefix(keySize))
    }

    /// v1 = chacha (32-byte key), v2/v3 = AES-128 (16-byte key).
    static func streamParams(version: Int) -> (keySize: Int, isAES: Bool) {
        version <= 1 ? (32, false) : (16, true)
    }

    static func connectHeader(host: String, port: Int, version: Int) -> Data {
        var out = Data()
        out.append(0x01) // protocol version byte (always 1 on the wire)
        out.append(version == 2 ? 0x05 : 0x01)
        out.append(0x00) // clientID length
        let hostBytes = Data(host.utf8.prefix(255)) // u8 length; connectViaProxy already rejects longer targets
        out.append(UInt8(hostBytes.count))
        out.append(hostBytes)
        out.appendBE16(UInt16(clamping: port))
        return out
    }

    static func udpHeader() -> Data { Data([0x01, 0x06, 0x00]) }

    /// Parse the one-byte server reply; returns the error message when the
    /// reply is a complete error frame, `.pending` when more bytes are
    /// needed, `.ok` for tunnel-established (consuming exactly one byte).
    enum ReplyParse {
        case ok(consumed: Int)
        case error(String)
        case pending
    }

    static func parseReply(_ data: Data) -> ReplyParse {
        guard let first = data.first else { return .pending }
        if first == 0x00 { return .ok(consumed: 1) }
        guard first == 0x02 else { return .error("unexpected snell reply byte \(first)") }
        guard data.count >= 3 else { return .pending }
        let msgLen = Int(data[2])
        guard data.count >= 3 + msgLen else { return .pending }
        let msg = String(decoding: data[3..<(3 + msgLen)], as: UTF8.self)
        return .error("snell server code \(data[1]): \(msg)")
    }

    // MARK: UDP packet framing (the bespoke Snell address format)

    /// Encode one UDP packet's inner frame: [0x01 command] + address in
    /// Snell's own format + payload. Domain: [len][host][port]; IPv4:
    /// [0x00, 0x04][addr][port]; IPv6: [0x00, 0x06][addr][port].
    static func udpFrame(target: NCTarget, payload: Data) -> Data {
        var out = Data()
        out.append(0x01)
        if let ip = target.ip {
            switch ip {
            case .v4(let a):
                out.append(contentsOf: [0x00, 0x04])
                out.append(contentsOf: [UInt8(a >> 24), UInt8((a >> 16) & 0xff),
                                        UInt8((a >> 8) & 0xff), UInt8(a & 0xff)])
            case .v6(let bytes):
                out.append(contentsOf: [0x00, 0x06])
                out.append(contentsOf: bytes)
            }
        } else {
            // u8 length: UDP targets do not pass connectViaProxy's isWireEncodable check, so cap here (no trap).
            let host = Data(target.host.utf8.prefix(255))
            out.append(UInt8(host.count))
            out.append(host)
        }
        out.appendBE16(UInt16(clamping: target.port))
        out.append(payload)
        return out
    }

    /// Decode one response packet: [0x04|0x06][addr][port][payload].
    static func parseUDPResponse(_ data: Data) -> (NCTarget, Data)? {
        guard let kind = data.first else { return nil }
        switch kind {
        case 0x04:
            guard data.count >= 1 + 4 + 2 else { return nil }
            let host = data[1..<5].map { String($0) }.joined(separator: ".")
            let port = Int(data[5]) << 8 | Int(data[6])
            return (NCTarget(host: host, port: port), Data(data.dropFirst(7)))
        case 0x06:
            guard data.count >= 1 + 16 + 2, let ip = NCIP(bytes: [UInt8](data[1..<17])) else { return nil }
            let port = Int(data[17]) << 8 | Int(data[18])
            return (NCTarget(host: ip.string, port: port), Data(data.dropFirst(19)))
        default:
            return nil
        }
    }
}

/// v1–v3 stream encoder: 16-byte salt, then SS-style sealed chunks keyed
/// by the Snell KDF.
final class NCSnellStreamEncoder {
    let salt: Data
    private let crypto: NCSS2022StreamCrypto

    init(psk: Data, version: Int, salt: Data? = nil) {
        let (keySize, isAES) = NCSnell.streamParams(version: version)
        self.salt = salt ?? Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        let key = NCSnell.sessionKey(psk: psk, salt: self.salt, keySize: keySize)
        crypto = NCSS2022StreamCrypto(sessionKey: key, isAES: isAES)
    }

    private var emittedSalt = false
    func encode(_ data: Data) -> Data? {
        var out = Data()
        if !emittedSalt { out.append(salt); emittedSalt = true }
        var rest = data
        while !rest.isEmpty {
            let chunk = Data(rest.prefix(0x3fff))
            rest = Data(rest.dropFirst(chunk.count))
            var lenBytes = Data(count: 2)
            lenBytes[0] = UInt8((chunk.count >> 8) & 0xff)
            lenBytes[1] = UInt8(chunk.count & 0xff)
            guard let sealedLen = crypto.seal(lenBytes), let sealedBody = crypto.seal(chunk) else { return nil }
            out.append(sealedLen)
            out.append(sealedBody)
        }
        return out
    }
}

/// v1–v3 stream decoder (chunk framing identical to legacy SS AEAD).
final class NCSnellStreamDecoder {
    private let psk: Data
    private let version: Int
    private var buffer = Data()
    private var crypto: NCSS2022StreamCrypto?
    private var pendingBodyLen: Int?

    init(psk: Data, version: Int) {
        self.psk = psk
        self.version = version
    }

    /// Feed wire bytes → plaintext pieces (one per decrypted chunk), or
    /// nil on decrypt failure.
    func feed(_ data: Data) -> [Data]? {
        buffer.append(data)
        if crypto == nil {
            guard buffer.count >= 16 else { return [] }
            let salt = Data(buffer.prefix(16))
            buffer = Data(buffer.dropFirst(16))
            let (keySize, isAES) = NCSnell.streamParams(version: version)
            let key = NCSnell.sessionKey(psk: psk, salt: salt, keySize: keySize)
            crypto = NCSS2022StreamCrypto(sessionKey: key, isAES: isAES)
        }
        guard let crypto else { return [] }
        var out: [Data] = []
        while true {
            if let bodyLen = pendingBodyLen {
                guard buffer.count >= bodyLen + 16 else { break }
                guard let plain = crypto.open(Data(buffer.prefix(bodyLen + 16))) else { return nil }
                buffer = Data(buffer.dropFirst(bodyLen + 16))
                pendingBodyLen = nil
                if !plain.isEmpty { out.append(plain) }
            } else {
                guard buffer.count >= 2 + 16 else { break }
                guard let lenData = crypto.open(Data(buffer.prefix(2 + 16))) else { return nil }
                buffer = Data(buffer.dropFirst(2 + 16))
                pendingBodyLen = Int(lenData[0]) << 8 | Int(lenData[1])
            }
        }
        return out
    }
}

// MARK: - v4 frames

/// v4 frame writer. The first frame prepends the 16-byte salt and adds
/// obfuscation padding (random length 0x100..<0x200) whose bytes are
/// pairwise-swapped with the payload ciphertext prefix.
final class NCSnellV4Writer {
    let salt: Data
    private let crypto: NCSS2022StreamCrypto
    private var saltSent = false
    private let firstPaddingLen: Int

    init(psk: Data, salt: Data? = nil, firstPaddingLen: Int? = nil) {
        self.salt = salt ?? Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        self.firstPaddingLen = firstPaddingLen ?? Int.random(in: 0x100..<0x200)
        let key = NCSnell.sessionKey(psk: psk, salt: self.salt, keySize: 16)
        crypto = NCSS2022StreamCrypto(sessionKey: key, isAES: true)
    }

    /// Seal one frame of payload (≤0x3FFF). An empty payload produces the
    /// zero frame that signals end-of-stream.
    func frame(_ payload: Data) -> Data? {
        let paddingLen = saltSent ? 0 : (payload.isEmpty ? 0 : firstPaddingLen)
        return frame(payload, paddingLen: paddingLen)
    }

    func frame(_ payload: Data, paddingLen: Int) -> Data? {
        guard payload.count <= 0x3fff, paddingLen <= 0x3fff,
              !(payload.isEmpty && paddingLen != 0) else { return nil }
        var header = Data(count: 7)
        header[0] = 0x04
        header[3] = UInt8((paddingLen >> 8) & 0xff)
        header[4] = UInt8(paddingLen & 0xff)
        header[5] = UInt8((payload.count >> 8) & 0xff)
        header[6] = UInt8(payload.count & 0xff)
        guard let sealedHeader = crypto.seal(header) else { return nil }
        var out = Data()
        if !saltSent { out.append(salt); saltSent = true }
        out.append(sealedHeader)
        if !payload.isEmpty {
            guard var sealedPayload = crypto.seal(payload) else { return nil }
            if paddingLen > 0 {
                var padding = Data((0..<paddingLen).map { _ in UInt8.random(in: 0...255) })
                Self.swap(&padding, &sealedPayload)
                out.append(padding)
            }
            out.append(sealedPayload)
        }
        return out
    }

    /// Write a possibly-large blob as a sequence of frames.
    func write(_ data: Data) -> Data? {
        var out = Data()
        var rest = data
        while !rest.isEmpty {
            let chunk = Data(rest.prefix(0x3fff))
            rest = Data(rest.dropFirst(chunk.count))
            guard let f = frame(chunk) else { return nil }
            out.append(f)
        }
        return out
    }

    /// swapPadding from the reference: bytes at even indices swap between
    /// the padding and the payload ciphertext, up to the shorter length.
    static func swap(_ padding: inout Data, _ payload: inout Data) {
        let limit = min(padding.count, payload.count)
        var i = 0
        while i < limit {
            let tmp = padding[i]
            padding[i] = payload[i]
            payload[i] = tmp
            i += 2
        }
    }
}

/// v4 frame reader: salt once, then sealed header / padding / sealed
/// payload per frame. A zero-payload frame yields the `.end` marker.
final class NCSnellV4Reader {
    enum Piece {
        case data(Data)
        case end
    }

    private let psk: Data
    private var buffer = Data()
    private var crypto: NCSS2022StreamCrypto?
    private var pendingFrame: (padding: Int, payloadLen: Int)?

    init(psk: Data) { self.psk = psk }

    func feed(_ data: Data) -> [Piece]? {
        buffer.append(data)
        if crypto == nil {
            guard buffer.count >= 16 else { return [] }
            let salt = Data(buffer.prefix(16))
            buffer = Data(buffer.dropFirst(16))
            let key = NCSnell.sessionKey(psk: psk, salt: salt, keySize: 16)
            crypto = NCSS2022StreamCrypto(sessionKey: key, isAES: true)
        }
        guard let crypto else { return [] }
        var out: [Piece] = []
        while true {
            if let pending = pendingFrame {
                let need = pending.padding + pending.payloadLen + 16
                guard buffer.count >= need else { break }
                var frameBytes = Data(buffer.prefix(need))
                buffer = Data(buffer.dropFirst(need))
                pendingFrame = nil
                var sealedPayload = Data(frameBytes.dropFirst(pending.padding))
                if pending.padding > 0 {
                    var padding = Data(frameBytes.prefix(pending.padding))
                    NCSnellV4Writer.swap(&padding, &sealedPayload)
                }
                guard let plain = crypto.open(sealedPayload) else { return nil }
                out.append(.data(plain))
            } else {
                guard buffer.count >= 7 + 16 else { break }
                guard let header = crypto.open(Data(buffer.prefix(7 + 16))) else { return nil }
                buffer = Data(buffer.dropFirst(7 + 16))
                guard header.count == 7, header[0] == 0x04 else { return nil }
                let paddingLen = Int(header[3]) << 8 | Int(header[4])
                let payloadLen = Int(header[5]) << 8 | Int(header[6])
                if payloadLen == 0 {
                    guard paddingLen == 0 else { return nil }
                    out.append(.end)
                } else {
                    pendingFrame = (paddingLen, payloadLen)
                }
            }
        }
        return out
    }
}
