import CryptoKit
import Foundation

// MARK: - disco (discovery) message codec — Tailscale magicsock protocol
//
// Wire format (tailscale.com/disco):
//   packet  = magic(6) || senderDiscoPub(32) || nonce(24) || box(payload)
//   magic   = the UTF-8 bytes of "TS💝"
//   payload = type(1) || version(1 = 0) || body, NaCl-box encrypted to the
//             recipient's disco key
//   ping        (type 1): TxID(12) || NodeKey(32)
//   pong        (type 2): TxID(12) || Src AddrPort
//   callMeMaybe (type 3): concatenated AddrPorts (sender's endpoints)
//   AddrPort    = family(1: 4 or 6) || ip(4 or 16) || port(2, big-endian)
//
// The AddrPort family-byte framing and the ping/pong/callMeMaybe layouts
// follow disco.go as published; without a live peer in this environment
// the byte layout is implemented from the spec and flagged in the phase
// report as not interop-verified.

enum NCTailscaleDisco {
    static let magic: [UInt8] = [0x54, 0x53, 0xF0, 0x9F, 0x92, 0x9D] // "TS💝"

    enum Message: Equatable {
        case ping(txid: Data, nodeKey: Data?)
        case pong(txid: Data, src: String)
        case callMeMaybe(endpoints: [String])
    }

    static func isDisco(_ data: Data) -> Bool {
        data.count > magic.count && Array(data.prefix(magic.count)) == magic
    }

    // MARK: Seal / open

    static func seal(
        _ message: Message,
        senderPrivate: Curve25519.KeyAgreement.PrivateKey,
        senderPublic: Data,
        recipientPublic: Data
    ) -> Data? {
        let payload = encode(message)
        let nonce = NCTailscaleDiscoRandom.data(count: 24)
        guard let boxed = NCNaClBox.Box.seal(
            message: payload,
            nonce24: [UInt8](nonce),
            recipientPublicKey: [UInt8](recipientPublic),
            senderPrivateKey: senderPrivate
        ) else { return nil }
        var out = Data(magic)
        out += senderPublic
        out += nonce
        out += Data(boxed)
        return out
    }

    /// Returns (senderDiscoPub, message) or nil for non-disco/undecryptable input.
    static func open(
        _ packet: Data,
        recipientPrivate: Curve25519.KeyAgreement.PrivateKey
    ) -> (senderPublic: Data, message: Message)? {
        guard isDisco(packet), packet.count > magic.count + 32 + 24 else { return nil }
        let bytes = [UInt8](packet)
        let sender = Data(bytes[magic.count..<(magic.count + 32)])
        let nonce = Array(bytes[(magic.count + 32)..<(magic.count + 56)])
        let boxed = Array(bytes[(magic.count + 56)...])
        guard let plain = NCNaClBox.Box.open(
            box: boxed,
            nonce24: nonce,
            senderPublicKey: [UInt8](sender),
            recipientPrivateKey: recipientPrivate
        ), let message = decode(plain) else { return nil }
        return (sender, message)
    }

    // MARK: Payload encode / decode

    private static func encode(_ message: Message) -> [UInt8] {
        switch message {
        case .ping(let txid, let nodeKey):
            var out: [UInt8] = [1, 0]
            out += [UInt8](txid)
            if let nodeKey { out += [UInt8](nodeKey) }
            return out
        case .pong(let txid, let src):
            var out: [UInt8] = [2, 0]
            out += [UInt8](txid)
            if let ep = encodeAddrPort(src) { out += ep }
            return out
        case .callMeMaybe(let endpoints):
            var out: [UInt8] = [3, 0]
            for ep in endpoints {
                if let b = encodeAddrPort(ep) { out += b }
            }
            return out
        }
    }

    private static func decode(_ payload: [UInt8]) -> Message? {
        guard payload.count >= 2 else { return nil }
        let type = payload[0]
        let body = Array(payload.dropFirst(2))
        switch type {
        case 1:
            guard body.count >= 12 else { return nil }
            let txid = Data(body[0..<12])
            let nodeKey = body.count >= 44 ? Data(body[12..<44]) : nil
            return .ping(txid: txid, nodeKey: nodeKey)
        case 2:
            guard body.count >= 12, let (src, _) = decodeAddrPort(body, at: 12) else { return nil }
            return .pong(txid: Data(body[0..<12]), src: src)
        case 3:
            var endpoints: [String] = []
            var off = 0
            while off < body.count {
                guard let (ep, next) = decodeAddrPort(body, at: off) else { break }
                endpoints.append(ep)
                off = next
            }
            return .callMeMaybe(endpoints: endpoints)
        default:
            return nil
        }
    }

    // MARK: AddrPort codec ("ip:port" / "[v6]:port" strings)

    static func encodeAddrPort(_ endpoint: String) -> [UInt8]? {
        guard let (ip, port) = parseEndpoint(endpoint) else { return nil }
        switch ip {
        case .v4(let v):
            return [4,
                    UInt8((v >> 24) & 0xff), UInt8((v >> 16) & 0xff),
                    UInt8((v >> 8) & 0xff), UInt8(v & 0xff),
                    UInt8((port >> 8) & 0xff), UInt8(port & 0xff)]
        case .v6(let bytes):
            return [6] + bytes + [UInt8((port >> 8) & 0xff), UInt8(port & 0xff)]
        }
    }

    static func decodeAddrPort(_ bytes: [UInt8], at offset: Int) -> (String, Int)? {
        guard offset < bytes.count else { return nil }
        switch bytes[offset] {
        case 4:
            guard offset + 7 <= bytes.count else { return nil }
            let ip = Array(bytes[(offset + 1)..<(offset + 5)])
            let port = Int(bytes[offset + 5]) << 8 | Int(bytes[offset + 6])
            guard let addr = NCIP(bytes: ip) else { return nil }
            return ("\(addr.string):\(port)", offset + 7)
        case 6:
            guard offset + 19 <= bytes.count else { return nil }
            let ip = Array(bytes[(offset + 1)..<(offset + 17)])
            let port = Int(bytes[offset + 17]) << 8 | Int(bytes[offset + 18])
            guard let addr = NCIP(bytes: ip) else { return nil }
            return ("[\(addr.string)]:\(port)", offset + 19)
        default:
            return nil
        }
    }

    /// Splits "1.2.3.4:41641" / "[fd7a::1]:41641" into (IP, port).
    static func parseEndpoint(_ endpoint: String) -> (NCIP, UInt16)? {
        let t = endpoint.trimmingCharacters(in: .whitespaces)
        if t.hasPrefix("[") {
            guard let close = t.firstIndex(of: "]"), t.index(after: close) < t.endIndex,
                  t[t.index(after: close)] == ":" else { return nil }
            let host = String(t[t.index(after: t.startIndex)..<close])
            let portStr = String(t[t.index(close, offsetBy: 2)...])
            guard let ip = NCIP(host), let port = UInt16(portStr) else { return nil }
            return (ip, port)
        }
        guard let lastColon = t.lastIndex(of: ":") else { return nil }
        let host = String(t[..<lastColon])
        let portStr = String(t[t.index(after: lastColon)...])
        guard let ip = NCIP(host), let port = UInt16(portStr) else { return nil }
        return (ip, port)
    }
}
