import Foundation
import CryptoKit

/// AnyTLS (mihomo's transport/anytls): a TLS connection carrying
/// [sha256(password)][paddingLen u16][padding] as its first bytes, then
/// a small multiplexed session of frames
/// [cmd u8][streamID u32 BE][len u16 BE][data]:
/// 0 waste, 1 SYN, 2 PSH, 3 FIN, 4 settings, 5 alert, 6 padding-scheme
/// update, 7 SYNACK, 8/9 heart request/response, 10 server settings.
/// The client's first frame is cmdSettings with a string map
/// {v: 2, client: <metadata>, padding-md5: <md5 of the scheme>}.
/// Each stream's first payload is the target's SOCKS-style address.
/// UDP rides UDP-over-TCP v2 (see NCUoT below).
enum NCAnyTLS {
    static let cmdWaste: UInt8 = 0
    static let cmdSYN: UInt8 = 1
    static let cmdPSH: UInt8 = 2
    static let cmdFIN: UInt8 = 3
    static let cmdSettings: UInt8 = 4
    static let cmdAlert: UInt8 = 5
    static let cmdUpdatePaddingScheme: UInt8 = 6
    static let cmdSYNACK: UInt8 = 7
    static let cmdHeartRequest: UInt8 = 8
    static let cmdHeartResponse: UInt8 = 9
    static let cmdServerSettings: UInt8 = 10

    static let defaultPaddingScheme = """
        stop=8
        0=30-30
        1=100-400
        2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
        3=9-9,500-1000
        4=500-1000
        5=500-1000
        6=500-1000
        7=500-1000
        """

    static func authBlock(password: String, paddingLen: Int) -> Data {
        var out = Data(SHA256.hash(data: Data(password.utf8)))
        out.appendBE16(UInt16(clamping: paddingLen))
        out.append(Data(count: paddingLen))
        return out
    }

    static func settingsFrame(clientMetadata: String) -> Data {
        let md5 = Insecure.MD5.hash(data: Data(defaultPaddingScheme.utf8))
            .ncHex
        let map = "client=\(clientMetadata)\npadding-md5=\(md5)\nv=2"
        return frame(cmd: cmdSettings, streamID: 0, data: Data(map.utf8))
    }

    static func frame(cmd: UInt8, streamID: UInt32, data: Data = Data()) -> Data {
        var out = Data()
        out.append(cmd)
        out.appendBE32(streamID)
        out.appendBE16(UInt16(clamping: data.count))
        out.append(data)
        return out
    }

    struct Frame {
        let cmd: UInt8
        let streamID: UInt32
        let data: Data
    }

    /// Incremental frame parser.
    struct FrameParser {
        private var buffer = Data()
        /// Offset walk + one compaction per feed (rv2-proto: was a tail copy per frame, O(n²) on large reads).
        mutating func feed(_ data: Data) -> [Frame] {
            buffer.append(data)
            var out: [Frame] = []
            var off = 0
            while buffer.count - off >= 7 {
                let b = buffer.startIndex + off
                let len = Int(buffer[b + 5]) << 8 | Int(buffer[b + 6])
                guard buffer.count - off >= 7 + len else { break }
                let sid = UInt32(buffer[b + 1]) << 24 | UInt32(buffer[b + 2]) << 16 | UInt32(buffer[b + 3]) << 8 | UInt32(buffer[b + 4])
                out.append(Frame(cmd: buffer[b], streamID: sid, data: Data(buffer[(b + 7)..<(b + 7 + len)])))
                off += 7 + len
            }
            if off >= buffer.count { buffer = Data() }
            else if off > 0 { buffer = Data(buffer[(buffer.startIndex + off)...]) }
            return out
        }
    }
}

/// UDP-over-TCP v2 (sing common/uot) as AnyTLS/Hysteria-style outbounds
/// use it: the stream targets `sp.v2.udp-over-tcp.arpa:0`; the first
/// bytes are a request [isConnect u8][destination in SOCKS atyp form];
/// packets then use UoT's OWN address family bytes (0=v4, 1=v6, 2= fqdn)
/// + [len u16] + payload.
enum NCUoT {
    static let magicTarget = NCTarget(host: "sp.v2.udp-over-tcp.arpa", port: 0)

    static func request(destination: NCTarget) -> Data {
        var out = Data()
        out.append(0x00) // isConnect = false
        out.append(destination.atypEncoded)
        return out
    }

    static func packet(target: NCTarget, payload: Data) -> Data {
        var out = Data()
        if let ip = target.ip {
            switch ip {
            case .v4(let a):
                out.append(0x00)
                out.append(contentsOf: [UInt8(a >> 24), UInt8((a >> 16) & 0xff),
                                        UInt8((a >> 8) & 0xff), UInt8(a & 0xff)])
            case .v6(let bytes):
                out.append(0x01)
                out.append(contentsOf: bytes)
            }
        } else {
            let host = Data(target.host.utf8)
            out.append(0x02)
            out.append(UInt8(host.count))
            out.append(host)
        }
        out.appendBE16(UInt16(clamping: target.port))
        out.appendBE16(UInt16(clamping: payload.count))
        out.append(payload)
        return out
    }

    /// Parse one packet from the front of `data`; nil = incomplete.
    static func parsePacket(_ data: Data) -> (NCTarget, Data, Int)? {
        guard let family = data.first else { return nil }
        var offset = 1
        let host: String
        switch family {
        case 0x00:
            guard data.count >= offset + 4 else { return nil }
            host = data[offset..<(offset + 4)].map { String($0) }.joined(separator: ".")
            offset += 4
        case 0x01:
            guard data.count >= offset + 16 else { return nil }
            host = NCIP.v6([UInt8](data[offset..<(offset + 16)])).string
            offset += 16
        case 0x02:
            guard data.count >= offset + 1 else { return nil }
            let len = Int(data[offset])
            offset += 1
            guard data.count >= offset + len else { return nil }
            host = String(decoding: data[offset..<(offset + len)], as: UTF8.self)
            offset += len
        default:
            return nil
        }
        guard data.count >= offset + 4 else { return nil }
        let port = Int(data[offset]) << 8 | Int(data[offset + 1])
        let len = Int(data[offset + 2]) << 8 | Int(data[offset + 3])
        offset += 4
        guard data.count >= offset + len else { return nil }
        return (NCTarget(host: host, port: port), Data(data[offset..<(offset + len)]), offset + len)
    }
}
