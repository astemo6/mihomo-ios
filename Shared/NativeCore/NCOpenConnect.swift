import Foundation

/// OpenConnect (Cisco AnyConnect compatible) protocol support.
///
/// Design note: docs/nc-proto-openconnect.md.
/// References:
/// - IETF Draft: The OpenConnect VPN Protocol Version 1.2 (draft-mavrogiannopoulos-openconnect-04)
/// - OpenConnect client: https://github.com/openconnect/openconnect (cstp.c, auth.c)
/// - OpenConnect server: https://gitlab.com/openconnect/ocserv
enum NCOpenConnect {

    // MARK: - Constants

    /// CSTP 4-byte magic header: "STF\x01" (RFC draft §2.3, Table 1).
    static let cstpMagic: [UInt8] = [0x53, 0x54, 0x46, 0x01]

    /// CSTP framing header length (8 bytes).
    static let cstpHeaderSize = 8

    /// DTLS framing header length (1 byte payload type).
    static let dtlsHeaderSize = 1

    /// Default HTTPS / CSTP server port.
    static let defaultPort = 443

    /// Default tunnel MTU (TCP MSS less TLS/CSTP overhead, openconnect cstp.c).
    static let defaultMTU = 1406

    /// Default link base MTU (draft §2.2.5.1).
    static let defaultBaseMTU = 1500

    /// Default client User-Agent string (draft §2.2.5.1).
    static let defaultUserAgent = "Open AnyConnect VPN Agent v5.01"

    /// RFC 5705 TLS exporter label for DTLS PSK generation (draft §2.2.7.1).
    static let dtlsExporterLabel = "EXPORTER-openconnect-psk"

    // MARK: - Payload Types (draft §2.3 Table 2)

    enum PayloadType: UInt8 {
        /// 0x00: DATA - TLS/DTLS record contains an IPv4 or IPv6 packet.
        case data = 0x00
        /// 0x03: DPD-REQ - Dead Peer Detection request.
        case dpdReq = 0x03
        /// 0x04: DPD-RESP - Dead Peer Detection response.
        case dpdResp = 0x04
        /// 0x05: DISCONNECT - Disconnect request (followed by reason byte, e.g. 0xb0).
        case disconnect = 0x05
        /// 0x07: KEEPALIVE - Channel keepalive.
        case keepalive = 0x07
        /// 0x08: COMPRESSED DATA - Compressed data packet (lz4 / lzs).
        case compressedData = 0x08
        /// 0x09: TERMINATE - Server shutting down.
        case terminate = 0x09
    }

    // MARK: - CSTP Framing (TCP Channel, 8-byte header)

    /// Encapsulates a payload into a CSTP packet (draft §2.3 Table 1):
    /// [0..3]: "STF\x01" (0x53, 0x54, 0x46, 0x01)
    /// [4..5]: Big-endian 16-bit payload length
    /// [6]: Payload type (PayloadType)
    /// [7]: 0x00 (reserved)
    /// [8..]: Payload data
    static func encodeCSTP(type: PayloadType, payload: Data = Data()) -> Data {
        var packet = Data()
        packet.reserveCapacity(cstpHeaderSize + payload.count)
        packet.append(contentsOf: cstpMagic)
        let count = min(payload.count, 0xffff)
        packet.append(UInt8((count >> 8) & 0xff))
        packet.append(UInt8(count & 0xff))
        packet.append(type.rawValue)
        packet.append(0x00)
        if !payload.isEmpty {
            packet.append(payload)
        }
        return packet
    }

    /// Decodes the first complete CSTP packet from a data buffer.
    /// Returns (type, payload, consumedBytes) if a full packet is present, or nil if incomplete or invalid.
    static func decodeCSTP(_ data: Data) -> (type: PayloadType, payload: Data, consumed: Int)? {
        guard data.count >= cstpHeaderSize else { return nil }
        let start = data.startIndex
        guard data[start] == cstpMagic[0],
              data[start + 1] == cstpMagic[1],
              data[start + 2] == cstpMagic[2],
              data[start + 3] == cstpMagic[3] else {
            return nil
        }
        let length = (Int(data[start + 4]) << 8) | Int(data[start + 5])
        let total = cstpHeaderSize + length
        guard data.count >= total else { return nil }
        guard let type = PayloadType(rawValue: data[start + 6]) else { return nil }
        let payload = data.subdata(in: (start + cstpHeaderSize)..<(start + total))
        return (type, payload, total)
    }

    // MARK: - DTLS Framing (UDP Channel, 1-byte header)

    /// Encapsulates a payload into a DTLS packet (draft §2.4):
    /// [0]: Payload type (PayloadType)
    /// [1..]: Payload data
    static func encodeDTLS(type: PayloadType, payload: Data = Data()) -> Data {
        var packet = Data()
        packet.reserveCapacity(dtlsHeaderSize + payload.count)
        packet.append(type.rawValue)
        if !payload.isEmpty {
            packet.append(payload)
        }
        return packet
    }

    /// Decodes a DTLS packet from a datagram buffer.
    static func decodeDTLS(_ data: Data) -> (type: PayloadType, payload: Data)? {
        guard !data.isEmpty else { return nil }
        guard let type = PayloadType(rawValue: data[data.startIndex]) else { return nil }
        let payload = data.count > dtlsHeaderSize ? data.dropFirst(dtlsHeaderSize) : Data()
        return (type, Data(payload))
    }

    // MARK: - Config Model

    struct Config: Equatable {
        let name: String
        let server: String
        let port: Int
        let username: String?
        let password: String?
        let authGroup: String?
        let cookie: String?
        let sni: String?
        let skipCertVerify: Bool
        let serverCertPin: String?
        let dtls: Bool
        let mtu: Int
        let userAgent: String
        let localHostname: String?

        /// Parses and validates a canonical `NCProxy` for OpenConnect.
        /// Returns (config, nil) on success, or (nil, reason) on validation failure.
        static func parse(_ p: NCProxy) -> (Config?, String?) {
            if let why = NCOpenConnect.unsupportedReason(p) {
                return (nil, why)
            }
            guard let server = p.server, !server.isEmpty else {
                return (nil, "OpenConnect 缺少服务器地址")
            }
            let port = p.port ?? NCOpenConnect.defaultPort
            let f = p.fields

            let username = f["username"]?.string
            let password = p.password
            let authGroup = f["auth-group"]?.string ?? f["group"]?.string
            let cookie = f["cookie"]?.string
            let sni = f["sni"]?.string ?? f["servername"]?.string ?? server
            let skipCertVerify = f["skip-cert-verify"]?.bool ?? false
            let serverCertPin = f["server-cert-pin"]?.string ?? f["cert-sha256"]?.string
            let dtls = f["dtls"]?.bool ?? true
            let mtu = f["mtu"]?.int ?? NCOpenConnect.defaultMTU
            let userAgent = f["user-agent"]?.string ?? NCOpenConnect.defaultUserAgent
            let localHostname = f["local-hostname"]?.string

            let cfg = Config(
                name: p.name,
                server: server,
                port: port,
                username: username,
                password: password,
                authGroup: authGroup,
                cookie: cookie,
                sni: sni,
                skipCertVerify: skipCertVerify,
                serverCertPin: serverCertPin,
                dtls: dtls,
                mtu: mtu,
                userAgent: userAgent,
                localHostname: localHostname
            )
            return (cfg, nil)
        }
    }

    // MARK: - Unsupported Gate (App / Diagnostic display)

    /// Returns a localized reason string if the proxy has unsupported parameters or credentials,
    /// or nil if the proxy configuration is dial-ready.
    static func unsupportedReason(_ p: NCProxy) -> String? {
        let f = p.fields
        if let explicit = f["unsupported"]?.string, !explicit.isEmpty {
            return explicit
        }
        guard let server = p.server, !server.isEmpty else {
            return "OpenConnect 缺少服务器地址"
        }
        if let port = p.port, port <= 0 || port > 65535 {
            return "OpenConnect 端口无效"
        }
        let username = f["username"]?.string
        let password = p.password
        let hasUserPass = (username != nil && !username!.isEmpty && password != nil)
        let cookie = f["cookie"]?.string
        let hasCookie = (cookie != nil && !cookie!.isEmpty)
        if !hasUserPass && !hasCookie {
            return "OpenConnect 缺少认证凭据（需用户名密码或 cookie）"
        }

        // Posture / CSD security constraints (iOS sandbox cannot run host binaries)
        if f["csd-wrapper"] != nil || f["csd"] != nil {
            return "OpenConnect 不支持 CSD 外部脚本或扫描程序（受 iOS 沙箱限制）"
        }
        if f["hip"] != nil || f["hip-report"] != nil {
            return "OpenConnect 不支持 HIP 报告检测"
        }
        if f["tncc"] != nil {
            return "OpenConnect 不支持 TNCC 准入检测"
        }
        if f["token-secret"] != nil || f["totp"] != nil {
            return "OpenConnect 静态配置不支持动态软件令牌生成"
        }
        if let comp = f["compression"]?.string, !comp.isEmpty && comp.lowercased() != "none" {
            return "OpenConnect 不启用数据面压缩（防范 CRIME 侧信道泄露）"
        }

        return nil
    }
}
