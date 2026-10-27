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

    /// fix/nc-openconnect-dp: the data plane is a lwIP netif over the CSTP channel (PacketTunnel only,
    /// NCOpenConnectNetif.swift). Outside the tunnel (the App's 延迟测试) there is no such stack, like WireGuard.
    /// Flipped to true only once the real-ocserv loopback (proto-loopback.yml job `openconnect`) is green; until then
    /// NCSupport keeps a valid node unavailable (the connector still dials, so the loopback can run).
    static let dataPlaneVerified = false

    /// Shown by NCSupport for a valid node while `dataPlaneVerified` is false.
    static let dataPlaneUnavailable = "OpenConnect 数据面验证中（真实 ocserv 回环测试通过前暂不可用）"

    static let tunnelOnly = "OpenConnect 仅在 VPN 隧道内可用（CSTP 承载 IP 包，由隧道内的用户态 TCP/IP 栈收发）"

    /// The webvpn cookie value from a configured `cookie` (a bare token, `webvpn=<token>`, or a Cookie header line).
    static func cookieValue(_ raw: String) -> String {
        var v = raw.trimmingCharacters(in: .whitespaces)
        if let r = v.range(of: "webvpn=", options: .caseInsensitive) {
            v = String(v[r.upperBound...])
            if let semi = v.firstIndex(of: ";") { v = String(v[..<semi]) }
        }
        return v.trimmingCharacters(in: .whitespaces)
    }

    /// Total length of a complete CSTP frame at the head of `data` (any payload type), nil while incomplete or
    /// when the magic is wrong. Lets the pump skip frames whose type it does not know instead of stalling.
    static func completeFrameLength(_ data: Data) -> Int? {
        guard data.count >= cstpHeaderSize else { return nil }
        let s = data.startIndex
        guard data[s] == cstpMagic[0], data[s + 1] == cstpMagic[1], data[s + 2] == cstpMagic[2],
              data[s + 3] == cstpMagic[3] else { return nil }
        let total = cstpHeaderSize + ((Int(data[s + 4]) << 8) | Int(data[s + 5]))
        return data.count >= total ? total : nil
    }

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

    // MARK: - Tunnel Parameters & Auth Models

    struct TunnelParameters: Equatable {
        var assignedIPv4: String?
        var netmaskIPv4: String?
        var assignedIPv6: String?
        var dnsServers: [String] = []
        var splitIncludes: [String] = []
        var splitExcludes: [String] = []
        var baseMTU: Int = 1500
        var mtu: Int = 1406
        var keepalive: Int = 300
        var dpd: Int = 30
        var dtlsPort: Int?
        var dtlsAppID: String?
        var dtlsCipherSuite: String?
        var dtlsKeepalive: Int?
        var dtlsDPD: Int?

        static func parse(headers: [String: String]) -> TunnelParameters {
            parse(headerList: headers.sorted { $0.key < $1.key }.map { ($0.key, $0.value) })
        }

        /// The CONNECT response headers in wire order (repeated X-CSTP-DNS / -Split-Include are all kept).
        static func parse(headerList: [(String, String)]) -> TunnelParameters {
            var params = TunnelParameters()
            for (rawKey, val) in headerList {
                let k = rawKey.lowercased()
                switch k {
                case "x-cstp-address": params.assignedIPv4 = val
                case "x-cstp-netmask": params.netmaskIPv4 = val
                case "x-cstp-address-ip6":
                    // "fd00::2/64" -> the interface address; the prefix length is not needed for a point-to-point netif.
                    params.assignedIPv6 = val.split(separator: "/").first.map(String.init) ?? val
                case "x-cstp-dns", "x-cstp-dns-ip6":
                    if !val.isEmpty, !params.dnsServers.contains(val) { params.dnsServers.append(val) }
                case "x-cstp-split-include": params.splitIncludes.append(val)
                case "x-cstp-split-exclude": params.splitExcludes.append(val)
                case "x-cstp-base-mtu": if let n = Int(val) { params.baseMTU = n }
                case "x-cstp-mtu": if let n = Int(val) { params.mtu = n }
                case "x-cstp-keepalive": if let n = Int(val) { params.keepalive = n }
                case "x-cstp-dpd": if let n = Int(val) { params.dpd = n }
                case "x-dtls-port": if let n = Int(val) { params.dtlsPort = n }
                case "x-dtls-app-id": params.dtlsAppID = val
                case "x-dtls-ciphersuite": params.dtlsCipherSuite = val
                case "x-dtls-keepalive": if let n = Int(val) { params.dtlsKeepalive = n }
                case "x-dtls-dpd": if let n = Int(val) { params.dtlsDPD = n }
                default: break
                }
            }
            return params
        }
    }

    enum AuthType: String, Equatable {
        case initType = "init"
        case authRequest = "auth-request"
        case authReply = "auth-reply"
        case complete = "complete"
        case error = "error"
    }

    struct AuthResponse: Equatable {
        let type: AuthType
        let formAction: String?
        let inputs: [String: String] // name -> input type
        let message: String?
        let error: String?

        static func parse(xmlString: String) -> AuthResponse? {
            // Strip XML comments
            var cleaned = xmlString
            while let start = cleaned.range(of: "<!--") {
                if let end = cleaned[start.lowerBound...].range(of: "-->") {
                    cleaned.removeSubrange(start.lowerBound..<end.upperBound)
                } else {
                    break
                }
            }

            // Extract config-auth type
            guard let typeStr = extractAttribute(named: "type", inTag: "config-auth", from: cleaned),
                  let authType = AuthType(rawValue: typeStr) else {
                return nil
            }

            // Extract form action
            let formAction = extractAttribute(named: "action", inTag: "form", from: cleaned)

            // Extract inputs
            var inputs: [String: String] = [:]
            var searchRange = cleaned.startIndex..<cleaned.endIndex
            while let inputStart = cleaned[searchRange].range(of: "<input") {
                guard let inputEnd = cleaned[inputStart.lowerBound..<cleaned.endIndex].range(of: ">") else { break }
                let tagStr = String(cleaned[inputStart.lowerBound..<inputEnd.upperBound])
                if let name = extractAttributeValue(named: "name", inString: tagStr) {
                    let type = extractAttributeValue(named: "type", inString: tagStr) ?? "text"
                    inputs[name] = type
                }
                searchRange = inputEnd.upperBound..<cleaned.endIndex
            }

            // Extract message and error tags
            let msg = extractTagContent(named: "message", from: cleaned).map(unescapeXML)
            let err = extractTagContent(named: "error", from: cleaned).map(unescapeXML)

            return AuthResponse(type: authType, formAction: formAction, inputs: inputs, message: msg, error: err)
        }

        private static func extractAttribute(named attr: String, inTag tag: String, from xml: String) -> String? {
            guard let tagRange = xml.range(of: "<\(tag)") else { return nil }
            guard let endRange = xml[tagRange.lowerBound...].range(of: ">") else { return nil }
            let fullTag = String(xml[tagRange.lowerBound..<endRange.upperBound])
            return extractAttributeValue(named: attr, inString: fullTag)
        }

        private static func extractAttributeValue(named attr: String, inString tag: String) -> String? {
            for quote in ["\"", "'"] {
                for pattern in ["\(attr)=\(quote)", "\(attr) =\(quote)", "\(attr)= \(quote)", "\(attr) = \(quote)"] {
                    if let r = tag.range(of: pattern) {
                        let after = tag[r.upperBound...]
                        if let endQuote = after.range(of: quote) {
                            return String(after[..<endQuote.lowerBound])
                        }
                    }
                }
            }
            return nil
        }

        private static func extractTagContent(named tag: String, from xml: String) -> String? {
            guard let open = xml.range(of: "<\(tag)>") else { return nil }
            guard let close = xml[open.upperBound...].range(of: "</\(tag)>") else { return nil }
            return String(xml[open.upperBound..<close.lowerBound]).trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }

    struct HTTPMessage: Equatable {
        let statusCode: Int
        let statusText: String
        let headers: [String: String]
        let rawHeaders: [(String, String)]
        let cookies: [String: String]
        let body: Data

        // Manual Equatable: rawHeaders is a tuple array, which cannot synthesize conformance.
        static func == (lhs: HTTPMessage, rhs: HTTPMessage) -> Bool {
            lhs.statusCode == rhs.statusCode && lhs.statusText == rhs.statusText
                && lhs.headers == rhs.headers && lhs.cookies == rhs.cookies && lhs.body == rhs.body
                && lhs.rawHeaders.count == rhs.rawHeaders.count
                && zip(lhs.rawHeaders, rhs.rawHeaders).allSatisfy { $0.0 == $1.0 && $0.1 == $1.1 }
        }

        static func parse(data: Data) -> (message: HTTPMessage, consumed: Int)? {
            let crlf2 = Data([0x0d, 0x0a, 0x0d, 0x0a])
            let lf2 = Data([0x0a, 0x0a])
            var headerEnd: Int = -1
            var delimLen = 4
            if let r = data.range(of: crlf2) {
                headerEnd = r.upperBound
                delimLen = 4
            } else if let r = data.range(of: lf2) {
                headerEnd = r.upperBound
                delimLen = 2
            } else {
                return nil
            }

            let headerBytes = data.subdata(in: data.startIndex..<(headerEnd - delimLen))
            guard let headerStr = String(data: headerBytes, encoding: .utf8) ?? String(data: headerBytes, encoding: .isoLatin1) else {
                return nil
            }

            let lines = headerStr.components(separatedBy: "\n").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
            guard let statusLine = lines.first else { return nil }
            let statusParts = statusLine.components(separatedBy: " ")
            guard statusParts.count >= 2, let code = Int(statusParts[1]) else { return nil }
            let text = statusParts.dropFirst(2).joined(separator: " ")

            var headers: [String: String] = [:]
            var rawHeaders: [(String, String)] = []
            var cookies: [String: String] = [:]

            for line in lines.dropFirst() {
                guard let colonIdx = line.firstIndex(of: ":") else { continue }
                let k = line[..<colonIdx].trimmingCharacters(in: .whitespaces)
                let v = line[line.index(after: colonIdx)...].trimmingCharacters(in: .whitespaces)
                let lowerK = k.lowercased()
                headers[lowerK] = v
                rawHeaders.append((k, v))

                if lowerK == "set-cookie" {
                    let cookieParts = v.components(separatedBy: ";")
                    if let first = cookieParts.first {
                        let pair = first.components(separatedBy: "=")
                        if pair.count >= 2 {
                            let name = pair[0].trimmingCharacters(in: .whitespaces)
                            let val = pair.dropFirst().joined(separator: "=").trimmingCharacters(in: .whitespaces)
                            if !name.isEmpty {
                                cookies[name] = val
                            }
                        }
                    }
                }
            }

            let cl = Int(headers["content-length"] ?? "0") ?? 0
            let bodyStart = headerEnd
            let requiredTotal = bodyStart + cl
            guard data.count >= requiredTotal else { return nil }
            let body = data.subdata(in: bodyStart..<requiredTotal)
            let msg = HTTPMessage(statusCode: code, statusText: text, headers: headers, rawHeaders: rawHeaders, cookies: cookies, body: body)
            return (msg, requiredTotal - data.startIndex)
        }
    }

    // MARK: - XML & Form Builders

    static func buildInitXML(clientVersion: String = "v5.01") -> String {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<config-auth client=\"vpn\" type=\"init\"><version who=\"vpn\">\(clientVersion)</version></config-auth>"
    }

    static func buildAuthReplyXML(username: String?, password: String?, authGroup: String?, clientVersion: String = "v5.01") -> String {
        var s = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<config-auth client=\"vpn\" type=\"auth-reply\">\n<version who=\"vpn\">\(clientVersion)</version>\n<auth>\n"
        if let authGroup, !authGroup.isEmpty {
            s += "<group_list>\(escapeXML(authGroup))</group_list>\n"
        }
        if let username, !username.isEmpty {
            s += "<username>\(escapeXML(username))</username>\n"
        }
        if let password, !password.isEmpty {
            s += "<password>\(escapeXML(password))</password>\n"
        }
        s += "</auth>\n</config-auth>"
        return s
    }

    static func buildFormURLEncoded(fields: [(String, String)]) -> String {
        return fields.map { key, val in
            let ek = urlEncode(key)
            let ev = urlEncode(val)
            return "\(ek)=\(ev)"
        }.joined(separator: "&")
    }

    static func escapeXML(_ string: String) -> String {
        return string
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&apos;")
    }

    static func unescapeXML(_ string: String) -> String {
        return string
            .replacingOccurrences(of: "&quot;", with: "\"")
            .replacingOccurrences(of: "&apos;", with: "'")
            .replacingOccurrences(of: "&gt;", with: ">")
            .replacingOccurrences(of: "&lt;", with: "<")
            .replacingOccurrences(of: "&amp;", with: "&")
    }

    static func urlEncode(_ string: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-_.~")
        return string.addingPercentEncoding(withAllowedCharacters: allowed) ?? string
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
            let authGroup = f["auth-group"]?.string
            let cookie = f["cookie"]?.string
            let sni = f["sni"]?.string ?? server // importers normalise tls-name / servername / peer into sni
            let skipCertVerify = f["skip-cert-verify"]?.bool ?? false
            let serverCertPin = f["server-cert-pin"]?.string
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
        // NCProxy.port maps out-of-range values to nil, so a present-but-nil port is invalid (70000 must not fall back to 443).
        if f["port"] != nil, (p.port ?? 0) <= 0 {
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
