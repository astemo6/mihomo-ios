import Foundation

/// TrustTunnel (AdGuard) protocol models, deep link decoder/encoder, and wire primitives.
///
/// Specification:
/// - TrustTunnel Protocol Specification v1.0 (AdGuard VPN, Apache 2.0 License)
///   Repository: https://github.com/TrustTunnel/TrustTunnel (formerly AdguardTeam/TrustTunnel)
/// - TrustTunnel Deep Link Specification v2 (`tt://?<base64url>`)
///   RFC 9000 variable-length integer (VarInt) + Tag-Length-Value (TLV) binary payload
/// - Upstream transports:
///   1. HTTP/2 over TLS (ALPN: `h2`, initial window: 131072)
///   2. HTTP/3 over QUIC (ALPN: `h3`, RFC 9000 QUIC v1)
/// - Authentication: HTTP Basic Auth on every CONNECT request:
///   `proxy-authorization: Basic <base64(username:password)>`
public enum NCTrustTunnel {

    public static let protoType = "trusttunnel"
    public static let defaultPort = 443
    public static let currentDeepLinkVersion: UInt64 = 2

    // MARK: - RFC 9000 Variable-Length Integer (VarInt)

    /// Decodes a QUIC / TLS variable-length integer (RFC 9000 §16).
    /// Returns decoded value and increments `offset`.
    public static func readVarInt(data: Data, offset: inout Int) -> UInt64? {
        guard offset < data.count else { return nil }
        let start = data.startIndex
        let b0 = data[start + offset]
        let prefix = b0 >> 6
        switch prefix {
        case 0:
            offset += 1
            return UInt64(b0 & 0x3f)
        case 1:
            guard offset + 2 <= data.count else { return nil }
            let val = (UInt64(b0 & 0x3f) << 8) | UInt64(data[start + offset + 1])
            offset += 2
            return val
        case 2:
            guard offset + 4 <= data.count else { return nil }
            let val = (UInt64(b0 & 0x3f) << 24)
                | (UInt64(data[start + offset + 1]) << 16)
                | (UInt64(data[start + offset + 2]) << 8)
                | UInt64(data[start + offset + 3])
            offset += 4
            return val
        case 3:
            guard offset + 8 <= data.count else { return nil }
            var val: UInt64 = UInt64(b0 & 0x3f)
            for i in 1..<8 {
                val = (val << 8) | UInt64(data[start + offset + i])
            }
            offset += 8
            return val
        default:
            return nil
        }
    }

    /// Encodes a variable-length integer (RFC 9000 §16).
    public static func writeVarInt(_ value: UInt64) -> Data {
        var out = Data()
        if value < (1 << 6) {
            out.append(UInt8(value))
        } else if value < (1 << 14) {
            out.append(UInt8(0x40 | (value >> 8)))
            out.append(UInt8(value & 0xff))
        } else if value < (1 << 30) {
            out.append(UInt8(0x80 | (value >> 24)))
            out.append(UInt8((value >> 16) & 0xff))
            out.append(UInt8((value >> 8) & 0xff))
            out.append(UInt8(value & 0xff))
        } else if value < (UInt64(1) << 62) {
            out.append(UInt8(0xc0 | (value >> 56)))
            for i in stride(from: 48, through: 0, by: -8) {
                out.append(UInt8((value >> i) & 0xff))
            }
        }
        return out
    }

    // MARK: - RFC 4648 Base64URL

    public static func base64URLDecode(_ string: String) -> Data? {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let mod4 = base64.count % 4
        if mod4 > 0 {
            base64.append(String(repeating: "=", count: 4 - mod4))
        }
        return Data(base64Encoded: base64)
    }

    public static func base64URLEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
    }

    // MARK: - TLV String Array Helper

    public static func decodeStringArray(_ data: Data) -> [String] {
        var result: [String] = []
        var off = 0
        while off < data.count {
            guard let len = readVarInt(data: data, offset: &off) else { break }
            guard off + Int(len) <= data.count else { break }
            let sub = data.subdata(in: (data.startIndex + off)..<(data.startIndex + off + Int(len)))
            if let s = String(data: sub, encoding: .utf8) {
                result.append(s)
            }
            off += Int(len)
        }
        return result
    }

    public static func encodeStringArray(_ list: [String]) -> Data {
        var out = Data()
        for s in list {
            let bytes = Data(s.utf8)
            out.append(writeVarInt(UInt64(bytes.count)))
            out.append(bytes)
        }
        return out
    }

    // MARK: - Certificate Helpers (DER <-> PEM)

    public static func derToPem(_ der: Data) -> String {
        let b64 = der.base64EncodedString()
        var lines: [String] = []
        var i = b64.startIndex
        while i < b64.endIndex {
            let next = b64.index(i, offsetBy: 64, limitedBy: b64.endIndex) ?? b64.endIndex
            lines.append(String(b64[i..<next]))
            i = next
        }
        return "-----BEGIN CERTIFICATE-----\n" + lines.joined(separator: "\n") + "\n-----END CERTIFICATE-----\n"
    }

    // MARK: - Deep Link Parser (`tt://?<base64url>`)

    /// Parses a `tt://?<payload>` deep-link URI into an `NCProxy`.
    static func parseDeepLink(_ uri: String) -> NCProxy? {
        let trimmed = uri.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.lowercased().hasPrefix("tt://") else { return nil }

        let remainder: String
        if let qIndex = trimmed.firstIndex(of: "?") {
            remainder = String(trimmed[trimmed.index(after: qIndex)...])
        } else {
            remainder = String(trimmed.dropFirst("tt://".count))
        }
        let clean = remainder.trimmingCharacters(in: CharacterSet(charactersIn: "/ "))
        guard !clean.isEmpty, let payload = base64URLDecode(clean) else { return nil }

        return parsePayload(payload)
    }

    /// Parses binary TLV payload (TrustTunnel Deep Link Spec).
    static func parsePayload(_ data: Data) -> NCProxy? {
        var off = 0
        var version: UInt64 = 0
        var hostname: String?
        var addresses: [String] = []
        var customSni: String?
        var hasIpv6: Bool = true
        var username: String?
        var password: String?
        var skipVerification: Bool = false
        var certificate: Data?
        var upstreamProtocol: UInt64 = 1 // 1 = http2, 2 = http3
        var antiDpi: Bool = false
        var clientRandomPrefix: String?
        var name: String?
        var dnsUpstreams: [String] = []
        var subscriptionUrl: String?
        var clientRandomAuthKey: String?

        while off < data.count {
            guard let tagRaw = readVarInt(data: data, offset: &off),
                  let len = readVarInt(data: data, offset: &off) else {
                return nil
            }
            guard off + Int(len) <= data.count else { return nil }
            let val = data.subdata(in: (data.startIndex + off)..<(data.startIndex + off + Int(len)))
            off += Int(len)

            switch tagRaw {
            case 0x00: // version (VarInt)
                var vOff = 0
                if let v = readVarInt(data: val, offset: &vOff) {
                    if v > currentDeepLinkVersion {
                        // Reject unsupported newer versions per DEEP_LINK.md
                        return nil
                    }
                    version = v
                }
            case 0x01: // hostname (String)
                hostname = String(data: val, encoding: .utf8)
            case 0x02: // addresses (String, one address:port per TLV entry)
                if let addr = String(data: val, encoding: .utf8) {
                    addresses.append(addr)
                }
            case 0x03: // custom_sni (String)
                customSni = String(data: val, encoding: .utf8)
            case 0x04: // has_ipv6 (Bool)
                if let first = val.first { hasIpv6 = (first != 0) }
            case 0x05: // username (String)
                username = String(data: val, encoding: .utf8)
            case 0x06: // password (String)
                password = String(data: val, encoding: .utf8)
            case 0x07: // skip_verification (Bool)
                if let first = val.first { skipVerification = (first != 0) }
            case 0x08: // certificate (Bytes, DER chain)
                certificate = val
            case 0x09: // upstream_protocol (VarInt: 0x01 = http2, 0x02 = http3)
                var pOff = 0
                if let p = readVarInt(data: val, offset: &pOff) {
                    upstreamProtocol = p
                } else if let first = val.first {
                    upstreamProtocol = UInt64(first)
                }
            case 0x0a: // anti_dpi (Bool)
                if let first = val.first { antiDpi = (first != 0) }
            case 0x0b: // client_random_prefix (String)
                clientRandomPrefix = String(data: val, encoding: .utf8)
            case 0x0c: // name (String)
                name = String(data: val, encoding: .utf8)
            case 0x0d: // dns_upstreams (String[])
                dnsUpstreams = decodeStringArray(val)
            case 0x0e: // subscription_url (String)
                subscriptionUrl = String(data: val, encoding: .utf8)
            case 0x0f: // client_random_auth_key (String)
                clientRandomAuthKey = String(data: val, encoding: .utf8)
            default:
                // Forward compatibility: unknown tags MUST be ignored per DEEP_LINK.md
                break
            }
        }

        // Validation rules per DEEP_LINK.md:
        if let subUrl = subscriptionUrl {
            guard subUrl.lowercased().hasPrefix("https://") else { return nil }
        } else {
            // When subscription_url is absent, static parameters are required
            guard let h = hostname, !h.isEmpty,
                  !addresses.isEmpty,
                  let u = username, !u.isEmpty,
                  let p = password, !p.isEmpty else {
                return nil
            }
        }

        // Determine server & port
        var server = hostname ?? ""
        var port = defaultPort
        if let firstAddr = addresses.first {
            let (h, p) = parseHostPort(firstAddr)
            server = h
            if let p { port = p }
        }

        let displayName = name ?? hostname ?? server
        let isQUIC = (upstreamProtocol == 2)
        let sni = customSni ?? hostname ?? server

        var fields: [String: NCJSONValue] = [
            "server": .string(server),
            "port": .number(Double(port)),
            "quic": .bool(isQUIC),
            "network": .string(isQUIC ? "h3" : "h2"),
            "skip-cert-verify": .bool(skipVerification),
            "has-ipv6": .bool(hasIpv6),
            "sni": .string(sni),
            "servername": .string(sni)
        ]

        if let username { fields["username"] = .string(username) }
        if let password { fields["password"] = .string(password) }
        if let hostname { fields["hostname"] = .string(hostname) }
        if let customSni { fields["custom-sni"] = .string(customSni) }

        if addresses.count > 1 {
            fields["addresses"] = .array(addresses.map { .string($0) })
        }
        if let cert = certificate {
            fields["certificate"] = .string(derToPem(cert))
        }
        if antiDpi {
            fields["anti-dpi"] = .bool(true)
        }
        if let prefix = clientRandomPrefix {
            fields["client-random-prefix"] = .string(prefix)
        }
        if let key = clientRandomAuthKey {
            fields["client-random-auth-key"] = .string(key)
        }
        if !dnsUpstreams.isEmpty {
            fields["dns-upstreams"] = .array(dnsUpstreams.map { .string($0) })
        }
        if let subUrl = subscriptionUrl {
            fields["subscription-url"] = .string(subUrl)
        }

        return NCProxy(name: displayName, type: protoType, fields: fields)
    }

    // MARK: - Deep Link Encoder

    public static func encodeDeepLink(
        hostname: String,
        addresses: [String],
        username: String,
        password: String,
        name: String? = nil,
        customSni: String? = nil,
        hasIpv6: Bool = true,
        skipVerification: Bool = false,
        upstreamProtocol: UInt64 = 1,
        antiDpi: Bool = false,
        clientRandomPrefix: String? = nil,
        clientRandomAuthKey: String? = nil,
        dnsUpstreams: [String] = [],
        subscriptionUrl: String? = nil
    ) -> String {
        var out = Data()

        // Tag 0x00: version 2
        out.append(writeVarInt(0x00))
        let vData = writeVarInt(currentDeepLinkVersion)
        out.append(writeVarInt(UInt64(vData.count)))
        out.append(vData)

        // Tag 0x01: hostname
        if !hostname.isEmpty {
            let hData = Data(hostname.utf8)
            out.append(writeVarInt(0x01))
            out.append(writeVarInt(UInt64(hData.count)))
            out.append(hData)
        }

        // Tag 0x02: addresses
        for addr in addresses {
            let aData = Data(addr.utf8)
            out.append(writeVarInt(0x02))
            out.append(writeVarInt(UInt64(aData.count)))
            out.append(aData)
        }

        // Tag 0x03: custom_sni
        if let cs = customSni, !cs.isEmpty {
            let csData = Data(cs.utf8)
            out.append(writeVarInt(0x03))
            out.append(writeVarInt(UInt64(csData.count)))
            out.append(csData)
        }

        // Tag 0x04: has_ipv6 (only encode if false)
        if !hasIpv6 {
            out.append(writeVarInt(0x04))
            out.append(writeVarInt(1))
            out.append(0x00)
        }

        // Tag 0x05: username
        if !username.isEmpty {
            let uData = Data(username.utf8)
            out.append(writeVarInt(0x05))
            out.append(writeVarInt(UInt64(uData.count)))
            out.append(uData)
        }

        // Tag 0x06: password
        if !password.isEmpty {
            let pData = Data(password.utf8)
            out.append(writeVarInt(0x06))
            out.append(writeVarInt(UInt64(pData.count)))
            out.append(pData)
        }

        // Tag 0x07: skip_verification (only encode if true)
        if skipVerification {
            out.append(writeVarInt(0x07))
            out.append(writeVarInt(1))
            out.append(0x01)
        }

        // Tag 0x09: upstream_protocol (1 = http2, 2 = http3)
        if upstreamProtocol != 1 {
            let pData = writeVarInt(upstreamProtocol)
            out.append(writeVarInt(0x09))
            out.append(writeVarInt(UInt64(pData.count)))
            out.append(pData)
        }

        // Tag 0x0a: anti_dpi (only encode if true)
        if antiDpi {
            out.append(writeVarInt(0x0a))
            out.append(writeVarInt(1))
            out.append(0x01)
        }

        // Tag 0x0b: client_random_prefix
        if let pref = clientRandomPrefix, !pref.isEmpty {
            let pData = Data(pref.utf8)
            out.append(writeVarInt(0x0b))
            out.append(writeVarInt(UInt64(pData.count)))
            out.append(pData)
        }

        // Tag 0x0c: name
        if let n = name, !n.isEmpty {
            let nData = Data(n.utf8)
            out.append(writeVarInt(0x0c))
            out.append(writeVarInt(UInt64(nData.count)))
            out.append(nData)
        }

        // Tag 0x0d: dns_upstreams
        if !dnsUpstreams.isEmpty {
            let dData = encodeStringArray(dnsUpstreams)
            out.append(writeVarInt(0x0d))
            out.append(writeVarInt(UInt64(dData.count)))
            out.append(dData)
        }

        // Tag 0x0e: subscription_url
        if let sub = subscriptionUrl, !sub.isEmpty {
            let sData = Data(sub.utf8)
            out.append(writeVarInt(0x0e))
            out.append(writeVarInt(UInt64(sData.count)))
            out.append(sData)
        }

        // Tag 0x0f: client_random_auth_key
        if let key = clientRandomAuthKey, !key.isEmpty {
            let kData = Data(key.utf8)
            out.append(writeVarInt(0x0f))
            out.append(writeVarInt(UInt64(kData.count)))
            out.append(kData)
        }

        return "tt://?" + base64URLEncode(out)
    }

    // MARK: - Standard URI Parser (`trusttunnel://` or `trust-tunnel://`)

    static func parseURI(_ uri: String) -> NCProxy? {
        guard let url = URL(string: uri) else { return nil }
        let scheme = url.scheme?.lowercased() ?? ""
        guard scheme == "trusttunnel" || scheme == "trust-tunnel" else { return nil }
        guard let host = url.host, !host.isEmpty else { return nil }
        let port = url.port ?? defaultPort
        let username = url.user?.removingPercentEncoding ?? ""
        let password = url.password?.removingPercentEncoding ?? ""
        let name = url.fragment?.removingPercentEncoding ?? host

        var queryMap: [String: String] = [:]
        if let query = url.query {
            for part in query.components(separatedBy: "&") {
                let kv = part.components(separatedBy: "=")
                if kv.count == 2 {
                    let k = kv[0].lowercased()
                    let v = kv[1].removingPercentEncoding ?? kv[1]
                    queryMap[k] = v
                }
            }
        }

        let isQUIC = (queryMap["quic"] == "true" || queryMap["quic"] == "1" || queryMap["h3"] == "true" || queryMap["h3"] == "1")
        let sni = queryMap["sni"] ?? queryMap["custom-sni"] ?? host
        let skipCert = (queryMap["skip-cert-verify"] == "true" || queryMap["skip_verification"] == "true" || queryMap["allowinsecure"] == "1")

        var fields: [String: NCJSONValue] = [
            "server": .string(host),
            "port": .number(Double(port)),
            "username": .string(username),
            "password": .string(password),
            "quic": .bool(isQUIC),
            "network": .string(isQUIC ? "h3" : "h2"),
            "sni": .string(sni),
            "servername": .string(sni),
            "skip-cert-verify": .bool(skipCert)
        ]
        if let alpn = queryMap["alpn"] {
            fields["alpn"] = .string(alpn)
        }
        if let ms = queryMap["max-streams"], let n = Int(ms) {
            fields["max-streams"] = .number(Double(n))
        }
        if let headers = queryMap["headers"] {
            fields["headers"] = .string(headers)
        }
        return NCProxy(name: name, type: protoType, fields: fields)
    }

    // MARK: - Address Helper

    public static func parseHostPort(_ address: String) -> (host: String, port: Int?) {
        var host = address
        var port: Int? = nil
        if address.hasPrefix("["), let close = address.firstIndex(of: "]") {
            host = String(address[address.index(after: address.startIndex)..<close])
            let tail = address[address.index(after: close)...]
            if tail.hasPrefix(":") {
                port = Int(tail.dropFirst())
            }
        } else if let colon = address.lastIndex(of: ":") {
            host = String(address[..<colon])
            port = Int(address[address.index(after: colon)...])
        }
        return (host, port)
    }
}

// MARK: - Wire Formats (for S1 reference and S2 data plane)

public enum NCTrustTunnelWire {
    public static let udpPseudoHost = "_udp2"
    public static let icmpPseudoHost = "_icmp"
    public static let checkPseudoHost = "_check"

    /// Generates HTTP CONNECT request headers per TrustTunnel spec §5.1 / §6.2.
    public static func connectHeaders(
        authority: String,
        username: String,
        password: String,
        userAgent: String? = nil
    ) -> [(String, String)] {
        let creds = Data("\(username):\(password)".utf8).base64EncodedString()
        let ua: String
        if let userAgent {
            ua = userAgent
        } else if authority == udpPseudoHost {
            ua = "iOS _udp2"
        } else if authority == icmpPseudoHost {
            ua = "iOS _icmp"
        } else {
            ua = "iOS TrustTunnel"
        }
        return [
            (":method", "CONNECT"),
            (":authority", authority),
            ("user-agent", ua),
            ("proxy-authorization", "Basic \(creds)")
        ]
    }

    /// QPACK field section for TrustTunnel HTTP/3 CONNECT request (RFC 9204 / RFC 9220)
    public static func qpackConnectHeaders(
        authority: String,
        username: String,
        password: String,
        userAgent: String? = nil
    ) -> Data {
        let creds = Data("\(username):\(password)".utf8).base64EncodedString()
        let ua: String
        if let userAgent {
            ua = userAgent
        } else if authority == udpPseudoHost {
            ua = "iOS _udp2"
        } else if authority == icmpPseudoHost {
            ua = "iOS _icmp"
        } else {
            ua = "iOS TrustTunnel"
        }
        var out = Data([0x00, 0x00]) // Required Insert Count = 0, Base = 0
        // :method CONNECT -> QPACK static index 15: 1 T=1 index(6) -> 0xC0 | 15 = 0xCF
        out.append(NCHy2.qpackEncodeInteger(15, prefixBits: 6, flags: 0xC0))
        // :authority <authority> -> Literal with static name ref 0: 0 1 N=0 T=1 index(4) -> 0x50 | 0 = 0x50
        out.append(NCHy2.qpackEncodeInteger(0, prefixBits: 4, flags: 0x50))
        out.append(NCHy2.qpackEncodeString(authority))
        // proxy-authorization: Basic <creds> -> Literal with literal name: 0 0 1 N=0 H=0 nameLen(3) -> 0x20
        out.append(NCHy2.qpackEncodeString("proxy-authorization", prefixBits: 3, flags: 0x20))
        out.append(NCHy2.qpackEncodeString("Basic \(creds)"))
        // user-agent: <ua> -> Literal with static name ref 95 (RFC 9204 Appendix A; 94 is upgrade-insecure-requests)
        out.append(NCHy2.qpackEncodeInteger(95, prefixBits: 4, flags: 0x50))
        out.append(NCHy2.qpackEncodeString(ua))
        return out
    }

    /// Padded IP Address encoding per TrustTunnel spec §11.2:
    /// - IPv4: zero-padded to 16 bytes (12 zero bytes + 4 bytes IPv4)
    /// - IPv6: 16 bytes
    public static func padIPAddress(_ ipString: String) -> Data? {
        if let ip = NCIP(ipString) {
            switch ip {
            case .v4(let v4):
                var d = Data(count: 12)
                d.append(UInt8((v4 >> 24) & 0xff))
                d.append(UInt8((v4 >> 16) & 0xff))
                d.append(UInt8((v4 >> 8) & 0xff))
                d.append(UInt8(v4 & 0xff))
                return d
            case .v6(let v6):
                return Data(v6)
            }
        }
        return nil
    }

    /// Outgoing UDP packet framing (Client -> Endpoint) per TrustTunnel spec §6.3:
    /// `[Length u32 BE][SrcIP 16B][SrcPort u16 BE][DstIP 16B][DstPort u16 BE][App Name Len u8][App Name][Payload]`
    public static func encodeClientPacket(
        srcIP: Data,
        srcPort: UInt16,
        dstIP: Data,
        dstPort: UInt16,
        appName: String = "",
        payload: Data
    ) -> Data {
        guard srcIP.count == 16, dstIP.count == 16 else { return Data() }
        let appData = Data(appName.utf8)
        let appLen = UInt8(clamping: appData.count)
        let innerLen = 16 + 2 + 16 + 2 + 1 + Int(appLen) + payload.count
        var out = Data()
        out.appendBE32(UInt32(innerLen))
        out.append(srcIP)
        out.appendBE16(srcPort)
        out.append(dstIP)
        out.appendBE16(dstPort)
        out.append(appLen)
        if appLen > 0 {
            out.append(appData.prefix(Int(appLen)))
        }
        out.append(payload)
        return out
    }

    /// Incoming UDP packet framing (Endpoint -> Client) per TrustTunnel spec §6.4:
    /// `[Length u32 BE][SrcIP 16B][SrcPort u16 BE][DstIP 16B][DstPort u16 BE][Payload]`
    public static func encodeServerPacket(
        srcIP: Data,
        srcPort: UInt16,
        dstIP: Data,
        dstPort: UInt16,
        payload: Data
    ) -> Data {
        guard srcIP.count == 16, dstIP.count == 16 else { return Data() }
        let innerLen = 16 + 2 + 16 + 2 + payload.count
        var out = Data()
        out.appendBE32(UInt32(innerLen))
        out.append(srcIP)
        out.appendBE16(srcPort)
        out.append(dstIP)
        out.appendBE16(dstPort)
        out.append(payload)
        return out
    }

    public struct UDPPacket: Equatable {
        public let srcIP: Data
        public let srcPort: UInt16
        public let dstIP: Data
        public let dstPort: UInt16
        public let appName: String?
        public let payload: Data

        public init(srcIP: Data, srcPort: UInt16, dstIP: Data, dstPort: UInt16, appName: String? = nil, payload: Data) {
            self.srcIP = srcIP
            self.srcPort = srcPort
            self.dstIP = dstIP
            self.dstPort = dstPort
            self.appName = appName
            self.payload = payload
        }
    }

    /// Decode incoming UDP packet (Endpoint -> Client) per TrustTunnel spec §6.4:
    /// `[Length u32 BE][SrcIP 16B][SrcPort u16 BE][DstIP 16B][DstPort u16 BE][Payload]`
    public static func decodeServerPacket(data: Data, offset: inout Int) -> UDPPacket? {
        guard offset + 4 <= data.count else { return nil }
        let start = data.startIndex + offset
        let len = Int(data[start]) << 24 | Int(data[start + 1]) << 16 | Int(data[start + 2]) << 8 | Int(data[start + 3])
        guard offset + 4 + len <= data.count else { return nil }
        guard len >= 36 else { return nil } // 16 (src) + 2 + 16 (dst) + 2
        let p = start + 4
        let srcIP = data.subdata(in: p..<(p + 16))
        let srcPort = UInt16(data[p + 16]) << 8 | UInt16(data[p + 17])
        let dstIP = data.subdata(in: (p + 18)..<(p + 34))
        let dstPort = UInt16(data[p + 34]) << 8 | UInt16(data[p + 35])
        let payload = data.subdata(in: (p + 36)..<(p + len))
        offset += 4 + len
        return UDPPacket(srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort, appName: nil, payload: payload)
    }

    /// Decode outgoing UDP packet (Client -> Endpoint) per TrustTunnel spec §6.3:
    /// `[Length u32 BE][SrcIP 16B][SrcPort u16 BE][DstIP 16B][DstPort u16 BE][App Name Len u8][App Name][Payload]`
    public static func decodeClientPacket(data: Data, offset: inout Int) -> UDPPacket? {
        guard offset + 4 <= data.count else { return nil }
        let start = data.startIndex + offset
        let len = Int(data[start]) << 24 | Int(data[start + 1]) << 16 | Int(data[start + 2]) << 8 | Int(data[start + 3])
        guard offset + 4 + len <= data.count else { return nil }
        guard len >= 37 else { return nil } // 16 + 2 + 16 + 2 + 1
        let p = start + 4
        let srcIP = data.subdata(in: p..<(p + 16))
        let srcPort = UInt16(data[p + 16]) << 8 | UInt16(data[p + 17])
        let dstIP = data.subdata(in: (p + 18)..<(p + 34))
        let dstPort = UInt16(data[p + 34]) << 8 | UInt16(data[p + 35])
        let appLen = Int(data[p + 36])
        guard 37 + appLen <= len else { return nil }
        let appData = data.subdata(in: (p + 37)..<(p + 37 + appLen))
        let appName = String(data: appData, encoding: .utf8) ?? ""
        let payload = data.subdata(in: (p + 37 + appLen)..<(p + len))
        offset += 4 + len
        return UDPPacket(srcIP: srcIP, srcPort: srcPort, dstIP: dstIP, dstPort: dstPort, appName: appName, payload: payload)
    }
}
