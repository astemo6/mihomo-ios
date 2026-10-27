import CryptoKit
import Foundation
import Network

/// MASQUE protocol models, wire format primitives, and configuration parser.
///
/// Standards implemented / tracked:
/// - RFC 9298: Proxying UDP in HTTP (CONNECT-UDP)
/// - RFC 9484: Proxying IP in HTTP (CONNECT-IP)
/// - RFC 9297: HTTP Datagrams and the Capsule Protocol
/// - RFC 8441 / RFC 9220: Bootstrapping WebSockets with HTTP/2 / Extended CONNECT in HTTP/3
///
/// Two primary architectural lines:
/// 1. CONNECT-UDP (Surge / RFC 9298 style):
///    Multiplexed UDP tunnels over HTTP/3 stream(s) using HTTP Datagrams with Context ID 0.
/// 2. CONNECT-IP (Clash.Meta / Cloudflare WARP MASQUE / RFC 9484 style):
///    Full IP packet tunnel over HTTP/3 or HTTP/2, encapsulating raw IPv4/IPv6 packets in
///    HTTP Datagrams with Context ID 0, coordinated via Capsule Protocol (ADDRESS_ASSIGN, etc.).
enum NCMASQUE {

    // MARK: - Constants

    /// Capsule types defined in RFC 9297 §5.4 and RFC 9484 §12.3.
    static let capsuleTypeDatagram: UInt64 = 0x00
    static let capsuleTypeAddressAssign: UInt64 = 0x01
    static let capsuleTypeAddressRequest: UInt64 = 0x02
    static let capsuleTypeRouteAdvertisement: UInt64 = 0x03

    /// HTTP/3 Setting IDs (RFC 9220 §3, RFC 9297 §2.1.1, draft-ietf-masque-h3-datagram).
    static let settingEnableConnectProtocol: UInt64 = 0x08
    static let settingH3Datagram: UInt64 = 0x33
    static let settingH3DatagramDraft00: UInt64 = 0x276

    /// Default Cloudflare WARP MASQUE parameters.
    static let defaultWarpSNI = "consumer-masque.cloudflareclient.com"
    static let defaultWarpL4SNI = "consumer-masque-proxy.cloudflareclient.com"
    static let defaultWarpURI = "https://cloudflareaccess.com"
    static let defaultConnectUDPPath = "/.well-known/masque/udp/{target_host}/{target_port}/"
    static let defaultConnectIPPath = "/.well-known/masque/ip/*/*/"
    static let defaultMTU = 1280

    // MARK: - Mode

    enum Mode: String, Equatable {
        /// RFC 9298: CONNECT-UDP (L4 datagram proxying).
        case connectUDP = "connect-udp"
        /// RFC 9484: CONNECT-IP (L3 IP packet proxying, default for WARP).
        case connectIP = "connect-ip"
        /// HTTP/3 CONNECT TCP proxying (Clash.Meta network: h3-l4proxy).
        case l4Proxy = "h3-l4proxy"
    }

    // MARK: - Config

    struct Config: Equatable {
        let name: String
        let server: String
        let port: Int
        let mode: Mode
        let privateKey: String?
        let publicKey: String?
        let ip: String?
        let ipv6: String?
        let uri: String
        let sni: String?
        let alpn: [String]
        let mtu: Int
        let udp: Bool
        let remoteDnsResolve: Bool
        let dns: [String]
        let network: String
        let congestionController: String?
        let username: String?
        let password: String?
        let skipCertVerify: Bool
        let rawFields: [String: NCJSONValue]

        init?(proxy: NCProxy) {
            guard let srv = proxy.server, !srv.isEmpty, let p = proxy.port, p > 0 else {
                return nil
            }
            name = proxy.name
            server = srv
            port = p
            let f = proxy.fields

            let net = f["network"]?.string?.lowercased() ?? "quic"
            network = net

            // Explicit mode wins; otherwise a WARP-style key pair means CONNECT-IP and a credential-only
            // (Surge-style) node means CONNECT-UDP (fix/nc-proto-masque-int: it used to fall to CONNECT-IP).
            let explicit = f["mode"]?.string?.lowercased()
            if net == "h3-l4proxy" {
                mode = .l4Proxy
            } else if explicit == "connect-ip" {
                mode = .connectIP
            } else if explicit == "connect-udp" {
                mode = .connectUDP
            } else if !(f["private-key"]?.string ?? f["privateKey"]?.string ?? "").isEmpty {
                mode = .connectIP
            } else {
                mode = .connectUDP
            }

            privateKey = NCMASQUE.cleanBase64Key(f["private-key"]?.string ?? f["privateKey"]?.string)
            publicKey = NCMASQUE.cleanBase64Key(f["public-key"]?.string ?? f["publicKey"]?.string)
            ip = f["ip"]?.string ?? f["tunnelIp"]?.string ?? f["address"]?.string
            ipv6 = f["ipv6"]?.string

            let rawURI = f["uri"]?.string ?? f["template"]?.string
            if let rawURI, !rawURI.isEmpty {
                uri = rawURI
            } else {
                uri = mode == .connectUDP ? NCMASQUE.defaultConnectUDPPath : NCMASQUE.defaultWarpURI
            }

            sni = f["sni"]?.string
            if let alpnArr = f["alpn"]?.array?.compactMap({ $0.string }), !alpnArr.isEmpty {
                alpn = alpnArr
            } else if let alpnStr = f["alpn"]?.string, !alpnStr.isEmpty {
                alpn = alpnStr.split(separator: ",").map { String($0.trimmingCharacters(in: .whitespaces)) }
            } else {
                alpn = net == "h2" ? ["h2"] : ["h3"]
            }

            mtu = f["mtu"]?.int ?? NCMASQUE.defaultMTU
            udp = f["udp"]?.bool ?? true
            remoteDnsResolve = f["remote-dns-resolve"]?.bool ?? (f["remote-dns"]?.bool ?? false)

            if let dnsArr = f["dns"]?.array?.compactMap({ $0.string }) {
                dns = dnsArr
            } else if let dnsStr = f["dns"]?.string, !dnsStr.isEmpty {
                dns = dnsStr.split(separator: ",").map { String($0.trimmingCharacters(in: .whitespaces)) }
            } else {
                dns = []
            }

            congestionController = f["congestion-controller"]?.string ?? f["cc"]?.string
            username = f["username"]?.string
            password = proxy.password ?? f["password"]?.string
            skipCertVerify = f["skip-cert-verify"]?.bool ?? false
            rawFields = f
        }
    }

    // MARK: - Key Cleaning

    /// Strip PEM headers, footers, whitespace, and return normalized base64 key string.
    static func cleanBase64Key(_ raw: String?) -> String? {
        guard let raw else { return nil }
        var cleaned = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if cleaned.isEmpty { return nil }
        let lines = cleaned.components(separatedBy: .newlines)
        let filtered = lines.filter { line in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            return !trimmed.hasPrefix("-----") && !trimmed.isEmpty
        }
        cleaned = filtered.joined().replacingOccurrences(of: " ", with: "")
        return cleaned.isEmpty ? nil : cleaned
    }

    // MARK: - Shadowrocket URI Parser & Generator

    /// Parse Shadowrocket `masque://<host>:<port>?<query>#<name>` share URI.
    ///
    /// Query parameters accepted (aligned with Shadowrocket 2.2.90+ and community generators):
    /// - `publicKey`, `public_key`, `public-key`: base64 DER public key
    /// - `privateKey`, `private_key`, `private-key`: base64 private key or PEM
    /// - `ip`, `address`, `tunnelIp`: tunnel IPv4 (or CIDR)
    /// - `ipv6`: tunnel IPv6 (or CIDR)
    /// - `dns`: comma-separated DNS list
    /// - `udp`: "1" / "0" / boolean
    /// - `cc`, `congestion_control`, `congestion-controller`: congestion controller
    /// - `flag`: metadata flag / label
    /// - `sni`: custom SNI
    /// - `alpn`: custom ALPN
    /// - `template`, `uri`: URI template
    /// - `network`: transport network (e.g. "h2", "h3-l4proxy")
    static func parseShadowrocket(_ uri: String) -> NCProxy? {
        guard let sep = uri.range(of: "://") else { return nil }
        let scheme = uri[..<sep.lowerBound].lowercased()
        guard scheme == "masque" else { return nil }
        let rest = String(uri[sep.upperBound...])

        var s = rest
        var name = ""
        if let hash = s.firstIndex(of: "#") {
            name = String(s[s.index(after: hash)...]).removingPercentEncoding ?? ""
            s = String(s[..<hash])
        }

        var query: [String: String] = [:]
        if let q = s.firstIndex(of: "?") {
            let qs = s[s.index(after: q)...]
            s = String(s[..<q])
            for pair in qs.split(separator: "&") {
                let kv = pair.split(separator: "=", maxSplits: 1)
                guard !kv.isEmpty else { continue }
                let key = String(kv[0]).trimmingCharacters(in: .whitespaces)
                let val = kv.count > 1 ? (String(kv[1]).removingPercentEncoding ?? String(kv[1])) : ""
                query[key] = val
            }
        }

        // Host and port (supports [v6]:port or host:port).
        var host = s
        var port: Int? = nil
        if host.hasPrefix("["), let close = host.firstIndex(of: "]") {
            let v6 = String(host[host.index(after: host.startIndex)..<close])
            let tail = host[host.index(after: close)...]
            if tail.hasPrefix(":") { port = Int(tail.dropFirst()) }
            host = v6
        } else if let colon = host.lastIndex(of: ":"), host.filter({ $0 == ":" }).count == 1 {
            port = Int(host[host.index(after: colon)...])
            host = String(host[..<colon])
        }

        guard !host.isEmpty, let p = port, p > 0 else { return nil }

        func firstQ(_ keys: [String]) -> String? {
            for k in keys {
                if let v = query[k], !v.isEmpty { return v }
            }
            return nil
        }

        var fields: [String: NCJSONValue] = [
            "server": .string(host),
            "port": .number(Double(p)),
        ]

        if let priv = cleanBase64Key(firstQ(["privateKey", "private_key", "private-key"])) {
            fields["private-key"] = .string(priv)
        }
        if let pub = cleanBase64Key(firstQ(["publicKey", "public_key", "public-key", "peer_public_key"])) {
            fields["public-key"] = .string(pub)
        }

        if let addrs = firstQ(["ip", "address", "tunnelIp", "ips"]) {
            for part in addrs.split(separator: ",") {
                let item = part.trimmingCharacters(in: .whitespaces)
                let rawIP = item.split(separator: "/").first.map(String.init) ?? item
                if rawIP.contains(":") {
                    if fields["ipv6"] == nil { fields["ipv6"] = .string(rawIP) }
                } else {
                    if fields["ip"] == nil { fields["ip"] = .string(rawIP) }
                }
            }
        }
        if let v6 = firstQ(["ipv6"]) {
            let rawIP = v6.split(separator: "/").first.map(String.init) ?? v6
            fields["ipv6"] = .string(rawIP)
        }

        if let dns = firstQ(["dns"]) {
            let list = dns.split(separator: ",").map { String($0.trimmingCharacters(in: .whitespaces)) }
            fields["dns"] = .array(list.map { .string($0) })
            fields["remote-dns-resolve"] = .bool(true)
        }

        if let udpStr = firstQ(["udp"]) {
            fields["udp"] = .bool(udpStr == "1" || udpStr.lowercased() == "true")
        } else {
            fields["udp"] = .bool(true)
        }

        if let cc = firstQ(["cc", "congestion_control", "congestion-controller"]) {
            fields["congestion-controller"] = .string(cc)
        }

        if let flag = firstQ(["flag"]) {
            fields["flag"] = .string(flag)
        }
        if let sni = firstQ(["sni"]) {
            fields["sni"] = .string(sni)
        }
        if let alpn = firstQ(["alpn"]) {
            fields["alpn"] = .array(alpn.split(separator: ",").map { .string(String($0.trimmingCharacters(in: .whitespaces))) })
        }
        if let uriTmpl = firstQ(["template", "uri"]) {
            fields["uri"] = .string(uriTmpl)
        }
        if let net = firstQ(["network"]) {
            fields["network"] = .string(net.lowercased())
        }
        if let mtuStr = firstQ(["mtu"]), let mtu = Int(mtuStr) {
            fields["mtu"] = .number(Double(mtu))
        }

        let nodeName = name.isEmpty ? "\(host):\(p)" : name
        return NCProxy(name: nodeName, type: "masque", fields: fields)
    }

    /// Encode a proxy dictionary into a Shadowrocket compatible `masque://` share URI.
    static func encodeShareLink(_ m: [String: Any]) throws -> String {
        let name = (m["name"] as? String) ?? ""
        let server = (m["server"] as? String) ?? ""
        let port: Int
        if let p = m["port"] as? Int { port = p }
        else if let pStr = m["port"] as? String, let p = Int(pStr) { port = p }
        else if let pNum = m["port"] as? NSNumber { port = pNum.intValue }
        else { port = 443 }

        guard !server.isEmpty else {
            throw NSError(domain: "NCMASQUE", code: 1, userInfo: [NSLocalizedDescriptionKey: "MASQUE 节点缺少服务器地址"])
        }

        func enc(_ v: String) -> String {
            v.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)?
                .replacingOccurrences(of: "%2C", with: ",") ?? v
        }

        var params: [String] = []

        if let pub = cleanBase64Key(m["public-key"] as? String ?? m["publicKey"] as? String) {
            params.append("publicKey=\(enc(pub))")
        }
        if let priv = cleanBase64Key(m["private-key"] as? String ?? m["privateKey"] as? String) {
            params.append("privateKey=\(enc(priv))")
        }
        if let ip = m["ip"] as? String ?? m["tunnelIp"] as? String, !ip.isEmpty {
            params.append("ip=\(enc(ip))")
        }
        if let ipv6 = m["ipv6"] as? String, !ipv6.isEmpty {
            params.append("ipv6=\(enc(ipv6))")
        }
        if let dns = m["dns"] as? [String], !dns.isEmpty {
            params.append("dns=\(enc(dns.joined(separator: ", ")))")
        } else if let dnsStr = m["dns"] as? String, !dnsStr.isEmpty {
            params.append("dns=\(enc(dnsStr))")
        }

        let udp = (m["udp"] as? Bool) ?? true
        params.append("udp=\(udp ? "1" : "0")")

        if let cc = m["congestion-controller"] as? String ?? m["cc"] as? String, !cc.isEmpty {
            params.append("cc=\(enc(cc))")
        }
        if let flag = m["flag"] as? String, !flag.isEmpty {
            params.append("flag=\(enc(flag))")
        }
        if let sni = m["sni"] as? String, !sni.isEmpty {
            params.append("sni=\(enc(sni))")
        }
        if let uri = m["uri"] as? String ?? m["template"] as? String, !uri.isEmpty {
            params.append("uri=\(enc(uri))")
        }

        let hostFormatted = server.contains(":") && !server.hasPrefix("[") ? "[\(server)]" : server
        let frag = name.addingPercentEncoding(withAllowedCharacters: .urlFragmentAllowed) ?? name
        let qStr = params.isEmpty ? "" : "?\(params.joined(separator: "&"))"
        return "masque://\(hostFormatted):\(port)\(qStr)#\(frag)"
    }

    // MARK: - Variable-Length Integer (QUIC RFC 9000 §16)

    static func varintEncode(_ value: UInt64) -> Data {
        if value < 64 {
            return Data([UInt8(value)])
        } else if value < 16384 {
            return Data([UInt8(0x40 | (value >> 8)), UInt8(value & 0xff)])
        } else if value < 1073741824 {
            return Data([
                UInt8(0x80 | (value >> 24)),
                UInt8((value >> 16) & 0xff),
                UInt8((value >> 8) & 0xff),
                UInt8(value & 0xff)
            ])
        } else {
            var out = Data([UInt8(0xc0 | (value >> 56))])
            for i in (0..<7).reversed() {
                out.append(UInt8((value >> (i * 8)) & 0xff))
            }
            return out
        }
    }

    static func varintDecode(_ data: Data, at offset: Int = 0) -> (value: UInt64, length: Int)? {
        guard offset < data.count else { return nil }
        let idx = data.startIndex + offset
        let first = data[idx]
        let prefix = first >> 6
        switch prefix {
        case 0:
            return (UInt64(first & 0x3f), 1)
        case 1:
            guard offset + 2 <= data.count else { return nil }
            let b1 = data[idx + 1]
            let v = (UInt64(first & 0x3f) << 8) | UInt64(b1)
            return (v, 2)
        case 2:
            guard offset + 4 <= data.count else { return nil }
            var v = UInt64(first & 0x3f)
            for i in 1..<4 { v = (v << 8) | UInt64(data[idx + i]) }
            return (v, 4)
        default:
            guard offset + 8 <= data.count else { return nil }
            var v = UInt64(first & 0x3f)
            for i in 1..<8 { v = (v << 8) | UInt64(data[idx + i]) }
            return (v, 8)
        }
    }

    // MARK: - HTTP/3 Datagram Header (RFC 9297 §2.1 + RFC 9298 §5 / RFC 9484 §6)

    /// Encode an HTTP/3 Datagram for a QUIC DATAGRAM frame:
    /// Quarter Stream ID (varint = streamID / 4) + Context ID (varint, 0 for payload) + payload.
    static func encodeH3Datagram(streamID: UInt64, contextID: UInt64 = 0, payload: Data) -> Data {
        var out = varintEncode(streamID / 4)
        out.append(varintEncode(contextID))
        out.append(payload)
        return out
    }

    /// Decode an HTTP/3 Datagram received from a QUIC DATAGRAM frame payload.
    static func decodeH3Datagram(_ packet: Data) -> (streamID: UInt64, contextID: UInt64, payload: Data)? {
        guard let (quarterStreamID, qLen) = varintDecode(packet, at: 0) else { return nil }
        guard let (contextID, cLen) = varintDecode(packet, at: qLen) else { return nil }
        let headerLen = qLen + cLen
        guard packet.count >= headerLen else { return nil }
        let payload = Data(packet[(packet.startIndex + headerLen)...])
        return (quarterStreamID * 4, contextID, payload)
    }

    // MARK: - Capsule Protocol (RFC 9297 §3.2, §3.5)

    struct Capsule: Equatable {
        let type: UInt64
        let value: Data
    }

    static func encodeCapsule(type: UInt64, value: Data) -> Data {
        var out = varintEncode(type)
        out.append(varintEncode(UInt64(value.count)))
        out.append(value)
        return out
    }

    /// Incremental Capsule Protocol stream parser.
    struct CapsuleParser {
        private var buffer = Data()

        mutating func feed(_ data: Data) -> [Capsule] {
            buffer.append(data)
            var capsules: [Capsule] = []
            var offset = 0
            while offset < buffer.count {
                guard let (type, tLen) = varintDecode(buffer, at: offset) else { break }
                guard let (length, lLen) = varintDecode(buffer, at: offset + tLen) else { break }
                let headerLen = tLen + lLen
                let len = Int(length)
                guard offset + headerLen + len <= buffer.count else { break }
                let valStart = buffer.startIndex + offset + headerLen
                let valEnd = valStart + len
                capsules.append(Capsule(type: type, value: Data(buffer[valStart..<valEnd])))
                offset += headerLen + len
            }
            if offset >= buffer.count {
                buffer = Data()
            } else if offset > 0 {
                buffer = Data(buffer[(buffer.startIndex + offset)...])
            }
            return capsules
        }
    }

    // MARK: - RFC 9484 Capsule Values

    /// ADDRESS_ASSIGN Capsule (Type 0x01): assigned IP prefixes.
    struct AssignedAddress: Equatable {
        let requestID: UInt64
        let ipVersion: UInt8 // 4 or 6
        let address: Data    // 4 or 16 bytes
        let prefixLength: UInt8

        func encode() -> Data {
            var out = varintEncode(requestID)
            out.append(ipVersion)
            out.append(address)
            out.append(prefixLength)
            return out
        }

        static func decodeSequence(_ data: Data) -> [AssignedAddress]? {
            var out: [AssignedAddress] = []
            var offset = 0
            while offset < data.count {
                guard let (reqID, rLen) = varintDecode(data, at: offset) else { return nil }
                offset += rLen
                guard offset < data.count else { return nil }
                let ver = data[data.startIndex + offset]
                offset += 1
                let addrLen = ver == 4 ? 4 : (ver == 6 ? 16 : 0)
                guard addrLen > 0, offset + addrLen <= data.count else { return nil }
                let addr = Data(data[(data.startIndex + offset)..<(data.startIndex + offset + addrLen)])
                offset += addrLen
                guard offset < data.count else { return nil }
                let prefix = data[data.startIndex + offset]
                offset += 1
                out.append(AssignedAddress(requestID: reqID, ipVersion: ver, address: addr, prefixLength: prefix))
            }
            return out
        }
    }

    /// ADDRESS_REQUEST Capsule (Type 0x02): client address request.
    struct RequestedAddress: Equatable {
        let requestID: UInt64
        let ipVersion: UInt8 // 4 or 6
        let address: Data    // 4 or 16 bytes (all zeros for no preference)
        let prefixLength: UInt8

        func encode() -> Data {
            var out = varintEncode(requestID)
            out.append(ipVersion)
            out.append(address)
            out.append(prefixLength)
            return out
        }

        static func decodeSequence(_ data: Data) -> [RequestedAddress]? {
            var out: [RequestedAddress] = []
            var offset = 0
            while offset < data.count {
                guard let (reqID, rLen) = varintDecode(data, at: offset) else { return nil }
                offset += rLen
                guard offset < data.count else { return nil }
                let ver = data[data.startIndex + offset]
                offset += 1
                let addrLen = ver == 4 ? 4 : (ver == 6 ? 16 : 0)
                guard addrLen > 0, offset + addrLen <= data.count else { return nil }
                let addr = Data(data[(data.startIndex + offset)..<(data.startIndex + offset + addrLen)])
                offset += addrLen
                guard offset < data.count else { return nil }
                let prefix = data[data.startIndex + offset]
                offset += 1
                out.append(RequestedAddress(requestID: reqID, ipVersion: ver, address: addr, prefixLength: prefix))
            }
            return out
        }
    }

    /// ROUTE_ADVERTISEMENT Capsule (Type 0x03): routing table advertisement.
    struct RouteAdvertisement: Equatable {
        let ipVersion: UInt8 // 4 or 6
        let startIP: Data    // 4 or 16 bytes
        let endIP: Data      // 4 or 16 bytes
        let ipProtocol: UInt8 // 0 = all protocols

        func encode() -> Data {
            var out = Data([ipVersion])
            out.append(startIP)
            out.append(endIP)
            out.append(ipProtocol)
            return out
        }

        static func decodeSequence(_ data: Data) -> [RouteAdvertisement]? {
            var out: [RouteAdvertisement] = []
            var offset = 0
            while offset < data.count {
                guard offset < data.count else { return nil }
                let ver = data[data.startIndex + offset]
                offset += 1
                let addrLen = ver == 4 ? 4 : (ver == 6 ? 16 : 0)
                guard addrLen > 0, offset + 2 * addrLen + 1 <= data.count else { return nil }
                let start = Data(data[(data.startIndex + offset)..<(data.startIndex + offset + addrLen)])
                offset += addrLen
                let end = Data(data[(data.startIndex + offset)..<(data.startIndex + offset + addrLen)])
                offset += addrLen
                let proto = data[data.startIndex + offset]
                offset += 1
                out.append(RouteAdvertisement(ipVersion: ver, startIP: start, endIP: end, ipProtocol: proto))
            }
            return out
        }
    }

    // MARK: - HTTP/3 Settings Frame with Extended CONNECT

    /// Construct HTTP/3 SETTINGS frame announcing Extended CONNECT and HTTP Datagrams.
    static func http3SettingsFrame(enableConnectProtocol: Bool = true,
                                  enableDatagrams: Bool = true,
                                  includeLegacyDraft00: Bool = true) -> Data {
        var payload = Data()
        // QPACK_MAX_TABLE_CAPACITY = 0
        payload.append(varintEncode(0x01))
        payload.append(varintEncode(0))
        // QPACK_BLOCKED_STREAMS = 0
        payload.append(varintEncode(0x07))
        payload.append(varintEncode(0))
        if enableConnectProtocol {
            // SETTINGS_ENABLE_CONNECT_PROTOCOL = 1 (RFC 9220 §3)
            payload.append(varintEncode(settingEnableConnectProtocol))
            payload.append(varintEncode(1))
        }
        if enableDatagrams {
            // SETTINGS_H3_DATAGRAM = 1 (RFC 9297 §2.1.1)
            payload.append(varintEncode(settingH3Datagram))
            payload.append(varintEncode(1))
            if includeLegacyDraft00 {
                // SETTINGS_H3_DATAGRAM_00 = 1 (0x276, needed for Cloudflare WARP compatibility)
                payload.append(varintEncode(settingH3DatagramDraft00))
                payload.append(varintEncode(1))
            }
        }
        var frame = varintEncode(0x04) // Frame Type: SETTINGS
        frame.append(varintEncode(UInt64(payload.count)))
        frame.append(payload)
        return frame
    }

    // MARK: - QPACK Extended CONNECT Request Header

    /// Encode QPACK field section for an Extended CONNECT request.
    /// RFC 9204 §4.5 + RFC 8441 / RFC 9220:
    /// - :method = CONNECT
    /// - :protocol = connect-udp | connect-ip
    /// - :scheme = https
    /// - :authority = <host>
    /// - :path = <path>
    /// - capsule-protocol = ?1
    static func qpackEncodeExtendedConnect(protocolValue: String,
                                          authority: String,
                                          path: String,
                                          extraHeaders: [(String, String)] = []) -> Data {
        // Section prefix: Required Insert Count = 0, Base = 0 (no dynamic table).
        var out = Data([0x00, 0x00])

        // 1. :method CONNECT (Static table index 15)
        out.append(qpackEncodeInteger(15, prefixBits: 6, flags: 0xC0))

        // 2. :scheme https (Static table index 23)
        out.append(qpackEncodeInteger(23, prefixBits: 6, flags: 0xC0))

        // 3. :authority (Static table index 0, name ref)
        out.append(qpackEncodeInteger(0, prefixBits: 4, flags: 0x50))
        out.append(qpackEncodeString(authority))

        // 4. :path (Static table index 1, name ref)
        out.append(qpackEncodeInteger(1, prefixBits: 4, flags: 0x50))
        out.append(qpackEncodeString(path))

        // 5. :protocol = <protocolValue> (Literal name, literal value)
        out.append(qpackEncodeString(":protocol", prefixBits: 3, flags: 0x20))
        out.append(qpackEncodeString(protocolValue))

        // 6. capsule-protocol = ?1 (Literal name, literal value)
        out.append(qpackEncodeString("capsule-protocol", prefixBits: 3, flags: 0x20))
        out.append(qpackEncodeString("?1"))

        // Extra headers (authorization, etc.)
        for (name, value) in extraHeaders {
            if name.lowercased() == "authorization" {
                // Static table index 83 has name "authorization"
                out.append(qpackEncodeInteger(83, prefixBits: 4, flags: 0x50))
                out.append(qpackEncodeString(value))
            } else {
                out.append(qpackEncodeString(name.lowercased(), prefixBits: 3, flags: 0x20))
                out.append(qpackEncodeString(value))
            }
        }
        return out
    }

    // MARK: - URI Template Expansion (RFC 9298 §3)

    /// Expand an RFC 9298 URI template with the target host and port.
    /// Extracts the relative HTTP path component if an absolute URI was passed.
    static func expandURITemplate(_ template: String, target: NCTarget) -> String {
        var path = template
        // RFC 6570 simple expansion percent-encodes reserved characters: an IPv6 literal is 2001%3Adb8%3A%3A1, no brackets.
        let bare = target.host.hasPrefix("[") && target.host.hasSuffix("]") ? String(target.host.dropFirst().dropLast()) : target.host
        let hostStr = bare.replacingOccurrences(of: ":", with: "%3A")
        if path.contains("{target_host}") || path.contains("{target_port}") {
            path = path.replacingOccurrences(of: "{target_host}", with: hostStr)
            path = path.replacingOccurrences(of: "{target_port}", with: "\(target.port)")
        } else {
            if !path.hasSuffix("/") { path += "/" }
            path += "\(hostStr)/\(target.port)/"
        }
        // Absolute template: keep everything from the first "/" after the authority, byte for byte.
        // (fix/nc-proto-masque-int: URL.path dropped the trailing "/" and masque-go's ServeMux answered the
        // Extended CONNECT with a 307 redirect to the slash path — the #160 loopback failure.)
        if let schemeEnd = path.range(of: "://") {
            let afterAuthority = path[schemeEnd.upperBound...]
            if let slash = afterAuthority.firstIndex(of: "/") {
                path = String(afterAuthority[slash...])
            } else {
                path = "/"
            }
        }
        if !path.hasPrefix("/") {
            path = "/" + path
        }
        return path
    }

    // MARK: - QPACK Response Decoding (RFC 9204)

    /// Decode a QPACK field section using the static table and literal field lines.
    /// Forwarded to NCHy2.qpackDecodeFieldSection.
    static func qpackDecodeFieldSection(_ data: Data) -> [(name: String, value: String)]? {
        NCHy2.qpackDecodeFieldSection(data)
    }

    // MARK: - QPACK Integer & String Primitives

    private static func qpackEncodeInteger(_ value: Int, prefixBits: Int, flags: UInt8) -> Data {
        let maxPrefix = (1 << prefixBits) - 1
        if value < maxPrefix {
            return Data([flags | UInt8(value)])
        }
        var out = Data([flags | UInt8(maxPrefix)])
        var rem = value - maxPrefix
        while rem >= 128 {
            out.append(UInt8(rem & 0x7f) | 0x80)
            rem >>= 7
        }
        out.append(UInt8(rem))
        return out
    }

    private static func qpackEncodeString(_ str: String, prefixBits: Int = 7, flags: UInt8 = 0) -> Data {
        let raw = Data(str.utf8)
        var out = qpackEncodeInteger(raw.count, prefixBits: prefixBits, flags: flags)
        out.append(raw)
        return out
    }
}
