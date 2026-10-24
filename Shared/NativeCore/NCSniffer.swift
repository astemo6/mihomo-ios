import Foundation

/// First-packet protocol sniffing (mihomo's sniffer is the behavioral spec):
/// TLS ClientHello -> SNI (and ALPN), plain HTTP -> Host. QUIC initial-packet
/// SNI arrives with the QUIC batch; until then QUIC flows fall back to IP rules.
enum NCSniffer {
    enum Detected: Equatable {
        case tls(sni: String?, alpn: [String])
        case http(host: String?, method: String)
        case unknown
    }

    static func detect(_ data: Data) -> Detected {
        guard let first = data.first else { return .unknown }
        if first == 0x16 {
            return parseClientHello(data)
        }
        // HTTP methods are uppercase ASCII tokens followed by a space.
        if let head = String(decoding: data.prefix(16), as: UTF8.self).split(separator: " ").first,
           ["GET", "POST", "PUT", "HEAD", "DELETE", "PATCH", "OPTIONS", "CONNECT", "TRACE"].contains(String(head)) {
            return parseHTTP(data, method: String(head))
        }
        return .unknown
    }

    // MARK: TLS ClientHello

    static func parseClientHello(_ data: Data) -> Detected {
        var r = NCReader(data)
        guard r.u8() == 0x16, // handshake record
              r.skip(2), // record version
              let recLen = r.u16(), r.remaining >= 4 else { return .unknown }
        _ = recLen
        guard r.u8() == 0x01, // ClientHello
              r.skip(3), // handshake length
              r.skip(2), // client version
              r.skip(32), // random
              let sidLen = r.u8(), r.skip(Int(sidLen)),
              let csLen = r.u16(), r.skip(Int(csLen)),
              let compLen = r.u8(), r.skip(Int(compLen)),
              let extLen = r.u16() else { return .tls(sni: nil, alpn: []) }
        _ = extLen
        var sni: String?
        var alpn: [String] = []
        while r.remaining >= 4 {
            guard let extType = r.u16(), let extSize = r.u16(), r.remaining >= extSize else { break }
            let body = Data(r.bytes.prefix(Int(extSize)))
            r.skip(Int(extSize))
            if extType == 0x0000 { sni = parseServerName(body) }
            if extType == 0x0010 { alpn = parseALPN(body) }
        }
        return .tls(sni: sni, alpn: alpn)
    }

    private static func parseServerName(_ body: Data) -> String? {
        var r = NCReader(body)
        guard let listLen = r.u16(), r.remaining >= Int(listLen) else { return nil }
        while r.remaining >= 3 {
            guard let nameType = r.u8(), let nameLen = r.u16(), r.remaining >= nameLen else { return nil }
            let name = String(decoding: r.bytes.prefix(Int(nameLen)), as: UTF8.self)
            r.skip(Int(nameLen))
            if nameType == 0 { return name }
        }
        return nil
    }

    private static func parseALPN(_ body: Data) -> [String] {
        var r = NCReader(body)
        guard let listLen = r.u16(), r.remaining >= Int(listLen) else { return [] }
        var out: [String] = []
        while r.remaining >= 1 {
            guard let len = r.u8(), r.remaining >= len else { break }
            out.append(String(decoding: r.bytes.prefix(Int(len)), as: UTF8.self))
            r.skip(Int(len))
        }
        return out
    }

    // MARK: HTTP

    static func parseHTTP(_ data: Data, method: String) -> Detected {
        let text = String(decoding: data.prefix(8192), as: UTF8.self)
        var host: String?
        for line in text.components(separatedBy: "\r\n").dropFirst() {
            if line.isEmpty { break }
            let lower = line.lowercased()
            if lower.hasPrefix("host:") {
                host = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
                break
            }
        }
        if let h = host, let colon = h.lastIndex(of: ":"), !h.contains("]") {
            host = String(h[h.startIndex..<colon])
        }
        return .http(host: host, method: method)
    }
}

/// Bounds-checked big-endian cursor used by the sniffers/parsers.
struct NCReader {
    let bytes: [UInt8]
    private(set) var pos = 0

    init(_ data: Data) { bytes = [UInt8](data) }
    var remaining: Int { bytes.count - pos }

    mutating func u8() -> UInt8? {
        guard remaining >= 1 else { return nil }
        defer { pos += 1 }
        return bytes[pos]
    }

    mutating func u16() -> UInt16? {
        guard remaining >= 2 else { return nil }
        defer { pos += 2 }
        return UInt16(bytes[pos]) << 8 | UInt16(bytes[pos + 1])
    }

    mutating func skip(_ n: Int) -> Bool {
        guard n >= 0, remaining >= n else { return false }
        pos += n
        return true
    }
}
