import Foundation

/// VLESS request head (v0, no encryption layer): version || UUID || addons ||
/// command || port || address. Addons carry the flow string as protobuf
/// field 1 when set (e.g. "xtls-rprx-vision"); Vision's padding/unpadding of
/// the stream itself arrives with the Vision batch.
enum NCVLESS {
    static func requestHead(uuid: String, target: NCTarget, flow: String = "", command: UInt8 = 0x01) -> Data? {
        guard let id = uuidBytes(uuid) else { return nil }
        // rv2-proto: domain length is a u8 on the wire (UInt8(count) trapped past 255), port a u16.
        guard target.isWireEncodable else { return nil }
        var out = Data()
        out.append(0x00) // version
        out.append(contentsOf: id)
        if flow.isEmpty {
            out.append(0x00) // no addons
        } else {
            var addons = Data()
            addons.append(0x0a) // protobuf field 1, length-delimited
            let flowBytes = Array(flow.utf8.prefix(127)) // single-byte varint length
            addons.append(UInt8(flowBytes.count))
            addons.append(contentsOf: flowBytes)
            out.append(UInt8(addons.count))
            out.append(addons)
        }
        out.append(command) // 0x01 TCP, 0x02 UDP
        out.append(UInt8((target.port >> 8) & 0xff))
        out.append(UInt8(target.port & 0xff))
        guard let addr = addressEncoded(target) else { return nil }
        out.append(addr) // VLESS address types differ from SOCKS
        return out
    }

    /// VLESS address encoding: 0x01 IPv4, 0x02 domain (length-prefixed),
    /// 0x03 IPv6 — NOT the SOCKS numbering.
    /// fix/nc-socks-domain-len (#170): nil for an unencodable target; the
    /// domain is never truncated to fit the u8 length.
    static func addressEncoded(_ target: NCTarget) -> Data? {
        guard target.isWireEncodable else { return nil }
        var out = Data()
        if let ip = target.ip {
            switch ip {
            case .v4:
                out.append(0x01)
                out.append(contentsOf: ip.bytes)
            case .v6:
                out.append(0x03)
                out.append(contentsOf: ip.bytes)
            }
        } else {
            let host = Array(target.host.utf8)
            out.append(0x02)
            out.append(UInt8(host.count))
            out.append(contentsOf: host)
        }
        return out
    }

    static func uuidBytes(_ uuid: String) -> [UInt8]? {
        let hex = uuid.lowercased().filter { $0 != "-" }
        guard hex.count == 32 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(16)
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            guard let b = UInt8(hex[idx..<next], radix: 16) else { return nil }
            bytes.append(b)
            idx = next
        }
        return bytes
    }
}
