import Foundation

/// fix/nc-e2e-gaps: the pure half of NCProbeProxy (PacketTunnel/NativeCore/NCProbeProxy.swift) — which loopback
/// listeners with a fixed policy the runtime config asks for, and the HTTP proxy request-head parse — in Shared so
/// the unit tests compile it.
enum NCProbeListener {
    struct Spec: Equatable {
        let name: String
        let port: UInt16
        let policy: String
    }

    /// The loopback listeners with a fixed policy from the runtime config's `listeners` (mixed / http).
    static func specs(_ raw: [String: NCJSONValue]?) -> [Spec] {
        var out: [Spec] = []
        for v in raw?["listeners"]?.array ?? [] {
            guard let o = v.object else { continue }
            let type = (o["type"]?.string ?? "").lowercased()
            let listen = o["listen"]?.string ?? "127.0.0.1"
            guard type == "mixed" || type == "http",
                  listen == "127.0.0.1" || listen == "localhost",
                  let policy = o["proxy"]?.string, !policy.isEmpty,
                  let p = o["port"]?.int, (1...65535).contains(p) else { continue }
            out.append(Spec(name: o["name"]?.string ?? "listener", port: UInt16(p), policy: policy))
        }
        return out
    }

    /// Parses the request head: (host, port, bytes to send upstream first, CONNECT?). nil = bad request.
    static func parse(head: Data, headEnd: Range<Data.Index>) -> (host: String, port: Int, upstream: Data, connect: Bool)? {
        let text = String(decoding: head[head.startIndex..<headEnd.lowerBound], as: UTF8.self)
        let rest = Data(head[headEnd.upperBound...])
        var lines = text.components(separatedBy: "\r\n")
        guard !lines.isEmpty else { return nil }
        let parts = lines.removeFirst().split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard parts.count == 3 else { return nil }
        let (method, uri, version) = (parts[0], parts[1], parts[2])
        if method.uppercased() == "CONNECT" {
            guard let hp = splitAuthority(uri, defaultPort: 443) else { return nil }
            return (hp.0, hp.1, rest, true)
        }
        guard let url = URLComponents(string: uri), url.scheme?.lowercased() == "http",
              let rawHost = url.host, !rawHost.isEmpty else { return nil }
        let host = rawHost.hasPrefix("[") ? String(rawHost.dropFirst().dropLast()) : rawHost
        let port = url.port ?? 80
        var path = url.percentEncodedPath.isEmpty ? "/" : url.percentEncodedPath
        if let q = url.percentEncodedQuery { path += "?" + q }
        var out = "\(method) \(path) \(version)\r\n"
        var hasHost = false
        for line in lines where !line.isEmpty {
            let name = line.split(separator: ":", maxSplits: 1).first.map { $0.trimmingCharacters(in: .whitespaces).lowercased() } ?? ""
            if ["proxy-connection", "proxy-authorization", "connection", "keep-alive"].contains(name) { continue }
            if name == "host" { hasHost = true }
            out += line + "\r\n"
        }
        if !hasHost { out += "Host: \(port == 80 ? rawHost : "\(rawHost):\(port)")\r\n" }
        out += "Connection: close\r\n\r\n"
        return (host, port, Data(out.utf8) + rest, false)
    }

    /// host:port, [v6]:port, or a bare host (default port) — same rule as NCLocalProxy.splitAuthority.
    static func splitAuthority(_ s: String, defaultPort: Int) -> (String, Int)? {
        if s.hasPrefix("[") {
            guard let close = s.firstIndex(of: "]") else { return nil }
            let host = String(s[s.index(after: s.startIndex)..<close])
            let rest = s[s.index(after: close)...]
            if rest.isEmpty { return (host, defaultPort) }
            guard rest.hasPrefix(":"), let p = Int(rest.dropFirst()), (1...65535).contains(p) else { return nil }
            return (host, p)
        }
        let parts = s.split(separator: ":")
        if parts.count == 1 { return (String(parts[0]), defaultPort) }
        guard parts.count == 2, let p = Int(parts[1]), (1...65535).contains(p), !parts[0].isEmpty else { return nil }
        return (String(parts[0]), p)
    }
}
