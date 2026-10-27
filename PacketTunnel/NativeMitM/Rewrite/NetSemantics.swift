// Native MitM stage 3 (lane s3-full) — small pieces of net/url and net/http semantics the native rewrite engine
// reproduces byte for byte: request-target parsing (url.ParseRequestURI + URL.EscapedPath / RequestURI), absolute
// URL parsing for plain http(s) URLs (url.Parse), net.SplitHostPort, httputil's query cleaning (url.ParseQuery +
// Values.Encode), http.StatusText and http.DetectContentType.
//
// The escape tables and every function here are held to the old core by UnitTests/NativeMitmRegexFixtures.json (generated
// by the retired bridge the old core standard library itself).

import Foundation

enum NetURL {
    // net/url shouldEscape tables (bit set: the byte is escaped), generated from the old core 1.26:
    // pathEsc = (&url.URL{Path: "/"+b}).EscapedPath() != "/"+b, queryEsc = url.QueryEscape(b) != b.
    static let pathEsc: [UInt32] = [4294967295, 3489662895, 2013265920, 3087007745, 4294967295, 4294967295, 4294967295, 4294967295]
    static let queryEsc: [UInt32] = [4294967295, 4227899391, 2013265921, 3087007745, 4294967295, 4294967295, 4294967295, 4294967295]

    static func escapesInPath(_ c: UInt8) -> Bool { pathEsc[Int(c >> 5)] & (1 << UInt32(c & 31)) != 0 }
    static func escapesInQuery(_ c: UInt8) -> Bool { queryEsc[Int(c >> 5)] & (1 << UInt32(c & 31)) != 0 }

    private static let upperhex = Array("0123456789ABCDEF".utf8)

    private static func unhex(_ c: UInt8) -> UInt8 {
        switch c {
        case 0x30...0x39: return c - 0x30
        case 0x61...0x66: return c - 0x61 + 10
        default: return c - 0x41 + 10
        }
    }

    /// url.unescape (path or query-component mode). nil: a bad escape (the old core errors).
    static func unescape(_ s: [UInt8], query: Bool) -> [UInt8]? {
        var out = [UInt8]()
        out.reserveCapacity(s.count)
        var i = 0
        while i < s.count {
            let c = s[i]
            if c == UInt8(ascii: "%") {
                guard i + 2 < s.count, RWAscii.isHex(s[i + 1]), RWAscii.isHex(s[i + 2]) else { return nil }
                out.append(unhex(s[i + 1]) << 4 | unhex(s[i + 2]))
                i += 3
                continue
            }
            out.append(query && c == UInt8(ascii: "+") ? UInt8(ascii: " ") : c)
            i += 1
        }
        return out
    }

    /// url.escape in path mode.
    static func escapePath(_ s: [UInt8]) -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(s.count)
        for c in s {
            if escapesInPath(c) { out += [UInt8(ascii: "%"), upperhex[Int(c >> 4)], upperhex[Int(c & 15)]] } else { out.append(c) }
        }
        return out
    }

    /// url.QueryEscape.
    static func queryEscape(_ s: [UInt8]) -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(s.count)
        for c in s {
            if c == UInt8(ascii: " ") { out.append(UInt8(ascii: "+")) } else if escapesInQuery(c) {
                out += [UInt8(ascii: "%"), upperhex[Int(c >> 4)], upperhex[Int(c & 15)]]
            } else { out.append(c) }
        }
        return out
    }

    /// url.validEncoded in path mode.
    static func validEncodedPath(_ s: [UInt8]) -> Bool {
        for c in s {
            switch c {
            case UInt8(ascii: "!"), UInt8(ascii: "$"), UInt8(ascii: "&"), UInt8(ascii: "'"), UInt8(ascii: "("), UInt8(ascii: ")"),
                 UInt8(ascii: "*"), UInt8(ascii: "+"), UInt8(ascii: ","), UInt8(ascii: ";"), UInt8(ascii: "="), UInt8(ascii: ":"),
                 UInt8(ascii: "@"), UInt8(ascii: "["), UInt8(ascii: "]"), UInt8(ascii: "%"):
                continue
            default:
                if escapesInPath(c) { return false }
            }
        }
        return true
    }

    /// URL.EscapedPath for the path as written (setPath + EscapedPath). nil: a bad escape.
    static func escapedPath(_ raw: [UInt8]) -> String? {
        guard let path = unescape(raw, query: false) else { return nil }
        if path == Array("*".utf8) { return "*" }
        if validEncodedPath(raw) { return String(decoding: raw, as: UTF8.self) }
        return String(decoding: escapePath(path), as: UTF8.self)
    }

    struct Target {
        var host: String?       // absolute-form target: its host
        var path: String        // EscapedPath
        var query: String       // RawQuery
        var forceQuery: Bool
    }

    /// url.ParseRequestURI(t) as http's server sees it, for origin-form ("/…") and plain absolute http(s) targets.
    /// nil: the old core errors, or a form Swift does not reproduce ("*", "//…", authority oddities).
    static func parseRequestURI(_ t: String) -> Target? {
        let b = Array(t.utf8)
        if b.isEmpty || b.contains(where: { $0 < 0x20 || $0 == 0x7F }) { return nil }
        if b.first == UInt8(ascii: "/") {
            if b.count > 1 && b[1] == UInt8(ascii: "/") { return nil }
            return splitPathQuery(b[...], host: nil)
        }
        guard let a = parseAbsolute(t) else { return nil }
        return Target(host: a.host, path: a.path, query: a.query, forceQuery: a.forceQuery)
    }

    /// The query split url.parse does ("?" at the very end, and the only one: ForceQuery) and the path's escaping.
    private static func splitPathQuery(_ rest: ArraySlice<UInt8>, host: String?) -> Target? {
        let q = UInt8(ascii: "?")
        var pathPart = rest
        var query = ""
        var force = false
        let count = rest.reduce(0) { $0 + ($1 == q ? 1 : 0) }
        if rest.last == q && count == 1 {
            pathPart = rest.dropLast()
            force = true
        } else if let i = rest.firstIndex(of: q) {
            pathPart = rest[rest.startIndex..<i]
            query = String(decoding: rest[(i + 1)...], as: UTF8.self)
        }
        guard let p = escapedPath(Array(pathPart)) else { return nil }
        return Target(host: host, path: p, query: query, forceQuery: force)
    }

    struct Absolute {
        var scheme: String
        var host: String
        var path: String        // EscapedPath
        var query: String
        var forceQuery: Bool
    }

    /// url.Parse for "http://host[:port][/path][?query]" with a plain host (letters, digits, "-", ".", optional
    /// ":digits"), no userinfo, no fragment. nil: anything else (the old core's result is not reproduced).
    static func parseAbsolute(_ s: String) -> Absolute? {
        let b = Array(s.utf8)
        if b.contains(where: { $0 < 0x20 || $0 == 0x7F || $0 == UInt8(ascii: "#") }) { return nil }
        let scheme: String
        var i: Int
        if s.hasPrefix("https://") { scheme = "https"; i = 8 } else if s.hasPrefix("http://") { scheme = "http"; i = 7 } else { return nil }
        let start = i
        while i < b.count && b[i] != UInt8(ascii: "/") && b[i] != UInt8(ascii: "?") { i += 1 }
        let host = String(decoding: b[start..<i], as: UTF8.self)
        guard NativeRewriteEngine.plainHost(host) else { return nil }
        guard let t = splitPathQuery(b[i...], host: host) else { return nil }
        return Absolute(scheme: scheme, host: host, path: t.path, query: t.query, forceQuery: t.forceQuery)
    }

    /// net.SplitHostPort. nil: the old core reports an error.
    static func splitHostPort(_ hp: String) -> (String, String)? {
        let b = Array(hp.utf8)
        guard let i = b.lastIndex(of: UInt8(ascii: ":")) else { return nil }
        var j = 0, k = 0
        let host: [UInt8]
        if b.first == UInt8(ascii: "[") {
            guard let end = b.firstIndex(of: UInt8(ascii: "]")) else { return nil }
            if end + 1 == b.count { return nil }
            if end + 1 != i { return nil }
            host = Array(b[1..<end])
            j = 1; k = end + 1
        } else {
            host = Array(b[0..<i])
            if host.contains(UInt8(ascii: ":")) { return nil }
        }
        if b[j...].contains(UInt8(ascii: "[")) { return nil }
        if b[k...].contains(UInt8(ascii: "]")) { return nil }
        return (String(decoding: host, as: UTF8.self), String(decoding: b[(i + 1)...], as: UTF8.self))
    }

    /// flow_request.go flowCleanQuery (httputil cleanQueryParams): a query with ";" or a bad escape is re-encoded
    /// from url.ParseQuery (unparsable parameters dropped). nil: not reproduced.
    static func cleanQuery(_ s: String) -> String? {
        let b = Array(s.utf8)
        var i = 0
        var dirty = false
        while i < b.count {
            if b[i] == UInt8(ascii: ";") { dirty = true; break }
            if b[i] == UInt8(ascii: "%") {
                if i + 2 >= b.count || !RWAscii.isHex(b[i + 1]) || !RWAscii.isHex(b[i + 2]) { dirty = true; break }
                i += 3
                continue
            }
            i += 1
        }
        if !dirty { return s }
        // url.ParseQuery
        if b.reduce(0, { $0 + ($1 == UInt8(ascii: "&") ? 1 : 0) }) + 1 > 10000 { return "" } // limit: error, empty map
        var m: [[UInt8]: [[UInt8]]] = [:]
        for part in b.split(separator: UInt8(ascii: "&"), omittingEmptySubsequences: false) {
            if part.contains(UInt8(ascii: ";")) || part.isEmpty { continue }
            let kv = part.split(separator: UInt8(ascii: "="), maxSplits: 1, omittingEmptySubsequences: false)
            guard let k = unescape(Array(kv[0]), query: true) else { continue }
            guard let v = unescape(kv.count > 1 ? Array(kv[1]) : [], query: true) else { continue }
            m[k, default: []].append(v)
        }
        // Values.Encode
        var out = [UInt8]()
        for k in m.keys.sorted(by: { $0.lexicographicallyPrecedes($1) }) {
            let ke = queryEscape(k)
            for v in m[k] ?? [] {
                if !out.isEmpty { out.append(UInt8(ascii: "&")) }
                out += ke
                out.append(UInt8(ascii: "="))
                out += queryEscape(v)
            }
        }
        return String(decoding: out, as: UTF8.self)
    }
}

enum NetStatus {
    /// http.StatusText (the old core 1.26).
    static let text: [Int: String] = [
        100: "Continue", 101: "Switching Protocols", 102: "Processing", 103: "Early Hints",
        200: "OK", 201: "Created", 202: "Accepted", 203: "Non-Authoritative Information", 204: "No Content", 205: "Reset Content",
        206: "Partial Content", 207: "Multi-Status", 208: "Already Reported", 226: "IM Used",
        300: "Multiple Choices", 301: "Moved Permanently", 302: "Found", 303: "See Other", 304: "Not Modified", 305: "Use Proxy",
        307: "Temporary Redirect", 308: "Permanent Redirect",
        400: "Bad Request", 401: "Unauthorized", 402: "Payment Required", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
        406: "Not Acceptable", 407: "Proxy Authentication Required", 408: "Request Timeout", 409: "Conflict", 410: "Gone",
        411: "Length Required", 412: "Precondition Failed", 413: "Request Entity Too Large", 414: "Request URI Too Long",
        415: "Unsupported Media Type", 416: "Requested Range Not Satisfiable", 417: "Expectation Failed", 418: "I'm a teapot",
        421: "Misdirected Request", 422: "Unprocessable Entity", 423: "Locked", 424: "Failed Dependency", 425: "Too Early",
        426: "Upgrade Required", 428: "Precondition Required", 429: "Too Many Requests", 431: "Request Header Fields Too Large",
        451: "Unavailable For Legal Reasons",
        500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout",
        505: "HTTP Version Not Supported", 506: "Variant Also Negotiates", 507: "Insufficient Storage", 508: "Loop Detected",
        510: "Not Extended", 511: "Network Authentication Required",
    ]

    /// resp.Status as flow.go runResponse builds it: fmt.Sprintf("%d %s", code, http.StatusText(code)).
    static func status(_ code: Int) -> String { "\(code) \(text[code] ?? "")" }
}

enum NetSniff {
    private static func isWS(_ b: UInt8) -> Bool { b == 0x09 || b == 0x0A || b == 0x0C || b == 0x0D || b == 0x20 }

    private enum Sig {
        case html(String)
        case masked(mask: [UInt8], pat: [UInt8], skipWS: Bool, ct: String)
        case exact([UInt8], String)
        case mp4
        case text
    }

    private static func m(_ mask: [UInt8], _ pat: [UInt8], _ ct: String, skipWS: Bool = false) -> Sig {
        .masked(mask: mask, pat: pat, skipWS: skipWS, ct: ct)
    }
    private static func bytes(_ s: String) -> [UInt8] { Array(s.utf8) }

    private static let sigs: [Sig] = [
        .html("<!DOCTYPE HTML"), .html("<HTML"), .html("<HEAD"), .html("<SCRIPT"), .html("<IFRAME"), .html("<H1"), .html("<DIV"),
        .html("<FONT"), .html("<TABLE"), .html("<A"), .html("<STYLE"), .html("<TITLE"), .html("<B"), .html("<BODY"), .html("<BR"),
        .html("<P"), .html("<!--"),
        m([0xFF, 0xFF, 0xFF, 0xFF, 0xFF], bytes("<?xml"), "text/xml; charset=utf-8", skipWS: true),
        .exact(bytes("%PDF-"), "application/pdf"),
        .exact(bytes("%!PS-Adobe-"), "application/postscript"),
        m([0xFF, 0xFF, 0x00, 0x00], [0xFE, 0xFF, 0x00, 0x00], "text/plain; charset=utf-16be"),
        m([0xFF, 0xFF, 0x00, 0x00], [0xFF, 0xFE, 0x00, 0x00], "text/plain; charset=utf-16le"),
        m([0xFF, 0xFF, 0xFF, 0x00], [0xEF, 0xBB, 0xBF, 0x00], "text/plain; charset=utf-8"),
        .exact([0x00, 0x00, 0x01, 0x00], "image/x-icon"),
        .exact([0x00, 0x00, 0x02, 0x00], "image/x-icon"),
        .exact(bytes("BM"), "image/bmp"),
        .exact(bytes("GIF87a"), "image/gif"),
        .exact(bytes("GIF89a"), "image/gif"),
        m([0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], bytes("RIFF") + [0, 0, 0, 0] + bytes("WEBPVP"), "image/webp"),
        .exact([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], "image/png"),
        .exact([0xFF, 0xD8, 0xFF], "image/jpeg"),
        m([0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF], bytes("FORM") + [0, 0, 0, 0] + bytes("AIFF"), "audio/aiff"),
        m([0xFF, 0xFF, 0xFF], bytes("ID3"), "audio/mpeg"),
        m([0xFF, 0xFF, 0xFF, 0xFF, 0xFF], bytes("OggS") + [0], "application/ogg"),
        m([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], bytes("MThd") + [0, 0, 0, 6], "audio/midi"),
        m([0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF], bytes("RIFF") + [0, 0, 0, 0] + bytes("AVI "), "video/avi"),
        m([0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF], bytes("RIFF") + [0, 0, 0, 0] + bytes("WAVE"), "audio/wave"),
        .mp4,
        .exact([0x1A, 0x45, 0xDF, 0xA3], "video/webm"),
        m([UInt8](repeating: 0, count: 34) + [0xFF, 0xFF], [UInt8](repeating: 0, count: 34) + bytes("LP"), "application/vnd.ms-fontobject"),
        .exact([0x00, 0x01, 0x00, 0x00], "font/ttf"),
        .exact(bytes("OTTO"), "font/otf"),
        .exact(bytes("ttcf"), "font/collection"),
        .exact(bytes("wOFF"), "font/woff"),
        .exact(bytes("wOF2"), "font/woff2"),
        .exact([0x1F, 0x8B, 0x08], "application/x-gzip"),
        .exact(bytes("PK") + [0x03, 0x04], "application/zip"),
        .exact(bytes("Rar!") + [0x1A, 0x07, 0x00], "application/x-rar-compressed"),
        .exact(bytes("Rar!") + [0x1A, 0x07, 0x01, 0x00], "application/x-rar-compressed"),
        .exact([0x00, 0x61, 0x73, 0x6D], "application/wasm"),
        .text,
    ]

    /// http.DetectContentType.
    static func detect<D: Collection>(_ input: D) -> String where D.Element == UInt8 {
        let data = Array(input.prefix(512))
        var first = 0
        while first < data.count && isWS(data[first]) { first += 1 }
        for sig in sigs {
            if let ct = match(sig, data, first) { return ct }
        }
        return "application/octet-stream"
    }

    private static func match(_ sig: Sig, _ data: [UInt8], _ first: Int) -> String? {
        switch sig {
        case .exact(let p, let ct):
            return data.starts(with: p) ? ct : nil
        case .masked(let mask, let pat, let skip, let ct):
            let d = skip ? Array(data[first...]) : data
            if mask.count != pat.count || d.count < pat.count { return nil }
            for i in 0..<pat.count where d[i] & mask[i] != pat[i] { return nil }
            return ct
        case .html(let h):
            let d = Array(data[first...])
            let hb = Array(h.utf8)
            if d.count < hb.count + 1 { return nil }
            for i in 0..<hb.count {
                var db = d[i]
                if hb[i] >= 0x41 && hb[i] <= 0x5A { db &= 0xDF }
                if hb[i] != db { return nil }
            }
            let tt = d[hb.count]
            return tt == 0x20 || tt == 0x3E ? "text/html; charset=utf-8" : nil
        case .mp4:
            if data.count < 12 { return nil }
            let box = Int(data[0]) << 24 | Int(data[1]) << 16 | Int(data[2]) << 8 | Int(data[3])
            if data.count < box || box % 4 != 0 { return nil }
            if Array(data[4..<8]) != Array("ftyp".utf8) { return nil }
            var st = 8
            while st < box {
                if st != 12 && Array(data[st..<(st + 3)]) == Array("mp4".utf8) { return "video/mp4" }
                st += 4
            }
            return nil
        case .text:
            for b in data[first...] {
                if b <= 0x08 || b == 0x0B || (0x0E...0x1A).contains(b) || (0x1C...0x1F).contains(b) { return nil }
            }
            return "text/plain; charset=utf-8"
        }
    }
}
