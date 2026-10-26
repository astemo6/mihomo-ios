// Native MitM stage 3a — the rewrite snapshot Go exports (bridge/mitm/rewritesnap.go, MitmRewriteSnapshot) and
// small pieces of Go's net/http behaviour the native rewrite engine has to reproduce byte for byte.
//
// Swift never parses Surge / Loon / QX / Egern / Stash text: it evaluates the Ruleset Go compiled, in Go's rule
// order, with Go's portability verdict per pattern. See NativeRewriteEngine.swift for what is decided natively and
// what is handed back to the Go flow.

import Foundation

// MARK: - Snapshot (JSON from Go; field names = rewritesnap.go json tags)

struct RWSnapRegex: Decodable {
    var p: String
    var ok: Bool
    /// Go's explicit ICU translation (bridge/mitm/rewriteicu.go), valid for ASCII input.
    var icu: String?
    /// regexp2 capture slot → ICU group index (nil: identity).
    var slots: [Int]?
    var lit: String?
    var fold: Bool?
    var groups: Int
    var named: Bool?
    var empty: Bool?
}

/// A replacement as regexp2 parsed it (syntax.ReplacerData): r >= 0 → s[r]; r <= -5 → capture slot -5-r;
/// -4 text before the match ($`), -3 after it ($'), -2 last group ($+), -1 whole input ($_).
struct RWSnapTemplate: Decodable {
    var s: [String]?
    var r: [Int]
}

struct RWSnapHeaderOp: Decodable {
    var op: String
    var name: String?
    var value: String?
    var re: RWSnapRegex?
    var tp: RWSnapTemplate?
    /// regexp2 rejects the replacement: Go leaves the header unchanged.
    var tperr: Bool?
}

struct RWSnapLocal: Decodable {
    var status: Int
    var headers: [[String]]?
    var body: Data?
    var file: RWSnapFile?
}

/// A Map Local answer read from disk at request time (handler.go serveLargeMapLocal / mapLocalData).
struct RWSnapFile: Decodable {
    var path: String
    var remote: Bool?
    var ctype: String?
    var maxAge: Int?
    var large: Int
}

struct RWSnapScript: Decodable {
    var name: String
    var type: String
    var requiresBody: Bool?
}

struct RWSnapRule: Decodable {
    var i: Int
    var kind: String
    var phase: String
    var re: RWSnapRegex?
    var hgate: Bool?
    var hre: RWSnapRegex?
    var action: String?
    var target: String?
    var targetOK: Bool?
    var tp: RWSnapTemplate?
    var tperr: Bool?
    var headers: [RWSnapHeaderOp]?
    var opsOK: Bool?
    var local: RWSnapLocal?
    var script: RWSnapScript?
    // stage 3b body rules (bodysnap.go; NativeBodyRewrite.swift)
    var body: [RWSnapBodyOp]?
    var jsonOps: [RWSnapJSONOp]?
    var jq: [RWSnapJQStep]?
    /// fix/nc-jq-full: the whole jq filter (NativeJQ); preferred over the legacy `jq` step list
    var jqx: String?
    var bodyOK: Bool?
    var bodyWhy: String?
}

struct RWSnapHost: Decodable {
    var pat: String
    var port: Int?
}

struct RWSnapshot: Decodable {
    static let supportedVersion = 1
    var version: Int
    var gen: Int64?
    var on: Bool
    var capture: Bool
    var inc: [RWSnapHost]?
    var exc: [RWSnapHost]?
    var rules: [RWSnapRule]?
    var total: Int?
    var portable: Int?

    static func decode(_ json: String) -> RWSnapshot? {
        guard !json.isEmpty, let s = try? JSONDecoder().decode(RWSnapshot.self, from: Data(json.utf8)),
              s.version == supportedVersion else { return nil }
        return s
    }
}

// MARK: - Go net/http header semantics

/// ASCII helpers shared by the engine (inputs are gated to printable ASCII before any regex runs).
enum RWAscii {
    static func isTokenByte(_ c: UInt8) -> Bool {
        switch c {
        case UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "0")...UInt8(ascii: "9"): return true
        case UInt8(ascii: "!"), UInt8(ascii: "#"), UInt8(ascii: "$"), UInt8(ascii: "%"), UInt8(ascii: "&"), UInt8(ascii: "'"),
             UInt8(ascii: "*"), UInt8(ascii: "+"), UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: "^"), UInt8(ascii: "_"),
             UInt8(ascii: "`"), UInt8(ascii: "|"), UInt8(ascii: "~"): return true
        default: return false
        }
    }
    static func isHex(_ c: UInt8) -> Bool {
        (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66)
    }
    static func isDigit(_ c: UInt8) -> Bool { c >= 0x30 && c <= 0x39 }
    /// Printable ASCII without space (0x21…0x7E).
    static func isVisible(_ s: String) -> Bool { s.utf8.allSatisfy { $0 >= 0x21 && $0 <= 0x7E } }
    /// Printable ASCII with space (0x20…0x7E).
    static func isPrintable(_ s: String) -> Bool { s.utf8.allSatisfy { $0 >= 0x20 && $0 <= 0x7E } }
    static func lower(_ s: String) -> String {
        String(decoding: s.utf8.map { ($0 >= 0x41 && $0 <= 0x5A) ? $0 + 32 : $0 }, as: UTF8.self)
    }
    static func equalFold(_ a: String, _ b: String) -> Bool { lower(a) == lower(b) }
    /// Go strings.TrimSpace on ASCII input (callers gate non-ASCII away).
    static func trimSpace(_ s: String) -> String {
        let ws: Set<UInt8> = [0x20, 0x09, 0x0A, 0x0B, 0x0C, 0x0D]
        let b = Array(s.utf8)
        var i = 0, j = b.count
        while i < j && ws.contains(b[i]) { i += 1 }
        while j > i && ws.contains(b[j - 1]) { j -= 1 }
        return String(decoding: b[i..<j], as: UTF8.self)
    }
    /// textproto.TrimString: ASCII space and tab only.
    static func trimOWS(_ s: String) -> String {
        let b = Array(s.utf8)
        var i = 0, j = b.count
        while i < j && (b[i] == 0x20 || b[i] == 0x09) { i += 1 }
        while j > i && (b[j - 1] == 0x20 || b[j - 1] == 0x09) { j -= 1 }
        return String(decoding: b[i..<j], as: UTF8.self)
    }
    /// Byte-order comparison (Go sort.Strings).
    static func less(_ a: String, _ b: String) -> Bool { a.utf8.lexicographicallyPrecedes(b.utf8) }
    static func contains(_ hay: String, _ needle: String) -> Bool {
        let h = Array(hay.utf8), n = Array(needle.utf8)
        if n.isEmpty { return true }
        if n.count > h.count { return false }
        let first = n[0]
        var i = 0
        let last = h.count - n.count
        while i <= last {
            if h[i] == first {
                var k = 1
                while k < n.count && h[i + k] == n[k] { k += 1 }
                if k == n.count { return true }
            }
            i += 1
        }
        return false
    }
}

/// Canonical MIME header map (http.Header semantics): canonical keys (textproto.CanonicalMIMEHeaderKey),
/// values in order, iteration sorted when flattened.
struct CanonicalHeader: Equatable {
    private(set) var map: [String: [String]] = [:]

    init() {}

    /// Pairs as Go produced them (canonical keys already; nothing trimmed).
    init(raw pairs: [[String]]) {
        for kv in pairs where kv.count == 2 { map[kv[0], default: []].append(kv[1]) }
    }

    /// headerFromPairs (flow.go): key trimmed, empty keys skipped, Add.
    init(pairs: [[String]]) {
        for kv in pairs where kv.count == 2 {
            let k = RWAscii.trimSpace(kv[0])
            if k.isEmpty { continue }
            add(k, kv[1])
        }
    }

    static func canonical(_ s: String) -> String {
        let b = Array(s.utf8)
        for c in b where !RWAscii.isTokenByte(c) { return s }
        var out = [UInt8]()
        out.reserveCapacity(b.count)
        var upper = true
        for var c in b {
            if upper && c >= 0x61 && c <= 0x7A { c -= 32 } else if !upper && c >= 0x41 && c <= 0x5A { c += 32 }
            out.append(c)
            upper = c == UInt8(ascii: "-")
        }
        return String(decoding: out, as: UTF8.self)
    }

    mutating func add(_ k: String, _ v: String) { map[CanonicalHeader.canonical(k), default: []].append(v) }
    mutating func set(_ k: String, _ v: String) { map[CanonicalHeader.canonical(k)] = [v] }
    mutating func del(_ k: String) { map.removeValue(forKey: CanonicalHeader.canonical(k)) }
    func get(_ k: String) -> String { map[CanonicalHeader.canonical(k)]?.first ?? "" }
    func values(_ k: String) -> [String] { map[CanonicalHeader.canonical(k)] ?? [] }
    func has(_ k: String) -> Bool { map[CanonicalHeader.canonical(k)] != nil }

    /// flowHeaderPairs: keys sorted (byte order), values in order.
    var sortedPairs: [[String]] {
        map.keys.sorted(by: RWAscii.less).flatMap { k in (map[k] ?? []).map { [k, $0] } }
    }

    /// httpguts.HeaderValuesContainsToken.
    func containsToken(_ k: String, _ token: String) -> Bool {
        for v in values(k) {
            for part in v.split(separator: ",", omittingEmptySubsequences: false) {
                if RWAscii.equalFold(RWAscii.trimOWS(String(part)), token) { return true }
            }
        }
        return false
    }

    /// flow.go flowRemoveHopByHop (httputil's list plus the headers Connection names).
    mutating func removeHopByHop() {
        for f in values("Connection") {
            for sf in f.split(separator: ",", omittingEmptySubsequences: false) {
                let t = RWAscii.trimOWS(String(sf))
                if !t.isEmpty { del(t) }
            }
        }
        for h in ["Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer",
                  "Transfer-Encoding", "Upgrade"] { del(h) }
    }
}
