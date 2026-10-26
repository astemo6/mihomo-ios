// Native MitM stage 2, lane `http` (B8a): header op vocabulary + hop-by-hop stripping.
//
// Ported from astemo6's draft drafts/native-mitm/HeaderRewrite.swift (origin/draft/native-mitm-b7b8 6b53dc6), with
// fixes:
//   • CR/LF check: the draft used String.contains("\r"), which misses a CRLF pair ("\r\n" is ONE Character in Swift),
//     so "a\r\nInjected: x" passed validation (response splitting). Now validated per byte (CTL / DEL rejected, HTAB ok).
//   • hop-by-hop list matches the old core httputil.ReverseProxy (adds Proxy-Authenticate); all Connection fields are read, not
//     just the first; `TE: trailers` is kept and Upgrade can be kept for an upgrade, as ReverseProxy does (design §12.1).
//   • works on the contract heads (HTTPHead) and keeps wire order / case.

import Foundation

enum HeaderOp: Equatable {
    case set(name: String, value: String)
    case add(name: String, value: String)
    case remove(name: String)
}

enum HeaderRewriteError: Error, Equatable {
    case illegalName(String)
    case illegalValue(name: String)
}

enum HTTPHeaderRewrite {
    /// the old core net/http/httputil hopHeaders.
    static let hopByHop: Set<String> = [
        "connection", "proxy-connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailer", "transfer-encoding", "upgrade",
    ]

    /// Drops hop-by-hop fields and every field nominated by any Connection field (RFC 9110 §7.6.1), plus `extraDrop`.
    /// `keepUpgrade`: keep Upgrade (and re-add `Connection: Upgrade`) for a request that is being upgraded.
    /// `TE: trailers` survives, as in ReverseProxy.
    static func stripHopByHop<H: HTTPHead>(_ head: inout H, extraDrop: Set<String> = [], keepUpgrade: Bool = false) {
        var drop = hopByHop.union(extraDrop.map { $0.lowercased() })
        for token in head.tokens(for: "Connection") { drop.insert(token) }
        let teTrailers = head.tokens(for: "TE").contains("trailers")
        let upgrade = keepUpgrade ? head.values(for: "Upgrade") : []
        var out = head.headers.filter { !drop.contains($0.name.lowercased()) }
        if teTrailers { out.append(("Te", "trailers")) }
        if !upgrade.isEmpty {
            out.append(("Connection", "Upgrade"))
            for u in upgrade { out.append(("Upgrade", u)) }
        }
        if !HTTPWire.same(out, head.headers) { head.headers = out }
    }

    @discardableResult
    static func apply<H: HTTPHead>(_ ops: [HeaderOp], to head: inout H) throws -> Int {
        for op in ops {
            switch op {
            case let .set(name, value):
                try validate(name: name, value: value)
                head.setHeader(name, value)
            case let .add(name, value):
                try validate(name: name, value: value)
                head.addHeader(name, value)
            case let .remove(name):
                guard isValidName(name) else { throw HeaderRewriteError.illegalName(name) }
                head.removeHeader(name)
            }
        }
        return ops.count
    }

    static func isValidName(_ name: String) -> Bool {
        let b = Array(name.utf8)
        return !b.isEmpty && b.allSatisfy(HTTPWire.isTokenByte)
    }

    static func isValidValue(_ value: String) -> Bool {
        value.unicodeScalars.allSatisfy { $0.value == 0x09 || ($0.value >= 0x20 && $0.value != 0x7F) }
    }

    private static func validate(name: String, value: String) throws {
        guard isValidName(name) else { throw HeaderRewriteError.illegalName(name) }
        guard isValidValue(value) else { throw HeaderRewriteError.illegalValue(name: name) }
    }
}
