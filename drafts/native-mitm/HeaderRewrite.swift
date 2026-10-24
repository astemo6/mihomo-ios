import Foundation

/// B8 draft (native MitM lane): header-level rewrites applied by the Swift
/// layer.
///
/// The rule table itself is built by Go (B6: Go parses Surge / Loon / QX /
/// Egern modules and hands down plain ops). This file only defines the op
/// vocabulary and applies it. Body rewrites do NOT live here — bodies go
/// through the body channel to Go (B1–B3), so the same script runs for the
/// native and the Go-only path.
///
/// Deliberately small op set (everything the four dialects' header rewrites
/// reduce to):
///   - request/response header set / add / remove
///   - dropping hop-by-hop headers before relay (RFC 9110 §7.6.1): the relay
///     hop re-frames the body, so Transfer-Encoding / Content-Length are
///     recomputed at serialization time, never copied blindly.
/// Values with CR or LF are rejected at apply time (response splitting);
/// a poisoned rule must fail the rewrite, not the connection's integrity.

enum HeaderOp: Equatable {
    case set(name: String, value: String)
    case add(name: String, value: String)
    case remove(name: String)
}

enum HeaderRewriteError: Error, Equatable {
    case illegalValue(name: String)
    case illegalName(String)
}

enum HeaderRewrite {
    /// Hop-by-hop fields that must not cross the relay hop unchanged.
    /// Content-Length and Transfer-Encoding are handled by re-framing; the
    /// rest are connection-scoped by definition.
    static let hopByHop: Set<String> = [
        "connection", "keep-alive", "proxy-connection", "proxy-authorization",
        "te", "trailer", "transfer-encoding", "upgrade",
    ]

    /// Remove hop-by-hop fields, including any field named by the Connection
    /// header itself (RFC 9110 §7.6.1), plus `extraDrop` (e.g. Content-Length
    /// when the body will be re-framed or replaced).
    static func stripHopByHop(_ headers: HTTPHeaders, extraDrop: Set<String> = []) -> HTTPHeaders {
        var drop = hopByHop.union(extraDrop.map { $0.lowercased() })
        if let conn = headers.first("Connection") {
            for token in conn.split(separator: ",") {
                drop.insert(token.trimmingCharacters(in: .whitespaces).lowercased())
            }
        }
        var out = HTTPHeaders()
        for f in headers.fields where !drop.contains(f.name.lowercased()) {
            out.append(f.name, f.value)
        }
        return out
    }

    @discardableResult
    static func apply(_ ops: [HeaderOp], to headers: inout HTTPHeaders) throws -> Int {
        var applied = 0
        for op in ops {
            switch op {
            case .set(let name, let value):
                try validate(name: name, value: value)
                headers.set(name, value)
            case .add(let name, let value):
                try validate(name: name, value: value)
                headers.append(name, value)
            case .remove(let name):
                guard isValidName(name) else { throw HeaderRewriteError.illegalName(name) }
                headers.remove(name)
            }
            applied += 1
        }
        return applied
    }

    private static func validate(name: String, value: String) throws {
        guard isValidName(name) else { throw HeaderRewriteError.illegalName(name) }
        guard !value.contains("\r"), !value.contains("\n") else {
            throw HeaderRewriteError.illegalValue(name: name)
        }
    }

    private static func isValidName(_ name: String) -> Bool {
        // RFC 9110 token characters.
        let specials = "!#$%&'*+-.^_`|~"
        return !name.isEmpty && name.allSatisfy {
            $0.isASCII && ($0.isLetter || $0.isNumber || specials.contains($0))
        }
    }
}
