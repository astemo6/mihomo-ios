import Foundation

/// fix/nc-delay-2: how NCController splits a request target into path components and query values — shared so
/// unit tests run the App's real URL building (ControllerClient.enc / query) against the controller's real decoding
/// (node names with spaces, brackets, emoji flags, "/", "%", "+", "&"). Needs sync to feat/nc-kernel.
enum NCControllerRoute {
    /// "/providers/proxies/P/N%20%5BCF%5D/healthcheck?url=…&timeout=5000" → (decoded path, components, query).
    /// Components are split BEFORE percent-decoding, so an encoded "/" inside a name stays inside its component.
    static func split(target: String) -> (path: String, comps: [String], query: [String: String]) {
        var rawPath = target
        var query: [String: String] = [:]
        if let q = target.firstIndex(of: "?") {
            rawPath = String(target[target.startIndex..<q])
            for pair in target[target.index(after: q)...].split(separator: "&") {
                let kv = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                guard kv.count == 2 else { continue }
                query[decode(String(kv[0]))] = decode(String(kv[1]))
            }
        }
        let comps = rawPath.split(separator: "/").map { decode(String($0)) }
        return (decode(rawPath), comps, query)
    }

    private static func decode(_ s: String) -> String { s.removingPercentEncoding ?? s }
}
