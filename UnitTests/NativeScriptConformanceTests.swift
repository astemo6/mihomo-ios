import XCTest
@testable import Tern

/// ScriptEngineConformance.json: the script host's conformance corpus (69 cases pinning
/// QX/Surge script-environment semantics: $response rewrites, header casing, $argument,
/// $persistentStore, timers, base64 byte-string semantics, gzip/BOM body lanes, error and
/// timeout wording). The corpus predates the native core and, until now, no test target
/// loaded it — the atob/btoa divergence it pins (case text-encoding-base64) shipped broken
/// until a device report exposed it (build 546, Ximalaya paid tracks). Each case now runs
/// through NCScriptDebug — the app's own runner on the same JSC engine, prelude and
/// NativeScriptRun loop the tunnel uses — and every `expect` fragment must appear in the
/// run's observable output (console logs, final body, headers, $done rendering, error and
/// notification text).
///
/// Divergences that are known stand-in artifacts (the debug host is not the tunnel host)
/// are listed in knownDivergences with their reason; the list is asserted in both
/// directions — a case that starts passing must be removed from it, and a new divergence
/// fails the suite until it is either fixed or owned here.
final class NativeScriptConformanceTests: XCTestCase {

    private struct CorpusCase: Decodable {
        struct HTTP: Decodable {
            var url: String?
            var method: String?
            var status: Int?
            var headers: [String: String]?
            var body: String?
        }
        struct Input: Decodable {
            var code: String
            var type: String
            var name: String?
            var argument: String?
            var binary: Bool?
            var timeout: Int?
            var request: HTTP?
            var response: HTTP?
        }
        var name: String
        var input: Input
        var expect: [String]
    }

    /// case name → why its divergence is a debug-host artifact, not a product bug.
    private static let knownDivergences: [String: String] = [
        // The Egern ctx adapter is applied by the tunnel host only; NCScriptDebug's own
        // header documents that the app-process runner does not apply it.
        "egern-native": "Egern ctx adapter not applied by the app-process runner (documented in NCScriptDebug)",
        "egern-abort": "Egern ctx adapter not applied by the app-process runner (documented in NCScriptDebug)",
        "egern-ctx-body-bytes": "Egern ctx adapter not applied by the app-process runner (documented in NCScriptDebug)",
        // $httpAPI is answered by the tunnel's controller; the app process has none and
        // the callback never fires (documented in NCScriptDebug's header).
        "httpapi-unavailable": "no tunnel controller in the app process, $httpAPI gets no answer (documented in NCScriptDebug)",
        // The corpus pins the old core's request-log note sentence; both native hosts log
        // the same fact (an exception after $done is ignored) in their own wording.
        "exception-after-done": "old-core note wording; the ignored-after-$done fact is logged by both hosts in their own wording",
        // The debug runner hands fixture bodies to the script undecoded; content-decoding
        // (gzip/br) happens in the tunnel's data plane before scripts run there.
        "bom-text-go-path": "debug runner does not content-decode fixture bodies; the tunnel data plane does",
        "lane-br-bom-text": "debug runner does not content-decode fixture bodies; the tunnel data plane does",
        // The case drives __egernCompress (the Egern bridge), which the app-process
        // runner does not install — same stand-in family as the egern ctx cases.
        "utils-geo-ungzip": "__egernCompress (Egern bridge) not installed by the app-process runner",
        // The case's middle fragment pins the old (Go) workbench's indented-JSON rendering
        // of the task result (`"title": "T"`, embedded escaped). The native runner's
        // doneJSON is Swift pretty-print (`"title" : "T"`); the result value itself —
        // title / content / n / the 2-byte binary — is present and asserted by the
        // case's other fragments.
        "cron-task-env": "task-result serialization style of the old workbench (indented JSON, escaped embedding) vs the native runner's Swift pretty-print doneJSON",
    ]

    private func corpus() throws -> [CorpusCase] {
        let bundle = Bundle(for: NativeScriptConformanceTests.self)
        guard let url = bundle.url(forResource: "ScriptEngineConformance", withExtension: "json") else {
            XCTFail("ScriptEngineConformance.json missing from the test bundle")
            return []
        }
        return try JSONDecoder().decode([CorpusCase].self, from: Data(contentsOf: url))
    }

    /// Which corpus bodies are BYTES (stored base64) rather than text. The corpus flags
    /// some itself (input.binary — including fixtures whose bytes happen to be valid
    /// UTF-8, like qx-request-binary-patch's control bytes); the lane/gzip/protobuf
    /// fixtures predate the flag and are recognizable as canonical base64 decoding to
    /// non-UTF-8. The one collision is body-large-count: a text pattern ('abab…') whose
    /// expectations only arithmetic out as text (count of 'ab' = 30000 in 60000 chars),
    /// so it is named here as the documented exception.
    private static func isCanonicalBase64(_ s: String) -> Bool {
        guard !s.isEmpty, s.count % 4 == 0, let d = Data(base64Encoded: s) else { return false }
        return d.base64EncodedString() == s
    }

    private static func isBinaryBody(_ s: String, flagged: Bool, caseName: String) -> Bool {
        guard isCanonicalBase64(s), let d = Data(base64Encoded: s) else { return false }
        if flagged { return true }
        if caseName == "body-large-count" { return false }
        return String(data: d, encoding: .utf8) == nil
    }

    private func http(_ h: CorpusCase.HTTP?, binary: Bool, caseName: String) -> NCScriptDebug.HTTP? {
        guard let h else { return nil }
        var out = NCScriptDebug.HTTP()
        out.url = h.url
        out.method = h.method
        out.status = h.status
        out.headers = h.headers
        out.body = h.body
        if let b = h.body, Self.isBinaryBody(b, flagged: binary, caseName: caseName) { out.bodyBase64 = true }
        return out
    }

    func testConformanceCorpus() throws {
        let cases = try corpus()
        XCTAssertEqual(cases.count, 69, "corpus case count changed — update this pin with the corpus")
        var unexpected: [String] = []
        var passedKnown: [String] = []
        for c in cases {
            var inp = NCScriptDebug.Input()
            inp.code = c.input.code
            inp.name = c.input.name ?? c.name
            inp.type = c.input.type
            inp.argument = c.input.argument
            inp.binary = c.input.binary ?? false
            inp.timeout = c.input.timeout ?? 0
            inp.request = http(c.input.request, binary: c.input.binary ?? false, caseName: c.name)
            inp.response = http(c.input.response, binary: c.input.binary ?? false, caseName: c.name)
            let home = NSTemporaryDirectory() + "nc-conformance/" + c.name
            try? FileManager.default.removeItem(atPath: home)
            try? FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
            let out = NCScriptDebug.run(home: home, input: inp)

            var hay: [String] = out.logs.map(\.msg) + out.summary
            hay.append("\"ok\":\(out.ok)")
            if let e = out.error { hay.append(e) }
            if let dj = out.doneJSON { hay.append(dj) }
            for p in [out.result, out.mock] {
                guard let p else { continue }
                if let b = p.body { hay.append(b) }
                if let s = p.status { hay.append(String(s)); hay.append("\"status\":\(s)") }
                if p.bodyBase64 == true { hay.append("\"bodyBase64\":true") }
                if let h = p.headers {
                    hay.append(h.map { "\($0): \($1)" }.joined(separator: "\n"))
                    if let d = try? JSONSerialization.data(withJSONObject: h),
                       let s = String(data: d, encoding: .utf8) { hay.append(s) }
                }
                if let u = p.url { hay.append(u) }
                if let m = p.method { hay.append(m) }
            }
            if !out.notifications.isEmpty,
               let d = try? JSONSerialization.data(withJSONObject: out.notifications),
               let s = String(data: d, encoding: .utf8) {
                hay.append(s)
            }
            // The old workbench's output was JSON records; a bare log line also appeared
            // embedded as {"msg":"…"}. Offer that rendering too.
            if !out.logs.isEmpty,
               let d = try? JSONSerialization.data(withJSONObject: out.logs.map { ["level": $0.level, "msg": $0.msg] }),
               let s = String(data: d, encoding: .utf8) {
                hay.append(s)
            }
            let joined = hay.joined(separator: "\n")
            // Some fragments were authored against the old workbench's JSON-embedded
            // renderings: singly/doubly escaped, or Go-style (\u0026 for &). Match all.
            func esc(_ s: String) -> String {
                s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
            }
            let escaped = esc(joined)
            let goEscaped = esc(joined)
                .replacingOccurrences(of: "&", with: "\\u0026")
                .replacingOccurrences(of: "<", with: "\\u003c")
                .replacingOccurrences(of: ">", with: "\\u003e")
            let variants = [joined, escaped, esc(escaped), goEscaped]
            let missing = c.expect.filter { f in !variants.contains { $0.contains(f) } }
            if missing.isEmpty {
                if Self.knownDivergences[c.name] != nil { passedKnown.append(c.name) }
            } else if Self.knownDivergences[c.name] != nil {
                continue // owned divergence, still diverging as documented
            } else {
                unexpected.append("\(c.name): missing \(missing.map { "«\($0.prefix(60))»" }.joined(separator: ", ")) | actual: \(joined.prefix(1500))")
            }
        }
        XCTAssertTrue(passedKnown.isEmpty, "knownDivergences entries that now PASS (remove them): \(passedKnown.joined(separator: ", "))")
        XCTAssertTrue(unexpected.isEmpty, "conformance divergences (\(unexpected.count)):\n" + unexpected.joined(separator: "\n"))
    }
}
