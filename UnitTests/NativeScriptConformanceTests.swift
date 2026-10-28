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
    ]

    private func corpus() throws -> [CorpusCase] {
        let bundle = Bundle(for: NativeScriptConformanceTests.self)
        guard let url = bundle.url(forResource: "ScriptEngineConformance", withExtension: "json") else {
            XCTFail("ScriptEngineConformance.json missing from the test bundle")
            return []
        }
        return try JSONDecoder().decode([CorpusCase].self, from: Data(contentsOf: url))
    }

    /// A corpus body is base64 bytes (not text) iff it is canonical base64 whose decoding
    /// is not valid UTF-8 — the gzip/protobuf/binary lanes store their fixtures that way.
    private static func isBase64Bytes(_ s: String) -> Bool {
        guard !s.isEmpty, s.count % 4 == 0, let d = Data(base64Encoded: s) else { return false }
        guard d.base64EncodedString() == s else { return false }
        return String(data: d, encoding: .utf8) == nil
    }

    private func http(_ h: CorpusCase.HTTP?) -> NCScriptDebug.HTTP? {
        guard let h else { return nil }
        var out = NCScriptDebug.HTTP()
        out.url = h.url
        out.method = h.method
        out.status = h.status
        out.headers = h.headers
        out.body = h.body
        if let b = h.body, Self.isBase64Bytes(b) { out.bodyBase64 = true }
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
            inp.request = http(c.input.request)
            inp.response = http(c.input.response)
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
                if let h = p.headers { hay.append(h.map { "\($0): \($1)" }.joined(separator: "\n")) }
                if let u = p.url { hay.append(u) }
                if let m = p.method { hay.append(m) }
            }
            if !out.notifications.isEmpty,
               let d = try? JSONSerialization.data(withJSONObject: out.notifications),
               let s = String(data: d, encoding: .utf8) {
                hay.append(s)
            }
            let joined = hay.joined(separator: "\n")
            let missing = c.expect.filter { !joined.contains($0) }
            if missing.isEmpty {
                if Self.knownDivergences[c.name] != nil { passedKnown.append(c.name) }
            } else if Self.knownDivergences[c.name] != nil {
                continue // owned divergence, still diverging as documented
            } else {
                unexpected.append("\(c.name): missing \(missing.map { "«\($0.prefix(60))»" }.joined(separator: ", ")) | actual: \(joined.prefix(300))")
            }
        }
        XCTAssertTrue(passedKnown.isEmpty, "knownDivergences entries that now PASS (remove them): \(passedKnown.joined(separator: ", "))")
        XCTAssertTrue(unexpected.isEmpty, "conformance divergences (\(unexpected.count)):\n" + unexpected.joined(separator: "\n"))
    }
}
