import XCTest
@testable import Tern

/// Regression (device 2026-10-28, build 545 diagnostics): every response script whose API
/// answers chunked / without Content-Length was handed back "body length unknown" at head
/// time, so NO response script ever ran for those flows (ximalaya baseInfo, xiaohongshu
/// config / homefeed, youtube get_watch). The load machinery (bodyAdmit budget, capped
/// store, raw pass-through) is built for unknown lengths — head() must ask for the body
/// (.needBody), not hand the flow back.
final class NativeScriptChunkedBodyTests: XCTestCase {

    private final class FakeFetch: ScriptFetch {
        var meta = ""
        var body = Data()
        func done() {}
    }

    private final class FakeHost: ScriptHostAPI {
        func ready() -> Bool { true }
        func token() -> Int64 { 1 }
        func cancel(_ token: Int64) {}
        func reserve(gen: Int64, rule: Int, token: Int64) -> ScriptReserveAnswer { ScriptReserveAnswer(slot: 1) }
        func release(slot: Int64, ran: Bool) {}
        func prepare(gen: Int64, rule: Int, slot: Int64, reload: Bool) -> ScriptPrepared { ScriptPrepared(ok: true) }
        func bodyAdmit(gen: Int64, rule: Int, respRules: [Int], url: String, contentLength: Int64, enc: String, token: Int64) -> ScriptAdmit {
            ScriptAdmit(ok: true, ticket: 1, cap: 8 << 20, limit: 8 << 20)
        }
        func bodyLoaded(ticket: Int64, url: String, decoded: Int64) -> String { "" }
        func bodyFailed(ticket: Int64, url: String, kind: String, raw: Int64, detail: String) -> String { "" }
        func bodyRelease(ticket: Int64) {}
        func bodyCharge(ticket: Int64) -> NativeBodyCharge? { nil }
        func bodyCheck(gen: Int64, rule: Int, blen: Int64, limit: Int64) -> ScriptBodyCheck { ScriptBodyCheck(limit: limit, note: nil) }
        func skip(gen: Int64, rule: Int, why: String) -> String { "" }
        func fail(gen: Int64, rule: Int, mode: String, detail: String, stop: Int, timeoutMs: Int64, afterDone: Bool) -> ScriptFail { ScriptFail() }
        func host(gen: Int64, rule: Int, op: String, arg: String) -> String { "" }
        func bytes(op: String, arg: String, input: Data) -> Data? { nil }
        func api(gen: Int64, rule: Int, arg: String) -> String { "" }
        func fetch(gen: Int64, rule: Int, token: Int64, arg: String, body: Data) -> ScriptFetch { FakeFetch() }
        func memLow() -> Bool { false }
        func reqBodyAdmit(gen: Int64, rule: Int, url: String, contentLength: Int64, token: Int64) -> ScriptAdmit { ScriptAdmit(ok: true, ticket: 1, cap: 8 << 20, limit: 8 << 20) }
        func reqBodySkip(gen: Int64, rule: Int, why: String, blen: Int64) -> String { "" }
        func reqLimit(gen: Int64, rule: Int) -> Int64 { 8 << 20 }
        func held() -> Int64 { 0 }
    }

    private final class FakeJS: NativeJSEngine {
        func begin(run: JSCRun, key: String, setup: String) -> String { "" }
        func call(_ runID: Int64, fn: String?, arg: String?) -> String { "" }
        func end(_ runID: Int64) {}
    }

    private func makeResponse() -> NativeScriptResponse {
        let view = ScriptRequestView(url: "https://edith.xiaohongshu.com/api/sns/v2/system_service/config",
                                     method: "GET", header: CanonicalHeader(), host: "edith.xiaohongshu.com")
        return NativeScriptResponse(gen: 1,
                                    steps: [ScriptPlanStep(rule: 0, kind: .script(requiresBody: true))],
                                    request: view, hostAPI: FakeHost(), js: FakeJS(),
                                    store: NativeBodyStore.shared, nativeBase: 0)
    }

    func testChunkedResponseAsksForBodyInsteadOfHandBack() {
        let r = makeResponse()
        let out = r.head(status: 200,
                         headers: [["Content-Type", "application/json"], ["Transfer-Encoding", "chunked"]],
                         length: -1)
        switch out {
        case .needBody:
            break // the session now pushes the chunked body and the script runs on it
        case .handBack(let why):
            XCTFail("chunked response must not hand back (was \"body length unknown\"): \(why)")
        case .done:
            XCTFail("a body script cannot finish at head time")
        }
        r.end()
    }

    func testNoContentLengthResponseAsksForBody() {
        let r = makeResponse()
        let out = r.head(status: 200, headers: [["Content-Type", "application/json"]], length: -1)
        if case .handBack(let why) = out { XCTFail("length-less response must not hand back: \(why)") }
        if case .done = out { XCTFail("a body script cannot finish at head time") }
        r.end()
    }

    func testKnownLengthResponseStillAsksForBody() {
        let r = makeResponse()
        let out = r.head(status: 200,
                         headers: [["Content-Type", "application/json"], ["Content-Length", "1234"]],
                         length: 1234)
        if case .handBack(let why) = out { XCTFail("known-length response regressed: \(why)") }
        if case .done = out { XCTFail("a body script cannot finish at head time") }
        r.end()
    }
}
