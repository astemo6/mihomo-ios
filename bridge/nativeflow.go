package libmihomo

// Native flow API (feat/native-mitm stage 2; bridge/mitm/flow.go, work/native-mitm-design.md §12). The Swift
// HTTP/1.1 session behind the native TLS front calls these for every request on a decrypted connection: Swift
// frames bytes and moves them; every rule decision (URL rewrite / reject / redirect, Map Local, header and body
// rewrites, request and response scripts, admission, body budgets, the native body lane, every fallback) is
// made in Go by the same code as the Go path. All calls are synchronous and safe from any thread; the
// blocking ones (MitmFlowBegin, MitmFlowAwait, MitmFlowResponse, MitmFlowWrite while Go reads, MitmFlowRead of
// a local body Go is still producing) must not run on the main thread. Decisions are JSON objects; see the
// design document for the fields and the call sequence.

import "github.com/astemo6/mihomo-ios/bridge/mitm"

// MitmFlowBegin starts a flow from a request head (JSON: method, target, host, headers [[name, value]…],
// length, connHost, connPort, tls, connId). Returns the first decision: need-body (push the request body, then
// MitmFlowAwait), forward, local, drop, busy, or error.
func MitmFlowBegin(headJSON string) string {
	engMu.Lock()
	e := eng
	engMu.Unlock()
	if e == nil {
		return `{"id":0,"action":"error","note":"MitM engine not running","length":0}`
	}
	return e.FlowBegin(headJSON)
}

// MitmFlowAwait waits for the decision after a need-body (or after MitmFlowWrite answered "full").
func MitmFlowAwait(id int64) string { return mitm.FlowAwait(id) }

// MitmFlowWrite pushes the next piece of a body: which 0 = the client's request body, 1 = the upstream's
// response body. "" taken, "full" not taken (await the decision or drain with MitmFlowRead, then push it
// again), "stop" Go no longer wants this body, "gone" the flow ended.
func MitmFlowWrite(id int64, which int, b []byte) string { return mitm.FlowWrite(id, which, b) }

// MitmFlowClose ends a pushed body ("" clean end, else why the read failed).
func MitmFlowClose(id int64, which int, errText string) { mitm.FlowClose(id, which, errText) }

// MitmFlowRead pulls up to max bytes of a body Go produced: which 0 = towards the upstream (body mode "read"
// of a forward decision), 1 = towards the client (a local answer, or body mode "read" of a respond decision).
// Empty: ask MitmFlowReadState.
func MitmFlowRead(id int64, which int, max int) []byte { return mitm.FlowRead(id, which, max) }

// MitmFlowReadState explains the last MitmFlowRead: "" read again, "more" push more of the source body first,
// "eof" complete, "err: …" failed (cut the connection; never present a cut body as complete).
func MitmFlowReadState(id int64, which int) string { return mitm.FlowReadState(id, which) }

// MitmFlowResponse runs the response phase on the upstream's head (JSON: status, headers, length). Returns
// need-body (push the upstream body, then MitmFlowAwait), respond, upgrade, or error (answer 502).
func MitmFlowResponse(id int64, headJSON string) string { return mitm.FlowResponse(id, headJSON) }

// MitmFlowUpstreamFailed: the upstream could not be reached or failed before its head (answer 502).
func MitmFlowUpstreamFailed(id int64, why string) { mitm.FlowUpstreamFailed(id, why) }

// MitmFlowEnd finishes a flow. sent = body bytes the native side delivered itself (body modes "upstream" and
// "lane"); errText = why it stopped early ("" complete). Frees everything Go holds for the flow, including a
// lane handle it handed over (do not Free that handle in Swift).
func MitmFlowEnd(id int64, sent int64, errText string) { mitm.FlowEnd(id, sent, errText) }

// MitmFlowCancel: the client went away (scripts waiting for a slot, budget waits and body loads stop).
func MitmFlowCancel(id int64, why string) { mitm.FlowCancel(id, why) }

// MitmFlowStats is a JSON object (live flows, totals, pipe bytes now / peak) for diagnostics.
func MitmFlowStats() string { return mitm.FlowStats() }
