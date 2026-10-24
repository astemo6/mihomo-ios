package mitm

// Native request scripts (native-final, switch nativeMitmScript): http-request scripts run in Swift the way
// lane s3-script runs http-response scripts (PacketTunnel/NativeMitM/Script/NativeRequestScripts.swift). The Swift
// rewrite engine stops at a matching request script, the dispatcher runs it (the same slots, program cache, host
// APIs and log lines through nativescript.go), applies $done to its copy of the request and the engine goes on
// with the next rule.
//
// Whenever Swift cannot finish the request on its own after a script ran (a later rule only Go handles, a
// response it hands back), it hands the request to the Go flow API with FlowHead.Scripted: the outcome of every
// request script it already ran. requestPhase then applies those outcomes at the same points instead of running
// the scripts again (handler.go), so no script runs twice and the request ends exactly as on the Go path: the same
// Match / Note calls, the same body loading, the same URL / method / header / body changes, local answer or abort.
//
// This file: the hand-over types, and the request body admission of a native request script (requestPhase's
// loadBody up to the read: memory gates, limits, the body budget — split around the bytes Swift holds).

import (
	"fmt"
)

// FlowScripted is the outcome of one request script Swift ran (FlowHead.Scripted).
type FlowScripted struct {
	Rule int `json:"rule"` // Ruleset index (snapshot generation FlowHead.Gen)
	// Load: Swift ran loadBody for it (a requires-body script that got its slot): Go loads the body too.
	Load bool `json:"load,omitempty"`
	// Skip: it did not run (slot refused / body skipped): the request-log note; the log line is written.
	Skip string `json:"skip,omitempty"`
	// Fail: it ran and failed: the request-log note; the log lines are written.
	Fail string `json:"fail,omitempty"`
	// The result ($done) — parseDone(requestPhase).
	Abort   bool                  `json:"abort,omitempty"`
	URL     *string               `json:"url,omitempty"`
	Method  *string               `json:"method,omitempty"`
	Headers *[][2]string          `json:"headers,omitempty"`
	BodySet bool                  `json:"bodySet,omitempty"`
	Body    []byte                `json:"body,omitempty"`
	Mock    *FlowScriptedResponse `json:"mock,omitempty"`
}

// FlowScriptedResponse is a request script's local answer ($done({response})).
type FlowScriptedResponse struct {
	Status  int          `json:"status"`
	Headers *[][2]string `json:"headers,omitempty"`
	Body    []byte       `json:"body,omitempty"`
}

type flowScriptedSet struct {
	st *state
	by map[int]*FlowScripted
}

func newFlowScriptedSet(st *state, list []FlowScripted) *flowScriptedSet {
	s := &flowScriptedSet{st: st, by: map[int]*FlowScripted{}}
	for i := range list {
		s.by[list[i].Rule] = &list[i]
	}
	return s
}

// at is the outcome for Ruleset index i (nil: Go runs the script itself).
func (s *flowScriptedSet) at(i int) *FlowScripted {
	if s == nil {
		return nil
	}
	return s.by[i]
}

// result is the ScriptResult parseDone(requestPhase) would have produced.
func (f *FlowScripted) result() *ScriptResult {
	res := &ScriptResult{Abort: f.Abort}
	if f.Abort {
		return res
	}
	if m := f.Mock; m != nil {
		r := &ScriptHTTP{Status: m.Status, Body: m.Body}
		if m.Headers != nil {
			r.Header = pairsHeader(*m.Headers)
		}
		res.Response = r
		return res
	}
	if f.URL != nil {
		res.URL = *f.URL
	}
	if f.Method != nil {
		res.Method = *f.Method
	}
	if f.Headers != nil {
		res.Header = pairsHeader(*f.Headers)
	}
	if f.BodySet {
		res.Body, res.BodySet = f.Body, true
		if res.Body == nil {
			res.Body = []byte{}
		}
	}
	return res
}

// ---- the request body of a native request script: requestPhase's loadBody, split around the bytes ----

type nsReqAdmitJS struct {
	OK     bool   `json:"ok,omitempty"`
	Ticket int64  `json:"ticket,omitempty"` // the body budget share (NativeScriptBodyRelease)
	Cap    int64  `json:"cap,omitempty"`    // reqCap: the most loadBody reads
	Limit  int64  `json:"limit,omitempty"`  // the script's body limit
	Skip   string `json:"skip,omitempty"`   // reqSkip
	Retry  bool   `json:"retry,omitempty"`  // bodyLoaded stays false: a later script with a larger limit may read it
	Gone   bool   `json:"gone,omitempty"`
}

// NativeScriptReqBodyAdmit is requestPhase's loadBody(limit) for the request script at rule up to the read, for
// a body of known length contentLength (Swift hands chunked request bodies to Go): heapHigh with small work, the
// script's limit and reqCap (phaseBodyCap over the request phase's rules), the body budget (small pool or
// bodyBudget). On success the share is held under the returned ticket until NativeScriptBodyRelease (Go: until
// the request phase ends). contentLength 0 (no body) loads nothing. Log lines are written here as loadBody writes
// them.
func (e *Engine) NativeScriptReqBodyAdmit(gen int64, rule int, url string, contentLength int64, token int64) string {
	st, r := e.scriptRule(gen, rule)
	if r == nil {
		return jsonString(nsReqAdmitJS{Gone: true, Skip: "脚本规则已更新"})
	}
	limit := scriptBodyLimit(r.Script)
	var rules []*Rule
	if st.cfg.AnyOn() {
		rules = st.rs.Rules
	}
	reqCap := phaseBodyCap(rules, "request")
	if contentLength == 0 {
		return jsonString(nsReqAdmitJS{OK: true, Cap: int64(reqCap), Limit: int64(limit)})
	}
	small := false
	if heapHigh() {
		if !smallWorkOK(contentLength, smallBodyFloor) {
			skip := heapHighReason()
			e.logf("warning", fmt.Sprintf("[MitM] %s，跳过请求体处理：%s", skip, clip(url, 100)))
			return jsonString(nsReqAdmitJS{Skip: skip, Limit: int64(limit)})
		}
		small = true
		if reqCap > smallWorkMax {
			reqCap = smallWorkMax
		}
	}
	want := int64(reqCap)
	if contentLength > 0 && contentLength < want {
		want = contentLength
	}
	if contentLength > int64(limit) {
		return jsonString(nsReqAdmitJS{Retry: true, Limit: int64(limit), Skip: fmt.Sprintf("请求体 %d KB 超过上限 %d KB", contentLength>>10, limit>>10)})
	}
	if contentLength > int64(reqCap) {
		return jsonString(nsReqAdmitJS{Limit: int64(limit), Skip: fmt.Sprintf("请求体 %d KB 超过上限 %d KB", contentLength>>10, reqCap>>10)})
	}
	ctx := tokenCtx(token)
	var rel func()
	if small || want <= smallWorkMax {
		rel = acquireSmall(ctx, want, bodyBudgetWait)
	} else {
		rel = bodyBudget.acquire(ctx, want, bodyBudgetWait)
	}
	if rel == nil {
		e.logf("warning", fmt.Sprintf("[MitM] 同时处理的请求/响应体过多，跳过：%s", clip(url, 100)))
		return jsonString(nsReqAdmitJS{Limit: int64(limit), Skip: "同时处理的请求/响应体过多"})
	}
	reg := nativeScripts
	reg.mu.Lock()
	id := reg.next()
	reg.charges[id] = &nsCharge{charge: &bodyCharge{ctx: ctx}, reqRelease: rel}
	reg.mu.Unlock()
	nsHeld.Add(1)
	return jsonString(nsReqAdmitJS{OK: true, Ticket: id, Cap: int64(reqCap), Limit: int64(limit)})
}

// NativeScriptReqBodySkip is requestPhase's skip of a requires-body request script whose loadBody said no: why
// is reqSkip ("" → 「请求体超过上限」), or — blen ≥ 0, a body loaded earlier that is over this script's limit —
// the limit message with bodyLimitNote. Writes the 「跳过脚本：」 log line and returns the request-log note.
func (e *Engine) NativeScriptReqBodySkip(gen int64, rule int, why string, blen int64) string {
	_, r := e.scriptRule(gen, rule)
	if r == nil {
		return ""
	}
	if limit := scriptBodyLimit(r.Script); blen >= 0 && blen > int64(limit) {
		why = fmt.Sprintf("请求体 %d KB 超过上限 %d KB（%s）", blen>>10, limit>>10, bodyLimitNote(r.Script, limit))
	}
	if why == "" {
		why = "请求体超过上限"
	}
	e.Logs.Add(r.Script.Name, "warn", "跳过脚本："+why)
	return "跳过脚本：" + r.Script.Name + " — " + why
}

// NativeScriptReqLimit is scriptBodyLimit of the request script at rule (-1: gone).
func (e *Engine) NativeScriptReqLimit(gen int64, rule int) int64 {
	_, r := e.scriptRule(gen, rule)
	if r == nil {
		return -1
	}
	return int64(scriptBodyLimit(r.Script))
}
