package mitm

// Native script dispatch — native MitM stage 3, lane s3-script (Swift side: PacketTunnel/NativeMitM/Script/).
//
// With the switch nativeMitmScript on, a request whose response phase runs http-response scripts can be handled
// in Swift end to end: the upstream body goes from the session straight into NativeBodyStore (decoded there), the
// Swift dispatcher builds $request / $response, runs the scripts in JavaScriptCore (JSCScriptEngine, a Swift run
// object instead of Go's runCtx: blobs, timers, the event loop, $done, timeouts all in Swift) and applies $done to
// the response. No Go flow, no pipe, no Go body copy, no runCtx and no goroutine per run.
//
// Go keeps what must stay shared with the Go path, all of it without body bytes:
//   - admission: the HTTP script slots, the large-bundle lock and the measured queue (Reserve / Release), the body
//     budget (bodyCharge incl. fix/xmly-memory's small pool), the one-large-body lock, heapHigh / small work;
//   - the program cache index (programFor: the JavaScriptCore context of a script is still loaded, dropped and
//     shed by Go), the setup fields Go derives from the Script (argument, Egern env, language…);
//   - host APIs whose state lives in Go: $persistentStore (the store shared with the app), notifications,
//     $httpAPI, geo lookups, and $httpClient, which still egresses through mihomo routing (rc.do);
//   - every log line and request-log note, formatted here by the same code as the Go path's.
//
// Every function takes the snapshot generation and the Ruleset index of the script rule (rewritesnap.go) so a
// request racing a reload uses the rules it was matched with. A rule the snapshot no longer knows answers an
// error and the Swift side treats it as a script error / skips it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// nsReg holds the Go-side state of native script work: cancellable contexts (one per native flow / run, cancelled
// when the client goes away or the run ends), reserved slots and body charges. Everything is keyed by small
// integers Swift passes back; a forgotten key is a no-op.
type nsReg struct {
	mu      sync.Mutex
	seq     int64
	ctxs    map[int64]nsCtx
	slots   map[int64]*nsSlot
	charges map[int64]*nsCharge
}

type nsCtx struct {
	ctx    context.Context
	cancel context.CancelFunc
}

type nsSlot struct {
	sl *Slot
	s  *ScriptRunner
	// bigLate: the large-bundle lock taken by Prepare (the script's size became known only after Reserve, as
	// execute's own bigSem acquisition does on the Go path); released with the slot.
	bigLate bool
}

type nsCharge struct {
	charge   *bodyCharge
	want, cl int64 // the first charge and the announced length (takeBig's message)
	respCap  int
	capBy    *Script
	enc      string
	ctx      context.Context
	released bool
}

var nativeScripts = &nsReg{ctxs: map[int64]nsCtx{}, slots: map[int64]*nsSlot{}, charges: map[int64]*nsCharge{}}

// Counters (tests, diagnostics): native runs prepared, slots and charges currently held.
var (
	nsPrepared atomic.Int64
	nsHeld     atomic.Int64 // slots + charges + contexts held for Swift right now
)

func (r *nsReg) next() int64 {
	r.seq++
	return r.seq
}

// NativeScriptToken makes a cancellable context for a native flow or run (cancel with NativeScriptCancel, which
// also forgets it).
func NativeScriptToken() int64 {
	ctx, cancel := context.WithCancel(context.Background())
	r := nativeScripts
	r.mu.Lock()
	id := r.next()
	r.ctxs[id] = nsCtx{ctx, cancel}
	r.mu.Unlock()
	nsHeld.Add(1)
	return id
}

// NativeScriptCancel cancels and forgets a token (idempotent).
func NativeScriptCancel(token int64) {
	r := nativeScripts
	r.mu.Lock()
	c, ok := r.ctxs[token]
	delete(r.ctxs, token)
	r.mu.Unlock()
	if ok {
		c.cancel()
		nsHeld.Add(-1)
	}
}

func tokenCtx(token int64) context.Context {
	r := nativeScripts
	r.mu.Lock()
	c, ok := r.ctxs[token]
	r.mu.Unlock()
	if !ok {
		// unknown / already cancelled: a cancelled context, so waits end at once
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx
	}
	return c.ctx
}

// NativeScriptHeld is what Go holds for native script work right now (tests: 0 after every flow).
func NativeScriptHeld() int64 { return nsHeld.Load() }

// scriptRule is the script rule at Ruleset index i of snapshot generation gen.
func (e *Engine) scriptRule(gen int64, i int) (*state, *Rule) {
	if e == nil {
		return nil, nil
	}
	st := e.snapState(gen)
	if st == nil || st.rs == nil || i < 0 || i >= len(st.rs.Rules) {
		return nil, nil
	}
	r := st.rs.Rules[i]
	if r.Kind != KindScript || r.Script == nil {
		return nil, nil
	}
	return st, r
}

// NativeScriptReady: JavaScriptCore runs scripts (not wedged) and the native body lane is registered — the two
// things the Swift dispatcher needs. Checked per response; false → the Go flow handles it.
func NativeScriptReady() bool { return nativeUsable() && laneUsable() != nil }

// ---- admission: the HTTP script slots ----

type nsReserveJS struct {
	Slot int64  `json:"slot,omitempty"`
	Err  string `json:"err,omitempty"`
	Note string `json:"note,omitempty"`
	Gone bool   `json:"gone,omitempty"` // the rule is no longer in the snapshot
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// NativeScriptReserve takes an HTTP script slot for rule (ScriptRunner.Reserve: the same slots, large-bundle lock
// and queue as the Go path). It blocks like Reserve; token cancels the wait (client gone). On failure the script
// log line is written here exactly as reserveFailed does and note is the request-log note.
func (e *Engine) NativeScriptReserve(gen int64, rule int, token int64) string {
	_, r := e.scriptRule(gen, rule)
	if r == nil {
		return jsonString(nsReserveJS{Gone: true, Err: "rule gone"})
	}
	sl, err := e.scripts.Reserve(tokenCtx(token), r)
	if err != nil {
		return jsonString(nsReserveJS{Err: err.Error(), Note: e.reserveFailedNote(r, err)})
	}
	reg := nativeScripts
	reg.mu.Lock()
	id := reg.next()
	reg.slots[id] = &nsSlot{sl: sl, s: e.scripts}
	reg.mu.Unlock()
	nsHeld.Add(1)
	return jsonString(nsReserveJS{Slot: id})
}

// reserveFailedNote is handler.go's reserveFailed with the note returned instead of written to an Entry.
func (e *Engine) reserveFailedNote(rule *Rule, err error) string {
	if isQueueSkip(err) {
		if e.scripts.queue.shouldLog(rule.Script.Name) {
			e.Logs.Add(rule.Script.Name, "warn", err.Error())
		}
		return "跳过脚本：" + rule.Script.Name + " — " + err.Error()
	}
	e.Logs.Add(rule.Script.Name, "error", err.Error())
	return scriptErrNote(rule.Script.Name, err)
}

// NativeScriptRelease gives a slot back (Slot.Release); ran: the script really ran in it (queue timing).
func NativeScriptRelease(slot int64, ran bool) {
	reg := nativeScripts
	reg.mu.Lock()
	s := reg.slots[slot]
	delete(reg.slots, slot)
	reg.mu.Unlock()
	if s == nil {
		return
	}
	nsHeld.Add(-1)
	if ran {
		s.sl.ran = true
	}
	if s.bigLate {
		<-s.s.bigSem
	}
	s.sl.Release()
}

// ---- the program and the setup ----

// nsPrepareJS answers NativeScriptPrepare.
type nsPrepareJS struct {
	OK bool `json:"ok"`
	// Key: the JavaScriptCore context key (Begin's key). Err: the script cannot run (load / syntax error,
	// queue timeout for the large-bundle lock) — the Go path's run error, logged by the caller as one.
	Key       string          `json:"key,omitempty"`
	Err       string          `json:"err,omitempty"`
	Name      string          `json:"name,omitempty"`
	TimeoutMs int64           `json:"timeoutMs,omitempty"`
	Setup     json.RawMessage `json:"setup,omitempty"` // __tern_begin's setup without phase / req / resp
	NotNative bool            `json:"notNative,omitempty"`
}

// NativeScriptPrepare makes sure rule's script is loaded in JavaScriptCore (programFor: the Go path's cache index,
// so ShedMemory / DropIdle / LRU eviction drop it there as before) and returns its context key, the run timeout
// and the setup fields Go derives from the Script. Called after Reserve, like execute. slot: the slot from
// NativeScriptReserve (a large bundle whose size was unknown at Reserve takes the large-bundle lock here and keeps
// it with the slot). reload: Begin answered "missing" (the engine dropped the context): compile again.
func (e *Engine) NativeScriptPrepare(gen int64, rule int, slot int64, reload bool) (out string) {
	defer func() {
		if p := recover(); p != nil {
			out = jsonString(nsPrepareJS{Err: fmt.Sprintf("脚本运行时内部错误：%v", p)})
		}
	}()
	st, r := e.scriptRule(gen, rule)
	if r == nil {
		return jsonString(nsPrepareJS{Err: "脚本规则已更新"})
	}
	sc := r.Script
	eng := nativeEngineNow()
	if eng == nil {
		return jsonString(nsPrepareJS{NotNative: true, Err: "JavaScriptCore 不可用"})
	}
	s := e.scripts
	timeout := scriptTimeout(sc, 120*time.Second, 10*time.Second)
	reg := nativeScripts
	reg.mu.Lock()
	ns := reg.slots[slot]
	reg.mu.Unlock()
	if ns != nil && !ns.sl.big && !ns.bigLate && s.knownSize(sc) >= largeProgSource {
		// execute: a large bundle compiles and runs one at a time (bigSem → sem lock order is kept: the HTTP
		// slot is already held, exactly as on the Go path when the size became known after Reserve)
		select {
		case s.bigSem <- struct{}{}:
			ns.bigLate = true
		case <-time.After(timeout):
			return jsonString(nsPrepareJS{Err: "脚本排队超时"})
		}
	}
	prog, src, err := s.programFor(sc, eng)
	if err != nil {
		return jsonString(nsPrepareJS{Err: err.Error()})
	}
	if reload {
		// the engine dropped the context on its own (jsnative.go begin's "missing" path): load it again from the
		// source (re-read when programFor answered from the file-signature cache)
		if src == "" {
			b := sc.Source
			if b == nil {
				if b, err = s.e.res.Get(sc.Path, sc.UpdateInterval); err != nil {
					return jsonString(nsPrepareJS{Err: fmt.Errorf("加载脚本失败：%w", err).Error()})
				}
			}
			src = string(b)
		}
		code, err := scriptCode([]byte(src))
		if err != nil {
			return jsonString(nsPrepareJS{Err: err.Error()})
		}
		if err := eng.compile(prog, sc.Name, code); err != nil {
			return jsonString(nsPrepareJS{Err: err.Error()})
		}
	}
	rc := &runCtx{script: sc, name: sc.Name, e: e}
	setup, err := rc.setupJSON(nil, nil)
	if err != nil {
		return jsonString(nsPrepareJS{Err: err.Error()})
	}
	_ = st
	nsPrepared.Add(1)
	return jsonString(nsPrepareJS{OK: true, Key: prog.key, Name: sc.Name, TimeoutMs: timeout.Milliseconds(), Setup: json.RawMessage(setup)})
}

// ---- the response body: modifyResponse's loadBody, split around the bytes Swift holds ----

type nsAdmitJS struct {
	OK     bool   `json:"ok,omitempty"`
	Ticket int64  `json:"ticket,omitempty"`
	Cap    int64  `json:"cap,omitempty"`   // respCap: the decode limit (the lane's limit)
	Limit  int64  `json:"limit,omitempty"` // the script's body limit (scriptBodyLimit)
	Skip   string `json:"skip,omitempty"`  // respSkip
	Retry  bool   `json:"retry,omitempty"` // loaded stays false: a later script with a larger limit may read it
	Gone   bool   `json:"gone,omitempty"`
}

func (e *Engine) rulesOf(gen int64, idx []int) []*Rule {
	st := e.snapState(gen)
	if st == nil || st.rs == nil {
		return nil
	}
	out := make([]*Rule, 0, len(idx))
	for _, i := range idx {
		if i >= 0 && i < len(st.rs.Rules) {
			out = append(out, st.rs.Rules[i])
		}
	}
	return out
}

func parseIdx(csv string) []int {
	var out []int
	for _, f := range strings.Split(csv, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(f)); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// NativeScriptBodyAdmit is loadBody up to the first read, for the script at rule (the first that needs the body):
// heapHigh (with fix/xmly-memory's small work), the announced length against the script's limit and respCap, the
// one-large-body lock, the body budget's first charge. respRules: the response phase's matched rules (f.rules, as
// Ruleset indices) — respCap comes from them. url is f.url (log lines). On success the charge is held under the
// returned ticket until NativeScriptBodyRelease. Log lines are written here as loadBody writes them.
func (e *Engine) NativeScriptBodyAdmit(gen int64, rule int, respRules string, url string, contentLength int64, enc string, token int64) string {
	_, r := e.scriptRule(gen, rule)
	rules := e.rulesOf(gen, parseIdx(respRules))
	if r == nil || len(rules) == 0 {
		return jsonString(nsAdmitJS{Gone: true, Skip: "脚本规则已更新"})
	}
	limit := scriptBodyLimit(r.Script)
	respCap, respCapScript := phaseBodyCapScript(rules, "")
	if heapHigh() {
		cl := contentLength
		if enc != "" && cl >= 0 {
			cl = min(cl*4, smallWorkMax) // compressed: judged on a typical decoded size, capped below
		}
		if !smallWorkOK(cl, smallBodyFloor) {
			skip := heapHighReason()
			e.logf("warning", fmt.Sprintf("[MitM] %s，跳过响应体处理：%s", skip, clip(url, 100)))
			return jsonString(nsAdmitJS{Skip: skip, Limit: int64(limit)})
		}
		if respCap > smallWorkMax {
			respCap = smallWorkMax
		}
		return e.nsAdmitRest(rules, limit, respCap, respCapScript, true, url, contentLength, enc, token)
	}
	return e.nsAdmitRest(rules, limit, respCap, respCapScript, false, url, contentLength, enc, token)
}

func (e *Engine) nsAdmitRest(rules []*Rule, limit, respCap int, respCapScript *Script, small bool, url string, contentLength int64, enc string, token int64) string {
	if contentLength > int64(limit) && enc == "" {
		return jsonString(nsAdmitJS{Retry: true, Limit: int64(limit), Skip: fmt.Sprintf("响应体 %d KB 超过上限 %d KB", contentLength>>10, limit>>10)})
	}
	if contentLength > int64(respCap) {
		return jsonString(nsAdmitJS{Limit: int64(limit), Skip: fmt.Sprintf("响应体 %d KB 超过上限 %d KB（%s）", contentLength>>10, respCap>>10, bodyLimitNote(respCapScript, respCap))})
	}
	want := int64(bodyBudgetChunk)
	if contentLength > 0 {
		want = contentLength
	}
	if want > int64(respCap) {
		want = int64(respCap)
	}
	ctx := tokenCtx(token)
	charge := &bodyCharge{ctx: ctx}
	if (enc == "" && contentLength > bigBodyThreshold) || (enc != "" && contentLength > bigBodyThreshold/4) {
		rel := acquireBigBody(ctx)
		if rel == nil {
			skip := fmt.Sprintf("另一个大响应体正在处理（本响应 %d KB，已等待 %d 秒）", max(want, contentLength)>>10, int(bigBodyWait/time.Second))
			e.logf("warning", fmt.Sprintf("[MitM] %s，原样放行：%s", skip, clip(url, 100)))
			return jsonString(nsAdmitJS{Limit: int64(limit), Skip: skip})
		}
		charge.big = rel
	}
	charge.small = small || want <= smallWorkMax
	if err := charge.ensure(want); err != nil {
		charge.release()
		skip := fmt.Sprintf("同时处理的响应体过多（需 %d KB，已占用 %d KB / %d KB）", want>>10, bodyBudget.inUse()>>10, bodyBudget.capNow()>>10)
		e.logf("warning", fmt.Sprintf("[MitM] %s，跳过：%s", skip, clip(url, 100)))
		return jsonString(nsAdmitJS{Limit: int64(limit), Skip: skip})
	}
	reg := nativeScripts
	reg.mu.Lock()
	id := reg.next()
	reg.charges[id] = &nsCharge{charge: charge, want: want, cl: contentLength, respCap: respCap, capBy: respCapScript, enc: enc, ctx: ctx}
	reg.mu.Unlock()
	nsHeld.Add(1)
	_ = rules
	return jsonString(nsAdmitJS{OK: true, Ticket: id, Cap: int64(respCap), Limit: int64(limit)})
}

func chargeOf(ticket int64) *nsCharge {
	reg := nativeScripts
	reg.mu.Lock()
	defer reg.mu.Unlock()
	return reg.charges[ticket]
}

// NativeScriptBodyLoaded is loadBodyLane after a complete decode: the one-large-body lock for a body that decoded
// past bigBodyThreshold, the charge grown to the decoded size, the lock handed back for a small result. "" = loaded;
// otherwise respSkip (the body passes through as received — the caller serves the raw bytes).
func (e *Engine) NativeScriptBodyLoaded(ticket int64, url string, decoded int64) string {
	c := chargeOf(ticket)
	if c == nil {
		return "脚本规则已更新"
	}
	ch := c.charge
	if decoded > bigBodyThreshold && ch.big == nil {
		rel := acquireBigBody(c.ctx)
		if rel == nil {
			skip := fmt.Sprintf("另一个大响应体正在处理（本响应 %d KB，已等待 %d 秒）", max(c.want, c.cl)>>10, int(bigBodyWait/time.Second))
			e.logf("warning", fmt.Sprintf("[MitM] %s，原样放行：%s", skip, clip(url, 100)))
			return skip
		}
		ch.big = rel
	}
	if err := ch.ensure(decoded); err != nil {
		skip := fmt.Sprintf("同时处理的响应体过多（需 %d KB，已占用 %d KB / %d KB）", decoded>>10, bodyBudget.inUse()>>10, bodyBudget.capNow()>>10)
		e.logf("warning", fmt.Sprintf("[MitM] %s，跳过：%s", skip, clip(url, 100)))
		return skip
	}
	if decoded <= bigBodyThreshold && ch.big != nil {
		ch.big()
		ch.big = nil
	}
	return ""
}

// NativeScriptBodyFailed formats (and logs) respSkip for a body the lane could not load, as loadBodyLane does:
// kind "too-big" (decoded past respCap), "decode" (detail: the store's error), "lane" (a store failure; counted by
// the lane breaker), "cancel" (client gone). raw: encoded bytes received.
func (e *Engine) NativeScriptBodyFailed(ticket int64, url, kind string, raw int64, detail string) string {
	c := chargeOf(ticket)
	respCap, enc := MaxBody, ""
	var capBy *Script
	if c != nil {
		respCap, enc, capBy = c.respCap, c.enc, c.capBy
	}
	switch kind {
	case "too-big":
		skip := fmt.Sprintf("响应体解压后超过 %d KB（%s；Content-Encoding: %s，已收 %d KB）", respCap>>10, bodyLimitNote(capBy, respCap), orNone(enc), raw>>10)
		e.logf("warning", fmt.Sprintf("[MitM] %s，原样放行：%s", skip, clip(url, 100)))
		return skip
	case "decode":
		return fmt.Sprintf("响应体解码失败（Content-Encoding: %s，%d KB）：%s", enc, raw>>10, detail)
	case "cancel":
		return "客户端已断开"
	}
	laneFailure(e.logf, detail)
	return "原生响应体通道出错：" + shortErr(errors.New("lane: "+detail))
}

// NativeScriptBodyRelease hands a body charge back (modifyResponse's deferred f.release: the rules are done with
// the body). Idempotent.
func NativeScriptBodyRelease(ticket int64) {
	reg := nativeScripts
	reg.mu.Lock()
	c := reg.charges[ticket]
	delete(reg.charges, ticket)
	reg.mu.Unlock()
	if c == nil {
		return
	}
	nsHeld.Add(-1)
	c.charge.release()
}

// nsSkipJS answers NativeScriptBodyCheck.
type nsSkipJS struct {
	Limit int64  `json:"limit"`
	Note  string `json:"note,omitempty"` // non-empty: skipped (log line written)
}

// NativeScriptBodyCheck is the per-script check of an already loaded body: the script's limit against blen
// (loaded && !tooBig && blen > limit → skip with modifyResponse's message). limit < 0: scriptBodyLimit(rule) now (a
// later script); the first script passes the limit its admission used (modifyResponse computes it once per script).
// On skip the script log line is written and note is the request-log note.
func (e *Engine) NativeScriptBodyCheck(gen int64, rule int, blen, limit64 int64) string {
	_, r := e.scriptRule(gen, rule)
	if r == nil {
		return jsonString(nsSkipJS{Note: "脚本规则已更新"})
	}
	limit := int(limit64)
	if limit64 < 0 {
		limit = scriptBodyLimit(r.Script)
	}
	if blen <= int64(limit) {
		return jsonString(nsSkipJS{Limit: int64(limit)})
	}
	why := fmt.Sprintf("响应体 %d KB 超过上限 %d KB（%s）", blen>>10, limit>>10, bodyLimitNote(r.Script, limit))
	return jsonString(nsSkipJS{Limit: int64(limit), Note: e.NativeScriptSkip(gen, rule, why)})
}

// NativeScriptSkip writes modifyResponse's 「跳过脚本：」 log line for rule and returns the request-log note.
func (e *Engine) NativeScriptSkip(gen int64, rule int, why string) string {
	_, r := e.scriptRule(gen, rule)
	if r == nil {
		return ""
	}
	if why == "" {
		why = "响应体超过上限或编码不支持"
	}
	e.Logs.Add(r.Script.Name, "warn", "跳过脚本："+why)
	return "跳过脚本：" + r.Script.Name + " — " + why
}

// nsFailJS answers NativeScriptFail.
type nsFailJS struct {
	Note    string `json:"note,omitempty"`
	Ignored bool   `json:"ignored,omitempty"` // an exception after $done: logged as a warning, the answer stands
	Msg     string `json:"msg,omitempty"`
}

// NativeScriptFail turns a failed native run into the Go path's error and logs it the way execute + modifyResponse
// do (the 「运行引擎」 debug line for a run that existed and was not cancelled, then the error), returning the
// request-log note. mode:
//
//	"js"      detail: the engine's error JSON {kind, message} (parseNativeErr → jsErr with the run's stop reason)
//	"timeout" the event loop's deadline passed (「脚本执行超时（…）」)
//	"cancel"  the flow was cancelled (errScriptCancelled)
//	"done"    $done's descriptor did not parse (detail: the decoder's error)
//	"msg"     detail is the message (Prepare's error: load / syntax / queue — no run existed)
//
// stop: the run's stop reason (1 timeout, 2 memory, 3 cancelled). afterDone: $done was already called — an
// exception (not an interruption) is then only logged as 「$done 之后的异常已忽略」 and Ignored is set.
func (e *Engine) NativeScriptFail(gen int64, rule int, mode, detail string, stop int, timeoutMs int64, afterDone bool) string {
	_, r := e.scriptRule(gen, rule)
	if r == nil {
		return jsonString(nsFailJS{})
	}
	name := r.Script.Name
	timeout := time.Duration(timeoutMs) * time.Millisecond
	ran := true
	var err error
	switch mode {
	case "js":
		jerr := parseNativeErr(detail)
		var je *jsError
		rc := &runCtx{}
		rc.stop.Store(int32(stop))
		if afterDone && !(errors.As(jerr, &je) && je.kind == "interrupted") {
			msg := (&ScriptRunner{e: e}).jsErr(rc, jerr, timeout).Error()
			e.Logs.Add(name, "warn", "$done 之后的异常已忽略："+msg)
			return jsonString(nsFailJS{Ignored: true, Msg: msg})
		}
		if stop == stopCancelled && errors.As(jerr, &je) && je.kind == "interrupted" {
			err = errScriptCancelled
		} else {
			err = (&ScriptRunner{e: e}).jsErr(rc, jerr, timeout)
		}
	case "timeout":
		err = fmt.Errorf("脚本执行超时（%s）", timeout)
	case "cancel":
		err = errScriptCancelled
	case "done":
		err = fmt.Errorf("脚本运行时内部错误：$done %s", detail)
	default:
		err = errors.New(detail)
		ran = false
	}
	if ran && !errors.Is(err, errScriptCancelled) {
		e.Logs.Add(name, "debug", "运行引擎：JavaScriptCore")
	}
	e.Logs.Add(name, "error", err.Error())
	return jsonString(nsFailJS{Note: scriptErrNote(name, err), Msg: err.Error()})
}

// ---- host APIs whose state lives in Go ----

// NativeScriptHost answers the prelude host ops that need Go state for rule's script: log ("level\nmsg"), sread /
// swrite / sclear ($persistentStore — the store the app and the Go path share), notify, geo, btoa / atob (hostOp's
// exact rules), and two log lines of execute: x-doneerr (readDone's warning) and x-finished (the run's time).
// Anything else answers "" (the Swift run handles it).
func (e *Engine) NativeScriptHost(gen int64, rule int, op, arg string) string {
	_, r := e.scriptRule(gen, rule)
	if r == nil {
		return ""
	}
	switch op {
	case "log", "sread", "swrite", "sclear", "notify", "geo", "btoa", "atob":
	case "x-doneerr": // readDone's warning for a $done argument the prelude could not read
		e.Logs.Add(r.Script.Name, "warn", "$done 的参数无法读取："+clip(arg, 300))
		return ""
	case "x-finished": // execute's closing debug line (arg: milliseconds)
		e.Logs.Add(r.Script.Name, "debug", fmt.Sprintf("执行完成，用时 %s ms（JavaScriptCore）", arg))
		return ""
	default:
		return ""
	}
	rc := &runCtx{script: r.Script, name: r.Script.Name, e: e}
	return rc.hostOp(op, arg)
}

// NativeScriptBytes runs a byte transform of the prelude: op "ungzip" (inflateAny) or "compress" (arg: the Egern
// compression op, egernCompress). nil = failed (the prelude sees -1).
func NativeScriptBytes(op, arg string, in []byte) []byte {
	var out []byte
	var err error
	switch op {
	case "ungzip":
		out, err = inflateAny(in)
	case "compress":
		out, err = egernCompress(arg, in)
	default:
		return nil
	}
	if err != nil {
		return nil
	}
	if out == nil {
		out = []byte{}
	}
	return out
}

// NativeScriptAPI is $httpAPI (rc.httpAPI): the bridge answers; the result is returned as the __tern_deliver
// argument ("" when the script passed no callback).
func (e *Engine) NativeScriptAPI(gen int64, rule int, arg string) string {
	_, r := e.scriptRule(gen, rule)
	if r == nil {
		return ""
	}
	var d struct {
		M    string          `json:"m"`
		P    string          `json:"p"`
		HasB bool            `json:"hasB"`
		BS   bool            `json:"bs"`
		B    json.RawMessage `json:"b"`
		CB   int64           `json:"cb"`
	}
	if json.Unmarshal([]byte(arg), &d) != nil {
		return ""
	}
	var body any
	if d.HasB {
		if d.BS {
			var s string
			_ = json.Unmarshal(d.B, &s)
			body = s
			var m map[string]any
			if json.Unmarshal([]byte(s), &m) == nil {
				body = m
			}
		} else {
			_ = json.Unmarshal(d.B, &body)
		}
	}
	res, err := e.callAPI(d.M, d.P, body)
	if err != nil {
		e.Logs.Add(r.Script.Name, "warning", "$httpAPI "+d.M+" "+d.P+"："+err.Error())
		res = map[string]any{"error": err.Error()}
	}
	if d.CB < 0 {
		return ""
	}
	out, _ := json.Marshal(map[string]any{"id": d.CB, "v": res})
	return string(out)
}

// NativeFetch is one finished $httpClient download for a native run: Meta is __tern_deliver's JSON without the
// body ({id, err} or {id, status, headers}); Body the decoded bytes. The body budget share is held until Done
// (called once the callback ran, or the run ended without running it — deliverFetch's rule).
type NativeFetch struct {
	Meta    string
	Body    []byte
	release func()
	once    sync.Once
}

// Done returns the download's body budget share (idempotent).
func (f *NativeFetch) Done() {
	f.once.Do(func() {
		if f.release != nil {
			f.release()
			nsHeld.Add(-1)
		}
	})
}

// NativeScriptFetch performs a $httpClient / $task.fetch request (the prelude's fetch JSON) for a native run, the
// way startFetch + do do it: through the engine's client, i.e. mihomo's routing and the script's policy, with the
// body budget charged as it is read. body: the request body bytes (the blob the prelude named). token: the run's
// context (cancelled when the run ends). Blocks for the download (call it off the JavaScript thread).
func (e *Engine) NativeScriptFetch(gen int64, rule int, token int64, arg string, body []byte) *NativeFetch {
	var j fetchJS
	if json.Unmarshal([]byte(arg), &j) != nil {
		return &NativeFetch{Meta: `{"id":0,"err":"bad request"}`}
	}
	_, r := e.scriptRule(gen, rule)
	if r == nil {
		return &NativeFetch{Meta: jsonString(map[string]any{"id": j.ID, "err": "脚本规则已更新"})}
	}
	fr := &fetchReq{url: j.URL, method: j.Method, headers: pairsHeader(j.Headers), timeout: 15 * time.Second,
		binary: j.Binary, policy: j.Policy, insecure: j.Insecure, noRedirect: j.NoRedirect, body: body}
	if j.Timeout > 0 {
		fr.timeout = time.Duration(j.Timeout * float64(time.Millisecond))
	}
	rc := &runCtx{script: r.Script, name: r.Script.Name, e: e, ctx: tokenCtx(token)}
	res := rc.do(fr)
	d := map[string]any{"id": j.ID}
	if res.err != nil {
		d["err"] = res.err.Error()
		return &NativeFetch{Meta: jsonString(d)}
	}
	d["status"] = res.status
	d["headers"] = headerPairs(res.header)
	f := &NativeFetch{Meta: jsonString(d), Body: res.body, release: res.release}
	if f.Body == nil {
		f.Body = []byte{}
	}
	if f.release != nil {
		nsHeld.Add(1)
	}
	return f
}

// ---- the run's memory guard ----

var nsGuardGC atomic.Int64

// NativeScriptMemLow is startMemGuard's condition for a native run (polled by Swift every 50 ms while the run's
// JavaScript executes): in the extension, less than scriptAvailFloor available even after returning memory to the
// OS; without a probe, live heap objects above 90 % of the soft limit.
func NativeScriptMemLow() bool {
	if _, known := availableMemory(); known {
		if ok, known, _ := availableAtLeast(scriptAvailFloor); known && !ok {
			if a, _ := availableMemoryNow(); a < scriptAvailFloor {
				return true
			}
		}
		return false
	}
	limit := memGuardLimit()
	if limit <= 0 || limit >= 1<<40 {
		return false
	}
	threshold := uint64(limit) / 10 * 9
	sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(sample)
	if sample[0].Value.Kind() != metrics.KindUint64 || sample[0].Value.Uint64() <= threshold {
		return false
	}
	now := time.Now().UnixNano()
	if last := nsGuardGC.Load(); now-last > int64(500*time.Millisecond) && nsGuardGC.CompareAndSwap(last, now) {
		runtime.GC()
		metrics.Read(sample)
		if sample[0].Value.Uint64() <= threshold {
			return false
		}
	}
	return true
}

// NativeScriptStats: native script work counters (diagnostics).
func NativeScriptStats() string {
	return fmt.Sprintf("native scripts prepared %d, held %d", nsPrepared.Load(), nsHeld.Load())
}
