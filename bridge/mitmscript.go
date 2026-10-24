package libmihomo

// Native script dispatch (native MitM stage 3, lane s3-script; bridge/mitm/nativescript.go). The Swift dispatcher
// (PacketTunnel/NativeMitM/Script/) runs http-response scripts of a natively handled request in JavaScriptCore
// with the body in NativeBodyStore; these calls are what stays in Go — admission (script slots, large-bundle lock,
// queue, body budget, big-body lock, memory gates), the program cache index, Go-state host APIs ($persistentStore,
// notifications, $httpAPI, geo, $httpClient through mihomo routing) and log lines. None of them carries a body,
// except $httpClient's request / response and the rare ungzip / compress helpers. All are synchronous; the ones
// that can block (Reserve, BodyAdmit, BodyLoaded, Fetch, Prepare) must not run on the main thread. Every call
// answers harmlessly when the MitM engine is not running.

import "github.com/astemo6/mihomo-ios/bridge/mitm"

func curEngine() *mitm.Engine {
	engMu.Lock()
	defer engMu.Unlock()
	return eng
}

// MitmScriptReady: JavaScriptCore runs scripts and the native body lane is registered.
func MitmScriptReady() bool { return curEngine() != nil && mitm.NativeScriptReady() }

// MitmScriptToken makes a cancellable context for a native flow or run; MitmScriptCancel cancels and forgets it.
func MitmScriptToken() int64                 { return mitm.NativeScriptToken() }
func MitmScriptCancel(token int64)           { mitm.NativeScriptCancel(token) }
func MitmScriptHeld() int64                  { return mitm.NativeScriptHeld() }
func MitmScriptStats() string                { return mitm.NativeScriptStats() }
func MitmScriptMemLow() bool                 { return mitm.NativeScriptMemLow() }
func MitmScriptRelease(slot int64, ran bool) { mitm.NativeScriptRelease(slot, ran) }
func MitmScriptBodyRelease(ticket int64)     { mitm.NativeScriptBodyRelease(ticket) }

// MitmScriptReserve takes an HTTP script slot for Ruleset rule of snapshot gen (JSON {slot} | {err, note}).
func MitmScriptReserve(gen int64, rule int, token int64) string {
	e := curEngine()
	if e == nil {
		return `{"gone":true,"err":"MitM engine not running"}`
	}
	return e.NativeScriptReserve(gen, rule, token)
}

// MitmScriptPrepare loads rule's script into JavaScriptCore and returns its key, timeout and setup base (JSON).
func MitmScriptPrepare(gen int64, rule int, slot int64, reload bool) string {
	e := curEngine()
	if e == nil {
		return `{"ok":false,"err":"MitM engine not running"}`
	}
	return e.NativeScriptPrepare(gen, rule, slot, reload)
}

// MitmScriptBodyAdmit is loadBody's admission for the script rule that first needs the response body.
// respRules: the response phase's matched rules as comma-separated Ruleset indices.
func MitmScriptBodyAdmit(gen int64, rule int, respRules string, url string, contentLength int64, enc string, token int64) string {
	e := curEngine()
	if e == nil {
		return `{"gone":true,"skip":"MitM engine not running"}`
	}
	return e.NativeScriptBodyAdmit(gen, rule, respRules, url, contentLength, enc, token)
}

// MitmScriptBodyLoaded completes the admission once the body decoded ("" ok, else the skip reason).
func MitmScriptBodyLoaded(ticket int64, url string, decoded int64) string {
	e := curEngine()
	if e == nil {
		return "MitM engine not running"
	}
	return e.NativeScriptBodyLoaded(ticket, url, decoded)
}

// MitmScriptBodyFailed formats (and logs) the skip reason of a body that could not be loaded.
func MitmScriptBodyFailed(ticket int64, url, kind string, raw int64, detail string) string {
	e := curEngine()
	if e == nil {
		return "MitM engine not running"
	}
	return e.NativeScriptBodyFailed(ticket, url, kind, raw, detail)
}

// MitmScriptBodyCheck checks an already loaded body against rule's limit (limit < 0: computed now; JSON {limit, note}).
func MitmScriptBodyCheck(gen int64, rule int, blen, limit int64) string {
	e := curEngine()
	if e == nil {
		return `{"limit":0,"note":"MitM engine not running"}`
	}
	return e.NativeScriptBodyCheck(gen, rule, blen, limit)
}

// MitmScriptSkip logs 「跳过脚本：why」 for rule and returns the request-log note.
func MitmScriptSkip(gen int64, rule int, why string) string {
	e := curEngine()
	if e == nil {
		return ""
	}
	return e.NativeScriptSkip(gen, rule, why)
}

// MitmScriptFail logs a failed native run of rule like the Go path (JSON {note, ignored, msg}; see mitm.NativeScriptFail).
func MitmScriptFail(gen int64, rule int, mode, detail string, stop int, timeoutMs int64, afterDone bool) string {
	e := curEngine()
	if e == nil {
		return "{}"
	}
	return e.NativeScriptFail(gen, rule, mode, detail, stop, timeoutMs, afterDone)
}

// MitmScriptHost answers the Go-state host ops of rule's script (log, sread, swrite, sclear, notify, geo, btoa, atob).
func MitmScriptHost(gen int64, rule int, op, arg string) string {
	e := curEngine()
	if e == nil {
		return ""
	}
	return e.NativeScriptHost(gen, rule, op, arg)
}

// MitmScriptBytes: "ungzip" / "compress" (arg: the Egern op) on in; nil when it failed.
func MitmScriptBytes(op, arg string, in []byte) []byte { return mitm.NativeScriptBytes(op, arg, in) }

// MitmScriptAPI is $httpAPI for rule's script: the __tern_deliver argument ("" without callback).
func MitmScriptAPI(gen int64, rule int, arg string) string {
	e := curEngine()
	if e == nil {
		return ""
	}
	return e.NativeScriptAPI(gen, rule, arg)
}

// MitmScriptFetchResult is one finished $httpClient download (see mitm.NativeFetch).
type MitmScriptFetchResult struct{ f *mitm.NativeFetch }

// Meta is __tern_deliver's JSON without the body ({id, err} or {id, status, headers}).
func (r *MitmScriptFetchResult) Meta() string { return r.f.Meta }

// Body is the decoded response body (empty on error).
func (r *MitmScriptFetchResult) Body() []byte { return r.f.Body }

// Done returns the download's body budget share; call it once the callback ran or the run ended.
func (r *MitmScriptFetchResult) Done() { r.f.Done() }

// MitmScriptFetch performs a $httpClient request of rule's script through mihomo (blocking).
func MitmScriptFetch(gen int64, rule int, token int64, arg string, body []byte) *MitmScriptFetchResult {
	e := curEngine()
	if e == nil {
		return &MitmScriptFetchResult{f: &mitm.NativeFetch{Meta: `{"id":0,"err":"MitM engine not running"}`}}
	}
	return &MitmScriptFetchResult{f: e.NativeScriptFetch(gen, rule, token, arg, body)}
}

// MitmScriptReqBodyAdmit is requestPhase's loadBody admission for a native request script (native-final): JSON
// {ok, ticket, cap, limit} | {skip, retry} (see mitm.NativeScriptReqBodyAdmit). Release with MitmScriptBodyRelease.
func MitmScriptReqBodyAdmit(gen int64, rule int, url string, contentLength int64, token int64) string {
	e := curEngine()
	if e == nil {
		return `{"gone":true,"skip":"MitM engine not running"}`
	}
	return e.NativeScriptReqBodyAdmit(gen, rule, url, contentLength, token)
}

// MitmScriptReqBodySkip logs requestPhase's 「跳过脚本：」 line for a request script whose body was refused and
// returns the request-log note (blen ≥ 0: a loaded body over the script's limit).
func MitmScriptReqBodySkip(gen int64, rule int, why string, blen int64) string {
	e := curEngine()
	if e == nil {
		return ""
	}
	return e.NativeScriptReqBodySkip(gen, rule, why, blen)
}

// MitmScriptReqLimit is scriptBodyLimit of rule's script (-1: gone / not running).
func MitmScriptReqLimit(gen int64, rule int) int64 {
	e := curEngine()
	if e == nil {
		return -1
	}
	return e.NativeScriptReqLimit(gen, rule)
}
