package mitm

// Request-log records for requests the Swift rewrite engine answered (native MitM stage 3a).
//
// A request NativeRewriteDriver decides in Swift never reaches the flow API, so requestPhase / modifyResponse /
// NativeFlow.end never write its Entry. Swift reports it instead, off the hot path: it queues small events and
// hands them over in batches (MitmRecordNative, JSON array) — no flow, no goroutine, no http.Request. Each event
// is applied with the same Entry calls the Go path makes at the same point, so the request list and the detail
// view cannot tell a native entry from a Go one:
//
//	drop      requestPhase reject-drop: Match(url rule) · Finish(0, 「拒绝（断开）」)
//	local     reject* / 302 / 307 / Map Local: Match(rules…) · SetURL · Local(status, headers, body, capture)
//	forward   the request goes upstream: Match(url header rule, request header rules…) · SetURL · ReqHeaders
//	response  modifyResponse: Match(response header rules…) · Response(status, headers); 101 → Finish(101, 「WebSocket / Upgrade」)
//	end       NativeFlow.end: AddBytes(sent) (upstream body mode) · Note(why) once a response exists · Finish(-1)
//	cancel    NativeFlow.end(cancelled): after a response Note(why) · Finish(-1) (its body's Close); before it Finish(0, why)
//	upstream  FlowUpstreamFailed: Finish(502, 「上游错误：」+why)
//	error     a response the native engine could not finish: Finish(502, 「内部错误」)
//	abort     a natively run response script aborted: Match(rules…) · Note(notes…) · Finish(502, 「上游错误：」+why)
//
// notes (lane s3-script, native script dispatch): the event's request-log notes in order (skipped scripts, script
// errors) — "response" writes them after its Match calls, every other event before its own action.
//
// Rules travel as indices into the Ruleset of snapshot generation gen; their labels come from that state (the
// current one or one reload back). Times are Swift's: t is the request's start (unix seconds), ms the time from
// start to the event, so Time / Duration read the same as Go's (ms resolution / µs resolution).
// Entries are inserted in start-time order, so a forward recorded when its first event arrives sits where a Go
// entry started at the same moment would. The entry of a forward is kept by its key k until "end" / "cancel" /
// "upstream" (bounded: nativeRecPendingMax; the oldest are forgotten — their entries stay in the ring, unfinished,
// like a Go entry whose flow never ended).
//
// Captured bodies: a local answer's body is recorded like Go's (capture on); a forwarded request's bodies are
// streamed by Swift and not captured (headers are).

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"sync"
	"time"
)

// NativeRecord is one event of a natively answered request (see above).
type NativeRecord struct {
	K       int64       `json:"k"`  // Swift's key for the request (unique per tunnel run)
	Ev      string      `json:"ev"` // drop / local / forward / response / end / cancel / upstream / error
	T       float64     `json:"t"`  // request start, unix seconds
	Ms      float64     `json:"ms"` // start → this event, milliseconds
	Gen     int64       `json:"gen,omitempty"`
	Rules   []int       `json:"rules,omitempty"` // Ruleset indices matched, in Go's Match order
	Method  string      `json:"method,omitempty"`
	URL     string      `json:"url,omitempty"`  // URL at this point (after a header URL rewrite)
	Host    string      `json:"host,omitempty"` // r.Host as the request arrived (port stripped here, like Start)
	TLS     bool        `json:"tls,omitempty"`
	Status  int         `json:"status,omitempty"`
	Headers [][2]string `json:"headers,omitempty"` // request headers (forward) / response headers (local, response)
	Len     int64       `json:"len,omitempty"`     // local: body length
	Body    []byte      `json:"body,omitempty"`    // local: the body (only sent while capture is on)
	Sent    int64       `json:"sent,omitempty"`    // end: body bytes delivered from the upstream (upstream mode)
	Resp    bool        `json:"resp,omitempty"`    // end / cancel: a response decision exists (Go: nf.respBody != nil)
	Why     string      `json:"why,omitempty"`
	// Notes: request-log notes of the event, in order (native script dispatch, lane s3-script: skipped scripts,
	// script errors, an abort) — written before the event's own action, like modifyResponse's ent.Note calls.
	Notes []string `json:"notes,omitempty"`
}

const nativeRecPendingMax = 512

type nativeRecs struct {
	mu      sync.Mutex
	pending map[int64]*Entry
	order   []int64 // insertion order of pending keys (oldest first; may hold finished keys)
}

var (
	nativeRecMu  sync.Mutex
	nativeRecAll = map[*Engine]*nativeRecs{}
)

func (e *Engine) nativeRecs() *nativeRecs {
	nativeRecMu.Lock()
	defer nativeRecMu.Unlock()
	r := nativeRecAll[e]
	if r == nil {
		r = &nativeRecs{pending: map[int64]*Entry{}}
		nativeRecAll[e] = r
	}
	return r
}

func forgetNativeRecords(e *Engine) {
	nativeRecMu.Lock()
	delete(nativeRecAll, e)
	nativeRecMu.Unlock()
}

// RecordNative applies a JSON array of NativeRecord; it returns how many were applied (-1: bad JSON).
func (e *Engine) RecordNative(js string) int {
	if e == nil || e.Requests == nil {
		return 0
	}
	var recs []NativeRecord
	if err := json.Unmarshal([]byte(js), &recs); err != nil {
		return -1
	}
	n := 0
	for i := range recs {
		if e.applyNative(&recs[i]) {
			n++
		}
	}
	return n
}

// NativePending is the number of native forwards waiting for their end (tests, diagnostics).
func (e *Engine) NativePending() int {
	r := e.nativeRecs()
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}

func (e *Engine) applyNative(rec *NativeRecord) bool {
	recs := e.nativeRecs()
	switch rec.Ev {
	case "drop", "local", "forward":
		ent := e.Requests.startNative(rec)
		for _, l := range e.nativeLabels(rec) {
			ent.Match(l)
		}
		ms := nativeMs(rec.Ms)
		switch rec.Ev {
		case "drop":
			ent.finishAt(0, "拒绝（断开）", ms)
		case "local":
			ent.SetURL(rec.URL)
			body := rec.Body
			ent.mu.Lock()
			ent.IsLocal = true
			ent.Status = rec.Status
			ent.RespHdr = flatHeaders(headerFromPairs(rec.Headers))
			ent.Bytes = rec.Len
			ent.mu.Unlock()
			if len(body) > 0 && e.state() != nil && e.state().cfg.capture() {
				ent.RespBody(body, "")
			}
			ent.finishAt(-1, "", ms)
		case "forward":
			ent.SetURL(rec.URL)
			ent.ReqHeaders(ent.Method, headerFromPairs(rec.Headers))
			recs.mu.Lock()
			recs.pending[rec.K] = ent
			recs.order = append(recs.order, rec.K)
			for len(recs.pending) > nativeRecPendingMax && len(recs.order) > 0 {
				delete(recs.pending, recs.order[0])
				recs.order = recs.order[1:]
			}
			if len(recs.order) > 4*nativeRecPendingMax {
				live := recs.order[:0]
				for _, k := range recs.order {
					if recs.pending[k] != nil {
						live = append(live, k)
					}
				}
				recs.order = live
			}
			recs.mu.Unlock()
		}
		return true
	case "response", "end", "cancel", "upstream", "error", "abort":
		recs.mu.Lock()
		ent := recs.pending[rec.K]
		if ent != nil && rec.Ev != "response" {
			delete(recs.pending, rec.K)
		}
		recs.mu.Unlock()
		if ent == nil {
			return false
		}
		ms := nativeMs(rec.Ms)
		if rec.Ev != "response" {
			for _, n := range rec.Notes {
				ent.Note(n)
			}
		}
		switch rec.Ev {
		case "response":
			if rec.Status != http.StatusSwitchingProtocols {
				for _, l := range e.nativeLabels(rec) {
					ent.Match(l)
				}
			}
			for _, n := range rec.Notes {
				ent.Note(n)
			}
			ent.Response(rec.Status, headerFromPairs(rec.Headers))
			if rec.Status == http.StatusSwitchingProtocols {
				ent.finishAt(101, "WebSocket / Upgrade", ms)
			}
		case "end":
			if rec.Sent > 0 {
				ent.AddBytes(int(rec.Sent))
			}
			if rec.Why != "" && rec.Resp {
				ent.Note(rec.Why)
			}
			ent.finishAt(-1, "", ms)
		case "cancel":
			why := rec.Why
			if why == "" {
				why = "客户端取消"
			}
			if rec.Resp {
				// the response body's Close finishes the entry first (status kept), then the note stays
				ent.Note(why)
				ent.finishAt(-1, "", ms)
			} else {
				ent.finishAt(0, why, ms)
			}
		case "upstream":
			ent.finishAt(502, "上游错误："+rec.Why, ms)
		case "error":
			ent.finishAt(502, "内部错误", ms)
		case "abort":
			// a response script aborted (Egern ctx.abort()): runResponse's modifyResponse error → 502
			for _, l := range e.nativeLabels(rec) {
				ent.Match(l)
			}
			ent.finishAt(502, "上游错误："+shortErr(errors.New(rec.Why)), ms)
		}
		return true
	}
	return false
}

// nativeLabels are the rule labels of rec.Rules in the state of its snapshot generation.
func (e *Engine) nativeLabels(rec *NativeRecord) []string {
	if len(rec.Rules) == 0 {
		return nil
	}
	st := e.snapState(rec.Gen)
	if st == nil || st.rs == nil {
		return nil
	}
	out := make([]string, 0, len(rec.Rules))
	for _, i := range rec.Rules {
		if i >= 0 && i < len(st.rs.Rules) {
			out = append(out, st.rs.Rules[i].label())
		}
	}
	return out
}

// nativeMs rounds a duration to Go's resolution (Finish: microseconds / 1000).
func nativeMs(ms float64) float64 {
	if ms < 0 || math.IsNaN(ms) || math.IsInf(ms, 0) {
		return 0
	}
	return math.Trunc(ms*1000) / 1000
}

// startNative is Start for a native record: same host / time rules, inserted in start-time order.
func (l *RequestLog) startNative(rec *NativeRecord) *Entry {
	host := stripLogPort(rec.Host)
	t := rec.T
	if t <= 0 || math.IsNaN(t) || math.IsInf(t, 0) {
		t = float64(time.Now().UnixMilli()) / 1000
	}
	t = math.Trunc(t*1000) / 1000
	method := rec.Method
	if method == "" {
		method = http.MethodGet
	}
	e := &Entry{ID: l.seq.Add(1), Time: t, Method: method, URL: rec.URL, Host: host, MitM: rec.TLS,
		start: time.UnixMilli(int64(t * 1000)), ring: l}
	l.mu.Lock()
	i := len(l.list)
	for j := 0; i > 0 && j < 256 && l.list[i-1].Time > t; j++ {
		i--
	}
	l.list = append(l.list, nil)
	copy(l.list[i+1:], l.list[i:])
	l.list[i] = e
	if len(l.list) > l.max {
		copy(l.list, l.list[len(l.list)-l.max:])
		l.list = l.list[:l.max]
	}
	l.mu.Unlock()
	return e
}

// stripLogPort is Start's host rule (r.Host without its port).
func stripLogPort(host string) string {
	for i := len(host) - 1; i > 0; i-- {
		if host[i] == ']' {
			return host
		}
		if host[i] == ':' {
			return host[:i]
		}
	}
	return host
}

// finishAt is Finish with the duration measured by Swift.
func (e *Entry) finishAt(status int, note string, ms float64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.Done {
		return
	}
	e.Done = true
	if status >= 0 {
		e.Status = status
	}
	if note != "" {
		e.Notes = append(e.Notes, note)
	}
	e.Duration = ms
}
