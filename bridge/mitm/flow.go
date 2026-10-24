package mitm

// Native flow API (feat/native-mitm stage 2, Go side; design: work/native-mitm-design.md §12).
//
// With the native TLS front (nativeterm.go) a decrypted HTTP/1.1 connection lives in Swift. Swift only frames
// bytes; every decision stays here, made by the same code as the Go path:
//
//	FlowBegin(request head)      → need-body | forward | local | drop | busy   (request phase, flowRequestPhase)
//	FlowWrite / FlowClose        ← the client's request body, when asked (need-body)
//	FlowAwait                    → the decision once the body was read
//	FlowRead / FlowReadState     → an outbound body Go produced (rewritten request body, local response body)
//	FlowResponse(response head)  → need-body | respond | upgrade | error       (response phase: modifyResponse)
//	FlowWrite / FlowClose        ← the upstream's response body, when asked
//	FlowEnd(sent, err) / FlowCancel(why)
//
// The response phase is the Go path's own modifyResponse, called on an *http.Response built from the head
// with an in-pipe as its body, so admission, budgets (bodyBudget, bigBodyLock, the dynamic body cap), the
// native body lane, header rewrites, body rewrites, scripts and every pass-through fallback are the very same
// code. The request phase is the Go path's own requestPhase (handler.go, shared with serveHTTP) writing to a
// flowWriter instead of net/http's ResponseWriter, with flowOutbound standing in for ReverseProxy; the
// differential tests in flow_parity_test.go check both paths against each other.
//
// Body modes in decisions (what the native side sends next):
//
//	none      no body
//	client    send the client's own request body unchanged (Go never read it)
//	upstream  send the upstream's own response body unchanged (Go never read it); report bytes in FlowEnd
//	read      pull the body from Go with FlowRead (Go read part of it, rewrote it, or produced it)
//	lane      the body is in NativeBodyStore under lane.handle (raw: the encoded original); read it there and
//	          leave the handle to Go (freed at FlowEnd); report bytes in FlowEnd
//
// Memory: a flow holds no body in Go beyond what the Go path would hold for the same rules (the phase code
// is shared) plus its pipes (flowPipeCap each, flowPipeBudget overall). FlowStats reports both.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	flowReq  = 0 // body towards the upstream (the client's request body)
	flowResp = 1 // body towards the client (the upstream's response body, or a local answer)
)

// flowMaxLive bounds the flows Go keeps state for; past it FlowBegin answers "busy".
var flowMaxLive int64 = 512

// flowIdle: a flow nobody touched for this long is reaped (its handles freed, its entry finished). Native
// sessions call FlowEnd; this only bounds leaks from a session that died without it.
var flowIdle = 10 * time.Minute

// flowAwaitMax bounds a FlowBegin / FlowAwait / FlowResponse wait (a script queue, the big-body lock and
// the body budget all have their own shorter bounds; this is the backstop).
var flowAwaitMax = 2 * time.Minute

// FlowHead is the request head the native session parsed (JSON from Swift).
type FlowHead struct {
	Method string `json:"method"`
	// Target is the request-target as on the wire ("/path?q", or an absolute URL).
	Target string `json:"target"`
	// Host is the Host header ("" none; the connection's host is used then).
	Host string `json:"host"`
	// Headers in wire order, duplicates kept; Host and Transfer-Encoding may be included (Go moves them out
	// the way net/http's server does).
	Headers [][2]string `json:"headers"`
	// Length is the request body length: >= 0 Content-Length, -1 chunked / unknown. Ignored when Headers has
	// Content-Length.
	Length int64 `json:"length"`
	// Connection: the CONNECT target (or SNI) and port, whether it is TLS, and the connection id the CONNECT
	// listener gave it (0 unknown).
	ConnHost string `json:"connHost"`
	ConnPort int    `json:"connPort"`
	TLS      bool   `json:"tls"`
	ConnID   int64  `json:"connId"`
}

// FlowRespHead is the upstream response head (JSON from Swift).
type FlowRespHead struct {
	Status  int         `json:"status"`
	Headers [][2]string `json:"headers"`
	// Length: >= 0 the body length, -1 unknown (chunked / close-delimited). Content-Length in Headers wins.
	Length int64 `json:"length"`
}

// FlowLane names a NativeBodyStore handle holding a body.
type FlowLane struct {
	Handle int64 `json:"handle"`
	Raw    bool  `json:"raw"`
}

// flowDecision is what FlowBegin / FlowAwait / FlowResponse return (as JSON).
type flowDecision struct {
	ID     int64  `json:"id"`
	Action string `json:"action"`
	// Which: the body a need-body asks for (0 request, 1 response).
	Which int `json:"which"`
	// forward
	Method string `json:"method,omitempty"`
	URL    string `json:"url,omitempty"`
	Host   string `json:"host,omitempty"`
	// local / respond / error / upgrade
	Status  int         `json:"status,omitempty"`
	Headers [][2]string `json:"headers,omitempty"`
	// Body mode (see above) and its length (-1 unknown: chunked towards the client, close-delimited or
	// chunked towards the upstream).
	Body   string    `json:"body,omitempty"`
	Length int64     `json:"length"`
	Lane   *FlowLane `json:"lane,omitempty"`
	Note   string    `json:"note,omitempty"`
}

func (d flowDecision) json() string {
	if d.Body == "" && (d.Action == "forward" || d.Action == "local" || d.Action == "respond") {
		d.Body = "none"
	}
	b, _ := json.Marshal(d)
	return string(b)
}

// NativeFlow is one request/response exchange of a native HTTP/1.1 session.
type NativeFlow struct {
	id     int64
	e      *Engine
	ctx    context.Context
	cancel context.CancelCauseFunc

	mu   sync.Mutex
	cond *sync.Cond
	// phaseActive: a phase goroutine is running (in-pipe reads block, pushes wait for room).
	phaseActive bool
	// final: the phase published its decision (pushes stop waiting); pending: a decision not yet taken.
	final   bool
	pending *flowDecision
	stage   string // "request", "upstream", "response", "done"

	in  [2]*flowPipe // in-pipes: client request body, upstream response body
	out [2]io.Reader // what FlowRead serves: request body towards upstream, response body towards client
	ost [2]string    // FlowReadState: "" / "more" / "eof" / "err: …"
	cl  [2]io.Closer // closed at the end
	ent *Entry
	req *http.Request // the request after the request phase (outbound form)
	f   *flow         // response-phase rules, budget release
	// respBody is the response body modifyResponse left (finishBody / captureBody around the real reader).
	respBody io.ReadCloser
	respMode string // body mode of the response decision
	laneH    int64  // lane handle handed to the native side (respMode "lane")

	// afterPhase: a FlowEnd that arrived while the phase goroutine ran; it runs when the goroutine returns.
	afterPhase func()

	held     atomic.Int64 // pipe bytes this flow buffers
	lastSeen atomic.Int64 // unix nanos of the last API call
	ended    atomic.Bool
}

var (
	flowSeq     atomic.Int64
	flowMu      sync.Mutex
	flowTable   = map[int64]*NativeFlow{}
	flowLive    atomic.Int64
	flowTotal   atomic.Int64
	flowBusy    atomic.Int64
	flowReaped  atomic.Int64
	flowNeeded  atomic.Int64 // need-body decisions
	flowLaneOut atomic.Int64 // response bodies handed over as lane handles
	flowRawOut  atomic.Int64 // response bodies left to the native side unchanged (upstream mode)
	flowReaper  sync.Once
)

func (nf *NativeFlow) touch() { nf.lastSeen.Store(time.Now().UnixNano()) }

// publishLocked hands a decision to the waiting FlowBegin / FlowAwait / FlowResponse. Called with mu held.
func (nf *NativeFlow) publishLocked(d flowDecision) {
	d.ID = nf.id
	if d.Action == "need-body" {
		flowNeeded.Add(1)
	} else {
		nf.final = true
	}
	nf.pending = &d
	nf.cond.Broadcast()
}

func (nf *NativeFlow) publish(d flowDecision) {
	nf.mu.Lock()
	nf.publishLocked(d)
	nf.mu.Unlock()
}

// await waits for the next decision.
func (nf *NativeFlow) await() string {
	nf.mu.Lock()
	defer nf.mu.Unlock()
	deadline := time.Now().Add(flowAwaitMax)
	stop := context.AfterFunc(nf.ctx, func() { nf.mu.Lock(); nf.cond.Broadcast(); nf.mu.Unlock() })
	defer stop()
	t := time.AfterFunc(flowAwaitMax, func() { nf.mu.Lock(); nf.cond.Broadcast(); nf.mu.Unlock() })
	defer t.Stop()
	for nf.pending == nil {
		if nf.ctx.Err() != nil {
			return flowDecision{ID: nf.id, Action: "gone", Note: causeText(nf.ctx)}.json()
		}
		if !nf.phaseActive {
			return flowDecision{ID: nf.id, Action: "error", Note: "no decision pending"}.json()
		}
		if time.Now().After(deadline) {
			return flowDecision{ID: nf.id, Action: "error", Note: "timed out waiting for the rules"}.json()
		}
		nf.cond.Wait()
	}
	d := *nf.pending
	nf.pending = nil
	return d.json()
}

func causeText(ctx context.Context) string {
	if c := context.Cause(ctx); c != nil {
		return c.Error()
	}
	return "cancelled"
}

func lookupFlow(id int64) *NativeFlow {
	flowMu.Lock()
	nf := flowTable[id]
	flowMu.Unlock()
	if nf != nil {
		nf.touch()
	}
	return nf
}

func startReaper() {
	flowReaper.Do(func() {
		go func() {
			for {
				time.Sleep(flowIdle / 4)
				reapFlows(time.Now())
			}
		}()
	})
}

// reapFlows ends flows idle past flowIdle (sessions that vanished without FlowEnd).
func reapFlows(now time.Time) int {
	var old []*NativeFlow
	flowMu.Lock()
	for _, nf := range flowTable {
		if now.Sub(time.Unix(0, nf.lastSeen.Load())) > flowIdle {
			old = append(old, nf)
		}
	}
	flowMu.Unlock()
	for _, nf := range old {
		flowReaped.Add(1)
		nf.end(0, "原生连接无响应，已回收", true)
	}
	return len(old)
}

func headerFromPairs(pairs [][2]string) http.Header {
	h := make(http.Header, len(pairs))
	for _, kv := range pairs {
		k := strings.TrimSpace(kv[0])
		if k == "" {
			continue
		}
		h.Add(k, kv[1])
	}
	return h
}

// headerPairs flattens h in a stable order (keys sorted, values in order).
func flowHeaderPairs(h http.Header) [][2]string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([][2]string, 0, len(h))
	for _, k := range keys {
		for _, v := range h[k] {
			out = append(out, [2]string{k, v})
		}
	}
	return out
}

// FlowBegin starts a flow from a request head (JSON FlowHead) and returns the first decision (JSON).
func (e *Engine) FlowBegin(headJSON string) string {
	var head FlowHead
	if err := json.Unmarshal([]byte(headJSON), &head); err != nil {
		return flowDecision{Action: "error", Note: "bad head: " + err.Error()}.json()
	}
	r, err := head.request()
	if err != nil {
		return flowDecision{Action: "error", Note: "bad head: " + err.Error()}.json()
	}
	if flowLive.Load() >= flowMaxLive {
		flowBusy.Add(1)
		return flowDecision{Action: "busy", Note: "too many native flows"}.json()
	}
	startReaper()
	ctx, cancel := context.WithCancelCause(context.Background())
	nf := &NativeFlow{id: flowSeq.Add(1), e: e, ctx: ctx, cancel: cancel, stage: "request"}
	nf.cond = sync.NewCond(&nf.mu)
	nf.touch()
	nf.in[flowReq] = newFlowPipe(nf, flowReq, false)
	nf.in[flowResp] = newFlowPipe(nf, flowResp, false)
	meta := &connMeta{host: head.ConnHost, port: head.ConnPort, tls: head.TLS, connID: head.ConnID}
	ctx = context.WithValue(ctx, metaKey{}, meta)
	r = r.WithContext(ctx)
	if r.ContentLength != 0 {
		r.Body = nf.in[flowReq]
	} else {
		r.Body = http.NoBody
		nf.mu.Lock()
		nf.in[flowReq].closeWrite(nil)
		nf.mu.Unlock()
	}
	flowMu.Lock()
	flowTable[nf.id] = nf
	flowMu.Unlock()
	flowLive.Add(1)
	flowTotal.Add(1)
	nf.mu.Lock()
	nf.phaseActive = true
	nf.mu.Unlock()
	go nf.runRequest(r)
	return nf.await()
}

// request builds the *http.Request net/http's server would have produced for the head.
func (h *FlowHead) request() (*http.Request, error) {
	if h.Method == "" {
		h.Method = http.MethodGet
	}
	if h.Target == "" {
		h.Target = "/"
	}
	r, err := http.NewRequest(h.Method, "http://placeholder/", nil)
	if err != nil {
		return nil, err
	}
	u, err := parseRequestTarget(h.Target)
	if err != nil {
		return nil, err
	}
	r.URL = u
	r.RequestURI = h.Target
	r.Proto, r.ProtoMajor, r.ProtoMinor = "HTTP/1.1", 1, 1
	r.Header = headerFromPairs(h.Headers)
	host := h.Host
	if v := r.Header.Get("Host"); v != "" {
		host = v
	}
	r.Header.Del("Host")
	if host == "" && u.Host != "" {
		host = u.Host
	}
	if host == "" {
		host = h.ConnHost
		if h.ConnPort != 0 && h.ConnPort != 443 && h.ConnPort != 80 {
			host += ":" + strconv.Itoa(h.ConnPort)
		}
	}
	r.Host = host
	r.ContentLength = h.Length
	if te := r.Header.Values("Transfer-Encoding"); len(te) > 0 {
		r.Header.Del("Transfer-Encoding")
		r.TransferEncoding = []string{"chunked"}
		r.ContentLength = -1
	}
	if cl := r.Header.Get("Content-Length"); cl != "" && len(r.TransferEncoding) == 0 {
		n, err := strconv.ParseInt(strings.TrimSpace(cl), 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("bad Content-Length %q", cl)
		}
		r.ContentLength = n
	}
	if r.ContentLength < 0 && len(r.TransferEncoding) == 0 && (h.Method == http.MethodGet || h.Method == http.MethodHead) {
		r.ContentLength = 0 // net/http: no framing on a GET means no body
	}
	return r, nil
}

func parseRequestTarget(t string) (*urlT, error) { return parseURI(t) }

// FlowAwait waits for the decision after a need-body (JSON).
func FlowAwait(id int64) string {
	nf := lookupFlow(id)
	if nf == nil {
		return flowDecision{ID: id, Action: "gone", Note: "unknown flow"}.json()
	}
	return nf.await()
}

// FlowWrite pushes the next piece of the client's request body (which 0) or the upstream's response body
// (which 1). "" taken; "full" not taken (FlowAwait for the pending decision, or FlowRead first, then push it
// again); "stop" Go no longer wants this body (drop the rest; for the upstream body: stop reading it);
// "gone" the flow ended.
func FlowWrite(id int64, which int, b []byte) string {
	nf := lookupFlow(id)
	if nf == nil || which < 0 || which > 1 {
		return "gone"
	}
	nf.mu.Lock()
	defer nf.mu.Unlock()
	p := nf.in[which]
	return p.push(b, func() bool { return nf.phaseActive && !nf.final })
}

// FlowClose ends a pushed body: errText "" a clean end, else the read failed (client / upstream cut).
func FlowClose(id int64, which int, errText string) {
	nf := lookupFlow(id)
	if nf == nil || which < 0 || which > 1 {
		return
	}
	nf.mu.Lock()
	defer nf.mu.Unlock()
	var err error
	if errText != "" {
		err = errors.New(errText)
	}
	nf.in[which].closeWrite(err)
}

// FlowRead pulls up to max bytes of a body Go produced (which 0: towards the upstream, 1: towards the
// client). Empty: see FlowReadState.
func FlowRead(id int64, which int, max int) []byte {
	nf := lookupFlow(id)
	if nf == nil || which < 0 || which > 1 {
		return nil
	}
	if max <= 0 || max > 4*laneChunk {
		max = laneChunk
	}
	nf.mu.Lock()
	r := nf.out[which]
	nf.mu.Unlock()
	if r == nil {
		nf.setState(which, "err: no body to read")
		return nil
	}
	buf := make([]byte, max)
	n := 0
	for n < max {
		k, err := r.Read(buf[n:])
		n += k
		if err == nil {
			if k == 0 {
				break
			}
			continue
		}
		switch {
		case errors.Is(err, io.EOF):
			nf.setState(which, "eof")
		case errors.Is(err, errFlowWouldBlock):
			nf.setState(which, "more")
		default:
			nf.setState(which, "err: "+shortErr(err))
		}
		return buf[:n]
	}
	nf.setState(which, "")
	return buf[:n]
}

func (nf *NativeFlow) setState(which int, s string) {
	nf.mu.Lock()
	nf.ost[which] = s
	nf.mu.Unlock()
}

// FlowReadState explains the last FlowRead: "" more may follow (read again), "more" Go needs more of the
// pushed body first (FlowWrite the next piece, or FlowClose), "eof" the body is complete, "err: …" the body
// failed (cut the connection: never send a truncated body as complete).
func FlowReadState(id int64, which int) string {
	nf := lookupFlow(id)
	if nf == nil || which < 0 || which > 1 {
		return "err: unknown flow"
	}
	nf.mu.Lock()
	defer nf.mu.Unlock()
	return nf.ost[which]
}

// FlowResponse runs the response phase on the upstream's head (JSON FlowRespHead); the decision (JSON).
func FlowResponse(id int64, headJSON string) string {
	nf := lookupFlow(id)
	if nf == nil {
		return flowDecision{ID: id, Action: "gone", Note: "unknown flow"}.json()
	}
	var head FlowRespHead
	if err := json.Unmarshal([]byte(headJSON), &head); err != nil {
		return flowDecision{ID: id, Action: "error", Status: 502, Note: "bad head: " + err.Error()}.json()
	}
	nf.mu.Lock()
	// The request phase goroutine publishes "forward" and only then runs its deferred bookkeeping, which reads
	// final / phaseActive — the very fields the response phase resets. Wait for it to return (phaseDone
	// broadcasts): an immediate FlowResponse otherwise got the request goroutine's "request phase ended
	// without a decision" as its answer (seen under -race, stage 3a).
	for nf.phaseActive && nf.stage == "upstream" {
		nf.cond.Wait()
	}
	if nf.stage != "upstream" || nf.f == nil {
		st := nf.stage
		nf.mu.Unlock()
		return flowDecision{ID: id, Action: "error", Status: 502, Note: "flow is not waiting for a response (" + st + ")"}.json()
	}
	nf.stage = "response"
	nf.phaseActive, nf.final, nf.pending = true, false, nil
	nf.mu.Unlock()
	go nf.runResponse(head)
	return nf.await()
}

// FlowUpstreamFailed reports that the upstream could not be reached or failed before a response head (the
// native side answers 502, like the Go path's ReverseProxy).
func FlowUpstreamFailed(id int64, why string) {
	nf := lookupFlow(id)
	if nf == nil {
		return
	}
	nf.ent.Finish(502, "上游错误："+why)
	nf.end(0, "", false)
}

// FlowEnd finishes a flow: sent is the body bytes the native side delivered itself (upstream / lane modes),
// errText why it stopped early ("" complete). Frees everything Go still holds for the flow.
func FlowEnd(id int64, sent int64, errText string) {
	nf := lookupFlow(id)
	if nf == nil {
		return
	}
	nf.end(sent, errText, false)
}

// FlowCancel is FlowEnd for a client that went away mid-way (scripts waiting for a slot, budgets, the lane
// all see the cancellation).
func FlowCancel(id int64, why string) {
	nf := lookupFlow(id)
	if nf == nil {
		return
	}
	if why == "" {
		why = "客户端取消"
	}
	nf.end(0, why, true)
}

// end tears the flow down (idempotent). cancelled: the client went away (the entry says so unless it is
// already finished).
func (nf *NativeFlow) end(sent int64, why string, cancelled bool) {
	if !nf.ended.CompareAndSwap(false, true) {
		return
	}
	if cancelled {
		nf.cancel(errors.New(why))
	} else {
		nf.cancel(errors.New("flow ended"))
	}
	nf.mu.Lock()
	for _, p := range nf.in {
		p.closeRead()
		p.closeWrite(nil)
	}
	stage := nf.stage
	nf.stage = "done"
	active := nf.phaseActive
	respBody := nf.respBody
	nf.respBody = nil
	mode := nf.respMode
	closers := nf.cl
	nf.mu.Unlock()
	if nf.ent != nil && sent > 0 && (mode == "upstream" || mode == "lane") {
		nf.ent.AddBytes(int(sent))
	}
	if nf.ent != nil && why != "" && respBody != nil {
		nf.ent.Note(why)
	}
	finish := func() {
		for _, c := range closers {
			if c != nil {
				_ = c.Close()
			}
		}
		if respBody != nil {
			_ = respBody.Close() // finishBody / captureBody: finishes the entry; a lane reader frees its handle
		}
		if nf.f != nil && nf.f.release != nil {
			nf.f.release()
		}
		if nf.ent != nil {
			switch {
			case cancelled && (stage == "request" || stage == "upstream" || stage == "response"):
				nf.ent.Finish(0, why)
			default:
				nf.ent.Finish(-1, "")
			}
		}
		flowMu.Lock()
		delete(flowTable, nf.id)
		flowMu.Unlock()
		flowLive.Add(-1)
	}
	if active {
		// the phase goroutine still runs (it sees the cancellation); it calls finish when it returns
		nf.mu.Lock()
		nf.afterPhase = finish
		still := nf.phaseActive
		if !still {
			nf.afterPhase = nil
		}
		nf.mu.Unlock()
		if still {
			return
		}
	}
	finish()
}

// phaseDone marks the phase goroutine finished; a FlowEnd that came while it ran completes now.
func (nf *NativeFlow) phaseDone() {
	nf.mu.Lock()
	nf.phaseActive = false
	fn := nf.afterPhase
	nf.afterPhase = nil
	nf.cond.Broadcast()
	nf.mu.Unlock()
	if fn != nil {
		fn()
	}
}

// FlowStats is a JSON object for diagnostics and the memory log.
func FlowStats() string {
	b, _ := json.Marshal(map[string]int64{
		"live": flowLive.Load(), "total": flowTotal.Load(), "busy": flowBusy.Load(), "reaped": flowReaped.Load(),
		"needBody": flowNeeded.Load(), "laneOut": flowLaneOut.Load(), "upstreamOut": flowRawOut.Load(),
		"pipeBytes": flowPipeBytes.Load(), "pipePeak": flowPipePeak.Load(),
	})
	return string(b)
}

// FlowHeld is the pipe bytes one flow buffers now (-1 unknown flow).
func FlowHeld(id int64) int64 {
	flowMu.Lock()
	nf := flowTable[id]
	flowMu.Unlock()
	if nf == nil {
		return -1
	}
	return nf.held.Load()
}
