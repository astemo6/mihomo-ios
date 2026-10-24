package mitm

// Request and response phases of the native flow API (flow.go).
//
// flowRequestPhase runs the same requestPhase as serveHTTP (handler.go: one implementation of the request
// rule loop), writing local answers to a flowWriter instead of the connection and stopping where serveHTTP
// hands the request to httputil.ReverseProxy; flowOutbound reproduces what ReverseProxy would send.
// flow_parity_test.go drives both paths with the same rules and compares what the client and the upstream see.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/http/httpguts"
)

type urlT = url.URL

func parseURI(t string) (*url.URL, error) { return url.ParseRequestURI(t) }

// flowWriter is the http.ResponseWriter local answers are written to. Like net/http's server it snapshots the
// header at WriteHeader and commits it with the first body bytes (sniffing a missing Content-Type from them)
// or when the handler returns (an empty body: Content-Length 0). Committing publishes the "local" decision;
// the body goes through an out-pipe the native side pulls with FlowRead(id, 1).
type flowWriter struct {
	nf        *NativeFlow
	h         http.Header
	snap      http.Header
	status    int
	committed bool
	pipe      *flowPipe
}

func (w *flowWriter) Header() http.Header { return w.h }

func (w *flowWriter) WriteHeader(code int) {
	if w.status != 0 {
		return
	}
	w.status = code
	w.snap = w.h.Clone()
}

// commit publishes the local decision; first is the first body chunk (nil: the handler wrote no body).
func (w *flowWriter) commit(first []byte) {
	if w.committed {
		return
	}
	w.committed = true
	nf := w.nf
	code := w.status
	h := w.snap
	bodyOK := code >= 200 && code != http.StatusNoContent && code != http.StatusNotModified
	if _, haveType := h["Content-Type"]; !haveType && h.Get("Content-Encoding") == "" && bodyOK && len(first) > 0 {
		h.Set("Content-Type", http.DetectContentType(first))
	}
	length := int64(-1)
	if cl := h.Get("Content-Length"); cl != "" {
		if n, err := strconv.ParseInt(cl, 10, 64); err == nil && n >= 0 {
			length = n
		}
	} else if first == nil {
		length = 0
	}
	body := "read"
	if length == 0 || !bodyOK {
		body, length = "none", max(length, 0)
	}
	if bodyOK {
		h.Del("Content-Length")
	}
	h.Del("Transfer-Encoding")
	nf.mu.Lock()
	nf.in[flowReq].closeRead() // a local answer: the rest of the client's request body is not wanted
	nf.out[flowResp] = w.pipe
	nf.stage = "done"
	nf.publishLocked(flowDecision{Action: "local", Status: code, Headers: flowHeaderPairs(h), Body: body, Length: length})
	nf.mu.Unlock()
}

func (w *flowWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if len(b) == 0 {
		return 0, nil
	}
	w.commit(b)
	return w.pipe.Write(b)
}

// runRequest is the request phase goroutine.
func (nf *NativeFlow) runRequest(r *http.Request) {
	w := &flowWriter{nf: nf, h: http.Header{}, pipe: newFlowPipe(nf, flowResp, true)}
	defer func() {
		p := recover()
		if p == nil && w.status != 0 {
			w.commit(nil)
		}
		nf.mu.Lock()
		w.pipe.closeWrite(nil)
		decided := nf.final
		nf.mu.Unlock()
		if p != nil {
			if p == http.ErrAbortHandler {
				if !decided {
					nf.publish(flowDecision{Action: "drop"})
				}
			} else {
				nf.e.logf("error", fmt.Sprintf("[MitM] 处理 %s 时出错：%v", clip(r.URL.String(), 100), p))
				if nf.ent != nil {
					nf.ent.Finish(502, "内部错误")
				}
				if !decided {
					nf.publish(flowDecision{Action: "local", Status: http.StatusBadGateway, Headers: [][2]string{{"Content-Type", "text/plain; charset=utf-8"}}, Body: "none", Length: 0, Note: "mitm error"})
				}
			}
		} else if !decided {
			nf.publish(flowDecision{Action: "error", Note: "request phase ended without a decision"})
		}
		nf.phaseDone()
	}()
	nf.e.flowRequestPhase(nf, w, r)
}

// flowRequestPhase is the request phase of a native flow: the Go path's own requestPhase (handler.go) with
// local answers going to the flowWriter, ending in a "forward" decision with the outbound request as
// ReverseProxy would send it.
func (e *Engine) flowRequestPhase(nf *NativeFlow, w *flowWriter, r *http.Request) {
	p := e.startRequest(r)
	ent := p.ent
	nf.ent = ent
	defer func() {
		if v := recover(); v != nil {
			if v == http.ErrAbortHandler {
				ent.Finish(0, "已断开")
			}
			panic(v) // runRequest answers drop / 502
		}
	}()
	defer p.releaseBody()
	f := e.requestPhase(p, w, r)
	if f == nil {
		return // answered locally (w committed the "local" decision)
	}
	// --- where serveHTTP builds the ReverseProxy: the outbound request as ReverseProxy would send it ---
	target, _ := url.Parse(f.url)
	out := flowOutbound(r, target)
	p.releaseBody()
	nf.forward(out, f)
}

// flowOutbound is the request httputil.ReverseProxy (with serveHTTP's Rewrite) sends upstream for r.
func flowOutbound(r *http.Request, target *url.URL) *http.Request {
	out := r.Clone(r.Context())
	out.Body = r.Body
	if r.ContentLength == 0 {
		out.Body = nil
	}
	out.Close = false
	upType := ""
	if httpguts.HeaderValuesContainsToken(out.Header["Connection"], "Upgrade") {
		upType = out.Header.Get("Upgrade")
	}
	flowRemoveHopByHop(out.Header)
	if httpguts.HeaderValuesContainsToken(r.Header["Te"], "trailers") {
		out.Header.Set("Te", "trailers")
	}
	if upType != "" {
		out.Header.Set("Connection", "Upgrade")
		out.Header.Set("Upgrade", upType)
	}
	out.Header.Del("Forwarded")
	out.Header.Del("X-Forwarded-For")
	out.Header.Del("X-Forwarded-Host")
	out.Header.Del("X-Forwarded-Proto")
	out.URL.RawQuery = flowCleanQuery(out.URL.RawQuery)
	if target != nil {
		out.URL.Scheme = target.Scheme
		out.URL.Host = target.Host
	}
	out.Host = r.Host
	return out
}

// flowHopHeaders: httputil's hop-by-hop list.
var flowHopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func flowRemoveHopByHop(h http.Header) {
	for _, f := range h["Connection"] {
		for _, sf := range strings.Split(f, ",") {
			if sf = textproto.TrimString(sf); sf != "" {
				h.Del(sf)
			}
		}
	}
	for _, f := range flowHopHeaders {
		h.Del(f)
	}
}

// flowCleanQuery is httputil's cleanQueryParams (unparsable query parameters are dropped).
func flowCleanQuery(s string) string {
	reencode := func(s string) string {
		v, _ := url.ParseQuery(s)
		return v.Encode()
	}
	ishex := func(c byte) bool {
		return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
	}
	for i := 0; i < len(s); {
		switch s[i] {
		case ';':
			return reencode(s)
		case '%':
			if i+2 >= len(s) || !ishex(s[i+1]) || !ishex(s[i+2]) {
				return reencode(s)
			}
			i += 3
		default:
			i++
		}
	}
	return s
}

// forward publishes the "forward" decision for the outbound request.
func (nf *NativeFlow) forward(out *http.Request, f *flow) {
	h := out.Header.Clone()
	h.Del("Content-Length") // framing is the native client's: Length says it
	nf.mu.Lock()
	defer nf.mu.Unlock()
	in := nf.in[flowReq]
	mode := "read"
	length := out.ContentLength
	switch {
	case out.Body == nil || out.Body == http.NoBody || length == 0:
		mode, length = "none", 0
		if out.Body != nil && !in.touched {
			in.closeRead()
		}
	case out.Body == io.Reader(in) && !in.touched:
		mode = "client"
	}
	if mode == "read" {
		nf.out[flowReq] = out.Body
		nf.cl[flowReq] = out.Body
	}
	nf.req = out
	nf.f = f
	nf.stage = "upstream"
	nf.publishLocked(flowDecision{Action: "forward", Method: out.Method, URL: out.URL.String(), Host: out.Host, Headers: flowHeaderPairs(h), Body: mode, Length: length})
}

// runResponse is the response phase goroutine: the Go path's modifyResponse on the upstream's head.
func (nf *NativeFlow) runResponse(head FlowRespHead) {
	e := nf.e
	resp := &http.Response{
		StatusCode: head.Status,
		Status:     fmt.Sprintf("%d %s", head.Status, http.StatusText(head.Status)),
		Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header:        headerFromPairs(head.Headers),
		ContentLength: head.Length,
		Request:       nf.req,
	}
	if te := resp.Header.Values("Transfer-Encoding"); len(te) > 0 {
		resp.Header.Del("Transfer-Encoding")
		resp.ContentLength = -1
	} else if cl := resp.Header.Get("Content-Length"); cl != "" {
		if n, err := strconv.ParseInt(strings.TrimSpace(cl), 10, 64); err == nil && n >= 0 {
			resp.ContentLength = n
		}
	}
	noBody := nf.req.Method == http.MethodHead || head.Status == http.StatusNoContent || head.Status == http.StatusNotModified || (head.Status >= 100 && head.Status < 200)
	in := nf.in[flowResp]
	if noBody || resp.ContentLength == 0 {
		resp.Body = http.NoBody
		nf.mu.Lock()
		in.closeWrite(nil)
		nf.mu.Unlock()
	} else {
		resp.Body = in
	}
	var err error
	func() {
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("内部错误：%v", p)
				e.logf("error", fmt.Sprintf("[MitM] 处理 %s 的响应时出错：%v", clip(nf.f.url, 100), p))
			}
		}()
		if resp.StatusCode != http.StatusSwitchingProtocols {
			flowRemoveHopByHop(resp.Header)
		}
		err = e.modifyResponse(nf.f, resp)
	}()
	defer nf.phaseDone()
	if err != nil {
		// ReverseProxy: the body is closed and its ErrorHandler answers 502
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		nf.mu.Lock()
		in.closeRead()
		nf.mu.Unlock()
		if errors.Is(err, context.Canceled) {
			nf.ent.Finish(0, "客户端取消")
		} else {
			nf.ent.Finish(502, "上游错误："+shortErr(err))
		}
		nf.publish(flowDecision{Action: "error", Status: http.StatusBadGateway, Body: "none", Length: 0, Note: err.Error()})
		return
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		nf.mu.Lock()
		nf.respMode = "upstream"
		nf.publishLocked(flowDecision{Action: "upgrade", Status: resp.StatusCode, Headers: flowHeaderPairs(resp.Header), Body: "upstream", Length: -1})
		nf.mu.Unlock()
		return
	}
	h := resp.Header.Clone()
	length := int64(-1)
	if cl := h.Get("Content-Length"); cl != "" {
		if n, err := strconv.ParseInt(strings.TrimSpace(cl), 10, 64); err == nil && n >= 0 {
			length = n
		}
	} else if resp.ContentLength >= 0 {
		length = resp.ContentLength
	}
	d := flowDecision{Action: "respond", Status: resp.StatusCode, Length: length}
	mode := "read"
	var lane *FlowLane
	body := resp.Body
	inner := io.Reader(body)
	if fb, ok := body.(*finishBody); ok {
		inner = fb.rc
	}
	switch {
	case noBody:
		mode = "none"
	case inner == io.Reader(in) && !in.touched:
		mode = "upstream"
		flowRawOut.Add(1)
	default:
		if lr, ok := inner.(*laneReader); ok && lr.off == 0 {
			mode = "lane"
			lane = &FlowLane{Handle: lr.h, Raw: lr.raw}
			d.Length = lr.size
			flowLaneOut.Add(1)
		}
	}
	if !noBody {
		h.Del("Content-Length")
	}
	h.Del("Transfer-Encoding")
	d.Headers, d.Body, d.Lane = flowHeaderPairs(h), mode, lane
	if mode == "none" {
		// HEAD / 204 / 304: Length is the entity's (Content-Length is kept in the headers too); send no body
		d.Length = length
	}
	if ct, _, _ := mime.ParseMediaType(h.Get("Content-Type")); ct == "text/event-stream" {
		d.Note = "flush" // ReverseProxy flushes server-sent events immediately
	}
	nf.mu.Lock()
	nf.respBody = body
	nf.respMode = mode
	if mode == "read" {
		nf.out[flowResp] = body
	} else if mode != "upstream" {
		in.closeRead()
	}
	if lane != nil {
		nf.laneH = lane.Handle
	}
	nf.publishLocked(d)
	nf.mu.Unlock()
}
