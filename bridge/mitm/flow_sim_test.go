package mitm

// flowSim plays the stage-2 native HTTP/1.1 session (Swift) against the flow API, single-threaded and in the
// order work/native-mitm-design.md §12 prescribes, so the tests exercise exactly the call sequence the Swift
// side will make. The upstream is the engine's own upstream transport (what the relay dials through).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

type simResult struct {
	status    int
	header    http.Header
	body      []byte
	dropped   bool
	decisions []flowDecision
	upstream  *http.Request // what was sent upstream (nil: answered locally)
	upBody    []byte
	n         int64 // body bytes delivered (body itself kept unless discard)
	err       string
}

type flowSim struct {
	t       testing.TB
	e       *Engine
	chunk   int                                          // client / upstream push size
	lane    NativeBodies                                 // to read lane bodies (nil: laneAny())
	rt      http.RoundTripper                            // upstream (nil: e.upstream())
	onUp    func(*http.Request)                          // hook before the upstream round trip
	hook    func(id int64, stage string, d flowDecision) // after each decision
	noEnd   bool                                         // leave the flow open (leak / reaper tests)
	upErr   string                                       // fail the upstream instead of sending
	cut     int                                          // close the client after this many response bytes (0: never)
	discard bool                                         // count lane body bytes without keeping them (heap tests)
	chunked bool                                         // send the request body without a length (Transfer-Encoding: chunked)
}

func newFlowSim(t testing.TB, e *Engine) *flowSim { return &flowSim{t: t, e: e, chunk: 7 << 10} }

func parseDecision(t testing.TB, s string) flowDecision {
	t.Helper()
	var d flowDecision
	if err := json.Unmarshal([]byte(s), &d); err != nil {
		t.Fatalf("decision %q: %v", s, err)
	}
	return d
}

// pusher feeds a body to FlowWrite in chunks, remembering a chunk Go did not take ("full").
type pusher struct {
	src     io.Reader
	pending []byte
	done    bool // FlowClose sent
	stopped bool
	chunk   int
	buf     []byte // reused (pending points into it until Go takes it)
}

// push sends chunks until Go says full / stop or the body ends. Returns false when a chunk is pending.
func (p *pusher) push(e *Engine, id int64, which int) {
	for !p.done && !p.stopped {
		if p.pending == nil {
			if p.buf == nil {
				p.buf = make([]byte, p.chunk)
			}
			n, err := p.src.Read(p.buf)
			if n > 0 {
				p.pending = p.buf[:n]
			} else if err != nil {
				msg := ""
				if err != io.EOF {
					msg = err.Error()
				}
				FlowClose(id, which, msg)
				p.done = true
				return
			} else {
				continue
			}
		}
		switch r := FlowWrite(id, which, p.pending); r {
		case "":
			p.pending = nil
		case "full":
			return
		case "stop", "gone":
			p.stopped = true
			p.pending = nil
			return
		default:
			panic("FlowWrite: " + r)
		}
	}
}

// rest is what the native side still has of the body (sent unchanged in client / upstream mode).
func (p *pusher) rest() []byte {
	b, _ := io.ReadAll(p.src)
	return append(append([]byte(nil), p.pending...), b...)
}

// pull reads a Go-produced body, pushing more of src whenever Go says "more".
func (s *flowSim) pull(id int64, which int, src *pusher) ([]byte, string) {
	var out []byte
	for i := 0; ; i++ {
		b := FlowRead(id, which, 32<<10)
		out = append(out, b...)
		if len(b) > 0 {
			if s.cut > 0 && which == flowResp && len(out) >= s.cut {
				return out, "cut"
			}
			continue
		}
		st := FlowReadState(id, which)
		switch {
		case st == "eof":
			return out, ""
		case st == "more":
			if src == nil || src.done || src.stopped {
				if src != nil && src.done {
					continue // closed: the next read sees EOF
				}
				return out, "more without a source"
			}
			src.push(s.e, id, which) // the body being read is fed by the pipe of the same index
		case st == "":
			continue
		default:
			return out, st
		}
		if i > 1<<20 {
			return out, "no progress"
		}
	}
}

func (s *flowSim) do(method, rawurl string, hdr http.Header, body []byte) simResult {
	t := s.t
	t.Helper()
	var res simResult
	u, err := url.Parse(rawurl)
	if err != nil {
		t.Fatal(err)
	}
	port := 443
	if u.Scheme == "http" {
		port = 80
	}
	if p := u.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}
	head := FlowHead{Method: method, Target: u.RequestURI(), Host: u.Host, Length: int64(len(body)), ConnHost: u.Hostname(), ConnPort: port, TLS: u.Scheme == "https"}
	if body == nil {
		head.Length = 0
	}
	if s.chunked && body != nil {
		head.Length = -1
		head.Headers = append(head.Headers, [2]string{"Transfer-Encoding", "chunked"})
	}
	keys := make([]string, 0, len(hdr))
	for k := range hdr {
		keys = append(keys, k)
	}
	for _, k := range keys {
		for _, v := range hdr[k] {
			head.Headers = append(head.Headers, [2]string{k, v})
		}
	}
	hj, _ := json.Marshal(head)
	cli := &pusher{src: bytes.NewReader(body), chunk: s.chunk}
	d := parseDecision(t, s.e.FlowBegin(string(hj)))
	id := d.ID
	defer func() {
		if !s.noEnd && id != 0 {
			sent := int64(0)
			if len(res.decisions) > 0 {
				last := res.decisions[len(res.decisions)-1]
				if last.Body == "upstream" || last.Body == "lane" {
					sent = res.n
				}
			}
			errText := ""
			if s.cut > 0 {
				FlowCancel(id, "客户端断开")
			} else {
				FlowEnd(id, sent, errText)
			}
		}
	}()
	record := func(stage string) {
		res.decisions = append(res.decisions, d)
		if s.hook != nil {
			s.hook(id, stage, d)
		}
	}
	record("begin")
	for d.Action == "need-body" {
		if d.Which != flowReq {
			t.Fatalf("request phase asked for body %d", d.Which)
		}
		cli.push(s.e, id, flowReq)
		d = parseDecision(t, FlowAwait(id))
		record("await")
	}
	switch d.Action {
	case "drop":
		res.dropped = true
		return res
	case "busy", "error", "gone":
		res.err = d.Action + ": " + d.Note
		return res
	case "local":
		res.status = d.Status
		res.header = flowPairsHeader(d.Headers)
		if d.Body == "read" {
			b, why := s.pull(id, flowResp, nil)
			res.body = b
			if why != "" {
				res.err = "local body: " + why
			}
		}
		return res
	case "forward":
	default:
		t.Fatalf("unexpected decision %+v", d)
	}
	// the outbound request
	var upBody []byte
	switch d.Body {
	case "client":
		upBody = cli.rest()
	case "read":
		b, why := s.pull(id, flowReq, cli)
		if why != "" {
			res.err = "request body: " + why
			return res
		}
		upBody = b
	}
	ou, err := url.Parse(d.URL)
	if err != nil {
		t.Fatalf("forward url %q: %v", d.URL, err)
	}
	oreq, _ := http.NewRequest(d.Method, d.URL, nil)
	oreq.URL = ou
	oreq.Host = d.Host
	oreq.Header = flowPairsHeader(d.Headers)
	if _, ok := oreq.Header["User-Agent"]; !ok {
		oreq.Header["User-Agent"] = nil // the native client adds no User-Agent of its own
	}
	if len(upBody) > 0 || d.Body == "read" || d.Body == "client" {
		oreq.Body = io.NopCloser(bytes.NewReader(upBody))
		oreq.ContentLength = int64(len(upBody))
		if d.Length < 0 {
			oreq.ContentLength = -1 // streamed without a length, as the decision says
		}
	}
	res.upstream, res.upBody = oreq, upBody
	if s.onUp != nil {
		s.onUp(oreq)
	}
	if s.upErr != "" {
		FlowUpstreamFailed(id, s.upErr)
		res.status = 502
		return res
	}
	rt := s.rt
	if rt == nil {
		rt = s.e.upstream()
	}
	uresp, err := rt.RoundTrip(oreq.WithContext(t.Context()))
	if err != nil {
		FlowUpstreamFailed(id, err.Error())
		res.status = 502
		return res
	}
	defer uresp.Body.Close()
	rh := FlowRespHead{Status: uresp.StatusCode, Length: uresp.ContentLength, Headers: headerPairsTest(uresp.Header)}
	rj, _ := json.Marshal(rh)
	up := &pusher{src: uresp.Body, chunk: s.chunk}
	d = parseDecision(t, FlowResponse(id, string(rj)))
	record("response")
	for d.Action == "need-body" {
		if d.Which != flowResp {
			t.Fatalf("response phase asked for body %d", d.Which)
		}
		up.push(s.e, id, flowResp)
		d = parseDecision(t, FlowAwait(id))
		record("await")
	}
	switch d.Action {
	case "error":
		res.status = d.Status
		return res
	case "upgrade":
		res.status = d.Status
		res.header = flowPairsHeader(d.Headers)
		return res
	case "respond":
	default:
		t.Fatalf("unexpected response decision %+v", d)
	}
	res.status = d.Status
	res.header = flowPairsHeader(d.Headers)
	switch d.Body {
	case "upstream":
		res.body = up.rest()
	case "read":
		b, why := s.pull(id, flowResp, up)
		res.body = b
		if why != "" && why != "cut" {
			res.err = "response body: " + why
		}
	case "lane":
		n := s.lane
		if n == nil {
			n = laneAny()
		}
		size := n.Len(d.Lane.Handle, d.Lane.Raw)
		if size != d.Length {
			res.err = fmt.Sprintf("lane length %d, decision says %d", size, d.Length)
		}
		for off := int64(0); off < size; {
			b := n.Read(d.Lane.Handle, d.Lane.Raw, off, 32<<10)
			if len(b) == 0 {
				res.err = "lane read short"
				break
			}
			if !s.discard {
				res.body = append(res.body, b...)
			}
			res.n += int64(len(b))
			off += int64(len(b))
		}
	}
	if d.Body != "lane" {
		res.n = int64(len(res.body))
	}
	if d.Length >= 0 && d.Body != "none" && res.n != d.Length && s.cut == 0 {
		res.err = fmt.Sprintf("body %d bytes, decision length %d", len(res.body), d.Length)
	}
	return res
}

func flowPairsHeader(p [][2]string) http.Header {
	h := http.Header{}
	for _, kv := range p {
		h.Add(kv[0], kv[1])
	}
	return h
}

func headerPairsTest(h http.Header) [][2]string { return flowHeaderPairs(h) }

// goDo sends the same request through the Go path (the harness's proxy client).
func goDo(t testing.TB, c *http.Client, method, rawurl string, hdr http.Header, body []byte) simResult {
	t.Helper()
	var rb io.Reader
	if body != nil {
		rb = bytes.NewReader(body)
	}
	req, _ := http.NewRequest(method, rawurl, rb)
	for k, vs := range hdr {
		req.Header[k] = vs
	}
	resp, err := c.Do(req)
	if err != nil {
		return simResult{dropped: true, err: err.Error()}
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	r := simResult{status: resp.StatusCode, header: resp.Header, body: b}
	if err != nil {
		r.err = err.Error()
	}
	return r
}

// normHeader drops what legitimately differs between the two transports (framing, Date, h2 pseudo headers).
func normHeader(h http.Header) string {
	var keys []string
	for k := range h {
		switch k {
		case "Content-Length", "Transfer-Encoding", "Date", "Connection", "Keep-Alive":
			continue
		}
		keys = append(keys, k)
	}
	sortStrings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + ": " + strings.Join(h[k], ", ") + "\n")
	}
	return b.String()
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// sameOutcome compares a Go-path result with a flow result; "" when they match.
func sameOutcome(g, f simResult) string {
	if g.dropped || f.dropped {
		if g.dropped != f.dropped {
			return fmt.Sprintf("dropped: go %v (%s) flow %v (%s)", g.dropped, g.err, f.dropped, f.err)
		}
		return ""
	}
	if f.err != "" {
		return "flow error: " + f.err
	}
	if g.status != f.status {
		return fmt.Sprintf("status go %d flow %d", g.status, f.status)
	}
	if !bytes.Equal(g.body, f.body) {
		return fmt.Sprintf("body differs:\n go   %q\n flow %q", clip(string(g.body), 300), clip(string(f.body), 300))
	}
	if gh, fh := normHeader(g.header), normHeader(f.header); gh != fh {
		return fmt.Sprintf("headers differ:\n go:\n%s flow:\n%s", gh, fh)
	}
	return ""
}
