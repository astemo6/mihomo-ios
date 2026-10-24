package mitm

// Behaviour of the native flow API beyond parity: body modes, streaming pass-through with bounded buffering,
// cancellation, reaping, admission, the outbound request form and the Go-heap cost of a lane body.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"
)

func waitFlows(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for flowLive.Load() != 0 || flowPipeBytes.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("flows still live: %s", FlowStats())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func entryFor(e *Engine, u string) *Summary {
	for _, s := range e.Requests.List(0) {
		if s.URL == u {
			s := s
			return &s
		}
	}
	return nil
}

func noCapture() *bool { f := false; return &f }

// TestFlowBodyModes: with capture off, untouched bodies never pass through Go ("client" / "upstream"), a
// header-only response rule still leaves the body to the native side, and the bytes the native side reports
// at FlowEnd reach the request log.
func TestFlowBodyModes(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, CaptureBodies: noCapture(), Hostnames: []string{"api.test.com"},
		Rules: items(`http-response ^https://api\.test\.com/json\?h header-add X-Hdr yes`)}
	h := newHarness(t, cfg, nil)
	sim := newFlowSim(t, h.e)
	var modes []string
	sim.hook = func(id int64, stage string, d flowDecision) { modes = append(modes, d.Action+":"+d.Body) }

	r := sim.do("POST", "https://api.test.com/echo?c", http.Header{"User-Agent": {"T"}}, []byte("abc"))
	if !strings.Contains(string(r.body), `"body":"abc"`) {
		t.Fatalf("echo: %q", r.body)
	}
	r = sim.do("GET", "https://api.test.com/json?h", http.Header{"User-Agent": {"T"}}, nil)
	if r.header.Get("X-Hdr") != "yes" {
		t.Fatalf("header rule not applied: %v", r.header)
	}
	want := []string{"forward:client", "respond:upstream", "forward:none", "respond:upstream"}
	if strings.Join(modes, " ") != strings.Join(want, " ") {
		t.Fatalf("modes %v, want %v", modes, want)
	}
	waitFlows(t)
	s := entryFor(h.e, "https://api.test.com/json?h")
	if s == nil || !s.Done || s.Bytes != int64(len(r.body)) || s.Status != 200 {
		t.Fatalf("request log entry: %+v (body %d bytes)", s, len(r.body))
	}
}

// TestFlowStreamsOversizeBody: a request body past the rewrite cap streams through Go in pipe-sized pieces (the
// rule is skipped, the original reaches the upstream intact) and neither the flow nor all pipes ever buffer
// more than the pipe bounds; the Go path behaves the same.
func TestFlowStreamsOversizeBody(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, CaptureBodies: noCapture(), Hostnames: []string{"api.test.com"},
		Rules: items(`^https://api\.test\.com/echo\?big url request-body aaa request-body bbb`)}
	h := newHarness(t, cfg, nil)
	body := bytes.Repeat([]byte("aaaa"), (MaxBody+300<<10)/4)
	sim := newFlowSim(t, h.e)
	sim.chunk = 32 << 10
	// announced length past the cap: the rule is skipped before anything is read, the native side sends its
	// own body ("client")
	f := sim.do("POST", "https://api.test.com/echo?big", http.Header{"User-Agent": {"T"}}, body)
	if fr := f.decisions[0]; fr.Action != "forward" || fr.Body != "client" || fr.Length != int64(len(body)) || !bytes.Equal(f.upBody, body) {
		t.Fatalf("announced: decision %+v, upstream %d bytes", fr, len(f.upBody))
	}
	// chunked (length unknown): Go reads up to the cap, gives up on the rule and streams the original through
	var maxHeld int64
	flowPipePeak.Store(0)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			flowMu.Lock()
			for _, nf := range flowTable {
				if v := nf.held.Load(); v > maxHeld {
					maxHeld = v
				}
			}
			flowMu.Unlock()
			time.Sleep(200 * time.Microsecond)
		}
	}()
	sim.chunked = true
	f = sim.do("POST", "https://api.test.com/echo?big", http.Header{"User-Agent": {"T"}}, body)
	close(stop)
	<-done
	if f.err != "" {
		t.Fatal(f.err)
	}
	var fwd flowDecision
	for _, d := range f.decisions {
		if d.Action == "forward" {
			fwd = d
		}
	}
	if fwd.Body != "read" || fwd.Length != -1 || f.decisions[0].Action != "need-body" {
		t.Fatalf("chunked: decisions %+v", f.decisions)
	}
	if !bytes.Equal(f.upBody, body) {
		t.Fatalf("upstream got %d bytes, want the original %d", len(f.upBody), len(body))
	}
	// the Go path with an unannounced length gives the client the same answer
	req, _ := http.NewRequest("POST", "https://api.test.com/echo?big", struct{ io.Reader }{bytes.NewReader(body)})
	req.Header.Set("User-Agent", "T")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	gb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(gb, f.body) || resp.StatusCode != f.status {
		tail := func(b []byte) string { return string(b[max(0, len(b)-160):]) }
		t.Fatalf("Go path %d %d B …%q, flow %d %d B …%q", resp.StatusCode, len(gb), tail(gb), f.status, len(f.body), tail(f.body))
	}
	t.Logf("pipe peak %d B, flow held max %d B", flowPipePeak.Load(), maxHeld)
	if flowPipePeak.Load() > 2*flowPipeCap || maxHeld > 2*flowPipeCap {
		t.Fatalf("pipes buffered too much: peak %d, flow %d (cap %d)", flowPipePeak.Load(), maxHeld, flowPipeCap)
	}
	waitFlows(t)
}

// TestFlowLargeMapLocal: a Map Local file served from disk streams through the out-pipe (bounded), with the
// same answer as the Go path.
func TestFlowLargeMapLocal(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, CaptureBodies: noCapture(), Hostnames: []string{"api.test.com"}}
	h := newHarness(t, cfg, nil)
	big := bytes.Repeat([]byte("0123456789abcdef"), (memCacheMax+100<<10)/16)
	p := filepath.Join(h.home, "big.bin")
	if err := os.WriteFile(p, big, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg.Rules = items(`^https://api\.test\.com/big data-type=file data="` + p + `" header="Content-Type:application/octet-stream"`)
	h.e.Reload(cfg, Build(h.home, cfg))
	flowPipePeak.Store(0)
	sim := newFlowSim(t, h.e)
	f := sim.do("GET", "https://api.test.com/big", http.Header{"User-Agent": {"T"}}, nil)
	g := goDo(t, h.client, "GET", "https://api.test.com/big", http.Header{"User-Agent": {"T"}}, nil)
	if why := sameOutcome(g, f); why != "" {
		t.Fatal(why)
	}
	if len(f.body) != len(big) || f.decisions[0].Action != "local" || f.decisions[0].Length != int64(len(big)) {
		t.Fatalf("local %d bytes, decision %+v", len(f.body), f.decisions[0])
	}
	if flowPipePeak.Load() > 2*flowPipeCap {
		t.Fatalf("out-pipe buffered %d", flowPipePeak.Load())
	}
	waitFlows(t)
}

// startManual runs a flow up to the response head by hand (for tests that interrupt it).
func startManual(t *testing.T, e *Engine, rawurl string) (int64, *http.Response) {
	t.Helper()
	u, _ := url.Parse(rawurl)
	hj, _ := json.Marshal(FlowHead{Method: "GET", Target: u.RequestURI(), Host: u.Host, ConnHost: u.Hostname(), ConnPort: 443, TLS: true, Headers: [][2]string{{"User-Agent", "T"}}})
	d := parseDecision(t, e.FlowBegin(string(hj)))
	if d.Action != "forward" {
		t.Fatalf("begin: %+v", d)
	}
	req, _ := http.NewRequest(d.Method, d.URL, nil)
	req.Header = flowPairsHeader(d.Headers)
	resp, err := e.upstream().RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return d.ID, resp
}

func respHeadJSON(resp *http.Response) string {
	b, _ := json.Marshal(FlowRespHead{Status: resp.StatusCode, Length: resp.ContentLength, Headers: flowHeaderPairs(resp.Header)})
	return string(b)
}

// TestFlowCancelMidBody: the client goes away while Go streams a response body into the lane: the load
// stops, the lane handle and the body budget are freed, the entry says why, and the flow is gone.
func TestFlowCancelMidBody(t *testing.T) {
	l := useFakeLane(t)
	h := newLaneHarness(t, laneCfg(""), map[string]string{"vip.js": vipJS})
	id, resp := startManual(t, h.e, "https://api.test.com/body?enc=gzip&n=2000000")
	d := parseDecision(t, FlowResponse(id, respHeadJSON(resp)))
	if d.Action != "need-body" || d.Which != flowResp {
		t.Fatalf("response: %+v", d)
	}
	buf := make([]byte, 16<<10)
	n, _ := io.ReadFull(resp.Body, buf)
	if r := FlowWrite(id, flowResp, buf[:n]); r != "" {
		t.Fatalf("write: %q", r)
	}
	if l.opened.Load() != 1 {
		t.Fatalf("lane opened %d", l.opened.Load())
	}
	FlowCancel(id, "客户端断开")
	if got := parseDecision(t, FlowAwait(id)); got.Action != "gone" {
		t.Fatalf("await after cancel: %+v", got)
	}
	if r := FlowWrite(id, flowResp, buf[:n]); r != "gone" {
		t.Fatalf("write after cancel: %q", r)
	}
	waitFlows(t)
	waitLive(t, l)
	if bodyBudget.inUse() != 0 {
		t.Fatalf("body budget still holds %d", bodyBudget.inUse())
	}
	s := entryFor(h.e, "https://api.test.com/body?enc=gzip&n=2000000")
	if s == nil || !s.Done {
		t.Fatalf("entry %+v", s)
	}
}

// TestFlowEndFreesLaneHandle: a lane body handed to the native side is freed by FlowEnd, not by Swift.
func TestFlowEndFreesLaneHandle(t *testing.T) {
	l := useFakeLane(t)
	h := newLaneHarness(t, laneCfg(""), map[string]string{"vip.js": vipJS})
	sim := newFlowSim(t, h.e)
	sim.lane = l
	sim.noEnd = true
	r := sim.do("GET", "https://api.test.com/body?enc=br&n=400000", http.Header{"User-Agent": {"T"}}, nil)
	last := r.decisions[len(r.decisions)-1]
	if last.Body != "lane" || !bytes.HasPrefix(r.body, []byte(`{"vip":true,`)) {
		t.Fatalf("decision %+v body %q", last, clip(string(r.body), 40))
	}
	if l.live() == 0 {
		t.Fatal("handle freed before FlowEnd")
	}
	FlowEnd(last.ID, int64(len(r.body)), "")
	waitLive(t, l)
	waitFlows(t)
	if s := entryFor(h.e, "https://api.test.com/body?enc=br&n=400000"); s == nil || s.Bytes != int64(len(r.body)) {
		t.Fatalf("entry %+v", s)
	}
}

// TestFlowReaperAndBusy: a flow whose session vanished is reaped (handles freed, entry finished); past
// flowMaxLive new flows get "busy".
func TestFlowReaperAndBusy(t *testing.T) {
	l := useFakeLane(t)
	h := newLaneHarness(t, laneCfg(""), map[string]string{"vip.js": vipJS})
	sim := newFlowSim(t, h.e)
	sim.lane = l
	sim.noEnd = true
	r := sim.do("GET", "https://api.test.com/body?enc=gzip&n=300000", http.Header{"User-Agent": {"T"}}, nil)
	if r.err != "" {
		t.Fatal(r.err)
	}
	old := flowMaxLive
	flowMaxLive = 1
	hj, _ := json.Marshal(FlowHead{Method: "GET", Target: "/x", Host: "api.test.com", ConnHost: "api.test.com", ConnPort: 443, TLS: true})
	if d := parseDecision(t, h.e.FlowBegin(string(hj))); d.Action != "busy" {
		t.Fatalf("over the cap: %+v", d)
	}
	flowMaxLive = old
	if n := reapFlows(time.Now()); n != 0 {
		t.Fatalf("reaped a fresh flow")
	}
	if n := reapFlows(time.Now().Add(flowIdle + time.Second)); n != 1 {
		t.Fatalf("reaped %d", n)
	}
	waitLive(t, l)
	waitFlows(t)
}

// TestFlowUpstreamFailedAndDrop: an unreachable upstream is a 502 entry; reject-drop and an aborting request
// script drop the connection.
func TestFlowUpstreamFailedAndDrop(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(`^https://api\.test\.com/drop url reject-drop`)}
	h := newHarness(t, cfg, nil)
	sim := newFlowSim(t, h.e)
	sim.upErr = "dial tcp: refused"
	sim.do("GET", "https://api.test.com/json?down", http.Header{"User-Agent": {"T"}}, nil)
	if s := entryFor(h.e, "https://api.test.com/json?down"); s == nil || s.Status != 502 || !s.Done {
		t.Fatalf("entry %+v", s)
	}
	sim.upErr = ""
	if r := sim.do("GET", "https://api.test.com/drop", nil, nil); !r.dropped {
		t.Fatalf("reject-drop: %+v", r)
	}
	waitFlows(t)
}

// TestFlowOutboundForm: the outbound request is what httputil.ReverseProxy would send: hop-by-hop headers
// (and those Connection names) removed, Te: trailers and an Upgrade kept, client X-Forwarded-* dropped,
// unparsable query parameters cleaned, no Go User-Agent added.
func TestFlowOutboundForm(t *testing.T) {
	r, _ := http.NewRequest("GET", "https://api.test.com/ws?a=1;b=2", nil)
	r.Header = http.Header{
		"Connection": {"Upgrade, X-Hop"}, "Upgrade": {"websocket"}, "X-Hop": {"1"}, "Keep-Alive": {"5"},
		"Te": {"trailers"}, "X-Forwarded-For": {"1.2.3.4"}, "Forwarded": {"for=x"}, "Proxy-Authorization": {"x"}, "X-Keep": {"k"},
	}
	r.Host = "api.test.com"
	target, _ := url.Parse("https://api.test.com/ws?a=1;b=2")
	out := flowOutbound(r, target)
	got := fmt.Sprint(out.Header)
	want := fmt.Sprint(http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Te": {"trailers"}, "X-Keep": {"k"}})
	if got != want {
		t.Fatalf("headers %s, want %s", got, want)
	}
	if out.URL.RawQuery != "" || out.Host != "api.test.com" || out.URL.Scheme != "https" {
		t.Fatalf("url %s host %s", out.URL, out.Host)
	}
}

// TestFlowLaneGoHeap: a 3 MB script body through the flow API and the lane stays off the Go heap (only the
// pipes' chunks and the lane's 32 KB transfer garbage), like stage 1's TestLaneKeepsGoHeapFlat.
func TestFlowLaneGoHeap(t *testing.T) {
	if raceEnabled {
		t.Skip("heap figures under -race are meaningless")
	}
	l := useFakeLane(t)
	h := newLaneHarness(t, laneCfg(""), map[string]string{"vip.js": `$done({})`})
	sim := newFlowSim(t, h.e)
	sim.lane = l
	sim.chunk = 32 << 10
	u := fmt.Sprintf("https://api.test.com/body?enc=gzip&n=%d", 3<<20)
	sim.do("GET", u, http.Header{"User-Agent": {"T"}}, nil) // warm
	sim.discard = true
	defer debug.SetGCPercent(debug.SetGCPercent(5))
	// the Go path for the same body, as the reference (it holds the encoded and decoded body)
	goGet := func() {
		resp, err := h.client.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	SetNativeBodies(nil)
	goGet()
	gb, gp := peakHeapDuring(goGet)
	SetNativeBodies(l)
	var res simResult
	base, peak := peakHeapDuring(func() { res = sim.do("GET", u, http.Header{"User-Agent": {"T"}}, nil) })
	t.Logf("Go heap peak above base, Go path without lane: %.2f MB", float64(gp-gb)/(1<<20))
	if res.err != "" {
		t.Fatal(res.err)
	}
	t.Logf("Go heap peak above base through the flow API: %.2f MB (body %d bytes, mode %s)", float64(peak-base)/(1<<20), res.n, res.decisions[len(res.decisions)-1].Body)
	if res.n < 3<<20-64 || res.decisions[len(res.decisions)-1].Body != "lane" {
		t.Fatalf("body %d bytes, decisions %+v", res.n, res.decisions)
	}
	if peak-base > 5<<19 || (peak-base)*2 > gp-gb {
		t.Fatalf("flow + lane held %d KB of Go heap", (peak-base)>>10)
	}
	waitLive(t, l)
	waitFlows(t)
}

// TestFlowConcurrent: many sessions at once over the compat rules (scripts, body rewrites, local answers,
// request bodies) give the same answers as one at a time, and nothing is left behind.
func TestFlowConcurrent(t *testing.T) {
	h := compatHarness(t)
	want := map[string]simResult{}
	sim := newFlowSim(t, h.e)
	for _, c := range compatParityCases {
		m := c.method
		if m == "" {
			m = "GET"
		}
		want[c.name] = sim.do(m, c.url, c.header(), []byte(c.body))
	}
	var wg sync.WaitGroup
	errs := make(chan string, 1000)
	for g := 0; g < 24; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			s := newFlowSim(t, h.e)
			s.chunk = 1 + g*977
			for i := 0; i < len(compatParityCases); i++ {
				c := compatParityCases[(i+g*7)%len(compatParityCases)]
				m := c.method
				if m == "" {
					m = "GET"
				}
				got := s.do(m, c.url, c.header(), []byte(c.body))
				if why := sameOutcome(want[c.name], got); why != "" {
					errs <- c.name + ": " + why
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	n := 0
	for e := range errs {
		if n++; n <= 10 {
			t.Error(e)
		}
	}
	waitFlows(t)
	if bodyBudget.inUse() != 0 {
		t.Fatalf("body budget still holds %d", bodyBudget.inUse())
	}
	t.Logf("stats %s", FlowStats())
}
