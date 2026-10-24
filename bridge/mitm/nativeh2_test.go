package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"runtime/pprof"
	"sync"
	"testing"
	"time"
)

// Native MitM stage 3 lane s3-h2 (Go side): the ALPN offer the native front sees, and what one HTTP/2 MitM
// connection / in-flight stream costs Go on the Go path versus what stays in Go when Swift serves h2.

func TestNativeOfferH2(t *testing.T) {
	cases := []struct {
		alpn []string
		h2   bool
		want []string
		ok   bool
	}{
		{nil, false, nil, true},
		{nil, true, nil, true},
		{[]string{"h2", "http/1.1"}, false, []string{"http/1.1"}, true},
		{[]string{"h2", "http/1.1"}, true, []string{"h2", "http/1.1"}, true},
		{[]string{"h2"}, false, nil, false},
		{[]string{"h2"}, true, []string{"h2"}, true},
		{[]string{"spdy/3", "h2"}, true, []string{"h2"}, true},
		{[]string{"spdy/3"}, true, nil, false},
		{[]string{"http/1.1", "h2"}, true, []string{"http/1.1", "h2"}, true},
	}
	for _, c := range cases {
		got, ok := nativeOffer(c.alpn, c.h2)
		if ok != c.ok || !reflect.DeepEqual(got, c.want) {
			t.Errorf("nativeOffer(%v, %v) = %v %v, want %v %v", c.alpn, c.h2, got, ok, c.want, c.ok)
		}
		if !c.h2 && nativeEligible(c.alpn) != c.ok {
			t.Errorf("nativeEligible(%v) disagrees", c.alpn)
		}
	}
}

// h2Handshake runs a TLS handshake through the engine's CONNECT front offering protos; returns the negotiated
// protocol (Go terminated TLS when the fake front declined).
func h2Handshake(t *testing.T, h *harness, protos []string) string {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(h.ca.Cert)
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", h.e.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "CONNECT api.test.com:443 HTTP/1.1\r\nHost: api.test.com:443\r\n\r\n")
	br := bufio.NewReader(c)
	if resp, err := http.ReadResponse(br, nil); err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v", err)
	}
	tc := tls.Client(&bufConn{Conn: c, r: br}, &tls.Config{ServerName: "api.test.com", RootCAs: pool, NextProtos: protos})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	return tc.ConnectionState().NegotiatedProtocol
}

func TestNativeTermH2Offer(t *testing.T) {
	h := newHarness(t, termCfg(), nil)
	f := useFakeTerm(t, h, "decline")
	t.Cleanup(func() { SetNativeH2(false) })

	// switch off: "h2" is never passed on, h2-only clients are not offered at all (stage 2 behaviour)
	SetNativeH2(false)
	h2Handshake(t, h, []string{"h2", "http/1.1"})
	if a, _ := f.lastALP.Load().(string); a != "http/1.1" {
		t.Fatalf("switch off: offer %q", a)
	}
	n := f.calls.Load()
	if p := h2Handshake(t, h, []string{"h2"}); p != "h2" || f.calls.Load() != n {
		t.Fatalf("switch off, h2-only: negotiated %q, Listen calls +%d", p, f.calls.Load()-n)
	}

	// switch on: the native side sees h2 and h2-only clients; it declined here, so Go still served h2
	SetNativeH2(true)
	h2Handshake(t, h, []string{"h2", "http/1.1"})
	if a, _ := f.lastALP.Load().(string); a != "h2,http/1.1" {
		t.Fatalf("switch on: offer %q", a)
	}
	if p := h2Handshake(t, h, []string{"h2"}); p != "h2" {
		t.Fatalf("switch on, h2-only after decline: negotiated %q", p)
	}
	if a, _ := f.lastALP.Load().(string); a != "h2" {
		t.Fatalf("switch on, h2-only: offer %q", a)
	}

	// the engine's own h2 option off: the native side must not offer h2 either
	off := false
	cfg := termCfg()
	cfg.H2 = &off
	h.e.Reload(cfg, Build(h.home, cfg))
	h2Handshake(t, h, []string{"h2", "http/1.1"})
	if a, _ := f.lastALP.Load().(string); a != "http/1.1" {
		t.Fatalf("engine h2 off: offer %q", a)
	}
}

// ---- cost measurement ----
//
//	go test ./mitm -run TestH2PerConnectionCost -v
//
// Go path: an HTTP/2 client through the engine's CONNECT front; Go terminates TLS, net/http's h2 server runs
// one handler goroutine per stream, ReverseProxy forwards over the engine's h2 upstream transport.
// Native h2: Go keeps only (a) the handoff pipe per connection (the same as for HTTP/1.1, see s2cost_test.go
// and feat/s2-pipe's lean pipe) and (b) one flow per in-flight stream (flow API state, no resident goroutine);
// HPACK, frames, flow control, TLS and the upstream h2 connection live in Swift. (b) is measured here on the
// real flow API with the same requests held in flight.

type h2Cost struct {
	what           string
	n              int
	gor, heapK     float64
	stackK, sysK   float64
	heapAllocTotal float64
}

type memSnap struct {
	gor                   int
	heap, stack, sys, tot uint64
}

func snapMem() memSnap {
	for i := 0; i < 3; i++ {
		runtime.GC()
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return memSnap{unlabeledGoroutines(), m.HeapInuse, m.StackInuse, m.Sys, m.TotalAlloc}
}

func costOf(what string, n int, a, b memSnap) h2Cost {
	f := float64(n)
	return h2Cost{what, n, float64(b.gor-a.gor) / f, float64(int64(b.heap)-int64(a.heap)) / f / 1024,
		float64(int64(b.stack)-int64(a.stack)) / f / 1024, float64(int64(b.sys)-int64(a.sys)) / f / 1024,
		float64(b.tot-a.tot) / f / 1024}
}

func TestH2PerConnectionCost(t *testing.T) {
	if testing.Short() {
		t.Skip("measurement")
	}
	const conns, streams = 24, 32
	release := make(chan struct{})
	var held sync.WaitGroup
	var origin *httptest.Server
	pprof.Do(context.Background(), pprof.Labels("lane", "origin"), func(context.Context) {
		mux := http.NewServeMux()
		mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ad":true,"data":{"ads":[1,2],"keep":1}}`)
		})
		mux.HandleFunc("/hold", func(w http.ResponseWriter, r *http.Request) {
			held.Done()
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(200)
			w.(http.Flusher).Flush() // head out, body pending: the stream stays open in every hop
			<-release
			_, _ = io.WriteString(w, "done")
		})
		origin = httptest.NewUnstartedServer(mux)
		origin.EnableHTTP2 = true
		origin.StartTLS()
	})
	defer origin.Close()
	upAddr := origin.Listener.Addr().String()

	home := t.TempDir()
	ca, err := GenerateCA(home)
	if err != nil {
		t.Fatal(err)
	}
	e := New(home, func(ctx context.Context, network, addr, policy string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", upAddr)
	}, func(string, string) {})
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	cfg := termCfg()
	cfg.SkipCertVerify = true
	noCapture := false // capture on makes both paths read bodies through Go (32 KB); measure the transport itself
	cfg.CaptureBodies = &noCapture
	_ = os.MkdirAll(ScriptsDir(home), 0o755)
	e.Reload(cfg, Build(home, cfg))
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", e.Port()))
	newClient := func() *http.Client {
		tr := &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: pool}, ForceAttemptHTTP2: true, DisableCompression: true}
		return &http.Client{Transport: tr, Timeout: 30 * time.Second}
	}
	get := func(c *http.Client, path string) *http.Response {
		var resp *http.Response
		pprof.Do(context.Background(), pprof.Labels("lane", "client"), func(context.Context) {
			var err error
			resp, err = c.Get("https://api.test.com" + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			if resp.ProtoMajor != 2 {
				t.Fatalf("client not on h2: %s", resp.Proto)
			}
		})
		return resp
	}
	warm := newClient()
	r := get(warm, "/json")
	_, _ = io.ReadAll(r.Body)
	r.Body.Close()
	warm.CloseIdleConnections()
	time.Sleep(200 * time.Millisecond)

	var rs []h2Cost
	// (1) idle h2 connections on the Go path (one request done, connection kept)
	s0 := snapMem()
	clients := make([]*http.Client, conns)
	for i := range clients {
		clients[i] = newClient()
		r := get(clients[i], "/json")
		_, _ = io.ReadAll(r.Body)
		r.Body.Close()
	}
	time.Sleep(300 * time.Millisecond)
	rs = append(rs, costOf("go-path idle h2 conn", conns, s0, snapMem()))
	for _, c := range clients {
		c.CloseIdleConnections()
	}
	time.Sleep(300 * time.Millisecond)

	// (2) in-flight streams on one Go-path h2 connection (response head sent, body pending)
	c := newClient()
	r = get(c, "/json")
	_, _ = io.ReadAll(r.Body)
	r.Body.Close()
	time.Sleep(200 * time.Millisecond)
	s1 := snapMem()
	held.Add(streams)
	resps := make(chan *http.Response, streams)
	for i := 0; i < streams; i++ {
		go func() { resps <- get(c, "/hold") }()
	}
	held.Wait()
	time.Sleep(300 * time.Millisecond)
	rs = append(rs, costOf("go-path in-flight h2 stream", streams, s1, snapMem()))
	close(release)
	for i := 0; i < streams; i++ {
		r := <-resps
		_, _ = io.ReadAll(r.Body)
		r.Body.Close()
	}
	c.CloseIdleConnections()
	time.Sleep(300 * time.Millisecond)

	// (3) native h2: what Go keeps per in-flight stream = one flow (request phase done, response head in,
	// body relayed by Swift in "upstream" mode)
	head := func(i int) string {
		b, _ := json.Marshal(FlowHead{Method: "GET", Target: fmt.Sprintf("/hold?i=%d", i), Host: "api.test.com",
			Headers: [][2]string{{"Accept", "*/*"}, {"User-Agent", "h2-cost"}}, Length: 0, ConnHost: "api.test.com", ConnPort: 443, TLS: true})
		return string(b)
	}
	s2 := snapMem()
	ids := make([]int64, streams)
	for i := range ids {
		var d flowDecision
		_ = json.Unmarshal([]byte(e.FlowBegin(head(i))), &d)
		if d.Action != "forward" {
			t.Fatalf("flow %d: %+v", i, d)
		}
		ids[i] = d.ID
		_ = json.Unmarshal([]byte(FlowResponse(d.ID, `{"status":200,"headers":[["Content-Type","text/plain"]],"length":-1}`)), &d)
		if d.Action != "respond" || d.Body != "upstream" {
			t.Fatalf("flow %d response: %+v", i, d)
		}
	}
	time.Sleep(100 * time.Millisecond)
	rs = append(rs, costOf("native h2 stream (Go flow)", streams, s2, snapMem()))
	for _, id := range ids {
		FlowEnd(id, 4, "")
	}

	for _, x := range rs {
		t.Logf("H2COST %-30s n=%-3d goroutines=%.2f heapInuse=%.1f KiB stack=%.1f KiB sys=%.1f KiB allocated=%.1f KiB (per item)",
			x.what, x.n, x.gor, x.heapK, x.stackK, x.sysK, x.heapAllocTotal)
	}
	if rs[2].gor > 0.5 {
		t.Errorf("a native in-flight flow keeps %.2f goroutines in Go", rs[2].gor)
	}
}
