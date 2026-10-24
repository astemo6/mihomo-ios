package mitm

// Native MitM stage 2 (lane wire): what one decrypted MitM connection costs the Go side today (Go path: Go
// terminates TLS, net/http serves, ReverseProxy forwards) versus with the native TLS front (Go only pipes the
// client to the loopback front and carries the front's upstream through the relay). Run:
//
//	go test ./mitm -run TestS2PerConnectionCost -v
//
// Attribution: the client, the origin and the stand-in native front each run under their own pprof label, so
// their goroutines are excluded by label; what is left unlabeled (minus the idle baseline) is the engine's. Heap is
// HeapInuse after GC, delta from the baseline: the Go-path figure minus the direct (no MitM) figure is the engine's;
// the native-front figure still includes the stand-in front's own crypto/tls state (in production that lives in
// Swift), so it is an upper bound on what stays in Go.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const s2Conns = 40

// s2Front is a minimal native TLS front stand-in (HTTP/1.1, upstream through the relay), labeled lane=front.
type s2Front struct {
	e  *Engine
	mu sync.Mutex
	ls map[string]net.Listener
}

func (f *s2Front) Listen(host, alpn string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ln, ok := f.ls[host]; ok {
		return int64(ln.Addr().(*net.TCPAddr).Port)
	}
	p12, err := f.e.LeafIdentity(host)
	if err != nil {
		return 0
	}
	key, leaf, chain, err := pkcs12.DecodeChain(p12, LeafIdentityPassword)
	if err != nil {
		return 0
	}
	cert := tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}
	for _, c := range chain {
		cert.Certificate = append(cert.Certificate, c.Raw)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		return 0
	}
	f.ls[host] = ln
	relay, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", f.e.RelayPort()))
	up := &http.Transport{Proxy: http.ProxyURL(relay), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, MaxIdleConnsPerHost: s2Conns * 2}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out, _ := http.NewRequest(r.Method, "https://"+r.Host+r.URL.RequestURI(), r.Body)
		resp, err := up.RoundTrip(out)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})}
	go pprof.Do(context.Background(), pprof.Labels("lane", "front"), func(context.Context) { _ = srv.Serve(ln) })
	return int64(ln.Addr().(*net.TCPAddr).Port)
}

func (f *s2Front) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ln := range f.ls {
		_ = ln.Close()
	}
}

// unlabeledGoroutines counts goroutines without a lane label (the engine's, plus the test runtime).
func unlabeledGoroutines() int {
	var b bytes.Buffer
	_ = pprof.Lookup("goroutine").WriteTo(&b, 1)
	n := 0
	for _, blk := range strings.Split(b.String(), "\n\n") {
		lines := strings.SplitN(blk, "\n", 3)
		var cnt int
		for _, l := range lines {
			if _, err := fmt.Sscanf(l, "%d @", &cnt); err == nil {
				break
			}
		}
		if cnt == 0 || strings.Contains(blk, `"lane":`) {
			continue
		}
		n += cnt
	}
	return n
}

func heapInuse() uint64 {
	for i := 0; i < 3; i++ {
		runtime.GC()
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapInuse
}

type s2Result struct {
	mode         string
	gorPerConn   float64
	heapPerConnK float64
}

// s2Opt: lean = the lean pipe (leanpipe.go) on the native hops, false = the old pipe(); core = upstream dials
// return an in-memory pipe bridged to the origin by a labeled "core" goroutine pair, like mihomo's
// inner.HandleTcp (the relay's real upstream), instead of a plain TCP socket.
// handoff = the relay hands its socket to the (simulated) core instead of dialing + piping (SetRelayHandoff).
type s2Opt struct{ lean, core, handoff bool }

func (o s2Opt) String() string {
	s := "before"
	if o.lean {
		s = "after"
	}
	if o.handoff {
		s += "+handoff"
	}
	if o.core {
		s += "/core-pipe"
	} else {
		s += "/tcp"
	}
	return s
}

// coreLikeDial: net.Pipe to the caller, the other end copied to a TCP conn to addr under lane=core.
func coreLikeDial(addr string) (net.Conn, error) {
	tc, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	c1, c2 := net.Pipe()
	coreRelay(c2, tc)
	return c1, nil
}

// coreRelay copies c ↔ tc under lane=core (mihomo's own relay of an INNER connection).
func coreRelay(c, tc net.Conn) {
	go pprof.Do(context.Background(), pprof.Labels("lane", "core"), func(context.Context) {
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(tc, c); _ = tc.(*net.TCPConn).CloseWrite(); done <- struct{}{} }()
		_, _ = io.Copy(c, tc)
		_ = c.Close()
		<-done
		_ = tc.Close()
	})
}

func s2Measure(t *testing.T, mode string, o s2Opt) s2Result {
	leanPipeOff.Store(!o.lean)
	defer leanPipeOff.Store(false)
	// origin under its own label
	var origin *httptest.Server
	pprof.Do(context.Background(), pprof.Labels("lane", "origin"), func(context.Context) {
		origin = httptest.NewUnstartedServer(upstreamHandler())
		origin.StartTLS() // HTTP/1.1 origin: both paths reach it the same way
	})
	defer origin.Close()
	upAddr := origin.Listener.Addr().String()

	home := t.TempDir()
	ca, err := GenerateCA(home)
	if err != nil {
		t.Fatal(err)
	}
	dial := func(ctx context.Context, network, addr, policy string) (net.Conn, error) {
		if o.core {
			return coreLikeDial(upAddr)
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", upAddr)
	}
	e := New(home, dial, func(string, string) {})
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	cfg := termCfg()
	cfg.SkipCertVerify = true
	_ = os.MkdirAll(ScriptsDir(home), 0o755)
	e.Reload(cfg, Build(home, cfg))
	var front *s2Front
	if mode == "native-front" || mode == "front-only" || mode == "relay" {
		if _, err := e.StartRelay(); err != nil {
			t.Fatal(err)
		}
		if o.handoff {
			e.SetRelayHandoff(func(c net.Conn, target, policy string) error {
				tc, err := net.Dial("tcp", upAddr)
				if err != nil {
					return err
				}
				coreRelay(c, tc)
				return nil
			})
		}
	}
	if mode == "native-front" || mode == "front-only" {
		front = &s2Front{e: e, ls: map[string]net.Listener{}}
		SetNativeTerminator(front)
		defer func() { SetNativeTerminator(nil); resetTermBreaker(); front.close() }()
	}
	// warm-up connection (listeners, leaf cert, relay, lean poller) so the baseline excludes one-time state
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	newClient := func() *http.Client {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, InsecureSkipVerify: mode == "direct" || mode == "relay"}, DisableCompression: true}
		switch mode {
		case "front-only":
			fp := front.Listen("api.test.com", "http/1.1")
			tr.DialContext = func(ctx context.Context, n, a string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", fp))
			}
		case "direct":
			tr.DialContext = func(ctx context.Context, n, a string) (net.Conn, error) { return dial(ctx, n, a, "") }
		case "relay": // the native front's upstream: one CONNECT through the relay per connection
			pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", e.RelayPort()))
			tr.Proxy = http.ProxyURL(pu)
		default:
			pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", e.Port()))
			tr.Proxy = http.ProxyURL(pu)
		}
		return &http.Client{Transport: tr, Timeout: 15 * time.Second}
	}
	get := func(c *http.Client) {
		pprof.Do(context.Background(), pprof.Labels("lane", "client"), func(context.Context) {
			resp, err := c.Get("https://api.test.com/json")
			if err != nil {
				t.Fatalf("%s %v: %v", mode, o, err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if !strings.Contains(string(b), `"keep":1`) {
				t.Fatalf("%s %v: body %q", mode, o, b)
			}
		})
	}
	warm := newClient()
	get(warm)
	warm.CloseIdleConnections()
	time.Sleep(200 * time.Millisecond)

	g0, h0 := unlabeledGoroutines(), heapInuse()
	clients := make([]*http.Client, s2Conns)
	for i := range clients {
		clients[i] = newClient()
		get(clients[i]) // one request, connection left idle in keep-alive (the common steady state)
	}
	time.Sleep(300 * time.Millisecond)
	g1, h1 := unlabeledGoroutines(), heapInuse()
	for _, c := range clients {
		c.CloseIdleConnections()
	}
	if mode == "native-front" {
		if n, _ := TermStats(); n == 0 {
			t.Fatal("native front never took a connection")
		}
	}
	// let the closed connections' pipes wind down before the next mode's baseline
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && (leanParked.Load() > 0 || leanCopying.Load() > 0) {
		time.Sleep(20 * time.Millisecond)
	}
	return s2Result{mode, float64(g1-g0) / s2Conns, float64(int64(h1)-int64(h0)) / s2Conns / 1024}
}

// s2Cost is one hop's per-connection cost in Go.
type s2Cost struct{ gor, heapK float64 }

func (c s2Cost) String() string { return fmt.Sprintf("%.2f goroutines + %.1f KiB", c.gor, c.heapK) }

func s2Diff(a, b s2Result) s2Cost {
	return s2Cost{a.gorPerConn - b.gorPerConn, a.heapPerConnK - b.heapPerConnK}
}

// TestS2PerConnectionCost reports what one MitM connection costs the Go side: the Go path (Go terminates TLS)
// versus the native front's two Go hops — the handoff pipe client ↔ front (engine.go/nativeterm.go) and the
// relay CONNECT pipe front ↔ origin (relay.go) — before (pipe(): a goroutine and a 16 KiB buffer per direction
// plus the waiting caller) and after (leanpipe.go). Idle keep-alive connections, 40 per run.
func TestS2PerConnectionCost(t *testing.T) {
	if testing.Short() {
		t.Skip("measurement")
	}
	type key struct {
		mode string
		o    s2Opt
	}
	rs := map[key]s2Result{}
	for _, core := range []bool{false, true} {
		for _, m := range []string{"direct", "go-path"} {
			o := s2Opt{lean: true, core: core}
			rs[key{m, o}] = s2Measure(t, m, o)
		}
		opts := []s2Opt{{lean: false, core: core}, {lean: true, core: core}}
		if core {
			opts = append(opts, s2Opt{lean: true, core: true, handoff: true})
		}
		for _, o := range opts {
			for _, m := range []string{"front-only", "native-front", "relay"} {
				rs[key{m, o}] = s2Measure(t, m, o)
			}
		}
	}
	for _, o := range []s2Opt{{}, {lean: true}, {core: true}, {lean: true, core: true}, {lean: true, core: true, handoff: true}} {
		for _, m := range []string{"direct", "go-path", "front-only", "native-front", "relay"} {
			if r, ok := rs[key{m, o}]; ok {
				t.Logf("S2COST raw %-24s mode=%-12s unlabeled goroutines/conn=%.2f heapInuse/conn=%.1f KiB", o, m, r.gorPerConn, r.heapPerConnK)
			}
		}
	}
	var after s2Cost
	for _, core := range []bool{false, true} {
		lo, bo := s2Opt{lean: true, core: core}, s2Opt{lean: false, core: core}
		// Go path engine: its own goroutine per connection; heap = TLS server + net/http conn, measured as what
		// the stand-in front costs for the same work (go-path − front-only on the same dial).
		goPath := s2Cost{rs[key{"go-path", lo}].gorPerConn, rs[key{"go-path", lo}].heapPerConnK - rs[key{"front-only", lo}].heapPerConnK}
		hb, ha := s2Diff(rs[key{"native-front", bo}], rs[key{"front-only", bo}]), s2Diff(rs[key{"native-front", lo}], rs[key{"front-only", lo}])
		rb, ra := s2Diff(rs[key{"relay", bo}], rs[key{"direct", lo}]), s2Diff(rs[key{"relay", lo}], rs[key{"direct", lo}])
		up := "tcp"
		if core {
			up = "core-pipe"
		}
		t.Logf("S2COST [upstream %s] Go path engine/conn: %v", up, goPath)
		t.Logf("S2COST [upstream %s] stage2 handoff pipe/conn: before %v → after %v", up, hb, ha)
		t.Logf("S2COST [upstream %s] relay pipe/upstream conn: before %v → after %v (heap vs the direct baseline is noisy; saved: %v)", up, rb, ra,
			s2Diff(rs[key{"relay", bo}], rs[key{"relay", lo}]))
		if core {
			ho := s2Opt{lean: true, core: true, handoff: true}
			rh := s2Diff(rs[key{"relay", ho}], rs[key{"direct", s2Opt{lean: true}}]) // core relays socket ↔ socket like direct/tcp
			t.Logf("S2COST [upstream %s] relay with socket handoff to the core/upstream conn: %v", up, rh)
			ra = rh
		}
		t.Logf("S2COST [upstream %s] stage2 Go total/conn (handoff + 1 relay conn): before %v → after %v (Go path %v)", up,
			s2Cost{hb.gor + rb.gor, hb.heapK + rb.heapK}, s2Cost{ha.gor + ra.gor, ha.heapK + ra.heapK}, goPath)
		if core {
			after = s2Cost{ha.gor + ra.gor, ha.heapK + ra.heapK}
			// goroutines are exact; the stage-2 total (production-like upstream) must undercut the Go path.
			if after.gor >= goPath.gor {
				t.Errorf("stage 2 still costs %.2f goroutines/conn in Go (Go path %.2f)", after.gor, goPath.gor)
			}
			if ha.gor > 0.05 {
				t.Errorf("handoff pipe still parks %.2f goroutines/conn", ha.gor)
			}
		}
	}
}

// s2PipeOnly measures the pipe itself: n idle connection pairs piped by handoffPipe (old pipe() when lean is
// false), the far ends held by the test. upstream "tcp" = socket ↔ socket (the client ↔ front hop),
// "mem" = socket ↔ in-memory pipe (the relay over mihomo's inner.HandleTcp without the socket handoff).
func s2PipeOnly(t *testing.T, lean bool, upstream string) s2Cost {
	leanPipeOff.Store(!lean)
	defer leanPipeOff.Store(false)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	pair := func() (near, far net.Conn) {
		far, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		near, err = ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		return near, far
	}
	// warm-up (poller, pools)
	{
		a, af := pair()
		b, bf := pair()
		go handoffPipe(a, b)
		_, _ = af.Write([]byte("x"))
		one := make([]byte, 1)
		_, _ = io.ReadFull(bf, one)
		af.Close()
		bf.Close()
		time.Sleep(100 * time.Millisecond)
	}
	const n = 100
	fars := make([]net.Conn, 0, 2*n)
	g0, h0 := unlabeledGoroutines(), heapInuse()
	for i := 0; i < n; i++ {
		a, af := pair()
		var b, bf net.Conn
		if upstream == "mem" {
			b, bf = net.Pipe()
		} else {
			b, bf = pair()
		}
		fars = append(fars, af, bf)
		go handoffPipe(a, b)
		// one round trip each way so both directions have run once (and returned their buffers)
		_, _ = af.Write([]byte("ping"))
		buf := make([]byte, 4)
		if _, err := io.ReadFull(bf, buf); err != nil {
			t.Fatal(err)
		}
		go func() { _, _ = bf.Write([]byte("pong")) }()
		if _, err := io.ReadFull(af, buf); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(200 * time.Millisecond)
	g1, h1 := unlabeledGoroutines(), heapInuse()
	// the far ends themselves (2 sockets or a socket + net.Pipe end) are the test's; subtract an unpiped set
	for _, c := range fars {
		c.Close()
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && (leanParked.Load() > 0 || leanCopying.Load() > 0) {
		time.Sleep(20 * time.Millisecond)
	}
	return s2Cost{float64(g1-g0) / n, float64(int64(h1)-int64(h0)) / n / 1024}
}

// TestS2PipeOnlyCost: the pipe alone, before/after, plus the same connections unpiped (what the sockets and
// the test's own objects cost) so the pipe's share can be read off.
func TestS2PipeOnlyCost(t *testing.T) {
	if testing.Short() {
		t.Skip("measurement")
	}
	for _, up := range []string{"tcp", "mem"} {
		b := s2PipeOnly(t, false, up)
		a := s2PipeOnly(t, true, up)
		t.Logf("S2COST pipe only [%s]: before %v → after %v per piped connection (sockets/objects included)", up, b, a)
		if up == "tcp" && a.gor > 0.05 {
			t.Errorf("lean pipe parks %.2f goroutines per socket pair", a.gor)
		}
		// heap: on Linux the old socket ↔ socket pipe spliced without touching its buffers (TCPConn.ReadFrom), so
		// only the in-memory case is compared; on Darwin/iOS ReadFrom has no splice and copies through 32 KiB.
		if a.gor >= b.gor || (up == "mem" && a.heapK >= b.heapK) {
			t.Errorf("lean pipe no cheaper: before %v after %v", b, a)
		}
	}
}
