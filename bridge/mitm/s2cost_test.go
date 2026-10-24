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

func s2Measure(t *testing.T, mode string) s2Result {
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
	if mode == "native-front" || mode == "front-only" {
		if _, err := e.StartRelay(); err != nil {
			t.Fatal(err)
		}
		front = &s2Front{e: e, ls: map[string]net.Listener{}}
		SetNativeTerminator(front)
		defer func() { SetNativeTerminator(nil); resetTermBreaker(); front.close() }()
	}
	// warm-up connection (listeners, leaf cert, relay) so the baseline excludes one-time state
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	newClient := func() *http.Client {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, InsecureSkipVerify: mode == "direct"}, DisableCompression: true}
		if mode == "front-only" {
			fp := front.Listen("api.test.com", "http/1.1")
			tr.DialContext = func(ctx context.Context, n, a string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", fp))
			}
		} else if mode != "direct" {
			pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", e.Port()))
			tr.Proxy = http.ProxyURL(pu)
		} else {
			tr.DialContext = func(ctx context.Context, n, a string) (net.Conn, error) { var d net.Dialer; return d.DialContext(ctx, "tcp", upAddr) }
		}
		return &http.Client{Transport: tr, Timeout: 15 * time.Second}
	}
	get := func(c *http.Client) {
		pprof.Do(context.Background(), pprof.Labels("lane", "client"), func(context.Context) {
			resp, err := c.Get("https://api.test.com/json")
			if err != nil {
				t.Fatalf("%s: %v", mode, err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if !strings.Contains(string(b), `"keep":1`) {
				t.Fatalf("%s: body %q", mode, b)
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
	return s2Result{mode, float64(g1-g0) / s2Conns, float64(int64(h1)-int64(h0)) / s2Conns / 1024}
}

func TestS2PerConnectionCost(t *testing.T) {
	if testing.Short() {
		t.Skip("measurement")
	}
	var rs []s2Result
	for _, m := range []string{"direct", "go-path", "native-front", "front-only"} {
		rs = append(rs, s2Measure(t, m))
	}
	for _, r := range rs {
		t.Logf("S2COST mode=%-12s engine goroutines/conn=%.2f heapInuse/conn=%.1f KiB", r.mode, r.gorPerConn, r.heapPerConnK)
	}
	goPath, native, frontOnly := rs[1], rs[2], rs[3]
	// front-only = client straight to the stand-in front (no engine handoff pipe); native-front − front-only is
	// what the handoff itself costs Go per connection (loopback pipe: 3 goroutines + 2×16 KiB buffers, engine.go pipe).
	// go-path − front-only ≈ Go's TLS + net/http server state per connection versus the same done by "the front".
	t.Logf("S2COST handoff pipe cost/conn in Go: goroutines=%.2f heap=%.1f KiB; go-path vs front-only heap/conn=%.1f KiB; goroutines go-path=%.2f native(Go side)=%.2f",
		native.gorPerConn-frontOnly.gorPerConn, native.heapPerConnK-frontOnly.heapPerConnK, goPath.heapPerConnK-frontOnly.heapPerConnK,
		goPath.gorPerConn, native.gorPerConn)
}
