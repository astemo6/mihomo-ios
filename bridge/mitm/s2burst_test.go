package mitm

// Native MitM stage 2 memory check (feat/s2-pipe, user 2026-10-24 13:31 「先试试新代码能不能降低内存占用」): a
// 喜马拉雅-like burst — 100 concurrent MitM connections, one small JSON request each, then left idle in
// keep-alive — through the Go path versus through the native front, measuring only the process the engine lives
// in. The clients, the origin and the stand-in native front (TLS + HTTP/1.1 + an upstream pool through the relay,
// what Swift does in production) run in a child process, so nothing but the engine, the relay and a stand-in
// for mihomo's own per-upstream-connection relay is in the measured Go runtime.
//
//	go test ./mitm -run TestS2BurstMemory -v
//
// The mihomo stand-in (coreSim): every upstream dial (Go path: the engine's http.Transport through
// inner.HandleTcp; native: the relay's socket handoff) costs what mihomo's relay of an INNER connection costs —
// two goroutines and two 32 KiB copy buffers — so the Go path's h2-multiplexed upstream and the native pool's
// HTTP/1.1 connections are charged the same per connection.

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const s2BurstConns = 100

type s2Mem struct {
	heapMB, sysMB, stackMB float64
	gor                    int
}

func s2ReadMem() s2Mem {
	for i := 0; i < 3; i++ {
		runtime.GC()
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	const mb = 1 << 20
	return s2Mem{float64(m.HeapInuse) / mb, float64(m.Sys-m.HeapReleased) / mb, float64(m.StackInuse) / mb, runtime.NumGoroutine()}
}

func (a s2Mem) sub(b s2Mem) s2Mem {
	return s2Mem{a.heapMB - b.heapMB, a.sysMB - b.sysMB, a.stackMB - b.stackMB, a.gor - b.gor}
}

// coreSimRelay copies a ↔ b like mihomo's relay of one INNER connection (2 goroutines, 2 × 32 KiB).
func coreSimRelay(a, b net.Conn) {
	cp := func(dst, src net.Conn) {
		buf := make([]byte, 32<<10)
		_, _ = io.CopyBuffer(writerOnly{dst}, readerOnly{src}, buf)
		_ = dst.Close()
		_ = src.Close()
	}
	go cp(a, b)
	go cp(b, a)
}

type s2BurstResult struct {
	mode        string
	base, after s2Mem
	upDials     int64
}

func s2Burst(t *testing.T, mode string) s2BurstResult {
	home := t.TempDir()
	ca, err := GenerateCA(home)
	if err != nil {
		t.Fatal(err)
	}
	var originAddr atomic.Value
	var upDials atomic.Int64
	dial := func(ctx context.Context, network, addr, policy string) (net.Conn, error) {
		tc, err := net.Dial("tcp", originAddr.Load().(string))
		if err != nil {
			return nil, err
		}
		upDials.Add(1)
		c1, c2 := net.Pipe() // inner.HandleTcp
		coreSimRelay(c2, tc)
		return c1, nil
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
	if _, err := e.StartRelay(); err != nil {
		t.Fatal(err)
	}
	e.SetRelayHandoff(func(c net.Conn, target, policy string) error {
		tc, err := net.Dial("tcp", originAddr.Load().(string))
		if err != nil {
			return err
		}
		upDials.Add(1)
		coreSimRelay(c, tc) // tunnel.HandleTCPConn on the socket itself
		return nil
	})
	p12, err := e.LeafIdentity("api.test.com")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p12Path, caPath := filepath.Join(dir, "leaf.p12"), filepath.Join(dir, "ca.pem")
	_ = os.WriteFile(p12Path, p12, 0o600)
	_ = os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}), 0o600)

	cmd := exec.Command(os.Args[0], "-test.run=^TestS2BurstHelper$", "-test.v=false")
	cmd.Env = append(os.Environ(), "S2BURST_HELPER=1", "S2BURST_MODE="+mode, "S2BURST_P12="+p12Path, "S2BURST_CA="+caPath,
		"S2BURST_ENGINE="+strconv.Itoa(e.Port()), "S2BURST_RELAY="+strconv.Itoa(e.RelayPort()), "S2BURST_N="+strconv.Itoa(s2BurstConns))
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close(); _ = cmd.Wait() }()
	lines := bufio.NewScanner(stdout)
	expect := func(prefix string) string {
		for lines.Scan() {
			l := lines.Text()
			if strings.HasPrefix(l, "S2B ") {
				l = strings.TrimPrefix(l, "S2B ")
				if strings.HasPrefix(l, "fail ") {
					t.Fatalf("helper: %s", l)
				}
				if strings.HasPrefix(l, prefix) {
					return strings.TrimSpace(strings.TrimPrefix(l, prefix))
				}
			}
		}
		t.Fatalf("helper ended before %q", prefix)
		return ""
	}
	originAddr.Store(expect("origin "))
	if mode != "go-path" {
		fp, _ := strconv.Atoi(expect("front "))
		f := &cappedFront{port: int64(fp), cap: 1 << 30}
		if mode == "native-cap48" {
			f.cap = 48 + 1 // + the warm-up connection; the Swift runtime caps live sessions at 48 (NativeMitmRuntime.maxSessions)
		}
		SetNativeTerminator(f)
		defer func() { SetNativeTerminator(nil); resetTermBreaker() }()
	}
	_, _ = io.WriteString(stdin, "warm\n")
	expect("warm")
	time.Sleep(300 * time.Millisecond)
	base := s2ReadMem()
	h0, _ := TermStats()
	_, _ = io.WriteString(stdin, "burst\n")
	expect("idle")
	time.Sleep(time.Second)
	after := s2ReadMem()
	if mode == "native" {
		if h1, _ := TermStats(); h1-h0 < s2BurstConns {
			t.Fatalf("native front took %d of %d connections", h1-h0, s2BurstConns)
		}
	}
	_, _ = io.WriteString(stdin, "quit\n")
	expect("bye")
	return s2BurstResult{mode, base, after, upDials.Load()}
}

// cappedFront answers the helper's front port for the first cap Listen calls, then declines (Go path).
type cappedFront struct {
	port int64
	cap  int64
	n    atomic.Int64
}

func (f *cappedFront) Listen(host, alpn string) int64 {
	if f.n.Add(1) > f.cap {
		return 0
	}
	return f.port
}

func TestS2BurstMemory(t *testing.T) {
	if testing.Short() || os.Getenv("S2BURST_HELPER") != "" {
		t.Skip("measurement")
	}
	var rs []s2BurstResult
	for _, m := range []string{"go-path", "native", "native-cap48"} {
		rs = append(rs, s2Burst(t, m))
	}
	t.Logf("S2BURST %d concurrent MitM connections, 1 small JSON request each, then idle keep-alive; engine process only (MB, after GC)", s2BurstConns)
	t.Logf("S2BURST | mode         | Go heap (inuse) | Go sys | stacks | goroutines | upstream dials |")
	for _, r := range rs {
		d := r.after.sub(r.base)
		t.Logf("S2BURST | %-12s | +%.2f (%.2f) | +%.2f (%.2f) | +%.2f (%.2f) | +%d (%d) | %d |", r.mode,
			d.heapMB, r.after.heapMB, d.sysMB, r.after.sysMB, d.stackMB, r.after.stackMB, d.gor, r.after.gor, r.upDials)
	}
	g := rs[0].after.sub(rs[0].base)
	for _, r := range rs[1:] {
		n := r.after.sub(r.base)
		t.Logf("S2BURST %s − go-path: heap %+.2f MB, stacks %+.2f MB, goroutines %+d", r.mode, n.heapMB-g.heapMB, n.stackMB-g.stackMB, n.gor-g.gor)
	}
}

// TestS2BurstHelper is the child process of TestS2BurstMemory: origin, clients and (native mode) the stand-in
// native front. Driven over stdin/stdout.
func TestS2BurstHelper(t *testing.T) {
	if os.Getenv("S2BURST_HELPER") == "" {
		t.Skip("helper process only")
	}
	out := func(f string, a ...any) { fmt.Printf("S2B "+f+"\n", a...) }
	fail := func(err error) { out("fail %v", err); os.Exit(1) }
	mode := os.Getenv("S2BURST_MODE")
	n, _ := strconv.Atoi(os.Getenv("S2BURST_N"))
	enginePort, relayPort := os.Getenv("S2BURST_ENGINE"), os.Getenv("S2BURST_RELAY")

	// origin: small JSON, keep-alive (HTTP/1.1 and h2, like a real API host)
	key, leaf, chain, err := pkcs12.DecodeChain(mustRead(os.Getenv("S2BURST_P12")), LeafIdentityPassword)
	if err != nil {
		fail(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}
	for _, c := range chain {
		cert.Certificate = append(cert.Certificate, c.Raw)
	}
	oln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		fail(err)
	}
	osrv := &http.Server{Handler: upstreamHandler()}
	go func() { _ = osrv.Serve(oln) }()
	out("origin %s", oln.Addr())

	if mode != "go-path" {
		fln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
		if err != nil {
			fail(err)
		}
		relay, _ := url.Parse("http://127.0.0.1:" + relayPort)
		// like the Swift UpstreamPool: HTTP/1.1, keep at most 2 idle per host
		up := &http.Transport{Proxy: http.ProxyURL(relay), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, MaxIdleConnsPerHost: 2}
		fsrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			o, _ := http.NewRequest(r.Method, "https://"+r.Host+r.URL.RequestURI(), r.Body)
			resp, err := up.RoundTrip(o)
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
		go func() { _ = fsrv.Serve(fln) }()
		out("front %d", fln.Addr().(*net.TCPAddr).Port)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(mustRead(os.Getenv("S2BURST_CA")))
	proxy, _ := url.Parse("http://127.0.0.1:" + enginePort)
	newClient := func() *http.Client {
		return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy),
			TLSClientConfig: &tls.Config{RootCAs: pool, NextProtos: []string{"http/1.1"}}, DisableCompression: true}}
	}
	get := func(c *http.Client) error {
		resp, err := c.Get("https://api.test.com/json")
		if err != nil {
			return err
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(b), `"keep":1`) {
			return fmt.Errorf("body %q", b)
		}
		return nil
	}
	var clients []*http.Client
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		switch in.Text() {
		case "warm":
			c := newClient()
			if err := get(c); err != nil {
				fail(err)
			}
			c.CloseIdleConnections()
			out("warm")
		case "burst":
			clients = make([]*http.Client, n)
			var wg sync.WaitGroup
			errs := make(chan error, n)
			start := make(chan struct{})
			for i := range clients {
				clients[i] = newClient()
				wg.Add(1)
				go func(c *http.Client) {
					defer wg.Done()
					<-start
					if err := get(c); err != nil {
						errs <- err
					}
				}(clients[i])
			}
			close(start)
			wg.Wait()
			close(errs)
			if err := <-errs; err != nil {
				fail(err)
			}
			out("idle")
		case "quit":
			for _, c := range clients {
				c.CloseIdleConnections()
			}
			out("bye")
			os.Exit(0)
		}
	}
}

func mustRead(p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		fmt.Printf("S2B fail %v\n", err)
		os.Exit(1)
	}
	return b
}
