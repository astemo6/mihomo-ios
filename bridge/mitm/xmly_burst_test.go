package mitm

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// v0.19.22 喜马拉雅 report (user 2026-10-23 22:40, v0.19.21: 「打开喜马拉雅后有问题，自动断连」): opening the
// app fired a burst of requests matching the 363 KB unlock script (~1.1 s of goja per run, large bundles
// run one at a time). The queue grew to ~10 s (script log 「客户端已断开，跳过脚本（排队 9881 ms）」), the
// runtime ran back to back while the app retried, and the extension went from 18 MB to 40 MB and was
// killed by jetsam. This rig replays such a burst against the real script and samples the Go heap and
// the goroutine count.

type burstStats struct {
	baseHeap   uint64 // heap objects after warm-up + GC
	peakHeap   uint64 // heap objects, bytes
	gcs        uint64 // GC cycles during the burst
	peakGor    int
	ok, failed int // requests answered / attempts the client gave up on (timeout; each is retried once)
	ran        int // script runs that finished
	skipped    int // requests the queue turned away (passed through unchanged)
	elapsed    time.Duration
}

func (b burstStats) String() string {
	return fmt.Sprintf("heap %.1f → peak %.1f MB (+%.1f), peak goroutines %d, GCs %d, answered %d, client timeouts %d, script runs %d, skipped by queue %d, %s",
		float64(b.baseHeap)/(1<<20), float64(b.peakHeap)/(1<<20), float64(b.peakHeap-b.baseHeap)/(1<<20), b.peakGor, b.gcs, b.ok, b.failed, b.ran, b.skipped, b.elapsed.Round(10*time.Millisecond))
}

// xmlyBurst sends n concurrent requests for paths the unlock script matches; each response is a JSON body
// of about bodyKB; the client gives up after clientTimeout (the app's ~10 s).
func xmlyBurst(t *testing.T, n, bodyKB int, clientTimeout time.Duration) burstStats {
	t.Helper()
	src := ximalayaFile(t)
	home := t.TempDir()
	if _, err := GenerateCA(home); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Dir(ModulePath(home, "xmly")), 0o755)
	if err := os.WriteFile(ModulePath(home, "xmly"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	seedScript(t, home, ximalayaURL, src)
	pad := `"` + strings.Repeat("x", 1000) + `"`
	var items []string
	for i := 0; i < bodyKB; i++ {
		items = append(items, pad)
	}
	body := `{"ret":0,"msg":"成功","data":{"uid":1,"isVip":false,"vipStatus":0,"list":[` + strings.Join(items, ",") + `]}}`
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		_, _ = io.WriteString(w, body)
	}))
	up.EnableHTTP2 = true
	up.StartTLS()
	t.Cleanup(up.Close)
	dial := func(ctx context.Context, network, addr, policy string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", up.Listener.Addr().String())
	}
	e := New(home, dial, nil)
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)
	cfg := &Config{Enabled: true, MitM: true, SkipCertVerify: true, Modules: []Module{{ID: "xmly", Name: "喜马拉雅", URL: ximalayaURL, Enabled: true}}}
	e.Reload(cfg, Build(home, cfg))
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", e.Port()))
	newClient := func() *http.Client {
		tr := &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr, Timeout: clientTimeout}
	}
	// Warm up: compile the program once (the device had it cached too).
	warm := newClient()
	req, _ := http.NewRequest("GET", "https://180.153.10.20/mobile-user/v2/homePage/1?device=iPhone", nil)
	req.Host = "mobile.ximalaya.com"
	if resp, err := warm.Do(req); err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	paths := []string{"/mobile-user/v2/homePage/%d", "/product/detail/v1/%d", "/v1/album/track/ts-%d",
		"/mobile-playpage/track/v4/baseInfo/ts-%d", "/mobile-playpage/playpage/tabs/v2/%d",
		"/mobile-playpage/playpage/track/qualityAndEffect/%d", "/mobile/download/v2/track/%d"}

	// The extension's soft limit (GOMEMLIMIT 30.2 MB in the device log, ~26 MB above an idle core).
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	oldLimit := debug.SetMemoryLimit(int64(ms.HeapAlloc) + 26<<20)
	defer debug.SetMemoryLimit(oldLimit)
	var st burstStats
	gcS := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}, {Name: "/gc/cycles/total:gc-cycles"}}
	metrics.Read(gcS)
	st.baseHeap = gcS[0].Value.Uint64()
	gc0 := gcS[1].Value.Uint64()
	stop := make(chan struct{})
	var sampWG sync.WaitGroup
	sampWG.Add(1)
	go func() {
		defer sampWG.Done()
		s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
		tk := time.NewTicker(2 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
			}
			metrics.Read(s)
			if v := s[0].Value.Uint64(); v > st.peakHeap {
				st.peakHeap = v
			}
			if g := runtime.NumGoroutine(); g > st.peakGor {
				st.peakGor = g
			}
		}
	}()
	runs0 := runtimesCreated.Load()
	skip0 := countNotes(e, "排队过长")
	var ok, failed atomic.Int32
	var wg sync.WaitGroup
	start := time.Now()
	// The app's three connections (h2) carry the burst.
	clients := []*http.Client{newClient(), newClient(), newClient()}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// The app retries a request that timed out once (the device log: the burst went on).
			for attempt := 0; attempt < 2; attempt++ {
				req, _ := http.NewRequest("GET", "https://180.153.10.20"+fmt.Sprintf(paths[i%len(paths)], 1000+i)+"?device=iPhone", nil)
				req.Host = "mobile.ximalaya.com"
				resp, err := clients[i%len(clients)].Do(req)
				if err == nil {
					_, err = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
				if err == nil {
					ok.Add(1)
					return
				}
				failed.Add(1)
			}
		}(i)
	}
	wg.Wait()
	st.elapsed = time.Since(start)
	// Runs cancelled by the client going away still finish in the background for a moment.
	time.Sleep(300 * time.Millisecond)
	close(stop)
	sampWG.Wait()
	st.ok, st.failed = int(ok.Load()), int(failed.Load())
	st.ran = int(runtimesCreated.Load() - runs0)
	metrics.Read(gcS)
	st.gcs = gcS[1].Value.Uint64() - gc0
	st.skipped = countNotes(e, "排队过长") - skip0
	return st
}

func countLogs(e *Engine, sub string) int {
	n := 0
	for _, l := range e.Logs.List(0, "") {
		if strings.Contains(l.Msg, sub) {
			n++
		}
	}
	return n
}

func countNotes(e *Engine, sub string) int {
	n := 0
	for _, s := range e.Requests.List(0) {
		for _, note := range s.Notes {
			if strings.Contains(note, sub) {
				n++
			}
		}
	}
	return n
}

// TestXimalayaBurstBounded: a burst of 30 matching requests (80 KB bodies) no longer builds a queue the
// app gives up on: every client gets an answer well inside its 10 s timeout, the requests the queue
// cannot serve in time pass through unchanged (noted 「脚本排队过长」), and the runtime does not run back
// to back for the length of the burst.
func TestXimalayaBurstBounded(t *testing.T) {
	if raceEnabled || testing.Short() {
		t.Skip("real ximalaya script is too slow under the race detector")
	}
	st := xmlyBurst(t, 30, 80, 10*time.Second)
	t.Logf("burst 30 × 80 KB: %s", st)
	if st.failed != 0 {
		t.Errorf("%d clients timed out", st.failed)
	}
	if st.skipped == 0 {
		t.Errorf("no request was turned away by the queue")
	}
	if st.elapsed > 9*time.Second {
		t.Errorf("burst took %s", st.elapsed)
	}
}

// TestXimalayaBurstReport prints burst numbers for sizes from XMLY_BURST (e.g. "1,10,30,40"); manual.
func TestXimalayaBurstReport(t *testing.T) {
	spec := os.Getenv("XMLY_BURST")
	if spec == "" || raceEnabled {
		t.Skip("set XMLY_BURST=1,10,30")
	}
	for _, f := range strings.Split(spec, ",") {
		var n int
		fmt.Sscan(f, &n)
		st := xmlyBurst(t, n, 80, 10*time.Second)
		t.Logf("burst %d × 80 KB: %s", n, st)
	}
}
