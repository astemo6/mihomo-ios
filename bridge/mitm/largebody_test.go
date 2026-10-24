package mitm

// fix/selective-largebody: v0.19.25 device report 2026-10-25 01:38 — with 喜马拉雅 and YouTube open together,
// 「跳过脚本：响应体解压后超过 970 KB（当前内存预算 970 KB，隧道可用 6.7 MB；Content-Encoding: br，已收 140 KB）」.

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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// shortLargeBodyWait shortens the large-body wait for a test (fixed probes never free anything).
func shortLargeBodyWait(t *testing.T, d time.Duration) {
	t.Helper()
	old, oldStall := largeBodyWait, largeBodyStall
	largeBodyWait = d
	largeBodyStall = min(oldStall, d/2)
	t.Cleanup(func() { largeBodyWait, largeBodyStall = old, oldStall })
}

// TestLargeBodyBudgetMath pins the budget the WARN quotes and the tight fallback, at the device's 6.7 MB.
func TestLargeBodyBudgetMath(t *testing.T) {
	for _, c := range []struct {
		avail      int64
		dyn, tight int // KB
	}{
		{6700 << 20 / 1000, 1262, 1894}, // device 6.7 MB: was (6.7−4)/3 ≈ 920 KB (the WARN's 970 KB was read a moment earlier)
		{8 << 20, 1706, 2560},
		{9 << 20, 2048, 3072},
		{5 << 20, 683, 0}, // below the 6 MB heapHigh line: no tight fallback (small work only)
	} {
		tunnelConditions(t, 0, c.avail)
		dyn, _, _ := dynamicBodyMax()
		if dyn < bodyBudgetMin {
			dyn = bodyBudgetMin
		}
		gotDyn, gotTight := dyn>>10, tightBodyMax()>>10
		old := max((c.avail-4<<20)/3, bodyBudgetMin) >> 10
		t.Logf("available %.1f MB: budget %d KB (before: %d KB), tight fallback %d KB", float64(c.avail)/(1<<20), gotDyn, old, gotTight)
		if c.dyn >= 256 && (gotDyn < c.dyn-2 || gotDyn > c.dyn+2) || gotTight < c.tight-2 || gotTight > c.tight+2 {
			t.Errorf("available %d: budget %d KB tight %d KB, want %d / %d", c.avail, gotDyn, gotTight, c.dyn, c.tight)
		}
	}
	if e := estimateDecoded(200<<10, "br", 0); e != 1600<<10 {
		t.Errorf("br estimate %d", e)
	}
	if e := estimateLow(200<<10, "br", 0); e != 600<<10 {
		t.Errorf("br low estimate %d", e)
	}
	if e := estimateDecoded(-1, "br", 3<<20); e != 3<<20 {
		t.Errorf("unknown length uses the hint: %d", e)
	}
}

// ytXmlyEngine: one engine with the YouTube Enhance module and the 喜马拉雅 module, both upstreams on one server.
func ytXmlyEngine(t *testing.T) (*http.Client, *Engine) {
	t.Helper()
	home := t.TempDir()
	if _, err := GenerateCA(home); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Dir(ModulePath(home, "yt")), 0o755)
	if err := os.WriteFile(ModulePath(home, "yt"), ytFile(t, "yt_enhance.sgmodule"), 0o644); err != nil {
		t.Fatal(err)
	}
	xsrc := ximalayaFile(t)
	if err := os.WriteFile(ModulePath(home, "xmly"), xsrc, 0o644); err != nil {
		t.Fatal(err)
	}
	seedScript(t, home, ytResponseURL, ytFile(t, "yt_youtube.response.js"))
	seedScript(t, home, ytRequestURL, ytFile(t, "yt_youtube.request.js"))
	seedScript(t, home, ximalayaURL, xsrc)
	mux := http.NewServeMux()
	mux.HandleFunc("/mobile-user/v2/homePage/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		_, _ = io.WriteString(w, `{"ret":0,"msg":"成功","data":{"uid":1,"nickname":"tester","isVip":false,"vipStatus":0,"vipInfo":{"isVip":false},"svipInfo":{"isVip":false}}}`)
	})
	mux.HandleFunc("/youtubei/v1/player", func(w http.ResponseWriter, r *http.Request) {
		if ytPlayerHandler != nil {
			ytPlayerHandler(w, r)
			return
		}
		http.NotFound(w, r)
	})
	up := httptest.NewUnstartedServer(mux)
	up.EnableHTTP2 = true
	up.StartTLS()
	t.Cleanup(up.Close)
	dial := func(ctx context.Context, network, addr, policy string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", up.Listener.Addr().String())
	}
	var logMu sync.Mutex
	logDone := false
	e := New(home, dial, func(level, msg string) {
		logMu.Lock()
		defer logMu.Unlock()
		if !logDone && (strings.Contains(msg, "大响应体") || strings.Contains(msg, "跳过") || strings.Contains(msg, "重新解码")) {
			t.Logf("[%s] %s", level, msg)
		}
	})
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)
	t.Cleanup(func() { logMu.Lock(); logDone = true; logMu.Unlock() })
	cfg := &Config{Enabled: true, MitM: true, SkipCertVerify: true, Modules: []Module{
		{ID: "yt", Name: "YouTube", URL: ytModuleURL, Enabled: true},
		{ID: "xmly", Name: "喜马拉雅解锁@tg/giegie777", URL: ximalayaURL, Enabled: true},
	}}
	e.Reload(cfg, Build(home, cfg))
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", e.Port()))
	tr := &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true, DisableCompression: true}
	return &http.Client{Transport: tr, Timeout: 60 * time.Second}, e
}

var xmlyLastErr atomic.Value

func xmlyHomePage(c *http.Client) bool {
	req, _ := http.NewRequest("GET", "https://180.153.10.20/mobile-user/v2/homePage/1792747994306?device=iPhone", nil)
	req.Host = "mobile.ximalaya.com"
	resp, err := c.Do(req)
	if err != nil {
		xmlyLastErr.Store(err.Error())
		return false
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	ok := strings.Contains(string(b), `"isVip":true`)
	if !ok {
		xmlyLastErr.Store(fmt.Sprintf("%d %s", resp.StatusCode, b))
	}
	return ok
}

// TestYouTubeBrWithXmlyAt6_7MB reproduces the device report: a ~1.5 MB (decoded) br protobuf player answer for
// the YouTube response script at 6.7 MB available while 喜马拉雅 script traffic runs concurrently. Before: budget
// (6.7−4)/3 = 0.9 MB → skipped, ads kept. Now it is processed — after making room (JavaScriptCore / cache
// garbage reclaimed: the normal budget), or, when nothing comes back, with the tight fallback — and the 喜马拉雅
// requests all go through meanwhile.
func TestYouTubeBrWithXmlyAt6_7MB(t *testing.T) {
	if raceEnabled {
		t.Skip("real scripts are too slow under the race detector")
	}
	player := ytBigPlayerCompressible(1536 << 10)
	br := brEncode(player)
	t.Logf("player %d KB decoded, br %d KB (estimate %d KB, low %d KB)", len(player)>>10, len(br)>>10,
		estimateDecoded(int64(len(br)), "br", 0)>>10, estimateLow(int64(len(br)), "br", 0)>>10)
	ytPlayerHandler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.Header().Set("Content-Encoding", "br")
		w.Header().Set("Content-Length", fmt.Sprint(len(br)))
		_, _ = w.Write(br)
	}
	defer func() { ytPlayerHandler = nil }()

	for _, tc := range []struct {
		name      string
		reclaimMB int64 // what the engine's reclaim gives back (JavaScriptCore garbage after the 喜马拉雅 burst)
	}{{"reclaim-frees-2.5MB", 5 << 19}, {"nothing-to-reclaim", 0}} {
		t.Run(tc.name, func(t *testing.T) {
			bodyHints.Lock()
			bodyHints.m = map[string]int64{}
			bodyHints.Unlock()
			tunnelConditions(t, 0, 20<<20) // warm-up: compile both scripts with room
			c, e := ytXmlyEngine(t)
			if !xmlyHomePage(c) {
				t.Fatal("xmly warm-up not unlocked")
			}
			if ok, _ := ytPost(t, c); !ok {
				t.Fatalf("youtube warm-up not stripped: %s", entryNotes(e))
			}
			// the device state: 6.7 MB available; reclaim (rate limited, as on the device) returns reclaimMB once
			var avail atomic.Int64
			avail.Store(6700 << 20 / 1000)
			SetAvailableMemoryProbe(func() int64 { return avail.Load() })
			var given atomic.Bool
			orig := reclaimHook.Load()
			hook := func() {
				if orig != nil {
					(*orig)()
				}
				if tc.reclaimMB > 0 && given.CompareAndSwap(false, true) {
					avail.Add(tc.reclaimMB)
				}
			}
			reclaimHook.Store(&hook)
			defer reclaimHook.Store(orig)
			lastReclaim.Store(0)
			w0, wok0 := largeWaits.Load(), largeWaitsOK.Load()

			var xok, xall atomic.Int64
			stop := make(chan struct{})
			var wg sync.WaitGroup
			// two 喜马拉雅 request loops (the app's pace: a request, a short pause); under memory pressure the
			// script queue admits one waiter (fix/xmly-memory-2), so back-to-back hammering would be skipped by
			// design whatever YouTube does
			for g := 0; g < 2; g++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						select {
						case <-stop:
							return
						default:
						}
						xall.Add(1)
						if xmlyHomePage(c) {
							xok.Add(1)
						}
						time.Sleep(100 * time.Millisecond)
					}
				}()
			}
			start := time.Now()
			var ok bool
			var n int
			base, peak := peakHeapDuring(func() { ok, n = ytPost(t, c) })
			took := time.Since(start)
			t.Logf("Go heap during the YouTube answer (Go path, with 喜马拉雅 running): %.1f → peak %.1f MB (+%.1f)", float64(base)/(1<<20), float64(peak)/(1<<20), float64(peak-base)/(1<<20))
			time.Sleep(200 * time.Millisecond)
			close(stop)
			wg.Wait()
			notes := entryNotes(e)
			t.Logf("youtube: stripped=%v, %d KB out in %d ms; large-body waits +%d (room found +%d); 喜马拉雅 %d/%d unlocked; available now %.1f MB",
				ok, n>>10, took.Milliseconds(), largeWaits.Load()-w0, largeWaitsOK.Load()-wok0, xok.Load(), xall.Load(), float64(avail.Load())/(1<<20))
			if !ok || strings.Contains(notes, "跳过脚本：youtube") {
				t.Fatalf("YouTube answer not processed at 6.7 MB: notes %q", notes)
			}
			if xok.Load() != xall.Load() || xall.Load() == 0 {
				var xn []string
				for _, s := range e.Requests.List(0) {
					if strings.Contains(s.URL, "/homePage/") && len(s.Notes) > 0 {
						xn = s.Notes
						break
					}
				}
				t.Fatalf("喜马拉雅 unlocked %d of %d while the large body waited; last %v; notes %q", xok.Load(), xall.Load(), xmlyLastErr.Load(), xn)
			}
			if took > largeBodyWait+3*time.Second {
				t.Fatalf("YouTube answer took %v", took)
			}
		})
	}
}

// TestLaneTooBigRetried: a chunked (length unknown) br body that decodes past the budget on the lane path is
// decoded again with a larger cap once room was made (the encoded bytes received so far replayed), instead of
// being passed through.
func TestLaneTooBigRetried(t *testing.T) {
	l := useFakeLane(t)
	_ = l
	player := ytBigPlayerCompressible(1536 << 10)
	br := brEncode(player)
	ytPlayerHandler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.Header().Set("Content-Encoding", "br")
		fl, _ := w.(http.Flusher)
		for off := 0; off < len(br); off += 64 << 10 { // chunked: no Content-Length
			_, _ = w.Write(br[off:min(off+64<<10, len(br))])
			if fl != nil {
				fl.Flush()
			}
		}
	}
	defer func() { ytPlayerHandler = nil }()
	bodyHints.Lock()
	bodyHints.m = map[string]int64{}
	bodyHints.Unlock()
	tunnelConditions(t, 0, 20<<20)
	c, e := ytXmlyEngine(t)
	if ok, _ := ytPost(t, c); !ok {
		t.Fatalf("warm-up not stripped: %s", entryNotes(e))
	}
	bodyHints.Lock()
	bodyHints.m = map[string]int64{} // first large answer at low memory: no hint yet
	bodyHints.Unlock()
	// 6 MB available (budget (6−3)/3 = 1 MB < 1.5 MB decoded); the reclaim gives 3 MB back
	var avail atomic.Int64
	avail.Store(6 << 20)
	SetAvailableMemoryProbe(func() int64 { return avail.Load() })
	orig := reclaimHook.Load()
	var given atomic.Bool
	hook := func() {
		if orig != nil {
			(*orig)()
		}
		if given.CompareAndSwap(false, true) {
			avail.Add(3 << 20)
		}
	}
	shortLargeBodyWait(t, 2*time.Second)
	r0, rok0 := largeRetries.Load(), largeRetriesOK.Load()
	// the first decode runs before the reclaim (the hook is installed only now and the 1 s rate limit is reset)
	reclaimHook.Store(&hook)
	defer reclaimHook.Store(orig)
	lastReclaim.Store(time.Now().UnixNano()) // not before the first decode
	lastFreeOS.Store(time.Now().UnixNano())
	ok, n := ytPost(t, c)
	t.Logf("chunked br %d KB → %d KB decoded: stripped=%v, %d KB out; lane retries +%d (ok +%d)", len(br)>>10, len(player)>>10, ok, n>>10,
		largeRetries.Load()-r0, largeRetriesOK.Load()-rok0)
	if laneUsable() == nil {
		t.Skip("lane not used in this configuration")
	}
	if !ok || largeRetriesOK.Load()-rok0 < 1 {
		t.Fatalf("not retried: stripped=%v notes %q", ok, entryNotes(e))
	}
}

// TestSelectiveTakesYouTubeAndXmlyHosts: with nativeMitmSelective (kinds 1) the YouTube response script's host is
// handed to the native front from its URL pattern; the 喜马拉雅 script's pattern hides its host (".+((ximalaya)|
// (xmcdn)).+(…\/…)"), so its connection host is learned from the first Go-path match. Other hosts stay on Go.
// (A body the native front hands back to Go is pulled without per-chunk garbage: flow_readbuf_test.go.)
func TestSelectiveTakesYouTubeAndXmlyHosts(t *testing.T) {
	tunnelConditions(t, 0, 20<<20)
	c, e := ytXmlyEngine(t)
	old := NativeSelective()
	SetNativeSelective(SelectiveHeavy)
	defer SetNativeSelective(old)
	if !e.selectiveWants("youtubei.googleapis.com") {
		t.Error("youtubei.googleapis.com not selected")
	}
	if e.selectiveWants("www.example.com") {
		t.Error("www.example.com selected")
	}
	if e.selectiveWants("180.153.10.20") {
		t.Error("喜马拉雅 IP selected before any match")
	}
	if raceEnabled {
		t.Skip("real 喜马拉雅 script is too slow under the race detector (CI 40119565072, 40121285371: homePage not unlocked in time)")
	}
	if !xmlyHomePage(c) {
		t.Fatalf("homePage not unlocked: %v", xmlyLastErr.Load())
	}
	if !e.selectiveWants("180.153.10.20") {
		t.Error("喜马拉雅 connection host not learned from the Go-path match")
	}
}
