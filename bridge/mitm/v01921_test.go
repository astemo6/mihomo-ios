package mitm

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"encoding/json"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/dop251/goja"
)

// v0.19.21 喜马拉雅 / YouTube on device (v0.19.20, iOS 18.7.8): the script log showed
//   ERROR ximalaya「脚本过大（0.3 MB），在隧道内编译约需 28 MB 内存，超出 iOS 网络扩展的内存上限（26 MB），已跳过」
//   WARN  ximalaya「响应体超过上限或编码不支持，跳过脚本」
// and the request detail only 「脚本错误：ximalaya」. The gates compared the Go heap with GOMEMLIMIT (26 MB,
// the GC's soft target) instead of what iOS allows the extension (~50 MB). These tests reproduce the
// device state (26 MB soft limit, ~19 MB of live core heap) and check the gates now go by the
// extension's available memory (os_proc_available_memory through the bridge's probe).

// tunnelConditions emulates the extension: memGuardLimit / GOMEMLIMIT at 26 MB and live MB of heap held
// by "the core". avail < 0: no probe (old heuristics); else the probe reports avail bytes.
func tunnelConditions(t *testing.T, liveMB int, avail int64) {
	t.Helper()
	oldLimit := memGuardLimit
	memGuardLimit = func() int64 { return 26 << 20 }
	oldGo := debug.SetMemoryLimit(26 << 20)
	ballast := make([][]byte, liveMB)
	for i := range ballast {
		ballast[i] = make([]byte, 1<<20)
		ballast[i][0] = 1
	}
	if avail >= 0 {
		var a atomic.Int64
		a.Store(avail)
		SetAvailableMemoryProbe(func() int64 { return a.Load() })
	} else {
		SetAvailableMemoryProbe(nil)
	}
	t.Cleanup(func() {
		runtime.KeepAlive(ballast)
		memGuardLimit = oldLimit
		debug.SetMemoryLimit(oldGo)
		SetAvailableMemoryProbe(nil)
		lastHeapGC.Store(0)
		lastFreeOS.Store(0)
	})
}

type xmlyRig struct {
	e *Engine
	c *http.Client
}

func newXmlyRig(t *testing.T) *xmlyRig {
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
	mux := http.NewServeMux()
	mux.HandleFunc("/mobile-user/v2/homePage/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		_, _ = io.WriteString(w, `{"ret":0,"msg":"成功","data":{"uid":1,"nickname":"tester","isVip":false,"vipStatus":0,"vipInfo":{"isVip":false},"svipInfo":{"isVip":false}}}`)
	})
	up := httptest.NewUnstartedServer(mux)
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
	cfg := &Config{Enabled: true, MitM: true, SkipCertVerify: true, Modules: []Module{{ID: "xmly", Name: "喜马拉雅解锁@tg/giegie777", URL: ximalayaURL, Enabled: true}}}
	e.Reload(cfg, Build(home, cfg))
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", e.Port()))
	tr := &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true}
	return &xmlyRig{e: e, c: &http.Client{Transport: tr, Timeout: 60 * time.Second}}
}

// homePage fetches the VIP-gated homePage through the engine: unlocked + the entry's notes.
func (x *xmlyRig) homePage(t *testing.T) (bool, []string) {
	t.Helper()
	seq := x.e.Requests.List(0)
	_ = seq
	req, _ := http.NewRequest("GET", "https://180.153.10.20/mobile-user/v2/homePage/1792747994306?device=iPhone", nil)
	req.Host = "mobile.ximalaya.com"
	resp, err := x.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var v struct {
		Data struct {
			IsVip     bool `json:"isVip"`
			VipStatus int  `json:"vipStatus"`
		} `json:"data"`
	}
	ok := json.Unmarshal(b, &v) == nil && v.Data.IsVip && v.Data.VipStatus != 0
	var notes []string
	for _, s := range x.e.Requests.List(0) {
		if strings.Contains(s.URL, "/homePage/") {
			notes = s.Notes
			break // newest first
		}
	}
	return ok, notes
}

func TestXimalayaTunnelMemoryGates(t *testing.T) {
	if raceEnabled {
		t.Skip("real ximalaya script is too slow under the race detector")
	}
	// 1. Device state before the fix (no probe): the GOMEMLIMIT gates refuse the script.
	t.Run("old-heuristic-reproduces-device", func(t *testing.T) {
		tunnelConditions(t, 19, -1)
		x := newXmlyRig(t)
		ok, notes := x.homePage(t)
		joined := strings.Join(notes, " | ")
		if ok || !(strings.Contains(joined, "脚本错误：ximalaya — 脚本过大") || strings.Contains(joined, "跳过脚本：ximalaya — 内存紧张")) {
			t.Fatalf("expected the device refusal, ok=%v notes=%q", ok, notes)
		}
		t.Logf("no probe, 26 MB soft limit, 19 MB live: notes %q", notes)
	})
	// 2. Same heap, but iOS still allows 20 MB: compiled once, unlocked, no note; the second request
	// reuses the cached program (no recompile), also after a MemoryGuard FreeMemory (DropCaches).
	t.Run("available-memory", func(t *testing.T) {
		tunnelConditions(t, 19, 20<<20)
		x := newXmlyRig(t)
		c0 := compileCount.Load()
		for i := 0; i < 3; i++ {
			ok, notes := x.homePage(t)
			if !ok || len(notes) != 0 {
				t.Fatalf("run %d: unlocked=%v notes=%q", i, ok, notes)
			}
			x.e.DropCaches()
		}
		if n := compileCount.Load() - c0; n != 1 {
			t.Fatalf("compiled %d times for 3 requests, want 1", n)
		}
	})
	// 3. Really short of memory (3 MB left): skipped with the reason in the script log and the note.
	t.Run("short-of-memory", func(t *testing.T) {
		tunnelConditions(t, 0, 3<<20)
		x := newXmlyRig(t)
		ok, notes := x.homePage(t)
		joined := strings.Join(notes, " | ")
		if ok || !strings.Contains(joined, "跳过脚本：ximalaya — 内存紧张（隧道可用 3.0 MB）") {
			t.Fatalf("ok=%v notes=%q", ok, notes)
		}
		var logged bool
		for _, l := range x.e.Logs.List(0, "ximalaya") {
			logged = logged || strings.Contains(l.Msg, "跳过脚本：内存紧张（隧道可用 3.0 MB）")
		}
		if !logged {
			t.Fatalf("script log lacks the reason: %+v", x.e.Logs.List(0, ""))
		}
	})
	// 4. Enough for a body but not for the compile (8 MB < 11 MB estimate + 4 MB reserve).
	t.Run("compile-gate", func(t *testing.T) {
		tunnelConditions(t, 0, 8<<20)
		x := newXmlyRig(t)
		ok, notes := x.homePage(t)
		joined := strings.Join(notes, " | ")
		if ok || !strings.Contains(joined, "脚本错误：ximalaya — 脚本过大（0.3 MB），编译约需 11 MB 内存，隧道当前可用 8 MB") {
			t.Fatalf("ok=%v notes=%q", ok, notes)
		}
	})
}

// TestYouTubeTunnelMemoryGates: youtube.response.js (133 KB, under the large-bundle gate) was skipped by
// the body gate on device (heap incl. garbage > 70 % of 26 MB); with the probe it strips the ads.
func TestYouTubeTunnelMemoryGates(t *testing.T) {
	t.Run("old-heuristic-reproduces-device", func(t *testing.T) {
		tunnelConditions(t, 19, -1)
		c, _, e := ytEngineE(t, "yt_ddgksf2013_qx.conf", ytQXURL, map[string]string{
			"https://raw.githubusercontent.com/Maasea/sgmodule/refs/heads/master/Script/Youtube/youtube.response.js": "yt_youtube.response.js"})
		req, _ := http.NewRequest("POST", "https://youtubei.googleapis.com/youtubei/v1/player?prettyPrint=false", bytes.NewReader([]byte{0x0a, 0x00}))
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		var notes []string
		for _, s := range e.Requests.List(0) {
			notes = append(notes, s.Notes...)
		}
		if !strings.Contains(strings.Join(notes, " "), "内存紧张") {
			t.Fatalf("expected the body gate to skip the script under the old heuristic, notes %q", notes)
		}
	})
	t.Run("available-memory", func(t *testing.T) {
		tunnelConditions(t, 19, 20<<20)
		c, _ := ytEngine(t, "yt_ddgksf2013_qx.conf", ytQXURL, map[string]string{
			"https://raw.githubusercontent.com/Maasea/sgmodule/refs/heads/master/Script/Youtube/youtube.response.js": "yt_youtube.response.js"})
		ytPlayerStripped(t, c)
		ytBrowseStripped(t, c)
	})
}

// TestScriptErrorNote: the request detail shows the error and its position, not only the script name.
func TestScriptErrorNote(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`^https://api\.test\.com/json url script-response-body boom.js`)}
	h := newHarness(t, cfg, map[string]string{"boom.js": "var o = JSON.parse($response.body);\nnull.x = 1;\n$done({})"})
	h.get("https://api.test.com/json")
	var notes []string
	for _, s := range h.e.Requests.List(0) {
		notes = append(notes, s.Notes...)
	}
	j := strings.Join(notes, " | ")
	if !strings.Contains(j, "脚本错误：boom — 脚本异常：TypeError") || !strings.Contains(j, "boom.js:3") {
		t.Fatalf("note %q", j)
	}
	if got := scriptErrNote("x", fmt.Errorf("第一行\n第二行")); got != "脚本错误：x — 第一行" {
		t.Fatalf("%q", got)
	}
	if got := scriptErrNote("x", fmt.Errorf("%s", strings.Repeat("错", 300))); !strings.HasSuffix(got, "…") || !strings.Contains(got, strings.Repeat("错", 160)) {
		t.Fatalf("clip %q", got)
	}
}

// TestBodyDecodings: br, gzip, zlib-deflate, raw-deflate and stacked codings reach body scripts decoded.
func TestBodyDecodings(t *testing.T) {
	plain := []byte(`{"ret":0,"data":{"isVip":false}}`)
	var zb, fb, bb bytes.Buffer
	zw := zlib.NewWriter(&zb)
	zw.Write(plain)
	zw.Close()
	fw, _ := flate.NewWriter(&fb, 5)
	fw.Write(plain)
	fw.Close()
	bw := brotli.NewWriter(&bb)
	bw.Write(plain)
	bw.Close()
	var gzbr bytes.Buffer // "gzip, br": gzip first, then br
	gzipped := gz(plain)
	bw2 := brotli.NewWriter(&gzbr)
	bw2.Write(gzipped)
	bw2.Close()
	for enc, b := range map[string][]byte{"br": bb.Bytes(), "gzip": gzipped, "deflate": zb.Bytes(), "Deflate": fb.Bytes(), "gzip, br": gzbr.Bytes(), "identity": plain} {
		got, err := decodeBody(enc, b, MaxBody)
		if err != nil || !bytes.Equal(got, plain) {
			t.Errorf("%s: %v %q", enc, err, got)
		}
	}
	if _, err := decodeBody("compress", []byte("x"), MaxBody); err == nil {
		t.Error("unknown coding accepted")
	}
}

// TestCompileMemoryMeasured documents the compile cost the gate's estimate (32× source) rests on.
func TestCompileMemoryMeasured(t *testing.T) {
	if raceEnabled {
		t.Skip()
	}
	heap := func() uint64 {
		s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
		metrics.Read(s)
		return s[0].Value.Uint64()
	}
	for _, f := range []string{"testdata/ximalaya_weigiegie.js", "testdata/yt_youtube.response.js"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		runtime.GC()
		base := heap()
		old := debug.SetGCPercent(-1) // nothing collected: the peak is everything compile allocates
		p, err := goja.Compile("x.js", "(function(){\n"+string(src)+"\n}).call(this);", false)
		peak := heap() - base
		debug.SetGCPercent(old)
		if err != nil {
			t.Fatal(err)
		}
		runtime.GC()
		kept := heap() - base
		runtime.KeepAlive(p)
		t.Logf("%s: %d KB source → compile peak %.1f MB (%.0f×), program %.1f MB (%.1f×)", filepath.Base(f), len(src)>>10,
			float64(peak)/(1<<20), float64(peak)/float64(len(src)), float64(kept)/(1<<20), float64(kept)/float64(len(src)))
		if len(src) >= largeProgSource && peak > uint64(len(src))*compileBytesPerSourceByte {
			t.Errorf("compile peak %d over the gate's estimate %d", peak, len(src)*compileBytesPerSourceByte)
		}
		if kept > uint64(len(src))*progBytesPerSourceByte {
			t.Errorf("program %d over the cache's estimate %d", kept, len(src)*progBytesPerSourceByte)
		}
	}
}

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

// TestLogRingFolds: a script logging the same lines every run (Apple WLOC) folds into one line each with
// a count; other scripts in between stop the fold; warn / error lines fold the same way but stay.
func TestLogRingFolds(t *testing.T) {
	l := NewLogRing(500)
	for i := 0; i < 30; i++ {
		l.Add("Apple WLOC", "log", "[settings] passthrough mode")
		l.Add("Apple WLOC", "log", "[wloc] Response unchanged")
		l.Add("Apple WLOC", "log", "Done!")
		l.Add("Apple WLOC", "debug", fmt.Sprintf("执行完成，用时 %d ms", i))
	}
	got := l.List(0, "")
	if len(got) != 4 {
		t.Fatalf("%d lines: %+v", len(got), got)
	}
	for _, g := range got {
		if g.Count != 30 {
			t.Fatalf("count %+v", g)
		}
	}
	if got[3].Msg != "执行完成，用时 29 ms" {
		t.Fatalf("newest debug text kept: %q", got[3].Msg)
	}
	l.Add("ximalaya", "error", "脚本过大")
	l.Add("Apple WLOC", "log", "Done!") // another script in between: no fold
	l.Add("ximalaya", "error", "脚本过大")
	if n := len(l.List(0, "")); n != 7 {
		t.Fatalf("%d lines, want 7", n)
	}
	since := l.Seq()
	l.Add("ximalaya", "error", "脚本过大")
	if nl := l.List(since, ""); len(nl) != 1 || nl[0].Count != 2 {
		t.Fatalf("folded line must be new for List(since): %+v", nl)
	}
}

// ytBigPlayer is ytPlayerWithAds padded to ~size bytes (an unknown field the script carries along).
func ytBigPlayer(size int) []byte {
	b := ytPlayerWithAds()
	pad := make([]byte, size)
	x := uint32(2463534242)
	for i := range pad { // xorshift: not compressible to nothing, like real player responses
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		pad[i] = byte(x)
	}
	return pbBytes(b, 999, pad)
}

// TestYouTubeLargeBrotliUnderTunnelLimit: on device YouTube's player / browse answers (0.5–2 MB
// protobuf, br over HTTP/2) were skipped several times a second with 「响应体超过上限或编码不支持」. Here:
// 1.5 MB br-encoded player responses (with and without Content-Length), four at once, under the
// tunnel's 26 MB soft limit with 19 MB of live core heap and 20 MB available: every one is stripped.
func TestYouTubeLargeBrotliUnderTunnelLimit(t *testing.T) {
	player := ytBigPlayer(1500 << 10)
	var br bytes.Buffer
	bw := brotli.NewWriterLevel(&br, 5)
	bw.Write(player)
	bw.Close()
	ytPlayerHandler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.Header().Set("Content-Encoding", "br")
		if r.URL.Query().Get("cl") == "1" {
			w.Header().Set("Content-Length", fmt.Sprint(br.Len()))
		}
		_, _ = w.Write(br.Bytes())
	}
	defer func() { ytPlayerHandler = nil }()
	run := func(t *testing.T) (stripped int, notes []string) {
		c, _, e := ytEngineE(t, "yt_enhance.sgmodule", ytModuleURL, map[string]string{
			ytResponseURL: "yt_youtube.response.js", ytRequestURL: "yt_youtube.request.js"})
		type res struct {
			ok  bool
			err error
		}
		ch := make(chan res, 4)
		for i := 0; i < 4; i++ {
			go func(i int) {
				req, _ := http.NewRequest("POST", fmt.Sprintf("https://youtubei.googleapis.com/youtubei/v1/player?prettyPrint=false&cl=%d", i%2), bytes.NewReader([]byte{0x0a, 0x00}))
				req.Header.Set("Content-Type", "application/x-protobuf")
				resp, err := c.Do(req)
				if err != nil {
					ch <- res{err: err}
					return
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				fs, err := pbTopFields(body)
				ch <- res{ok: err == nil && !hasField(fs, 7) && !hasField(fs, 68) && hasField(fs, 2) && len(body) > 1<<20}
			}(i)
		}
		for i := 0; i < 4; i++ {
			r := <-ch
			if r.err != nil {
				t.Fatal(r.err)
			}
			if r.ok {
				stripped++
			}
		}
		for _, s := range e.Requests.List(0) {
			notes = append(notes, s.Notes...)
		}
		return
	}
	t.Run("old-heuristic-reproduces-device", func(t *testing.T) {
		tunnelConditions(t, 19, -1)
		n, notes := run(t)
		if n == 4 {
			t.Fatalf("expected skips under the old heuristics, notes %q", notes)
		}
		t.Logf("no probe: %d/4 stripped, notes %q", n, notes)
	})
	t.Run("available-memory", func(t *testing.T) {
		tunnelConditions(t, 19, 20<<20)
		n, notes := run(t)
		if n != 4 || len(notes) != 0 {
			t.Fatalf("%d/4 stripped, notes %q", n, notes)
		}
	})
}

// TestBodyBudgetChargesRealSize: an encoded / unknown-length body charges what it takes, not the cap,
// and the budget grows with available memory in the extension.
func TestBodyBudgetChargesRealSize(t *testing.T) {
	if u := bodyBudget.inUse(); u != 0 {
		t.Fatalf("budget in use at start: %d", u)
	}
	c := &bodyCharge{ctx: context.Background()}
	if err := c.ensure(bodyBudgetChunk); err != nil {
		t.Fatal(err)
	}
	if err := c.ensure(1500 << 10); err != nil {
		t.Fatal(err)
	}
	if u := bodyBudget.inUse(); u != 1500<<10 {
		t.Fatalf("in use %d", u)
	}
	c.release()
	c.release()
	if u := bodyBudget.inUse(); u != 0 {
		t.Fatalf("after release %d", u)
	}
	if bodyBudget.capNow() != bodyBudgetBytes {
		t.Fatalf("no probe: cap %d", bodyBudget.capNow())
	}
	SetAvailableMemoryProbe(func() int64 { return 30 << 20 })
	defer SetAvailableMemoryProbe(nil)
	if got := bodyBudget.capNow(); got != 12<<20 {
		t.Fatalf("30 MB available: cap %d, want 12 MB", got)
	}
}

// TestWarmScriptRunIsFast: a 200 KB body script (below the large-bundle size, like the 小红书 ad scripts)
// compiles once; warm runs reuse the program and take well under 50 ms.
func TestWarmScriptRunIsFast(t *testing.T) {
	if raceEnabled {
		t.Skip()
	}
	var src strings.Builder
	src.WriteString("var o = JSON.parse($response.body); o.ads = []; ")
	for i := 0; src.Len() < 200<<10; i++ {
		fmt.Fprintf(&src, "function f%d(a){ return a.map(function(x){ return x + %d }) }\n", i, i)
	}
	src.WriteString("$done({body: JSON.stringify(o)})")
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`^https://api\.test\.com/json url script-response-body feed.js`)}
	h := newHarness(t, cfg, map[string]string{"feed.js": src.String()})
	tunnelConditions(t, 16, 20<<20)
	c0 := compileCount.Load()
	var warm []time.Duration
	for i := 0; i < 6; i++ {
		t0 := time.Now()
		_, b := h.get("https://api.test.com/json")
		d := time.Since(t0)
		if !strings.Contains(b, `"ads":[]`) {
			t.Fatalf("not edited: %.100s", b)
		}
		if i > 0 {
			warm = append(warm, d)
		}
		h.e.DropCaches() // MemoryGuard FreeMemory between requests must not force a recompile
	}
	if n := compileCount.Load() - c0; n != 1 {
		t.Fatalf("compiled %d times, want 1", n)
	}
	for _, d := range warm {
		if d > 50*time.Millisecond {
			t.Errorf("warm run %v, want < 50 ms (all: %v)", d, warm)
		}
	}
	t.Logf("warm runs %v", warm)
}
