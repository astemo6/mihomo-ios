package mitm

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
)

// v0.19.22 YouTube (user 2026-10-23 22:41: 「YouTube也有问题」): the script log showed
//   WARN youtube.response ×2 「跳过脚本：响应体解压后超过 2048 KB（Content-Encoding: br，压缩 812 KB）」
// and the ads came back. The Quantumult X rewrite (no max-size in QX syntax) got the fixed 2 MB cap.
// Now: the script's own max-size is honoured, no max-size / -1 get the dynamic budget (available
// memory above scriptAvailFloor / bodyCopyFactor, ≤ BodyHardMax), bodies above bigBodyThreshold go one
// at a time, and the skip WARN names the budget it used.

// ytBigPlayerCompressible is a ~size player answer whose padding compresses roughly like real
// protobuf (812 KB of br for ~3 MB on device).
func ytBigPlayerCompressible(size int) []byte {
	b := ytPlayerWithAds()
	pad := make([]byte, size)
	x := uint32(2463534242)
	words := [][]byte{[]byte("videoId"), []byte("https://i.ytimg.com/vi/"), []byte("thumbnail"), []byte("\x08\x96\x01"), []byte("title")}
	for i := 0; i < len(pad); {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		if x%3 == 0 {
			i += copy(pad[i:], words[x%uint32(len(words))])
		} else {
			pad[i] = byte(x >> 8)
			i++
		}
	}
	return pbBytes(b, 999, pad)
}

func brEncode(b []byte) []byte {
	var out bytes.Buffer
	w := brotli.NewWriterLevel(&out, 5)
	_, _ = w.Write(b)
	_ = w.Close()
	return out.Bytes()
}

// ytPost posts youtubei/v1/player and reports whether the answer came back without its ads.
func ytPost(t *testing.T, c *http.Client) (stripped bool, n int) {
	t.Helper()
	req, _ := http.NewRequest("POST", "https://youtubei.googleapis.com/youtubei/v1/player?prettyPrint=false", bytes.NewReader([]byte{0x0a, 0x00}))
	req.Header.Set("Content-Type", "application/x-protobuf")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	fs, err := pbTopFields(body)
	return err == nil && !hasField(fs, 7) && !hasField(fs, 68) && hasField(fs, 2), len(body)
}

func entryNotes(e *Engine) string {
	var notes []string
	for _, s := range e.Requests.List(0) {
		notes = append(notes, s.Notes...)
	}
	return strings.Join(notes, " | ")
}

// peakHeapDuring samples the heap while f runs (bytes above the level before).
func peakHeapDuring(f func()) (base, peak uint64) {
	runtime.GC()
	s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(s)
	base = s[0].Value.Uint64()
	peak = base
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tk := time.NewTicker(time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
			}
			metrics.Read(s)
			if v := s[0].Value.Uint64(); v > peak {
				peak = v
			}
		}
	}()
	f()
	close(stop)
	wg.Wait()
	return base, peak
}

func TestYouTube3MBUnderDynamicBudget(t *testing.T) {
	player := ytBigPlayerCompressible(3 << 20)
	br := brEncode(player)
	t.Logf("player %d KB, br %d KB", len(player)>>10, len(br)>>10)
	ytPlayerHandler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.Header().Set("Content-Encoding", "br")
		_, _ = w.Write(br)
	}
	defer func() { ytPlayerHandler = nil }()
	qx := map[string]string{"https://raw.githubusercontent.com/Maasea/sgmodule/refs/heads/master/Script/Youtube/youtube.response.js": "yt_youtube.response.js"}

	// A 50 MB extension with ~15 MB of headroom: the QX rewrite (no max-size) strips the ads from a
	// 3 MB br protobuf answer.
	for _, mod := range []struct{ file, url string }{{"yt_ddgksf2013_qx.conf", ytQXURL}, {"yt_enhance.sgmodule", ytModuleURL}} {
		t.Run("headroom-15MB/"+mod.file, func(t *testing.T) {
			tunnelConditions(t, 0, 15<<20)
			scripts := qx
			if strings.HasSuffix(mod.file, ".sgmodule") {
				scripts = map[string]string{ytResponseURL: "yt_youtube.response.js", ytRequestURL: "yt_youtube.request.js"}
			}
			c, _, e := ytEngineE(t, mod.file, mod.url, scripts)
			ytPost(t, c) // compile once
			var ok bool
			var n int
			base, peak := peakHeapDuring(func() { ok, n = ytPost(t, c) })
			t.Logf("%s: stripped=%v, %d KB out, heap %.1f → peak %.1f MB (+%.1f)", mod.file, ok, n>>10,
				float64(base)/(1<<20), float64(peak)/(1<<20), float64(peak-base)/(1<<20))
			if !ok {
				t.Fatalf("ads not stripped, notes %q", entryNotes(e))
			}
			if notes := entryNotes(e); strings.Contains(notes, "跳过脚本") {
				t.Fatalf("notes %q", notes)
			}
		})
	}

	// Really short of memory (8 MB available → budget (8-4)/3 ≈ 1.3 MB): passed through unchanged, and
	// the WARN says which budget it used.
	t.Run("headroom-8MB", func(t *testing.T) {
		tunnelConditions(t, 0, 8<<20)
		c, _, e := ytEngineE(t, "yt_ddgksf2013_qx.conf", ytQXURL, qx)
		ok, n := ytPost(t, c)
		if ok || n < 512<<10 {
			t.Fatalf("expected the original answer, stripped=%v len=%d", ok, n)
		}
		notes := entryNotes(e)
		if !strings.Contains(notes, "响应体解压后超过 1365 KB（当前内存预算 1365 KB，隧道可用 8.0 MB；Content-Encoding: br") {
			t.Fatalf("notes %q", notes)
		}
	})
}

// TestScriptMaxSizeHonoured: an explicit max-size is the script's limit (Surge / Loon semantics) even
// when the budget is larger; -1 and no max-size take the budget.
func TestScriptMaxSizeHonoured(t *testing.T) {
	tunnelConditions(t, 0, 30<<20) // budget (30-4)/3 ≈ 8.7 MB → BodyHardMax
	if got := scriptBodyLimit(&Script{MaxSize: 128 << 10}); got != 128<<10 {
		t.Fatalf("max-size 128 KB → %d", got)
	}
	if got := scriptBodyLimit(&Script{MaxSize: -1}); got != BodyHardMax {
		t.Fatalf("max-size -1 → %d", got)
	}
	if got := scriptBodyLimit(&Script{}); got != BodyHardMax {
		t.Fatalf("no max-size → %d", got)
	}
	if got := scriptBodyLimit(&Script{MaxSize: 64 << 20}); got != BodyHardMax {
		t.Fatalf("max-size 64 MB → %d", got)
	}
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`small = type=http-response,pattern=^https://api\.test\.com/echo,requires-body=1,max-size=1024,script-path=s.js`)}
	h := newHarness(t, cfg, map[string]string{"s.js": `$done({body: "patched"})`})
	_, body := h.do("POST", "https://api.test.com/echo", strings.Repeat("a", 4096))
	if body == "patched" || !strings.Contains(body, `"method":"POST"`) {
		t.Fatalf("max-size=1024 script ran on a 4 KB body: %q", clip(body, 40))
	}
	if notes := entryNotes(h.e); !strings.Contains(notes, "脚本 max-size 1 KB") {
		t.Fatalf("notes %q", notes)
	}
}

// TestBigBodiesOneAtATime: while another big body holds the lock past bigBodyWait the answer passes
// through unchanged with a note; once it is free the script runs.
func TestBigBodiesOneAtATime(t *testing.T) {
	old := bigBodyWait
	bigBodyWait = 200 * time.Millisecond
	defer func() { bigBodyWait = old }()
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`big = type=http-response,pattern=^https://api\.test\.com/echo,requires-body=1,max-size=-1,script-path=s.js`)}
	h := newHarness(t, cfg, map[string]string{"s.js": `$done({body: "len=" + $response.body.length})`})
	payload := strings.Repeat("a", 1500<<10)
	rel := acquireBigBody(context.Background())
	if rel == nil {
		t.Fatal("lock busy at start")
	}
	_, body := h.do("POST", "https://api.test.com/echo", payload)
	if !strings.Contains(body, `"method":"POST"`) || len(body) < 1500<<10 {
		t.Fatalf("expected pass-through while the lock is held, got %q", clip(body, 40))
	}
	if notes := entryNotes(h.e); !strings.Contains(notes, "另一个大响应体正在处理") {
		t.Fatalf("notes %q", notes)
	}
	rel()
	_, body = h.do("POST", "https://api.test.com/echo", payload)
	if !strings.HasPrefix(body, "len=") {
		t.Fatalf("script did not run once the lock was free: %q", clip(body, 40))
	}
	if len(bigBodyLock) != 0 {
		t.Fatal("lock still held after the response")
	}
}

// TestDecodeBodyExactSize: large compressed bodies decode into a buffer of exactly their size, and the
// limit still fails instead of truncating.
func TestDecodeBodyExactSize(t *testing.T) {
	plain := ytBigPlayerCompressible(3 << 20)
	br := brEncode(plain)
	out, err := decodeBody("br", br, 4<<20)
	if err != nil || !bytes.Equal(out, plain) || cap(out) != len(plain) {
		t.Fatalf("err %v len %d cap %d", err, len(out), cap(out))
	}
	if _, err := decodeBody("br", br, 2<<20); err != errBodyTooBig {
		t.Fatalf("limit: %v", err)
	}
	var allocs uint64
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	before := ms.TotalAlloc
	_, _ = decodeBody("br", br, 4<<20)
	runtime.ReadMemStats(&ms)
	allocs = ms.TotalAlloc - before
	// io.ReadAll's doubling allocated ~2.5× the body; exact sizing ~1× plus the decoder's window.
	if !raceEnabled && allocs > uint64(len(plain))*3/2+(4<<20) {
		t.Fatalf("decode allocated %d KB for a %d KB body", allocs>>10, len(plain)>>10)
	}
	t.Logf("decode of %d KB allocated %d KB", len(plain)>>10, allocs>>10)
}

// TestTextModeBodyLazy: a text-mode script that only reads bodyBytes never pays for the string; one
// that changes body / bodyBytes or leaves them alone still gets the right result.
func TestTextModeBodyLazy(t *testing.T) {
	bin := []byte{0xff, 0xfe, 0x00, 'a', 0x80}
	cases := []struct {
		name, js string
		want     []byte
	}{
		{"untouched-done-response", `$done($response)`, bin},
		{"bytes-only", `var u = new Uint8Array($response.bodyBytes); u[0] = 1; $done({bodyBytes: u.buffer})`, append([]byte{1}, bin[1:]...)},
		{"set-body", `$response.body = "x"; $done($response)`, []byte("x")},
		{"set-body-same", `$response.body = $response.body; $done($response)`, bin},
		{"set-bytes", `$response.bodyBytes = new Uint8Array([7,8]).buffer; $done($response)`, []byte{7, 8}},
		{"read-body-done-response", `var s = $response.body; $done($response)`, bin},
		{"spread", `$done({...$response, body: $response.body + "!"})`, []byte(bodyString(bin) + "!")},
		{"delete-and-set", `delete $response.body; $response.body = "y"; $done($response)`, []byte("y")},
		{"bytes-read-body-set", `var b = $response.bodyBytes; $response.body = "z"; $done($response)`, []byte("z")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := New(t.TempDir(), nil, nil)
			sc := &Script{Name: "t", Type: "http-response", Path: "t.js", RequiresBody: true, Source: []byte(c.js)}
			rule := &Rule{Kind: KindScript, Phase: "response", Script: sc}
			res, err := e.scripts.Run(context.Background(), rule, &ScriptHTTP{URL: "https://x/", Method: "GET", Header: http.Header{}},
				&ScriptHTTP{Status: 200, Header: http.Header{}, Body: bin, HasBody: true})
			if err != nil {
				t.Fatal(err)
			}
			got := res.Body
			if !res.BodySet {
				got = bin // the handler keeps the original
			}
			if !bytes.Equal(got, c.want) {
				t.Fatalf("got %q (set=%v), want %q", got, res.BodySet, c.want)
			}
		})
	}
}

// simulatedExtension makes the available-memory probe follow the Go heap: headroom bytes above the
// current level, shrinking as the heap (objects + unused spans + stacks) grows — the 50 MB extension
// with ~15 MB left. GOMEMLIMIT goes to the level plus 60 % of the headroom (the device: 30 of 50 MB).
func simulatedExtension(t *testing.T, headroom int64) {
	t.Helper()
	sample := func() int64 {
		s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}, {Name: "/memory/classes/heap/unused:bytes"}, {Name: "/memory/classes/heap/stacks:bytes"}}
		metrics.Read(s)
		return int64(s[0].Value.Uint64() + s[1].Value.Uint64() + s[2].Value.Uint64())
	}
	runtime.GC()
	base := sample()
	oldGo := debug.SetMemoryLimit(base + headroom*6/10)
	oldLimit := memGuardLimit
	memGuardLimit = func() int64 { return base + headroom*6/10 }
	SetAvailableMemoryProbe(func() int64 { return headroom - (sample() - base) })
	t.Cleanup(func() {
		SetAvailableMemoryProbe(nil)
		debug.SetMemoryLimit(oldGo)
		memGuardLimit = oldLimit
		lastHeapGC.Store(0)
		lastFreeOS.Store(0)
	})
}

// TestYouTube3MBSimulatedExtension: with the probe following the heap (15 MB of headroom, a soft limit
// at 9 MB above the level) the 3 MB answer is either stripped or — if the script itself needs more than
// the extension has — interrupted by the memory guard and passed through; the heap never goes past the
// headroom.
func TestYouTube3MBSimulatedExtension(t *testing.T) {
	player := ytBigPlayerCompressible(3 << 20)
	br := brEncode(player)
	ytPlayerHandler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.Header().Set("Content-Encoding", "br")
		_, _ = w.Write(br)
	}
	defer func() { ytPlayerHandler = nil }()
	for _, mod := range []struct{ file, url string }{{"yt_ddgksf2013_qx.conf", ytQXURL}, {"yt_enhance.sgmodule", ytModuleURL}} {
		t.Run(mod.file, func(t *testing.T) {
			scripts := map[string]string{"https://raw.githubusercontent.com/Maasea/sgmodule/refs/heads/master/Script/Youtube/youtube.response.js": "yt_youtube.response.js"}
			if strings.HasSuffix(mod.file, ".sgmodule") {
				scripts = map[string]string{ytResponseURL: "yt_youtube.response.js", ytRequestURL: "yt_youtube.request.js"}
			}
			c, _, e := ytEngineE(t, mod.file, mod.url, scripts)
			ytPost(t, c) // compile once (before the simulation, like a warm extension)
			simulatedExtension(t, 15<<20)
			var ok bool
			base, peak := peakHeapDuring(func() { ok, _ = ytPost(t, c) })
			t.Logf("%s: stripped=%v, heap %.1f → peak %.1f MB (+%.1f), notes %q", mod.file, ok,
				float64(base)/(1<<20), float64(peak)/(1<<20), float64(peak-base)/(1<<20), entryNotes(e))
			if peak-base > 15<<20 {
				t.Fatalf("heap went %.1f MB above the level with 15 MB of headroom", float64(peak-base)/(1<<20))
			}
		})
	}
}
