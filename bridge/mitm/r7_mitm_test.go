package mitm

// Review 7 (bridge/mitm lane) regression tests, from the probes in work/review7/mitm_probes.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// P2-1: large-bundle HTTP scripts waiting for the large-bundle lock must not hold the HTTP script slots.
func TestR7BigSemDoesNotHoldHTTPSlot(t *testing.T) {
	big := "var x = 1;\n" + strings.Repeat("// pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad\n", (largeProgSource/66)+10) + "$done({});"
	small := `$done({headers: Object.assign({}, $request.headers, {"X-Small": "1"})});`
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`big = type=http-request,pattern=^https://api\.test\.com/big,script-path=big.js,timeout=3`,
		`small = type=http-request,pattern=^https://api\.test\.com/echo,script-path=small.js,timeout=1`,
	)}
	h := newHarness(t, cfg, map[string]string{"big.js": big, "small.js": small})
	h.e.scripts.bigSem <- struct{}{} // a long-running large task holds the lock
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); h.get("https://api.test.com/big") }()
	}
	time.Sleep(300 * time.Millisecond)
	_, body := h.get("https://api.test.com/echo")
	<-h.e.scripts.bigSem
	wg.Wait()
	if !strings.Contains(strings.ToLower(body), "x-small") {
		for _, l := range h.e.Logs.List(0, "") {
			t.Logf("log %s %s %s", l.Script, l.Level, l.Msg)
		}
		t.Fatalf("small script did not run while large scripts waited for the large-bundle lock: %s", body)
	}
}

// P2-3: Egern body_rewrites get the RE2 fast path (a 600 KB body is rewritten, not skipped).
func TestR7EgernBodyRewriteFast(t *testing.T) {
	src := "name: x\nbody_rewrites:\n  - response_regex:\n      match: \"^https://a\\\\.com/\"\n      find: '\"ad\":true'\n      replace: '\"ad\":false'\n"
	rs := &Ruleset{}
	rs.ParseText(src, "eg", nil)
	var r *Rule
	for _, x := range rs.Rules {
		if x.Kind == KindBody {
			r = x
		}
	}
	if r == nil {
		t.Fatalf("no body rule: %+v %v", rs.Rules, rs.Errors)
	}
	if r.Body[0].fast == nil {
		t.Fatal("Egern body rewrite has no RE2 fast path")
	}
	body := bytes.Repeat([]byte(`{"ad":true},`), 600<<10/12)
	e := New(t.TempDir(), nil, nil)
	out, err := e.applyBodyRule(r, body)
	if err != nil {
		t.Fatalf("600 KB Egern rewrite: %v", err)
	}
	if bytes.Contains(out, []byte(`"ad":true`)) || !bytes.Contains(out, []byte(`"ad":false`)) {
		t.Fatal("not rewritten")
	}
}

// P3-1: HEAD through a requires-body response script keeps the upstream Content-Length.
func TestR7HeadKeepsContentLength(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`s = type=http-response,pattern=^https://api\.test\.com/h,requires-body=1,script-path=s.js`)}
	h := newHarness(t, cfg, map[string]string{"s.js": `$done({headers: $response.headers});`})
	h.up.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "12345")
		if r.Method != "HEAD" {
			_, _ = w.Write(make([]byte, 12345))
		}
	})
	req, _ := http.NewRequest("HEAD", "https://api.test.com/h", nil)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if cl := resp.Header.Get("Content-Length"); cl != "12345" {
		t.Fatalf("HEAD Content-Length = %q, want 12345", cl)
	}
	resp, body := h.get("https://api.test.com/h")
	if len(body) != 12345 || resp.Header.Get("Content-Length") != "12345" {
		t.Fatalf("GET: %d bytes, Content-Length %q", len(body), resp.Header.Get("Content-Length"))
	}
}

// P3-2: a response rule listed before a URL-changing request script matches the final URL.
func TestR7RespRulesMatchFinalURL(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(
		`http-response ^https://api\.test\.com/echo header-add X-Resp hit`),
		Scripts: items(`rw = type=http-request,pattern=^https://api\.test\.com/old,script-path=rw.js`)}
	h := newHarness(t, cfg, map[string]string{"rw.js": `$done({url: "https://api.test.com/echo"});`})
	resp, _ := h.get("https://api.test.com/old")
	if v := resp.Header.Get("X-Resp"); v != "hit" {
		t.Fatalf("rewritten request: X-Resp=%q", v)
	}
	resp, _ = h.get("https://api.test.com/echo")
	if v := resp.Header.Get("X-Resp"); v != "hit" {
		t.Fatalf("direct: X-Resp=%q", v)
	}
}

// P3-3: a response script that replaces the body without requires-body closes the upstream body, so the
// upstream HTTP/1.1 connection is reused.
func TestR7ReplacedUpstreamBodyClosed(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`s = type=http-response,pattern=^https://api\.test\.com/m,script-path=s.js`)}
	h := newHarness(t, cfg, map[string]string{"s.js": `$done({body: "mock"});`})
	var conns atomic.Int64
	payload := bytes.Repeat([]byte("x"), 64<<10)
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		_, _ = w.Write(payload)
	}))
	up.Config.ConnState = func(c net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	up.StartTLS() // HTTP/1.1 only
	defer up.Close()
	addr := up.Listener.Addr().String()
	h.e.dial = func(ctx context.Context, network, a, policy string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	h.e.tmu.Lock()
	h.e.transport = nil
	h.e.tmu.Unlock()
	for i := 0; i < 5; i++ {
		if _, b := h.get(fmt.Sprintf("https://api.test.com/m?%d", i)); b != "mock" {
			t.Fatalf("body %q", b)
		}
	}
	if n := conns.Load(); n != 1 {
		t.Fatalf("upstream connections for 5 sequential mocked requests: %d, want 1", n)
	}
}

// P3-4: a captured gzip response whose compressed size is over 32 KB still gets a text preview.
func TestR7CaptureGzipPreviewOver32K(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(`^https://api\.test\.com/none - reject`)}
	h := newHarness(t, cfg, nil)
	raw := make([]byte, 60<<10)
	_, _ = rand.Read(raw)
	text := []byte(hex.EncodeToString(raw)) // 120 KB text, ~60 KB gzip
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(text)
	_ = zw.Close()
	if gz.Len() <= captureLimit {
		t.Fatalf("fixture too small: %d", gz.Len())
	}
	h.up.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(gz.Bytes())
	})
	h.get("https://api.test.com/g")
	deadline := time.Now().Add(2 * time.Second)
	for {
		var got string
		for _, s := range h.e.Requests.List(0) {
			ent := h.e.Requests.Get(s.ID)
			ent.mu.Lock()
			if strings.HasSuffix(ent.URL, "/g") {
				got = ent.RespBodyS
			}
			ent.mu.Unlock()
		}
		if got != "" {
			if !strings.HasPrefix(string(text), got[:64]) {
				t.Fatalf("preview is not the decoded text: %q", got[:64])
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no text preview for a >32 KB gzip response")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// P3-5: two Store instances flushing at once never corrupt store.json (unique temp files).
func TestR7StoreConcurrentFlushNoCorruption(t *testing.T) {
	home := t.TempDir()
	_ = os.MkdirAll(EngineDir(home), 0o755)
	a, b := NewStore(home), NewStore(home)
	big := strings.Repeat("A", 3<<20)
	for i := 0; i < 30; i++ {
		a.Write("k", big+fmt.Sprint(i), false)
		b.Write("j", "small"+fmt.Sprint(i), false)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = a.Flush() }()
		go func() { defer wg.Done(); _ = b.Flush() }()
		wg.Wait()
		if _, err := os.Stat(filepath.Join(EngineDir(home), "store.json.bad")); err == nil {
			t.Fatalf("iter %d: store quarantined", i)
		}
		raw, _ := os.ReadFile(filepath.Join(EngineDir(home), "store.json"))
		var m map[string]string
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("iter %d: corrupt store.json (%d bytes): %v", i, len(raw), err)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(EngineDir(home), "*.tmp")); len(left) > 0 {
		t.Fatalf("temp files left: %v", left)
	}
}

// P3-5: a failed write keeps the pending change for the next flush.
func TestR7StoreFailedFlushKeepsPending(t *testing.T) {
	home := t.TempDir()
	_ = os.MkdirAll(EngineDir(home), 0o755)
	s := NewStore(home)
	s.Write("k", "v1", false)
	dir := EngineDir(home)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skip(err)
	}
	err := s.Flush()
	_ = os.Chmod(dir, 0o755)
	if err == nil {
		t.Skip("directory not read-only here (root?)")
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "store.json"))
	if !strings.Contains(string(raw), `"k":"v1"`) {
		t.Fatalf("pending change lost after a failed flush: %s", raw)
	}
}

// P3-6: a remote task / panel script that is not downloaded yet is sized after downloading (so its first
// run waits for the large-bundle lock), and Prefetch downloads task scripts too.
func TestR7TaskScriptsPrefetchedAndSized(t *testing.T) {
	big := "var x = 1;\n" + strings.Repeat("// pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad\n", (largeProgSource/66)+10) + "$done({});"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, big)
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	dial := func(ctx context.Context, network, a, policy string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	home := t.TempDir()
	e := New(home, dial, nil)
	tk := &Task{ID: "t1", Kind: "generic", Script: &Script{Name: "big", Path: "http://s.test/first.js", Timeout: 1}}
	e.scripts.bigSem <- struct{}{} // another large bundle is running
	_, err := e.scripts.RunTask(tk, nil, nil)
	<-e.scripts.bigSem
	if err == nil || !strings.Contains(err.Error(), "排队超时") {
		t.Fatalf("first run of an undownloaded large task script did not wait for the large-bundle lock: %v", err)
	}
	if _, err := os.Stat(CachePath(home, tk.Script.Path)); err != nil {
		t.Fatalf("not cached: %v", err)
	}

	rs := &Ruleset{Tasks: []*Task{{ID: "t2", Kind: "cron", Script: &Script{Name: "c", Path: "http://s.test/cron.js"}}}}
	e.res.Prefetch(rs)
	if _, err := os.Stat(CachePath(home, "http://s.test/cron.js")); err != nil {
		t.Fatalf("Prefetch skipped the task script: %v", err)
	}
}

// B29: an HTTP script stops when its client goes away instead of running to its timeout.
func TestR7ScriptStopsWhenClientGone(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`spin = type=http-request,pattern=^https://api\.test\.com/spin,script-path=spin.js,timeout=20`)}
	h := newHarness(t, cfg, map[string]string{"spin.js": `while (true) {}`})
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.test.com/spin", nil)
	if resp, err := h.client.Do(req); err == nil {
		resp.Body.Close()
	}
	deadline := time.Now().Add(3 * time.Second)
	for LiveRuntimes() > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("script still running %v after the client left", time.Since(deadline.Add(-3*time.Second)))
		}
		time.Sleep(20 * time.Millisecond)
	}
	found := false
	for _, l := range h.e.Logs.List(0, "") {
		if l.Script == "spin" && strings.Contains(l.Msg, "已停止") {
			found = true
		}
	}
	if !found {
		t.Fatal("no 已停止 log for the cancelled script")
	}
}

// P3-7: Engine.Stop cancels running task scripts.
func TestR7StopCancelsTaskScripts(t *testing.T) {
	home := t.TempDir()
	_ = os.MkdirAll(ScriptsDir(home), 0o755)
	_ = os.WriteFile(filepath.Join(ScriptsDir(home), "spin.js"), []byte(`while (true) {}`), 0o644)
	e := New(home, nil, nil)
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	tk := &Task{ID: "spin", Kind: "generic", Script: &Script{Name: "spin", Path: "spin.js", Timeout: 300}}
	done := make(chan error, 1)
	go func() { _, err := e.scripts.RunTask(tk, nil, nil); done <- err }()
	time.Sleep(300 * time.Millisecond)
	e.Stop()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "已停止") {
			t.Fatalf("task ended with %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("task script kept running after Engine.Stop")
	}
	// a later run on a restarted engine works again
	_ = os.WriteFile(filepath.Join(ScriptsDir(home), "ok.js"), []byte(`$done({})`), 0o644)
	if _, err := e.scripts.RunTask(&Task{ID: "ok", Kind: "generic", Script: &Script{Name: "ok", Path: "ok.js"}}, nil, nil); err != nil {
		t.Fatalf("run after stop: %v", err)
	}
}

// P3-8: Status (/mitm/status) while the engine stops and starts — must be race-free (run with -race).
func TestR7StatusVsStopNoRace(t *testing.T) {
	e := New(t.TempDir(), nil, nil)
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				st := e.Status()
				if st.Running != (st.Port != 0) {
					t.Errorf("inconsistent status %+v", st)
					return
				}
			}
		}
	}()
	for i := 0; i < 20; i++ {
		e.Stop()
		if err := e.Start(); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	e.Stop()
	if e.Status().Running || e.Port() != 0 {
		t.Fatal("still running after Stop")
	}
}

// OPT-1: URL patterns RE2 can take are matched on RE2, with the same result as regexp2.
func TestR7URLMatchRE2SameAsRegexp2(t *testing.T) {
	pats := []string{
		`^https?:\/\/api\d\.example\.com\/v1\/(ad|banner|splash)\/.+`,
		`^https://a\.com/x$`,
		`\.(js|css)$`,
		`^https?://(www\.)?youtube\.com/api/stats/ads`,
		`(?i)^HTTPS://B\.COM/`,
		`^https://c\.com/(?<id>\d+)`,
		`^https://d\.com/[^/]+/feed\?`,
		`^https://e\.com/\w+-\d{2,4}`,
		`^https://(?!keep\.)f\.com/`, // lookahead → regexp2
		`^https://g\.com/(a)\1`,      // backreference → regexp2
		`\bad\b`,                     // word boundary → regexp2
		`[a-z-[aeiou]]x`,             // .NET class subtraction → regexp2
	}
	urls := []string{
		"https://api1.example.com/v1/ad/x", "http://api9.example.com/v1/banner/1?z", "https://api1.example.com/v2/ad/x",
		"https://a.com/x", "https://a.com/x/", "https://a.com/x?y", "https://cdn.test/app.js", "https://cdn.test/app.js?v=1",
		"https://www.youtube.com/api/stats/ads?x", "https://b.com/z", "https://c.com/123", "https://d.com/u/feed?x",
		"https://e.com/abc-123", "https://f.com/", "https://keep.f.com/", "https://g.com/aa", "https://h.com/ad",
		"https://b.com/bx",
	}
	fast := 0
	for _, p := range pats {
		rs := &Ruleset{}
		rs.ParseLine(p+" - reject", "", "u")
		if len(rs.Rules) != 1 {
			t.Fatalf("%s: %v", p, rs.Errors)
		}
		r := rs.Rules[0]
		if r.fre != nil {
			fast++
		}
		for _, u := range urls {
			got := r.match(u)
			want, _ := r.re.MatchString(u)
			if got != want {
				t.Errorf("%s on %s: fast=%v got %v want %v", p, u, r.fre != nil, got, want)
			}
		}
	}
	if fast != 8 {
		t.Errorf("RE2 path taken for %d of the 8 RE2-compatible patterns", fast)
	}
}

func BenchmarkR7URLMatch300(b *testing.B) {
	rs := &Ruleset{}
	for i := 0; i < 300; i++ {
		rs.ParseLine(fmt.Sprintf(`^https?:\/\/api%d\.example\.com\/v1\/(ad|banner|splash)\/.+ - reject`, i), "", "u")
	}
	u := "https://api.real-host.com/v2/feed/timeline?cursor=abcdefghijklmnopqrstuvwxyz0123456789&count=20&include_entities=true"
	req, _ := http.NewRequest("GET", u, nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for k := 0; k < 3; k++ { // URL, map-local and phase loops each walk the rules
			for _, r := range rs.Rules {
				r.matchReq(u, req)
			}
		}
	}
}

// B26: a large map-local file is streamed from disk instead of being read into memory per request.
func TestR7LargeMapLocalStreamed(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(
		`^https://api\.test\.com/big data="big.json" header="X-From:map"`)}
	payload := strings.Repeat(`{"k":"v"},`, 4<<20/10)
	h := newHarness(t, cfg, map[string]string{"big.json": payload})
	rs := Build(h.home, cfg)
	if len(rs.Rules) != 1 || rs.Rules[0].Kind != KindMapLocal || rs.Rules[0].DataType != "file" {
		t.Fatalf("rule: %+v %v", rs.Rules, rs.Errors)
	}
	get := func() {
		resp, err := h.client.Get("https://api.test.com/big")
		if err != nil {
			t.Fatal(err)
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if n != int64(len(payload)) || resp.Header.Get("Content-Length") != strconv.Itoa(len(payload)) ||
			resp.Header.Get("X-From") != "map" || resp.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("got %d bytes, headers %v", n, resp.Header)
		}
	}
	get() // warm up connections
	var a, b runtime.MemStats
	runtime.ReadMemStats(&a)
	for i := 0; i < 3; i++ {
		get()
	}
	runtime.ReadMemStats(&b)
	if d := b.TotalAlloc - a.TotalAlloc; d > uint64(len(payload)) {
		t.Fatalf("3 requests allocated %d KB for a %d KB file (read into memory each time?)", d>>10, len(payload)>>10)
	}
}
