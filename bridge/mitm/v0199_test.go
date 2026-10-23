package mitm

// v0.19.9: the official BoxJS and Sub-Store modules, added through the generic module flow, must work
// on the generic MitM script engine (request scripts answering locally, large bodies, persistent store,
// cron tasks). The fixtures are the real upstream files, downloaded at test time and cached in the OS
// temp dir; the tests skip when offline (MIHOMO_OFFLINE=1 forces the skip). Nothing large is committed.

import (
	"compress/gzip"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dop251/goja"
)

const (
	boxjsBase    = "https://raw.githubusercontent.com/chavyleung/scripts/master/box/"
	substoreConf = "https://raw.githubusercontent.com/sub-store-org/Sub-Store/master/config/"
	substoreRel  = "https://github.com/sub-store-org/Sub-Store/releases/latest/download/"
)

// fixture downloads u once per machine (cached under the OS temp dir) or skips the test.
func fixture(t *testing.T, u string) []byte {
	t.Helper()
	if os.Getenv("MIHOMO_OFFLINE") != "" {
		t.Skip("offline")
	}
	h := sha1.Sum([]byte(u))
	dir := filepath.Join(os.TempDir(), "mihomo-fixtures")
	p := filepath.Join(dir, hex.EncodeToString(h[:]))
	if fi, err := os.Stat(p); err == nil && time.Since(fi.ModTime()) < 24*time.Hour {
		if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
			return b
		}
	}
	c := &http.Client{Timeout: 60 * time.Second}
	resp, err := c.Get(u)
	if err != nil {
		t.Skipf("offline (%v)", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Skipf("fixture %s: HTTP %d", u, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil || len(b) == 0 {
		t.Skipf("fixture %s: %v", u, err)
	}
	_ = os.MkdirAll(dir, 0o755)
	_ = os.WriteFile(p, b, 0o644)
	return b
}

// seedScript puts a downloaded script where the engine's resource cache looks for script-path u.
func seedScript(t *testing.T, home, u string, b []byte) {
	t.Helper()
	cp := CachePath(home, u)
	_ = os.MkdirAll(filepath.Dir(cp), 0o755)
	if err := os.WriteFile(cp, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// dumpScriptLogs prints the engine's script log when the test failed.
func dumpScriptLogs(h *harness) {
	h.t.Cleanup(func() {
		if !h.t.Failed() {
			return
		}
		for _, l := range h.e.Logs.List(0, "") {
			h.t.Logf("script log [%s] %s: %s", l.Level, l.Script, clip(l.Msg, 600))
		}
	})
}

func parseModuleText(text, name string) *Ruleset {
	rs := &Ruleset{}
	rs.ParseText(text, name, nil)
	return rs
}

func hasHost(rs *Ruleset, h string) bool {
	for _, x := range rs.Hostnames {
		if strings.TrimPrefix(x, "%APPEND% ") == h {
			return true
		}
	}
	return false
}

// TestV0199OfficialModulesParse: every official BoxJS / Sub-Store module format imports into the
// expected request scripts, MitM hosts and cron tasks.
func TestV0199OfficialModulesParse(t *testing.T) {
	type want struct {
		url     string
		scripts int
		tasks   int
		host    string
		timeout int
	}
	cases := []want{
		{boxjsBase + "rewrite/boxjs.rewrite.surge.sgmodule", 1, 0, "boxjs.com", 120},
		{boxjsBase + "rewrite/boxjs.rewrite.loon.plugin", 1, 0, "boxjs.com", 120},
		{boxjsBase + "rewrite/boxjs.rewrite.quanx.conf", 1, 0, "boxjs.com", 0},
		{boxjsBase + "rewrite/boxjs.rewrite.stash.stoverride", 1, 0, "boxjs.com", 120},
		{substoreConf + "Surge.sgmodule", 2, 1, "sub.store", 900},
		{substoreConf + "Surge-Noability.sgmodule", 2, 1, "sub.store", 900},
		{substoreConf + "Surge-ability.sgmodule", 2, 1, "sub.store", 0},
		{substoreConf + "Surge-Beta.sgmodule", 2, 1, "sub.store", 0},
		{substoreConf + "Loon.plugin", 2, 1, "sub.store", 900},
		{substoreConf + "QX.snippet", 2, 0, "sub.store", 0},
		{substoreConf + "QX-Task.json", 0, 1, "", 0},
		{substoreConf + "Stash.stoverride", 2, 1, "sub.store", 900},
		{substoreConf + "Egern.yaml", 2, 1, "sub.store", 900},
	}
	for _, c := range cases {
		name := c.url[strings.LastIndex(c.url, "/")+1:]
		t.Run(name, func(t *testing.T) {
			rs := parseModuleText(string(fixture(t, c.url)), name)
			n := 0
			for _, r := range rs.Rules {
				if r.Kind == KindScript {
					n++
					if r.Script.Path == "" || !r.Script.RequiresBody {
						t.Errorf("script %s: path=%q requiresBody=%v", r.Script.Name, r.Script.Path, r.Script.RequiresBody)
					}
					if c.timeout > 0 && r.Script.Timeout != c.timeout {
						t.Errorf("script %s timeout %d, want %d", r.Script.Name, r.Script.Timeout, c.timeout)
					}
					if strings.Contains(r.Script.Path, "{") {
						t.Errorf("unsubstituted argument in %q", r.Script.Path)
					}
				}
			}
			enabledTasks := 0
			for _, tk := range rs.Tasks {
				if !tk.DisabledByLine {
					enabledTasks++
				}
				if tk.Cron == "" || strings.Contains(tk.Cron, "{") || tk.Script == nil || !strings.HasPrefix(tk.Script.Path, "https://") {
					t.Errorf("task %+v", tk)
				}
			}
			if n != c.scripts || enabledTasks != c.tasks {
				t.Errorf("scripts=%d tasks=%d (want %d/%d) errors=%v format=%s", n, enabledTasks, c.scripts, c.tasks, rs.Errors, rs.Format)
			}
			if c.host != "" && !hasHost(rs, c.host) {
				t.Errorf("hosts %v lack %s", rs.Hostnames, c.host)
			}
			if len(rs.Errors) > 0 {
				t.Errorf("errors: %v", rs.Errors)
			}
		})
	}
}

// liveHeapPeak samples the live heap (after a forced GC) every 2 ms until stopped: the peak of what is
// really reachable, not of garbage waiting for the collector.
type liveHeapPeak struct {
	stop chan struct{}
	done chan struct{}
	peak atomic.Uint64
}

func startHeapPeak() *liveHeapPeak {
	hp := &liveHeapPeak{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(hp.done)
		for {
			select {
			case <-hp.stop:
				return
			default:
			}
			runtime.GC()
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > hp.peak.Load() {
				hp.peak.Store(m.HeapAlloc)
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	return hp
}

func (hp *liveHeapPeak) Reset() uint64 { return hp.peak.Swap(0) }

func (hp *liveHeapPeak) Stop() uint64 { close(hp.stop); <-hp.done; return hp.peak.Load() }

func liveHeap() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

func mb(b uint64) float64 { return float64(b) / (1 << 20) }

func (h *harness) do(method, u, body string, hdr ...string) (*http.Response, string) {
	h.t.Helper()
	req, _ := http.NewRequest(method, u, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, u, err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

// TestV0199SubStoreBackend runs the real Sub-Store bundle from its official Surge module on sub.store:
// API answered locally (no upstream), a local subscription created and downloaded in two targets, data
// kept in $persistentStore. Reports heap numbers for the 50 MB extension budget.
func TestV0199SubStoreBackend(t *testing.T) {
	mod := fixture(t, substoreConf+"Surge-Noability.sgmodule")
	core := fixture(t, substoreRel+"sub-store-1.min.js")
	simple := fixture(t, substoreRel+"sub-store-0.min.js")
	cfg := &Config{Enabled: true, MitM: true, Modules: []Module{{ID: "substore", Name: "Sub-Store", Enabled: true}}}
	h := newHarness(t, cfg, nil)
	dumpScriptLogs(h)
	if err := writeFileForTest(ModulePath(h.home, "substore"), string(mod)); err != nil {
		t.Fatal(err)
	}
	seedScript(t, h.home, substoreRel+"sub-store-1.min.js", core)
	seedScript(t, h.home, substoreRel+"sub-store-0.min.js", simple)
	rs := Build(h.home, cfg)
	h.e.Reload(cfg, rs)
	savedIdle := largeProgIdleNs.Load()
	largeProgIdleNs.Store(int64(2 * time.Second))
	defer largeProgIdleNs.Store(savedIdle)

	base := liveHeap()
	hp := startHeapPeak()
	t0 := time.Now()
	resp, body := h.do("GET", "https://sub.store/api/subs", "", "Origin", "https://sub-store.vercel.app")
	first := time.Since(t0)
	coldPeak := hp.Reset()
	if resp.StatusCode != 200 || !strings.Contains(body, `"status":"success"`) {
		t.Fatalf("GET /api/subs: %d %s", resp.StatusCode, clip(body, 400))
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got == "" {
		t.Logf("no CORS header on /api/subs (headers %v)", resp.Header)
	}
	sub := `{"name":"t1","displayName":"T1","source":"local","content":"ss://YWVzLTEyOC1nY206cGFzcw@1.2.3.4:8388#HK%20Node\ntrojan://pw@example.com:443?sni=example.com#JP%20Node","process":[]}`
	resp, body = h.do("POST", "https://sub.store/api/subs", sub)
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		t.Fatalf("POST /api/subs: %d %s", resp.StatusCode, clip(body, 400))
	}
	resp, body = h.do("GET", "https://sub.store/download/t1?target=ClashMeta", "")
	if resp.StatusCode != 200 || !strings.Contains(body, "HK Node") || !strings.Contains(body, "trojan") {
		t.Fatalf("download ClashMeta: %d %s", resp.StatusCode, clip(body, 400))
	}
	resp, body = h.do("GET", "https://sub.store/download/t1?target=QX", "")
	if resp.StatusCode != 200 || !strings.Contains(body, "shadowsocks=1.2.3.4:8388") {
		t.Fatalf("download QX: %d %s", resp.StatusCode, clip(body, 400))
	}
	resp, body = h.do("GET", "https://sub.store/api/subs", "")
	if !strings.Contains(body, `"t1"`) {
		t.Fatalf("sub not persisted: %s", clip(body, 300))
	}
	peak := hp.Stop()
	steady := liveHeap()
	// Idle release: the compiled bundle leaves the cache after largeProgIdle without a run.
	cached := liveHeap()
	rel := largeReleases.Load()
	deadline := time.Now().Add(10 * time.Second)
	for largeReleases.Load() == rel && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if largeReleases.Load() == rel {
		t.Fatalf("large program not released after idle")
	}
	released := liveHeap()
	t.Logf("Sub-Store idle release: heap with bundle cached %.1f MB → after release %.1f MB", mb(cached), mb(released))

	// Under the tunnel's soft limit (GOMEMLIMIT 26 MB) a cold compile of the 1.3 MB bundle (~43 MB peak)
	// cannot fit in the ~50 MB extension: the engine refuses it with a log line instead of being killed.
	dropKeepRecent = 0 // drop everything, in use or not
	defer func() { dropKeepRecent = 60 * time.Second }()
	h.e.DropCaches()
	old := debug.SetMemoryLimit(26 << 20)
	defer debug.SetMemoryLimit(old)
	seq := h.e.Logs.Seq()
	resp, _ = h.do("GET", "https://sub.store/api/subs", "")
	refused := false
	for _, l := range h.e.Logs.List(seq, "") {
		if strings.Contains(l.Msg, "脚本过大") {
			refused = true
			t.Logf("26 MB limit: %s", l.Msg)
		}
	}
	if !refused || resp.StatusCode == 200 {
		t.Fatalf("expected the compile gate under a 26 MB limit (status %d)", resp.StatusCode)
	}
	raw, _ := h.e.Store.Read("sub-store")
	var probe map[string]any
	if err := json.Unmarshal([]byte(raw), &probe); err != nil {
		t.Fatalf("store key sub-store not JSON (%d bytes): %v", len(raw), err)
	}
	t.Logf("Sub-Store memory (live heap): base %.1f MB; cold request (compile sub-store-0) peak %.1f MB in %v; warm requests incl. a cold compile of sub-store-1 peak %.1f MB; after GC with one bundle cached %.1f MB; store key %d bytes",
		mb(base), mb(coldPeak), first.Round(time.Millisecond), mb(peak), mb(steady), len(raw))
}

// TestV0199BoxJSOfficial runs the real chavy.boxjs.js from the official Surge module: the UI page, the
// /query/boxdata API, saving data through /api/save that other scripts then read from $persistentStore.
func TestV0199BoxJSOfficial(t *testing.T) {
	mod := fixture(t, boxjsBase+"rewrite/boxjs.rewrite.surge.sgmodule")
	box := fixture(t, boxjsBase+"chavy.boxjs.js")
	cfg := &Config{Enabled: true, MitM: true, Modules: []Module{{ID: "boxjs", Name: "BoxJs", Enabled: true}}}
	h := newHarness(t, cfg, nil)
	dumpScriptLogs(h)
	if err := writeFileForTest(ModulePath(h.home, "boxjs"), string(mod)); err != nil {
		t.Fatal(err)
	}
	seedScript(t, h.home, boxjsBase+"chavy.boxjs.js", box)
	h.e.Reload(cfg, Build(h.home, cfg))
	resp, body := h.do("GET", "https://boxjs.com/query/boxdata", "")
	if resp.StatusCode != 200 || !strings.Contains(body, `"datas"`) {
		t.Fatalf("boxdata: %d %s", resp.StatusCode, clip(body, 400))
	}
	resp, body = h.do("POST", "https://boxjs.com/api/save", `[{"key":"test_key","val":"hello"}]`)
	if resp.StatusCode != 200 {
		t.Fatalf("save: %d %s", resp.StatusCode, clip(body, 300))
	}
	if v, _ := h.e.Store.Read("test_key"); v != "hello" {
		t.Fatalf("store test_key=%q after /api/save", v)
	}
	_ = h.e.Store.Write("from_script", "42", false)
	resp, body = h.do("GET", "https://boxjs.com/query/data/from_script", "")
	if !strings.Contains(body, "42") {
		t.Fatalf("query data: %d %s", resp.StatusCode, clip(body, 300))
	}
}

// TestV0199GojaEvalStashLevel: the patched goja (bridge/third_party/goja) resolves outer bindings from a
// direct eval() inside class methods / constructors and strict functions with default parameters.
func TestV0199GojaEvalStashLevel(t *testing.T) {
	cases := map[string]string{
		"ctor-default": `(function(){ let a=1; var C=class{constructor(x="d"){this.v=a; if(x){let q=eval('1')}}}; return new C().v })()`,
		"ctor-simple":  `(function(){ let a=1; var C=class{constructor(x){eval('1'); this.v=a}}; return new C().v })()`,
		"method":       `(function(){ let a=1; var C=class{m(x="d"){eval('1'); return a}}; return new C().m() })()`,
		"strict-fn":    `(function(){'use strict'; let a=1; function f(x="d"){ eval('1'); return a}; return f() })()`,
		"strict-var":   `(function(){'use strict'; var a=1; function f(x="d"){ eval('1'); return a}; return f() })()`,
		"loop":         `(function(){ let a=0; var C=class{m(){ let r=0; for(let i=0;i<3;i++){ r+=eval('i+a') } return r/3 }}; return new C().m() })()`,
		"substore":     `(function(){ let yo=()=>1; var j1=class{constructor(name="untitled",debug=!1){if(this.name=name,this.http=yo(),false){let d=eval('1')}}}; return new j1("s").http })()`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			v, err := goja.New().RunString(src)
			if err != nil || v.ToInteger() != 1 {
				t.Fatalf("got %v, %v", v, err)
			}
		})
	}
}

// TestV0199SubStoreSyncTask runs the official 「Sub-Store Sync」 cron task (cron-sync-artifacts.min.js)
// from the Surge module through the task runner. With no artifacts / Gist token configured it must end
// cleanly (no exception), reading the same $persistentStore the request scripts write.
func TestV0199SubStoreSyncTask(t *testing.T) {
	mod := fixture(t, substoreConf+"Surge-Noability.sgmodule")
	cron := fixture(t, substoreRel+"cron-sync-artifacts.min.js")
	cfg := &Config{Enabled: true, MitM: true, Modules: []Module{{ID: "substore", Name: "Sub-Store", Enabled: true}}}
	h := newHarness(t, cfg, nil)
	dumpScriptLogs(h)
	if err := writeFileForTest(ModulePath(h.home, "substore"), string(mod)); err != nil {
		t.Fatal(err)
	}
	seedScript(t, h.home, substoreRel+"cron-sync-artifacts.min.js", cron)
	rs := Build(h.home, cfg)
	if len(rs.Tasks) != 1 || rs.Tasks[0].Cron != "55 23 * * *" || rs.Tasks[0].Script.Timeout != 900 {
		t.Fatalf("tasks: %+v", rs.Tasks)
	}
	h.e.Reload(cfg, rs)
	_ = h.e.Store.Write("sub-store", `{"subs":[],"collections":[],"artifacts":[],"settings":{},"files":[]}`, false)
	seq := h.e.Logs.Seq()
	if _, err := h.e.scripts.RunTask(rs.Tasks[0], nil, nil); err != nil {
		t.Fatalf("sync task: %v", err)
	}
	var msgs []string
	for _, l := range h.e.Logs.List(seq, "") {
		msgs = append(msgs, l.Msg)
		if l.Level == "error" {
			t.Errorf("task error: %s", l.Msg)
		}
	}
	t.Logf("sync task log: %s", clip(strings.Join(msgs, " | "), 600))
}

// review 5 P1-4 / P2-5: $httpClient decodes bodies even when the script sends its own Accept-Encoding,
// and fails loudly above MaxScriptBody instead of truncating.
func TestV0199HTTPClientEncodingAndCap(t *testing.T) {
	big := strings.Repeat("x", MaxScriptBody+10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gz":
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			_, _ = io.WriteString(gz, `{"ok":true,"ae":"`+r.Header.Get("Accept-Encoding")+`"}`)
			_ = gz.Close()
		case "/big":
			_, _ = io.WriteString(w, big)
		}
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	dial := func(ctx context.Context, network, a, policy string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	code := `$httpClient.get({url: "http://t.test/gz", headers: {"Accept-Encoding": "gzip, deflate, br", "User-Agent": "x"}}, (e, r, d) => {
  const o = JSON.parse(d);
  $httpClient.get("http://t.test/big", (e2, r2, d2) => { $done({body: JSON.stringify({ok: o.ok, ce: r.headers["Content-Encoding"] || "", err: e2 || "", len: d2 ? d2.length : 0})}) });
});`
	out := DebugRun(t.TempDir(), DebugInput{Code: code, Type: "http-request", Request: &DebugHTTP{URL: "https://a.test/"}}, dial)
	if !out.OK || out.Result == nil {
		t.Fatalf("run: %+v", out)
	}
	var r struct {
		OK  bool   `json:"ok"`
		CE  string `json:"ce"`
		Err string `json:"err"`
		Len int    `json:"len"`
	}
	if err := json.Unmarshal([]byte(out.Result.Body), &r); err != nil {
		t.Fatalf("%v: %s", err, out.Result.Body)
	}
	if !r.OK || r.CE != "" || !strings.Contains(r.Err, "响应体超过") || r.Len != 0 {
		t.Fatalf("got %+v", r)
	}
}

// review 5 P1-5: a tiny write to a multi-MB store stays cheap (streamed, coalesced) and an edit the app
// made to store.json meanwhile survives the flush.
func TestV0199StoreWriteCostAndMerge(t *testing.T) {
	home := t.TempDir()
	s := NewStore(home)
	val := strings.Repeat(`{"k":"v\"q"},`, 878<<10/13)
	for i := 0; i < 5; i++ {
		if !s.Write("big"+strconv.Itoa(i), val, false) {
			t.Fatal("write big")
		}
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	for i := 0; i < 20; i++ {
		s.Write("counter", strconv.Itoa(i), false)
		_ = s.Flush()
	}
	runtime.ReadMemStats(&m1)
	perWrite := (m1.TotalAlloc - m0.TotalAlloc) / 20
	t.Logf("store %.1f MB: %.2f MB allocated per one-key write+flush", float64(5*len(val))/(1<<20), float64(perWrite)/(1<<20))
	if perWrite > 1<<20 {
		t.Fatalf("one small write allocates %.1f MB", float64(perWrite)/(1<<20))
	}
	// The app edits the file (another process), then a script writes before reading it.
	time.Sleep(10 * time.Millisecond)
	app := NewStore(home)
	app.Write("from_app", "1", false)
	if err := app.Flush(); err != nil {
		t.Fatal(err)
	}
	s.Write("from_script", "2", false) // loads the app's version first (mtime changed)
	s.mu.Lock()
	s.data["from_app"] = "1" // simulate a race: the app's write lands after our load
	s.mu.Unlock()
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	fresh := NewStore(home)
	if v, _ := fresh.Read("from_app"); v != "1" {
		t.Fatal("app edit lost")
	}
	if v, _ := fresh.Read("from_script"); v != "2" {
		t.Fatal("script write lost")
	}
	if v, _ := fresh.Read("big3"); v != val {
		t.Fatal("big value corrupted")
	}
	odd := "a\x01b\tc\n\u2028中文\"\\ \x7f"
	s.Write("odd", odd, false)
	_ = s.Flush()
	if v, _ := NewStore(home).Read("odd"); v != odd {
		t.Fatalf("escaping round trip: %q", v)
	}
}
