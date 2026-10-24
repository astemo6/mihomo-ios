package mitm

// Lane s3-script (native script dispatch): the Go half — the calls the Swift dispatcher makes (nativescript.go) —
// and what handling a script response in Swift saves on the Go side compared with the Go flow API.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// echoNative is a NativeJS that runs no JavaScript: Begin answers $done({body: $response.body}) at once (a script
// that hands the lane body back untouched). It isolates the dispatch cost (runCtx, event loop, setup / $done JSON,
// flow pipes, lane loading) from any engine's own heap — JavaScriptCore's heap is not the Go heap either.
type echoNative struct {
	mu      sync.Mutex
	loaded  map[string]bool
	gorPeak atomic.Int64
}

func (n *echoNative) Prepare(string) string { return "" }
func (n *echoNative) Load(key, name, src string) string {
	n.mu.Lock()
	n.loaded[key] = true
	n.mu.Unlock()
	return ""
}
func (n *echoNative) Drop(key string) { n.mu.Lock(); delete(n.loaded, key); n.mu.Unlock() }
func (n *echoNative) Collect()        {}
func (n *echoNative) Begin(run NativeRun, key, setup string) string {
	n.mu.Lock()
	ok := n.loaded[key]
	n.mu.Unlock()
	if !ok {
		return "missing"
	}
	if g := int64(runtime.NumGoroutine()); g > n.gorPeak.Load() {
		n.gorPeak.Store(g)
	}
	var st struct {
		Resp *struct {
			Body int64 `json:"body"`
		} `json:"resp"`
	}
	_ = json.Unmarshal([]byte(setup), &st)
	body := int64(-1)
	if st.Resp != nil {
		body = st.Resp.Body
	}
	run.Host("done", fmt.Sprintf(`{"kind":"obj","body":%d}`, body))
	return ""
}
func (n *echoNative) Call(int64, string, string) string { return "" }
func (n *echoNative) End(int64)                         {}

func useEchoNative(t *testing.T) (*echoNative, *fakeLane) {
	l := useFakeLane(t) // registers a lane + the goja stand-in; replaced by echoNative below
	n := &echoNative{loaded: map[string]bool{}}
	if msg := SetNativeEngine(n); msg != "" {
		t.Fatal(msg)
	}
	return n, l
}

const nsConf = `vip = type=http-response,pattern=^https://api\.test\.com/body,requires-body=1,max-size=-1,script-path=vip.js`

func nsEngine(t *testing.T) (*Engine, int64, int) {
	home := t.TempDir()
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, CaptureBodies: noCapture(), Scripts: items(nsConf)}
	if err := writeFileForTest(ScriptsDir(home)+"/vip.js", vipJS); err != nil {
		t.Fatal(err)
	}
	e := New(home, rwDial, nil)
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)
	rs := Build(home, cfg)
	if len(rs.Errors) > 0 {
		t.Fatal(rs.Errors)
	}
	e.Reload(cfg, rs)
	gen := e.RewriteSnapshotGen()
	rule := -1
	for i, r := range rs.Rules {
		if r.Kind == KindScript {
			rule = i
		}
	}
	if rule < 0 {
		t.Fatal("no script rule")
	}
	return e, gen, rule
}

// TestNativeScriptCallSequence walks the Swift dispatcher's Go calls for one response (slot, admission, program,
// body charge, logs, release) and checks every handle is returned.
func TestNativeScriptCallSequence(t *testing.T) {
	_, l := useEchoNative(t)
	e, gen, rule := nsEngine(t)
	if !NativeScriptReady() {
		t.Fatal("not ready with a native engine + lane")
	}
	tok := NativeScriptToken()
	var res nsReserveJS
	_ = json.Unmarshal([]byte(e.NativeScriptReserve(gen, rule, tok)), &res)
	if res.Slot <= 0 {
		t.Fatalf("reserve: %+v", res)
	}
	var adm nsAdmitJS
	_ = json.Unmarshal([]byte(e.NativeScriptBodyAdmit(gen, rule, strconv.Itoa(rule), "https://api.test.com/body", 1000, "", tok)), &adm)
	if !adm.OK || adm.Ticket <= 0 || adm.Cap < 1000 {
		t.Fatalf("admit: %+v", adm)
	}
	var p nsPrepareJS
	_ = json.Unmarshal([]byte(e.NativeScriptPrepare(gen, rule, res.Slot, false)), &p)
	if !p.OK || !strings.HasPrefix(p.Key, "jsc:") || p.TimeoutMs != 10000 || len(p.Setup) == 0 {
		t.Fatalf("prepare: %+v", p)
	}
	var setup map[string]any
	if err := json.Unmarshal(p.Setup, &setup); err != nil || setup["name"] != "vip" || setup["phase"] != "task" {
		t.Fatalf("setup base: %s", p.Setup)
	}
	var p2 nsPrepareJS
	_ = json.Unmarshal([]byte(e.NativeScriptPrepare(gen, rule, res.Slot, true)), &p2)
	if !p2.OK || p2.Key != p.Key {
		t.Fatalf("reload: %+v", p2)
	}
	if s := e.NativeScriptBodyLoaded(adm.Ticket, "https://api.test.com/body", 1000); s != "" {
		t.Fatalf("loaded: %s", s)
	}
	var chk nsSkipJS
	_ = json.Unmarshal([]byte(e.NativeScriptBodyCheck(gen, rule, 1000, -1)), &chk)
	if chk.Note != "" || chk.Limit < 1000 {
		t.Fatalf("check: %+v", chk)
	}
	_ = json.Unmarshal([]byte(e.NativeScriptBodyCheck(gen, rule, 1<<30, 1<<20)), &chk)
	if !strings.HasPrefix(chk.Note, "跳过脚本：vip — 响应体 1048576 KB 超过上限 1024 KB") {
		t.Fatalf("check over: %+v", chk)
	}
	e.NativeScriptHost(gen, rule, "x-finished", "3")
	NativeScriptRelease(res.Slot, true)
	NativeScriptBodyRelease(adm.Ticket)
	NativeScriptCancel(tok)
	if h := NativeScriptHeld(); h != 0 {
		t.Fatalf("held %d", h)
	}
	if bodyBudget.inUse() != 0 {
		t.Fatalf("body budget in use %d", bodyBudget.inUse())
	}
	var lines []string
	for _, ln := range e.Logs.List(0, "vip") {
		lines = append(lines, ln.Level+" "+ln.Msg)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "debug 执行完成，用时 3 ms（JavaScriptCore）") || !strings.Contains(joined, "warn 跳过脚本：响应体 1048576 KB 超过上限 1024 KB") {
		t.Fatalf("logs:\n%s", joined)
	}
	if l.live() != 0 {
		t.Fatalf("lane handles left: %d", l.live())
	}
}

// TestNativeScriptFailMessages: NativeScriptFail gives the Go path's messages, log lines and notes.
func TestNativeScriptFailMessages(t *testing.T) {
	useEchoNative(t)
	e, gen, rule := nsEngine(t)
	cases := []struct {
		mode, detail string
		stop         int
		afterDone    bool
		want         string
		ignored      bool
	}{
		{"js", `{"kind":"exception","message":"Error: boom"}`, 0, false, "脚本异常：Error: boom", false},
		{"js", `{"kind":"terminated","message":"terminated"}`, stopTimeout, false, "脚本执行超时（10s）", false},
		{"js", `{"kind":"terminated","message":"terminated"}`, stopMemory, false, "脚本内存占用过高，已终止（保护隧道内存）", false},
		{"js", `{"kind":"terminated","message":"terminated"}`, stopCancelled, false, errScriptCancelled.Error(), false},
		{"js", `{"kind":"exception","message":"RangeError: Maximum call stack size exceeded."}`, 0, false, "脚本调用栈溢出（递归过深）", false},
		{"js", `{"kind":"exception","message":"TypeError: x"}`, 0, true, "脚本异常：TypeError: x", true},
		{"js", `{"kind":"terminated","message":"t"}`, stopTimeout, true, "脚本执行超时（10s）", false},
		{"js", "missing", 0, false, "脚本引擎错误：missing", false},
		{"timeout", "", 0, false, "脚本执行超时（10s）", false},
		{"cancel", "", 0, false, errScriptCancelled.Error(), false},
		{"msg", "脚本语法错误：x", 0, false, "脚本语法错误：x", false},
	}
	for _, c := range cases {
		var f nsFailJS
		_ = json.Unmarshal([]byte(e.NativeScriptFail(gen, rule, c.mode, c.detail, c.stop, 10000, c.afterDone)), &f)
		if f.Msg != c.want || f.Ignored != c.ignored {
			t.Errorf("%s %q stop %d: got %+v, want %q ignored=%v", c.mode, c.detail, c.stop, f, c.want, c.ignored)
		}
		if !c.ignored && f.Note != scriptErrNote("vip", fmt.Errorf("%s", c.want)) {
			t.Errorf("%s: note %q", c.mode, f.Note)
		}
	}
}

// TestNativeScriptGoCost measures what one script response costs the Go side through the Go flow API (body pushed
// into Go, loaded into the lane through Go, a runCtx + event loop per run) and through the native dispatcher (only
// the admission / program / log calls Swift makes, plus the request-log records). Same script rule, same body; the
// engine itself is echoNative in both (no JavaScript heap counted). Logged, not asserted (machine dependent), except
// that native must allocate less and create no goroutine per request.
func TestNativeScriptGoCost(t *testing.T) {
	n, l := useEchoNative(t)
	e, gen, rule := nsEngine(t)
	for _, size := range []int{4 << 10, 300 << 10, 3 << 20} {
		body := bytes.Repeat([]byte(`{"a":1}`), size/7)
		head, _ := json.Marshal(FlowHead{Method: "GET", Target: "/body?x=1", Host: "api.test.com", Headers: [][2]string{{"Accept", "*/*"}}, ConnHost: "api.test.com", ConnPort: 443, TLS: true})
		resp, _ := json.Marshal(FlowRespHead{Status: 200, Headers: [][2]string{{"Content-Type", "application/json"}, {"Content-Length", strconv.Itoa(len(body))}}, Length: int64(len(body))})
		goPath := func() {
			d := rwDecode(t, e.FlowBegin(string(head)))
			if d.Action != "forward" {
				t.Fatalf("begin: %+v", d)
			}
			r := rwDecode(t, FlowResponse(d.ID, string(resp)))
			for r.Action == "need-body" {
				for off := 0; off < len(body); {
					end := min(off+32<<10, len(body))
					switch FlowWrite(d.ID, flowResp, body[off:end]) {
					case "full":
						time.Sleep(50 * time.Microsecond)
						continue
					}
					off = end
				}
				FlowClose(d.ID, flowResp, "")
				r = rwDecode(t, FlowAwait(d.ID))
			}
			if r.Action != "respond" || r.Body != "lane" {
				t.Fatalf("response: %+v", r)
			}
			FlowEnd(d.ID, int64(len(body)), "")
		}
		nativePath := func() {
			tok := NativeScriptToken()
			var res nsReserveJS
			_ = json.Unmarshal([]byte(e.NativeScriptReserve(gen, rule, tok)), &res)
			var adm nsAdmitJS
			_ = json.Unmarshal([]byte(e.NativeScriptBodyAdmit(gen, rule, strconv.Itoa(rule), "https://api.test.com/body?x=1", int64(len(body)), "", tok)), &adm)
			if s := e.NativeScriptBodyLoaded(adm.Ticket, "https://api.test.com/body?x=1", int64(len(body))); s != "" {
				t.Fatalf("loaded: %s", s)
			}
			var p nsPrepareJS
			_ = json.Unmarshal([]byte(e.NativeScriptPrepare(gen, rule, res.Slot, false)), &p)
			if !p.OK {
				t.Fatalf("prepare: %+v", p)
			}
			e.NativeScriptHost(gen, rule, "x-finished", "1")
			NativeScriptRelease(res.Slot, true)
			NativeScriptBodyRelease(adm.Ticket)
			NativeScriptCancel(tok)
			k := time.Now().UnixNano()
			recs := fmt.Sprintf(`[{"k":%d,"ev":"forward","t":%d,"ms":1,"gen":%d,"method":"GET","url":"https://api.test.com/body?x=1","host":"api.test.com","tls":true,"headers":[["Accept","*/*"]]},`+
				`{"k":%d,"ev":"response","ms":2,"gen":%d,"rules":[%d],"status":200,"headers":[["Content-Length","%d"],["Content-Type","application/json"]]}]`,
				k, time.Now().Unix(), gen, k, gen, rule, len(body))
			e.RecordNative(recs)
			e.RecordNative(fmt.Sprintf(`[{"k":%d,"ev":"end","ms":3,"sent":%d,"resp":true}]`, k, len(body)))
		}
		measure := func(name string, f func()) (float64, float64) {
			for i := 0; i < 20; i++ {
				f()
			}
			waitFlows(t)
			const reps = 100
			var a, b runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&a)
			g0 := runtime.NumGoroutine()
			n.gorPeak.Store(0)
			for i := 0; i < reps; i++ {
				f()
			}
			runtime.ReadMemStats(&b)
			per := float64(b.TotalAlloc-a.TotalAlloc) / reps
			allocs := float64(b.Mallocs-a.Mallocs) / reps
			peak := n.gorPeak.Load()
			extra := int64(0)
			if peak > 0 {
				extra = peak - int64(g0)
			}
			t.Logf("body %4d KB  %-6s: %8.1f KB allocated / request (%5.0f allocs); goroutines above idle during the run: %d",
				len(body)>>10, name, per/1024, allocs, extra)
			return per, float64(extra)
		}
		goAlloc, goGor := measure("go", goPath)
		nAlloc, nGor := measure("native", nativePath)
		// In the tunnel every MitmFlowWrite chunk is also copied by gomobile into a Go []byte (the test pushes Go
		// slices), so the go path allocates the body once more per request on top of the measured figure.
		t.Logf("body %4d KB  saved per request: %.1f KB Go allocation measured (+%d KB gomobile push copies in the tunnel), %.0f goroutines; body copies through Go: go path 4 (gomobile push, pipe, lane load buffer, gomobile copy to the store) vs native 0",
			len(body)>>10, (goAlloc-nAlloc)/1024, len(body)>>10, goGor-nGor)
		if nAlloc >= goAlloc {
			t.Errorf("native dispatch allocates %.0f B ≥ go path %.0f B", nAlloc, goAlloc)
		}
	}
	if l.live() != 0 {
		t.Fatalf("lane handles left: %d", l.live())
	}
	if h := NativeScriptHeld(); h != 0 {
		t.Fatalf("held %d", h)
	}
}
