package mitm

// native-final: the hand-over of a request whose request scripts Swift already ran (FlowHead.Scripted). For
// every case the same request goes through the Go flow API twice — once with Go running the request script,
// once with the script's outcome handed over (the script file replaced by one that throws, so a second run would
// show) — and the two must agree on the decisions, what goes upstream, the request-log entry, and the script
// log (the hand-over writes no script log line).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
)

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

const fsConf = `hdr = type=http-request,pattern=^https://api\.test\.com/hdr,script-path=hdr.js
url = type=http-request,pattern=^https://api\.test\.com/url,script-path=url.js
body = type=http-request,pattern=^https://api\.test\.com/body,requires-body=1,script-path=body.js
mock = type=http-request,pattern=^https://api\.test\.com/mock$,script-path=mock.js
mockbad = type=http-request,pattern=^https://api\.test\.com/mockbad,script-path=mockbad.js
abort = type=http-request,pattern=^https://api\.test\.com/abort,script-path=abort.js
err = type=http-request,pattern=^https://api\.test\.com/err,script-path=err.js
two1 = type=http-request,pattern=^https://api\.test\.com/two,script-path=hdr.js
two2 = type=http-request,pattern=^https://api\.test\.com/two,requires-body=1,script-path=body.js
small = type=http-request,pattern=^https://api\.test\.com/small,requires-body=1,max-size=8,script-path=body.js`

var fsScripts = map[string]string{
	"hdr.js":     `console.log("ran " + Math.random()); var h = $request.headers; h["X-Req"] = "1"; h["Host"] = "api.test.com"; $done({headers: h});`,
	"url.js":     `console.log("ran " + Math.random()); $done({url: "https://api.test.com/changed?x=1", method: "post"});`,
	"body.js":    `console.log("ran " + Math.random()); $done({body: "[" + $request.body + "]"});`,
	"mock.js":    `console.log("ran " + Math.random()); $done({response: {status: 201, headers: {"Content-Type": "text/plain", "X-M": "1"}, body: "mocked"}});`,
	"mockbad.js": `console.log("ran " + Math.random()); $done({response: {status: 42, body: "x"}});`,
	"abort.js":   `console.log("ran " + Math.random()); $done({__egernAbort: true});`,
	"err.js":     `console.log("ran " + Math.random()); throw new Error("boom");`,
}

type fsOutcome struct {
	Decisions []string
	Up        string
	Status    int
	Body      string
	Dropped   bool
	Err       string
	Entry     string
}

func fsRun(t *testing.T, e *Engine, path string, body []byte, gen int64, scripted []FlowScripted) fsOutcome {
	t.Helper()
	s := newFlowSim(t, e)
	s.rt = rtFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/plain"}}, ContentLength: 2,
			Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
	})
	s.scriptedGen, s.scripted = gen, scripted
	before := e.Requests.List(0)
	hdr := http.Header{"User-Agent": {"T/1"}}
	if body != nil {
		hdr.Set("Content-Type", "text/plain")
	}
	method := "GET"
	if body != nil {
		method = "POST"
	}
	res := s.do(method, "https://api.test.com"+path, hdr, body)
	var o fsOutcome
	for _, d := range res.decisions {
		d.ID = 0
		b, _ := json.Marshal(d)
		o.Decisions = append(o.Decisions, string(b))
	}
	if res.upstream != nil {
		var hs []string
		for k, v := range res.upstream.Header {
			hs = append(hs, k+": "+strings.Join(v, ","))
		}
		sort.Strings(hs)
		o.Up = fmt.Sprintf("%s %s host=%s %v body=%q", res.upstream.Method, res.upstream.URL, res.upstream.Host, hs, res.upBody)
	}
	o.Status, o.Body, o.Dropped, o.Err = res.status, string(res.body), res.dropped, res.err
	after := e.Requests.List(0)
	if len(after) != len(before)+1 {
		t.Fatalf("%s: %d new entries", path, len(after)-len(before))
	}
	ent := e.Requests.Get(after[0].ID)
	if ent == nil {
		t.Fatalf("%s: entry", path)
	}
	ent.mu.Lock()
	o.Entry = fmt.Sprintf("%s %s status=%d local=%v bytes=%d matched=%v notes=%v req=%v resp=%v", ent.Method, ent.URL, ent.Status, ent.IsLocal, ent.Bytes, ent.Matched, ent.Notes, ent.ReqHdr, ent.RespHdr)
	ent.mu.Unlock()
	return o
}

func scriptLog(e *Engine) []string {
	var out []string
	for _, n := range []string{"hdr", "url", "body", "mock", "mockbad", "abort", "err", "two1", "two2", "small"} {
		for _, l := range e.Logs.List(0, n) {
			out = append(out, n+" "+l.Level+" "+l.Msg)
		}
	}
	return out
}

func TestFlowScriptedHandOverMatchesGo(t *testing.T) {
	home := t.TempDir()
	for name, src := range fsScripts {
		if err := writeFileForTest(ScriptsDir(home)+"/"+name, src); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, CaptureBodies: noCapture(), Scripts: items(strings.Split(fsConf, "\n")...)}
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
	idx := map[string]int{}
	for i, r := range rs.Rules {
		if r.Kind == KindScript {
			idx[r.Script.Name] = i
		}
	}
	str := func(s string) *string { return &s }
	hdrs := func(kv ...string) *[][2]string {
		var p [][2]string
		for i := 0; i+1 < len(kv); i += 2 {
			p = append(p, [2]string{kv[i], kv[i+1]})
		}
		return &p
	}
	type tc struct {
		path     string
		body     []byte
		scripted []FlowScripted
	}
	cases := []tc{
		{"/hdr", nil, []FlowScripted{{Rule: idx["hdr"], Headers: hdrs("User-Agent", "T/1", "X-Req", "1", "Host", "api.test.com")}}},
		{"/url", nil, []FlowScripted{{Rule: idx["url"], URL: str("https://api.test.com/changed?x=1"), Method: str("post")}}},
		{"/body", []byte("abc"), []FlowScripted{{Rule: idx["body"], Load: true, BodySet: true, Body: []byte("[abc]")}}},
		{"/body", []byte{}, []FlowScripted{{Rule: idx["body"], Load: true, BodySet: true, Body: []byte("[]")}}},
		{"/mock", nil, []FlowScripted{{Rule: idx["mock"], Mock: &FlowScriptedResponse{Status: 201, Headers: hdrs("Content-Type", "text/plain", "X-M", "1"), Body: []byte("mocked")}}}},
		{"/mockbad", nil, []FlowScripted{{Rule: idx["mockbad"], Mock: &FlowScriptedResponse{Status: 42, Body: []byte("x")}}}},
		{"/abort", nil, []FlowScripted{{Rule: idx["abort"], Abort: true}}},
		{"/err", nil, []FlowScripted{{Rule: idx["err"], Fail: "脚本 err 出错：boom"}}},
		// only the first of two scripts was run natively: Go runs the second itself
		{"/two", []byte("xy"), []FlowScripted{{Rule: idx["two1"], Headers: hdrs("User-Agent", "T/1", "Content-Type", "text/plain", "X-Req", "1", "Host", "api.test.com")}}},
		{"/small", []byte("0123456789abcdef"), []FlowScripted{{Rule: idx["small"], Load: true, Skip: "跳过脚本：small — 请求体 0 KB 超过上限 0 KB"}}},
	}
	for _, c := range cases {
		goOut := fsRun(t, e, c.path, c.body, 0, nil)
		goLog := scriptLog(e)
		if c.path == "/err" {
			// the outcome of the failed run is its note (taken from the Go run's entry)
			c.scripted[0].Fail = fsNote(goOut.Entry)
		}
		if c.path == "/small" {
			c.scripted[0].Skip = fsNote(goOut.Entry)
		}
		natOut := fsRun(t, e, c.path, c.body, gen, c.scripted)
		natLog := scriptLog(e)
		if c.path == "/two" {
			// Go runs two2 itself in the hand-over: only its lines are new
			for _, l := range natLog[len(goLog):] {
				if !strings.HasPrefix(l, "two2 ") {
					t.Errorf("/two: hand-over log line %q", l)
				}
			}
			if len(natLog) == len(goLog) {
				t.Errorf("/two: Go did not run the second script")
			}
		}
		if len(natLog) != len(goLog) && c.path != "/two" {
			t.Errorf("%s: the hand-over wrote script log lines: %v", c.path, natLog[len(goLog):])
		}
		g, _ := json.MarshalIndent(goOut, "", " ")
		n, _ := json.MarshalIndent(natOut, "", " ")
		if !bytes.Equal(g, n) {
			t.Errorf("%s differs:\ngo     %s\nscripted %s", c.path, g, n)
		}
	}
	if FlowStats() == "" {
		t.Fatal("stats")
	}
	// a generation the engine no longer has: refused (Swift ends the request)
	hj, _ := json.Marshal(FlowHead{Method: "GET", Target: "/hdr", Host: "api.test.com", ConnHost: "api.test.com", ConnPort: 443, TLS: true,
		Gen: gen + 1000, Scripted: []FlowScripted{{Rule: idx["hdr"]}}})
	if d := parseDecision(t, e.FlowBegin(string(hj))); d.Action != "error" || !strings.Contains(d.Note, "rules changed") {
		t.Fatalf("stale gen: %+v", d)
	}
}

// fsNote is the last request-log note of an fsOutcome entry string ("notes=[a b]" → b).
func fsNote(entry string) string {
	i := strings.Index(entry, "notes=[")
	if i < 0 {
		return ""
	}
	rest := entry[i+len("notes=["):]
	j := strings.Index(rest, "] req=")
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// The Go calls of a native request script's body (admission → release) and the request-log events it adds.
func TestNativeRequestScriptBodyAndRecords(t *testing.T) {
	home := t.TempDir()
	for name, src := range fsScripts {
		if err := writeFileForTest(ScriptsDir(home)+"/"+name, src); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, CaptureBodies: noCapture(), Scripts: items(strings.Split(fsConf, "\n")...)}
	e := New(home, rwDial, nil)
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)
	rs := Build(home, cfg)
	e.Reload(cfg, rs)
	gen := e.RewriteSnapshotGen()
	idx := map[string]int{}
	for i, r := range rs.Rules {
		if r.Kind == KindScript {
			idx[r.Script.Name] = i
		}
	}
	tok := NativeScriptToken()
	var a nsReqAdmitJS
	_ = json.Unmarshal([]byte(e.NativeScriptReqBodyAdmit(gen, idx["body"], "https://api.test.com/body", 3, tok)), &a)
	if !a.OK || a.Ticket <= 0 || a.Cap < 3 || a.Limit < 3 {
		t.Fatalf("admit: %+v", a)
	}
	if bodyBudget.inUse() == 0 && smallBudget.inUse() == 0 {
		t.Fatal("no body share held")
	}
	NativeScriptBodyRelease(a.Ticket)
	var a0 nsReqAdmitJS // fresh: json.Unmarshal keeps fields the new JSON omits (the old ticket)
	_ = json.Unmarshal([]byte(e.NativeScriptReqBodyAdmit(gen, idx["body"], "https://api.test.com/body", 0, tok)), &a0)
	if !a0.OK || a0.Ticket != 0 {
		t.Fatalf("no body: %+v", a0)
	}
	var r nsReqAdmitJS
	_ = json.Unmarshal([]byte(e.NativeScriptReqBodyAdmit(gen, idx["small"], "https://api.test.com/small", 16, tok)), &r)
	if r.OK || !r.Retry || r.Skip != "请求体 0 KB 超过上限 0 KB" {
		t.Fatalf("over limit: %+v", r)
	}
	if n := e.NativeScriptReqBodySkip(gen, idx["small"], r.Skip, -1); n != "跳过脚本：small — 请求体 0 KB 超过上限 0 KB" {
		t.Fatalf("skip note %q", n)
	}
	if n := e.NativeScriptReqBodySkip(gen, idx["small"], "", 4096); !strings.HasPrefix(n, "跳过脚本：small — 请求体 4 KB 超过上限 0 KB（") {
		t.Fatalf("loaded over limit note %q", n)
	}
	if l := e.NativeScriptReqLimit(gen, idx["small"]); l != 8 {
		t.Fatalf("limit %d", l)
	}
	NativeScriptCancel(tok)
	if h := NativeScriptHeld(); h != 0 {
		t.Fatalf("held %d", h)
	}
	if bodyBudget.inUse() != 0 || smallBudget.inUse() != 0 {
		t.Fatalf("budget left: %d / %d", bodyBudget.inUse(), smallBudget.inUse())
	}
	// request-log events: forward with notes and a changed method, drop with a script's abort
	recs := []NativeRecord{
		{K: 9001, Ev: "forward", T: 1, Gen: gen, Rules: []int{idx["url"]}, Method: "GET", URL: "https://api.test.com/changed?x=1", Host: "api.test.com", TLS: true,
			Headers: [][2]string{{"User-Agent", "T/1"}}, Notes: []string{"跳过脚本：x — y"}, ReqMethod: "POST"},
		{K: 9001, Ev: "end", Ms: 2},
		{K: 9002, Ev: "drop", T: 2, Gen: gen, Rules: []int{idx["abort"]}, Method: "GET", URL: "https://api.test.com/abort", Host: "api.test.com", TLS: true, Why: "脚本中止：abort"},
	}
	js, _ := json.Marshal(recs)
	if n := e.RecordNative(string(js)); n != 3 {
		t.Fatalf("applied %d", n)
	}
	list := e.Requests.List(0)
	var fwd, drop *Entry
	for _, s := range list {
		ent := e.Requests.Get(s.ID)
		switch ent.URL {
		case "https://api.test.com/changed?x=1":
			fwd = ent
		case "https://api.test.com/abort":
			drop = ent
		}
	}
	if fwd == nil || fwd.Method != "POST" || len(fwd.Notes) != 1 || fwd.Notes[0] != "跳过脚本：x — y" || len(fwd.Matched) != 1 {
		t.Fatalf("forward entry %+v", fwd)
	}
	if drop == nil || drop.Status != 0 || len(drop.Notes) != 1 || drop.Notes[0] != "脚本中止：abort" || !drop.Done {
		t.Fatalf("drop entry %+v", drop)
	}
}
