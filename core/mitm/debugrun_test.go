package mitm

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDebugRunResponse(t *testing.T) {
	home := t.TempDir()
	code := `console.log("url", $request.url); let o = JSON.parse($response.body); o.ad = false; console.warn("n", 2);
$notification.post("t", "s", "b"); $done({ body: JSON.stringify(o), status: 201 });`
	out := DebugRun(home, DebugInput{Code: code, Type: "http-response",
		Request:  &DebugHTTP{URL: "https://api.example.com/feed"},
		Response: &DebugHTTP{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"ad":true}`}}, nil)
	if !out.OK || !out.Done || out.Result == nil {
		t.Fatalf("out %+v", out)
	}
	if out.Result.Body != `{"ad":false}` || out.Result.Status != 201 {
		t.Fatalf("result %+v", out.Result)
	}
	if len(out.Logs) != 2 || out.Logs[0].Msg != "url https://api.example.com/feed" || out.Logs[1].Level != "warn" {
		t.Fatalf("logs %+v", out.Logs)
	}
	if len(out.Notifications) != 1 || out.Notifications[0]["title"] != "t" {
		t.Fatalf("notifs %+v", out.Notifications)
	}
	// Captured notifications must not land in the user's history.
	if _, err := os.Stat(filepath.Join(EngineDir(home), "notifications.json")); err == nil {
		t.Fatal("debug run wrote notification history")
	}
}

func TestDebugRunRequestMockAndErrors(t *testing.T) {
	home := t.TempDir()
	out := DebugRun(home, DebugInput{Code: `$done({response: {status: 200, body: "hi"}})`, Type: "http-request",
		Request: &DebugHTTP{URL: "http://boxjs.com/"}}, nil)
	if !out.OK || out.Mock == nil || out.Mock.Body != "hi" {
		t.Fatalf("mock %+v", out)
	}
	out = DebugRun(home, DebugInput{Code: `let x = ;`, Type: "http-request"}, nil)
	if out.OK || !strings.Contains(out.Error, "语法") {
		t.Fatalf("syntax %+v", out)
	}
	out = DebugRun(home, DebugInput{Code: `null.x`, Type: "generic"}, nil)
	if out.OK || !strings.Contains(out.Error, "异常") {
		t.Fatalf("exception %+v", out)
	}
	out = DebugRun(home, DebugInput{Code: `while(true){}`, Type: "generic", Timeout: 1}, nil)
	if out.OK || !strings.Contains(out.Error, "超时") || out.DurationMs < 900 {
		t.Fatalf("timeout %+v", out)
	}
	out = DebugRun(home, DebugInput{Code: `console.log(typeof $argument, $argument)`, Type: "cron", Argument: strPtr("a=1")}, nil)
	if !out.OK || out.Done || len(out.Logs) != 1 || out.Logs[0].Msg != "string a=1" || len(out.Summary) == 0 {
		t.Fatalf("argument %+v", out)
	}
}

func TestDebugRunGenericHTTPClientAndEgern(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("pong")) }))
	defer srv.Close()
	home := t.TempDir()
	out := DebugRun(home, DebugInput{Code: `$httpClient.get("` + srv.URL + `", (e, r, d) => { console.log(d); $done({title: "x", content: d}) })`, Type: "generic"}, nil)
	if !out.OK || !out.Done || len(out.Logs) != 1 || out.Logs[0].Msg != "pong" || !strings.Contains(out.DoneJSON, `"content": "pong"`) {
		t.Fatalf("generic %+v", out)
	}
	eg := `export default async function(ctx) { const b = ctx.response.json(); b.v = 2; return { body: JSON.stringify(b) } }`
	out = DebugRun(home, DebugInput{Code: eg, Type: "http-response", Response: &DebugHTTP{Body: `{"v":1}`}}, nil)
	if !out.OK || out.Result == nil || out.Result.Body != `{"v":2}` {
		t.Fatalf("egern %+v %+v", out, out.Result)
	}
	// Local script by path.
	_ = os.MkdirAll(ScriptsDir(home), 0o755)
	_ = os.WriteFile(filepath.Join(ScriptsDir(home), "a.js"), []byte(`$done({})`), 0o644)
	out = DebugRun(home, DebugInput{Path: "a.js", Type: "http-request"}, nil)
	if !out.OK || !out.Done || out.Summary[0] != "$done() 未做修改：原样放行" {
		t.Fatalf("path %+v", out)
	}
}

func strPtr(s string) *string { return &s }
