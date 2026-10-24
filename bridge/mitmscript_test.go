package libmihomo

import (
	"encoding/json"
	"math"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
)

// TestMitmScriptTestHook: the unit-test engine of lane s3-script starts, takes flows (goja here: no JavaScriptCore
// in Go tests), reports its logs / entries, exposes script rules in the snapshot, and stops.
func TestMitmScriptTestHook(t *testing.T) {
	// The hook's engine runs in a process without a tunnel (the unit-test host: no GOMEMLIMIT, no available-memory
	// probe). In this package earlier tests start the core, which sets the tunnel's GOMEMLIMIT (startGC) and leaves
	// it set with a large heap behind; heapHigh() then refuses body work and script downloads by design (CI
	// 40079040185: the $httpClient download was refused at once). Run under the host's conditions instead.
	defer debug.SetMemoryLimit(debug.SetMemoryLimit(math.MaxInt64))
	home := t.TempDir()
	conf := `vip = type=http-response,pattern=^https://api\.test\.com/vip,requires-body=1,script-path=vip.js
fetch = type=http-response,pattern=^https://api\.test\.com/fetch,requires-body=1,script-path=fetch.js
rule: http-response ^https://api\.test\.com/vip header-add X-Rule 1`
	scripts, _ := json.Marshal(map[string]string{
		"vip.js":   `var o=JSON.parse($response.body); o.vip=true; console.log("ran"); $done({body: JSON.stringify(o)})`,
		"fetch.js": `$httpClient.get({url:"http://fetch.test/gz", headers:{"User-Agent":"T/1"}}, function(e,r,d){ $done({body: e ? "error: " + e : d}) })`,
	})
	if msg := MitmScriptTestStart(home, conf, string(scripts), "api.test.com"); msg != "" {
		t.Fatal(msg)
	}
	defer MitmScriptTestStop()
	if MitmRewriteGeneration() == 0 || !strings.Contains(MitmRewriteSnapshot(), `"kind":"script"`) {
		t.Fatalf("snapshot: %s", MitmRewriteSnapshot())
	}
	run := func(path string, body string) string {
		d := MitmFlowBegin(`{"method":"GET","target":"` + path + `","host":"api.test.com","headers":[],"length":0,"connHost":"api.test.com","connPort":443,"tls":true}`)
		var fd struct {
			ID     int64  `json:"id"`
			Action string `json:"action"`
		}
		_ = json.Unmarshal([]byte(d), &fd)
		if fd.Action != "forward" {
			t.Fatalf("%s: %s", path, d)
		}
		r := MitmFlowResponse(fd.ID, `{"status":200,"headers":[["Content-Type","application/json"],["Content-Length","`+strconv.Itoa(len(body))+`"]],"length":`+strconv.Itoa(len(body))+`}`)
		for strings.Contains(r, `"need-body"`) {
			MitmFlowWrite(fd.ID, 1, []byte(body))
			MitmFlowClose(fd.ID, 1, "")
			r = MitmFlowAwait(fd.ID)
		}
		var out []byte
		for i := 0; i < 1000; i++ {
			b := MitmFlowRead(fd.ID, 1, 32<<10)
			out = append(out, b...)
			if len(b) == 0 && MitmFlowReadState(fd.ID, 1) == "eof" {
				break
			}
		}
		MitmFlowEnd(fd.ID, 0, "")
		return string(out)
	}
	if !strings.Contains(MitmRewriteSnapshot(), `"phase":"response","re"`) || !strings.Contains(MitmRewriteSnapshot(), `"kind":"header"`) {
		t.Fatalf("response header rule missing: %s", MitmRewriteSnapshot())
	}
	if got := run("/vip", `{"a":1}`); got != `{"a":1,"vip":true}` {
		t.Fatalf("vip body %q", got)
	}
	if got := run("/fetch", `{}`); !strings.Contains(got, `"ua":"T/1"`) || !strings.Contains(got, `"path":"/gz"`) {
		t.Fatalf("fetch body %q; engine: %s", got, MitmScriptTestTake())
	}
	take := MitmScriptTestTake()
	if !strings.Contains(take, `"msg":"ran"`) || !strings.Contains(take, "api.test.com/vip") || !strings.Contains(take, "X-Rule") && !strings.Contains(take, `"matched"`) {
		t.Fatalf("take: %s", take)
	}
	if len(MitmScriptTestEncode("br", []byte("hello"))) == 0 || MitmScriptTestEncode("zstd", nil) != nil {
		t.Fatal("encode")
	}
}
