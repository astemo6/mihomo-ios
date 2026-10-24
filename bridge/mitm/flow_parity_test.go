package mitm

// Differential tests: the same request through the Go path (the engine's CONNECT listener, crypto/tls,
// serveHTTP, ReverseProxy) and through the native flow API (flowSim playing the Swift session) must give the
// client the same status, headers and body, and the upstream the same request.

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

type parityCase struct {
	name, method, url string
	hdr               []string
	body              string
}

func (c parityCase) header() http.Header {
	// both clients send the same User-Agent (Go's client would add its own on the Go path)
	h := http.Header{"User-Agent": {"TernTest/1"}}
	for i := 0; i+1 < len(c.hdr); i += 2 {
		h.Set(c.hdr[i], c.hdr[i+1])
	}
	return h
}

// runParity drives every case through both paths; a mismatch is retried once against a second Go-path run
// (stateful scripts) before it counts.
func runParity(t *testing.T, h *harness, sim *flowSim, cases []parityCase) (same, diff int) {
	t.Helper()
	for _, c := range cases {
		m := c.method
		if m == "" {
			m = "GET"
		}
		var body []byte
		if c.body != "" || m == "POST" || m == "PUT" {
			body = []byte(c.body)
		}
		g := goDo(t, h.client, m, c.url, c.header(), body)
		f := sim.do(m, c.url, c.header(), body)
		why := sameOutcome(g, f)
		if why != "" {
			g2 := goDo(t, h.client, m, c.url, c.header(), body)
			if sameOutcome(g2, f) == "" {
				why = ""
			}
		}
		if why != "" {
			diff++
			t.Errorf("%s (%s %s): %s\n decisions: %+v", c.name, m, c.url, why, f.decisions)
			continue
		}
		same++
	}
	return
}

var compatParityCases = []parityCase{
	{"sg reject", "", "https://api.test.com/s/reject", nil, ""},
	{"sg reject-200", "", "https://api.test.com/s/r200", nil, ""},
	{"sg reject-img", "", "https://api.test.com/s/img", nil, ""},
	{"sg reject-dict", "", "https://api.test.com/s/dict", nil, ""},
	{"sg reject-array", "", "https://api.test.com/s/array", nil, ""},
	{"sg 302 $1", "", "https://api.test.com/s/302/abc", nil, ""},
	{"sg 307", "", "https://api.test.com/s/307", nil, ""},
	{"sg header (transparent)", "", "https://api.test.com/s/hdr", nil, ""},
	{"sg header-add", "", "https://api.test.com/echo?s1", nil, ""},
	{"sg header-del", "", "https://api.test.com/echo?s2", []string{"X-Gone", "1"}, ""},
	{"sg header-replace", "", "https://api.test.com/echo?s3", []string{"User-Agent", "Old/1"}, ""},
	{"sg header-replace-regex", "", "https://api.test.com/echo?s4", []string{"User-Agent", "Old/1"}, ""},
	{"sg response header-add", "", "https://api.test.com/json?s5", nil, ""},
	{"sg body rewrite", "", "https://api.test.com/json?s6", nil, ""},
	{"sg jq", "", "https://api.test.com/json?s7", nil, ""},
	{"sg request body rewrite", "POST", "https://api.test.com/echo?s8", nil, "xaaax"},
	{"sg map local text", "", "https://api.test.com/s/ml1", nil, ""},
	{"sg map local base64", "", "https://api.test.com/s/ml2", nil, ""},
	{"sg map local gif", "", "https://api.test.com/s/ml3", nil, ""},
	{"lo reject", "", "https://api.test.com/l/reject", nil, ""},
	{"lo reject-dict", "", "https://api.test.com/l/dict", nil, ""},
	{"lo 302", "", "https://api.test.com/l/302", nil, ""},
	{"lo 307", "", "https://api.test.com/l/307", nil, ""},
	{"lo json-del", "", "https://api.test.com/json?l1", nil, ""},
	{"lo json-replace", "", "https://api.test.com/json?l2", nil, ""},
	{"lo json-add", "", "https://api.test.com/json?l3", nil, ""},
	{"lo mock-response-body", "", "https://api.test.com/l/mock", nil, ""},
	{"lo request-header-add", "", "https://api.test.com/echo?l4", nil, ""},
	{"lo request-header-del", "", "https://api.test.com/echo?l5", []string{"X-Gone", "1"}, ""},
	{"lo response-header-add", "", "https://api.test.com/json?l6", nil, ""},
	{"lo script argument object", "", "https://api.test.com/json?l7", nil, ""},
	{"qx reject", "", "https://api.test.com/q/reject", nil, ""},
	{"qx reject-200", "", "https://api.test.com/q/r200", nil, ""},
	{"qx reject-img", "", "https://api.test.com/q/img", nil, ""},
	{"qx reject-dict", "", "https://api.test.com/q/dict", nil, ""},
	{"qx reject-array", "", "https://api.test.com/q/array", nil, ""},
	{"qx 302", "", "https://api.test.com/q/302", nil, ""},
	{"qx 307", "", "https://api.test.com/q/307", nil, ""},
	{"qx request-header regex", "", "https://api.test.com/echo?q1", []string{"User-Agent", "Old/1"}, ""},
	{"qx response-body regex", "", "https://api.test.com/json?q2", nil, ""},
	{"qx request-body regex", "POST", "https://api.test.com/echo?q3", nil, "xaaax"},
	{"qx jsonjq-response-body", "", "https://api.test.com/json?q4", nil, ""},
	{"qx echo-response", "", "https://api.test.com/q/echo", nil, ""},
	{"qx request-header spaces", "", "https://api.test.com/echo?q9", []string{"User-Agent", "Old/1"}, ""},
	{"qx response-body spaces", "", "https://api.test.com/json?q10", nil, ""},
	{"qx script-response-body", "", "https://api.test.com/json?q5", nil, ""},
	{"qx script-echo-response", "", "https://api.test.com/q/answer", nil, ""},
	{"eg reject-dict", "", "https://api.test.com/e/dict", nil, ""},
	{"eg 302", "", "https://api.test.com/e/302", nil, ""},
	{"eg header mode", "", "https://api.test.com/e/hdr", nil, ""},
	{"eg header add", "", "https://api.test.com/echo?e1", nil, ""},
	{"eg header delete", "", "https://api.test.com/echo?e2", []string{"X-Gone", "1"}, ""},
	{"eg response replace", "", "https://api.test.com/json?e3", nil, ""},
	{"eg response_regex", "", "https://api.test.com/json?e4", nil, ""},
	{"eg response_jq", "", "https://api.test.com/json?e5", nil, ""},
	{"eg map_locals", "", "https://api.test.com/e/ml", nil, ""},
	{"eg env $argument", "", "https://api.test.com/json?e6", nil, ""},
	{"eg env_schema", "", "https://api.test.com/json?e7", nil, ""},
	// no rule at all: plain pass-through both ways
	{"untouched json", "", "https://api.test.com/json?none", nil, ""},
	{"untouched gzip", "", "https://api.test.com/gzip", nil, ""},
	{"untouched binary", "", "https://api.test.com/bin", nil, ""},
	{"untouched POST echo", "POST", "https://api.test.com/echo?plain", []string{"Content-Type", "text/plain", "X-Forwarded-For", "1.2.3.4", "Forwarded", "for=1.2.3.4"}, "hello body"},
	{"untouched HEAD", "HEAD", "https://api.test.com/json?head", nil, ""},
}

// compatHarness is TestCompatRuleMatrix's setup: the four module formats installed side by side.
func compatHarness(t *testing.T) *harness {
	mods := []struct{ id, plat, text string }{
		{"sg", "Surge", surgeCompatModule}, {"lo", "Loon", loonCompatModule}, {"qx", "QX", qxCompatModule}, {"eg", "Egern", egernCompatModule},
	}
	cfg := &Config{Enabled: true, MitM: true}
	for _, m := range mods {
		cfg.Modules = append(cfg.Modules, Module{ID: m.id, Name: m.plat, Enabled: true, Args: map[string]string{"word": "hello", "MODE": "b"}})
	}
	h := newHarness(t, cfg, map[string]string{
		"arg.js":    `var o=JSON.parse($response.body); o.arg=$argument; $done({body: JSON.stringify(o)})`,
		"qx.js":     `var o=JSON.parse($response.body); o.qx=1; $done({body: JSON.stringify(o)})`,
		"answer.js": `$done({status: "HTTP/1.1 200 OK", headers: {"Content-Type": "application/json"}, body: JSON.stringify({answered: $request.url})})`,
		"env.js":    `var o=JSON.parse($response.body); o.arg=$argument; $done({body: JSON.stringify(o)})`,
		"mode.js":   `export default async function(ctx){ const d=await ctx.response.json(); d.mode=ctx.env.MODE||"unset"; return {body: d}; }`,
		"echo.json": `{"echo":1}`,
	})
	for _, m := range mods {
		if err := writeFileForTest(ModulePath(h.home, m.id), m.text); err != nil {
			t.Fatal(err)
		}
	}
	rs := Build(h.home, cfg)
	for _, e := range rs.Errors {
		t.Errorf("parse error: %s", e)
	}
	h.e.Reload(cfg, rs)
	return h
}

// TestFlowParityCompatMatrix: every row of the Surge / Loon / QX / Egern rule matrix gives the same answer
// through the flow API as through the Go path, with small and odd push sizes.
func TestFlowParityCompatMatrix(t *testing.T) {
	h := compatHarness(t)
	for _, chunk := range []int{1, 333, 32 << 10} {
		sim := newFlowSim(t, h.e)
		sim.chunk = chunk
		same, diff := runParity(t, h, sim, compatParityCases)
		t.Logf("push %d: %d same, %d different", chunk, same, diff)
	}
	if n := flowLive.Load(); n != 0 {
		t.Fatalf("%d flows left open", n)
	}
	if n := flowPipeBytes.Load(); n != 0 {
		t.Fatalf("%d pipe bytes left", n)
	}
}

const scriptParityConf = `
reqhdr = type=http-request,pattern=^https://api\.test\.com/echo\?rh,script-path=reqhdr.js
reqbody = type=http-request,pattern=^https://api\.test\.com/echo\?rb,requires-body=1,script-path=reqbody.js
requrl = type=http-request,pattern=^https://api\.test\.com/echo\?ru,script-path=requrl.js
reqmock = type=http-request,pattern=^https://api\.test\.com/echo\?rm,script-path=reqmock.js
reqabort = type=http-request,pattern=^https://api\.test\.com/echo\?ra,script-path=reqabort.js
respbody = type=http-response,pattern=^https://api\.test\.com/(json|gzip)\?sb,requires-body=1,script-path=respbody.js
respstatus = type=http-response,pattern=^https://api\.test\.com/json\?ss,requires-body=1,script-path=respstatus.js
resphdr = type=http-response,pattern=^https://api\.test\.com/json\?sh,script-path=resphdr.js
respbin = type=http-response,pattern=^https://api\.test\.com/bin\?bb,requires-body=1,binary-body-mode=1,script-path=respbin.js
respnone = type=http-response,pattern=^https://api\.test\.com/json\?sn,requires-body=1,script-path=respnone.js
resperr = type=http-response,pattern=^https://api\.test\.com/json\?se,requires-body=1,script-path=resperr.js
respmock = type=http-response,pattern=^https://api\.test\.com/json\?sm,script-path=respmock.js
`

var scriptParityJS = map[string]string{
	"reqhdr.js":     `var h=$request.headers; h["X-Script"]="1"; delete h["X-Gone"]; $done({headers:h})`,
	"reqbody.js":    `$done({body: ($request.body||"").toUpperCase() + "|" + $request.method})`,
	"requrl.js":     `$done({url: $request.url.replace("ru","ru2"), method: "PUT"})`,
	"reqmock.js":    `$done({response: {status: 418, headers: {"X-Mock": "1"}, body: "mocked " + $request.url}})`,
	"reqabort.js":   `$done({abort: true})`,
	"respbody.js":   `var o=JSON.parse($response.body); o.vip=true; o.url=$request.url; $done({body: JSON.stringify(o)})`,
	"respstatus.js": `$done({status: 201, headers: Object.assign({}, $response.headers, {"X-S": "s"}), body: "changed"})`,
	"resphdr.js":    `var h=$response.headers; h["X-Resp-Script"]="ok"; $done({headers: h})`,
	"respbin.js":    `var b=new Uint8Array($response.bodyBytes); b[0]=9; $done({bodyBytes: b.buffer})`,
	"respnone.js":   `$done({})`,
	"resperr.js":    `throw new Error("boom")`,
	"respmock.js":   `$done({body: "replaced without body"})`,
}

// TestFlowParityScripts: request / response scripts (headers, bodies, URL and method changes, local answers,
// abort, status changes, binary bodies, errors) agree between the two paths.
func TestFlowParityScripts(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}}
	cfg.Scripts = itemsFromConf(scriptParityConf)
	h := newHarness(t, cfg, scriptParityJS)
	cases := []parityCase{
		{"req headers", "", "https://api.test.com/echo?rh", []string{"X-Gone", "x", "X-Keep", "k"}, ""},
		{"req body", "POST", "https://api.test.com/echo?rb", nil, "hello"},
		{"req body empty", "POST", "https://api.test.com/echo?rb", nil, ""},
		{"req body large", "POST", "https://api.test.com/echo?rb", nil, strings.Repeat("abc", 100<<10)},
		{"req url+method", "", "https://api.test.com/echo?ru", nil, ""},
		{"req mock", "", "https://api.test.com/echo?rm", nil, ""},
		{"req abort", "", "https://api.test.com/echo?ra", nil, ""},
		{"resp body", "", "https://api.test.com/json?sb", nil, ""},
		{"resp body gzip", "", "https://api.test.com/gzip?sb", nil, ""},
		{"resp status", "", "https://api.test.com/json?ss", nil, ""},
		{"resp headers", "", "https://api.test.com/json?sh", nil, ""},
		{"resp binary", "", "https://api.test.com/bin?bb", nil, ""},
		{"resp untouched $done({})", "", "https://api.test.com/json?sn", nil, ""},
		{"resp script error", "", "https://api.test.com/json?se", nil, ""},
		{"resp body without requires-body", "", "https://api.test.com/json?sm", nil, ""},
	}
	for _, chunk := range []int{5, 32 << 10} {
		sim := newFlowSim(t, h.e)
		sim.chunk = chunk
		same, diff := runParity(t, h, sim, cases)
		t.Logf("push %d: %d same, %d different", chunk, same, diff)
	}
	if n := flowLive.Load(); n != 0 {
		t.Fatalf("%d flows left open", n)
	}
}

func itemsFromConf(s string) []Item {
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return items(lines...)
}

// TestFlowParityLane: with the native body lane (fake lane + native engine stand-in), script bodies of every
// encoding and size agree with the Go path, large results are handed to the native side as lane handles
// (no copy through Go), and every handle is freed once the flow ends.
func TestFlowParityLane(t *testing.T) {
	l := useFakeLane(t)
	h := newLaneHarness(t, laneCfg(""), map[string]string{"vip.js": vipJS})
	sim := newFlowSim(t, h.e)
	sim.lane = l
	var cases []parityCase
	for _, enc := range []string{"identity", "gzip", "deflate", "br"} {
		for _, n := range []int{100, 300 << 10} {
			cases = append(cases, parityCase{fmt.Sprintf("%s %d", enc, n), "", fmt.Sprintf("https://api.test.com/body?enc=%s&n=%d", enc, n), nil, ""})
		}
	}
	modes := map[string]int{}
	sim.hook = func(id int64, stage string, d flowDecision) {
		if stage == "response" || (stage == "await" && d.Action == "respond") {
			modes[d.Body]++
		}
	}
	same, diff := runParity(t, h, sim, cases)
	t.Logf("%d same, %d different; response body modes %v", same, diff, modes)
	if modes["lane"] == 0 {
		t.Fatalf("no response was handed over as a lane handle: %v", modes)
	}
	waitLive(t, l)
}
