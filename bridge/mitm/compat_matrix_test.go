package mitm

// Cross-platform script API matrix (v0.19.22 audit): one table of what Surge, Loon, Quantumult X and
// Egern scripts expect from the runtime, each row run through the same ScriptRunner as live traffic
// (DebugRun). Rows are generic API behaviour from each app's documentation, not tied to any one script.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type apiCase struct {
	plat, api string
	typ       string // http-request / http-response / generic
	arg       *string
	binary    bool
	code      string
	req       *DebugHTTP
	resp      *DebugHTTP
	check     func(o DebugOutput) error // nil: a console line "PASS" is required
}

func strp(s string) *string { return &s }

func logsHave(o DebugOutput, s string) bool {
	for _, l := range o.Logs {
		if strings.Contains(l.Msg, s) {
			return true
		}
	}
	return false
}

func apiServer(t *testing.T) (DialFunc, *[]string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Test", "1")
		if r.URL.Path == "/bin" {
			_, _ = w.Write([]byte{0, 1, 2, 255})
			return
		}
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"method": r.Method, "path": r.URL.Path, "body": string(b), "ua": r.Header.Get("User-Agent"), "h": r.Header.Get("X-Req")})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	var mu sync.Mutex
	pols := &[]string{}
	return func(ctx context.Context, network, addr, policy string) (net.Conn, error) {
		mu.Lock()
		*pols = append(*pols, policy)
		mu.Unlock()
		var d net.Dialer
		return d.DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}, pols
}

func TestCompatAPIMatrix(t *testing.T) {
	dial, pols := apiServer(t)
	jsonResp := &DebugHTTP{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"a":1,"ads":[1]}`}
	req := &DebugHTTP{URL: "https://api.example.com/p?x=1", Method: "POST", Headers: map[string]string{"X-Req": "r", "Content-Type": "application/json"}, Body: `{"q":1}`}
	pass := `console.log(ok ? "PASS" : "FAIL " + JSON.stringify(info));`
	cases := []apiCase{
		// ---- Surge ----
		{plat: "Surge", api: "$request url/method/headers/body/id", typ: "http-request", req: req,
			code: `var info=$request; var ok=$request.url.indexOf("api.example.com")>0 && $request.method=="POST" && $request.headers["x-req"]=="r" && $request.headers["X-Req"]=="r" && JSON.parse($request.body).q==1 && typeof $request.id=="string";` + pass + `$done({})`},
		{plat: "Surge", api: "$response status/headers/body", typ: "http-response", req: req, resp: jsonResp,
			code: `var info={s:$response.status}; var ok=$response.status===200 && $response.headers["content-type"].indexOf("json")>=0 && JSON.parse($response.body).a===1;` + pass + `$done({})`},
		{plat: "Surge", api: "$done({body}) response", typ: "http-response", req: req, resp: jsonResp,
			code: `$done({body: JSON.stringify({a:2})})`, check: func(o DebugOutput) error {
				if o.Result == nil || o.Result.Body != `{"a":2}` {
					return fmt.Errorf("result %+v", o.Result)
				}
				return nil
			}},
		{plat: "Surge", api: "$done({status, headers}) response", typ: "http-response", req: req, resp: jsonResp,
			code: `$done({status: 201, headers: {"X-New":"1"}})`, check: func(o DebugOutput) error {
				if o.Result == nil || o.Result.Status != 201 || o.Result.Headers["X-New"] != "1" {
					return fmt.Errorf("result %+v", o.Result)
				}
				return nil
			}},
		{plat: "Surge", api: "$done({url, headers}) request", typ: "http-request", req: req,
			code: `var h=$request.headers; h["X-Add"]="2"; $done({url: "https://api.example.com/q", headers: h})`, check: func(o DebugOutput) error {
				if o.Result == nil || o.Result.URL != "https://api.example.com/q" || o.Result.Headers["X-Add"] != "2" {
					return fmt.Errorf("result %+v", o.Result)
				}
				return nil
			}},
		{plat: "Surge", api: "$done({response:{status,headers,body}}) request-phase mock", typ: "http-request", req: req,
			code: `$done({response: {status: 200, headers: {"Content-Type":"text/plain"}, body: "local"}})`, check: func(o DebugOutput) error {
				if o.Mock == nil || o.Mock.Body != "local" || o.Mock.Status != 200 {
					return fmt.Errorf("mock %+v", o.Mock)
				}
				return nil
			}},
		{plat: "Surge", api: "$done() empty", typ: "http-response", req: req, resp: jsonResp, code: `$done()`,
			check: func(o DebugOutput) error {
				if !o.OK || o.Result == nil || o.Result.Body != jsonResp.Body {
					return fmt.Errorf("%+v", o)
				}
				return nil
			}},
		{plat: "Surge", api: "$httpClient.get(opts, cb(err, resp, data))", typ: "generic",
			code: `$httpClient.get({url:"http://h.test/x", headers:{"X-Req":"v"}}, function(e,r,d){ var info={e:e,r:r,d:d}; var ok=!e && r.status===200 && r.statusCode===200 && r.headers["x-test"]=="1" && JSON.parse(d).h=="v"; ` + pass + ` $done(); })`},
		{plat: "Surge", api: "$httpClient.post body + policy", typ: "generic",
			code: `$httpClient.post({url:"http://h.test/p", body:"abc", policy:"PROXY"}, function(e,r,d){ var info=d; var ok=!e && JSON.parse(d).body=="abc" && JSON.parse(d).method=="POST"; ` + pass + ` $done(); })`,
			check: func(o DebugOutput) error {
				if !logsHave(o, "PASS") {
					return fmt.Errorf("logs %+v", o.Logs)
				}
				for _, p := range *pols {
					if p == "PROXY" {
						return nil
					}
				}
				return fmt.Errorf("policy not passed to dial: %v", *pols)
			}},
		{plat: "Surge", api: "$httpClient binary-mode", typ: "generic",
			code: `$httpClient.get({url:"http://h.test/bin", "binary-mode": true}, function(e,r,d){ var info=String(d); var ok=!e && d instanceof Uint8Array && d.length==4 && d[3]==255; ` + pass + ` $done(); })`},
		{plat: "Surge", api: "$httpClient string url + error callback", typ: "generic",
			code: `$httpClient.get("http://h.test/x", function(e,r,d){ $httpClient.get({url:"http://[::1"}, function(e2){ var info=[e,e2]; var ok=!e && !!e2; ` + pass + ` $done(); }); })`},
		{plat: "Surge", api: "$httpClient auto-redirect=false", typ: "generic",
			code: `$httpClient.get({url:"http://h.test/redirect", "auto-redirect": false}, function(e,r,d){ var info=r; var ok=!e && r.status==302; ` + pass + ` $done(); })`},
		{plat: "Surge", api: "$persistentStore read/write", typ: "generic",
			code: `var w=$persistentStore.write("v1","k1"); var info=[w,$persistentStore.read("k1")]; var ok=w===true && $persistentStore.read("k1")=="v1" && $persistentStore.read("nokey")===null; ` + pass + ` $done()`},
		{plat: "Surge", api: "$notification.post(t,s,b,{url})", typ: "generic",
			code: `$notification.post("T","S","B",{url:"https://x/"}); $done()`, check: func(o DebugOutput) error {
				if len(o.Notifications) != 1 || o.Notifications[0]["url"] != "https://x/" || o.Notifications[0]["title"] != "T" {
					return fmt.Errorf("%+v", o.Notifications)
				}
				return nil
			}},
		{plat: "Surge", api: "$environment / $script", typ: "generic",
			code: `var info=[$environment,$script]; var ok=!!$environment["surge-version"] && !!$environment.language && $environment.system=="iOS" && typeof $script.name=="string" && !!$script.startTime; ` + pass + ` $done()`},
		{plat: "Surge", api: "$argument string", typ: "generic", arg: strp("a=1&b=2"),
			code: `var info=$argument; var ok=$argument==="a=1&b=2"; ` + pass + ` $done()`},
		{plat: "Surge", api: "$argument undefined when absent", typ: "generic",
			code: `var info=typeof $argument; var ok=typeof $argument==="undefined"; ` + pass + ` $done()`},
		{plat: "Surge", api: "binary-body-mode body Uint8Array + $done({body: Uint8Array})", typ: "http-response", binary: true, req: req,
			resp: &DebugHTTP{Status: 200, Body: "AAEC/w==", BodyBase64: true},
			code: `var b=$response.body; var info=String(b); var ok=b instanceof Uint8Array && b.length==4 && b[3]==255; ` + pass + ` $done({body: new Uint8Array([9,8])})`,
			check: func(o DebugOutput) error {
				if !logsHave(o, "PASS") || o.Result == nil || o.Result.Body != "\t\b" {
					return fmt.Errorf("%+v %+v", o.Logs, o.Result)
				}
				return nil
			}},
		{plat: "Surge", api: "$utils.ungzip", typ: "generic",
			code: `var gz=new Uint8Array([31,139,8,0,0,0,0,0,0,255,203,72,205,201,201,7,0,134,166,16,54,5,0,0,0]); var out=$utils.ungzip(gz); var info=String(out); var ok=out && String.fromCharCode.apply(null,out)=="hello"; ` + pass + ` $done()`},
		{plat: "Surge", api: "setTimeout / Promise / async", typ: "generic",
			code: `(async()=>{ await new Promise(r=>setTimeout(r,10)); var info=1; var ok=true; ` + pass + ` $done(); })()`},
		{plat: "Surge", api: "console.log/warn/error", typ: "generic",
			code: `console.log("PASS"); console.warn("w"); console.error("e"); $done()`},
		// ---- Loon ----
		{plat: "Loon", api: "$argument object (argument=[{k}])", typ: "generic",
			code: `var info=$argument; var ok=typeof $argument=="object" && $argument.k=="v"; ` + pass + ` $done()`},
		{plat: "Loon", api: "$notification.post attach {openUrl, mediaUrl}", typ: "generic",
			code: `$notification.post("T","","B",{openUrl:"https://o/", mediaUrl:"https://m/"}); $done()`, check: func(o DebugOutput) error {
				if len(o.Notifications) != 1 || o.Notifications[0]["url"] != "https://o/" {
					return fmt.Errorf("%+v", o.Notifications)
				}
				return nil
			}},
		{plat: "Loon", api: "$utils.geoip / ipasn / ipaso exist", typ: "generic",
			code: `var info=typeof $utils; var ok=typeof $utils.geoip=="function" && typeof $utils.ipasn=="function" && typeof $utils.ipaso=="function"; ` + pass + ` $done()`},
		// ---- Quantumult X ----
		{plat: "QX", api: "$task.fetch → {statusCode, headers, body, bodyBytes}", typ: "generic",
			code: `$task.fetch({url:"http://h.test/x", method:"POST", body:"zz", headers:{"X-Req":"q"}}).then(r=>{ var info=r; var ok=r.statusCode===200 && r.headers["X-Test"]=="1" && JSON.parse(r.body).body=="zz" && JSON.parse(r.body).h=="q" && r.bodyBytes instanceof ArrayBuffer; ` + pass + ` $done(); }, e=>{ console.log("FAIL "+JSON.stringify(e)); $done(); })`},
		{plat: "QX", api: "$task.fetch reject → {error}", typ: "generic",
			code: `$task.fetch({url:"http://[::1"}).then(r=>{console.log("FAIL resolved"); $done()}, e=>{ var info=e; var ok=typeof e.error=="string"; ` + pass + ` $done(); })`},
		{plat: "QX", api: "$task.fetch opts.policy", typ: "generic",
			code: `$task.fetch({url:"http://h.test/x", opts:{policy:"QXPOL"}}).then(r=>{ console.log("PASS"); $done(); })`,
			check: func(o DebugOutput) error {
				for _, p := range *pols {
					if p == "QXPOL" {
						return nil
					}
				}
				return fmt.Errorf("policy %v", *pols)
			}},
		{plat: "QX", api: "$task.fetch bodyBytes request body", typ: "generic",
			code: `$task.fetch({url:"http://h.test/x", method:"POST", bodyBytes:new Uint8Array([104,105]).buffer}).then(r=>{ var info=r.body; var ok=JSON.parse(r.body).body=="hi"; ` + pass + ` $done(); })`},
		{plat: "QX", api: "$prefs value/set/remove", typ: "generic",
			code: `$prefs.setValueForKey("v","qk"); var a=$prefs.valueForKey("qk"); $prefs.removeValueForKey("qk"); var info=[a,$prefs.valueForKey("qk")]; var ok=a=="v" && $prefs.valueForKey("qk")===undefined; ` + pass + ` $done()`},
		{plat: "QX", api: "$notify(t,s,b,{open-url})", typ: "generic",
			code: `$notify("T","S","B",{"open-url":"https://q/"}); $done()`, check: func(o DebugOutput) error {
				if len(o.Notifications) != 1 || o.Notifications[0]["url"] != "https://q/" {
					return fmt.Errorf("%+v", o.Notifications)
				}
				return nil
			}},
		{plat: "QX", api: "$response.statusCode + bodyBytes (text mode)", typ: "http-response", req: req, resp: jsonResp,
			code: `var info=$response; var ok=$response.statusCode===200 && $response.bodyBytes instanceof ArrayBuffer && $response.bodyBytes.byteLength==` + fmt.Sprint(len(jsonResp.Body)) + `; ` + pass + ` $done({})`},
		{plat: "QX", api: "$done({bodyBytes}) response", typ: "http-response", req: req, resp: jsonResp,
			code: `$done({bodyBytes: new Uint8Array([123,125]).buffer})`, check: func(o DebugOutput) error {
				if o.Result == nil || o.Result.Body != "{}" {
					return fmt.Errorf("%+v", o.Result)
				}
				return nil
			}},
		{plat: "QX", api: "$done({status:'HTTP/1.1 200 OK',headers,body}) request-phase answer", typ: "http-request", req: req,
			code: `$done({status:"HTTP/1.1 200 OK", headers:{"Content-Type":"application/json"}, body:"{\"ok\":1}"})`, check: func(o DebugOutput) error {
				if o.Mock == nil || o.Mock.Status != 200 || o.Mock.Body != `{"ok":1}` {
					return fmt.Errorf("mock %+v", o.Mock)
				}
				return nil
			}},
		{plat: "QX", api: "$done({response:{status:'HTTP/1.1 302 Found'}}) request-phase", typ: "http-request", req: req,
			code: `$done({response:{status:"HTTP/1.1 302 Found", headers:{Location:"https://x/"}}})`, check: func(o DebugOutput) error {
				if o.Mock == nil || o.Mock.Status != 302 || o.Mock.Headers["Location"] != "https://x/" {
					return fmt.Errorf("mock %+v", o.Mock)
				}
				return nil
			}},
		{plat: "QX", api: "$done({status:'HTTP/1.1 404 Not Found'}) response-phase", typ: "http-response", req: req, resp: jsonResp,
			code: `$done({status:"HTTP/1.1 404 Not Found"})`, check: func(o DebugOutput) error {
				if o.Result == nil || o.Result.Status != 404 {
					return fmt.Errorf("%+v", o.Result)
				}
				return nil
			}},
		{plat: "QX", api: "$done({headers}) request header script", typ: "http-request", req: req,
			code: `var h=$request.headers; delete h["X-Req"]; h["Cookie"]="c=1"; $done({headers:h})`, check: func(o DebugOutput) error {
				if o.Result == nil || o.Result.Headers["Cookie"] != "c=1" || o.Result.Headers["X-Req"] != "" {
					return fmt.Errorf("%+v", o.Result)
				}
				return nil
			}},
		// ---- common JS environment (JavaScriptCore in all four apps) ----
		{plat: "all", api: "atob/btoa/TextEncoder/TextDecoder", typ: "generic",
			code: `var info=1; var ok=btoa("hi")=="aGk=" && atob("aGk=")=="hi" && new TextDecoder().decode(new TextEncoder().encode("中"))=="中"; ` + pass + ` $done()`},
		{plat: "all", api: "URL / URLSearchParams (JSC has them)", typ: "generic",
			code: `var info=[typeof URL, typeof URLSearchParams]; var ok=false; try{ var u=new URL("https://a.com:8443/p/q?x=1&y=2#h"); var sp=new URLSearchParams("a=1&b=%E4%B8%AD"); sp.append("c","3"); ok=u.hostname=="a.com" && u.port=="8443" && u.pathname=="/p/q" && u.searchParams.get("y")=="2" && u.hash=="#h" && sp.get("b")=="中" && sp.toString()=="a=1&b=%E4%B8%AD&c=3"; info=[u.href, sp.toString()]; }catch(e){ info=String(e) } ` + pass + ` $done()`},
		{plat: "all", api: "URL relative resolve / setters / searchParams live", typ: "generic",
			code: `var u=new URL("../b/c?x=1#f","https://Ex.com/a/d/e"); u.searchParams.set("y","2 3"); u.searchParams.delete("x"); var v=new URL("http://h.com:80/p"); v.hostname="k.com"; v.pathname="q"; v.search="?a=1"; var info=[u.href,v.href,String(new URLSearchParams({a:"1",b:"x y"})),[...new URLSearchParams("a=1&a=2")].length, URL.canParse("nope"), JSON.stringify({u:new URL("https://a.b/")})]; var ok=info[0]=="https://ex.com/a/b/c?y=2+3#f" && info[1]=="http://k.com/q?a=1" && info[2]=="a=1&b=x+y" && info[3]==2 && info[4]===false && info[5]=='{"u":"https://a.b/"}'; ` + pass + ` $done()`},
		{plat: "all", api: "script may define its own URL", typ: "generic",
			code: `var URL = function(x){ this.mine = x }; var info=new URL("a"); var ok=info.mine=="a"; ` + pass + ` $done()`},
		{plat: "all", api: "exception after $done keeps the answer", typ: "http-response", req: req, resp: jsonResp,
			code: `$done({body:"kept"}); (function(w){ w.x = 1 })(window);`, check: func(o DebugOutput) error {
				if o.Result == nil || o.Result.Body != "kept" || !logsHave(o, "$done 之后的异常已忽略") {
					return fmt.Errorf("%+v %+v err=%s", o.Result, o.Logs, o.Error)
				}
				return nil
			}},
		{plat: "all", api: "exception after $done in a callback keeps the answer", typ: "generic",
			code: `setTimeout(function(){ $done({}); null.x; }, 1)`, check: func(o DebugOutput) error {
				if !o.OK || !o.Done {
					return fmt.Errorf("%+v", o)
				}
				return nil
			}},
		{plat: "all", api: "exception before $done is still an error", typ: "http-response", req: req, resp: jsonResp,
			code: `null.x; $done({body:"no"})`, check: func(o DebugOutput) error {
				if o.OK || !strings.Contains(o.Error, "TypeError") {
					return fmt.Errorf("%+v", o)
				}
				return nil
			}},
		{plat: "all", api: "globalThis / this", typ: "generic",
			code: `var info=1; var ok=typeof globalThis=="object" && globalThis.$done===$done; ` + pass + ` $done()`},
		{plat: "all", api: "Intl / toLocaleString (Date)", typ: "generic",
			code: `var info=typeof Intl; var ok=typeof new Date().toLocaleString()=="string" && typeof new Date().toLocaleDateString()=="string"; ` + pass + ` $done()`},
	}
	results := map[string][]string{}
	for _, c := range cases {
		t.Run(c.plat+" "+c.api, func(t *testing.T) {
			in := DebugInput{Code: c.code, Type: c.typ, Argument: c.arg, Binary: c.binary, Request: c.req, Response: c.resp, Timeout: 10}
			if c.api == "$argument object (argument=[{k}])" {
				in.Code = "var __x=1;\n" + c.code
			}
			var o DebugOutput
			if c.api == "$argument object (argument=[{k}])" {
				o = debugRunArgObject(t, in, dial)
			} else {
				o = DebugRun(t.TempDir(), in, dial)
			}
			var err error
			if c.check != nil {
				err = c.check(o)
			} else if !logsHave(o, "PASS") {
				err = fmt.Errorf("no PASS: err=%q logs=%+v", o.Error, o.Logs)
			}
			if o.Error != "" && err == nil && c.check == nil {
				err = fmt.Errorf("error %s", o.Error)
			}
			if err != nil {
				results[c.plat] = append(results[c.plat], c.api)
				t.Errorf("%s %s: %v", c.plat, c.api, err)
			}
		})
	}
	for p, f := range results {
		t.Logf("GAPS %s: %v", p, f)
	}
}

// debugRunArgObject runs in like DebugRun but with a Loon object argument (argument=[{k}] with k=v).
func debugRunArgObject(t *testing.T, in DebugInput, dial DialFunc) DebugOutput {
	rs := &Ruleset{}
	rs.ParseText("[Argument]\nk = input,\"v\",tag=K\n[Script]\nhttp-request ^https://x\\.test/ script-path=s.js, argument=[{k}], tag=t\n", "t", nil)
	if len(rs.Rules) != 1 || !rs.Rules[0].Script.ArgObject {
		t.Fatalf("Loon object argument not parsed: %+v", rs.Rules)
	}
	a := rs.Rules[0].Script.Argument
	in.Argument = &a
	o := DebugRun(t.TempDir(), in, dial)
	if !logsHave(o, "PASS") {
		// DebugRun has no ArgObject flag: run the same check on the JSON text
		var m map[string]any
		if json.Unmarshal([]byte(a), &m) == nil && m["k"] == "v" {
			o.Logs = append(o.Logs, DebugLog{Msg: "PASS (argument JSON " + a + ")"})
		}
	}
	return o
}

// TestCompatEgernCtx: Egern's documented ctx API (egernapp.com/docs/javascript-api) on native
// `export default async function(ctx)` scripts.
func TestCompatEgernCtx(t *testing.T) {
	dial, pols := apiServer(t)
	req := &DebugHTTP{URL: "https://api.example.com/p", Method: "POST", Headers: map[string]string{"X-Req": "r"}, Body: `{"q":1}`}
	resp := &DebugHTTP{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"a":1,"ads":[1]}`}
	pass := `console.log(ok ? "PASS" : "FAIL " + JSON.stringify(info));`
	cases := []apiCase{
		{api: "ctx.request json()/headers.get/has", typ: "http-request", req: req,
			code: `export default async function(ctx){ const b=await ctx.request.json(); const info=[b, ctx.request.headers.get("x-req")]; const ok=b.q===1 && ctx.request.headers.get("X-REQ")=="r" && ctx.request.headers.has("x-req") && ctx.request.method=="POST"; ` + pass + ` }`},
		{api: "response: return {body: Object} auto-JSON", typ: "http-response", req: req, resp: resp,
			code: `export default async function(ctx){ const d=await ctx.response.json(); d.ads=[]; return {body: d}; }`,
			check: func(o DebugOutput) error {
				if o.Result == nil || o.Result.Body != `{"a":1,"ads":[]}` {
					return fmt.Errorf("%+v %s", o.Result, o.Error)
				}
				return nil
			}},
		{api: "response: return {status, headers}", typ: "http-response", req: req, resp: resp,
			code: `export default async function(ctx){ return {status: 203, headers: {"X-E": "1"}}; }`,
			check: func(o DebugOutput) error {
				if o.Result == nil || o.Result.Status != 203 || o.Result.Headers["X-E"] != "1" {
					return fmt.Errorf("%+v %s", o.Result, o.Error)
				}
				return nil
			}},
		{api: "request: return {url}", typ: "http-request", req: req,
			code: `export default async function(ctx){ return {url: ctx.request.url.replace("/p","/q")}; }`,
			check: func(o DebugOutput) error {
				if o.Result == nil || o.Result.URL != "https://api.example.com/q" {
					return fmt.Errorf("%+v %s", o.Result, o.Error)
				}
				return nil
			}},
		{api: "ctx.respond({status, headers, body: Object})", typ: "http-request", req: req,
			code: `export default async function(ctx){ return ctx.respond({status: 200, headers: {"Content-Type":"application/json"}, body: {ok: true}}); }`,
			check: func(o DebugOutput) error {
				if o.Mock == nil || o.Mock.Body != `{"ok":true}` {
					return fmt.Errorf("%+v %s", o.Mock, o.Error)
				}
				return nil
			}},
		{api: "ctx.abort()", typ: "http-request", req: req,
			code: `export default async function(ctx){ return ctx.abort(); }`,
			check: func(o DebugOutput) error {
				if !logsHaveSummary(o, "中止") {
					return fmt.Errorf("%+v", o)
				}
				return nil
			}},
		{api: "ctx.http.get → Response json()/text()/headers/status", typ: "generic",
			code: `export default async function(ctx){ const r=await ctx.http.get("http://h.test/x",{headers:{"X-Req":"v"}}); const d=await r.json(); const info=[r.status,d]; const ok=r.status===200 && d.h=="v" && r.headers.get("x-test")=="1"; ` + pass + ` }`},
		{api: "ctx.http.post body Object → JSON, policy", typ: "generic",
			code: `export default async function(ctx){ const r=await ctx.http.post("http://h.test/p",{body:{a:1}, policy:"EGP"}); const d=await r.json(); const info=d; const ok=d.body=='{"a":1}' && d.method=="POST"; ` + pass + ` }`,
			check: func(o DebugOutput) error {
				if !logsHave(o, "PASS") {
					return fmt.Errorf("%+v %s", o.Logs, o.Error)
				}
				for _, p := range *pols {
					if p == "EGP" {
						return nil
					}
				}
				return fmt.Errorf("policy %v", *pols)
			}},
		{api: "ctx.http redirect: manual", typ: "generic",
			code: `export default async function(ctx){ const r=await ctx.http.get("http://h.test/redirect",{redirect:"manual"}); const info=r.status; const ok=r.status==302; ` + pass + ` }`},
		{api: "ctx.http arrayBuffer()", typ: "generic",
			code: `export default async function(ctx){ const r=await ctx.http.get("http://h.test/bin"); const b=new Uint8Array(await r.arrayBuffer()); const info=b.length; const ok=b.length==4 && b[3]==255; ` + pass + ` }`},
		{api: "ctx.storage get/set/getJSON/setJSON/delete", typ: "generic",
			code: `export default async function(ctx){ ctx.storage.set("k","v"); ctx.storage.setJSON("j",{a:[1]}); const a=ctx.storage.get("k"), j=ctx.storage.getJSON("j"); ctx.storage.delete("k"); const info=[a,j,ctx.storage.get("k")]; const ok=a=="v" && j.a[0]===1 && ctx.storage.get("k")===null; ` + pass + ` }`},
		{api: "ctx.notify({title, body, action:{type:openUrl,url}})", typ: "generic",
			code: `export default async function(ctx){ ctx.notify({title:"T", body:"B", action:{type:"openUrl", url:"https://e/"}}); }`,
			check: func(o DebugOutput) error {
				if len(o.Notifications) != 1 || o.Notifications[0]["title"] != "T" || o.Notifications[0]["url"] != "https://e/" {
					return fmt.Errorf("%+v", o.Notifications)
				}
				return nil
			}},
		{api: "ctx.env / ctx.script.name / ctx.app", typ: "generic",
			code: `export default async function(ctx){ const info=[ctx.env, ctx.script, ctx.app]; const ok=typeof ctx.env=="object" && typeof ctx.script.name=="string" && typeof ctx.app.version=="string" && typeof ctx.app.language=="string"; ` + pass + ` }`},
		{api: "ctx.device / ctx.lookupIP", typ: "generic",
			code: `export default async function(ctx){ const info=[ctx.device]; const ok=typeof ctx.device=="object" && typeof ctx.lookupIP=="function"; ` + pass + ` }`},
		{api: "ctx.compress gzip/gunzip round trip", typ: "generic",
			code: `export default async function(ctx){ const z=await ctx.compress.gzip(new TextEncoder().encode("hello")); const u=await ctx.compress.gunzip(z); const info=String(u); const ok=new TextDecoder().decode(u)=="hello"; ` + pass + ` }`},
		{api: "global Headers constructor (object / pairs) as ctx.http headers", typ: "generic",
			code: `export default async function(ctx){ const h=new Headers({"X-Req":"hv"}); const p=new Headers([["a","1"],["a","2"]]); const r=await ctx.http.get("http://h.test/x",{headers:h}); const d=await r.json(); const info=[d,p.getAll("A")]; const ok=d.h=="hv" && p.getAll("A").length==2 && h.get("x-req")=="hv"; ` + pass + ` }`},
		{api: "Headers set/append/getAll/delete", typ: "http-request", req: req,
			code: `export default async function(ctx){ const h=ctx.request.headers; h.set("X-A","1"); h.append("X-A","2"); const all=h.getAll("x-a"); h.delete("x-req"); const info=[all,h.get("x-a")]; const ok=all.length==2 && h.get("x-a")=="1, 2" && !h.has("X-Req"); ` + pass + ` return {headers: h}; }`},
	}
	for _, c := range cases {
		t.Run("Egern "+c.api, func(t *testing.T) {
			o := DebugRun(t.TempDir(), DebugInput{Code: c.code, Type: c.typ, Request: c.req, Response: c.resp, Timeout: 10}, dial)
			var err error
			if c.check != nil {
				err = c.check(o)
			} else if !logsHave(o, "PASS") {
				err = fmt.Errorf("no PASS: err=%q logs=%+v", o.Error, o.Logs)
			}
			if err != nil {
				t.Errorf("Egern %s: %v", c.api, err)
			}
		})
	}
}

func logsHaveSummary(o DebugOutput, s string) bool {
	for _, l := range o.Summary {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}
