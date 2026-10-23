package mitm

// Rule-type / placeholder matrix across the four module formats (v0.19.22 audit). Each module is
// installed the way the module store does it and driven through the real engine.

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

type ruleExp struct {
	name, method, url, body string
	hdr                     []string
	status                  int
	bodyHas, bodyNot        string
	respHdr                 [2]string
}

const surgeCompatModule = `#!name=Surge compat
#!arguments=host:api.test.com,word:hello
#!arguments-desc=host
[URL Rewrite]
^https://api\.test\.com/s/reject - reject
^https://api\.test\.com/s/r200 - reject-200
^https://api\.test\.com/s/img - reject-img
^https://api\.test\.com/s/dict - reject-dict
^https://api\.test\.com/s/array - reject-array
^https://api\.test\.com/s/302/(.*) https://api.test.com/x/$1 302
^https://api\.test\.com/s/307 https://api.test.com/y 307
^https://api\.test\.com/s/hdr https://api.test.com/echo header
[Header Rewrite]
http-request ^https://api\.test\.com/echo\?s1 header-add X-Added {{{word}}}
http-request ^https://api\.test\.com/echo\?s2 header-del X-Gone
http-request ^https://api\.test\.com/echo\?s3 header-replace User-Agent Repl
http-request ^https://api\.test\.com/echo\?s4 header-replace-regex User-Agent ^Old New
http-response ^https://api\.test\.com/json\?s5 header-add X-Resp yes
[Body Rewrite]
http-response ^https://api\.test\.com/json\?s6 "ad":true "ad":false
http-response-jq ^https://api\.test\.com/json\?s7 'del(.data.ads)'
http-request ^https://api\.test\.com/echo\?s8 aaa bbb
[Map Local]
^https://api\.test\.com/s/ml1 data-type=text data="hi there" status-code=201 header="X-ML:1|Content-Type:text/plain"
^https://api\.test\.com/s/ml2 data-type=base64 data="e30="
^https://api\.test\.com/s/ml3 data-type=tiny-gif
[MITM]
hostname = %APPEND% {{{host}}}
`

const loonCompatModule = `#!name=Loon compat
[Argument]
word = input,"world",tag=Word
on = switch,true,tag=On
[Rewrite]
^https://api\.test\.com/l/reject reject
^https://api\.test\.com/l/dict reject-dict
^https://api\.test\.com/l/302 302 https://api.test.com/x
^https://api\.test\.com/l/307 307 https://api.test.com/y
^https://api\.test\.com/json\?l1 response-body-json-del data.ads
^https://api\.test\.com/json\?l2 response-body-json-replace data.keep 9
^https://api\.test\.com/json\?l3 response-body-json-add data.new "{word}"
^https://api\.test\.com/l/mock mock-response-body data-type=json data="{\"m\":1}" status-code=202
^https://api\.test\.com/echo\?l4 request-header-add X-Loon {word}
^https://api\.test\.com/echo\?l5 request-header-del X-Gone
^https://api\.test\.com/json\?l6 response-header-add X-LR 1
[Script]
http-response ^https://api\.test\.com/json\?l7 script-path=arg.js, requires-body=true, argument=[{word},{on}], tag=argobj, enable={on}
[MITM]
hostname = api.test.com
`

const qxCompatModule = `hostname = api.test.com
^https://api\.test\.com/q/reject url reject
^https://api\.test\.com/q/r200 url reject-200
^https://api\.test\.com/q/img url reject-img
^https://api\.test\.com/q/dict url reject-dict
^https://api\.test\.com/q/array url reject-array
^https://api\.test\.com/q/302 url 302 https://api.test.com/x
^https://api\.test\.com/q/307 url 307 https://api.test.com/y
^https://api\.test\.com/echo\?q1 url request-header (\r\nUser-Agent:)[^\r\n]* request-header $1 QXUA
^https://api\.test\.com/json\?q2 url response-body "ad":true response-body "ad":false
^https://api\.test\.com/echo\?q3 url request-body aaa request-body ccc
^https://api\.test\.com/json\?q4 url jsonjq-response-body 'del(.data.ads)'
^https://api\.test\.com/q/echo url echo-response text/json echo-response echo.json
^https://api\.test\.com/json\?q5 url script-response-body qx.js
^https?:\/\/api\.test\.com\/echo\?q9 url request-header (\r\n)User-Agent:.+(\r\n) request-header $1User-Agent: Mozilla/5.0 (iPhone; QX)$2
^https://api\.test\.com/json\?q10 url response-body "ad":true response-body "ad": "no ad"
^https://api\.test\.com/q/answer url script-echo-response answer.js
`

const egernCompatModule = `name: Egern compat
compat_arguments:
  WORD: egern
env_schema:
  MODE:
    name: Mode
    options:
      - a
      - b
url_rewrites:
  - match: ^https://api\.test\.com/e/dict
    location: http://reject-dict/
  - match: ^https://api\.test\.com/e/302
    location: https://api.test.com/x
    status_code: 302
  - match: ^https://api\.test\.com/e/hdr
    location: https://api.test.com/echo
header_rewrites:
  - add:
      match: ^https://api\.test\.com/echo\?e1
      name: X-Eg
      value: "{{{WORD}}}"
  - delete:
      match: ^https://api\.test\.com/echo\?e2
      name: X-Gone
  - replace:
      match: ^https://api\.test\.com/json\?e3
      type: response
      name: X-ER
      value: r
body_rewrites:
  - response_regex:
      match: ^https://api\.test\.com/json\?e4
      find: '"ad":true'
      replace: '"ad":false'
  - response_jq:
      match: ^https://api\.test\.com/json\?e5
      filter: 'del(.data.ads)'
map_locals:
  - match: ^https://api\.test\.com/e/ml
    status_code: 203
    headers:
      X-EM: "1"
    body: egern-local
scriptings:
  - http_response:
      name: envarg
      match: ^https://api\.test\.com/json\?e6
      script_url: env.js
      body_required: true
      env:
        _compat.$argument: "k=v"
        FOO: bar
  - http_response:
      name: envmode
      match: ^https://api\.test\.com/json\?e7
      script_url: mode.js
      body_required: true
mitm:
  hostnames:
    includes:
      - api.test.com
`

func TestCompatRuleMatrix(t *testing.T) {
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
	dumpScriptLogs(h)
	for _, m := range mods {
		if err := writeFileForTest(ModulePath(h.home, m.id), m.text); err != nil {
			t.Fatal(err)
		}
	}
	rs := Build(h.home, cfg)
	for _, e := range rs.Errors {
		t.Errorf("parse error: %s", e)
	}
	for _, u := range rs.Unsupported {
		t.Errorf("unsupported: %s", u)
	}
	h.e.Reload(cfg, rs)
	exps := map[string][]ruleExp{
		"Surge": {
			{name: "reject", url: "https://api.test.com/s/reject", status: -1},
			{name: "reject-200", url: "https://api.test.com/s/r200", status: 200, bodyNot: "{"},
			{name: "reject-img", url: "https://api.test.com/s/img", status: 200, bodyHas: "GIF"},
			{name: "reject-dict", url: "https://api.test.com/s/dict", status: 200, bodyHas: "{}"},
			{name: "reject-array", url: "https://api.test.com/s/array", status: 200, bodyHas: "[]"},
			{name: "302 with $1", url: "https://api.test.com/s/302/abc", status: 302, respHdr: [2]string{"Location", "https://api.test.com/x/abc"}},
			{name: "307", url: "https://api.test.com/s/307", status: 307, respHdr: [2]string{"Location", "https://api.test.com/y"}},
			{name: "header (transparent)", url: "https://api.test.com/s/hdr", status: 200, bodyHas: `"path":"/echo"`},
			{name: "header-add + {{{arg}}}", url: "https://api.test.com/echo?s1", bodyHas: `"X-Added":"hello"`},
			{name: "header-del", url: "https://api.test.com/echo?s2", hdr: []string{"X-Gone", "1"}, bodyNot: "X-Gone"},
			{name: "header-replace", url: "https://api.test.com/echo?s3", hdr: []string{"User-Agent", "Old/1"}, bodyHas: `"User-Agent":"Repl"`},
			{name: "header-replace-regex", url: "https://api.test.com/echo?s4", hdr: []string{"User-Agent", "Old/1"}, bodyHas: `"User-Agent":"New/1"`},
			{name: "response header-add", url: "https://api.test.com/json?s5", respHdr: [2]string{"X-Resp", "yes"}},
			{name: "body rewrite", url: "https://api.test.com/json?s6", bodyHas: `"ad":false`},
			{name: "http-response-jq", url: "https://api.test.com/json?s7", bodyNot: "ads"},
			{name: "request body rewrite", method: "POST", url: "https://api.test.com/echo?s8", body: "xaaax", bodyHas: `"body":"xbbbx"`},
			{name: "map local text+status+header", url: "https://api.test.com/s/ml1", status: 201, bodyHas: "hi there", respHdr: [2]string{"X-ML", "1"}},
			{name: "map local base64", url: "https://api.test.com/s/ml2", status: 200, bodyHas: "{}"},
			{name: "map local tiny-gif", url: "https://api.test.com/s/ml3", status: 200, bodyHas: "GIF"},
		},
		"Loon": {
			{name: "reject", url: "https://api.test.com/l/reject", status: -1},
			{name: "reject-dict", url: "https://api.test.com/l/dict", status: 200, bodyHas: "{}"},
			{name: "302", url: "https://api.test.com/l/302", status: 302, respHdr: [2]string{"Location", "https://api.test.com/x"}},
			{name: "307", url: "https://api.test.com/l/307", status: 307},
			{name: "response-body-json-del", url: "https://api.test.com/json?l1", bodyNot: "ads"},
			{name: "response-body-json-replace", url: "https://api.test.com/json?l2", bodyHas: `"keep":9`},
			{name: "response-body-json-add + {arg}", url: "https://api.test.com/json?l3", bodyHas: `"new":"hello"`},
			{name: "mock-response-body", url: "https://api.test.com/l/mock", status: 202, bodyHas: `{"m":1}`},
			{name: "request-header-add + {arg}", url: "https://api.test.com/echo?l4", bodyHas: `"X-Loon":"hello"`},
			{name: "request-header-del", url: "https://api.test.com/echo?l5", hdr: []string{"X-Gone", "1"}, bodyNot: "X-Gone"},
			{name: "response-header-add", url: "https://api.test.com/json?l6", respHdr: [2]string{"X-LR", "1"}},
			{name: "argument=[{a},{b}] object + enable={x}", url: "https://api.test.com/json?l7", bodyHas: `"arg":{"word":"hello","on":true}`},
		},
		"QX": {
			{name: "reject", url: "https://api.test.com/q/reject", status: -1},
			{name: "reject-200", url: "https://api.test.com/q/r200", status: 200},
			{name: "reject-img", url: "https://api.test.com/q/img", status: 200, bodyHas: "GIF"},
			{name: "reject-dict", url: "https://api.test.com/q/dict", status: 200, bodyHas: "{}"},
			{name: "reject-array", url: "https://api.test.com/q/array", status: 200, bodyHas: "[]"},
			{name: "302", url: "https://api.test.com/q/302", status: 302},
			{name: "307", url: "https://api.test.com/q/307", status: 307},
			{name: "request-header regex", url: "https://api.test.com/echo?q1", hdr: []string{"User-Agent", "Old/1"}, bodyHas: `"User-Agent":"QXUA"`},
			{name: "response-body regex", url: "https://api.test.com/json?q2", bodyHas: `"ad":false`},
			{name: "request-body regex", method: "POST", url: "https://api.test.com/echo?q3", body: "xaaax", bodyHas: `"body":"xcccx"`},
			{name: "jsonjq-response-body", url: "https://api.test.com/json?q4", bodyNot: "ads"},
			{name: "echo-response file", url: "https://api.test.com/q/echo", status: 200, bodyHas: `{"echo":1}`},
			{name: "request-header regex, replacement with spaces (QX docs form)", url: "https://api.test.com/echo?q9", hdr: []string{"User-Agent", "Old/1"}, bodyHas: `"User-Agent":"Mozilla/5.0 (iPhone; QX)"`},
			{name: "response-body replacement with spaces", url: "https://api.test.com/json?q10", bodyHas: `"ad": "no ad"`},
			{name: "script-response-body", url: "https://api.test.com/json?q5", bodyHas: `"qx":1`},
			{name: "script-echo-response", url: "https://api.test.com/q/answer", status: 200, bodyHas: `"answered"`},
		},
		"Egern": {
			{name: "url_rewrites reject-dict", url: "https://api.test.com/e/dict", status: 200, bodyHas: "{}"},
			{name: "url_rewrites 302", url: "https://api.test.com/e/302", status: 302},
			{name: "url_rewrites header mode", url: "https://api.test.com/e/hdr", status: 200, bodyHas: `"path":"/echo"`},
			{name: "header_rewrites add + {{{arg}}}", url: "https://api.test.com/echo?e1", bodyHas: `"X-Eg":"egern"`},
			{name: "header_rewrites delete", url: "https://api.test.com/echo?e2", hdr: []string{"X-Gone", "1"}, bodyNot: "X-Gone"},
			{name: "header_rewrites response replace", url: "https://api.test.com/json?e3", respHdr: [2]string{"X-ER", "r"}},
			{name: "body_rewrites response_regex", url: "https://api.test.com/json?e4", bodyHas: `"ad":false`},
			{name: "body_rewrites response_jq", url: "https://api.test.com/json?e5", bodyNot: "ads"},
			{name: "map_locals status/headers/body", url: "https://api.test.com/e/ml", status: 203, bodyHas: "egern-local", respHdr: [2]string{"X-EM", "1"}},
			{name: "env _compat.$argument → $argument", url: "https://api.test.com/json?e6", bodyHas: `"arg":"k=v"`},
			{name: "env_schema value from module settings → ctx.env", url: "https://api.test.com/json?e7", bodyHas: `"mode":"b"`},
		},
	}
	var gaps []string
	for _, m := range mods {
		for _, x := range exps[m.plat] {
			method := x.method
			if method == "" {
				method = "GET"
			}
			req, _ := http.NewRequest(method, x.url, strings.NewReader(x.body))
			for i := 0; i+1 < len(x.hdr); i += 2 {
				req.Header.Set(x.hdr[i], x.hdr[i+1])
			}
			resp, err := h.client.Do(req)
			var body string
			var why string
			if err != nil {
				if x.status != -1 {
					why = "request failed: " + err.Error()
				}
			} else {
				b := make([]byte, 0)
				buf := make([]byte, 4096)
				for {
					n, e := resp.Body.Read(buf)
					b = append(b, buf[:n]...)
					if e != nil {
						break
					}
				}
				resp.Body.Close()
				body = string(b)
				switch {
				case x.status == -1 && resp.StatusCode < 400:
					why = fmt.Sprintf("reject answered %d %q", resp.StatusCode, clip(body, 80))
				case x.status > 0 && resp.StatusCode != x.status:
					why = fmt.Sprintf("status %d, want %d (%q)", resp.StatusCode, x.status, clip(body, 120))
				case x.bodyHas != "" && !strings.Contains(body, x.bodyHas):
					why = fmt.Sprintf("body lacks %q: %q", x.bodyHas, clip(body, 300))
				case x.bodyNot != "" && strings.Contains(body, x.bodyNot):
					why = fmt.Sprintf("body has %q: %q", x.bodyNot, clip(body, 300))
				case x.respHdr[0] != "" && resp.Header.Get(x.respHdr[0]) != x.respHdr[1]:
					why = fmt.Sprintf("header %s=%q", x.respHdr[0], resp.Header.Get(x.respHdr[0]))
				}
			}
			if why != "" {
				gaps = append(gaps, m.plat+" "+x.name)
				t.Errorf("%s %s: %s", m.plat, x.name, why)
			}
		}
	}
	t.Logf("gaps: %v", gaps)
}

// TestEgernModuleKeys: env_schema becomes module settings (not "unsupported"), an empty dns block is not
// reported, an undocumented key is reported instead of dropped silently.
func TestEgernModuleKeys(t *testing.T) {
	rs := &Ruleset{}
	rs.ParseText(`name: k
dns: {}
env_schema:
  FLAG:
    name: Flag
    options: ["true", "false"]
  CITY:
    description: City
    default_value: Shanghai
  THEME:
    options: [light, dark]
rewrites:
  - match: ^https://x
scriptings:
  - generic:
      name: g
      script_url: g.js
      env:
        CITY: Beijing
`, "k", map[string]string{"FLAG": "true"})
	if len(rs.Unsupported) != 1 || !strings.Contains(rs.Unsupported[0], "rewrites") {
		t.Fatalf("unsupported %v", rs.Unsupported)
	}
	want := map[string]string{"FLAG": "switch", "CITY": "input", "THEME": "select"}
	if len(rs.Arguments) != 3 {
		t.Fatalf("args %+v", rs.Arguments)
	}
	for _, a := range rs.Arguments {
		if !a.Env || want[a.Key] != a.Type || a.Default != "" {
			t.Errorf("arg %+v", a)
		}
		if a.Key == "CITY" && !strings.Contains(a.Desc, "默认 Shanghai") {
			t.Errorf("desc %q", a.Desc)
		}
	}
	if len(rs.Tasks) != 1 || rs.Tasks[0].Script.Env["FLAG"] != "true" || rs.Tasks[0].Script.Env["CITY"] != "Beijing" {
		t.Fatalf("env %+v", rs.Tasks[0].Script.Env)
	}
}
