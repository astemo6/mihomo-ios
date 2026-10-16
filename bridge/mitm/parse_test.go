package mitm

import (
	"strings"
	"testing"
)

func one(t *testing.T, line, section string) *Rule {
	t.Helper()
	rs := &Ruleset{}
	rs.ParseLine(line, section, "用户")
	if len(rs.Errors) > 0 {
		t.Fatalf("%q: errors %v", line, rs.Errors)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("%q: want 1 rule, got %d (unsupported=%v)", line, len(rs.Rules), rs.Unsupported)
	}
	return rs.Rules[0]
}

func TestSurgeLines(t *testing.T) {
	cases := []struct {
		line, kind, phase, action string
	}{
		{`^https?:\/\/ads\.example\.com\/v1 - reject`, KindURL, "request", "reject"},
		{`^https?://ad\.x\.com/img _ reject-img`, KindURL, "request", "reject-img"},
		{`^https?://a\.com/api/config - reject-dict`, KindURL, "request", "reject-dict"},
		{`^https?://a\.com/list - reject-array`, KindURL, "request", "reject-array"},
		{`^https?://a\.com/empty - reject-200`, KindURL, "request", "reject-200"},
		{`^http://old\.com/(.*) https://new.com/$1 302`, KindURL, "request", "302"},
		{`^http://old\.com/(.*) https://new.com/$1 307`, KindURL, "request", "307"},
		{`^https://a\.com/x https://b.com/x header`, KindURL, "request", "header"},
		{`^https?://a\.com header-add X-Test 1`, KindHeader, "request", ""},
		{`^https?://a\.com header-del Cookie`, KindHeader, "request", ""},
		{`^https?://a\.com header-replace User-Agent Mozilla/5.0 Test`, KindHeader, "request", ""},
		{`http-response ^https?://a\.com header-add X-Resp yes`, KindHeader, "response", ""},
		{`http-response ^https?://api\.a\.com/feed "ad":true "ad":false`, KindBody, "response", ""},
		{`http-request ^https?://api\.a\.com/post foo bar`, KindBody, "request", ""},
		{`http-response-jq ^https?://api\.a\.com/v2 'del(.data.ads)'`, KindJQ, "response", ""},
		{`^https?://a\.com/m data="{\"ok\":1}" data-type=text header="Content-Type:application/json" status-code=200`, KindMapLocal, "request", ""},
		{`^https?://a\.com/gif data-type=tiny-gif`, KindMapLocal, "request", ""},
	}
	for _, c := range cases {
		r := one(t, c.line, "")
		if r.Kind != c.kind || r.Phase != c.phase || (c.action != "" && r.Action != c.action) {
			t.Errorf("%q => kind=%s phase=%s action=%s", c.line, r.Kind, r.Phase, r.Action)
		}
	}
	r := one(t, `^https?://a\.com/m data="{\"ok\":1}" data-type=text header="Content-Type:application/json|X-A:b" status-code=201`, "")
	if r.Data != `{"ok":1}` || r.Status != 201 || r.RespHeaders["Content-Type"] != "application/json" || r.RespHeaders["X-A"] != "b" {
		t.Errorf("map local parsed wrong: %+v", r)
	}
	b := one(t, `http-response ^https?://api\.a\.com/feed "ad":true "ad":false "x" "y"`, "")
	if len(b.Body) != 2 || b.Body[0].Regex != `"ad":true` || b.Body[1].Repl != "y" {
		t.Errorf("body ops: %+v", b.Body)
	}
}

func TestSurgeScriptLine(t *testing.T) {
	line := `BiliBili广告 = type=http-response,pattern=^https?:\/\/app\.bilibili\.com\/x\/(v2|resource)\/(splash|feed){1,3},requires-body=1,max-size=0,script-path=https://example.com/bili.js,argument="a=1&b=2",timeout=20`
	r := one(t, line, "script")
	if r.Kind != KindScript || r.Phase != "response" || !r.Script.RequiresBody || r.Script.Timeout != 20 {
		t.Fatalf("bad script rule: %+v %+v", r, r.Script)
	}
	if r.Pattern != `^https?:\/\/app\.bilibili\.com\/x\/(v2|resource)\/(splash|feed){1,3}` {
		t.Errorf("pattern with commas split wrongly: %s", r.Pattern)
	}
	if r.Script.Argument != "a=1&b=2" || !r.Script.HasArgument || r.Script.Name != "BiliBili广告" {
		t.Errorf("argument/name: %+v", r.Script)
	}
	if !r.match("https://app.bilibili.com/x/v2/feed") {
		t.Error("regex should match")
	}
	// request script, binary body
	r = one(t, `yt = type=http-request,pattern=^https:\/\/youtubei\.googleapis\.com\/youtubei\/v1\/browse,requires-body=1,binary-body-mode=1,script-path=yt.js`, "")
	if r.Phase != "request" || !r.Script.BinaryBody {
		t.Errorf("binary request script: %+v", r.Script)
	}
}

func TestQXLines(t *testing.T) {
	cases := []struct {
		line, kind, phase string
	}{
		{`^https?:\/\/api\.x\.com\/ad url reject`, KindURL, "request"},
		{`^https?:\/\/api\.x\.com\/ad url reject-200`, KindURL, "request"},
		{`^https?:\/\/api\.x\.com\/ad url reject-img`, KindURL, "request"},
		{`^https?:\/\/api\.x\.com\/ad url reject-dict`, KindURL, "request"},
		{`^https?:\/\/api\.x\.com\/ad url reject-array`, KindURL, "request"},
		{`^http:\/\/a\.com url 302 https://b.com`, KindURL, "request"},
		{`^https:\/\/a\.com\/b url script-response-body https://raw.example.com/s.js`, KindScript, "response"},
		{`^https:\/\/a\.com\/b url script-request-header https://raw.example.com/s.js`, KindScript, "request"},
		{`^https:\/\/a\.com\/b url script-echo-response https://raw.example.com/s.js`, KindScript, "request"},
		{`^https:\/\/a\.com\/b url response-body "ad":\d+ response-body "ad":0`, KindBody, "response"},
		{`^https:\/\/a\.com url request-header (\r\n)User-Agent:.+(\r\n) request-header $1User-Agent: QX$2`, KindHeader, "request"},
		{`^https:\/\/a\.com\/x url echo-response text/json echo-response https://raw.example.com/x.json`, KindMapLocal, "request"},
	}
	for _, c := range cases {
		r := one(t, c.line, "")
		if r.Kind != c.kind || r.Phase != c.phase {
			t.Errorf("%q => %s/%s", c.line, r.Kind, r.Phase)
		}
	}
	r := one(t, `^https:\/\/a\.com\/b url script-response-body https://raw.example.com/s.js`, "")
	if !r.Script.RequiresBody || r.Script.Path != "https://raw.example.com/s.js" {
		t.Errorf("qx script: %+v", r.Script)
	}
}

func TestLoonLines(t *testing.T) {
	r := one(t, `http-response ^https?:\/\/api\.x\.com\/v1 script-path=https://e.com/a.js, requires-body=true, timeout=10, tag=去广告`, "script")
	if r.Kind != KindScript || r.Script.Name != "去广告" || !r.Script.RequiresBody {
		t.Errorf("loon script: %+v", r.Script)
	}
	r = one(t, `^https?:\/\/api\.x\.com\/v1 302 https://y.com`, "rewrite")
	if r.Action != "302" || r.Target != "https://y.com" {
		t.Errorf("loon 302: %+v", r)
	}
	r = one(t, `^https?:\/\/api\.x\.com\/feed response-body-json-del data.ads data.banner`, "rewrite")
	if r.Kind != KindJSON || len(r.JSON) != 2 {
		t.Errorf("loon json del: %+v", r)
	}
}

func TestHostnamesAndCoreRules(t *testing.T) {
	rs := &Ruleset{}
	rs.ParseText(`#!name=测试模块
#!desc=demo
[Rule]
DOMAIN-SUFFIX,ads.example.com,REJECT
URL-REGEX,^https?://a\.com/ads,REJECT-TINYGIF
DOMAIN,keep.com,PROXY

[MITM]
hostname = %APPEND% api.a.com, *.b.com, -c.b.com, d.com:8443
`, "m", nil)
	if rs.Name != "测试模块" || rs.Format != "" && rs.Format != "surge" {
		t.Errorf("meta: %q %q", rs.Name, rs.Format)
	}
	if strings.Join(rs.Hostnames, ",") != "api.a.com,*.b.com,-c.b.com,d.com:8443" {
		t.Errorf("hostnames: %v", rs.Hostnames)
	}
	if len(rs.CoreRules) != 1 || rs.CoreRules[0] != "DOMAIN-SUFFIX,ads.example.com,REJECT" {
		t.Errorf("core rules: %v", rs.CoreRules)
	}
	if len(rs.Rules) != 1 || rs.Rules[0].Action != "reject-img" {
		t.Errorf("url-regex reject: %+v", rs.Rules)
	}
	if len(rs.Unsupported) != 1 {
		t.Errorf("named policy rule should be unsupported: %v", rs.Unsupported)
	}
	m := NewHostMatcher(rs.Hostnames)
	for _, c := range []struct {
		h    string
		p    int
		want bool
	}{{"api.a.com", 443, true}, {"x.b.com", 443, true}, {"x.y.b.com", 443, true}, {"b.com", 443, false},
		{"c.b.com", 443, false}, {"d.com", 8443, true}, {"d.com", 443, false}, {"api.a.com", 80, false}} {
		if got := m.Match(c.h, c.p); got != c.want {
			t.Errorf("match %s:%d = %v", c.h, c.p, got)
		}
	}
}

func TestQXSnippetAndArgs(t *testing.T) {
	rs := &Ruleset{}
	rs.ParseText(`hostname = api.a.com, api.b.com
^https:\/\/api\.a\.com\/ad url reject-200
^https:\/\/api\.b\.com\/feed url script-response-body https://e.com/f.js
`, "qx", nil)
	if len(rs.Rules) != 2 || len(rs.Hostnames) != 2 || rs.Format != "list" {
		t.Fatalf("qx snippet: rules=%d hosts=%v fmt=%s err=%v", len(rs.Rules), rs.Hostnames, rs.Format, rs.Errors)
	}
	rs = &Ruleset{}
	rs.ParseText(`#!name=args
#!arguments=开关:true,目标:"https://x.com"
[URL Rewrite]
^https?://a\.com/(.*) {{{目标}}}/$1 302
[Script]
s = type=http-response,pattern=^https://a\.com,script-path=s.js,argument=on={{{开关}}}
`, "args", map[string]string{"开关": "false"})
	if len(rs.Arguments) != 2 || rs.Arguments[1].Default != "https://x.com" {
		t.Fatalf("args: %+v", rs.Arguments)
	}
	if rs.Rules[0].Target != "https://x.com/$1" || rs.Rules[1].Script.Argument != "on=false" {
		t.Errorf("arg substitution: %q %q", rs.Rules[0].Target, rs.Rules[1].Script.Argument)
	}
}

func TestStashOverride(t *testing.T) {
	rs := &Ruleset{}
	rs.ParseText(`name: 去广告
desc: demo
http:
  mitm:
    - "api.s.com"
  rewrite:
    - ^https?://api\.s\.com/ad - reject-dict
  script:
    - match: ^https?://api\.s\.com/feed
      name: feed
      type: response
      require-body: true
      timeout: 10
script-providers:
  feed:
    url: https://e.com/feed.js
    interval: 86400
`, "stash", nil)
	if rs.Format != "stash" || rs.Name != "去广告" || len(rs.Hostnames) != 1 || len(rs.Rules) != 2 {
		t.Fatalf("stash: %+v errors=%v", rs, rs.Errors)
	}
	if rs.Rules[1].Script.Path != "https://e.com/feed.js" || !rs.Rules[1].Script.RequiresBody {
		t.Errorf("stash script: %+v", rs.Rules[1].Script)
	}
}

func TestBadRegexReported(t *testing.T) {
	rs := &Ruleset{}
	rs.ParseLine(`^https://(a\.com - reject`, "", "u")
	if len(rs.Errors) != 1 {
		t.Errorf("want error for bad regex, got %v / %d rules", rs.Errors, len(rs.Rules))
	}
	// JS-style lookahead must compile (regexp2, not RE2)
	r := one(t, `^https?://(?!static\.)[\w.]+\.a\.com/ad - reject`, "")
	if !r.match("https://img.a.com/ad") || r.match("https://static.a.com/ad") {
		t.Error("lookahead semantics")
	}
}
