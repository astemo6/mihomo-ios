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
	if len(rs.CoreRules) != 2 || rs.CoreRules[0] != "DOMAIN-SUFFIX,ads.example.com,REJECT" || rs.CoreRules[1] != "DOMAIN,keep.com,PROXY" {
		t.Errorf("core rules: %v", rs.CoreRules)
	}
	if len(rs.Rules) != 1 || rs.Rules[0].Action != "reject-img" {
		t.Errorf("url-regex reject: %+v", rs.Rules)
	}
	// Named policies resolve against the profile at inject time; unknown ones are reported and dropped.
	raw := map[string]any{"proxy-groups": []any{map[string]any{"name": "Proxy", "type": "select"}}}
	unres := map[string]bool{}
	got := ResolveCoreRules(raw, append(rs.CoreRules, "DOMAIN,x.com,Netflix"), unres)
	if strings.Join(got, "|") != "DOMAIN-SUFFIX,ads.example.com,REJECT|DOMAIN,keep.com,Proxy" || !unres["Netflix"] {
		t.Errorf("resolve: %v %v", got, unres)
	}
	if mapPolicy("DOMAIN,x.com,Netflix", map[string]string{"Netflix": "Proxy"}) != "DOMAIN,x.com,Proxy" {
		t.Error("mapPolicy")
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

func TestLoonArgumentSection(t *testing.T) {
	text := `#!name=Loon Arg
[Argument]
blockAd = switch,true,tag=去广告,desc=开关
blockTrack = switch,false,tag=去追踪
tgt = select,"reject-dict","reject",tag=方式

[Rewrite]
^https?:\/\/ad\.example\.com\/\d{2} {tgt}
^https?:\/\/track\.example\.com\/ reject, enable={blockTrack}

[MITM]
hostname = ad.example.com
`
	rs := &Ruleset{}
	rs.ParseText(text, "t", nil)
	if rs.Format != "loon" || len(rs.Arguments) != 3 {
		t.Fatalf("format %s args %+v", rs.Format, rs.Arguments)
	}
	if rs.Arguments[2].Type != "select" || len(rs.Arguments[2].Options) != 2 || rs.Arguments[2].Default != "reject-dict" {
		t.Fatalf("%+v", rs.Arguments[2])
	}
	if len(rs.Rules) != 1 || !strings.Contains(rs.Rules[0].Pattern, `\d{2}`) {
		t.Fatalf("rules %+v errors %v", rs.Rules, rs.Errors)
	}
	rs2 := &Ruleset{}
	rs2.ParseText(text, "t", map[string]string{"blockTrack": "true", "tgt": "reject"})
	if len(rs2.Rules) != 2 {
		t.Fatalf("with args: %+v %v", rs2.Rules, rs2.Errors)
	}
}

func TestConvertRuleSyntaxes(t *testing.T) {
	cases := map[string]string{
		"DOMAIN-SUFFIX,google.com,Proxy":                    "DOMAIN-SUFFIX,google.com,P",
		"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve":              "IP-CIDR,10.0.0.0/8,P,no-resolve",
		"IP-CIDR6,2001:db8::/32,DIRECT":                     "IP-CIDR6,2001:db8::/32,P",
		"GEOIP,CN,DIRECT":                                   "GEOIP,CN,P",
		"IP-ASN,AS13335,Proxy,no-resolve":                   "IP-ASN,13335,P,no-resolve",
		"DEST-PORT,443,Proxy":                               "DST-PORT,443,P",
		"SRC-IP,192.168.1.2,DIRECT":                         "SRC-IP-CIDR,192.168.1.2/32,P",
		"DOMAIN-WILDCARD,*.a?.com,Proxy":                    "DOMAIN-WILDCARD,*.a?.com,P",
		"PROCESS-NAME,Telegram,Proxy":                       "PROCESS-NAME,Telegram,P",
		"AND,((DOMAIN-SUFFIX,a.com),(DEST-PORT,443)),Proxy": "AND,((DOMAIN-SUFFIX,a.com),(DST-PORT,443)),P",
		"OR,((PROTOCOL,UDP),(NOT,((DOMAIN,b.com)))),REJECT": "OR,((NETWORK,UDP),(NOT,((DOMAIN,b.com)))),P",
		"FINAL,Proxy,dns-failed":                            "MATCH,P",
		"host-suffix, apple.com, direct":                    "DOMAIN-SUFFIX,apple.com,P",
		"host-keyword, ads, reject":                         "DOMAIN-KEYWORD,ads,P",
		"host-wildcard, *.test.com, proxy":                  "DOMAIN-WILDCARD,*.test.com,P",
		"ip6-cidr, 2001:db8::/32, proxy":                    "IP-CIDR6,2001:db8::/32,P",
		"ip-asn, 4134, direct":                              "IP-ASN,4134,P",
		"final, proxy":                                      "MATCH,P",
		"RULE-SET,cn_domain,DIRECT":                         "RULE-SET,cn_domain,P",
		"RULE-SET,LAN,DIRECT":                               "GEOIP,private,P,no-resolve",
	}
	for in, want := range cases {
		c, err := ConvertRuleLine(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if got := c.Format("P"); got != want {
			t.Errorf("%s -> %s (want %s)", in, got, want)
		}
	}
	for _, bad := range []string{"USER-AGENT,Instagram*,Proxy", "URL-REGEX,^http://a,Proxy", "user-agent, Foo*, proxy", "CELLULAR-RADIO,LTE,DIRECT", "WEIRD,x,DIRECT"} {
		c, err := ConvertRuleLine(bad)
		if err == nil || c.Unsupported == "" {
			t.Errorf("%s should be flagged unsupported", bad)
		}
	}
	c, _ := ConvertRuleLine("RULE-SET,https://example.com/x.list,Proxy,no-resolve")
	if c.RemoteURL != "https://example.com/x.list" || c.RemoteKind != "list" || c.Policy != "Proxy" {
		t.Errorf("remote: %+v", c)
	}
	c, _ = ConvertRuleLine("DOMAIN-SET,https://example.com/d.txt,REJECT")
	if c.RemoteKind != "domainset" {
		t.Errorf("domain-set: %+v", c)
	}
	groups := []string{"Proxy", "Netflix"}
	if p, ok := ResolvePolicy("proxy", groups, nil, "Proxy"); !ok || p != "Proxy" {
		t.Error("proxy → first select")
	}
	if p, ok := ResolvePolicy("netflix", groups, nil, "Proxy"); !ok || p != "Netflix" {
		t.Error("case-insensitive group")
	}
	if p, _ := ResolvePolicy("REJECT-TINYGIF", groups, nil, ""); p != "REJECT" {
		t.Error(p)
	}
	if _, ok := ResolvePolicy("Disney", groups, nil, "Proxy"); ok {
		t.Error("unknown should not resolve")
	}
}

func TestConvertListLines(t *testing.T) {
	cases := map[string]string{
		"DOMAIN-SUFFIX,google.com":            "DOMAIN-SUFFIX,google.com",
		"IP-CIDR,1.0.0.0/8,no-resolve":        "IP-CIDR,1.0.0.0/8,no-resolve",
		"host-suffix, ads.com, reject":        "DOMAIN-SUFFIX,ads.com",
		"HOST,a.com,Proxy":                    "DOMAIN,a.com",
		"  - DOMAIN-KEYWORD,track":            "DOMAIN-KEYWORD,track",
		"AND,((DOMAIN,a.com),(DEST-PORT,80))": "AND,((DOMAIN,a.com),(DST-PORT,80))",
	}
	for in, want := range cases {
		got, ok := ConvertListLine(in, "list")
		if !ok || got != want {
			t.Errorf("%q -> %q %v (want %q)", in, got, ok, want)
		}
	}
	if got, _ := ConvertListLine(".apple.com", "domainset"); got != "+.apple.com" {
		t.Error(got)
	}
	if _, ok := ConvertListLine("# comment", "list"); ok {
		t.Error("comment")
	}
	if _, ok := ConvertListLine("USER-AGENT,foo", "list"); ok {
		t.Error("unsupported line should be dropped")
	}
}
