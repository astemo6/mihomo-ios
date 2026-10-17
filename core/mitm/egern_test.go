package mitm

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const egernModule = `name: Egern Test
description: "Egern module for tests"
compat_arguments:
  block_policy: REJECT
  sync_disabled: true
  cronexp: "0 8 * * *"
  host: api.test.com
compat_arguments_desc: |
  block_policy 拦截策略
rules:
  - domain_suffix:
      match: "ad.example.com"
      policy: "{{{block_policy}}}"
  - ip_cidr:
      match: 10.0.0.0/8
      policy: DIRECT
      no_resolve: true
  - asn:
      match: AS13335
      policy: DIRECT
  - url_regex:
      match: "^https://api\\.test\\.com/track"
      policy: REJECT
  - and:
      match:
        - domain_keyword:
            match: tracker
        - dest_port:
            match: "443,8443"
      policy: REJECT
  - rule_set:
      match: "https://example.com/egern-set.yaml"
      policy: Proxy
  - ssid:
      match: "Home*"
      policy: DIRECT
url_rewrites:
  - match: "^https://api\\.test\\.com/ad"
    location: "http://reject-dict/"
  - match: "^https://api\\.test\\.com/old/(.*)"
    location: "https://api.test.com/new/$1"
    status_code: 301
  - match: "^https://api\\.test\\.com/urlx"
    location: "https://api.test.com/echo"
  - match: "^https://api\\.test\\.com/off"
    location: "http://reject/"
    disabled: true
header_rewrites:
  - add:
      match: "^https://api\\.test\\.com/echo"
      name: X-Added
      value: hello
  - replace:
      match: "^https://api\\.test\\.com/echo"
      name: X-Set
      value: two
  - delete:
      match: "^https://api\\.test\\.com/echo"
      name: X-Remove
body_rewrites:
  - response_regex:
      match: "^https://api\\.test\\.com/json"
      find: '"ad":true'
      replace: '"ad":false'
  - response_jq:
      match: "^https://api\\.test\\.com/json"
      filter: 'del(.data.ads)'
map_locals:
  - match: "^https://api\\.test\\.com/local"
    status_code: 201
    headers:
      Content-Type: application/json
    body: '{"local": "x y"}'
scriptings:
  - http_response:
      name: resp
      match: "^https://{{{host}}}/json\\?s=1"
      script_url: resp.js
      body_required: true
      timeout: 15
      arguments:
        _compat.$argument: "k=v"
  - schedule:
      name: daily
      cron: "{{{cronexp}}}"
      script_url: https://example.com/daily.js
      disabled: {{{sync_disabled}}}
  - schedule:
      name: hourly
      cron: "0 * * * *"
      script_url: https://example.com/hourly.js
  - generic:
      name: status
      script_url: https://example.com/status.js
  - network:
      name: net
      script_url: https://example.com/net.js
mitm:
  hostnames:
    includes:
      - "*.test.com"
    excludes:
      - skip.test.com
widgets:
  - name: status
dns:
  nameservers: []
`

func TestEgernModuleParse(t *testing.T) {
	if !IsEgern(egernModule) {
		t.Fatal("not detected as Egern")
	}
	rs := &Ruleset{}
	rs.ParseText(egernModule, "Egern Test", map[string]string{"sync_disabled": "false"})
	if rs.Format != "egern" || rs.Name != "Egern Test" || rs.Desc == "" {
		t.Fatalf("meta: format=%s name=%s desc=%s", rs.Format, rs.Name, rs.Desc)
	}
	if len(rs.Arguments) != 4 || rs.Arguments[0].Key != "block_policy" || rs.Arguments[1].Type != "switch" || rs.Arguments[0].Desc == "" {
		t.Errorf("arguments: %+v", rs.Arguments)
	}
	wantCore := []string{"DOMAIN-SUFFIX,ad.example.com,REJECT", "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve", "IP-ASN,13335,DIRECT"}
	for _, w := range wantCore {
		found := false
		for _, c := range rs.CoreRules {
			if c == w {
				found = true
			}
		}
		if !found {
			t.Errorf("core rule %q missing: %v", w, rs.CoreRules)
		}
	}
	var and, set bool
	for _, c := range rs.CoreRules {
		if strings.HasPrefix(c, "AND,((DOMAIN-KEYWORD,tracker),(DST-PORT,443/8443)),REJECT") {
			and = true
		}
		if c == "RULE-SET,https://example.com/egern-set.yaml,Proxy" {
			set = true
		}
	}
	if !and || !set {
		t.Errorf("logic / rule_set: %v", rs.CoreRules)
	}
	if len(RemoteCoreRules(rs.CoreRules)) != 1 {
		t.Errorf("remote rule set not recognised")
	}
	// url_regex REJECT => URL rewrite; 3 url_rewrites (1 disabled); 3 header; 2 body; 1 map local; 1 script
	kinds := map[string]int{}
	for _, r := range rs.Rules {
		kinds[r.Kind]++
	}
	if kinds[KindURL] != 4 || kinds[KindHeader] != 3 || kinds[KindBody] != 1 || kinds[KindJQ] != 1 || kinds[KindMapLocal] != 1 || kinds[KindScript] != 1 {
		t.Errorf("rule kinds: %v errors=%v", kinds, rs.Errors)
	}
	for _, r := range rs.Rules {
		if r.Kind == KindScript {
			if r.Script.Argument != "k=v" || !r.Script.RequiresBody || r.Script.Timeout != 15 || r.Pattern != `^https://api.test.com/json\?s=1` {
				t.Errorf("script: %+v pattern=%s", r.Script, r.Pattern)
			}
		}
	}
	// sync_disabled overridden to false by the user => both schedules, plus generic + network
	if len(rs.Tasks) != 4 {
		t.Errorf("tasks: %d %+v errors=%v", len(rs.Tasks), rs.Tasks, rs.Errors)
	}
	for _, tk := range rs.Tasks {
		if tk.Script.Name == "daily" && tk.Cron != "0 8 * * *" {
			t.Errorf("cron arg substitution: %q", tk.Cron)
		}
		if tk.Format != "egern" {
			t.Errorf("task format %s", tk.Format)
		}
	}
	if len(rs.Panels) != 1 || rs.Panels[0].Script != "status" || rs.Panels[0].Format != "egern" {
		t.Errorf("panels: %+v", rs.Panels)
	}
	if len(rs.Hostnames) != 2 || rs.Hostnames[1] != "-skip.test.com" {
		t.Errorf("hostnames: %v", rs.Hostnames)
	}
	var sawDNS, sawSSID bool
	for _, u := range rs.Unsupported {
		if strings.HasPrefix(u, "dns") {
			sawDNS = true
		}
		if strings.Contains(u, "ssid") {
			sawSSID = true
		}
	}
	if !sawDNS || !sawSSID {
		t.Errorf("unsupported not reported: %v", rs.Unsupported)
	}

	// Default arguments: the daily schedule is disabled.
	rs2 := &Ruleset{}
	rs2.ParseText(egernModule, "Egern Test", nil)
	if len(rs2.Tasks) != 3 {
		t.Errorf("disabled schedule should be skipped: %d", len(rs2.Tasks))
	}
}

func TestEgernNotStash(t *testing.T) {
	stash := "name: x\nhttp:\n  mitm:\n    - a.com\n  url-rewrite:\n    - ^https://a.com - reject\n"
	if IsEgern(stash) {
		t.Fatal("stash detected as egern")
	}
	if IsEgern("[Rule]\nDOMAIN,a.com,REJECT\n") {
		t.Fatal("surge detected as egern")
	}
}

func TestEgernRoundTrip(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Modules: []Module{{ID: "eg", Name: "Egern", Enabled: true}}}
	h := newHarness(t, cfg, map[string]string{"resp.js": `
var o = JSON.parse($response.body); o.arg = $argument; $done({body: JSON.stringify(o)});`})
	if err := writeFileForTest(ModulePath(h.home, "eg"), egernModule); err != nil {
		t.Fatal(err)
	}
	rs := Build(h.home, cfg)
	h.e.Reload(cfg, rs)

	resp, body := h.get("https://api.test.com/ad")
	if resp.StatusCode != 200 || body != "{}" {
		t.Errorf("reject-dict: %d %q", resp.StatusCode, body)
	}
	resp, _ = h.get("https://api.test.com/old/x")
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "https://api.test.com/new/x" {
		t.Errorf("redirect: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, _ = h.get("https://api.test.com/track/1")
	if resp.StatusCode != 404 {
		t.Errorf("url_regex REJECT: %d", resp.StatusCode)
	}
	_, body = h.get("https://api.test.com/echo", "X-Remove", "1", "X-Set", "one")
	if !strings.Contains(body, `"X-Added":"hello"`) || !strings.Contains(body, `"X-Set":"two"`) || strings.Contains(body, "X-Remove") {
		t.Errorf("headers: %s", body)
	}
	_, body = h.get("https://api.test.com/json")
	if body != `{"ad":false,"data":{"keep":1}}` {
		t.Errorf("body+jq: %s", body)
	}
	resp, body = h.get("https://api.test.com/local")
	if resp.StatusCode != 201 || body != `{"local": "x y"}` || resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("map local: %d %q %s", resp.StatusCode, body, resp.Header.Get("Content-Type"))
	}
	_, body = h.get("https://api.test.com/json?s=1")
	if !strings.Contains(body, `"arg":"k=v"`) {
		t.Errorf("compat script argument: %s", body)
	}
	_, body = h.get("https://api.test.com/urlx")
	if !strings.Contains(body, `"path":"/echo"`) {
		t.Errorf("header-mode url rewrite: %s", body)
	}
}

func TestEgernRuleSetConvert(t *testing.T) {
	text := "no_resolve: true\ndomain_set:\n  - a.com\ndomain_suffix_set:\n  - b.com\nip_cidr_set:\n  - 1.1.1.0/24\nasn_set:\n  - \"AS15169\"\nssid_set:\n  - Home\n"
	if !IsEgernRuleSet(text) {
		t.Fatal("not detected")
	}
	if IsEgernRuleSet("DOMAIN,a.com\n") || IsEgernRuleSet("payload:\n  - DOMAIN,a.com\n") {
		t.Fatal("false positive")
	}
	lines, skipped := ConvertEgernRuleSet(text)
	want := map[string]bool{"DOMAIN,a.com": true, "DOMAIN-SUFFIX,b.com": true, "IP-CIDR,1.1.1.0/24,no-resolve": true, "IP-ASN,15169,no-resolve": true}
	if len(lines) != 4 || skipped != 1 {
		t.Fatalf("lines=%v skipped=%d", lines, skipped)
	}
	for _, l := range lines {
		if !want[l] {
			t.Errorf("unexpected %q", l)
		}
	}
}

// Native Egern scripts run through the ctx adapter (egernadapter.go).
const egernRespJS = `export default async function (ctx) {
  const data = await ctx.response.json();
  data.ad = false;
  delete data.data.ads;
  ctx.response.headers.set('X-Egern', ctx.env.FLAG || 'none');
  ctx.storage.setJSON('last', { status: ctx.response.status });
  return { headers: ctx.response.headers, body: data };
}
`

const egernReqJS = `export default async function handler(ctx) {
  if (ctx.request.url.endsWith('/block')) return ctx.abort();
  if (ctx.request.url.endsWith('/local')) {
    return ctx.respond({ status: 201, headers: { 'Content-Type': 'text/plain' }, body: 'hi ' + ctx.request.headers['user-agent'] });
  }
  const resp = await ctx.http.get('https://api.test.com/json', { timeout: 3000, insecureTls: true });
  const j = await resp.json();
  const h = ctx.request.headers;
  h.set('X-Fetched', String(j.ad));
  h['X-Name'] = ctx.script.name;
  return { headers: h, body: { sent: true } };
}
`

const egernTaskJS = `export default async function (ctx) {
  const prev = ctx.storage.get('runs');
  ctx.storage.set('runs', String(Number(prev || 0) + 1));
  const gz = await ctx.compress.gzip(new TextEncoder().encode('ok-gzip'));
  const back = await ctx.compress.gunzip(gz);
  ctx.notify({ title: 'Egern', body: new TextDecoder().decode(back), action: { type: 'openUrl', url: 'https://x' } });
  return { type: 'widget', backgroundColor: '#112233', children: [
    { type: 'text', text: '标题' }, { type: 'stack', children: [{ type: 'text', text: '第一行' }, { type: 'text', text: '第二行' }] } ] };
}
`

func TestNativeEgernScripts(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`req = type=http-request,pattern=^https://api\.test\.com/(echo|block|local),requires-body=1,script-path=req.js`,
		`panel = type=generic,script-path=task.js`)}
	h := newHarness(t, cfg, map[string]string{"resp.js": egernRespJS, "req.js": egernReqJS, "task.js": egernTaskJS})
	// the response script comes from an Egern module with env (ctx.env)
	mod := "name: T\nscriptings:\n  - http_response:\n      name: resp\n      match: ^https://api\\.test\\.com/json\n      script_url: resp.js\n      body_required: true\n      env:\n        FLAG: \"on\"\n"
	if err := os.MkdirAll(filepath.Dir(ModulePath(h.home, "m1")), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ModulePath(h.home, "m1"), []byte(mod), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg.Modules = []Module{{ID: "m1", Name: "T", Enabled: true}}
	h.e.Reload(cfg, Build(h.home, cfg))
	resp, body := h.get("https://api.test.com/json")
	if !strings.Contains(body, `"ad":false`) || strings.Contains(body, `"ads"`) || !strings.Contains(body, `"keep":1`) {
		t.Fatalf("response body: %s logs=%+v", body, h.e.Logs.List(0, ""))
	}
	if resp.Header.Get("X-Egern") != "on" {
		t.Errorf("header from ctx.env: %q", resp.Header.Get("X-Egern"))
	}
	if v, _ := h.e.Store.Read("last"); v != `{"status":200}` {
		t.Errorf("storage.setJSON: %q", v)
	}

	r2, err := h.client.Post("https://api.test.com/echo", "text/plain", strings.NewReader("orig"))
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	if !strings.Contains(string(b2), `"X-Fetched":"true"`) || !strings.Contains(string(b2), `"X-Name":"req"`) || !strings.Contains(string(b2), `{\"sent\":true}`) {
		t.Fatalf("request rewrite: %s logs=%+v", b2, h.e.Logs.List(0, ""))
	}

	r3, b3 := h.get("https://api.test.com/local")
	if r3.StatusCode != 201 || !strings.HasPrefix(b3, "hi ") {
		t.Errorf("ctx.respond: %d %q", r3.StatusCode, b3)
	}
	if _, err := h.client.Get("https://api.test.com/block"); err == nil {
		t.Errorf("ctx.abort should drop the request")
	}

	var notes []string
	h.e.SetNotifier(func(title, sub, body, url string) { notes = append(notes, title+"|"+body+"|"+url) })
	rs := Build(h.home, cfg)
	rs.Panels = append(rs.Panels, &Panel{ID: "p1", Name: "面板", Script: "panel", Source: "用户", Format: "egern"})
	h.e.Reload(cfg, rs)
	st, err := h.e.tasks.refreshPanel("p1")
	if err != nil || st.Error != "" {
		t.Fatalf("panel: %v %+v logs=%+v", err, st, h.e.Logs.List(0, ""))
	}
	if st.Title != "标题" || st.Content != "第一行\n第二行" || st.BGColor != "#112233" {
		t.Errorf("widget → panel: %+v bg=%q", st.Panel, st.BGColor)
	}
	if len(notes) != 1 || notes[0] != "Egern|ok-gzip|https://x" {
		t.Errorf("notify / compress: %v", notes)
	}
	if v, _ := h.e.Store.Read("runs"); v != "1" {
		t.Errorf("storage: %q", v)
	}
}

func TestAdaptEgernRejectsModules(t *testing.T) {
	if _, err := adaptEgern("import x from './a.js'\nexport default async function(ctx) {}"); err == nil {
		t.Fatal("import should be refused")
	}
	if out, err := adaptEgern("export default async (ctx) => ({ url: ctx.request.url })"); err != nil || !strings.Contains(out, "var __egernMain = async (ctx)") {
		t.Fatalf("arrow export: %v %s", err, out)
	}
}

func TestScriptResourcesAndQUIC(t *testing.T) {
	home := t.TempDir()
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"*.a.com"}, Scripts: items(
		`a = type=http-request,pattern=^https://x\.a\.com/,script-path=https://example.com/a.js`,
		`b = type=http-request,pattern=^https://y\.a\.com/,script-path=https://example.com/b.js,script-update-interval=600`,
		`c = type=cron,cronexp="0 8 * * *",script-path=https://example.com/a.js`),
		ScriptResources: map[string]ScriptResource{
			"https://example.com/a.js": {Disabled: true},
			"https://example.com/b.js": {Interval: 3600},
		},
		QUICAllow: []string{"video.a.com"},
	}
	rs := Build(home, cfg)
	if len(rs.Rules) != 1 || rs.Rules[0].Script.Path != "https://example.com/b.js" || rs.Rules[0].Script.UpdateInterval != 3600 {
		t.Fatalf("script filter: %+v", rs.Rules)
	}
	if len(rs.Tasks) != 0 {
		t.Errorf("disabled cron script still scheduled")
	}
	raw := map[string]any{"rules": []any{"MATCH,DIRECT"}}
	Inject(raw, 1234, rs, cfg)
	rules := raw["rules"].([]any)
	if !strings.Contains(rules[0].(string), "(NOT,((RULE-SET,__quic_allow)))") || !strings.HasSuffix(rules[0].(string), ",REJECT") {
		t.Errorf("quic allow: %v", rules[0])
	}
	rp := raw["rule-providers"].(map[string]any)
	if p := rp["__quic_allow"].(map[string]any)["payload"].([]any); p[0] != "DOMAIN,video.a.com" {
		t.Errorf("quic allow payload: %v", p)
	}
}

func TestHTTPAPIBinding(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`api = type=http-request,pattern=^https://api\.test\.com/api,script-path=api.js`)}
	h := newHarness(t, cfg, map[string]string{"api.js": `
$httpAPI("POST", "/v1/policy_groups/select", {group_name: "Proxy", policy: "HK"}, function (r1) {
  $httpAPI("GET", "/v1/nope", null, function (r2) {
    $done({response: {status: 200, body: JSON.stringify({sel: r1, err: r2.error ? "yes" : "no"})}});
  });
});`})
	var got []string
	h.e.SetAPI(func(method, path string, body any) (any, error) {
		got = append(got, method+" "+path)
		if path == "/v1/nope" {
			return nil, errUnsupported
		}
		m := body.(map[string]any)
		return map[string]any{"ok": m["group_name"].(string) + "→" + m["policy"].(string)}, nil
	})
	_, body := h.get("https://api.test.com/api")
	if body != `{"sel":{"ok":"Proxy→HK"},"err":"yes"}` || len(got) != 2 {
		t.Fatalf("$httpAPI: %s %v", body, got)
	}
}
