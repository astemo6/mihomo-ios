package libmihomo

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel"
)

func writeJSON(t *testing.T, p string, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestResourceListAndStore(t *testing.T) {
	home := t.TempDir()
	mod := "#!name=Mod\n[Rule]\nRULE-SET,https://example.com/mod.list,REJECT\n[Script]\ns = type=http-request,pattern=^https://a\\.com,script-path=https://example.com/s.js,script-update-interval=3600\n[MITM]\nhostname = a.com\n"
	cfg := mitm.Config{Enabled: true, Modules: []mitm.Module{
		{ID: "m1", Name: "Mod", URL: "https://example.com/mod.sgmodule", Enabled: true, Interval: 7200},
		{ID: "m2", Name: "Local", Enabled: false},
	}, ScriptResources: map[string]mitm.ScriptResource{"https://example.com/old.js": {Disabled: true}}}
	writeJSON(t, filepath.Join(home, "engine", "engine.json"), cfg)
	_ = os.MkdirAll(filepath.Dir(mitm.ModulePath(home, "m1")), 0o755)
	if err := os.WriteFile(mitm.ModulePath(home, "m1"), []byte(mod), 0o644); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(home, "rules.json"), map[string]any{"rules": []CustomRule{
		{ID: "r1", Line: "RULE-SET,https://example.com/a.list,DIRECT", Enabled: true, Interval: 600},
		{ID: "r2", Line: "https://example.com/qx.list, tag=QX, force-policy=proxy, update-interval=172800", Enabled: false},
		{ID: "r3", Line: "DOMAIN,x.com,DIRECT", Enabled: true},
	}})
	items := listResources(home)
	byKey := map[string]ResourceItem{}
	for _, it := range items {
		byKey[it.Key] = it
	}
	if m := byKey["module:m1"]; m.Format != "surge" || m.Interval != 7200 || m.UpdatedAt == 0 || !m.Enabled {
		t.Errorf("module row: %+v", m)
	}
	if m := byKey["module:m2"]; m.Interval != 86400 || m.Enabled || !strings.HasPrefix(m.Detail, "本地") {
		t.Errorf("local module row: %+v", m)
	}
	if r := byKey["ruleset:list|https://example.com/a.list"]; r.Interval != 600 || r.RefID != "r1" || !r.Enabled || r.UpdatedAt != 0 {
		t.Errorf("rule set row: %+v", r)
	}
	if r := byKey["ruleset:list|https://example.com/qx.list"]; r.Interval != 172800 || r.Enabled {
		t.Errorf("qx rule set row: %+v", r)
	}
	if r := byKey["ruleset:list|https://example.com/mod.list"]; !r.ReadOnly || r.Owner != "Mod" {
		t.Errorf("module rule set row: %+v", r)
	}
	if s := byKey["script:https://example.com/s.js"]; s.Interval != 3600 || s.Owner != "Mod" || !s.Enabled {
		t.Errorf("script row: %+v", s)
	}
	if s := byKey["script:https://example.com/old.js"]; s.Enabled {
		t.Errorf("disabled script row: %+v", s)
	}
	if _, ok := byKey["ruleset:list|x.com"]; ok || len(items) != 7 {
		t.Errorf("items: %d %+v", len(items), items)
	}

	// Store: Surge list, Egern YAML set, HTML error page, module validation.
	res := ResourceStore(home, "ruleset:list|https://example.com/a.list", []byte("DOMAIN-SUFFIX,a.com\nUSER-AGENT,x*\n"))
	if !strings.Contains(res, `"ok":true`) {
		t.Fatalf("store list: %s", res)
	}
	b, _ := os.ReadFile(ruleSetPath(home, "https://example.com/a.list", "list"))
	if string(b) != "DOMAIN-SUFFIX,a.com\n" {
		t.Errorf("converted list: %q", b)
	}
	res = ResourceStore(home, "ruleset:list|https://example.com/mod.list", []byte("domain_suffix_set:\n  - ads.com\n"))
	b, _ = os.ReadFile(ruleSetPath(home, "https://example.com/mod.list", "list"))
	if !strings.Contains(res, `"ok":true`) || string(b) != "DOMAIN-SUFFIX,ads.com\n" {
		t.Errorf("egern set: %s %q", res, b)
	}
	res = ResourceStore(home, "module:m1", []byte("<!DOCTYPE html><html>404</html>"))
	if !strings.Contains(res, `"ok":false`) {
		t.Errorf("html should fail: %s", res)
	}
	if b, _ := os.ReadFile(mitm.ModulePath(home, "m1")); string(b) != mod {
		t.Errorf("module overwritten by a bad download")
	}
	res = ResourceStore(home, "module:m1", []byte("hello world"))
	if !strings.Contains(res, `"ok":false`) {
		t.Errorf("unrecognised module should fail: %s", res)
	}
	ResourceSetError(home, "script:https://example.com/s.js", "HTTP 404")
	res = ResourceStore(home, "script:https://example.com/s.js", []byte("$done({})"))
	if !strings.Contains(res, `"ok":true`) {
		t.Errorf("script store: %s", res)
	}
	byKey = map[string]ResourceItem{}
	for _, it := range listResources(home) {
		byKey[it.Key] = it
	}
	if m := byKey["module:m1"]; m.Error == "" || m.CheckedAt == 0 {
		t.Errorf("module error not recorded: %+v", m)
	}
	if s := byKey["script:https://example.com/s.js"]; s.Error != "" || s.UpdatedAt == 0 {
		t.Errorf("script state: %+v", s)
	}
	if r := byKey["ruleset:list|https://example.com/a.list"]; r.UpdatedAt == 0 || !strings.Contains(r.Detail, "1 条") {
		t.Errorf("rule set after store: %+v", r)
	}
}

func hist(ds ...uint16) []C.DelayHistory {
	var out []C.DelayHistory
	for _, d := range ds {
		out = append(out, C.DelayHistory{Time: time.Now(), Delay: d})
	}
	return out
}

func TestSmartScoring(t *testing.T) {
	fast, _, _, _ := smartScore(hist(100, 110, 90, 100), true)
	flaky, _, fails, _ := smartScore(hist(60, 0, 60, 0, 60), true)
	lastFail, _, _, _ := smartScore(hist(80, 80, 80, 0), true)
	dead, _, _, _ := smartScore(hist(0, 0), false)
	none, _, _, _ := smartScore(nil, true)
	if fails != 2 || !(fast < flaky) || !(fast < lastFail) || !math.IsInf(dead, 1) || !math.IsInf(none, 1) {
		t.Fatalf("fast=%v flaky=%v lastFail=%v dead=%v none=%v", fast, flaky, lastFail, dead, none)
	}
	recent, avg, _, _ := smartScore(hist(500, 500, 500, 100, 100), true)
	if avg >= 300 || recent >= 300 {
		t.Errorf("recent successes should weigh more: avg=%d score=%v", avg, recent)
	}
	// hysteresis: only switch when clearly better
	if p := smartPick([]float64{100, 90}, 0); p != -1 {
		t.Errorf("should keep current (10%% better only): %d", p)
	}
	if p := smartPick([]float64{100, 50}, 0); p != 1 {
		t.Errorf("should switch: %d", p)
	}
	if p := smartPick([]float64{math.Inf(1), 300}, 0); p != 1 {
		t.Errorf("should leave a dead node: %d", p)
	}
	if p := smartPick([]float64{math.Inf(1), math.Inf(1)}, 0); p != -1 {
		t.Errorf("no data: %d", p)
	}
}

func TestHTTPAPIAndSmartLive(t *testing.T) {
	home := t.TempDir()
	ov := defaultOverrides()
	ov.ControllerPort = 19292
	ov.Secret = "s"
	writeJSON(t, filepath.Join(home, "overrides.json"), ov)
	prof := filepath.Join(home, "p.yaml")
	_ = os.WriteFile(prof, []byte(`proxies:
  - {name: demo, type: ss, server: 127.0.0.1, port: 1, cipher: aes-128-gcm, password: x}
proxy-groups:
  - {name: PROXY, type: select, proxies: [demo, DIRECT]}
  - {name: AUTO, type: url-test, proxies: [demo, DIRECT], url: "http://127.0.0.1:1/gen204", interval: 600}
rules:
  - MATCH,PROXY
`), 0o644)
	writeJSON(t, filepath.Join(home, "groups.json"), map[string]groupSettings{"p": {Smart: []string{"AUTO", "PROXY"}}})
	if err := Start(home, prof, 0); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		smartMu.Lock()
		n := len(smartStatus)
		smartMu.Unlock()
		if tunnel.Status() == tunnel.Running && n > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	res, err := httpAPI("GET", "/v1/policies", nil)
	if err != nil {
		t.Fatal(err)
	}
	pol := res.(map[string]any)
	if !strings.Contains(strings.Join(pol["policy-groups"].([]string), ","), "PROXY") {
		t.Errorf("policies: %v", pol)
	}
	if _, err := httpAPI("POST", "/v1/policy_groups/select", map[string]any{"group_name": "PROXY", "policy": "DIRECT"}); err != nil {
		t.Fatal(err)
	}
	res, _ = httpAPI("GET", "/v1/policy_groups/select?group_name=PROXY", nil)
	if res.(map[string]any)["policy"] != "DIRECT" {
		t.Errorf("select: %v", res)
	}
	if _, err := httpAPI("POST", "/v1/policy_groups/select", map[string]any{"group_name": "PROXY", "policy": "nope"}); err == nil {
		t.Errorf("unknown policy should fail")
	}
	if _, err := httpAPI("POST", "/v1/outbound", map[string]any{"mode": "direct"}); err != nil {
		t.Fatal(err)
	}
	res, _ = httpAPI("GET", "/v1/outbound", nil)
	if res.(map[string]any)["mode"] != "direct" {
		t.Errorf("outbound: %v", res)
	}
	tunnel.SetMode(tunnel.Rule)
	res, _ = httpAPI("GET", "/v1/profiles/current", nil)
	if res.(map[string]any)["name"] != "p" {
		t.Errorf("current profile: %v", res)
	}
	if _, err := httpAPI("GET", "/v1/requests/recent", nil); err == nil || !strings.Contains(err.Error(), "不支持") {
		t.Errorf("unsupported path: %v", err)
	}
	groups, _ := httpAPI("GET", "/v1/policy_groups", nil)
	if len(groups.(map[string]any)["AUTO"].([]any)) != 2 {
		t.Errorf("policy_groups: %v", groups)
	}

	// Smart: a select group is ignored; the url-test group gets status rows.
	smartTick(readSmartGroups(home, prof))
	smartMu.Lock()
	st := smartStatus["AUTO"]
	_, selPresent := smartStatus["PROXY"]
	smartMu.Unlock()
	if st == nil || len(st.Members) != 2 || st.Type != "URLTest" {
		t.Fatalf("smart status: %+v", st)
	}
	if !selPresent {
		t.Errorf("configured select group should still be listed (as waiting)")
	}
}

func TestQUICBlockAll(t *testing.T) {
	home := t.TempDir()
	C.SetHomeDir(home)
	writeJSON(t, filepath.Join(home, "engine", "engine.json"), mitm.Config{QUIC: "all"})
	inject, err := prepareEngine(home)
	if err != nil || inject == nil {
		t.Fatalf("inject=%v err=%v", inject != nil, err)
	}
	o := defaultOverrides()
	o.Secret = "s"
	rt, err := buildRuntimeWith([]byte(sample), o, 0, inject)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rt), "AND,((NETWORK,UDP),(DST-PORT,443),(NOT,((IN-TYPE,INNER)))),REJECT") {
		t.Fatalf("quic rule missing:\n%s", rt)
	}
	if _, err := executor.ParseWithBytes(rt); err != nil {
		t.Fatal(err)
	}
}

func TestClassifyText(t *testing.T) {
	cases := map[string]string{
		"proxies:\n  - {name: a, type: ss, server: 1.1.1.1, port: 1, cipher: aes-128-gcm, password: x}\n":        "profile",
		"[General]\nloglevel = notify\n[Proxy]\nA = ss, 1.1.1.1, 8388, encrypt-method=aes-128-gcm, password=x\n": "conf",
		"#!name=X\n[URL Rewrite]\n^https://a\\.com - reject\n":                                                   "module:surge",
		"[rewrite_local]\n^https://a\\.com url reject\n[mitm]\nhostname = a.com\n":                               "module:qx",
		"name: E\nscriptings:\n  - generic:\n      name: g\n      script_url: https://x/g.js\n":                  "module:egern",
		"name: S\nhttp:\n  mitm:\n    - a.com\n":                                                                 "module:stash",
		"ss://YWVzLTEyOC1nY206eA@1.2.3.4:8388#node":                                                              "nodes",
		"hello world": "",
	}
	for in, want := range cases {
		if got := ClassifyText(in); got != want {
			t.Errorf("%q => %q, want %q", in[:min(len(in), 30)], got, want)
		}
	}
}
