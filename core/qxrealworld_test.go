package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// v0.8.1: a QX config with every rewrite_local type, rewrite_remote (enabled / disabled / no tag),
// filter_remote, task_local and [mitm]. Public snippet URLs only.
func TestQXRealWorldImport(t *testing.T) {
	b, err := os.ReadFile("testdata/qx_realworld.conf")
	if err != nil {
		t.Fatal(err)
	}
	var res confResult
	if err := json.Unmarshal([]byte(ImportConf(string(b))), &res); err != nil {
		t.Fatal(err)
	}
	if res.Error != "" {
		t.Fatal(res.Error)
	}
	rep := res.Report
	// rewrite_remote: 4 modules, names from tag= or the file name, enabled= respected.
	if len(res.RewriteRemotes) != 4 || rep.Remotes != 4 {
		t.Fatalf("remotes %+v", res.RewriteRemotes)
	}
	want := map[string]bool{"开屏去广告": true, "YouTube去广告": true, "比价": false, "boxjs.rewrite.quanx": true}
	for _, m := range res.RewriteRemotes {
		en, ok := want[m.Name]
		if !ok || en != m.Enabled {
			t.Fatalf("remote %+v", m)
		}
	}
	// rewrite_local: 20 lines, 7 of them scripts; nothing unsupported; tasks; hostnames without exclusions.
	if rep.Rewrites != 13 || rep.Scripts != 7 {
		t.Fatalf("rewrites %d scripts %d", rep.Rewrites, rep.Scripts)
	}
	if rep.Tasks != 1 {
		t.Fatalf("tasks %d (the disabled one is skipped)", rep.Tasks)
	}
	if rep.Hostnames != 8 {
		t.Fatalf("hostnames %d", rep.Hostnames)
	}
	for _, s := range rep.Skipped {
		if strings.HasPrefix(s, "[重写]") {
			t.Fatalf("unexpected skipped: %s", s)
		}
	}
	if strings.Contains(res.Module, "passphrase") || strings.Contains(res.Module, "p12") {
		t.Fatal("CA settings must not be copied into the module")
	}
	if !strings.Contains(res.Module, "[task_local]") {
		t.Fatal("task_local missing from module")
	}
	// Rule providers: readable names, source URL kept, conversion recorded.
	var cfg map[string]any
	_ = yaml.Unmarshal([]byte(res.YAML), &cfg)
	rp, _ := cfg["rule-providers"].(map[string]any)
	for _, n := range []string{"YouTube", "Privacy", "Unbreak"} {
		m, ok := rp[n].(map[string]any)
		if !ok {
			t.Fatalf("rule provider %s missing: %v", n, rp)
		}
		if !strings.HasPrefix(str(m["url"]), "https://raw.githubusercontent.com/") || str(m["x-convert"]) != "list" {
			t.Fatalf("provider %s: %v", n, m)
		}
	}
	for _, r := range strList(cfg["rules"]) {
		if strings.Contains(r, "custom-") {
			t.Fatalf("hash name in rules: %s", r)
		}
	}
	// Runtime: the core gets the local converter, the inspector shows the source URL.
	home := t.TempDir()
	prof := filepath.Join(home, "p.yaml")
	_ = os.WriteFile(prof, []byte(res.YAML), 0o644)
	var ins inspectResult
	_ = json.Unmarshal([]byte(InspectProfile(home, prof)), &ins)
	if len(ins.RuleProviders) < 3 {
		t.Fatalf("inspect providers: %+v", ins.RuleProviders)
	}
	for _, p := range ins.RuleProviders {
		if strings.Contains(p.URL, "127.0.0.1") {
			t.Fatalf("inspector shows the local converter: %s", p.URL)
		}
	}
	// Plan: what the app downloads, and where.
	var plan []providerTask
	_ = json.Unmarshal([]byte(ProviderPlan(home, prof)), &plan)
	seen := 0
	for _, p := range plan {
		if p.Kind == "rule" && p.Convert == "list" && strings.HasPrefix(p.URL, "https://") && strings.HasPrefix(p.Path, home) {
			seen++
		}
		if p.Kind == "proxy" && p.Convert != "nodes" {
			t.Fatalf("node provider plan %+v", p)
		}
	}
	if seen != 3 {
		t.Fatalf("plan %+v", plan)
	}
	// Store: a QX list converted into the cache file the core reads.
	var out map[string]any
	for _, p := range plan {
		if p.Name == "Privacy" {
			_ = json.Unmarshal([]byte(ProviderStore(home, "rule", p.Path, p.Convert, []byte("host-suffix, ads.example.com, reject\nhost, t.example.com, reject\n# c\n"))), &out)
			got, _ := os.ReadFile(p.Path)
			if out["error"] != "" || out["count"].(float64) != 2 || !strings.Contains(string(got), "DOMAIN-SUFFIX,ads.example.com") {
				t.Fatalf("store %v %q", out, got)
			}
		}
	}
	if ProviderStore(home, "rule", "/etc/x.txt", "", []byte("x")) == "" || !strings.Contains(ProviderStore(home, "rule", "/etc/x.txt", "", []byte("x")), "路径") {
		t.Fatal("path outside home must be refused")
	}
}

// v0.8.0 profiles: convert+ URLs and custom-<hash> names are migrated, references follow.
func TestMigrateProfileProviders(t *testing.T) {
	old := `proxies: []
proxy-groups:
  - {name: P, type: select, proxies: [DIRECT], use: [机场A]}
proxy-providers:
  机场A: {type: http, url: "convert+nodes:https://sub.example.com/s", path: ./proxies/x.yaml, interval: 86400}
rule-providers:
  custom-1a2b3c4d: {type: http, behavior: classical, format: text, url: "convert+list:https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/TikTok/TikTok.list", path: ./ruleset/custom-1a2b3c4d.txt, interval: 86400}
  custom-99999999: {type: http, behavior: classical, format: text, url: "convert+list:https://example.com/a/TikTok.list", path: ./ruleset/custom-99999999.txt, interval: 86400}
rules:
  - RULE-SET,custom-1a2b3c4d,P
  - AND,((RULE-SET,custom-99999999),(NETWORK,TCP)),DIRECT
  - MATCH,P
`
	p := filepath.Join(t.TempDir(), "p.yaml")
	_ = os.WriteFile(p, []byte(old), 0o644)
	if n := MigrateProfileProviders(p); n != 3 {
		t.Fatalf("changed %d", n)
	}
	b, _ := os.ReadFile(p)
	s := string(b)
	if strings.Contains(s, "convert+") || strings.Contains(s, "custom-1a2b3c4d,") || !strings.Contains(s, "RULE-SET,TikTok,P") || !strings.Contains(s, "(RULE-SET,TikTok-2)") {
		t.Fatalf("migrated:\n%s", s)
	}
	if !strings.Contains(s, "ruleset/custom-1a2b3c4d.txt") {
		t.Fatal("cache path must stay")
	}
	if MigrateProfileProviders(p) != 0 {
		t.Fatal("second run must be a no-op")
	}
}
