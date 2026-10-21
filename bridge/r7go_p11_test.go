package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/hub/executor"
	"go.yaml.in/yaml/v3"
)

// Review 7 P1-1: disabling a 节点集 must not turn its groups into DIRECT-only when a node subscription is merged.
func r7DisableHome(t *testing.T, withSub bool) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	_ = os.MkdirAll(filepath.Join(home, "nodesubs"), 0o755)
	if withSub {
		_ = os.WriteFile(filepath.Join(home, "nodesubs", "s1.yaml"), []byte("proxies:\n  - {name: b1, type: ss, server: 1.1.1.1, port: 1, cipher: aes-128-gcm, password: x}\n"), 0o644)
		subs, _ := json.Marshal([]NodeSub{{ID: "s1", Name: "B", URL: "https://b.example/sub", Enabled: true}})
		_ = os.WriteFile(filepath.Join(home, "node-subscriptions.json"), subs, 0o644)
	}
	ob, _ := json.Marshal(map[string]map[string]ProviderOverride{"pid": {"A": {Disabled: true}}})
	_ = os.WriteFile(filepath.Join(home, "provider-overrides.json"), ob, 0o644)
	return home
}

const r7DisableProfile = `proxy-providers:
  A: {type: http, url: "https://a.example/sub", path: ./proxies/a.yaml, interval: 86400}
proxy-groups:
  - {name: 节点选择, type: select, use: [A]}
  - {name: 自动, type: url-test, use: [A], url: "https://www.gstatic.com/generate_204", interval: 300}
rules:
  - MATCH,节点选择
`

func r7Groups(t *testing.T, rt []byte) map[string]map[string]any {
	t.Helper()
	raw := map[string]any{}
	if err := yaml.Unmarshal(rt, &raw); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, g := range asList(raw["proxy-groups"]) {
		m := asMap(g)
		out[str(m["name"])] = m
	}
	return out
}

func TestR7P11DisableProviderMergesNodeSub(t *testing.T) {
	home := r7DisableHome(t, true)
	o := defaultOverrides()
	o.home, o.profileID = home, "pid"
	rt, err := buildRuntime([]byte(r7DisableProfile), o, 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rt), providerLostKey) {
		t.Fatalf("internal marker leaked into the runtime")
	}
	gs := r7Groups(t, rt)
	for _, n := range []string{"节点选择", "自动"} {
		g := gs[n]
		if strings.Join(strList(g["use"]), ",") != "B" {
			t.Fatalf("%s: want use [B], got %v", n, g["use"])
		}
		for _, p := range strList(g["proxies"]) {
			if p == "DIRECT" {
				t.Fatalf("%s must not contain DIRECT: %v", n, g["proxies"])
			}
		}
	}
	if _, err := executor.ParseWithBytes(rt); err != nil {
		t.Fatalf("runtime invalid: %v", err)
	}
}

func TestR7P11DisableProviderNoSubFallsBackToDirect(t *testing.T) {
	for _, safe := range []bool{false, true} {
		home := r7DisableHome(t, safe) // not safe: no node subscription; 安全模式: a subscription exists but is not merged
		o := defaultOverrides()
		o.home, o.profileID, o.SafeMode = home, "pid", safe
		rt, err := buildRuntime([]byte(r7DisableProfile), o, 0)
		if err != nil {
			t.Fatal(err)
		}
		gs := r7Groups(t, rt)
		for _, n := range []string{"节点选择", "自动"} {
			if strings.Join(strList(gs[n]["proxies"]), ",") != "DIRECT" || gs[n]["use"] != nil {
				t.Fatalf("safe=%v %s: want DIRECT only, got %v", safe, n, gs[n])
			}
		}
	}
}
