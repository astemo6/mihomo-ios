package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Review 7 R7A-4 (Go side): same-named nodes in two subscriptions are looked up by provider + name.
func TestR7A4NodeLookupByProvider(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "mihomo")
	_ = os.MkdirAll(filepath.Join(home, "nodesubs"), 0o755)
	node := func(server, pw string) string {
		return "proxies:\n  - {name: \"🇭🇰 香港 01\", type: ss, server: " + server + ", port: 1, cipher: aes-128-gcm, password: " + pw + "}\n"
	}
	_ = os.WriteFile(filepath.Join(home, "nodesubs", "a.yaml"), []byte(node("1.1.1.1", "pwA")), 0o644)
	_ = os.WriteFile(filepath.Join(home, "nodesubs", "b.yaml"), []byte(node("2.2.2.2", "pwB")), 0o644)
	subs, _ := json.Marshal([]NodeSub{{ID: "a", Name: "Alpha", Enabled: true}, {ID: "b", Name: "Beta", Enabled: true}})
	_ = os.WriteFile(filepath.Join(home, "node-subscriptions.json"), subs, 0o644)
	prof := filepath.Join(root, "p.yaml")
	_ = os.WriteFile(prof, []byte(`proxies:
  - {name: "🇭🇰 香港 01", type: ss, server: 3.3.3.3, port: 1, cipher: aes-128-gcm, password: pwP}
proxy-groups:
  - {name: P, type: select, proxies: ["🇭🇰 香港 01"]}
rules:
  - MATCH,P
`), 0o644)
	name := "🇭🇰 香港 01"
	for prov, want := range map[string]string{"": "pwP", "Alpha": "pwA", "Beta": "pwB"} {
		cfg := NodeConfigIn(home, prof, prov, name)
		if !strings.Contains(cfg, want) {
			t.Fatalf("provider %q: want %s, got %s", prov, want, cfg)
		}
		var sum map[string]any
		_ = json.Unmarshal([]byte(NodeSummaryIn(home, prof, prov, name)), &sum)
		if sum["source"] != prov || sum["error"] != nil {
			t.Fatalf("summary provider %q: %v", prov, sum)
		}
	}
	if NodeConfigIn(home, prof, "Gamma", name) != "" {
		t.Fatal("unknown provider must not fall back to another source")
	}
	var sum map[string]any
	_ = json.Unmarshal([]byte(NodeSummaryIn(home, prof, "Gamma", name)), &sum)
	if sum["error"] == nil {
		t.Fatalf("unknown provider: want error, got %v", sum)
	}
	// Old name-only API unchanged (profile first).
	if !strings.Contains(NodeConfig(home, prof, name), "pwP") {
		t.Fatal("NodeConfig compatibility")
	}
	// Delay test resolves the scoped node (server 127.0.0.1:1 style refusals are fine: only "not found" matters).
	resetRuntimeCache()
	if ms := NodeTestDelayIn(home, prof, "Gamma", name, "http://127.0.0.1:1/", 300); ms != -1 || !strings.Contains(LastError(), "找不到") {
		t.Fatalf("delay unknown provider: %d %s", ms, LastError())
	}
}
