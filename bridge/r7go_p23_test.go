package libmihomo

import (
	"strings"
	"testing"
)

// Review 7 P2-3: editing a provider link changes its cache path, so the new link's nodes load immediately.
func TestR7P23EditedLinkGetsOwnPath(t *testing.T) {
	mk := func() map[string]any {
		return map[string]any{
			"proxy-providers": map[string]any{
				"A": map[string]any{"type": "http", "url": "https://old.example/sub", "path": "./proxy_providers/a.yaml", "interval": 86400},
				"N": map[string]any{"type": "http", "url": "https://n.example/sub", "interval": 86400},
			},
			"proxy-groups": []any{map[string]any{"name": "P", "type": "select", "use": []any{"A", "N"}}},
		}
	}
	raw := mk()
	applyProviderOverrides(raw, map[string]ProviderOverride{"A": {URL: "https://new.example/sub"}, "N": {URL: "https://n2.example/sub"}})
	a := asMap(asMap(raw["proxy-providers"])["A"])
	if str(a["url"]) != "https://new.example/sub" || str(a["path"]) == "./proxy_providers/a.yaml" ||
		!strings.HasPrefix(str(a["path"]), "./proxy_providers/a-") || !strings.HasSuffix(str(a["path"]), ".yaml") {
		t.Fatalf("edited link must get a new path: %v", a)
	}
	if n := asMap(asMap(raw["proxy-providers"])["N"]); n["path"] != nil {
		t.Fatalf("a provider without path stays without (hash path already follows the URL): %v", n)
	}
	// Same link as the profile (or no edit): path unchanged; a second different link gets another path.
	raw = mk()
	applyProviderOverrides(raw, map[string]ProviderOverride{"A": {URL: "https://old.example/sub"}})
	if p := str(asMap(asMap(raw["proxy-providers"])["A"])["path"]); p != "./proxy_providers/a.yaml" {
		t.Fatalf("unchanged link must keep the path: %s", p)
	}
	raw = mk()
	applyProviderOverrides(raw, map[string]ProviderOverride{"A": {URL: "https://other.example/sub"}})
	if p := str(asMap(asMap(raw["proxy-providers"])["A"])["path"]); p == str(a["path"]) {
		t.Fatalf("different links must not share a path: %s", p)
	}
	// Loopback converter providers compare by their source URL.
	raw = map[string]any{"proxy-providers": map[string]any{"C": map[string]any{"type": "http", "path": "./p/c.yaml",
		"url": "http://127.0.0.1:9090/nodes/convert?url=https%3A%2F%2Fsrc.example%2Fs"}}}
	applyProviderOverrides(raw, map[string]ProviderOverride{"C": {URL: "https://src.example/s"}})
	if p := str(asMap(asMap(raw["proxy-providers"])["C"])["path"]); p != "./p/c.yaml" {
		t.Fatalf("same source behind the converter keeps the path: %s", p)
	}
}
