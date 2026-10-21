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

// Review 7 P2-2: the exported final config carries no secret, no loopback converter URL and no device path.
func TestR7P22FinalConfigPortable(t *testing.T) {
	dir := t.TempDir()
	ov := defaultOverrides()
	ov.Secret = "SuperSecret123"
	ob, _ := json.Marshal(ov)
	_ = os.WriteFile(filepath.Join(dir, "overrides.json"), ob, 0o644)
	// node subscription (device-local file provider)
	_ = os.MkdirAll(filepath.Join(dir, "nodesubs"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "nodesubs", "s1.yaml"), []byte("proxies:\n  - {name: b1, type: ss, server: 1.1.1.1, port: 1, cipher: aes-128-gcm, password: x}\n"), 0o644)
	subs, _ := json.Marshal([]NodeSub{{ID: "s1", Name: "B", URL: "https://b.example/sub", Enabled: true}})
	_ = os.WriteFile(filepath.Join(dir, "node-subscriptions.json"), subs, 0o644)
	// absolute-path local rule list (like a QX 自有策略 list in the App Group container)
	abs := filepath.Join(dir, "ownpolicy", "list.txt")
	_ = os.MkdirAll(filepath.Dir(abs), 0o755)
	_ = os.WriteFile(abs, []byte("# comment\nDOMAIN-SUFFIX,example.org\nDOMAIN,a.example.net\n"), 0o644)
	p := filepath.Join(dir, "profile.yaml")
	_ = os.WriteFile(p, []byte(`proxies:
  - {name: a, type: ss, server: 1.2.3.4, port: 1, cipher: aes-128-gcm, password: x}
proxy-providers:
  sub: {type: http, url: "https://example.com/sub?token=abc", x-convert: nodes, path: ./proxies/sub.yaml, interval: 3600}
rule-providers:
  r: {type: http, behavior: classical, format: text, url: "https://example.com/r.list", x-convert: surge, path: ./rules/r.txt}
  own: {type: file, behavior: classical, format: text, path: `+abs+`}
proxy-groups:
  - {name: P, type: select, proxies: [a], use: [sub]}
rules:
  - RULE-SET,r,P
  - RULE-SET,own,P
  - MATCH,P
`), 0o644)
	out, err := FinalConfig(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"SuperSecret123", "127.0.0.1:", "Authorization", dir, "x-source", "/convert"} {
		if strings.Contains(out, bad) {
			t.Fatalf("export still contains %q:\n%s", bad, out)
		}
	}
	for _, want := range []string{"https://example.com/sub?token=abc", "https://example.com/r.list", "导出说明"} {
		if !strings.Contains(out, want) {
			t.Fatalf("export lacks %q:\n%s", want, out)
		}
	}
	raw := map[string]any{}
	if err := yaml.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatal(err)
	}
	b := asMap(asMap(raw["proxy-providers"])["B"])
	if str(b["type"]) != "inline" || len(asList(b["payload"])) != 1 || b["path"] != nil {
		t.Fatalf("node subscription not inlined: %v", b)
	}
	own := asMap(asMap(raw["rule-providers"])["own"])
	if str(own["type"]) != "inline" || len(asList(own["payload"])) != 2 {
		t.Fatalf("local rule list not inlined: %v", own)
	}
	if _, err := executor.ParseWithBytes([]byte(out)); err != nil {
		t.Fatalf("exported config does not parse: %v", err)
	}
}

func TestR7P22MissingLocalFileExplained(t *testing.T) {
	raw := map[string]any{"rule-providers": map[string]any{
		"gone": map[string]any{"type": "file", "behavior": "domain", "path": "/var/mobile/Containers/Shared/AppGroup/X/l.txt"},
	}}
	notes := portableProviders(raw, t.TempDir(), "")
	g := asMap(asMap(raw["rule-providers"])["gone"])
	if len(notes) != 1 || strings.Contains(str(g["path"]), "/var/mobile") {
		t.Fatalf("want one note and no container path: %v %v", notes, g)
	}
}
