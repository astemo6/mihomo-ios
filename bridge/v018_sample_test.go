package libmihomo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// v0.18 示例配置: the profile bundled in the app (App/Resources/sample-profile.yaml) must pass the same
// validation as a user profile, cover every documented section, and carry no real-looking secrets.
func TestV018SampleProfileValidates(t *testing.T) {
	src := filepath.Join("..", "App", "Resources", "sample-profile.yaml")
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	// Bundled geo data, as the app installs it (GEOSITE / GEOIP rules load them while parsing).
	for _, f := range []string{"geoip.metadb", "GeoSite.dat"} {
		g, err := os.ReadFile(filepath.Join("..", "Geo", f))
		if err != nil {
			t.Skipf("geo file %s missing: %v", f, err)
		}
		_ = os.WriteFile(filepath.Join(home, f), g, 0o644)
	}
	p := filepath.Join(home, "sample.yaml")
	_ = os.WriteFile(p, b, 0o644)
	if e := ValidateConfigIn(home, p); e != "" {
		t.Fatalf("sample profile does not validate: %s", e)
	}

	var raw map[string]any
	if err := yaml.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"mode", "log-level", "dns", "proxies", "proxy-providers", "proxy-groups", "rule-providers", "rules"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("section %s missing", k)
		}
	}
	types := map[string]bool{}
	for _, px := range proxiesOf(raw) {
		types[str(px["type"])] = true
		if s := str(px["server"]); s != "" && !strings.HasSuffix(s, "example.com") {
			t.Errorf("node %s has a non-placeholder server %s", str(px["name"]), s)
		}
	}
	for _, want := range []string{"ss", "vmess", "vless", "trojan", "hysteria2", "tuic", "wireguard", "anytls", "ssh", "snell", "mieru", "socks5", "http", "sudoku", "trusttunnel", "shadowquic", "gost-relay"} {
		if !types[want] {
			t.Errorf("no active %s example", want)
		}
	}
	text := string(b)
	for _, want := range []string{"type: tailscale", "type: masque", "type: openvpn", "PROCESS-NAME", "[rewrite_local]", "[task_local]", "[MITM]", "[Panel]", "format: mrs", "include-all: true", "exclude-filter", "load-balance", "fallback", "nameserver-policy", "fake-ip-filter", "AND,", "OR,", "NOT,", "GEOIP,", "GEOSITE,", "MATCH,", "ports: 20000-30000", "network: xhttp", "reality-opts"} {
		if !strings.Contains(text, want) {
			t.Errorf("sample does not mention %q", want)
		}
	}
	groups := map[string]string{}
	for _, g := range asList(raw["proxy-groups"]) {
		m := g.(map[string]any)
		groups[str(m["type"])] = str(m["name"])
	}
	for _, want := range []string{"select", "url-test", "fallback", "load-balance"} {
		if groups[want] == "" {
			t.Errorf("no %s group", want)
		}
	}
}
