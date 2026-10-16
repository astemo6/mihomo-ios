package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const chainProfile = `proxies:
  - {name: A, type: socks5, server: a.com, port: 1}
  - {name: B, type: socks5, server: b.com, port: 1}
  - {name: C, type: socks5, server: c.com, port: 1, dialer-proxy: D}
  - {name: D, type: socks5, server: d.com, port: 1, dialer-proxy: C}
  - {name: E, type: socks5, server: e.com, port: 1, dialer-proxy: Nope}
proxy-providers:
  sub: {type: file, path: ./sub.yaml}
proxy-groups:
  - {name: Relay, type: select, proxies: [A, B]}
  - {name: Front, type: select, proxies: [B]}
  - {name: All, type: select, proxies: [Relay, Front], use: [sub]}
rules:
  - MATCH,All
`

func chainRuntime(t *testing.T, home, path string) map[string]any {
	t.Helper()
	b, _ := os.ReadFile(path)
	rt, err := buildRuntime(b, overridesFor(home, path), 0)
	if err != nil {
		t.Fatal(err)
	}
	raw := map[string]any{}
	_ = yaml.Unmarshal(rt, &raw)
	return raw
}

func proxyByName(raw map[string]any, n string) map[string]any {
	for _, p := range proxiesOf(raw) {
		if str(p["name"]) == n {
			return p
		}
	}
	return nil
}

func TestChainLoopsBrokenAndGroupChains(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "p1.yaml")
	_ = os.WriteFile(path, []byte(chainProfile), 0o644)

	raw := chainRuntime(t, home, path)
	// C ↔ D loop: the first one in order loses its dialer-proxy; missing target dropped.
	if proxyByName(raw, "C")["dialer-proxy"] != nil || proxyByName(raw, "D")["dialer-proxy"] != "C" {
		t.Fatalf("loop not broken: C=%v D=%v", proxyByName(raw, "C")["dialer-proxy"], proxyByName(raw, "D")["dialer-proxy"])
	}
	if proxyByName(raw, "E")["dialer-proxy"] != nil {
		t.Fatal("missing target kept")
	}

	// Group chain: Relay's members dial through Front.
	if e := SetGroupChain(home, path, "Relay", "Front"); e != "" {
		t.Fatal(e)
	}
	raw = chainRuntime(t, home, path)
	if proxyByName(raw, "A")["dialer-proxy"] != "Front" {
		t.Fatalf("A not chained: %v", proxyByName(raw, "A"))
	}
	// B is a member of Front itself → would loop → skipped.
	if proxyByName(raw, "B")["dialer-proxy"] != nil {
		t.Fatal("B should be skipped (loop through Front)")
	}

	// Provider override for a group that uses a provider.
	// All's direct members are groups (not chained); its provider gets the override.
	if e := SetGroupChain(home, path, "All", "A"); e != "" {
		t.Fatal(e)
	}
	raw = chainRuntime(t, home, path)
	if asMap(asMap(asMap(raw["proxy-providers"])["sub"])["override"])["dialer-proxy"] != "A" {
		t.Fatal("provider override")
	}
	_ = SetGroupChain(home, path, "All", "")
	_ = SetGroupChain(home, path, "Relay", "")
	if e := SetGroupChain(home, path, "Front", "A"); e != "" {
		t.Fatal(e)
	}
	raw = chainRuntime(t, home, path)
	if proxyByName(raw, "B")["dialer-proxy"] != "A" {
		t.Fatal("B via A")
	}
	// A group can't dial through itself or a group containing it.
	if e := SetGroupChain(home, path, "Front", "All"); e == "" {
		t.Fatal("Front via All (contains Front) must be refused")
	}

	var c struct {
		Current    string           `json:"current"`
		Candidates []chainCandidate `json:"candidates"`
	}
	_ = json.Unmarshal([]byte(ChainCandidates(home, path, "group", "Front")), &c)
	names := []string{}
	for _, x := range c.Candidates {
		names = append(names, x.Name)
	}
	j := strings.Join(names, ",")
	if c.Current != "A" || strings.Contains(j, "All") || strings.Contains(j, "Front") || !strings.Contains(j, "Relay") {
		t.Fatalf("group candidates %+v", c)
	}
	// B dials through A (Front chain) → B would loop.
	_ = json.Unmarshal([]byte(ChainCandidates(home, path, "node", "A")), &c)
	names = names[:0]
	for _, x := range c.Candidates {
		names = append(names, x.Name)
	}
	j = strings.Join(names, ",")
	if strings.Contains(j, "Relay") || strings.Contains(j, "All") || strings.Contains(j, "B") || j != "C,D,E" {
		t.Fatalf("node candidates %s", j)
	}

	// groups.json keeps the smart option alongside.
	b, _ := os.ReadFile(groupSettingsPath(home))
	if !strings.Contains(string(b), `"dialer"`) {
		t.Fatalf("%s", b)
	}
	// Safe mode ignores group chains.
	_ = os.WriteFile(filepath.Join(home, "overrides.json"), []byte(`{"safeMode":true}`), 0o644)
	raw = chainRuntime(t, home, path)
	if proxyByName(raw, "B")["dialer-proxy"] != nil {
		t.Fatal("safe mode applied group chain")
	}
}

func TestChainProviderOverride(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "p2.yaml")
	_ = os.WriteFile(path, []byte(chainProfile), 0o644)
	_ = os.WriteFile(groupSettingsPath(home), []byte(`{"p2":{"dialer":{"All":"Nope"}}}`), 0o644)
	raw := chainRuntime(t, home, path) // unknown via → ignored
	if asMap(asMap(asMap(raw["proxy-providers"])["sub"])["override"])["dialer-proxy"] != nil {
		t.Fatal("unknown via applied")
	}
	// Separate group that uses the provider, via a node outside it.
	prof := strings.Replace(chainProfile, "  - {name: All, type: select, proxies: [Relay, Front], use: [sub]}", "  - {name: All, type: select, proxies: [Relay, Front]}\n  - {name: Sub, type: url-test, use: [sub]}", 1)
	_ = os.WriteFile(path, []byte(prof), 0o644)
	if e := SetGroupChain(home, path, "Sub", "A"); e != "" {
		t.Fatal(e)
	}
	raw = chainRuntime(t, home, path)
	if asMap(asMap(asMap(raw["proxy-providers"])["sub"])["override"])["dialer-proxy"] != "A" {
		t.Fatalf("provider override missing: %v", raw["proxy-providers"])
	}
}

func TestChainParsesInCore(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "p3.yaml")
	prof := "proxies:\n  - {name: A, type: socks5, server: 127.0.0.1, port: 1}\n  - {name: B, type: socks5, server: 127.0.0.1, port: 2}\nproxy-groups:\n  - {name: G, type: select, proxies: [B]}\n  - {name: F, type: select, proxies: [A]}\nrules:\n  - MATCH,G\n"
	_ = os.WriteFile(path, []byte(prof), 0o644)
	if e := SetGroupChain(home, path, "G", "F"); e != "" {
		t.Fatal(e)
	}
	if msg := ValidateConfigIn(home, path); msg != "" {
		t.Fatal(msg)
	}
	if proxyByName(chainRuntime(t, home, path), "B")["dialer-proxy"] != "F" {
		t.Fatal("chain missing")
	}
}
