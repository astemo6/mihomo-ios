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

const proxyChainProfile = `proxies:
  - {name: A, type: socks5, server: a.com, port: 1}
  - {name: B, type: socks5, server: b.com, port: 1}
  - {name: C, type: socks5, server: c.com, port: 1, dialer-proxy: A}
  - {name: HK1, type: socks5, server: h1.com, port: 1}
  - {name: HK2, type: socks5, server: h2.com, port: 1}
proxy-providers:
  sub:
    type: inline
    payload:
      - {name: S1, type: socks5, server: s1.com, port: 1}
      - {name: S2, type: socks5, server: s2.com, port: 1}
proxy-groups:
  - {name: Entry, type: select, proxies: [A, B]}
  - {name: HK, type: url-test, proxies: [HK1, HK2], use: [sub], url: "https://www.gstatic.com/generate_204", interval: 300}
  - {name: Pick, type: select, proxies: [HK1, HK2]}
  - {name: Everything, type: select, include-all: true}
  - {name: Proxy, type: select, proxies: [Entry, HK]}
rules:
  - DOMAIN,example.com,Proxy
  - MATCH,Proxy
`

func writeProxyChains(t *testing.T, home string, chains []ProxyChain) {
	t.Helper()
	b, _ := json.Marshal(chains)
	if err := os.WriteFile(proxyChainsPath(home), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func setupProxyChains(t *testing.T, profile string, chains []ProxyChain) (string, string) {
	t.Helper()
	home := t.TempDir()
	path := filepath.Join(home, "p1.yaml")
	if err := os.WriteFile(path, []byte(profile), 0o644); err != nil {
		t.Fatal(err)
	}
	writeProxyChains(t, home, chains)
	return home, path
}

// buildParsed builds the runtime and parses it with the core (what Start does).
func buildParsed(t *testing.T, home, path string) (map[string]any, []byte) {
	t.Helper()
	b, _ := os.ReadFile(path)
	rt, err := buildRuntime(b, overridesFor(home, path), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.ParseWithBytes(rt); err != nil {
		t.Fatalf("core refused the runtime: %v\n%s", err, rt)
	}
	raw := map[string]any{}
	_ = yaml.Unmarshal(rt, &raw)
	return raw, rt
}

func groupNamed(raw map[string]any, n string) map[string]any {
	for _, x := range asList(raw["proxy-groups"]) {
		if g, ok := x.(map[string]any); ok && str(g["name"]) == n {
			return g
		}
	}
	return nil
}

func chainProviderNodes(raw map[string]any, pn string) []string {
	var out []string
	for _, p := range asList(asMap(asMap(raw["proxy-providers"])[pn])["payload"]) {
		out = append(out, str(asMap(p)["name"]))
	}
	return out
}

func TestProxyChainNodesThreeHops(t *testing.T) {
	home, path := setupProxyChains(t, proxyChainProfile, []ProxyChain{{ID: "1", Name: "链", UDP: true, Enabled: true, Members: []string{"Entry", "B", "C"}}})
	raw, rt := buildParsed(t, home, path)
	exit := groupNamed(raw, "链")
	if exit == nil || boolOf(exit["hidden"]) || str(exit["type"]) != "select" {
		t.Fatalf("exit group: %v\n%s", exit, rt)
	}
	use := strList(exit["use"])
	if len(use) != 1 || !strings.HasPrefix(use[0], GeneratedProviderPrefix) {
		t.Fatalf("exit use %v", use)
	}
	pv := asMap(asMap(raw["proxy-providers"])[use[0]])
	if str(pv["type"]) != "inline" || strings.Join(chainProviderNodes(raw, use[0]), ",") != "C" {
		t.Fatalf("exit provider %v", pv)
	}
	mid := str(asMap(pv["override"])["dialer-proxy"])
	if asMap(pv["override"])["udp"] != true {
		t.Fatalf("udp not set: %v", pv["override"])
	}
	mg := groupNamed(raw, mid)
	if mg == nil || !boolOf(mg["hidden"]) {
		t.Fatalf("middle hop %q: %v", mid, mg)
	}
	mu := strList(mg["use"])
	if len(mu) != 1 || strings.Join(chainProviderNodes(raw, mu[0]), ",") != "B" {
		t.Fatalf("middle provider %v", mu)
	}
	if v := str(asMap(asMap(asMap(raw["proxy-providers"])[mu[0]])["override"])["dialer-proxy"]); v != "Entry" {
		t.Fatalf("middle dials via %q, want Entry", v)
	}
	// The originals keep their own settings; the chain copy of C does not inherit dialer-proxy A.
	if proxyByName(raw, "C")["dialer-proxy"] != "A" {
		t.Fatalf("original C changed: %v", proxyByName(raw, "C"))
	}
	for _, p := range asList(pv["payload"]) {
		if _, ok := asMap(p)["dialer-proxy"]; ok {
			t.Fatalf("copy keeps its own dialer-proxy: %v", p)
		}
	}
	// include-all groups do not pick up the chain providers.
	ev := groupNamed(raw, "Everything")
	if boolOf(ev["include-all"]) || !boolOf(ev["include-all-proxies"]) || strings.Join(strList(ev["use"]), ",") != "sub" {
		t.Fatalf("include-all group not pinned to own providers: %v", ev)
	}
}

func TestProxyChainCoreDialerProxies(t *testing.T) {
	home, path := setupProxyChains(t, proxyChainProfile, []ProxyChain{{ID: "1", Name: "X", Enabled: true, Members: []string{"A", "B"}}})
	b, _ := os.ReadFile(path)
	rt, err := buildRuntime(b, overridesFor(home, path), 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := executor.ParseWithBytes(rt)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Proxies["X"]; !ok {
		t.Fatalf("chain group missing in the core")
	}
	found := false
	for name, pd := range cfg.Providers {
		if !strings.HasPrefix(name, GeneratedProviderPrefix) {
			continue
		}
		for _, p := range pd.Proxies() {
			if p.Name() == "B" {
				found = true
				if d := p.ProxyInfo().DialerProxy; d != "A" {
					t.Fatalf("core copy of B dials via %q", d)
				}
				if p.SupportUDP() {
					t.Fatalf("UDP off but the copy supports UDP")
				}
			}
		}
	}
	if !found {
		t.Fatalf("no chain copy of B in the core")
	}
}

func TestProxyChainGroupHops(t *testing.T) {
	home, path := setupProxyChains(t, proxyChainProfile, []ProxyChain{
		{ID: "1", Name: "经香港", Enabled: true, Members: []string{"A", "HK", "Pick"}},
	})
	raw, rt := buildParsed(t, home, path)
	// Middle hop: url-test HK copied (hidden), its nodes and the provider it uses dial via A.
	var mid map[string]any
	for _, x := range asList(raw["proxy-groups"]) {
		g := asMap(x)
		if strings.HasPrefix(str(g["name"]), "经香港 › ") {
			mid = g
		}
	}
	if mid == nil || !boolOf(mid["hidden"]) || str(mid["type"]) != "url-test" || str(mid["url"]) == "" {
		t.Fatalf("middle hop: %v\n%s", mid, rt)
	}
	use := strList(mid["use"])
	if len(use) != 2 {
		t.Fatalf("middle use %v", use)
	}
	for _, u := range use {
		if v := str(asMap(asMap(asMap(raw["proxy-providers"])[u])["override"])["dialer-proxy"]); v != "A" {
			t.Fatalf("%s dials via %q", u, v)
		}
	}
	if strings.Join(chainProviderNodes(raw, use[1]), ",") != "S1,S2" {
		t.Fatalf("copied provider %v", chainProviderNodes(raw, use[1]))
	}
	// Exit: the 手动选择 group Pick becomes the chain group with HK1 / HK2 dialing via the middle hop.
	exit := groupNamed(raw, "经香港")
	eu := strList(exit["use"])
	if len(eu) != 1 || strings.Join(chainProviderNodes(raw, eu[0]), ",") != "HK1,HK2" ||
		str(asMap(asMap(asMap(raw["proxy-providers"])[eu[0]])["override"])["dialer-proxy"]) != str(mid["name"]) {
		t.Fatalf("exit %v\n%s", exit, rt)
	}
}

func TestProxyChainSelectMiddleStaysVisible(t *testing.T) {
	home, path := setupProxyChains(t, proxyChainProfile, []ProxyChain{{ID: "1", Name: "Y", Enabled: true, Members: []string{"A", "Pick", "B"}}})
	raw, _ := buildParsed(t, home, path)
	for _, x := range asList(raw["proxy-groups"]) {
		g := asMap(x)
		if strings.HasPrefix(str(g["name"]), "Y › ") && boolOf(g["hidden"]) {
			t.Fatalf("a 手动选择 middle hop must stay choosable: %v", g)
		}
	}
}

func TestProxyChainDisabledAndBrokenRefsDropped(t *testing.T) {
	profile := strings.Replace(proxyChainProfile, "{name: Proxy, type: select, proxies: [Entry, HK]}", "{name: Proxy, type: select, proxies: [Entry, HK, Off, Broken]}", 1)
	profile = strings.Replace(profile, "  - MATCH,Proxy\n", "  - DOMAIN,off.com,Off\n  - MATCH,Broken\n", 1)
	home, path := setupProxyChains(t, profile, []ProxyChain{
		{ID: "1", Name: "Off", Enabled: false, Members: []string{"A", "B"}},
		{ID: "2", Name: "Broken", Enabled: true, Members: []string{"A", "Gone"}},
	})
	raw, rt := buildParsed(t, home, path)
	if strings.Join(strList(groupNamed(raw, "Proxy")["proxies"]), ",") != "Entry,HK" {
		t.Fatalf("refs not dropped: %v", groupNamed(raw, "Proxy"))
	}
	rules := strings.Join(strList(raw["rules"]), "\n")
	if strings.Contains(rules, "off.com") || !strings.Contains(rules, "MATCH,DIRECT") {
		t.Fatalf("rules: %s\n%s", rules, rt)
	}
	if groupNamed(raw, "Off") != nil || groupNamed(raw, "Broken") != nil {
		t.Fatalf("disabled / broken chain built")
	}
	for n := range asMap(raw["proxy-providers"]) {
		if strings.HasPrefix(n, GeneratedProviderPrefix) {
			t.Fatalf("leftover provider %s", n)
		}
	}
}

func TestProxyChainLoopAndNameClash(t *testing.T) {
	// Entry already routes through the chain (the user put the chain into its entry group).
	profile := strings.Replace(proxyChainProfile, "{name: Entry, type: select, proxies: [A, B]}", "{name: Entry, type: select, proxies: [A, B, L]}", 1)
	home, path := setupProxyChains(t, profile, []ProxyChain{
		{ID: "1", Name: "L", Enabled: true, Members: []string{"Entry", "C"}},
		{ID: "2", Name: "HK", Enabled: true, Members: []string{"A", "B"}}, // clashes with a group
	})
	raw, _ := buildParsed(t, home, path)
	if groupNamed(raw, "L") != nil {
		t.Fatalf("looping chain built")
	}
	if strings.Join(strList(groupNamed(raw, "Entry")["proxies"]), ",") != "A,B" {
		t.Fatalf("loop ref not dropped: %v", groupNamed(raw, "Entry"))
	}
	if str(groupNamed(raw, "HK")["type"]) != "url-test" {
		t.Fatalf("clashing chain replaced the group")
	}
	w := applyProxyChains(map[string]any{"proxies": []any{map[string]any{"name": "A"}}}, []ProxyChain{{Name: "A", Enabled: true, Members: []string{"A", "A"}}}, true)
	if len(w) != 1 || !strings.Contains(w[0], "同名") {
		t.Fatalf("warns %v", w)
	}
}

func TestProxyChainUsedByGroupAndChainNotNested(t *testing.T) {
	profile := strings.Replace(proxyChainProfile, "{name: Proxy, type: select, proxies: [Entry, HK]}", "{name: Proxy, type: select, proxies: [Entry, HK, Z]}", 1)
	home, path := setupProxyChains(t, profile, []ProxyChain{
		{ID: "1", Name: "Z", Enabled: true, Members: []string{"A", "B"}},
		{ID: "2", Name: "W", Enabled: true, Members: []string{"HK1", "Z"}}, // a chain cannot be a hop
	})
	raw, _ := buildParsed(t, home, path)
	if strings.Join(strList(groupNamed(raw, "Proxy")["proxies"]), ",") != "Entry,HK,Z" {
		t.Fatalf("group lost the chain: %v", groupNamed(raw, "Proxy"))
	}
	if groupNamed(raw, "W") != nil {
		t.Fatalf("nested chain built")
	}
}

func TestProxyChainSafeModeAndCandidates(t *testing.T) {
	home, path := setupProxyChains(t, proxyChainProfile, []ProxyChain{{ID: "1", Name: "Z", Enabled: true, Members: []string{"A", "B"}}})
	b, _ := os.ReadFile(path)
	o := overridesFor(home, path)
	o.SafeMode = true
	rt, err := buildRuntime(b, o, 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rt), GeneratedProviderPrefix) {
		t.Fatalf("安全模式 built a chain")
	}

	var c struct {
		Candidates []chainCandidate `json:"candidates"`
	}
	if err := json.Unmarshal([]byte(ProxyChainCandidates(home, path)), &c); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, x := range c.Candidates {
		names[x.Name] = true
	}
	if !names["Entry"] || !names["A"] || names["Z"] || names["GLOBAL"] || names[ProbeGroup] {
		t.Fatalf("candidates %v", names)
	}

	var gs struct {
		Chains []string `json:"chains"`
	}
	_ = json.Unmarshal([]byte(GroupSpecs(home, path)), &gs)
	if strings.Join(gs.Chains, ",") != "Z" {
		t.Fatalf("GroupSpecs chains %v", gs.Chains)
	}

	var ins struct {
		ProxyProviders []struct{ Name string } `json:"proxyProviders"`
		Groups         []struct{ Name string } `json:"groups"`
	}
	_ = json.Unmarshal([]byte(InspectProfile(home, path)), &ins)
	hasZ := false
	for _, g := range ins.Groups {
		hasZ = hasZ || g.Name == "Z"
	}
	if !hasZ {
		t.Fatalf("inspector misses the chain group")
	}
	for _, p := range ins.ProxyProviders {
		if strings.HasPrefix(p.Name, GeneratedProviderPrefix) {
			t.Fatalf("inspector lists %s", p.Name)
		}
	}
}

func TestProxyChainProbeGroupSkipsCopies(t *testing.T) {
	home, path := setupProxyChains(t, proxyChainProfile, []ProxyChain{{ID: "1", Name: "Z", Enabled: true, Members: []string{"A", "B"}}})
	raw, _ := buildParsed(t, home, path)
	pg := groupNamed(raw, ProbeGroup)
	if boolOf(pg["include-all"]) || !boolOf(pg["include-all-proxies"]) || strings.Join(strList(pg["use"]), ",") != "sub" {
		t.Fatalf("probe group %v", pg)
	}
}
