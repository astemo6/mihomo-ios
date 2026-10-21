package libmihomo

// hotfix/sub-disabled-nodes (device, v0.19.14-build232): a 停用 节点集 (provider override) or 停用 node subscription
// must leave no node in the runtime: not in proxy-providers, not in any group's `use:`, and not through include-all,
// include-all-providers or filter groups. 启用 brings the nodes back.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	types "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/hub/executor"
)

// QX-import shaped: providers from [server_remote], a name-filter group over every provider, include-all groups
// with filters, an include-all-providers group.
const subDisabledProfile = `
proxies:
  - {name: local1, type: ss, server: 192.0.2.1, port: 8388, cipher: aes-128-gcm, password: x}
proxy-providers:
  SelfBuild: {type: file, path: ./proxies/selfbuild.yaml}
  eds: {type: file, path: ./proxies/eds.yaml}
  薯条: {type: file, path: ./proxies/fries.yaml}
proxy-groups:
  - {name: proxy, type: select, proxies: [local1], include-all-providers: true}
  - {name: 回国, type: select, proxies: [proxy], use: [eds, 薯条, SelfBuild], filter: "^(?:eds-1|fries-1)$"}
  - {name: 自动选择, type: url-test, include-all: true, filter: "^(?!.*CFT).*$", url: "http://captive.apple.com/generate_204", interval: 600}
  - {name: 香港, type: url-test, include-all: true, filter: "HK", url: "http://captive.apple.com/generate_204", interval: 600}
  - {name: 只有eds, type: select, use: [eds]}
rules:
  - MATCH,proxy
`

func writeSubDisabledHome(t *testing.T) (home, path string) {
	t.Helper()
	home = t.TempDir()
	path = filepath.Join(home, "p1.yaml")
	if err := os.WriteFile(path, []byte(subDisabledProfile), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Join(home, "proxies"), 0o755)
	_ = os.MkdirAll(filepath.Join(home, "nodesubs"), 0o755)
	write := func(rel, prefix string, n int) {
		var b strings.Builder
		b.WriteString("proxies:\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "  - {name: %s-%d HK, type: ss, server: 192.0.2.%d, port: 8388, cipher: aes-128-gcm, password: x}\n", prefix, i, i+10)
		}
		if err := os.WriteFile(filepath.Join(home, rel), []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("proxies/selfbuild.yaml", "self", 3)
	write("proxies/eds.yaml", "eds", 4)
	write("proxies/fries.yaml", "fries", 5)
	write("nodesubs/s1.yaml", "nsub", 2)
	return home, path
}

func writeSubDisabledNodeSubs(t *testing.T, home string, enabled bool) {
	t.Helper()
	b, _ := json.Marshal([]NodeSub{{ID: "s1", Name: "MySub", URL: "https://sub.example.invalid", Enabled: enabled}})
	if err := os.WriteFile(nodeSubsPath(home), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

type subDisabledView struct {
	providers map[string]bool
	members   map[string][]string // group → members as the core lists them
	uses      map[string][]string
}

func inspectSubDisabled(t *testing.T, home, path string) subDisabledView {
	t.Helper()
	var r inspectResult
	if err := json.Unmarshal([]byte(InspectProfile(home, path)), &r); err != nil {
		t.Fatal(err)
	}
	if r.Error != "" {
		t.Fatalf("inspect: %s", r.Error)
	}
	v := subDisabledView{providers: map[string]bool{}, members: map[string][]string{}, uses: map[string][]string{}}
	for _, p := range r.ProxyProviders {
		v.providers[p.Name] = true
	}
	for _, g := range r.Groups {
		v.members[g.Name] = g.Members
		v.uses[g.Name] = g.Use
	}
	// The runtime must also be a config the core accepts.
	o := overridesFor(home, path)
	rt, err := buildRuntime([]byte(subDisabledProfile), o, 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := executor.ParseWithBytes(rt)
	if err != nil {
		t.Fatalf("core rejects runtime: %v", err)
	}
	for name, pv := range cfg.Providers {
		if pv.VehicleType() == types.Compatible {
			continue // "default" and the per-group providers (MIHOMO-PROBE …)
		}
		if !v.providers[name] {
			t.Fatalf("core has provider %q the inspector does not list", name)
		}
	}
	return v
}

func anyMemberWithPrefix(v subDisabledView, prefix string) string {
	for g, ms := range v.members {
		for _, m := range ms {
			if strings.HasPrefix(m, prefix) {
				return g + ":" + m
			}
		}
	}
	return ""
}

func TestSubDisabledProviderLeavesNoNodes(t *testing.T) {
	home, path := writeSubDisabledHome(t)
	writeSubDisabledNodeSubs(t, home, true)

	v := inspectSubDisabled(t, home, path)
	if !v.providers["eds"] || anyMemberWithPrefix(v, "eds-") == "" {
		t.Fatalf("baseline: eds should be loaded: %+v", v.members)
	}

	// 停用 eds (provider override) and the node subscription.
	writeProviderOverrides(t, home, "p1", map[string]ProviderOverride{"eds": {Disabled: true}})
	writeSubDisabledNodeSubs(t, home, false)
	v = inspectSubDisabled(t, home, path)
	if v.providers["eds"] || v.providers["MySub"] {
		t.Fatalf("disabled provider still in runtime: %v", v.providers)
	}
	if m := anyMemberWithPrefix(v, "eds-"); m != "" {
		t.Fatalf("disabled 节点集 node still in a group: %s", m)
	}
	if m := anyMemberWithPrefix(v, "nsub-"); m != "" {
		t.Fatalf("disabled node subscription node still in a group: %s", m)
	}
	for g, use := range v.uses {
		for _, u := range use {
			if u == "eds" || u == "MySub" {
				t.Fatalf("group %s still uses %s", g, u)
			}
		}
	}
	// The group that only used eds stays valid (DIRECT), the others keep their remaining nodes.
	if ms := v.members["只有eds"]; len(ms) != 1 || ms[0] != "DIRECT" {
		t.Fatalf("只有eds: %v", ms)
	}
	if anyMemberWithPrefix(v, "fries-") == "" || anyMemberWithPrefix(v, "self-") == "" {
		t.Fatalf("other providers lost: %+v", v.members)
	}

	// 启用 again: everything is back.
	writeProviderOverrides(t, home, "p1", map[string]ProviderOverride{})
	writeSubDisabledNodeSubs(t, home, true)
	v = inspectSubDisabled(t, home, path)
	if !v.providers["eds"] || !v.providers["MySub"] || anyMemberWithPrefix(v, "eds-") == "" || anyMemberWithPrefix(v, "nsub-") == "" {
		t.Fatalf("re-enabled providers missing: %v %+v", v.providers, v.members)
	}
}
