package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const subsSplitProfile = `
proxies:
  - {name: n1, type: ss, server: 192.0.2.1, port: 8388, cipher: aes-128-gcm, password: x}
proxy-providers:
  A:
    type: http
    url: https://example.com/a
    interval: 3600
    path: ./proxies/a.yaml
  B:
    type: http
    url: http://127.0.0.1:9999/nodes/convert?kind=nodes&url=https%3A%2F%2Fexample.com%2Fb
    path: ./proxies/b.yaml
  C:
    type: file
    path: ./proxies/c.yaml
proxy-groups:
  - {name: OnlyA, type: select, use: [A]}
  - {name: Mixed, type: select, proxies: [n1], use: [A, B]}
  - {name: Providers, type: url-test, include-all-providers: true}
rules:
  - MATCH,Mixed
`

func writeProviderOverrides(t *testing.T, home, id string, ov map[string]ProviderOverride) {
	t.Helper()
	b, _ := json.Marshal(map[string]map[string]ProviderOverride{id: ov})
	if err := os.WriteFile(providerOverridesPath(home), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func groupByName(raw map[string]any, name string) map[string]any {
	for _, gv := range asList(raw["proxy-groups"]) {
		if g, ok := gv.(map[string]any); ok && str(g["name"]) == name {
			return g
		}
	}
	return nil
}

func TestSubsSplitProviderDisableDelete(t *testing.T) {
	raw := map[string]any{}
	if err := yaml.Unmarshal([]byte(subsSplitProfile), &raw); err != nil {
		t.Fatal(err)
	}
	removed, warns := applyProviderOverrides(raw, map[string]ProviderOverride{"A": {Disabled: true}, "B": {Deleted: true}, "Z": {Disabled: true}})
	if len(warns) != 0 || strings.Join(removed, ",") != "A,B" {
		t.Fatalf("removed %v warns %v", removed, warns)
	}
	pp := asMap(raw["proxy-providers"])
	if _, ok := pp["A"]; ok {
		t.Fatal("A still present")
	}
	if _, ok := pp["C"]; !ok {
		t.Fatal("C must stay")
	}
	if g := groupByName(raw, "OnlyA"); g["use"] != nil || strings.Join(strList(g["proxies"]), ",") != "DIRECT" {
		t.Fatalf("OnlyA should fall back to DIRECT: %v", g)
	}
	if g := groupByName(raw, "Mixed"); g["use"] != nil || strings.Join(strList(g["proxies"]), ",") != "n1" {
		t.Fatalf("Mixed keeps n1 only: %v", g)
	}
	if g := groupByName(raw, "Providers"); len(asList(g["proxies"])) != 0 {
		t.Fatalf("include-all-providers group keeps C, no DIRECT: %v", g)
	}
	// Every provider gone: the include-all-providers group gets DIRECT.
	removed, _ = applyProviderOverrides(raw, map[string]ProviderOverride{"C": {Disabled: true}})
	if len(removed) != 1 || strings.Join(strList(groupByName(raw, "Providers")["proxies"]), ",") != "DIRECT" {
		t.Fatalf("empty include-all-providers group: %v", groupByName(raw, "Providers"))
	}
}

func TestSubsSplitProviderEdit(t *testing.T) {
	raw := map[string]any{}
	_ = yaml.Unmarshal([]byte(subsSplitProfile), &raw)
	_, warns := applyProviderOverrides(raw, map[string]ProviderOverride{
		"A": {URL: "https://example.org/new", Interval: 600, Filter: "(?i)hk|jp", ExcludeFilter: "expire", Name: "Shown", Icon: "🚀"},
		"B": {URL: "https://example.org/b2"},
		"C": {URL: "https://ignored.example", Filter: "(["},
	})
	pp := asMap(raw["proxy-providers"])
	a := asMap(pp["A"])
	if str(a["url"]) != "https://example.org/new" || intOf(a["interval"]) != 600 || str(a["filter"]) != "(?i)hk|jp" || str(a["exclude-filter"]) != "expire" {
		t.Fatalf("A edit: %v", a)
	}
	if _, ok := pp["Shown"]; ok {
		t.Fatal("display name must not rename the runtime provider")
	}
	b := asMap(pp["B"])
	if !strings.Contains(str(b["url"]), "127.0.0.1:9999/nodes/convert") || providerSourceURL(b) != "https://example.org/b2" {
		t.Fatalf("converter url keeps the converter, swaps the source: %v", b["url"])
	}
	c := asMap(pp["C"])
	if _, ok := c["url"]; ok {
		t.Fatal("file provider gets no url")
	}
	if _, ok := c["filter"]; ok || len(warns) != 1 {
		t.Fatalf("invalid filter ignored with one warning: %v %v", c, warns)
	}
}

func TestSubsSplitBuildRuntimeAndList(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "p1.yaml")
	if err := os.WriteFile(path, []byte(subsSplitProfile), 0o644); err != nil {
		t.Fatal(err)
	}
	writeProviderOverrides(t, home, "p1", map[string]ProviderOverride{"A": {Disabled: true}, "B": {Deleted: true}})
	o := overridesFor(home, path)
	o.home = home
	rt, err := buildRuntime([]byte(subsSplitProfile), o, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw := map[string]any{}
	_ = yaml.Unmarshal(rt, &raw)
	pp := asMap(raw["proxy-providers"])
	if _, ok := pp["A"]; ok {
		t.Fatal("disabled provider in runtime")
	}
	if _, ok := pp["B"]; ok {
		t.Fatal("deleted provider in runtime")
	}
	// Another profile id is not affected.
	o2 := overridesFor(home, filepath.Join(home, "p2.yaml"))
	o2.home = home
	rt2, _ := buildRuntime([]byte(subsSplitProfile), o2, 0)
	raw2 := map[string]any{}
	_ = yaml.Unmarshal(rt2, &raw2)
	if _, ok := asMap(raw2["proxy-providers"])["A"]; !ok {
		t.Fatal("overrides are per profile")
	}
	// ProfileProviders lists every provider of the file, overrides or not.
	var list []providerInfo
	if err := json.Unmarshal([]byte(ProfileProviders(home, path)), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 || list[0].Name != "A" || list[0].URL != "https://example.com/a" || list[0].Interval != 3600 || list[1].URL != "https://example.com/b" || list[2].Vehicle != "file" {
		t.Fatalf("list: %+v", list)
	}
	// The group editor no longer offers a deleted provider.
	var gs struct{ Providers []string }
	_ = json.Unmarshal([]byte(GroupSpecs(home, path)), &gs)
	for _, p := range gs.Providers {
		if p == "B" {
			t.Fatal("deleted provider offered in GroupSpecs")
		}
	}
}
