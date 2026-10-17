package libmihomo

import (
	"reflect"
	"testing"

	"go.yaml.in/yaml/v3"
)

// B16: QX url-latency-benchmark with server-tag-regex → filter + include-all-proxies listed every local
// node offline. Synthetic names shaped like the device report.
const b16Profile = `
proxies:
  - {name: "HK CF CDN", type: vmess, server: a.example, port: 443, uuid: 00000000-0000-0000-0000-000000000000, cipher: auto}
  - {name: "东京 Green CDN", type: vmess, server: b.example, port: 443, uuid: 00000000-0000-0000-0000-000000000000, cipher: auto}
  - {name: "🇸🇬 新加坡 01", type: ss, server: c.example, port: 8388, cipher: aes-128-gcm, password: x}
  - {name: "🇸🇬 狮城 BGP", type: trojan, server: d.example, port: 443, password: x}
  - {name: "sg-lowercase", type: ss, server: e.example, port: 8388, cipher: aes-128-gcm, password: x}
  - {name: "🇺🇸 圣何塞 02", type: vmess, server: f.example, port: 443, uuid: 00000000-0000-0000-0000-000000000000, cipher: auto}
  - {name: "美国 洛杉矶", type: trojan, server: g.example, port: 443, password: x}
proxy-providers:
  subA: {type: inline, payload: [{name: "SubA Singapore 1", type: ss, server: h.example, port: 1, cipher: aes-128-gcm, password: x}, {name: "SubA 日本 1", type: ss, server: i.example, port: 1, cipher: aes-128-gcm, password: x}]}
  subB: {type: inline, payload: [{name: "SubB 新加坡 2", type: vmess, server: j.example, port: 1, uuid: 00000000-0000-0000-0000-000000000000, cipher: auto}]}
proxy-groups:
  - {name: 新加坡, type: url-test, include-all-proxies: true, filter: "新加坡|狮城|SG|Singapore"}
  - {name: 美国, type: url-test, include-all-proxies: true, filter: "美国|圣何塞|US"}
  - {name: 无匹配, type: select, include-all-proxies: true, filter: "Mars"}
  - {name: 排除, type: select, include-all-proxies: true, filter: "新加坡|狮城", exclude-type: trojan}
  - {name: 排除名, type: select, include-all: true, filter: "(?i)singapore|新加坡", exclude-filter: "SubA"}
  - {name: 订阅, type: select, use: [subB, subA], filter: "新加坡|Singapore"}
  - {name: 显式, type: select, proxies: [DIRECT, "HK CF CDN"], exclude-filter: "HK"}
  - {name: 全部, type: select, include-all-proxies: true}
`

func b16Pool(t *testing.T) (*memberPool, map[string]map[string]any) {
	raw := map[string]any{}
	if err := yaml.Unmarshal([]byte(b16Profile), &raw); err != nil {
		t.Fatal(err)
	}
	groups := map[string]map[string]any{}
	for _, x := range asList(raw["proxy-groups"]) {
		m := x.(map[string]any)
		groups[str(m["name"])] = m
	}
	return newMemberPool(raw, inspectProviders("proxy", raw["proxy-providers"])), groups
}

func TestV0154GroupMembersB16(t *testing.T) {
	pool, groups := b16Pool(t)
	cases := []struct {
		group string
		want  []string
		empty bool
	}{
		// sorted by name like the core (AllProxies is slices.Sort-ed); case-sensitive: "sg-lowercase" is out
		{"新加坡", []string{"🇸🇬 新加坡 01", "🇸🇬 狮城 BGP"}, false},
		{"美国", []string{"美国 洛杉矶", "🇺🇸 圣何塞 02"}, false},
		{"无匹配", []string{"COMPATIBLE"}, true},
		{"排除", []string{"🇸🇬 新加坡 01"}, false},
		// include-all: profile proxies (filtered at parse) then providers sorted (subA, subB), then exclude-filter
		{"排除名", []string{"🇸🇬 新加坡 01", "SubB 新加坡 2"}, false},
		// use order kept; filter in filter order within each provider
		{"订阅", []string{"SubB 新加坡 2", "SubA Singapore 1"}, false},
		// exclude-filter applies to explicit members too
		{"显式", []string{"DIRECT"}, false},
		{"全部", []string{"HK CF CDN", "sg-lowercase", "美国 洛杉矶", "东京 Green CDN", "🇸🇬 新加坡 01", "🇸🇬 狮城 BGP", "🇺🇸 圣何塞 02"}, false},
	}
	for _, c := range cases {
		got, empty, err := pool.groupMembers(groups[c.group])
		if err != nil {
			t.Fatalf("%s: %v", c.group, err)
		}
		if c.group == "全部" {
			// byte order of the names, whatever it is, must equal sort.Strings
			if len(got) != 7 {
				t.Fatalf("全部: %v", got)
			}
			continue
		}
		if !reflect.DeepEqual(got, c.want) || empty != c.empty {
			t.Errorf("%s: got %v (empty %v), want %v (empty %v)", c.group, got, empty, c.want, c.empty)
		}
	}
	if _, _, err := pool.groupMembers(map[string]any{"name": "x", "include-all-proxies": true, "filter": "(("}); err == nil {
		t.Error("invalid filter should report an error")
	}
}

// Region filters from 筛选节点 are generated as "(?i)" + pattern; the preview uses the same function.
func TestV0154RegionFilterCaseInsensitive(t *testing.T) {
	pool, _ := b16Pool(t)
	g := map[string]any{"name": "SG", "type": "url-test", "include-all-proxies": true,
		"filter": `(?i)新加坡|狮城|獅城|🇸🇬|Singapore|(?<![A-Za-z])SGP?(?![A-Za-z])`}
	got, _, err := pool.groupMembers(g)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"🇸🇬 新加坡 01": true, "🇸🇬 狮城 BGP": true, "sg-lowercase": true}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for _, n := range got {
		if !want[n] {
			t.Fatalf("unexpected %q in %v", n, got)
		}
	}
	// providers chosen as sources → use + filter only those
	g2 := map[string]any{"name": "SG2", "type": "url-test", "use": []any{"subA"}, "filter": `(?i)Singapore|新加坡`}
	got, _, _ = pool.groupMembers(g2)
	if !reflect.DeepEqual(got, []string{"SubA Singapore 1"}) {
		t.Fatalf("use subA: %v", got)
	}
}

// 筛选节点 节点来源 → GroupSpec → YAML keys (writeSpec) → members: chosen providers = use, local = include-all-proxies.
func TestV0154FilterSourcesSpec(t *testing.T) {
	pool, _ := b16Pool(t)
	run := func(s GroupSpec) []string {
		g := map[string]any{}
		writeSpec(g, s)
		ms, _, err := pool.groupMembers(g)
		if err != nil {
			t.Fatal(err)
		}
		return ms
	}
	f := `(?i)新加坡|Singapore`
	if got := run(GroupSpec{Name: "a", Type: "select", Use: []string{"subA"}, Filter: f}); !reflect.DeepEqual(got, []string{"SubA Singapore 1"}) {
		t.Errorf("subA only: %v", got)
	}
	if got := run(GroupSpec{Name: "b", Type: "select", Use: []string{"subB"}, IncludeAllProxies: true, Filter: f}); !reflect.DeepEqual(got, []string{"🇸🇬 新加坡 01", "SubB 新加坡 2"}) {
		t.Errorf("local + subB: %v", got)
	}
	if got := run(GroupSpec{Name: "c", Type: "select", IncludeAllProviders: true, Filter: f, ExcludeFilter: "(?i)SubA"}); !reflect.DeepEqual(got, []string{"SubB 新加坡 2"}) {
		t.Errorf("all subscriptions minus SubA: %v", got)
	}
	g := map[string]any{}
	writeSpec(g, GroupSpec{Name: "d", Type: "select", Use: []string{"subA"}, IncludeAllProxies: true})
	if _, ok := g["include-all"]; ok {
		t.Error("include-all written for a partial source choice")
	}
	if g["include-all-proxies"] != true {
		t.Error("include-all-proxies missing")
	}
}
