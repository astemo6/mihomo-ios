package mitm

import (
	"strings"
	"testing"
)

// v0.14.1 hotfix: the injected __MITM__ outbound must never become a group member.
func TestInjectKeepsMitMOutOfGroups(t *testing.T) {
	raw := map[string]any{
		"proxies": []any{map[string]any{"name": "HK 01", "type": "ss"}},
		"proxy-groups": []any{
			map[string]any{"name": "自动选择", "type": "url-test", "include-all": true, "filter": "^(?!.*CFT)(?!.*AZ).*?$"},
			map[string]any{"name": "节点选择", "type": "select", "include-all-proxies": true},
			map[string]any{"name": "proxy", "type": "select", "proxies": []any{"HK 01"}, "include-all-providers": true},
			map[string]any{"name": "手动", "type": "select", "proxies": []any{"__MITM__", "HK 01"}},
			map[string]any{"name": "只有内部", "type": "select", "proxies": []any{"__MITM__"}},
			map[string]any{"name": "过滤", "type": "select", "use": []any{"sub"}, "filter": "HK", "exclude-filter": "测试`过期"},
		},
		"rules": []any{"MATCH,节点选择"},
	}
	rs := &Ruleset{Hostnames: []string{"example.com"}}
	Inject(raw, 12345, rs, &Config{Enabled: true, MitM: true})
	groups := raw["proxy-groups"].([]any)
	get := func(i int) map[string]any { return groups[i].(map[string]any) }
	if get(0)["exclude-filter"] != "^__MITM__$" || get(1)["exclude-filter"] != "^__MITM__$" {
		t.Fatalf("include-all groups: %v / %v", get(0)["exclude-filter"], get(1)["exclude-filter"])
	}
	if _, ok := get(2)["exclude-filter"]; ok {
		t.Errorf("explicit-list group without include-all/filter should not get an exclude-filter")
	}
	if l := get(3)["proxies"].([]any); len(l) != 1 || l[0] != "HK 01" {
		t.Errorf("explicit member not removed: %v", l)
	}
	if l := get(4)["proxies"].([]any); len(l) != 1 || l[0] != "DIRECT" {
		t.Errorf("emptied group should fall back to DIRECT: %v", l)
	}
	if get(5)["exclude-filter"] != "测试`过期`^__MITM__$" {
		t.Errorf("existing exclude-filter not combined: %v", get(5)["exclude-filter"])
	}
	// idempotent
	ExcludeFromGroups(raw)
	if get(5)["exclude-filter"] != "测试`过期`^__MITM__$" || get(0)["exclude-filter"] != "^__MITM__$" {
		t.Errorf("not idempotent: %v %v", get(5)["exclude-filter"], get(0)["exclude-filter"])
	}
	found := false
	for _, p := range raw["proxies"].([]any) {
		if p.(map[string]any)["name"] == ProxyName {
			found = true
		}
	}
	if !found {
		t.Fatal("outbound not injected")
	}
	if !strings.Contains(raw["rules"].([]any)[1].(string), ProxyName) {
		t.Errorf("steering rule missing: %v", raw["rules"])
	}
}

// Without MitM / rewrites nothing is injected and groups stay untouched.
func TestInjectOffLeavesGroups(t *testing.T) {
	raw := map[string]any{"proxy-groups": []any{map[string]any{"name": "a", "type": "url-test", "include-all": true}}}
	Inject(raw, 1, &Ruleset{}, &Config{})
	if _, ok := raw["proxy-groups"].([]any)[0].(map[string]any)["exclude-filter"]; ok {
		t.Fatal("exclude-filter added although nothing was injected")
	}
}
