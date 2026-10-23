package libmihomo

import (
	"reflect"
	"testing"
)

func TestApplyRuleProviderOverrides(t *testing.T) {
	raw := map[string]any{
		"rule-providers": map[string]any{
			"cn":     map[string]any{"type": "http", "url": "https://a.example/cn.yaml", "path": "./ruleset/cn.yaml"},
			"ads":    map[string]any{"type": "http", "url": "https://a.example/ads.yaml"},
			"wechat": map[string]any{"type": "http", "url": "https://a.example/wechat.yaml"},
		},
		"rules": []any{
			"RULE-SET,ads,REJECT",
			"AND,((RULE-SET,ads),(NETWORK,UDP)),REJECT",
			"RULE-SET,cn,DIRECT,no-resolve",
			"RULE-SET,wechat,DIRECT",
			"DOMAIN-SUFFIX,example.com,Proxy",
			"MATCH,Proxy",
		},
	}
	ov := map[string]ProviderOverride{
		"rule:ads":    {Disabled: true},
		"rule:cn":     {Policy: "Proxy", URL: "https://b.example/cn.yaml"},
		"rule:wechat": {Deleted: true},
		"Demo":        {Disabled: true}, // a 节点集 override: ignored here
	}
	removed, warns := applyRuleProviderOverrides(raw, ov)
	if len(warns) != 0 {
		t.Fatalf("warns %v", warns)
	}
	if !reflect.DeepEqual(removed, []string{"ads", "wechat"}) {
		t.Fatalf("removed %v", removed)
	}
	want := []any{"RULE-SET,cn,Proxy,no-resolve", "DOMAIN-SUFFIX,example.com,Proxy", "MATCH,Proxy"}
	if !reflect.DeepEqual(raw["rules"], want) {
		t.Fatalf("rules %v", raw["rules"])
	}
	rp := raw["rule-providers"].(map[string]any)
	if len(rp) != 1 {
		t.Fatalf("providers %v", rp)
	}
	cn := rp["cn"].(map[string]any)
	if cn["url"] != "https://b.example/cn.yaml" || cn["path"] == "./ruleset/cn.yaml" {
		t.Fatalf("cn %v", cn)
	}
}

// 手动排序 (user 2026-10-23): only RULE-SET rules move, inside the slots they hold; other rules, logic rules and
// MATCH stay; a rule set the saved order does not know keeps its place; 停用 sets are gone before ordering.
func TestRuleSetOrder(t *testing.T) {
	raw := map[string]any{
		"rule-providers": map[string]any{
			"cn": map[string]any{"type": "http", "url": "https://a.example/cn.yaml"},
			"ai": map[string]any{"type": "http", "url": "https://a.example/ai.yaml"},
			"wa": map[string]any{"type": "http", "url": "https://a.example/wa.yaml"},
			"fb": map[string]any{"type": "http", "url": "https://a.example/fb.yaml"},
			"nw": map[string]any{"type": "http", "url": "https://a.example/new.yaml"},
		},
		"rules": []any{
			"RULE-SET,cn,DIRECT",
			"DOMAIN-SUFFIX,example.com,Proxy",
			"RULE-SET,ai,US",
			"AND,((RULE-SET,wa),(NETWORK,UDP)),REJECT",
			"RULE-SET,nw,Proxy",
			"RULE-SET, wa ,Proxy",
			"RULE-SET,fb,Proxy",
			"MATCH,Proxy",
		},
	}
	ov := map[string]ProviderOverride{
		ruleOrderKey: {Order: []string{"wa", "ai", "fb", "cn"}},
		"rule:fb":    {Disabled: true},
	}
	removed, _ := applyRuleProviderOverrides(raw, ov)
	if !reflect.DeepEqual(removed, []string{"fb"}) {
		t.Fatalf("removed %v", removed)
	}
	want := []any{
		"RULE-SET, wa ,Proxy",
		"DOMAIN-SUFFIX,example.com,Proxy",
		"RULE-SET,ai,US",
		"AND,((RULE-SET,wa),(NETWORK,UDP)),REJECT",
		"RULE-SET,nw,Proxy",
		"RULE-SET,cn,DIRECT",
		"MATCH,Proxy",
	}
	if !reflect.DeepEqual(raw["rules"], want) {
		t.Fatalf("rules\n got %v\nwant %v", raw["rules"], want)
	}

	// Only the order entry (no other override): still applied; the order key is not a provider.
	raw2 := map[string]any{
		"rule-providers": map[string]any{"a": map[string]any{"type": "http"}, "b": map[string]any{"type": "http"}},
		"rules":          []any{"RULE-SET,a,DIRECT", "RULE-SET,b,Proxy", "MATCH,DIRECT"},
	}
	removed, warns := applyRuleProviderOverrides(raw2, map[string]ProviderOverride{ruleOrderKey: {Order: []string{"b", "a"}}})
	if len(removed) != 0 || len(warns) != 0 {
		t.Fatalf("removed %v warns %v", removed, warns)
	}
	if !reflect.DeepEqual(raw2["rules"], []any{"RULE-SET,b,Proxy", "RULE-SET,a,DIRECT", "MATCH,DIRECT"}) {
		t.Fatalf("rules %v", raw2["rules"])
	}
	if len(raw2["rule-providers"].(map[string]any)) != 2 {
		t.Fatalf("providers touched")
	}
	// The 节点集 overrides ignore the order entry.
	raw3 := map[string]any{"proxy-providers": map[string]any{"p": map[string]any{"type": "http"}}}
	if rm, _ := applyProviderOverrides(raw3, map[string]ProviderOverride{ruleOrderKey: {Order: []string{"p"}}}); len(rm) != 0 {
		t.Fatalf("proxy providers removed %v", rm)
	}
}
