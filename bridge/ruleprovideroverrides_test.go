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
