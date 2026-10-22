package libmihomo

import "testing"

func TestFaceTimePolicy(t *testing.T) {
	raw := map[string]any{
		"proxy-groups": []any{map[string]any{"name": "Auto", "type": "url-test"}, map[string]any{"name": "Proxy", "type": "select"}, map[string]any{"name": "Final", "type": "select"}},
		"rules":        []any{"DOMAIN,a.com,DIRECT", "MATCH,Final"},
	}
	if p := faceTimePolicy(raw); p != "Final" {
		t.Fatalf("got %q", p)
	}
	raw["rules"] = []any{"MATCH,DIRECT"}
	if p := faceTimePolicy(raw); p != "Proxy" {
		t.Fatalf("got %q", p)
	}
	applyFaceTimeRules(raw)
	rs := raw["rules"].([]any)
	if len(rs) != len(faceTimeMatchers)+1 || rs[0] != "DOMAIN-SUFFIX,push.apple.com,Proxy" {
		t.Fatalf("rules %v", rs)
	}
}
