package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
	"go.yaml.in/yaml/v3"
)

// 规则 → 本地规则 / Final (user 2026-10-23 「本地规则点进去无法修改」「Final 指向无法修改」).
const profileRulesProfile = `
proxies:
  - {name: 圣何塞, type: ss, server: 192.0.2.1, port: 8388, cipher: aes-128-gcm, password: x}
  - {name: 东京, type: ss, server: 192.0.2.2, port: 8388, cipher: aes-128-gcm, password: x}
proxy-groups:
  - {name: 终极清单, type: select, proxies: [圣何塞, 东京, DIRECT]}
  - {name: Apple, type: select, proxies: [DIRECT, 圣何塞]}
rules:
  - AND,((NETWORK,UDP),(DST-PORT,443)),REJECT-DROP
  - DOMAIN-SUFFIX,hark.com,圣何塞
  - DOMAIN-SUFFIX, dup.example ,DIRECT
  - DOMAIN-SUFFIX,dup.example,DIRECT
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,终极清单
`

func runtimeRules(t *testing.T, home, path, profile string) []string {
	t.Helper()
	o := overridesFor(home, path)
	o.home = home
	rt, err := buildRuntime([]byte(profile), o, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw := map[string]any{}
	if err := yaml.Unmarshal(rt, &raw); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range strList(raw["rules"]) {
		// Rules the build always adds (QUIC block, probe, …) are not the profile's.
		if strings.Contains(r, "__") || r == UDPFallbackRule || r == mitmQUICAll {
			continue
		}
		out = append(out, r)
	}
	return out
}

var mitmQUICAll = mitm.QUICBlockAllRule

func indexOfRule(rules []string, r string) int {
	for i, x := range rules {
		if x == r {
			return i
		}
	}
	return -1
}

func TestProfileRuleOverridesApply(t *testing.T) {
	raw := map[string]any{}
	if err := yaml.Unmarshal([]byte(profileRulesProfile), &raw); err != nil {
		t.Fatal(err)
	}
	ov := map[string]ProviderOverride{
		profileRulesKey: {Rules: []ProfileRuleOverride{
			{Rule: "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT-DROP", Index: 0, Line: "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"},
			{Rule: "DOMAIN-SUFFIX,hark.com,圣何塞", Index: 0, Line: "host-suffix, hark.com, 东京"}, // QX spelling converts
			{Rule: "DOMAIN-SUFFIX,dup.example,DIRECT", Index: 1, Disabled: true},              // the 2nd occurrence only
			{Rule: "GEOIP,CN,DIRECT", Index: 0, Deleted: true},
			{Rule: "DOMAIN,gone.example,DIRECT", Index: 0, Disabled: true}, // no longer in the profile: ignored
		}},
		finalRuleKey: {Policy: "Apple"},
		"rule:x":     {Disabled: true}, // a rule-set override: not ours
	}
	edited, warns := applyProfileRuleOverrides(raw, ov)
	if len(warns) != 0 {
		t.Fatalf("warns %v", warns)
	}
	want := []any{
		"AND,((NETWORK,UDP),(DST-PORT,443)),REJECT",
		"DOMAIN-SUFFIX,hark.com,东京",
		"DOMAIN-SUFFIX, dup.example ,DIRECT",
		"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
		"MATCH,Apple",
	}
	if !reflect.DeepEqual(raw["rules"], want) {
		t.Fatalf("rules\n got %v\nwant %v", raw["rules"], want)
	}
	if edited["MATCH,Apple"] != "MATCH,终极清单" || edited["DOMAIN-SUFFIX,hark.com,东京"] != "DOMAIN-SUFFIX,hark.com,圣何塞" {
		t.Fatalf("edited %v", edited)
	}
	// A policy the finished runtime does not have puts the profile's rule back.
	raw["rules"] = []any{"DOMAIN-SUFFIX,hark.com,东京", "MATCH,Apple"}
	delete(raw, "proxy-groups")
	w := checkEditedRuleTargets(raw, edited)
	if len(w) != 1 || !reflect.DeepEqual(raw["rules"], []any{"DOMAIN-SUFFIX,hark.com,东京", "MATCH,终极清单"}) {
		t.Fatalf("check %v %v", w, raw["rules"])
	}
}

func TestProfileRuleOverridesBadEditKeepsOriginal(t *testing.T) {
	raw := map[string]any{}
	_ = yaml.Unmarshal([]byte(profileRulesProfile), &raw)
	ov := map[string]ProviderOverride{profileRulesKey: {Rules: []ProfileRuleOverride{
		{Rule: "DOMAIN-SUFFIX,hark.com,圣何塞", Index: 0, Line: "USER-AGENT,foo*,DIRECT"},
		{Rule: "GEOIP,CN,DIRECT", Index: 0, Line: "RULE-SET,https://example.com/x.list,DIRECT"},
	}}}
	_, warns := applyProfileRuleOverrides(raw, ov)
	if len(warns) != 2 {
		t.Fatalf("warns %v", warns)
	}
	rules := strList(raw["rules"])
	if indexOfRule(rules, "DOMAIN-SUFFIX,hark.com,圣何塞") != 1 || indexOfRule(rules, "GEOIP,CN,DIRECT") != 5 {
		t.Fatalf("originals kept in place: %v", rules)
	}
	// Final without a MATCH in the profile is appended.
	raw2 := map[string]any{"rules": []any{"DOMAIN,a.example,DIRECT"}}
	_, _ = applyProfileRuleOverrides(raw2, map[string]ProviderOverride{finalRuleKey: {Policy: "direct"}})
	if !reflect.DeepEqual(raw2["rules"], []any{"DOMAIN,a.example,DIRECT", "MATCH,DIRECT"}) {
		t.Fatalf("final appended %v", raw2["rules"])
	}
}

// End to end: the runtime build applies the overrides on the profile's rules (custom rules still go first), a
// profile update keeps them while the rule is still there, and ProfileRules lists the rows the app shows.
func TestProfileRuleOverridesBuildRuntimeAndList(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "p1.yaml")
	if err := os.WriteFile(path, []byte(profileRulesProfile), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(customRulesPath(home), []byte(`{"rules":[{"id":"c1","line":"DOMAIN,custom.example,DIRECT","enabled":true}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	writeProviderOverrides(t, home, "p1", map[string]ProviderOverride{
		profileRulesKey: {Rules: []ProfileRuleOverride{
			{Rule: "DOMAIN-SUFFIX,hark.com,圣何塞", Index: 0, Line: "DOMAIN-SUFFIX,hark.com,DIRECT"},
			{Rule: "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT-DROP", Index: 0, Disabled: true},
			{Rule: "GEOIP,CN,DIRECT", Index: 0, Deleted: true},
			{Rule: "DOMAIN,removed.example,DIRECT", Index: 0, Line: "DOMAIN,removed.example,Apple"},
		}},
		finalRuleKey: {Policy: "东京"},
	})
	rules := runtimeRules(t, home, path, profileRulesProfile)
	if indexOfRule(rules, "DOMAIN,custom.example,DIRECT") != 0 {
		t.Fatalf("custom rules first: %v", rules)
	}
	if indexOfRule(rules, "DOMAIN-SUFFIX,hark.com,DIRECT") != 1 || indexOfRule(rules, "DOMAIN-SUFFIX,hark.com,圣何塞") >= 0 {
		t.Fatalf("edited in place: %v", rules)
	}
	for _, r := range rules {
		if strings.HasPrefix(r, "AND,((NETWORK,UDP)") || strings.HasPrefix(r, "GEOIP,CN") {
			t.Fatalf("disabled / deleted rule in runtime: %v", rules)
		}
	}
	if rules[len(rules)-1] != "MATCH,东京" {
		t.Fatalf("final: %v", rules)
	}

	// Another profile is not affected.
	other := runtimeRules(t, home, filepath.Join(home, "p2.yaml"), profileRulesProfile)
	if indexOfRule(other, "DOMAIN-SUFFIX,hark.com,圣何塞") < 0 || other[len(other)-1] != "MATCH,终极清单" {
		t.Fatalf("overrides are per profile: %v", other)
	}

	// The subscription is updated: a rule is added before them, spacing changes, hark.com stays.
	updated := strings.Replace(profileRulesProfile, "  - DOMAIN-SUFFIX,hark.com,圣何塞", "  - DOMAIN,new.example,DIRECT\n  - DOMAIN-SUFFIX , hark.com , 圣何塞", 1)
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
	rules = runtimeRules(t, home, path, updated)
	if indexOfRule(rules, "DOMAIN-SUFFIX,hark.com,DIRECT") != indexOfRule(rules, "DOMAIN,new.example,DIRECT")+1 {
		t.Fatalf("override kept after the update, in the profile's order: %v", rules)
	}

	var res profileRulesResult
	if err := json.Unmarshal([]byte(ProfileRules(home, path)), &res); err != nil {
		t.Fatal(err)
	}
	if res.Error != "" || len(res.Rules) != 8 {
		t.Fatalf("list %+v", res)
	}
	byPos := map[int]profileRuleItem{}
	for _, r := range res.Rules {
		byPos[r.Position] = r
	}
	h := byPos[2]
	if h.Rule != "DOMAIN-SUFFIX,hark.com,圣何塞" || !h.Edited || h.Line != "DOMAIN-SUFFIX,hark.com,DIRECT" || h.Proxy != "DIRECT" || h.Type != "DOMAIN-SUFFIX" || h.Payload != "hark.com" {
		t.Fatalf("edited row %+v", h)
	}
	if a := byPos[0]; !a.Disabled || a.Type != "AND" || a.Proxy != "REJECT-DROP" {
		t.Fatalf("disabled row %+v", a)
	}
	if g := byPos[6]; !g.Deleted {
		t.Fatalf("deleted row %+v", g)
	}
	if d3, d4 := byPos[3], byPos[4]; d3.Rule != "DOMAIN-SUFFIX,dup.example,DIRECT" || d3.Index != 0 || d4.Index != 1 {
		t.Fatalf("occurrences %+v %+v", d3, d4)
	}
	if ip := byPos[5]; ip.Options != "no-resolve" || ip.Proxy != "DIRECT" {
		t.Fatalf("options %+v", ip)
	}
	if res.Final.Policy != "东京" || res.Final.Original != "终极清单" || !res.Final.Edited {
		t.Fatalf("final %+v", res.Final)
	}
	if res.Stale != 1 {
		t.Fatalf("stale %d", res.Stale)
	}

	// The inspector (offline 规则 page) sees the same runtime.
	var ins struct {
		Rules []inspectRule `json:"rules"`
	}
	_ = json.Unmarshal([]byte(InspectProfile(home, path)), &ins)
	insFinal := ""
	for _, r := range ins.Rules {
		if r.Type == "MATCH" {
			insFinal = r.Proxy
		}
	}
	if insFinal != "东京" {
		t.Fatalf("inspect final %+v", ins.Rules)
	}

	// 恢复配置原样: no override, the profile's rules again.
	writeProviderOverrides(t, home, "p1", map[string]ProviderOverride{})
	rules = runtimeRules(t, home, path, updated)
	if indexOfRule(rules, "DOMAIN-SUFFIX , hark.com , 圣何塞") < 0 && indexOfRule(rules, "DOMAIN-SUFFIX,hark.com,圣何塞") < 0 {
		t.Fatalf("restored: %v", rules)
	}
	if rules[len(rules)-1] != "MATCH,终极清单" {
		t.Fatalf("final restored: %v", rules)
	}
}

// A Final / edit pointing at a group that a later step removed must not make the config fail to load.
func TestProfileRuleOverridesMissingPolicyFallsBack(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "p1.yaml")
	_ = os.WriteFile(path, []byte(profileRulesProfile), 0o644)
	writeProviderOverrides(t, home, "p1", map[string]ProviderOverride{
		profileRulesKey: {Rules: []ProfileRuleOverride{{Rule: "GEOIP,CN,DIRECT", Index: 0, Line: "GEOIP,CN,NoSuchGroup"}}},
		finalRuleKey:    {Policy: "AlsoMissing"},
	})
	rules := runtimeRules(t, home, path, profileRulesProfile)
	if indexOfRule(rules, "GEOIP,CN,DIRECT") < 0 || rules[len(rules)-1] != "MATCH,终极清单" {
		t.Fatalf("fallback to the profile's rules: %v", rules)
	}
}
