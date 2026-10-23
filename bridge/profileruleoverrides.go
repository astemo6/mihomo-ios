package libmihomo

// 规则 → 本地规则 → 配置规则 and 规则 → Final (user 2026-10-23 「本地规则点进去无法修改」「Final 指向无法修改」): the
// user's 编辑 / 停用 / 删除 of the profile's own rules and the policy of its MATCH rule. Kept in the same per-profile
// provider-overrides.json as the 节点集 / 规则集 overrides (so backups, snapshots and the runtime cache key already
// cover it), under two reserved keys that can never be a provider name:
//
//   "#profile-rules"  {"rules": [{"rule": <original rule text>, "index": <occurrence>, "line"?, "disabled"?, "deleted"?}]}
//   "#final"          {"policy": <policy of the profile's MATCH rule>}
//
// A profile rule is keyed by its text (spaces around top-level commas removed) and by which occurrence of that
// text it is (0 = the first), so a profile update keeps the override as long as the rule is still there, a rule
// the update removed simply drops its override, and two identical lines are told apart. The profile file is never
// rewritten. Overrides are applied first in buildRuntimeWith, on the profile's own rules, so the order (matching
// priority) stays the profile's: an edited rule keeps its place, a 停用 / 删除 rule leaves its place empty.
//
// An edited line goes through the same converter as 自定义规则 (Surge / QX / Loon spellings become mihomo rules).
// A line that does not convert keeps the profile's rule (warning in the log). After group edits, node
// subscriptions and chains are applied, checkEditedRuleTargets puts the profile's rule back for an edited rule
// (or the Final) whose policy is not in the runtime, so a stale edit can never make the whole config fail to load.

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
	"go.yaml.in/yaml/v3"
)

const (
	profileRulesKey = "#profile-rules"
	finalRuleKey    = "#final"
)

// ProfileRuleOverride is one entry of the "#profile-rules" override.
type ProfileRuleOverride struct {
	Rule     string `json:"rule"`
	Index    int    `json:"index"`
	Line     string `json:"line,omitempty"`
	Disabled bool   `json:"disabled,omitempty"`
	Deleted  bool   `json:"deleted,omitempty"`
}

// profileRuleKey normalizes a rule for matching: trimmed, no spaces around the top-level commas.
func profileRuleKey(rule string) string {
	return strings.Join(splitRuleTop(strings.TrimSpace(rule)), ",")
}

func splitRuleTop(s string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	return append(out, strings.TrimSpace(s[start:]))
}

func isMatchRule(rule string) bool {
	t := strings.ToUpper(strings.TrimSpace(strings.SplitN(rule, ",", 2)[0]))
	return t == "MATCH" || t == "FINAL"
}

type ruleOverrideRef struct {
	rule  string
	index int
}

func profileRuleOverrides(ov map[string]ProviderOverride) map[ruleOverrideRef]ProfileRuleOverride {
	list := ov[profileRulesKey].Rules
	if len(list) == 0 {
		return nil
	}
	m := make(map[ruleOverrideRef]ProfileRuleOverride, len(list))
	for _, r := range list {
		k := profileRuleKey(r.Rule)
		if k == "" || r.Index < 0 {
			continue
		}
		m[ruleOverrideRef{k, r.Index}] = r
	}
	return m
}

// convertEditedRule turns the line the user typed into a mihomo rule for raw (nil error = use it).
func convertEditedRule(raw map[string]any, line string) (string, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", fmt.Errorf("规则为空")
	}
	t := strings.ToUpper(strings.TrimSpace(strings.SplitN(line, ",", 2)[0]))
	if t == "SUB-RULE" {
		// mihomo only: kept as written (its target is a sub-rule name, checked after the build).
		return strings.Join(splitRuleTop(line), ","), nil
	}
	conv, err := mitm.ConvertRuleLine(line)
	if err != nil {
		return "", err
	}
	if conv.Rule == "" {
		if conv.Unsupported != "" {
			return "", fmt.Errorf("%s", conv.Unsupported)
		}
		return "", fmt.Errorf("不是有效的规则")
	}
	if conv.RemoteURL != "" {
		return "", fmt.Errorf("远程规则列表请在「订阅」里添加")
	}
	groups, proxies, first := mitm.ProfileNames(raw)
	pol, ok := mitm.ResolvePolicy(conv.Policy, groups, proxies, first)
	if !ok {
		pol = strings.TrimSpace(conv.Policy) // checked against the finished runtime (checkEditedRuleTargets)
	}
	if pol == "" {
		return "", fmt.Errorf("缺少策略")
	}
	return conv.Format(pol), nil
}

// profileRulePlan is what the overrides make of one rule of the profile.
type profileRulePlan struct {
	original string
	key      string
	index    int
	ov       *ProfileRuleOverride
	out      string // the rule in the runtime ("" = left out)
	err      string // the edit could not be applied (out is the original)
}

func planProfileRules(raw map[string]any, rules []any, ov map[string]ProviderOverride) (plans []profileRulePlan, matched int) {
	byRef := profileRuleOverrides(ov)
	seen := map[string]int{}
	for _, rv := range rules {
		r, ok := rv.(string)
		if !ok {
			plans = append(plans, profileRulePlan{index: -1})
			continue
		}
		k := profileRuleKey(r)
		n := seen[k]
		seen[k] = n + 1
		p := profileRulePlan{original: r, key: k, index: n, out: r}
		if o, ok := byRef[ruleOverrideRef{k, n}]; ok {
			o := o
			p.ov = &o
			matched++
			switch {
			case o.Deleted || o.Disabled:
				p.out = ""
			case strings.TrimSpace(o.Line) != "" && profileRuleKey(o.Line) != k:
				if conv, err := convertEditedRule(raw, o.Line); err != nil {
					p.err = err.Error()
				} else {
					p.out = conv
				}
			}
		}
		plans = append(plans, p)
	}
	return plans, matched
}

// applyProfileRuleOverrides applies "#profile-rules" and "#final" to the profile's own rules (raw["rules"]).
// edited maps each rule the overrides produced to the profile's rule it replaced ("" = an added MATCH), for
// checkEditedRuleTargets.
func applyProfileRuleOverrides(raw map[string]any, ov map[string]ProviderOverride) (edited map[string]string, warns []string) {
	if len(ov) == 0 {
		return nil, nil
	}
	final := strings.TrimSpace(ov[finalRuleKey].Policy)
	if len(ov[profileRulesKey].Rules) == 0 && final == "" {
		return nil, nil
	}
	rules := asList(raw["rules"])
	edited = map[string]string{}
	var out []any
	if len(ov[profileRulesKey].Rules) > 0 {
		plans, _ := planProfileRules(raw, rules, ov)
		out = make([]any, 0, len(rules))
		for i, p := range plans {
			if p.index < 0 {
				out = append(out, rules[i])
				continue
			}
			if p.err != "" {
				warns = append(warns, fmt.Sprintf("规则「%s」的修改无法使用（%s），已使用配置里的规则", p.original, p.err))
			}
			if p.out == "" {
				continue
			}
			if p.out != p.original {
				edited[p.out] = p.original
			}
			out = append(out, p.out)
		}
	} else {
		out = append([]any(nil), rules...)
	}
	if final != "" {
		groups, proxies, first := mitm.ProfileNames(raw)
		if pol, ok := mitm.ResolvePolicy(final, groups, proxies, first); ok {
			final = pol
		}
		nr := "MATCH," + final
		last := -1
		for i := len(out) - 1; i >= 0; i-- {
			if s, ok := out[i].(string); ok && isMatchRule(s) {
				last = i
				break
			}
		}
		if last >= 0 {
			if old, _ := out[last].(string); profileRuleKey(old) != nr {
				if orig, ok := edited[old]; ok {
					old = orig
					delete(edited, out[last].(string))
				}
				edited[nr] = old
				out[last] = nr
			}
		} else {
			edited[nr] = ""
			out = append(out, nr)
		}
	}
	raw["rules"] = out
	return edited, warns
}

// ruleTargetOf is the policy (or sub-rule) a rule sends traffic to.
func ruleTargetOf(rule string) string {
	t := strings.ToUpper(strings.TrimSpace(strings.SplitN(rule, ",", 2)[0]))
	parts := splitRuleTop(rule)
	switch t {
	case "MATCH", "FINAL":
		if len(parts) > 1 {
			return parts[1]
		}
		return ""
	case "AND", "OR", "NOT", "SUB-RULE":
		if len(parts) > 2 {
			return parts[2]
		}
		return ""
	}
	return splitRule(rule).Proxy
}

// checkEditedRuleTargets puts the profile's rule back for an edited rule whose policy the finished runtime does
// not have (a group removed since, a node renamed by the subscription, …).
func checkEditedRuleTargets(raw map[string]any, edited map[string]string) (warns []string) {
	if len(edited) == 0 {
		return nil
	}
	targets := map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "COMPATIBLE": true}
	groups, proxies, _ := mitm.ProfileNames(raw)
	for _, n := range groups {
		targets[n] = true
	}
	for _, n := range proxies {
		targets[n] = true
	}
	for _, p := range proxiesOf(raw) {
		targets[str(p["name"])] = true
	}
	subRules := asMap(raw["sub-rules"])
	rules := asList(raw["rules"])
	out := make([]any, 0, len(rules))
	changed := false
	for _, rv := range rules {
		r, ok := rv.(string)
		orig, isEdit := edited[r]
		if !ok || !isEdit {
			out = append(out, rv)
			continue
		}
		tg := ruleTargetOf(r)
		okTarget := targets[tg]
		if strings.EqualFold(strings.TrimSpace(strings.SplitN(r, ",", 2)[0]), "SUB-RULE") {
			_, okTarget = subRules[tg]
		}
		if okTarget {
			out = append(out, rv)
			continue
		}
		changed = true
		warns = append(warns, fmt.Sprintf("规则「%s」的策略「%s」不存在，已使用配置里的规则", r, tg))
		if orig != "" {
			out = append(out, orig)
		}
	}
	if changed {
		raw["rules"] = out
	}
	return warns
}

// ---------------- app API ----------------

type profileRuleItem struct {
	Position int    `json:"position"` // 0-based place in the profile's rules
	Rule     string `json:"rule"`     // override key: the rule's text
	Index    int    `json:"index"`    // override key: which occurrence of that text
	Original string `json:"original"` // the rule as the profile writes it
	Line     string `json:"line"`     // the line to edit: the user's edit, else the original
	Edited   bool   `json:"edited,omitempty"`
	Disabled bool   `json:"disabled,omitempty"`
	Deleted  bool   `json:"deleted,omitempty"`
	Error    string `json:"error,omitempty"`
	Type     string `json:"type"`
	Payload  string `json:"payload"`
	Proxy    string `json:"proxy"`
	Options  string `json:"options,omitempty"`
}

type profileFinalInfo struct {
	Policy   string `json:"policy"`   // in effect (override, else the profile's)
	Original string `json:"original"` // the profile's MATCH policy ("" = none)
	Edited   bool   `json:"edited,omitempty"`
}

type profileRulesResult struct {
	Rules []profileRuleItem `json:"rules"`
	Final profileFinalInfo  `json:"finalInfo"`
	// Stale counts saved overrides whose rule the profile no longer has (they do nothing; 全部恢复 clears them).
	Stale int    `json:"stale"`
	Error string `json:"error,omitempty"`
}

// profileOwnRaw is the profile as buildRuntimeWith starts from it (覆写脚本 output, share links converted).
func profileOwnRaw(homeDir, profilePath string) (map[string]any, error) {
	b, err := readRuntimeProfile(homeDir, profilePath, false)
	if err != nil {
		return nil, err
	}
	raw := map[string]any{}
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("YAML 解析失败: %w", err)
	}
	if raw == nil {
		raw = map[string]any{}
	}
	if _, ok := raw["proxies"]; !ok {
		if _, ok2 := raw["proxy-providers"]; !ok2 {
			if conv, err := convertLinks(b); err == nil {
				raw = map[string]any{}
				_ = yaml.Unmarshal(conv, &raw)
			}
		}
	}
	return raw, nil
}

// ProfileRules returns JSON (profileRulesResult): the profile's own rules in order with the user's overrides,
// and its Final, for 规则 → 本地规则 → 配置规则 and the Final row.
func ProfileRules(homeDir, profilePath string) string {
	res := profileRulesResult{Rules: []profileRuleItem{}}
	defer func() {
		if r := recover(); r != nil {
			res.Error = fmt.Sprint(r)
		}
	}()
	raw, err := profileOwnRaw(homeDir, profilePath)
	if err != nil {
		res.Error = err.Error()
		b, _ := json.Marshal(res)
		return string(b)
	}
	ov := readProviderOverrides(homeDir, profileIDFromPath(profilePath))
	rules := asList(raw["rules"])
	plans, matched := planProfileRules(raw, rules, ov)
	res.Stale = len(ov[profileRulesKey].Rules) - matched
	if res.Stale < 0 {
		res.Stale = 0
	}
	for i, p := range plans {
		if p.index < 0 {
			continue
		}
		if isMatchRule(p.original) {
			res.Final.Original = splitRule(p.original).Proxy
		}
		it := profileRuleItem{Position: i, Rule: p.key, Index: p.index, Original: p.original, Line: p.original, Error: p.err}
		shown := p.original
		if p.ov != nil {
			it.Disabled, it.Deleted = p.ov.Disabled, p.ov.Deleted
			if l := strings.TrimSpace(p.ov.Line); l != "" && profileRuleKey(l) != p.key {
				it.Line, it.Edited = l, true
				if p.err == "" {
					shown = p.out
				}
			}
		}
		sr := splitRule(shown)
		it.Type, it.Payload, it.Proxy, it.Options = sr.Type, sr.Payload, sr.Proxy, sr.Options
		res.Rules = append(res.Rules, it)
	}
	res.Final.Policy = res.Final.Original
	if f := strings.TrimSpace(ov[finalRuleKey].Policy); f != "" {
		res.Final.Policy, res.Final.Edited = f, f != res.Final.Original
	}
	b, _ := json.Marshal(res)
	return string(b)
}
