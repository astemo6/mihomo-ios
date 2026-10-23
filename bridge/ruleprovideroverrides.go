package libmihomo

// 规则 → 订阅 (user 2026-10-23 「对应的还要有删除，禁用，修改功能」): the user's 停用 / 删除 / 编辑 of the profile's own
// rule-providers. Kept in the same per-profile provider-overrides.json as the 节点集 overrides, under the key
// "rule:<provider name>", so backups, snapshots and the runtime cache key already cover it. The profile file is
// never rewritten.
//
//   disabled / deleted  the provider and every rule that uses it (RULE-SET,<name>,… and logic rules naming it)
//                       are left out of the runtime; deleted also hides the row in the app (恢复已删除的规则集).
//   url / interval      编辑 (http providers); a new link gets its own cache path.
//   policy              the policy of the profile's RULE-SET,<name>,<policy> rules.
//
// 手动排序 (user 2026-10-23 「这个规则要能手动调顺序」): the entry keyed ruleOrderKey carries `order`, the rule sets
// in the order the user dragged them into. applyRuleSetOrder moves only the RULE-SET,<name>,… rules among the
// positions they already hold: other rules (DOMAIN…, GEOIP…, logic rules, MATCH) stay where they are, and a rule
// set the saved order does not name (new in the profile) keeps its place. A profile update keeps the order.

import (
	"net/url"
	"sort"
	"strings"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
)

const ruleProviderOverridePrefix = "rule:"

// ruleOrderKey is the provider-overrides.json entry holding the rule-set order. It can never be a provider name
// the other loops act on: they look names up in the profile's providers, and "#" + "rule-order" is not one.
const ruleOrderKey = "#rule-order"

// applyRuleSetOrder reorders the simple RULE-SET rules of raw["rules"] by order (see the file comment).
func applyRuleSetOrder(raw map[string]any, order []string) {
	if len(order) < 2 {
		return
	}
	rules, ok := raw["rules"].([]any)
	if !ok || len(rules) < 2 {
		return
	}
	raw["rules"] = mitm.ReorderSlots(rules, func(v any) (string, bool) {
		r, ok := v.(string)
		if !ok {
			return "", false
		}
		return ruleSetNameOf(r)
	}, order)
}

func ruleSetNameOf(rule string) (name string, simple bool) {
	parts := strings.Split(rule, ",")
	if len(parts) >= 2 && strings.EqualFold(strings.TrimSpace(parts[0]), "RULE-SET") {
		return strings.TrimSpace(parts[1]), true
	}
	return "", false
}

// ruleMentionsSet reports whether a logic rule (AND / OR / NOT / SUB-RULE payloads) names the rule set.
func ruleMentionsSet(rule, name string) bool {
	r := strings.ReplaceAll(rule, " ", "")
	return strings.Contains(r, "(RULE-SET,"+name+")") || strings.Contains(r, "(RULE-SET,"+name+",")
}

// applyRuleProviderOverrides applies the "rule:" entries of ov to raw. Returns the rule sets left out and warnings.
func applyRuleProviderOverrides(raw map[string]any, ov map[string]ProviderOverride) (removed []string, warns []string) {
	rp, _ := raw["rule-providers"].(map[string]any)
	if len(ov) == 0 || len(rp) == 0 {
		return nil, nil
	}
	// The order last: rules of 停用 / 删除 rule sets are gone by then.
	defer applyRuleSetOrder(raw, ov[ruleOrderKey].Order)
	var names []string
	for k := range ov {
		if strings.HasPrefix(k, ruleProviderOverridePrefix) {
			names = append(names, strings.TrimPrefix(k, ruleProviderOverridePrefix))
		}
	}
	sort.Strings(names)
	gone := map[string]bool{}
	policy := map[string]string{}
	for _, name := range names {
		o := ov[ruleProviderOverridePrefix+name]
		v, ok := rp[name]
		if !ok {
			continue
		}
		if o.Disabled || o.Deleted {
			delete(rp, name)
			gone[name] = true
			removed = append(removed, name)
			continue
		}
		if p := strings.TrimSpace(o.Policy); p != "" {
			policy[name] = p
		}
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if u := strings.TrimSpace(o.URL); u != "" && strings.EqualFold(str(m["type"]), "http") {
			if pu, err := url.Parse(u); err == nil && (pu.Scheme == "http" || pu.Scheme == "https") && pu.Host != "" {
				changed := u != providerSourceURL(m)
				setProviderURL(m, u)
				if p := str(m["path"]); changed && p != "" {
					m["path"] = pathForURL(p, u)
				}
			} else {
				warns = append(warns, "规则集「"+name+"」的自定义链接无效，已使用配置里的链接")
			}
		}
		if o.Interval > 0 {
			m["interval"] = o.Interval
		}
	}
	if len(gone) == 0 && len(policy) == 0 {
		return removed, warns
	}
	rules := asList(raw["rules"])
	kept := make([]any, 0, len(rules))
	for _, rv := range rules {
		r, ok := rv.(string)
		if !ok {
			kept = append(kept, rv)
			continue
		}
		if name, simple := ruleSetNameOf(r); simple {
			if gone[name] {
				continue
			}
			if p, ok := policy[name]; ok {
				parts := strings.Split(r, ",")
				if len(parts) >= 3 {
					parts[2] = p
					r = strings.Join(parts, ",")
				}
			}
			kept = append(kept, r)
			continue
		}
		drop := false
		for n := range gone {
			if ruleMentionsSet(r, n) {
				drop = true
				break
			}
		}
		if !drop {
			kept = append(kept, r)
		}
	}
	if _, ok := raw["rules"]; ok {
		raw["rules"] = kept
	}
	return removed, warns
}
