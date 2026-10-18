package libmihomo

// 策略组编辑 (v0.9): the user's edits to policy groups, kept per profile in <home>/group-edits.json and
// applied in buildRuntime — the profile file itself is never rewritten. An edit replaces the group's
// spec, renames it (rules and other groups follow) or deletes it; new groups are appended.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

type GroupSpec struct {
	Name          string   `json:"name"`
	Type          string   `json:"type"` // select | url-test | fallback | load-balance
	Proxies       []string `json:"proxies"`
	Use           []string `json:"use,omitempty"`
	IncludeAll    bool     `json:"includeAll,omitempty"`
	// v0.15.4: kept apart from include-all (which also pulls in every provider) so a QX
	// server-tag-regex group or a 筛选节点 group limited to some sources round-trips exactly.
	IncludeAllProxies   bool   `json:"includeAllProxies,omitempty"`
	IncludeAllProviders bool   `json:"includeAllProviders,omitempty"`
	ExcludeType         string `json:"excludeType,omitempty"`
	Filter        string   `json:"filter,omitempty"`
	ExcludeFilter string   `json:"excludeFilter,omitempty"`
	URL           string   `json:"url,omitempty"`
	Interval      int      `json:"interval,omitempty"`
	Tolerance     int      `json:"tolerance,omitempty"`
	Lazy          *bool    `json:"lazy,omitempty"`
	Strategy      string   `json:"strategy,omitempty"` // load-balance: consistent-hashing | round-robin | sticky-sessions
	Icon          string   `json:"icon,omitempty"`
	Hidden        bool     `json:"hidden,omitempty"`
}

type GroupEdit struct {
	Deleted bool       `json:"deleted,omitempty"`
	Spec    *GroupSpec `json:"spec,omitempty"` // Spec.Name != original name = rename
}

type GroupEdits struct {
	Edits map[string]GroupEdit `json:"edits,omitempty"` // original group name → edit
	Added []GroupSpec          `json:"added,omitempty"`
	// feat/group-order: the 策略组 order (file names) of an 自定义 copy, re-applied when the copy is regenerated
	// from its updated source subscription (GroupOrderRegenerate). Not applied at runtime: the copy's file order
	// is the source of truth.
	Order []string `json:"order,omitempty"`
}

func groupEditsPath(home string) string { return filepath.Join(home, "group-edits.json") }

func readGroupEdits(home, profileID string) *GroupEdits {
	if home == "" || profileID == "" {
		return nil
	}
	m := map[string]GroupEdits{}
	if b, err := os.ReadFile(groupEditsPath(home)); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	if e, ok := m[profileID]; ok {
		return &e
	}
	return nil
}

func specFromGroup(g map[string]any) GroupSpec {
	s := GroupSpec{Name: str(g["name"]), Type: strings.ToLower(str(g["type"])), Proxies: strList(g["proxies"]), Use: strList(g["use"]),
		IncludeAll: boolOf(g["include-all"]), IncludeAllProxies: boolOf(g["include-all-proxies"]),
		IncludeAllProviders: boolOf(g["include-all-providers"]), ExcludeType: str(g["exclude-type"]), Filter: str(g["filter"]), ExcludeFilter: str(g["exclude-filter"]),
		URL: str(g["url"]), Interval: intOf(g["interval"]), Tolerance: intOf(g["tolerance"]), Strategy: str(g["strategy"]), Icon: str(g["icon"]),
		Hidden: boolOf(g["hidden"])}
	if v, ok := g["lazy"].(bool); ok {
		s.Lazy = &v
	}
	return s
}

// writeSpec replaces the fields the editor manages and leaves everything else (e.g. expected-status).
func writeSpec(g map[string]any, s GroupSpec) {
	set := func(k string, v any, empty bool) {
		if empty {
			delete(g, k)
		} else {
			g[k] = v
		}
	}
	g["name"] = s.Name
	g["type"] = s.Type
	px := make([]any, 0, len(s.Proxies))
	for _, p := range s.Proxies {
		px = append(px, p)
	}
	set("proxies", px, len(px) == 0)
	us := make([]any, 0, len(s.Use))
	for _, u := range s.Use {
		us = append(us, u)
	}
	set("use", us, len(us) == 0)
	set("include-all", true, !s.IncludeAll)
	set("include-all-proxies", true, !s.IncludeAllProxies || s.IncludeAll)
	set("include-all-providers", true, !s.IncludeAllProviders || s.IncludeAll)
	set("exclude-type", s.ExcludeType, s.ExcludeType == "")
	set("filter", s.Filter, s.Filter == "")
	set("exclude-filter", s.ExcludeFilter, s.ExcludeFilter == "")
	auto := s.Type != "select"
	set("url", s.URL, !auto || s.URL == "")
	set("interval", s.Interval, !auto || s.Interval <= 0)
	set("tolerance", s.Tolerance, s.Type != "url-test" || s.Tolerance <= 0)
	if s.Lazy != nil && auto {
		g["lazy"] = *s.Lazy
	} else {
		delete(g, "lazy")
	}
	set("strategy", s.Strategy, s.Type != "load-balance" || s.Strategy == "")
	set("icon", s.Icon, s.Icon == "")
	set("hidden", true, !s.Hidden)
}

// splitTopLevel splits a rule at commas outside parentheses.
func splitTopLevel(r string) []string {
	var out []string
	depth, start := 0, 0
	for i, c := range r {
		switch c {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, r[start:i])
				start = i + 1
			}
		}
	}
	return append(out, r[start:])
}

// rulePolicy returns the index of the policy field of a rule ("" when none).
func rulePolicyIndex(parts []string) int {
	if len(parts) < 2 {
		return -1
	}
	if strings.EqualFold(strings.TrimSpace(parts[0]), "MATCH") {
		return 1
	}
	if len(parts) < 3 {
		return -1
	}
	return 2
}

func mapRulePolicies(raw map[string]any, f func(string) string) {
	fix := func(l []any) {
		for i, v := range l {
			s, ok := v.(string)
			if !ok {
				continue
			}
			parts := splitTopLevel(s)
			if idx := rulePolicyIndex(parts); idx >= 0 {
				p := strings.TrimSpace(parts[idx])
				if n := f(p); n != p {
					parts[idx] = n
					l[i] = strings.Join(parts, ",")
				}
			}
		}
	}
	if rl, ok := raw["rules"].([]any); ok {
		fix(rl)
	}
	if sr, ok := raw["sub-rules"].(map[string]any); ok {
		for _, v := range sr {
			if rl, ok := v.([]any); ok {
				fix(rl)
			}
		}
	}
}

// applyGroupEdits applies e to raw and returns warnings.
func applyGroupEdits(raw map[string]any, e *GroupEdits) []string {
	if e == nil || (len(e.Edits) == 0 && len(e.Added) == 0) {
		return nil
	}
	var warn []string
	groups, _ := raw["proxy-groups"].([]any)
	renames := map[string]string{}
	deleted := map[string]bool{}
	var kept []any
	for _, gv := range groups {
		g, ok := gv.(map[string]any)
		if !ok {
			kept = append(kept, gv)
			continue
		}
		name := str(g["name"])
		ed, ok := e.Edits[name]
		if !ok {
			kept = append(kept, g)
			continue
		}
		if ed.Deleted {
			deleted[name] = true
			continue
		}
		if ed.Spec != nil {
			s := *ed.Spec
			if strings.TrimSpace(s.Name) == "" {
				s.Name = name
			}
			writeSpec(g, s)
			if s.Name != name {
				renames[name] = s.Name
			}
		}
		kept = append(kept, g)
	}
	existing := map[string]bool{}
	for _, gv := range kept {
		if g, ok := gv.(map[string]any); ok {
			existing[str(g["name"])] = true
		}
	}
	for _, s := range e.Added {
		if strings.TrimSpace(s.Name) == "" || existing[s.Name] {
			warn = append(warn, "新建的策略组「"+s.Name+"」与已有名称重复，已跳过")
			continue
		}
		g := map[string]any{}
		writeSpec(g, s)
		kept = append(kept, g)
		existing[s.Name] = true
	}
	// Fallback for rules that pointed at a deleted group: the first remaining select group.
	fallback := "DIRECT"
	for _, gv := range kept {
		if g, ok := gv.(map[string]any); ok && strings.EqualFold(str(g["type"]), "select") {
			fallback = str(g["name"])
			break
		}
	}
	for _, gv := range kept {
		g, ok := gv.(map[string]any)
		if !ok {
			continue
		}
		var px []any
		for _, p := range strList(g["proxies"]) {
			if deleted[p] {
				continue
			}
			if n, ok := renames[p]; ok {
				p = n
			}
			px = append(px, p)
		}
		if px != nil || g["proxies"] != nil {
			if len(px) == 0 {
				delete(g, "proxies")
			} else {
				g["proxies"] = px
			}
		}
	}
	mapRulePolicies(raw, func(p string) string {
		if n, ok := renames[p]; ok {
			return n
		}
		if deleted[p] {
			warn = append(warn, fmt.Sprintf("规则指向已删除的策略组「%s」，改用「%s」", p, fallback))
			return fallback
		}
		return p
	})
	raw["proxy-groups"] = kept
	return warn
}

// GroupEditCheck validates a candidate edit set for the profile: the merged config must have no empty
// groups and no cycles, and must parse. Returns "" or a Chinese reason.
func GroupEditCheck(homeDir, profilePath, editsJSON string) string {
	var e GroupEdits
	if err := json.Unmarshal([]byte(editsJSON), &e); err != nil {
		return err.Error()
	}
	b, err := os.ReadFile(profilePath)
	if err != nil {
		return err.Error()
	}
	raw := map[string]any{}
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return err.Error()
	}
	if raw == nil {
		raw = map[string]any{}
	}
	if w := applyGroupEdits(raw, &e); len(w) > 0 {
		for _, s := range w {
			if strings.Contains(s, "重复") {
				return s
			}
		}
	}
	gs := map[string]map[string]any{}
	for _, gv := range asList(raw["proxy-groups"]) {
		if g, ok := gv.(map[string]any); ok {
			gs[str(g["name"])] = g
		}
	}
	for n, g := range gs {
		if len(asList(g["proxies"])) == 0 && len(asList(g["use"])) == 0 && !boolOf(g["include-all"]) && !boolOf(g["include-all-proxies"]) && !boolOf(g["include-all-providers"]) {
			return "策略组「" + n + "」没有任何成员"
		}
	}
	// Cycle check over group → group members.
	state := map[string]int{}
	var visit func(string) string
	visit = func(n string) string {
		if state[n] == 1 {
			return n
		}
		if state[n] == 2 {
			return ""
		}
		state[n] = 1
		for _, m := range strList(gs[n]["proxies"]) {
			if _, ok := gs[m]; ok {
				if c := visit(m); c != "" {
					return c
				}
			}
		}
		state[n] = 2
		return ""
	}
	for n := range gs {
		if c := visit(n); c != "" {
			return "策略组「" + c + "」形成了循环引用"
		}
	}
	return ""
}

// GroupSpecs returns the profile's own group specs (before the user's edits, with node subscriptions
// merged) for the editor: {"groups":[GroupSpec], "providers":[name], "proxies":[name]}.
func GroupSpecs(homeDir, profilePath string) string {
	out := map[string]any{"groups": []GroupSpec{}, "providers": []string{}, "proxies": []string{}}
	defer func() { _ = recover() }()
	b, err := os.ReadFile(profilePath)
	if err == nil {
		raw := map[string]any{}
		if yaml.Unmarshal(b, &raw) == nil && raw != nil {
			all := readAllSubRules(homeDir)
			mergeNodeSubs(raw, homeDir, func(k string) *SubRules {
				if r, ok := all[k]; ok {
					return &r
				}
				return nil
			})
			var gs []GroupSpec
			for _, gv := range asList(raw["proxy-groups"]) {
				if g, ok := gv.(map[string]any); ok {
					gs = append(gs, specFromGroup(g))
				}
			}
			var pv, px []string
			if pp, ok := raw["proxy-providers"].(map[string]any); ok {
				for n := range pp {
					pv = append(pv, n)
				}
			}
			for _, p := range proxiesOf(raw) {
				px = append(px, str(p["name"]))
			}
			if gs != nil {
				out["groups"] = gs
			}
			if pv != nil {
				out["providers"] = pv
			}
			if px != nil {
				out["proxies"] = px
			}
		}
	}
	j, _ := json.Marshal(out)
	return string(j)
}
