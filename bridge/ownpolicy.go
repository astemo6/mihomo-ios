package libmihomo

// v0.12: QX [filter_remote] lines without force-policy keep each line's own policy (QX behaviour).
// A mihomo rule-provider carries no per-line policy, so:
//
//   - the importer marks the provider `x-own-policy: true` (its RULE-SET goes to proxy until downloaded);
//   - when the app downloads it (ProviderPlan reports convert "list-split"), ProviderStore writes the whole
//     converted list as usual plus one file per policy next to it and a sidecar <path>.policies.json;
//   - buildRuntime (expandOwnPolicyProviders) replaces the provider's RULE-SET with one RULE-SET per policy
//     (file providers "<name>#<policy>") followed by the original rule for lines without a policy, and
//     creates missing policies as select groups (fallback + DIRECT), as QX auto-creates them.
//
// The profile itself is never rewritten; deleting the sidecar returns to the single RULE-SET.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
)

type ownPolicyPart struct {
	Policy string `json:"policy"`
	File   string `json:"file"` // base name, same directory as the provider's cache file
	Count  int    `json:"count"`
}

const ownPolicyMaxParts = 32

func ownPolicySidecar(cachePath string) string { return cachePath + ".policies.json" }

// lineOwnPolicy returns the policy written on a QX/Surge list line ("host-suffix, a.com, Netflix"), or "".
func lineOwnPolicy(line string) string {
	l := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- "))
	parts := strings.Split(l, ",")
	if len(parts) < 3 {
		return ""
	}
	switch strings.ToUpper(strings.TrimSpace(parts[0])) {
	case "AND", "OR", "NOT":
		return ""
	}
	for _, p := range parts[2:] {
		p = strings.Trim(strings.TrimSpace(p), `'"`)
		if p == "" || strings.EqualFold(p, "no-resolve") || strings.Contains(p, "=") {
			continue
		}
		return p
	}
	return ""
}

// splitOwnPolicyList writes one converted file per policy and the sidecar. Lines without a policy stay
// only in the main file. Returns the number of parts written.
func splitOwnPolicyList(cachePath string, data []byte) (int, error) {
	type bucket struct {
		policy string
		lines  []string
	}
	var order []*bucket
	byKey := map[string]*bucket{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		raw := sc.Text()
		pol := lineOwnPolicy(raw)
		if pol == "" {
			continue
		}
		rule, ok := mitm.ConvertListLine(raw, "list")
		if !ok {
			continue
		}
		key := pol
		switch lp := strings.ToLower(pol); {
		case lp == "proxy" || lp == "direct" || strings.HasPrefix(lp, "reject"):
			key = lp
		}
		b := byKey[key]
		if b == nil {
			if len(order) >= ownPolicyMaxParts {
				continue
			}
			b = &bucket{policy: pol}
			byKey[key] = b
			order = append(order, b)
		}
		b.lines = append(b.lines, rule)
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	side := ownPolicySidecar(cachePath)
	if len(order) == 0 {
		_ = os.Remove(side)
		return 0, nil
	}
	base := strings.TrimSuffix(filepath.Base(cachePath), filepath.Ext(cachePath))
	parts := make([]ownPolicyPart, 0, len(order))
	for i, b := range order {
		f := base + ".own" + itoa(i) + ".txt"
		if err := os.WriteFile(filepath.Join(filepath.Dir(cachePath), f), []byte(strings.Join(b.lines, "\n")+"\n"), 0o644); err != nil {
			return 0, err
		}
		parts = append(parts, ownPolicyPart{Policy: b.policy, File: f, Count: len(b.lines)})
	}
	j, _ := json.Marshal(parts)
	if err := os.WriteFile(side, j, 0o644); err != nil {
		return 0, err
	}
	return len(parts), nil
}

func readOwnPolicyParts(cachePath string) []ownPolicyPart {
	b, err := os.ReadFile(ownPolicySidecar(cachePath))
	if err != nil {
		return nil
	}
	var parts []ownPolicyPart
	if json.Unmarshal(b, &parts) != nil {
		return nil
	}
	return parts
}

// expandOwnPolicyProviders applies the per-policy split at runtime (see the file comment).
func expandOwnPolicyProviders(raw map[string]any, home string) {
	rp, _ := raw["rule-providers"].(map[string]any)
	if len(rp) == 0 || home == "" {
		return
	}
	type exp struct {
		dir   string
		parts []ownPolicyPart
	}
	exps := map[string]exp{}
	for name, v := range rp {
		m, ok := v.(map[string]any)
		if !ok || !truthyAny(m["x-own-policy"]) {
			continue
		}
		p := str(m["path"])
		if p == "" {
			continue
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(home, p)
		}
		if parts := readOwnPolicyParts(p); len(parts) > 0 {
			exps[name] = exp{dir: filepath.Dir(p), parts: parts}
		}
	}
	rules, _ := raw["rules"].([]any)
	if len(exps) == 0 || len(rules) == 0 {
		return
	}
	known := map[string]string{} // lower-case name → name
	groups, _ := raw["proxy-groups"].([]any)
	for _, g := range groups {
		if m, ok := g.(map[string]any); ok {
			if n := str(m["name"]); n != "" {
				known[strings.ToLower(n)] = n
			}
		}
	}
	if ps, ok := raw["proxies"].([]any); ok {
		for _, p := range ps {
			if m, ok := p.(map[string]any); ok {
				if n := str(m["name"]); n != "" {
					if _, dup := known[strings.ToLower(n)]; !dup {
						known[strings.ToLower(n)] = n
					}
				}
			}
		}
	}
	resolve := func(pol, fallback string) string {
		lp := strings.ToLower(strings.TrimSpace(pol))
		switch {
		case lp == "proxy":
			return fallback
		case lp == "direct":
			return "DIRECT"
		case lp == "reject-drop":
			return "REJECT-DROP"
		case strings.HasPrefix(lp, "reject"):
			return "REJECT"
		}
		if n, ok := known[lp]; ok {
			return n
		}
		members := []any{}
		if fu := strings.ToUpper(fallback); fu != "DIRECT" && !strings.HasPrefix(fu, "REJECT") {
			members = append(members, fallback)
		}
		members = append(members, "DIRECT")
		groups = append(groups, map[string]any{"name": pol, "type": "select", "proxies": members})
		known[lp] = pol
		return pol
	}
	out := make([]any, 0, len(rules)+8)
	for _, r := range rules {
		s, ok := r.(string)
		if !ok {
			out = append(out, r)
			continue
		}
		f := strings.Split(s, ",")
		if len(f) < 3 || !strings.EqualFold(strings.TrimSpace(f[0]), "RULE-SET") {
			out = append(out, r)
			continue
		}
		name := strings.TrimSpace(f[1])
		e, ok := exps[name]
		if !ok {
			out = append(out, r)
			continue
		}
		fallback := strings.TrimSpace(f[2])
		rest := ""
		if len(f) > 3 {
			rest = "," + strings.Join(f[3:], ",")
		}
		for _, p := range e.parts {
			pn := name + "#" + p.Policy
			rp[pn] = map[string]any{"type": "file", "behavior": "classical", "format": "text", "path": filepath.Join(e.dir, p.File)}
			out = append(out, "RULE-SET,"+pn+","+resolve(p.Policy, fallback)+rest)
		}
		out = append(out, r)
	}
	raw["rules"] = out
	raw["proxy-groups"] = groups
}
