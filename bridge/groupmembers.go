package libmihomo

// B16 (v0.15.4): one offline expansion of proxy-group members for everything that shows or reasons
// about members without the core (InspectProfile → 策略 / Home cards / 节点管理 所属策略组 / shortcuts,
// GroupPreview → 策略组编辑 preview and 筛选节点 counts, the 前置代理 dial graph).
//
// It mirrors mihomo v1.19.32 exactly:
//   - adapter/outboundgroup/parser.go ParseProxyGroup: include-all = include-all-proxies +
//     include-all-providers; include-all-providers replaces `use` with every provider (sorted);
//     include-all-proxies appends the profile's proxies (sorted by name, groups excluded) that match any
//     backtick-separated `filter` (regexp2, regexp2.None = case-sensitive unless the pattern has (?i));
//     nothing at all → empty-fallback (default COMPATIBLE).
//   - adapter/outboundgroup/groupbase.go GetProxies: explicit / include-all-proxies members (the
//     group's "compatible" provider) are not filtered again; provider nodes are kept when they match a
//     filter, in filter order, de-duplicated; with several providers and several filters the whole list
//     is re-ordered by filter; then exclude-filter and exclude-type (EqualFold on the adapter type name,
//     split on |) apply to everything; an empty result is [empty-fallback].
//
// One deliberate difference: a name the core would list twice (an explicit member that also matches
// include-all-proxies, or one matching two filters) is listed once, because the app keys rows by name.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/dlclark/regexp2"
	C "github.com/metacubex/mihomo/constant"
	"go.yaml.in/yaml/v3"
)

type memberPool struct {
	proxies   []string            // profile proxies in YAML order
	types     map[string]string   // node / group name → YAML type
	providers map[string][]string // proxy-provider → node names (inline payload or cache)
}

func newMemberPool(raw map[string]any, provs []inspectProvider) *memberPool {
	mp := &memberPool{types: map[string]string{}, providers: map[string][]string{}}
	for _, p := range proxiesOf(raw) {
		n := str(p["name"])
		if n == "" {
			continue
		}
		mp.proxies = append(mp.proxies, n)
		mp.types[n] = str(p["type"])
	}
	for _, x := range asList(raw["proxy-groups"]) {
		if m, ok := x.(map[string]any); ok {
			if n := str(m["name"]); n != "" {
				mp.types[n] = str(m["type"])
			}
		}
	}
	for name := range asMap(raw["proxy-providers"]) {
		mp.providers[name] = nil
	}
	for _, pv := range provs {
		names := make([]string, 0, len(pv.Proxies))
		for _, p := range pv.Proxies {
			names = append(names, p.Name)
			if _, ok := mp.types[p.Name]; !ok {
				mp.types[p.Name] = p.Type
			}
		}
		mp.providers[pv.Name] = names
	}
	return mp
}

// adapterTypeName is C.AdapterType.String() for a YAML type (compared with EqualFold like the core).
func adapterTypeName(name, yamlType string) string {
	switch strings.ToUpper(name) {
	case "DIRECT":
		return "Direct"
	case "REJECT":
		return "Reject"
	case "REJECT-DROP":
		return "RejectDrop"
	case "COMPATIBLE":
		return "Compatible"
	case "PASS":
		return "Pass"
	case "PASS-RULE":
		return "PassRule"
	}
	switch strings.ToLower(yamlType) {
	case "ss":
		return "Shadowsocks"
	case "ssr":
		return "ShadowsocksR"
	case "gost-relay":
		return "GostRelay"
	case "select":
		return "Selector"
	case "url-test":
		return "URLTest"
	case "fallback":
		return "Fallback"
	case "load-balance":
		return "LoadBalance"
	case "":
		return "Unknown"
	}
	return yamlType
}

func compileGroupRegs(s string) ([]*regexp2.Regexp, error) {
	if s == "" {
		return nil, nil
	}
	var out []*regexp2.Regexp
	for _, f := range strings.Split(s, "`") {
		r, err := regexp2.Compile(f, regexp2.None)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func regMatch(r *regexp2.Regexp, s string) bool {
	ok, _ := r.MatchString(s)
	return ok
}

// groupMembers returns the members the core would list for group g, and whether the list is only the
// empty-fallback (nothing matched).
func (mp *memberPool) groupMembers(g map[string]any) (members []string, empty bool, err error) {
	fallback := str(g["empty-fallback"])
	if fallback == "" {
		fallback = "COMPATIBLE"
	}
	filterRegs, err := compileGroupRegs(str(g["filter"]))
	if err != nil {
		return []string{fallback}, true, fmt.Errorf("filter: %w", err)
	}
	excludeRegs, err := compileGroupRegs(str(g["exclude-filter"]))
	if err != nil {
		return []string{fallback}, true, fmt.Errorf("exclude-filter: %w", err)
	}
	var excludeTypes []string
	if et := str(g["exclude-type"]); et != "" {
		excludeTypes = strings.Split(et, "|")
	}

	includeAll := boolOf(g["include-all"])
	includeProviders := includeAll || boolOf(g["include-all-providers"])
	includeProxies := includeAll || boolOf(g["include-all-proxies"])

	use := strList(g["use"])
	if includeProviders {
		use = use[:0:0]
		for n := range mp.providers {
			use = append(use, n)
		}
		sort.Strings(use)
	}
	proxies := append([]string{}, strList(g["proxies"])...)
	parseFallback := false
	if includeProxies {
		all := append([]string{}, mp.proxies...)
		sort.Strings(all)
		if len(filterRegs) > 0 {
			for _, p := range all {
				for _, r := range filterRegs {
					if regMatch(r, p) {
						proxies = append(proxies, p)
					}
				}
			}
		} else {
			proxies = append(proxies, all...)
		}
		if len(proxies) == 0 && len(use) == 0 {
			proxies = []string{fallback}
			parseFallback = true
		}
	}

	// GetProxies
	var list []string
	nProviders := 0
	if len(proxies) > 0 {
		nProviders++
		list = append(list, proxies...) // compatible provider: not filtered
	}
	for _, u := range use {
		nodes, ok := mp.providers[u]
		if !ok {
			continue // the core refuses the profile; offline we just skip it
		}
		nProviders++
		if len(filterRegs) == 0 {
			list = append(list, nodes...)
			continue
		}
		seen := map[string]bool{}
		for _, r := range filterRegs {
			for _, n := range nodes {
				if !seen[n] && regMatch(r, n) {
					seen[n] = true
					list = append(list, n)
				}
			}
		}
	}
	if nProviders > 1 && len(filterRegs) > 1 {
		var re []string
		seen := map[string]bool{}
		for _, r := range filterRegs {
			for _, n := range list {
				if !seen[n] && regMatch(r, n) {
					seen[n] = true
					re = append(re, n)
				}
			}
		}
		for _, n := range list {
			if !seen[n] {
				seen[n] = true
				re = append(re, n)
			}
		}
		list = re
	}
	if len(excludeRegs) > 0 {
		var kept []string
	next:
		for _, n := range list {
			for _, r := range excludeRegs {
				if regMatch(r, n) {
					continue next
				}
			}
			kept = append(kept, n)
		}
		list = kept
	}
	if excludeTypes != nil {
		var kept []string
	nextType:
		for _, n := range list {
			t := adapterTypeName(n, mp.types[n])
			for _, et := range excludeTypes {
				if strings.EqualFold(t, et) {
					continue nextType
				}
			}
			kept = append(kept, n)
		}
		list = kept
	}
	if len(list) == 0 {
		return []string{fallback}, true, nil
	}
	if parseFallback && len(list) == 1 && list[0] == fallback {
		return list, true, nil
	}
	// de-duplicate (see the header)
	seen := map[string]bool{}
	out := list[:0:0]
	for _, n := range list {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out, false, nil
}

type groupPreviewItem struct {
	Members []string `json:"members"`
	Empty   bool     `json:"empty,omitempty"` // only the empty-fallback: nothing matched
	Error   string   `json:"error,omitempty"`
}

type groupPreviewResult struct {
	Groups []groupPreviewItem `json:"groups"`
	Error  string             `json:"error,omitempty"`
}

// GroupPreview returns the members the core would give each draft group (a JSON array of GroupSpec, the
// 策略组编辑 shape) in the profile at path with the current overrides — the same expansion as
// InspectProfile, so a preview / 筛选节点 count equals what the group shows after it is added.
func GroupPreview(homeDir, path, specsJSON string) string {
	res := groupPreviewResult{Groups: []groupPreviewItem{}}
	out := func() string { b, _ := json.Marshal(res); return string(b) }
	defer func() {
		if r := recover(); r != nil {
			res.Error = fmt.Sprint(r)
		}
	}()
	var specs []GroupSpec
	if err := json.Unmarshal([]byte(specsJSON), &specs); err != nil {
		res.Error = err.Error()
		return out()
	}
	pool, err := runtimePool(homeDir, path)
	if err != nil {
		res.Error = err.Error()
		return out()
	}
	for _, s := range specs {
		g := map[string]any{}
		writeSpec(g, s)
		ms, empty, err := pool.groupMembers(g)
		it := groupPreviewItem{Members: ms, Empty: empty}
		if err != nil {
			it.Error = err.Error()
		}
		res.Groups = append(res.Groups, it)
	}
	return out()
}

func runtimePool(homeDir, path string) (*memberPool, error) {
	C.SetHomeDir(homeDir)
	profile, err := readRuntimeProfile(homeDir, path, false)
	if err != nil {
		return nil, err
	}
	rt, err := buildRuntime(profile, overridesFor(homeDir, path), 0)
	if err != nil {
		return nil, err
	}
	raw := map[string]any{}
	if err := yaml.Unmarshal(rt, &raw); err != nil {
		return nil, err
	}
	return newMemberPool(raw, inspectProviders("proxy", raw["proxy-providers"])), nil
}
