package libmihomo

// 前置代理 (proxy chain, Surge underlying-proxy / Shadowrocket 代理链) through mihomo's `dialer-proxy`.
//
//   - A manual node stores `dialer-proxy` in its own YAML (it is a node field).
//   - A group's 前置代理 lives in our override store, <home>/groups.json {"<profile id>": {"dialer":
//     {"Group": "Via"}}}, next to the smart-selection option. While the runtime config is built every
//     inline proxy that is a direct member of the group gets `dialer-proxy: Via`, and every proxy-provider
//     the group `use`s gets `override.dialer-proxy: Via` (mihomo does not allow dialer-proxy on groups).
//
// Loops (A dials through B which dials through A, or a node dialing through a group that contains it)
// would recurse at connect time, so the build checks the graph: members that would loop are skipped
// with a warning, and any loop already in the profile is broken by dropping that dialer-proxy.

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/metacubex/mihomo/log"
	"go.yaml.in/yaml/v3"
)

type chainGraph struct {
	proxies   map[string]map[string]any // inline proxies by name
	groups    map[string]map[string]any
	providers map[string]map[string]any
	order     []string // proxies, then groups (stable output)
}

func newChainGraph(raw map[string]any) *chainGraph {
	g := &chainGraph{proxies: map[string]map[string]any{}, groups: map[string]map[string]any{}, providers: map[string]map[string]any{}}
	for _, p := range proxiesOf(raw) {
		if n := str(p["name"]); n != "" {
			g.proxies[n] = p
			g.order = append(g.order, n)
		}
	}
	for _, x := range asList(raw["proxy-groups"]) {
		if m, ok := x.(map[string]any); ok {
			if n := str(m["name"]); n != "" {
				g.groups[n] = m
				g.order = append(g.order, n)
			}
		}
	}
	for n, x := range asMap(raw["proxy-providers"]) {
		if m, ok := x.(map[string]any); ok {
			g.providers[n] = m
		}
	}
	return g
}

func truthyAny(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true"
	}
	return false
}

// members returns the outgoing edges of a node in the dial graph. Keys: "p:" proxy, "g:" group, "v:" provider.
func (g *chainGraph) edges(key string) []string {
	kind, name := key[:2], key[2:]
	var out []string
	add := func(n string) {
		if _, ok := g.proxies[n]; ok {
			out = append(out, "p:"+n)
		} else if _, ok := g.groups[n]; ok {
			out = append(out, "g:"+n)
		}
	}
	switch kind {
	case "p:":
		if d := str(g.proxies[name]["dialer-proxy"]); d != "" {
			add(d)
		}
	case "g:":
		m := g.groups[name]
		for _, x := range asList(m["proxies"]) {
			add(str(x))
		}
		if truthyAny(m["include-all"]) || truthyAny(m["include-all-proxies"]) {
			// B16: only the proxies the core really adds (filter / exclude-filter / exclude-type).
			pm := map[string]any{}
			for k, v := range m {
				pm[k] = v
			}
			delete(pm, "use")
			delete(pm, "include-all")
			delete(pm, "include-all-providers")
			pm["include-all-proxies"] = true
			pool := &memberPool{proxies: g.order[:0:0], types: map[string]string{}, providers: map[string][]string{}}
			for n, p := range g.proxies {
				pool.proxies = append(pool.proxies, n)
				pool.types[n] = str(p["type"])
			}
			for n, gm := range g.groups {
				pool.types[n] = str(gm["type"])
			}
			ms, _, _ := pool.groupMembers(pm)
			explicit := map[string]bool{}
			for _, x := range asList(m["proxies"]) {
				explicit[str(x)] = true
			}
			for _, n := range ms {
				if _, ok := g.proxies[n]; ok && !explicit[n] {
					out = append(out, "p:"+n)
				}
			}
		}
		uses := asList(m["use"])
		if truthyAny(m["include-all"]) || truthyAny(m["include-all-providers"]) {
			uses = nil
			for n := range g.providers {
				uses = append(uses, n)
			}
		}
		for _, x := range uses {
			if _, ok := g.providers[str(x)]; ok {
				out = append(out, "v:"+str(x))
			}
		}
	case "v:":
		if d := str(asMap(g.providers[name]["override"])["dialer-proxy"]); d != "" {
			add(d)
		}
	}
	return out
}

// reach returns every node reachable from start (start included).
func (g *chainGraph) reach(start string) map[string]bool {
	seen := map[string]bool{}
	stack := []string{start}
	for len(stack) > 0 {
		k := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[k] {
			continue
		}
		seen[k] = true
		stack = append(stack, g.edges(k)...)
	}
	return seen
}

func (g *chainGraph) key(name string) string {
	if _, ok := g.proxies[name]; ok {
		return "p:" + name
	}
	if _, ok := g.groups[name]; ok {
		return "g:" + name
	}
	return ""
}

// loopsThrough reports whether dialing via `via` can come back to target (a proxy / provider / group key).
func (g *chainGraph) loopsThrough(via, target string) bool {
	k := g.key(via)
	if k == "" {
		return false
	}
	return g.reach(k)[target]
}

var builtinPolicies = map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "COMPATIBLE": true, "GLOBAL": true}

// applyGroupChains applies the group 前置代理 settings; returns warnings.
func applyGroupChains(raw map[string]any, chains map[string]string) []string {
	if len(chains) == 0 {
		return nil
	}
	var warns []string
	names := make([]string, 0, len(chains))
	for n := range chains {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, group := range names {
		via := chains[group]
		g := newChainGraph(raw)
		gm, ok := g.groups[group]
		if !ok || via == "" {
			continue
		}
		if g.key(via) == "" && via != "DIRECT" {
			warns = append(warns, fmt.Sprintf("策略组「%s」的前置代理「%s」不存在，已忽略", group, via))
			continue
		}
		if via == group || g.loopsThrough(via, "g:"+group) {
			warns = append(warns, fmt.Sprintf("策略组「%s」的前置代理「%s」会形成循环，已忽略", group, via))
			continue
		}
		skipped := 0
		for _, x := range asList(gm["proxies"]) {
			n := str(x)
			p, ok := g.proxies[n]
			if !ok || n == via {
				continue
			}
			if g.loopsThrough(via, "p:"+n) {
				skipped++
				continue
			}
			p["dialer-proxy"] = via
		}
		for _, x := range asList(gm["use"]) {
			pv, ok := g.providers[str(x)]
			if !ok {
				continue
			}
			if g.loopsThrough(via, "v:"+str(x)) {
				skipped++
				continue
			}
			ov := asMap(pv["override"])
			ov["dialer-proxy"] = via
			pv["override"] = ov
		}
		if skipped > 0 {
			warns = append(warns, fmt.Sprintf("策略组「%s」：%d 个成员会与前置代理「%s」形成循环，已跳过", group, skipped, via))
		}
	}
	return warns
}

// breakChainLoops drops dialer-proxy entries that point at missing policies or form a loop.
func breakChainLoops(raw map[string]any) []string {
	var warns []string
	g := newChainGraph(raw)
	for _, n := range g.order {
		p, ok := g.proxies[n]
		if !ok {
			continue
		}
		d := str(p["dialer-proxy"])
		if d == "" {
			continue
		}
		if builtinPolicies[strings.ToUpper(d)] {
			continue
		}
		if g.key(d) == "" {
			delete(p, "dialer-proxy")
			warns = append(warns, fmt.Sprintf("节点「%s」的前置代理「%s」不存在，已忽略", n, d))
			continue
		}
		if d == n || g.loopsThrough(d, "p:"+n) {
			delete(p, "dialer-proxy")
			warns = append(warns, fmt.Sprintf("节点「%s」的前置代理「%s」会形成循环，已忽略", n, d))
		}
	}
	for n, pv := range g.providers {
		ov := asMap(pv["override"])
		d := str(ov["dialer-proxy"])
		if d == "" || builtinPolicies[strings.ToUpper(d)] {
			continue
		}
		if g.key(d) == "" || g.loopsThrough(d, "v:"+n) {
			delete(ov, "dialer-proxy")
			warns = append(warns, fmt.Sprintf("节点集「%s」的前置代理「%s」无效或会形成循环，已忽略", n, d))
		}
	}
	return warns
}

func readAllGroupSettings(home string) map[string]groupSettings {
	m := map[string]groupSettings{}
	if home == "" {
		return m
	}
	if b, err := os.ReadFile(groupSettingsPath(home)); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func readGroupChains(home, profilePath string) map[string]string {
	return readAllGroupSettings(home)[profileIDFromPath(profilePath)].Dialer
}

// applyChains runs in buildRuntimeWith: group chains, then the loop guard.
func applyChains(raw map[string]any, chains map[string]string) {
	for _, w := range append(applyGroupChains(raw, chains), breakChainLoops(raw)...) {
		log.Warnln("[Chain] %s", w)
		stage("%s", w)
	}
}

type chainCandidate struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Group bool   `json:"group"`
}

// ChainCandidates lists the policies that can be the 前置代理 of a node (kind "node") or a group (kind
// "group") of the profile without forming a loop. JSON {"current": "…", "candidates": [{name, type, group}]}.
func ChainCandidates(homeDir, profilePath, kind, name string) string {
	b, _ := os.ReadFile(profilePath)
	o := overridesFor(homeDir, profilePath)
	o.home = "" // no custom rules
	cur := ""
	if kind == "group" {
		cur = o.chains[name]
		delete(o.chains, name)
	}
	raw := map[string]any{}
	if rt, err := buildRuntime(b, o, 0); err == nil {
		_ = yaml.Unmarshal(rt, &raw)
	}
	g := newChainGraph(raw)
	target := ""
	switch kind {
	case "group":
		target = "g:" + name
	default:
		target = "p:" + name
		if p, ok := g.proxies[name]; ok {
			cur = str(p["dialer-proxy"])
			delete(p, "dialer-proxy")
		}
	}
	out := struct {
		Current    string           `json:"current"`
		Candidates []chainCandidate `json:"candidates"`
	}{Current: cur, Candidates: []chainCandidate{}}
	for _, n := range g.order {
		if n == name {
			continue
		}
		k := g.key(n)
		if g.reach(k)[target] {
			continue
		}
		c := chainCandidate{Name: n, Group: strings.HasPrefix(k, "g:")}
		if c.Group {
			c.Type = str(g.groups[n]["type"])
		} else {
			c.Type = str(g.proxies[n]["type"])
		}
		out.Candidates = append(out.Candidates, c)
	}
	j, _ := json.Marshal(out)
	return string(j)
}

// SetGroupChain stores (via != "") or clears the 前置代理 of a group for the profile. Returns "" or an error.
func SetGroupChain(homeDir, profilePath, group, via string) string {
	if via != "" {
		var c struct {
			Candidates []chainCandidate `json:"candidates"`
		}
		_ = json.Unmarshal([]byte(ChainCandidates(homeDir, profilePath, "group", group)), &c)
		ok := false
		for _, x := range c.Candidates {
			ok = ok || x.Name == via
		}
		if !ok {
			return fmt.Sprintf("「%s」不能作为「%s」的前置代理（不存在或会形成循环）", via, group)
		}
	}
	defer lockPath(groupSettingsPath(homeDir))() // v0.19.6: one read-modify-write of groups.json at a time
	all := readAllGroupSettings(homeDir)
	id := profileIDFromPath(profilePath)
	s := all[id]
	if s.Dialer == nil {
		s.Dialer = map[string]string{}
	}
	if via == "" {
		delete(s.Dialer, group)
	} else {
		s.Dialer[group] = via
	}
	if len(s.Dialer) == 0 {
		s.Dialer = nil
	}
	all[id] = s
	b, _ := json.MarshalIndent(all, "", "  ")
	if err := writeAtomic(groupSettingsPath(homeDir), b); err != nil {
		return err.Error()
	}
	return ""
}
