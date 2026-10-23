package libmihomo

// 代理链 (Loon proxy chain): a named, ordered list of nodes / policy groups, entry first → exit last,
// stored app-wide in <home>/proxy-chains.json (written by the app, ProxyChainStore). mihomo removed the
// `relay` group type ("please using dialer-proxy instead"), so each enabled chain is built from
// dialer-proxy while the runtime config is made:
//
//   - The entry hop is used as it is (its own selection, its own 前置代理).
//   - Every later hop k gets a copy that dials through hop k-1: its nodes go into an inline proxy-provider
//     (original names, provider-level override.dialer-proxy = hop k-1), a proxy-provider it uses is copied
//     with the same override, a nested group is copied the same way. The copy is a group named after the
//     chain for the exit hop (the policy users pick in groups and rules), and a hidden group for the hops
//     in between (a 手动选择 group stays visible as "<chain> › <group>" so its node can be chosen).
//   - Generated providers are named tern.chain/… (the app hides them from its node lists). Groups with
//     include-all / include-all-providers get an explicit `use:` of the profile's own providers instead,
//     so they do not pick the copies up.
//
// A chain that cannot be built in this profile (a member is missing, fewer than two hops, the name is
// taken, or the entry already routes through the chain) is skipped with a warning; a skipped or 停用
// chain's name is removed from group members and rules so the rest of the config still loads.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/metacubex/mihomo/log"
	"go.yaml.in/yaml/v3"
)

// ProxyChain is one entry of proxy-chains.json.
type ProxyChain struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	UDP     bool     `json:"udp"`
	Enabled bool     `json:"enabled"`
	Members []string `json:"members"`
}

// GeneratedProviderPrefix marks the proxy-providers made for chains (hidden in the app's node lists).
const GeneratedProviderPrefix = "tern.chain/"

func proxyChainsPath(home string) string { return filepath.Join(home, "proxy-chains.json") }

func readProxyChains(home string) []ProxyChain {
	if home == "" {
		return nil
	}
	b, err := os.ReadFile(proxyChainsPath(home))
	if err != nil {
		return nil
	}
	var out []ProxyChain
	if json.Unmarshal(b, &out) != nil {
		return nil
	}
	return out
}

func cloneAny(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = cloneAny(x)
		}
		return m
	case []any:
		l := make([]any, len(t))
		for i, x := range t {
			l[i] = cloneAny(x)
		}
		return l
	}
	return v
}

func cloneMap(m map[string]any) map[string]any {
	if c, ok := cloneAny(m).(map[string]any); ok {
		return c
	}
	return map[string]any{}
}

// chainBuild holds the state of one applyProxyChains run.
type chainBuild struct {
	raw       map[string]any
	proxies   map[string]map[string]any // the profile's own inline proxies
	groups    map[string]map[string]any // groups before any chain was added
	providers map[string]map[string]any // providers before any chain was added
	provOrder []string                  // own providers, sorted (mihomo sorts AllProviders)
	taken     map[string]bool           // every proxy / group name of the runtime
	generated map[string]bool           // groups made for chains
	aliases   map[string]bool           // chain names in use
	// per chain
	newGroups    []any
	newProviders map[string]any
	udp          bool
	alias        string
	err          string
}

func (b *chainBuild) unique(base string) string {
	n := base
	for i := 2; b.taken[n]; i++ {
		n = fmt.Sprintf("%s #%d", base, i)
	}
	b.taken[n] = true
	return n
}

func (b *chainBuild) providerName(hop int, base string) string {
	n := fmt.Sprintf("%s%s/%d/%s", GeneratedProviderPrefix, b.alias, hop, base)
	for i := 2; ; i++ {
		_, own := b.providers[n]
		_, mine := b.newProviders[n]
		if !own && !mine {
			return n
		}
		n = fmt.Sprintf("%s%s/%d/%s-%d", GeneratedProviderPrefix, b.alias, hop, base, i)
	}
}

// hopOverride is the provider override that makes every node of a copy dial through via.
func (b *chainBuild) hopOverride(base map[string]any, via string) map[string]any {
	ov := cloneMap(base)
	ov["dialer-proxy"] = via
	ov["udp"] = b.udp
	return ov
}

// copyGroup copies group g (named name) so that its nodes dial through via; depth guards nested groups.
func (b *chainBuild) copyGroup(g map[string]any, name string, via string, hop int, hidden bool, depth int) bool {
	if depth > 4 {
		b.err = fmt.Sprintf("策略组「%s」嵌套太深", str(g["name"]))
		return false
	}
	c := map[string]any{}
	for k, v := range g {
		switch k {
		case "name", "proxies", "use", "include-all", "include-all-proxies", "include-all-providers", "hidden", "dialer-proxy":
			continue
		}
		c[k] = cloneAny(v)
	}
	c["name"] = name
	if hidden {
		c["hidden"] = true
	}
	var payload []any
	seen := map[string]bool{}
	var explicitNodes []string
	addNode := func(n string, explicit bool) {
		if seen[n] {
			return
		}
		p, ok := b.proxies[n]
		if !ok {
			return
		}
		seen[n] = true
		cp := cloneMap(p)
		delete(cp, "dialer-proxy")
		payload = append(payload, cp)
		if explicit {
			explicitNodes = append(explicitNodes, n)
		}
	}
	var members []any
	for _, m := range strList(g["proxies"]) {
		switch {
		case builtinPolicies[strings.ToUpper(m)]:
			members = append(members, m)
		case b.generated[m] || b.aliases[m]:
			// another chain inside a later hop would lose its own hops: skipped
		case b.proxies[m] != nil:
			addNode(m, true)
		case b.groups[m] != nil:
			sub := b.unique(b.alias + " › " + m)
			subHidden := !strings.EqualFold(str(b.groups[m]["type"]), "select")
			if !b.copyGroup(b.groups[m], sub, via, hop, subHidden, depth+1) {
				return false
			}
			members = append(members, sub)
		}
	}
	includeAll := boolOf(g["include-all"])
	if includeAll || boolOf(g["include-all-proxies"]) {
		all := make([]string, 0, len(b.proxies))
		for n := range b.proxies {
			all = append(all, n)
		}
		sort.Strings(all)
		regs, _ := compileGroupRegs(str(g["filter"]))
		for _, n := range all {
			ok := len(regs) == 0
			for _, r := range regs {
				ok = ok || regMatch(r, n)
			}
			if ok {
				addNode(n, false)
			}
		}
	}
	var use []any
	if len(payload) > 0 {
		pn := b.providerName(hop, "nodes")
		b.newProviders[pn] = map[string]any{"type": "inline", "payload": payload, "override": b.hopOverride(nil, via)}
		use = append(use, pn)
	}
	uses := strList(g["use"])
	if includeAll || boolOf(g["include-all-providers"]) {
		uses = b.provOrder
	}
	for _, u := range uses {
		pv, ok := b.providers[u]
		if !ok {
			continue
		}
		cp := cloneMap(pv)
		cp["override"] = b.hopOverride(asMap(pv["override"]), via)
		if strings.EqualFold(str(cp["type"]), "http") {
			cp["interval"] = 0 // the profile's own provider keeps the shared cache file up to date
		}
		pn := b.providerName(hop, u)
		b.newProviders[pn] = cp
		use = append(use, pn)
	}
	// In mihomo a group filter skips its explicit `proxies:`; here they sit in a provider, so let them through.
	if f := str(c["filter"]); f != "" && len(explicitNodes) > 0 {
		quoted := make([]string, len(explicitNodes))
		for i, n := range explicitNodes {
			quoted[i] = strings.ReplaceAll(regexp.QuoteMeta(n), "`", `\x60`)
		}
		c["filter"] = f + "`^(?:" + strings.Join(quoted, "|") + ")$"
	}
	if len(members) == 0 && len(use) == 0 {
		b.err = fmt.Sprintf("策略组「%s」里没有可用的节点", str(g["name"]))
		return false
	}
	if len(members) > 0 {
		c["proxies"] = members
	}
	if len(use) > 0 {
		c["use"] = use
	}
	b.generated[name] = true
	b.newGroups = append(b.newGroups, c)
	return true
}

// hop builds hop k (member m dialing through via) under name.
func (b *chainBuild) hop(m, via, name string, k int, hidden bool) bool {
	if g, ok := b.groups[m]; ok {
		if hidden && strings.EqualFold(str(g["type"]), "select") {
			hidden = false // its node must stay choosable
		}
		return b.copyGroup(g, name, via, k, hidden, 0)
	}
	return b.copyGroup(map[string]any{"name": m, "type": "select", "proxies": []any{m}}, name, via, k, hidden, 0)
}

func groupList(raw map[string]any) []any { return asList(raw["proxy-groups"]) }

// applyProxyChains adds the enabled chains to raw. build=false (安全模式) only clears references.
func applyProxyChains(raw map[string]any, chains []ProxyChain, build bool) []string {
	if len(chains) == 0 {
		return nil
	}
	b := &chainBuild{raw: raw, proxies: map[string]map[string]any{}, groups: map[string]map[string]any{},
		providers: map[string]map[string]any{}, taken: map[string]bool{}, generated: map[string]bool{}, aliases: map[string]bool{}}
	for _, p := range proxiesOf(raw) {
		if n := str(p["name"]); n != "" {
			b.proxies[n] = p
			b.taken[n] = true
		}
	}
	for _, x := range groupList(raw) {
		if g, ok := x.(map[string]any); ok {
			if n := str(g["name"]); n != "" {
				b.groups[n] = g
				b.taken[n] = true
			}
		}
	}
	for n, x := range asMap(raw["proxy-providers"]) {
		if m, ok := x.(map[string]any); ok {
			b.providers[n] = m
			b.provOrder = append(b.provOrder, n)
		}
	}
	sort.Strings(b.provOrder)
	for n := range builtinPolicies {
		b.taken[n] = true
	}

	var warns []string
	dead := map[string]bool{}
	built := 0
	for _, ch := range chains {
		alias := strings.TrimSpace(ch.Name)
		if alias == "" {
			continue
		}
		if b.aliases[alias] || dead[alias] {
			warns = append(warns, fmt.Sprintf("代理链「%s」重名，只用第一条", alias))
			continue
		}
		if b.taken[alias] {
			warns = append(warns, fmt.Sprintf("代理链「%s」与已有的节点或策略组同名，未启用", alias))
			continue
		}
		if !build || !ch.Enabled {
			dead[alias] = true
			continue
		}
		fail := func(why string) {
			warns = append(warns, fmt.Sprintf("代理链「%s」未启用：%s", alias, why))
			dead[alias] = true
		}
		var members []string
		for _, m := range ch.Members {
			if m = strings.TrimSpace(m); m != "" {
				members = append(members, m)
			}
		}
		if len(members) < 2 {
			fail("至少需要两个节点或策略组")
			continue
		}
		bad := ""
		for _, m := range members {
			if b.aliases[m] || b.generated[m] || m == alias {
				bad = fmt.Sprintf("不能包含代理链「%s」", m)
				break
			}
			if b.proxies[m] == nil && b.groups[m] == nil {
				bad = fmt.Sprintf("当前配置里没有「%s」", m)
				break
			}
			if m == ProbeGroup {
				bad = fmt.Sprintf("不能使用「%s」", m)
				break
			}
		}
		if bad != "" {
			fail(bad)
			continue
		}
		b.alias, b.udp, b.err = alias, ch.UDP, ""
		b.newGroups, b.newProviders = nil, map[string]any{}
		b.taken[alias] = true
		prev := members[0]
		ok := true
		for k := 1; k < len(members); k++ {
			name := alias
			if k < len(members)-1 {
				name = b.unique(fmt.Sprintf("%s › %d %s", alias, k+1, members[k]))
			}
			if !b.hop(members[k], prev, name, k, name != alias) {
				ok = false
				break
			}
			prev = name
		}
		if !ok {
			delete(b.taken, alias)
			fail(b.err)
			continue
		}
		// Commit, then make sure the entry hop does not already route through the chain (a loop).
		oldGroups := raw["proxy-groups"]
		oldProviders := raw["proxy-providers"]
		pp := map[string]any{}
		for n, v := range asMap(raw["proxy-providers"]) {
			pp[n] = v
		}
		for n, v := range b.newProviders {
			pp[n] = v
		}
		raw["proxy-providers"] = pp
		raw["proxy-groups"] = append(append([]any{}, groupList(raw)...), b.newGroups...)
		g := newChainGraph(raw)
		if g.reach(g.key(members[0]))["g:"+alias] {
			raw["proxy-groups"] = oldGroups
			if oldProviders == nil {
				delete(raw, "proxy-providers")
			} else {
				raw["proxy-providers"] = oldProviders
			}
			for _, x := range b.newGroups {
				delete(b.generated, str(asMap(x)["name"]))
			}
			delete(b.taken, alias)
			fail(fmt.Sprintf("「%s」已经经过这条链，会形成循环", members[0]))
			continue
		}
		b.aliases[alias] = true
		built++
	}

	if built > 0 {
		// include-all groups would pick up the chain providers: list the profile's own providers instead.
		for _, x := range groupList(raw) {
			g, ok := x.(map[string]any)
			if !ok || b.generated[str(g["name"])] || b.aliases[str(g["name"])] {
				continue
			}
			all := boolOf(g["include-all"])
			if !all && !boolOf(g["include-all-providers"]) {
				continue
			}
			use := make([]any, 0, len(b.provOrder))
			for _, n := range b.provOrder {
				use = append(use, n)
			}
			delete(g, "include-all")
			delete(g, "include-all-providers")
			if all {
				g["include-all-proxies"] = true
			}
			if len(use) > 0 {
				g["use"] = use
			} else {
				delete(g, "use")
			}
		}
	}
	if len(dead) > 0 {
		warns = append(warns, dropPolicyRefs(raw, dead)...)
	}
	return warns
}

// dropPolicyRefs removes names from group members, rules and sub-rules (a 停用 or unusable chain).
func dropPolicyRefs(raw map[string]any, names map[string]bool) []string {
	var warns []string
	for _, x := range groupList(raw) {
		g, ok := x.(map[string]any)
		if !ok {
			continue
		}
		l := asList(g["proxies"])
		if len(l) == 0 {
			continue
		}
		kept := make([]any, 0, len(l))
		for _, m := range l {
			if !names[str(m)] {
				kept = append(kept, m)
			}
		}
		if len(kept) == len(l) {
			continue
		}
		if len(kept) == 0 && len(asList(g["use"])) == 0 && !boolOf(g["include-all"]) && !boolOf(g["include-all-proxies"]) && !boolOf(g["include-all-providers"]) {
			kept = []any{"DIRECT"}
		}
		g["proxies"] = kept
	}
	fix := func(l []any) []any {
		out := make([]any, 0, len(l))
		for _, v := range l {
			s, ok := v.(string)
			if ok {
				parts := splitTopLevel(s)
				if idx := rulePolicyIndex(parts); idx >= 0 && names[strings.TrimSpace(parts[idx])] {
					if strings.EqualFold(strings.TrimSpace(parts[0]), "MATCH") {
						parts[idx] = "DIRECT"
						v = strings.Join(parts, ",")
					} else {
						warns = append(warns, fmt.Sprintf("规则「%s」指向未启用的代理链，已跳过", s))
						continue
					}
				}
			}
			out = append(out, v)
		}
		return out
	}
	if rl, ok := raw["rules"].([]any); ok {
		raw["rules"] = fix(rl)
	}
	if sr, ok := raw["sub-rules"].(map[string]any); ok {
		for k, v := range sr {
			if rl, ok := v.([]any); ok {
				sr[k] = fix(rl)
			}
		}
	}
	return warns
}

func applyProxyChainsLogged(raw map[string]any, chains []ProxyChain, build bool) {
	for _, w := range applyProxyChains(raw, chains, build) {
		log.Warnln("[Chain] %s", w)
		stage("%s", w)
	}
}

// ProxyChainCandidates lists the nodes and policy groups of the profile that can be members of a chain:
// JSON {"candidates": [{name, type, group}]} (the runtime without chains, probe / GLOBAL / hidden groups left out).
func ProxyChainCandidates(homeDir, profilePath string) string {
	out := struct {
		Candidates []chainCandidate `json:"candidates"`
	}{Candidates: []chainCandidate{}}
	defer func() { _ = recover() }()
	b, _ := readRuntimeProfile(homeDir, profilePath, false)
	o := overridesFor(homeDir, profilePath)
	o.noProxyChains = true
	raw := map[string]any{}
	if rt, err := buildRuntime(b, o, 0); err == nil {
		_ = yaml.Unmarshal(rt, &raw)
	}
	for _, x := range groupList(raw) {
		g, ok := x.(map[string]any)
		if !ok {
			continue
		}
		n := str(g["name"])
		if n == "" || n == ProbeGroup || n == "GLOBAL" || boolOf(g["hidden"]) {
			continue
		}
		out.Candidates = append(out.Candidates, chainCandidate{Name: n, Type: str(g["type"]), Group: true})
	}
	for _, p := range proxiesOf(raw) {
		if n := str(p["name"]); n != "" {
			out.Candidates = append(out.Candidates, chainCandidate{Name: n, Type: str(p["type"])})
		}
	}
	j, _ := json.Marshal(out)
	return string(j)
}
