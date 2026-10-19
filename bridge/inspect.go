package libmihomo

// Offline view of a profile: what the 策略 / 规则 / 提供者 pages show while the tunnel is down.
// Built from the same runtime YAML the core would load (overrides + optional manual-node merge
// applied), without starting anything. Provider contents come from their cached files if present.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	C "github.com/metacubex/mihomo/constant"

	"go.yaml.in/yaml/v3"
)

type inspectProxy struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Server string `json:"server,omitempty"`
	Port   int    `json:"port,omitempty"`
	UDP    bool   `json:"udp,omitempty"`
	Source string `json:"source,omitempty"` // "" = profile, provider name otherwise
}

type inspectGroup struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Proxies  []string `json:"proxies"`
	Use      []string `json:"use"`
	URL      string   `json:"url,omitempty"`
	Interval int      `json:"interval,omitempty"`
	Hidden   bool     `json:"hidden,omitempty"`
	Icon     string   `json:"icon,omitempty"`
	Filter   string   `json:"filter,omitempty"`
	Selected string   `json:"selected,omitempty"` // saved selection (select groups), else first member
	// B16: what the core lists (groupMembers); Proxies stays the explicit list.
	Members       []string `json:"members"`
	MembersError  string   `json:"membersError,omitempty"`
	ExcludeFilter string   `json:"excludeFilter,omitempty"`
	ExcludeType   string   `json:"excludeType,omitempty"`
	IncludeAll    bool     `json:"includeAll,omitempty"`
}

type inspectRule struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Proxy   string `json:"proxy"`
	Options string `json:"options,omitempty"`
}

type inspectProvider struct {
	Name      string         `json:"name"`
	Kind      string         `json:"kind"`    // proxy | rule
	Vehicle   string         `json:"vehicle"` // http | file | inline
	Behavior  string         `json:"behavior,omitempty"`
	Format    string         `json:"format,omitempty"`
	URL       string         `json:"url,omitempty"`
	Path      string         `json:"path,omitempty"`
	Interval  int            `json:"interval,omitempty"`
	Cached    bool           `json:"cached"`
	CachedAt  float64        `json:"cachedAt,omitempty"` // unix seconds of the cached file
	Size      int64          `json:"size,omitempty"`
	Count     int            `json:"count"`             // nodes / rules in the cache (-1 unknown, e.g. .mrs)
	Proxies   []inspectProxy `json:"proxies,omitempty"` // proxy providers: cached nodes
	Preview   []string       `json:"preview,omitempty"` // rule providers: first lines
	CachePath string         `json:"cachePath,omitempty"`
}

type inspectResult struct {
	Mode           string            `json:"mode"`
	Proxies        []inspectProxy    `json:"proxies"`
	Groups         []inspectGroup    `json:"groups"`
	Rules          []inspectRule     `json:"rules"`
	ProxyProviders []inspectProvider `json:"proxyProviders"`
	RuleProviders  []inspectProvider `json:"ruleProviders"`
	Selected       map[string]string `json:"selected"`
	Error          string            `json:"error,omitempty"`
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	default:
		return fmt.Sprint(x)
	}
}

func intOf(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case string:
		return atoi(x, 0)
	}
	return 0
}

func boolOf(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return truthy(x)
	}
	return false
}

func strList(v any) []string {
	out := []string{}
	if l, ok := v.([]any); ok {
		for _, x := range l {
			if s := str(x); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func toInspectProxy(m map[string]any, source string) inspectProxy {
	return inspectProxy{Name: str(m["name"]), Type: str(m["type"]), Server: str(m["server"]), Port: intOf(m["port"]), UDP: boolOf(m["udp"]), Source: source}
}

// splitRule turns "TYPE,payload,TARGET[,opts]" (and logic rules AND/OR/NOT/SUB-RULE) into fields.
func splitRule(line string) inspectRule {
	line = strings.TrimSpace(line)
	i := strings.Index(line, ",")
	if i < 0 {
		return inspectRule{Type: line}
	}
	typ := strings.ToUpper(strings.TrimSpace(line[:i]))
	rest := line[i+1:]
	switch typ {
	case "AND", "OR", "NOT", "SUB-RULE":
		j := strings.LastIndex(rest, ",")
		if j < 0 {
			return inspectRule{Type: typ, Payload: rest}
		}
		return inspectRule{Type: typ, Payload: strings.TrimSpace(rest[:j]), Proxy: strings.TrimSpace(rest[j+1:])}
	case "MATCH", "FINAL":
		return inspectRule{Type: "MATCH", Proxy: strings.TrimSpace(rest)}
	}
	parts := strings.Split(rest, ",")
	r := inspectRule{Type: typ, Payload: strings.TrimSpace(parts[0])}
	if len(parts) > 1 {
		r.Proxy = strings.TrimSpace(parts[1])
	}
	if len(parts) > 2 {
		r.Options = strings.TrimSpace(strings.Join(parts[2:], ","))
	}
	return r
}

func providerCache(kind string, m map[string]any) (path string) {
	if p := str(m["path"]); p != "" {
		return C.Path.Resolve(p)
	}
	if u := str(m["url"]); u != "" {
		prefix := "proxies"
		if kind == "rule" {
			prefix = "rules"
		}
		return C.Path.GetPathByHash(prefix, u)
	}
	return ""
}

func inspectProviders(kind string, raw any) []inspectProvider {
	out := []inspectProvider{}
	mp, ok := raw.(map[string]any)
	if !ok {
		return out
	}
	for name, v := range mp {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		p := inspectProvider{Name: name, Kind: kind, Vehicle: strings.ToLower(str(m["type"])), Behavior: str(m["behavior"]),
			Format: str(m["format"]), URL: firstNonEmpty(str(m["x-source"]), str(m["url"])), Path: str(m["path"]), Interval: intOf(m["interval"]), Count: -1}
		if p.Vehicle == "inline" {
			if kind == "proxy" {
				for _, x := range proxiesOf(map[string]any{"proxies": m["payload"]}) {
					p.Proxies = append(p.Proxies, toInspectProxy(x, name))
				}
				p.Count = len(p.Proxies)
			} else {
				pl := strList(m["payload"])
				p.Count = len(pl)
				p.Preview = head(pl, 50)
			}
			p.Cached = true
			out = append(out, p)
			continue
		}
		cp := providerCache(kind, m)
		p.CachePath = cp
		if st, err := os.Stat(cp); err == nil && !st.IsDir() && st.Size() > 0 {
			p.Cached = true
			p.Size = st.Size()
			p.CachedAt = float64(st.ModTime().Unix())
			if st.Size() <= 8<<20 {
				if b, err := os.ReadFile(cp); err == nil {
					if kind == "proxy" {
						p.Proxies = parseProviderNodes(b, name)
						p.Count = len(p.Proxies)
					} else {
						p.Preview, p.Count = parseRuleCache(b, p.Format)
					}
				}
			}
		}
		out = append(out, p)
	}
	sortByName(out)
	return out
}

func head(l []string, n int) []string {
	if len(l) > n {
		return l[:n]
	}
	return l
}

func sortByName(l []inspectProvider) {
	for i := 1; i < len(l); i++ {
		for j := i; j > 0 && l[j].Name < l[j-1].Name; j-- {
			l[j], l[j-1] = l[j-1], l[j]
		}
	}
}

func parseProviderNodes(b []byte, source string) []inspectProxy {
	out := []inspectProxy{}
	raw := map[string]any{}
	if yaml.Unmarshal(b, &raw) == nil && raw != nil {
		if ps := proxiesOf(raw); len(ps) > 0 {
			for _, p := range ps {
				out = append(out, toInspectProxy(p, source))
			}
			return out
		}
	}
	ps, _ := parseNodeText(string(b))
	for _, p := range ps {
		out = append(out, toInspectProxy(p, source))
	}
	return out
}

func parseRuleCache(b []byte, format string) ([]string, int) {
	if strings.EqualFold(format, "mrs") || (len(b) > 4 && string(b[:4]) == "MRS\x01") {
		return []string{}, -1
	}
	raw := map[string]any{}
	if yaml.Unmarshal(b, &raw) == nil && raw != nil {
		if pl := strList(raw["payload"]); len(pl) > 0 {
			return head(pl, 50), len(pl)
		}
	}
	var lines []string
	for _, l := range strings.Split(strings.ReplaceAll(string(b), "\r", ""), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "//") || l == "payload:" {
			continue
		}
		lines = append(lines, strings.TrimSpace(strings.TrimPrefix(l, "- ")))
	}
	return head(lines, 50), len(lines)
}

// selectionsPath is <profile>.selected.json next to the profile YAML (group → node chosen in the app).
func selectionsPath(profilePath string) string {
	return strings.TrimSuffix(profilePath, filepath.Ext(profilePath)) + ".selected.json"
}

func readSelections(profilePath string) map[string]string {
	m := map[string]string{}
	if b, err := os.ReadFile(selectionsPath(profilePath)); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

// InspectProfile returns JSON (proxies, groups, rules, providers, saved selections) for the profile
// at path as the core would see it with the current overrides — without starting the core.
func InspectProfile(homeDir, path string) string {
	res := inspectResult{Proxies: []inspectProxy{}, Groups: []inspectGroup{}, Rules: []inspectRule{},
		ProxyProviders: []inspectProvider{}, RuleProviders: []inspectProvider{}, Selected: readSelections(path)}
	defer func() {
		if r := recover(); r != nil {
			res.Error = fmt.Sprint(r)
		}
	}()
	C.SetHomeDir(homeDir)
	profile, err := readRuntimeProfile(homeDir, path, false) // v0.19: override-script output when current
	if err != nil {
		res.Error = err.Error()
		b, _ := json.Marshal(res)
		return string(b)
	}
	o := overridesFor(homeDir, path)
	rt, err := buildRuntime(profile, o, 0)
	if err != nil {
		res.Error = err.Error()
		b, _ := json.Marshal(res)
		return string(b)
	}
	raw := map[string]any{}
	_ = yaml.Unmarshal(rt, &raw)
	res.Mode = strings.ToLower(str(raw["mode"]))
	if res.Mode == "" {
		res.Mode = "rule"
	}
	for _, p := range proxiesOf(raw) {
		res.Proxies = append(res.Proxies, toInspectProxy(p, ""))
	}
	res.ProxyProviders = inspectProviders("proxy", raw["proxy-providers"])
	pool := newMemberPool(raw, res.ProxyProviders)
	if gl, ok := raw["proxy-groups"].([]any); ok {
		for _, x := range gl {
			m, ok := x.(map[string]any)
			if !ok || str(m["name"]) == ProbeGroup {
				continue
			}
			g := inspectGroup{Name: str(m["name"]), Type: strings.ToLower(str(m["type"])), Proxies: strList(m["proxies"]), Use: strList(m["use"]),
				URL: str(m["url"]), Interval: intOf(m["interval"]), Hidden: boolOf(m["hidden"]), Icon: str(m["icon"]), Filter: str(m["filter"])}
			// B16: members as the core lists them (filter / exclude-filter / exclude-type / providers /
			// empty-fallback), not every proxy for include-all groups.
			ms, _, merr := pool.groupMembers(m)
			g.Members = ms
			if merr != nil {
				g.MembersError = merr.Error()
			}
			g.ExcludeFilter, g.ExcludeType = str(m["exclude-filter"]), str(m["exclude-type"])
			g.IncludeAll = boolOf(m["include-all"]) || boolOf(m["include-all-proxies"])
			if s, ok := res.Selected[g.Name]; ok && g.Type == "select" {
				g.Selected = s
			}
			res.Groups = append(res.Groups, g)
		}
	}
	for _, r := range strList(raw["rules"]) {
		res.Rules = append(res.Rules, splitRule(r))
	}
	res.RuleProviders = inspectProviders("rule", raw["rule-providers"])
	b, _ := json.Marshal(res)
	return string(b)
}

// SaveSelection records group → node for a profile (used while disconnected; applied after the next
// start). node == "" removes the entry.
func SaveSelection(profilePath, group, node string) string {
	defer lockPath(selectionsPath(profilePath))() // v0.19.6: one read-modify-write of the file at a time
	m := readSelections(profilePath)
	if node == "" {
		delete(m, group)
	} else {
		m[group] = node
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := writeAtomic(selectionsPath(profilePath), b); err != nil {
		return err.Error()
	}
	return ""
}
