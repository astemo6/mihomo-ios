package mitm

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Item is one user rewrite / script line with an enable switch.
type Item struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	Line    string `json:"line"`
	Note    string `json:"note,omitempty"`
}

// Module is an imported .sgmodule / QX snippet / Loon plugin / Stash override / rule list.
// Its text is cached by the app at <home>/engine/modules/<id>.txt.
type Module struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	URL       string            `json:"url"`
	Enabled   bool              `json:"enabled"`
	Args      map[string]string `json:"args,omitempty"`
	Policies  map[string]string `json:"policies,omitempty"` // module policy name → profile group (user's pick)
	UpdatedAt float64           `json:"updatedAt,omitempty"`
	Interval  int               `json:"interval,omitempty"` // auto-update interval in seconds (0 = 1 day)
}

// Config mirrors <home>/engine/engine.json written by the app.
type Config struct {
	Enabled        bool     `json:"enabled"`        // rewrite + scripts master switch
	MitM           bool     `json:"mitm"`           // HTTPS decryption master switch
	SkipCertVerify bool     `json:"skipCertVerify"` // do not verify upstream certificates
	H2             *bool    `json:"h2,omitempty"`   // offer h2 to clients (default true)
	CaptureBodies  *bool    `json:"captureBodies,omitempty"`
	Hostnames      []string `json:"hostnames"`
	Rules          []Item   `json:"rules"`
	Scripts        []Item   `json:"scripts"`
	Modules        []Module `json:"modules"`
	// Per remote script URL (resource manager): disable it, or override its update interval.
	ScriptResources map[string]ScriptResource `json:"scriptResources,omitempty"`
	// QUIC: "" / "mitm" = block UDP 443 only for MitM hosts (they fall back to TCP and can be decrypted;
	// everything else may use HTTP/3), "all" = block QUIC for all traffic.
	QUIC string `json:"quic,omitempty"`
	// MitM hosts whose QUIC is NOT blocked (their HTTP/3 traffic then bypasses decryption).
	QUICAllow []string `json:"quicAllow,omitempty"`
}

// ScriptResource is the user's per-script setting from the resource manager.
type ScriptResource struct {
	Disabled bool `json:"disabled,omitempty"`
	Interval int  `json:"interval,omitempty"` // seconds, 0 = the script line's own value
}

// scriptAllowed reports whether a script path is enabled, applying an interval override to sc.
func (c *Config) scriptAllowed(sc *Script) bool {
	if sc == nil || c.ScriptResources == nil {
		return true
	}
	r, ok := c.ScriptResources[sc.Path]
	if !ok {
		return true
	}
	if r.Interval > 0 {
		sc.UpdateInterval = r.Interval
	}
	return !r.Disabled
}

// filterScripts drops rules / tasks / panels whose script the user disabled in the resource manager.
func (c *Config) filterScripts(rs *Ruleset) {
	if len(c.ScriptResources) == 0 {
		return
	}
	rules := rs.Rules[:0]
	for _, r := range rs.Rules {
		if r.Kind == KindScript && !c.scriptAllowed(r.Script) {
			continue
		}
		rules = append(rules, r)
	}
	rs.Rules = rules
	tasks := rs.Tasks[:0]
	off := map[string]bool{}
	for _, t := range rs.Tasks {
		if !c.scriptAllowed(t.Script) {
			off[t.Script.Name] = true
			continue
		}
		tasks = append(tasks, t)
	}
	rs.Tasks = tasks
	panels := rs.Panels[:0]
	for _, p := range rs.Panels {
		if p.Script != "" && off[p.Script] {
			continue
		}
		panels = append(panels, p)
	}
	rs.Panels = panels
}

func (c *Config) h2() bool         { return c.H2 == nil || *c.H2 }
func (c *Config) capture() bool    { return c.CaptureBodies == nil || *c.CaptureBodies }
func EngineDir(home string) string { return filepath.Join(home, "engine") }
func ModulePath(home, id string) string {
	return filepath.Join(EngineDir(home), "modules", safeName(id)+".txt")
}
func ScriptsDir(home string) string { return filepath.Join(EngineDir(home), "scripts") }

func safeName(s string) string {
	b := []byte(s)
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			b[i] = '_'
		}
	}
	return string(b)
}

// LoadConfig reads engine.json (missing file => disabled engine).
func LoadConfig(home string) *Config {
	c := &Config{}
	b, err := os.ReadFile(filepath.Join(EngineDir(home), "engine.json"))
	if err == nil {
		_ = json.Unmarshal(b, c)
	}
	return c
}

// Build parses everything that is enabled into one Ruleset.
func Build(home string, c *Config) *Ruleset {
	rs := &Ruleset{}
	if c == nil {
		return rs
	}
	rs.addHosts(strings.Join(c.Hostnames, ","))
	if c.Enabled {
		for _, it := range c.Rules {
			if it.Enabled {
				rs.ParseLine(it.Line, "", "用户")
			}
		}
		for _, it := range c.Scripts {
			if it.Enabled {
				rs.ParseLine(it.Line, "script", "用户")
			}
		}
		for _, m := range c.Modules {
			if !m.Enabled {
				continue
			}
			b, err := os.ReadFile(ModulePath(home, m.ID))
			if err != nil {
				rs.Errors = append(rs.Errors, fmt.Sprintf("模块 %s 未下载", m.Name))
				continue
			}
			sub := &Ruleset{}
			sub.ParseText(string(b), m.Name, m.Args)
			rs.Rules = append(rs.Rules, sub.Rules...)
			rs.Tasks = append(rs.Tasks, sub.Tasks...)
			rs.Panels = append(rs.Panels, sub.Panels...)
			rs.Hostnames = append(rs.Hostnames, sub.Hostnames...)
			for _, r := range sub.CoreRules {
				rs.CoreRules = append(rs.CoreRules, mapPolicy(r, m.Policies))
			}
			for _, e := range sub.Errors {
				rs.Errors = append(rs.Errors, m.Name+"："+e)
			}
			if sub.SkipCertVerify != nil && *sub.SkipCertVerify {
				rs.SkipCertVerify = sub.SkipCertVerify
			}
		}
	}
	c.filterScripts(rs)
	rs.Hostnames = dedupe(rs.Hostnames)
	return rs
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ---- hostname matching ----

type hostPat struct {
	pat  string
	port int // 0 = default (443)
}

// HostMatcher implements Surge `hostname` semantics: wildcards * and ?, `-` prefix excludes,
// optional :port (default 443).
type HostMatcher struct {
	inc, exc []hostPat
}

func splitHostPort(h string) (string, int) {
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[:i], ":") {
		if p, err := strconv.Atoi(h[i+1:]); err == nil {
			return h[:i], p
		}
	}
	return h, 0
}

// NewHostMatcher builds a matcher from a hostname list.
func NewHostMatcher(list []string) *HostMatcher {
	m := &HostMatcher{}
	for _, h := range list {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		ex := strings.HasPrefix(h, "-")
		h = strings.TrimPrefix(h, "-")
		host, port := splitHostPort(h)
		p := hostPat{pat: host, port: port}
		if ex {
			m.exc = append(m.exc, p)
		} else {
			m.inc = append(m.inc, p)
		}
	}
	return m
}

func (p hostPat) match(host string, port int) bool {
	want := p.port
	if want == 0 {
		want = 443
	}
	if port != want && !(p.port == 0 && port == 0) {
		return false
	}
	return globMatch(p.pat, host)
}

// Empty reports whether no host is selected for MitM.
func (m *HostMatcher) Empty() bool { return len(m.inc) == 0 }

// Match reports whether host:port should be decrypted.
func (m *HostMatcher) Match(host string, port int) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, p := range m.exc {
		if globMatch(p.pat, host) && (p.port == 0 || p.port == port) {
			return false
		}
	}
	for _, p := range m.inc {
		if p.match(host, port) {
			return true
		}
	}
	return false
}

// Ports returns all TCP ports that carry MitM hosts.
func (m *HostMatcher) Ports() []int {
	set := map[int]bool{}
	for _, p := range m.inc {
		if p.port == 0 {
			set[443] = true
		} else {
			set[p.port] = true
		}
	}
	var out []int
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

func globMatch(pat, s string) bool {
	if pat == "*" || pat == s {
		return true
	}
	// iterative glob with * and ?
	px, sx := 0, 0
	nextPx, nextSx := -1, -1
	for px < len(pat) || sx < len(s) {
		if px < len(pat) {
			c := pat[px]
			switch c {
			case '*':
				nextPx, nextSx = px, sx+1
				px++
				continue
			case '?':
				if sx < len(s) {
					px++
					sx++
					continue
				}
			default:
				if sx < len(s) && s[sx] == c {
					px++
					sx++
					continue
				}
			}
		}
		if nextSx > 0 && nextSx <= len(s) {
			px, sx = nextPx, nextSx
			continue
		}
		return false
	}
	return true
}

func payloadFor(p hostPat) string {
	if ip := net.ParseIP(p.pat); ip != nil {
		if ip.To4() != nil {
			return "IP-CIDR," + p.pat + "/32,no-resolve"
		}
		return "IP-CIDR6," + p.pat + "/128,no-resolve"
	}
	if strings.ContainsAny(p.pat, "*?") {
		return "DOMAIN-WILDCARD," + p.pat
	}
	return "DOMAIN," + p.pat
}

// ProxyName is the mihomo outbound that points at the local engine listener.
const ProxyName = "__MITM__"

// Inject adds the engine outbound, host rule-sets and the steering rules to a mihomo config map.
// listenPort is the engine's 127.0.0.1 port. httpPlain routes all port-80 TCP into the engine
// (needed for plain-HTTP rewrites / scripts).
func Inject(raw map[string]any, listenPort int, rs *Ruleset, c *Config) {
	m := NewHostMatcher(rs.Hostnames)
	mitmOn := c.MitM && !m.Empty()
	httpPlain := c.Enabled && len(rs.Rules) > 0
	var pre []any
	if mitmOn || httpPlain {
		proxies, _ := raw["proxies"].([]any)
		proxies = append(proxies, map[string]any{"name": ProxyName, "type": "http", "server": "127.0.0.1", "port": listenPort})
		raw["proxies"] = proxies
	}
	if mitmOn {
		rp, _ := raw["rule-providers"].(map[string]any)
		if rp == nil {
			rp = map[string]any{}
		}
		var inc, exc []any
		for _, p := range m.inc {
			inc = append(inc, payloadFor(p))
		}
		for _, p := range m.exc {
			exc = append(exc, payloadFor(p))
		}
		rp["__mitm_hosts"] = map[string]any{"type": "inline", "behavior": "classical", "payload": inc}
		skip := ""
		if len(exc) > 0 {
			rp["__mitm_skip"] = map[string]any{"type": "inline", "behavior": "classical", "payload": exc}
			skip = ",(NOT,((RULE-SET,__mitm_skip)))"
		}
		raw["rule-providers"] = rp
		ports := make([]string, 0)
		for _, p := range m.Ports() {
			ports = append(ports, strconv.Itoa(p))
		}
		portExpr := strings.Join(ports, "/")
		// Block QUIC to MitM hosts so clients fall back to TCP (HTTP/3 can't be intercepted), except
		// for hosts the user allowed QUIC for.
		quicSkip := skip
		if allow := quicAllowPayload(c.QUICAllow); len(allow) > 0 {
			rp["__quic_allow"] = map[string]any{"type": "inline", "behavior": "classical", "payload": allow}
			quicSkip += ",(NOT,((RULE-SET,__quic_allow)))"
		}
		pre = append(pre, fmt.Sprintf("AND,((NETWORK,UDP),(DST-PORT,%s),(RULE-SET,__mitm_hosts)%s),REJECT", portExpr, quicSkip))
		pre = append(pre, fmt.Sprintf("AND,((NETWORK,TCP),(NOT,((IN-TYPE,INNER))),(DST-PORT,%s),(RULE-SET,__mitm_hosts)%s),%s", portExpr, skip, ProxyName))
	}
	if httpPlain {
		pre = append(pre, fmt.Sprintf("AND,((NETWORK,TCP),(NOT,((IN-TYPE,INNER))),(DST-PORT,80)),%s", ProxyName))
	}
	if c.Enabled {
		for _, r := range ResolveCoreRules(raw, rs.CoreRules, nil) {
			pre = append(pre, r)
		}
	}
	if len(pre) == 0 {
		return
	}
	rules, _ := raw["rules"].([]any)
	raw["rules"] = append(pre, rules...)
}

func quicAllowPayload(list []string) []any {
	var out []any
	for _, h := range list {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		host, _ := splitHostPort(h)
		out = append(out, payloadFor(hostPat{pat: host}))
	}
	return out
}

// QUICBlockAllRule is prepended when the user blocks QUIC for all traffic.
const QUICBlockAllRule = "AND,((NETWORK,UDP),(DST-PORT,443),(NOT,((IN-TYPE,INNER)))),REJECT"

// mapPolicy replaces the policy of a module rule with the user's chosen group for it.
func mapPolicy(rule string, m map[string]string) string {
	if len(m) == 0 {
		return rule
	}
	parts := splitTop(rule)
	idx := policyIndex(parts)
	if idx < 0 {
		return rule
	}
	if to, ok := m[parts[idx]]; ok && to != "" {
		parts[idx] = to
	}
	return strings.Join(parts, ",")
}

func policyIndex(parts []string) int {
	if len(parts) < 2 {
		return -1
	}
	if strings.ToUpper(parts[0]) == "MATCH" {
		return 1
	}
	if len(parts) < 3 {
		return -1
	}
	return 2
}

// ResolveCoreRules maps each rule's policy onto the profile (see ResolvePolicy). Rules whose policy
// does not exist are dropped and reported through unresolved (if non-nil). Remote RULE-SET /
// DOMAIN-SET URLs are left for the bridge to turn into providers.
func ResolveCoreRules(raw map[string]any, rules []string, unresolved map[string]bool) []string {
	groups, proxies, first := ProfileNames(raw)
	var out []string
	for _, r := range rules {
		parts := splitTop(r)
		idx := policyIndex(parts)
		if idx < 0 {
			continue
		}
		if t := strings.ToUpper(parts[0]); (t == "RULE-SET" || t == "DOMAIN-SET") && strings.Contains(parts[1], "://") {
			continue
		}
		pol, ok := ResolvePolicy(parts[idx], groups, proxies, first)
		if !ok {
			if unresolved != nil {
				unresolved[parts[idx]] = true
			}
			continue
		}
		parts[idx] = pol
		out = append(out, strings.Join(parts, ","))
	}
	return out
}

// UnresolvedPolicies lists the module policy names that have no group in raw.
func UnresolvedPolicies(raw map[string]any, rules []string) []string {
	un := map[string]bool{}
	ResolveCoreRules(raw, rules, un)
	out := []string{}
	for k := range un {
		out = append(out, k)
	}
	return out
}

// RemoteCoreRules returns module rules that reference remote Surge RULE-SET / DOMAIN-SET lists.
func RemoteCoreRules(rules []string) []string {
	var out []string
	for _, r := range rules {
		parts := splitTop(r)
		if len(parts) >= 3 && strings.Contains(parts[1], "://") {
			if t := strings.ToUpper(parts[0]); t == "RULE-SET" || t == "DOMAIN-SET" {
				out = append(out, r)
			}
		}
	}
	return out
}
