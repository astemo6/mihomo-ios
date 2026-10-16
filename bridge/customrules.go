package libmihomo

// Custom rules (规则 → 自定义规则) written in Surge / Quantumult X / Loon / mihomo syntax, and remote
// Surge RULE-SET / DOMAIN-SET / QX filter_remote lists. Lines are translated by mitm/rules.go; remote
// lists become mihomo rule-providers fetched through /rules/convert on the local controller, which
// downloads through the core's own rules and rewrites each line into mihomo classical text.

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	mhttp "github.com/metacubex/http"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
	"github.com/metacubex/chi"
	"github.com/metacubex/mihomo/hub/route"
	"github.com/metacubex/mihomo/log"

	"go.yaml.in/yaml/v3"
)

func init() { route.Register(convertRoutes) }

// CustomRule is one entry of <home>/rules.json.
type CustomRule struct {
	ID       string `json:"id"`
	Line     string `json:"line"`
	Enabled  bool   `json:"enabled"`
	Interval int    `json:"interval,omitempty"` // remote lists: seconds, default 86400
}

type customRulesFile struct {
	Rules []CustomRule `json:"rules"`
}

func readCustomRules(home string) []CustomRule {
	if home == "" {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(home, "rules.json"))
	if err != nil {
		return nil
	}
	var f customRulesFile
	_ = json.Unmarshal(b, &f)
	return f.Rules
}

type remoteSpec struct {
	URL      string
	Kind     string // list | domainset
	Policy   string
	Interval int
}

// parseQXRemote reads a QX filter_remote line: "https://x.list, tag=名称, force-policy=Proxy, update-interval=86400, enabled=true".
func parseQXRemote(line string) (remoteSpec, bool) {
	parts := strings.Split(line, ",")
	u := strings.TrimSpace(parts[0])
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return remoteSpec{}, false
	}
	sp := remoteSpec{URL: u, Kind: "list", Policy: "proxy", Interval: 86400}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "force-policy":
			sp.Policy = strings.TrimSpace(v)
		case "update-interval":
			if n := atoi(v, 0); n > 0 {
				sp.Interval = n
			}
		case "enabled":
			if !truthy(v) {
				return remoteSpec{}, false
			}
		}
	}
	return sp, true
}

func providerNameFor(u, kind string) string {
	h := sha1.Sum([]byte(kind + "|" + u))
	return "custom-" + hex.EncodeToString(h[:4])
}

// addRemoteProvider adds a converted rule-provider for sp and returns its RULE-SET rule (without policy).
func addRemoteProvider(raw map[string]any, o Overrides, sp remoteSpec) string {
	name := providerNameFor(sp.URL, sp.Kind)
	rp, _ := raw["rule-providers"].(map[string]any)
	if rp == nil {
		rp = map[string]any{}
	}
	behavior := "classical"
	if sp.Kind == "domainset" {
		behavior = "domain"
	}
	interval := sp.Interval
	if interval <= 0 {
		interval = 86400
	}
	q := url.Values{"url": {sp.URL}, "kind": {sp.Kind}}
	rp[name] = map[string]any{
		"type":     "http",
		"behavior": behavior,
		"format":   "text",
		"url":      fmt.Sprintf("http://127.0.0.1:%d/rules/convert?%s", o.ControllerPort, q.Encode()),
		"header":   map[string]any{"Authorization": []any{"Bearer " + o.Secret}},
		"proxy":    "DIRECT",
		"path":     "./ruleset/" + name + ".txt",
		"interval": interval,
	}
	raw["rule-providers"] = rp
	return "RULE-SET," + name
}

type ruleCheck struct {
	ID         string `json:"id"`
	Line       string `json:"line"`
	Enabled    bool   `json:"enabled"`
	Rule       string `json:"rule,omitempty"`
	Policy     string `json:"policy,omitempty"`
	Error      string `json:"error,omitempty"`
	Note       string `json:"note,omitempty"`
	Unresolved string `json:"unresolved,omitempty"`
}

// convertCustom turns custom rules into resolved mihomo rules for this profile, plus per-line diagnostics.
func convertCustom(raw map[string]any, o Overrides, rules []CustomRule) ([]any, []ruleCheck) {
	groups, proxies, first := mitm.ProfileNames(raw)
	var out []any
	var checks []ruleCheck
	for _, r := range rules {
		ck := ruleCheck{ID: r.ID, Line: r.Line, Enabled: r.Enabled}
		line := strings.TrimSpace(r.Line)
		var conv mitm.RuleConv
		var err error
		interval := r.Interval
		if sp, ok := parseQXRemote(line); ok {
			conv = mitm.RuleConv{Type: "RULE-SET", RemoteURL: sp.URL, RemoteKind: "list", Policy: sp.Policy}
			if interval == 0 {
				interval = sp.Interval
			}
			if !strings.Contains(strings.ToLower(line), "force-policy") {
				ck.Note = "QX 远程列表未指定 force-policy：整份列表使用 proxy（第一个手动选择组），列表内各行的策略被忽略"
			}
		} else {
			conv, err = mitm.ConvertRuleLine(line)
		}
		if err != nil {
			ck.Error = err.Error()
			checks = append(checks, ck)
			continue
		}
		if conv.Rule == "" && conv.RemoteURL == "" {
			checks = append(checks, ck)
			continue
		}
		if ck.Note == "" {
			ck.Note = conv.Note
		}
		pol, ok := mitm.ResolvePolicy(conv.Policy, groups, proxies, first)
		if !ok {
			ck.Error = fmt.Sprintf("策略「%s」在当前配置中不存在", conv.Policy)
			ck.Unresolved = conv.Policy
			checks = append(checks, ck)
			continue
		}
		ck.Policy = pol
		var rule string
		if conv.RemoteURL != "" {
			if !r.Enabled {
				ck.Rule = fmt.Sprintf("RULE-SET,<%s>,%s", conv.RemoteURL, pol)
				checks = append(checks, ck)
				continue
			}
			rule = addRemoteProvider(raw, o, remoteSpec{URL: conv.RemoteURL, Kind: conv.RemoteKind, Policy: pol, Interval: interval}) + "," + pol + conv.Options
		} else {
			rule = conv.Format(pol)
		}
		ck.Rule = rule
		checks = append(checks, ck)
		if r.Enabled {
			out = append(out, rule)
		}
	}
	return out, checks
}

// applyCustomRules prepends the user's custom rules (they win over the profile's rules).
func applyCustomRules(raw map[string]any, o Overrides) {
	rules := readCustomRules(o.home)
	if len(rules) == 0 {
		return
	}
	pre, _ := convertCustom(raw, o, rules)
	if len(pre) == 0 {
		return
	}
	existing, _ := raw["rules"].([]any)
	raw["rules"] = append(pre, existing...)
}

// addRemoteModuleRules turns module RULE-SET / DOMAIN-SET URLs into converted providers.
func addRemoteModuleRules(raw map[string]any, coreRules []string) {
	remote := mitm.RemoteCoreRules(coreRules)
	if len(remote) == 0 {
		return
	}
	o := readOverrides(curHome)
	var rs []CustomRule
	for i, r := range remote {
		rs = append(rs, CustomRule{ID: fmt.Sprint(i), Line: r, Enabled: true})
	}
	pre, checks := convertCustom(raw, o, rs)
	for _, c := range checks {
		if c.Error != "" {
			log.Warnln("[Module] %s: %s", c.Line, c.Error)
		}
	}
	existing, _ := raw["rules"].([]any)
	raw["rules"] = append(pre, existing...)
}

// CheckCustomRules returns JSON diagnostics for <home>/rules.json against the profile at profilePath.
func CheckCustomRules(homeDir, profilePath string) string {
	raw := profileRaw(homeDir, profilePath)
	_, checks := convertCustom(raw, readOverrides(homeDir), readCustomRules(homeDir))
	if checks == nil {
		checks = []ruleCheck{}
	}
	b, _ := json.Marshal(checks)
	return string(b)
}

// CheckRuleLine translates one line against the profile (live validation in the editor).
func CheckRuleLine(homeDir, profilePath, line string) string {
	raw := profileRaw(homeDir, profilePath)
	_, checks := convertCustom(raw, readOverrides(homeDir), []CustomRule{{ID: "1", Line: line, Enabled: true}})
	if len(checks) == 0 {
		return "{}"
	}
	b, _ := json.Marshal(checks[0])
	return string(b)
}

// ProfileGroups returns JSON ["group", …] of the profile's policy groups (targets for pickers).
func ProfileGroups(homeDir, profilePath string) string {
	g, _, _ := mitm.ProfileNames(profileRaw(homeDir, profilePath))
	if g == nil {
		g = []string{}
	}
	b, _ := json.Marshal(g)
	return string(b)
}

// ModuleUnresolved returns JSON ["policy", …]: policies a module's [Rule] lines use that the profile lacks.
func ModuleUnresolved(homeDir, profilePath, moduleText, argsJSON string) string {
	args := map[string]string{}
	_ = json.Unmarshal([]byte(argsJSON), &args)
	rs := &mitm.Ruleset{}
	rs.ParseText(moduleText, "模块", args)
	b, _ := json.Marshal(mitm.UnresolvedPolicies(profileRaw(homeDir, profilePath), rs.CoreRules))
	return string(b)
}

func profileRaw(homeDir, profilePath string) map[string]any {
	raw := map[string]any{}
	b, err := os.ReadFile(profilePath)
	if err != nil {
		return raw
	}
	o := readOverrides(homeDir)
	o.home = "" // don't recurse into custom rules
	if rt, err := buildRuntime(b, o, 0); err == nil {
		_ = yaml.Unmarshal(rt, &raw)
	}
	return raw
}

// ---------------- /rules/convert ----------------

// convertListText rewrites a Surge / Loon / Stash / QX list into mihomo text for the provider.
func convertListText(r io.Reader, kind string) (string, int, int) {
	var sb strings.Builder
	ok, skipped := 0, 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l, good := mitm.ConvertListLine(sc.Text(), kind)
		if !good {
			if t := strings.TrimSpace(sc.Text()); t != "" && !strings.HasPrefix(t, "#") && !strings.HasPrefix(t, ";") && !strings.HasPrefix(t, "//") && t != "payload:" {
				skipped++
			}
			continue
		}
		sb.WriteString(l)
		sb.WriteByte('\n')
		ok++
	}
	return sb.String(), ok, skipped
}

func convertRoutes(r chi.Router) {
	r.Get("/rules/convert", func(w mhttp.ResponseWriter, req *mhttp.Request) {
		src := req.URL.Query().Get("url")
		kind := req.URL.Query().Get("kind")
		if !strings.HasPrefix(src, "http://") && !strings.HasPrefix(src, "https://") {
			w.WriteHeader(mhttp.StatusBadRequest)
			return
		}
		tr := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return coreDial(ctx, network, addr, "")
			},
			TLSHandshakeTimeout: 15 * time.Second,
		}
		defer tr.CloseIdleConnections()
		cl := &http.Client{Transport: tr, Timeout: 60 * time.Second}
		up, _ := http.NewRequest("GET", src, nil)
		up.Header.Set("User-Agent", "Surge iOS/3000 mihomo-ios")
		resp, err := cl.Do(up)
		if err != nil {
			log.Warnln("[RuleSet] download %s: %v", src, err)
			w.WriteHeader(mhttp.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			w.WriteHeader(mhttp.StatusBadGateway)
			return
		}
		text, ok, skipped := convertListText(io.LimitReader(resp.Body, 16<<20), kind)
		if skipped > 0 {
			log.Infoln("[RuleSet] %s: %d 条已转换，%d 条不支持已跳过", src, ok, skipped)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, text)
	})
}
