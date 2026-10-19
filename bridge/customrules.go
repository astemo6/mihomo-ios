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
	"errors"
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
	Tag      string // QX tag= (provider display name)
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
		case "tag":
			sp.Tag = strings.TrimSpace(v)
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
// v0.8.1: the provider gets a readable name (QX tag or the list's file name, de-duplicated) and keeps
// its source URL in x-source for the UI; the cache file name stays hash-based (shared with the app's
// resource downloads). A provider for the same list that is already in the profile is reused.
func addRemoteProvider(raw map[string]any, o Overrides, sp remoteSpec) string {
	rp, _ := raw["rule-providers"].(map[string]any)
	if rp == nil {
		rp = map[string]any{}
	}
	path := "./ruleset/" + providerNameFor(sp.URL, sp.Kind) + ".txt"
	for n, v := range rp {
		if m, ok := v.(map[string]any); ok && str(m["path"]) == path {
			return "RULE-SET," + n
		}
	}
	name := uniqueProviderName(prettyProviderName(sp.URL, sp.Tag), func(s string) bool { _, ok := rp[s]; return ok })
	behavior := "classical"
	if sp.Kind == "domainset" {
		behavior = "domain"
	}
	interval := sp.Interval
	if interval <= 0 {
		interval = 86400
	}
	rp[name] = map[string]any{
		"type":     "http",
		"behavior": behavior,
		"format":   "text",
		"url":      ruleConvertURL(o, sp.URL, sp.Kind),
		"header":   map[string]any{"Authorization": []any{"Bearer " + o.Secret}},
		"proxy":    "DIRECT",
		"path":     path,
		"interval": interval,
		"x-source": sp.URL,
	}
	raw["rule-providers"] = rp
	return "RULE-SET," + name
}

func ruleConvertURL(o Overrides, src, kind string) string {
	return fmt.Sprintf("http://127.0.0.1:%d/rules/convert?%s", o.ControllerPort, url.Values{"url": {src}, "kind": {kind}}.Encode())
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
	o := readOverrides(curHomeStr())
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
	o := overridesFor(homeDir, profilePath)
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
	ok, skipped := convertListTo(&sb, r, kind)
	return sb.String(), ok, skipped
}

// convertListTo converts a rule list read from r line by line and writes the mihomo lines to w.
// v0.19.6 (review 7): the list used to be read whole, copied to a string for the Egern check, scanned
// and built into a second string before the handler wrote it: ≈3.4× the download in the extension's heap
// (16 MB cap → ~55 MB, over the ~50 MB budget). Lines are now streamed from the download to the response;
// only an Egern YAML rule set (recognised by its first meaningful line, small in practice) is read whole.
func convertListTo(w io.Writer, r io.Reader, kind string) (int, int) {
	br := bufio.NewReaderSize(r, 64<<10)
	ok, skipped := 0, 0
	first := true
	decided := false
	var head []string // lines before the first meaningful one (comments / blanks), kept for the Egern path
	emit := func(line string) {
		l, good := mitm.ConvertListLine(line, kind)
		if !good {
			if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "#") && !strings.HasPrefix(t, ";") && !strings.HasPrefix(t, "//") && t != "payload:" {
				skipped++
			}
			return
		}
		_, _ = io.WriteString(w, l)
		_, _ = io.WriteString(w, "\n")
		ok++
	}
	for {
		// ReadString has no line-length limit (v0.19.2: one over-long line must not drop the rest).
		line, err := br.ReadString('\n')
		if line != "" {
			if first {
				// v0.19.2: a UTF-8 BOM (lists saved on Windows) made the first rule unparseable.
				line = strings.TrimPrefix(line, "\ufeff")
				first = false
			}
			line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
			if !decided {
				head = append(head, line)
				t := strings.TrimSpace(line)
				if t != "" && !strings.HasPrefix(t, "#") && t != "no_resolve: true" && t != "no_resolve: false" {
					decided = true
					if mitm.IsEgernRuleSet(strings.Join(head, "\n")) {
						rest, _ := io.ReadAll(br)
						lines, sk := mitm.ConvertEgernRuleSet(strings.Join(head, "\n") + "\n" + string(rest))
						for _, l := range lines {
							_, _ = io.WriteString(w, l)
							_, _ = io.WriteString(w, "\n")
						}
						return len(lines), sk
					}
					for _, h := range head {
						emit(h)
					}
					head = nil
				}
			} else {
				emit(line)
			}
		}
		if err != nil {
			break
		}
	}
	for _, h := range head { // only comments / blanks / no_resolve lines
		emit(h)
	}
	return ok, skipped
}

// convertNodesText turns a downloaded subscription into a proxy-provider YAML: Clash / mihomo YAML passes
// through, anything else (QX / Surge / Loon lines, share links, base64) goes through parseNodeText.
func convertNodesText(data []byte) ([]byte, int, error) {
	t := strings.TrimSpace(strings.TrimPrefix(string(data), "\ufeff"))
	if strings.Contains(t, "proxies:") {
		return data, -1, nil
	}
	ps, _ := parseNodeText(t)
	if len(ps) == 0 {
		return nil, 0, errors.New("no nodes recognised")
	}
	// v0.19.6: one JSON flow line per node instead of yaml.Marshal (5k nodes: +60 MB → a few MB in the extension).
	b, err := marshalProxiesYAML(ps)
	return b, len(ps), err
}

func convertRoutes(r chi.Router) {
	r.Get("/nodes/convert", func(w mhttp.ResponseWriter, req *mhttp.Request) {
		src := req.URL.Query().Get("url")
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
		up.Header.Set("User-Agent", "clash.meta mihomo-ios")
		resp, err := cl.Do(up)
		if err != nil {
			log.Warnln("[Nodes] download %s: %v", redactURL(src), err)
			w.WriteHeader(mhttp.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			w.WriteHeader(mhttp.StatusBadGateway)
			return
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		out, n, err := convertNodesText(data)
		if err != nil {
			log.Warnln("[Nodes] %s: %v", redactURL(src), err)
			w.WriteHeader(mhttp.StatusBadGateway)
			return
		}
		if n >= 0 {
			log.Infoln("[Nodes] converted %d node(s)", n)
		}
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		_, _ = w.Write(out)
	})

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
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		bw := bufio.NewWriterSize(w, 32<<10) // v0.19.6: streamed (see convertListTo)
		ok, skipped := convertListTo(bw, io.LimitReader(resp.Body, 16<<20), kind)
		_ = bw.Flush()
		if skipped > 0 {
			log.Infoln("[RuleSet] %s: %d 条已转换，%d 条不支持已跳过", src, ok, skipped)
		}
	})
}

// redactURL keeps only scheme and host for logs (subscription URLs carry tokens).
func redactURL(s string) string {
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		return u.Scheme + "://" + u.Host + "/…"
	}
	return "(url)"
}
