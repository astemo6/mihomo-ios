package libmihomo

// Full-profile import of Surge .conf and Quantumult X .conf (best effort). Translation layer only:
// the result is an ordinary mihomo profile plus, when the file carries rewrite / MitM / script
// sections, a module text for the shared module store. A report lists what could not be carried over.

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/astemo6/mihomo-ios/bridge/mitm"

	"go.yaml.in/yaml/v3"
)

type confReport struct {
	Format    string   `json:"format"` // surge | qx
	Proxies   int      `json:"proxies"`
	Groups    int      `json:"groups"`
	Rules     int      `json:"rules"`
	Providers int      `json:"providers"`
	Module    bool     `json:"module"`
	// v0.8.1: what the module part holds, so the sheet can show counts per section.
	Rewrites  int      `json:"rewrites"`  // rewrite / map-local / header / body lines
	Scripts   int      `json:"scripts"`   // script rewrites
	Tasks     int      `json:"tasks"`     // cron / event tasks
	Hostnames int      `json:"hostnames"` // MitM hostnames
	Remotes   int      `json:"remotes"`   // rewrite_remote modules (incl. disabled)
	Skipped   []string `json:"skipped"`
	Notes     []string `json:"notes"`
}

type remoteModule struct {
	URL      string `json:"url"`
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	Interval int    `json:"interval"`
}

// parseQXRewriteRemote reads "<url>, tag=…, update-interval=…, opt-parser=…, enabled=…" (disabled lines too).
func parseQXRewriteRemote(line string) (remoteModule, bool) {
	parts := strings.Split(line, ",")
	u := strings.TrimSpace(parts[0])
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return remoteModule{}, false
	}
	m := remoteModule{URL: u, Enabled: true, Interval: 86400}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "tag":
			m.Name = v
		case "update-interval":
			if n := atoi(v, 0); n > 0 {
				m.Interval = n
			}
		case "enabled":
			m.Enabled = truthy(v)
		}
	}
	if m.Name == "" {
		m.Name = prettyProviderName(u, "")
	}
	return m, true
}

// confSettings are connection settings a QX [general] section carries (v0.11). They are not part of a
// mihomo profile; the import sheet offers to apply them to the app's own settings.
type confSettings struct {
	ExcludedRoutes []string `json:"excludedRoutes,omitempty"` // excluded_routes
	TrustedSSIDs   []string `json:"trustedSSIDs,omitempty"`   // ssid_suspended_list
	TestURL        string   `json:"testURL,omitempty"`        // server_check_url
	TestTimeoutMs  int      `json:"testTimeoutMs,omitempty"`  // server_check_timeout (≤ 5000)
	BlockQUIC      bool     `json:"blockQUIC,omitempty"`      // udp_drop_list contains QUIC
}

func (c confSettings) empty() bool {
	return len(c.ExcludedRoutes) == 0 && len(c.TrustedSSIDs) == 0 && c.TestURL == "" && c.TestTimeoutMs == 0 && !c.BlockQUIC
}

type confResult struct {
	YAML   string `json:"yaml"`
	Module string `json:"module,omitempty"`
	// RewriteRemotes: QX [rewrite_remote] lines; the app adds each as its own remote module (name from
	// tag= or the file name, enabled= respected, downloaded by the app).
	RewriteRemotes []remoteModule `json:"rewriteRemotes,omitempty"`
	Settings      *confSettings `json:"settings,omitempty"`
	Report        confReport `json:"report"`
	Error         string     `json:"error,omitempty"`
}

var confSectionRe = regexp.MustCompile(`^\[([^\]]+)\]\s*$`)

// Convert-on-download provider URLs: buildRuntime rewrites "convert+<kind>:<url>" to /rules/convert.
const convertScheme = "convert+"

func splitSections(text string) (order []string, secs map[string][]string) {
	secs = map[string][]string{}
	cur := ""
	for _, raw := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		t := strings.TrimSpace(raw)
		if m := confSectionRe.FindStringSubmatch(t); m != nil {
			cur = strings.ToLower(strings.TrimSpace(m[1]))
			if _, ok := secs[cur]; !ok {
				order = append(order, cur)
			}
			secs[cur] = append(secs[cur], "")
			continue
		}
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") || strings.HasPrefix(t, "//") {
			continue
		}
		secs[cur] = append(secs[cur], t)
	}
	return
}

func nonEmpty(l []string) []string {
	var out []string
	for _, s := range l {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func builtinPolicy(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if strings.HasPrefix(s, "REJECT") {
		if s == "REJECT-DROP" {
			return s
		}
		return "REJECT"
	}
	return "DIRECT"
}

// ImportConf converts a Surge or Quantumult X profile to mihomo. Returns JSON {yaml, module, report, error}.
func ImportConf(text string) string {
	res := confResult{Report: confReport{Skipped: []string{}, Notes: []string{}}}
	order, secs := splitSections(text)
	_, isQX := secs["server_local"]
	if _, ok := secs["policy"]; ok {
		isQX = true
	}
	for _, k := range []string{"filter_local", "server_remote", "filter_remote"} {
		if _, ok := secs[k]; ok {
			isQX = true
		}
	}
	if isQX {
		res.Report.Format = "qx"
	} else if _, ok := secs["proxy"]; ok || secs["rule"] != nil {
		res.Report.Format = "surge"
	} else {
		res.Error = "未识别为 Surge 或 Quantumult X 配置（缺少 [Proxy]/[Rule] 或 [server_local]/[policy] 段）"
		b, _ := json.Marshal(res)
		return string(b)
	}
	rep := &res.Report
	// QX [general] keys (v0.11), read up front: server_check_url is the default health-check URL of the
	// generated groups.
	qxGeneral := map[string]string{}
	if isQX {
		for _, l := range nonEmpty(secs["general"]) {
			if k, v, ok := strings.Cut(l, "="); ok {
				qxGeneral[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
			}
		}
	}
	checkURL := "https://www.gstatic.com/generate_204"
	if u := qxGeneral["server_check_url"]; strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		checkURL = u
	}
	checkTimeout := 0
	if n := atoi(qxGeneral["server_check_timeout"], 0); n > 0 {
		checkTimeout = min(n, 5000)
	}
	var proxies []any
	var groups []any
	groupNames := map[string]bool{}
	proxyNames := map[string]bool{}
	skip := func(sec, line, why string) {
		if len(rep.Skipped) < 200 {
			rep.Skipped = append(rep.Skipped, fmt.Sprintf("[%s] %s — %s", sec, line, why))
		}
	}

	// ---- proxies
	proxySec := "proxy"
	if isQX {
		proxySec = "server_local"
	}
	for _, l := range nonEmpty(secs[proxySec]) {
		var p map[string]any
		var err error
		if isQX {
			p, err = parseQXLine(l)
		} else {
			name, rhs, _ := strings.Cut(l, "=")
			name = strings.TrimSpace(name)
			rhs = strings.ToLower(strings.TrimSpace(rhs))
			if strings.HasPrefix(rhs, "direct") || strings.HasPrefix(rhs, "reject") {
				// Surge built-in alias like "Block = reject": a one-member group.
				groups = append(groups, map[string]any{"name": name, "type": "select", "proxies": []any{builtinPolicy(strings.SplitN(rhs, ",", 2)[0])}})
				groupNames[name] = true
				continue
			}
			p, err = parseSurgeLine(l)
		}
		if err != nil {
			skip(proxySec, l, err.Error())
			continue
		}
		proxies = append(proxies, p)
		proxyNames[strOf(p["name"])] = true
	}
	// [server_remote] (v0.8.1): each subscription becomes a mihomo proxy-provider, downloaded through the
	// local /nodes/convert endpoint (QX / Surge lines, share links, base64 or Clash YAML → proxies).
	proxyProviders := map[string]any{}
	var providerTags []string // provider names in file order
	var asPolicy [][2]string  // v0.11: [server_remote] as-policy → a group named after the subscription
	if isQX {
		for _, l := range nonEmpty(secs["server_remote"]) {
			sp, ok := parseQXServerRemote(l)
			if !ok {
				skip("server_remote", l, "无效或已禁用")
				continue
			}
			name := sp.Tag
			if name == "" {
				name = prettyProviderName(sp.URL, "")
			}
			name = uniqueProviderName(name, func(n string) bool { return proxyProviders[n] != nil })
			proxyProviders[name] = map[string]any{
				"type": "http", "url": sp.URL, "x-convert": "nodes", "path": "./proxies/" + providerNameFor(sp.URL, "nodes") + ".yaml",
				"interval":     sp.Interval,
				"health-check": map[string]any{"enable": true, "url": checkURL, "interval": 600, "lazy": true},
			}
			providerTags = append(providerTags, name)
			if sp.AsPolicy != "" {
				asPolicy = append(asPolicy, [2]string{name, sp.AsPolicy})
			}
		}
	}

	// ---- groups
	type pendingGroup struct {
		name, typ string
		qxType    string // v0.11: the QX policy keyword (static / available / round-robin / dest-hash / …)
		members   []string
		opts      map[string]string
	}
	var pg []pendingGroup
	parseGroup := func(name, typ string, parts []string) pendingGroup {
		g := pendingGroup{name: strings.TrimSpace(name), typ: typ, opts: map[string]string{}}
		for _, p := range parts {
			if kk, vv, ok := strings.Cut(p, "="); ok {
				g.opts[strings.ToLower(strings.TrimSpace(kk))] = strings.TrimSpace(vv)
				continue
			}
			g.members = append(g.members, strings.TrimSpace(p))
		}
		return g
	}
	if isQX {
		qxGroupType := map[string]string{"static": "select", "available": "fallback", "round-robin": "load-balance", "url-latency-benchmark": "url-test", "dest-hash": "load-balance", "ssid": "select"}
		for _, l := range nonEmpty(secs["policy"]) {
			k, v, ok := strings.Cut(l, "=")
			if !ok {
				continue
			}
			typ, known := qxGroupType[strings.ToLower(strings.TrimSpace(k))]
			if !known {
				skip("policy", l, "不支持的策略类型")
				continue
			}
			parts := splitParams(v)
			if len(parts) == 0 {
				continue
			}
			g := parseGroup(parts[0], typ, parts[1:])
			g.qxType = strings.ToLower(strings.TrimSpace(k))
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(k)), "ssid") {
				rep.Notes = append(rep.Notes, "SSID 策略组「"+g.name+"」按普通选择组导入（不随 Wi-Fi 切换）")
			}
			pg = append(pg, g)
		}
	} else {
		for _, l := range nonEmpty(secs["proxy group"]) {
			name, v, ok := strings.Cut(l, "=")
			if !ok {
				continue
			}
			parts := splitParams(v)
			if len(parts) == 0 {
				continue
			}
			t := strings.ToLower(strings.TrimSpace(parts[0]))
			typ := map[string]string{"select": "select", "url-test": "url-test", "fallback": "fallback", "load-balance": "load-balance", "smart": "url-test"}[t]
			if typ == "" {
				skip("Proxy Group", l, "不支持的策略组类型 "+t)
				continue
			}
			if t == "smart" {
				rep.Notes = append(rep.Notes, "Surge smart 组「"+strings.TrimSpace(name)+"」转为 url-test")
			}
			pg = append(pg, parseGroup(name, typ, parts[1:]))
		}
	}
	for _, a := range asPolicy {
		if groupNames[a[0]] {
			continue
		}
		typ, known := map[string]string{"static": "select", "available": "fallback", "round-robin": "load-balance", "url-latency-benchmark": "url-test", "dest-hash": "load-balance"}[strings.ToLower(a[1])]
		if !known {
			rep.Notes = append(rep.Notes, "订阅「"+a[0]+"」的 as-policy="+a[1]+" 不支持，未生成策略组")
			continue
		}
		g := pendingGroup{name: a[0], typ: typ, qxType: strings.ToLower(a[1]), opts: map[string]string{"resource-tag-regex": "^" + regexp.QuoteMeta(a[0]) + "$"}}
		pg = append(pg, g)
		groupNames[a[0]] = true
	}
	for _, g := range pg {
		groupNames[g.name] = true
	}
	providers := map[string]any{}
	for _, g := range pg {
		m := map[string]any{"name": g.name, "type": g.typ}
		var members []any
		for _, mem := range g.members {
			u := strings.ToUpper(mem)
			switch {
			case u == "DIRECT" || strings.HasPrefix(u, "REJECT"):
				members = append(members, builtinPolicy(u))
			case groupNames[mem] || proxyNames[mem]:
				members = append(members, mem)
			case u == "PROXY" && isQX:
				skip("group "+g.name, mem, "QX 的 proxy 成员没有对应项，已忽略")
			default:
				skip("group "+g.name, mem, "成员不存在")
			}
		}
		if pp := g.opts["policy-path"]; strings.Contains(pp, "://") {
			rep.Notes = append(rep.Notes, "策略组「"+g.name+"」的 policy-path 远程节点列表未导入，请把该订阅作为单独配置添加")
		}
		if re := firstNonEmpty(g.opts["policy-regex-filter"], g.opts["server-tag-regex"]); re != "" {
			m["filter"] = re
			if len(providerTags) > 0 {
				m["include-all"] = true // inline proxies + every provider
			} else {
				m["include-all-proxies"] = true
			}
		}
		if re := g.opts["resource-tag-regex"]; re != "" && len(providerTags) > 0 {
			var use []any
			if rx, err := regexp.Compile(re); err == nil {
				for _, t := range providerTags {
					if rx.MatchString(t) {
						use = append(use, t)
					}
				}
			}
			if len(use) > 0 {
				m["use"] = use
				delete(m, "include-all")
			}
		}
		// A QX group whose members are remote servers (not known here) uses the subscriptions instead.
		if len(members) == 0 && m["include-all"] == nil && m["include-all-proxies"] == nil && m["use"] == nil && len(providerTags) > 0 && hadUnknown(g.members, groupNames, proxyNames) {
			var use []any
			for _, t := range providerTags {
				use = append(use, t)
			}
			m["use"] = use
		}
		// Group icon (v0.7): QX img-url, Surge / Loon icon-url → mihomo `icon:` (only remote images;
		// QX built-in icon names have no file we could show).
		if ic := firstNonEmpty(g.opts["img-url"], g.opts["icon-url"]); strings.HasPrefix(ic, "http://") || strings.HasPrefix(ic, "https://") {
			m["icon"] = ic
		}
		if len(members) == 0 && m["include-all-proxies"] == nil && m["include-all"] == nil && m["use"] == nil {
			members = append(members, "DIRECT")
		}
		if len(members) > 0 {
			m["proxies"] = members
		}
		if g.typ == "url-test" || g.typ == "fallback" || g.typ == "load-balance" {
			m["url"] = firstNonEmpty(g.opts["url"], g.opts["check-interval-url"], checkURL)
			defInterval := 300
			if isQX && g.qxType == "available" {
				defInterval = 600
			}
			m["interval"] = atoi(firstNonEmpty(g.opts["interval"], g.opts["check-interval"]), defInterval)
			if tol := atoi(g.opts["tolerance"], 0); tol > 0 {
				m["tolerance"] = tol
			}
			if checkTimeout > 0 {
				m["timeout"] = checkTimeout
			}
			// v0.11: QX alive-checking=false (default) = only test when used → lazy.
			if v, ok := g.opts["alive-checking"]; ok {
				m["lazy"] = !truthy(v)
			}
			switch g.qxType {
			case "round-robin":
				m["strategy"] = "round-robin"
			case "dest-hash":
				m["strategy"] = "consistent-hashing"
			}
		}
		groups = append(groups, m)
	}

	// ---- rules
	var gl, pl []string
	firstSelect := ""
	for _, g := range groups {
		gm := g.(map[string]any)
		gl = append(gl, strOf(gm["name"]))
		if firstSelect == "" && gm["type"] == "select" {
			firstSelect = strOf(gm["name"])
		}
	}
	for n := range proxyNames {
		pl = append(pl, n)
	}
	var rules []any
	ruleSec := "rule"
	if isQX {
		ruleSec = "filter_local"
	}
	// v0.8.1: readable provider names (QX tag or file name, de-duplicated), source URL kept in `url`,
	// conversion recorded as x-convert; the cache file name stays hash-based.
	byList := map[string]string{}
	addRemote := func(u, kind, pol, line, tag string) {
		p, ok := mitm.ResolvePolicy(pol, gl, pl, firstSelect)
		if !ok {
			skip(ruleSec, line, "策略「"+pol+"」不存在")
			return
		}
		name, seen := byList[kind+"|"+u]
		if !seen {
			name = uniqueProviderName(prettyProviderName(u, tag), func(n string) bool { _, ok := providers[n]; return ok })
			byList[kind+"|"+u] = name
			behavior := "classical"
			if kind == "domainset" {
				behavior = "domain"
			}
			providers[name] = map[string]any{"type": "http", "behavior": behavior, "format": "text", "url": u, "x-convert": kind,
				"path": "./ruleset/" + providerNameFor(u, kind) + ".txt", "interval": 86400}
		}
		rules = append(rules, "RULE-SET,"+name+","+p)
	}
	var final any
	for _, l := range nonEmpty(secs[ruleSec]) {
		c, err := mitm.ConvertRuleLine(l)
		if err != nil {
			skip(ruleSec, l, err.Error())
			continue
		}
		if c.RemoteURL != "" {
			addRemote(c.RemoteURL, c.RemoteKind, c.Policy, l, "")
			continue
		}
		if c.Rule == "" {
			continue
		}
		pol, ok := mitm.ResolvePolicy(c.Policy, gl, pl, firstSelect)
		if !ok {
			skip(ruleSec, l, "策略「"+c.Policy+"」不存在")
			continue
		}
		if c.Type == "MATCH" {
			final = c.Format(pol)
			continue
		}
		rules = append(rules, c.Format(pol))
	}
	if isQX {
		var inserted []any
		for _, l := range nonEmpty(secs["filter_remote"]) {
			opts := qxLineOpts(l)
			if v, ok := opts["enabled"]; ok && !truthy(v) {
				skip("filter_remote", l, "已禁用")
				continue
			}
			before := len(rules)
			head := strings.ToUpper(strings.TrimSpace(strings.SplitN(l, ",", 2)[0]))
			switch head {
			case "FILTER_LAN", "FILTER_REGION":
				// v0.11: QX built-in lists.
				pol, ok := mitm.ResolvePolicy(firstNonEmpty(opts["force-policy"], "direct"), gl, pl, firstSelect)
				if !ok {
					skip("filter_remote", l, "策略「"+opts["force-policy"]+"」不存在")
					continue
				}
				if head == "FILTER_LAN" {
					for _, c := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16"} {
						rules = append(rules, "IP-CIDR,"+c+","+pol+",no-resolve")
					}
					rules = append(rules, "DOMAIN-SUFFIX,local,"+pol)
				} else {
					rules = append(rules, "GEOIP,CN,"+pol)
				}
			default:
				sp, ok := parseQXRemote(l)
				if !ok {
					skip("filter_remote", l, "无效或已禁用")
					continue
				}
				if opts["force-policy"] == "" {
					rep.Notes = append(rep.Notes, "filter_remote 未指定 force-policy 的列表按 proxy 处理："+sp.URL)
				}
				addRemote(sp.URL, "list", sp.Policy, l, sp.Tag)
			}
			// inserted-resource=true: QX checks these before the local rules.
			if truthy(opts["inserted-resource"]) && len(rules) > before {
				inserted = append(inserted, rules[before:]...)
				rules = rules[:before]
			}
		}
		if len(inserted) > 0 {
			rules = append(inserted, rules...)
		}
	}
	if isQX {
		var pre []any
		if v := qxGeneral["udp_drop_list"]; v != "" {
			var ports []string
			for _, x := range strings.Split(v, ",") {
				x = strings.TrimSpace(x)
				switch strings.ToUpper(x) {
				case "":
				case "QUIC":
					if res.Settings == nil {
						res.Settings = &confSettings{}
					}
					res.Settings.BlockQUIC = true
				case "STUN":
					ports = append(ports, "3478", "5349", "19302")
				default:
					if atoi(strings.ReplaceAll(x, "-", ""), -1) >= 0 {
						ports = append(ports, x)
					}
				}
			}
			if len(ports) > 0 {
				pre = append(pre, "AND,((NETWORK,UDP),(DST-PORT,"+strings.Join(ports, "/")+")),REJECT-DROP")
			}
		}
		if v := qxGeneral["udp_whitelist"]; v != "" {
			var ports []string
			for _, x := range strings.Split(v, ",") {
				if x = strings.TrimSpace(x); x != "" && atoi(strings.ReplaceAll(x, "-", ""), -1) >= 0 {
					ports = append(ports, x)
				}
			}
			if len(ports) > 0 {
				pre = append(pre, "AND,((NETWORK,UDP),(NOT,((DST-PORT,"+strings.Join(ports, "/")+")))),REJECT")
			}
		}
		if len(pre) > 0 {
			rules = append(pre, rules...)
		}
		// fallback_udp_policy: mihomo skips a rule whose policy cannot carry UDP, so a catch-all UDP rule
		// just before MATCH catches exactly the UDP QX would hand to the fallback policy.
		if v := qxGeneral["fallback_udp_policy"]; v != "" && !strings.EqualFold(v, "reject") {
			if pol, ok := mitm.ResolvePolicy(v, gl, pl, firstSelect); ok {
				rules = append(rules, "AND,((NETWORK,UDP)),"+pol)
			} else {
				rep.Notes = append(rep.Notes, "fallback_udp_policy 的策略「"+v+"」不存在，未导入")
			}
		}
	}
	if final == nil {
		target := firstSelect
		if target == "" {
			target = "DIRECT"
		}
		final = "MATCH," + target
		rep.Notes = append(rep.Notes, "原配置没有 FINAL 规则，已追加 MATCH,"+target)
	}
	rules = append(rules, final) // mihomo needs MATCH last

	// ---- DNS / general (best effort)
	cfg := map[string]any{"mode": "rule", "proxies": proxies, "proxy-groups": groups, "rules": rules}
	if len(providers) > 0 {
		cfg["rule-providers"] = providers
	}
	if len(proxyProviders) > 0 {
		cfg["proxy-providers"] = proxyProviders
	}
	listOf := func(v string) []any {
		var out []any
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" && s != "system" {
				out = append(out, s)
			}
		}
		return out
	}
	for _, l := range nonEmpty(secs["general"]) {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "dns-server":
			if ns := listOf(v); len(ns) > 0 {
				d, _ := cfg["dns"].(map[string]any)
				if d == nil {
					d = map[string]any{"enable": true}
				}
				d["default-nameserver"] = ns
				if d["nameserver"] == nil {
					d["nameserver"] = ns
				}
				cfg["dns"] = d
			}
		case "encrypted-dns-server":
			if ns := listOf(v); len(ns) > 0 {
				d, _ := cfg["dns"].(map[string]any)
				if d == nil {
					d = map[string]any{"enable": true}
				}
				d["nameserver"] = ns
				cfg["dns"] = d
			}
		case "ipv6":
			cfg["ipv6"] = truthy(v)
		}
	}
	if isQX {
		importQXDNS(cfg, nonEmpty(secs["dns"]), rep)
		importQXGeneral(cfg, qxGeneral, &res, rep)
	}

	// ---- rewrite / MitM / scripts → one module text
	moduleSecs := map[string]bool{"url rewrite": true, "header rewrite": true, "body rewrite": true, "map local": true, "script": true, "mitm": true,
		"rewrite_local": true, "task_local": true}
	known := map[string]bool{"": true, "general": true, "proxy": true, "proxy group": true, "rule": true, "server_local": true, "server_remote": true,
		"policy": true, "filter_local": true, "filter_remote": true, "dns": true, "replica": true, "host": true, "rewrite_remote": true}
	var mod strings.Builder
	for _, s := range order {
		if !moduleSecs[s] {
			if !known[s] {
				rep.Notes = append(rep.Notes, "["+s+"] 段未导入")
			}
			continue
		}
		lines := nonEmpty(secs[s])
		if len(lines) == 0 {
			continue
		}
		title := s
		if s == "mitm" && !isQX {
			title = "MITM"
		}
		if s == "mitm" {
			// Never copy the user's CA (passphrase / p12) into a module: our MitM uses its own CA.
			var kept []string
			for _, l := range lines {
				k, _, _ := strings.Cut(strings.ToLower(l), "=")
				switch strings.TrimSpace(k) {
				case "passphrase", "p12", "ca-passphrase", "ca-p12":
					continue
				}
				kept = append(kept, l)
			}
			lines = kept
			if len(lines) == 0 {
				continue
			}
		}
		mod.WriteString("[" + title + "]\n" + strings.Join(lines, "\n") + "\n\n")
	}
	if isQX {
		for _, l := range nonEmpty(secs["rewrite_remote"]) {
			if m, ok := parseQXRewriteRemote(l); ok {
				res.RewriteRemotes = append(res.RewriteRemotes, m)
			} else {
				skip("rewrite_remote", l, "不是有效的远程重写链接")
			}
		}
		rep.Remotes = len(res.RewriteRemotes)
	}
	if mod.Len() > 0 {
		res.Module = mod.String()
		rep.Module = true
		// Parse the module part with the engine's own parser so the report shows exactly what the module
		// store will hold, and every line it cannot use (instead of dropping it silently).
		rs := &mitm.Ruleset{}
		rs.ParseText(res.Module, "导入", nil)
		for _, r := range rs.Rules {
			if r.Kind == mitm.KindScript {
				rep.Scripts++
			} else {
				rep.Rewrites++
			}
		}
		for _, tk := range rs.Tasks {
			if !tk.DisabledByLine { // v0.11: enabled=false tasks are kept (off) but not counted
				rep.Tasks++
			}
		}
		for _, h := range rs.Hostnames {
			if !strings.HasPrefix(h, "-") {
				rep.Hostnames++
			}
		}
		for _, l := range rs.Unsupported {
			skip("重写", l, "不支持")
		}
		for _, e := range rs.Errors {
			rep.Skipped = append(rep.Skipped, "[重写] "+e)
		}
	}
	rep.Proxies, rep.Groups, rep.Rules, rep.Providers = len(proxies), len(groups), len(rules), len(providers)+len(proxyProviders)
	if len(proxyProviders) > 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("[server_remote] 的 %d 个节点订阅已转为节点集（连接时下载）", len(proxyProviders)))
	}
	if len(proxies) == 0 && len(proxyProviders) == 0 {
		rep.Notes = append(rep.Notes, "没有导入到节点；可以之后在「手动节点」或订阅中补充")
	}
	y, err := yaml.Marshal(cfg)
	if err != nil {
		res.Error = err.Error()
	} else {
		res.YAML = string(y)
	}
	b, _ := json.Marshal(res)
	return string(b)
}

// rewriteConvertProviders points providers that need a format conversion at the local converter for the
// core's own refreshes. v0.8.1: profiles keep the source URL in `url` plus `x-convert: <kind>`
// (list | domainset | nodes); the legacy "convert+<kind>:<url>" form is still accepted. The source is kept
// in x-source (ignored by mihomo, read by the inspector) so the UI never shows 127.0.0.1. The app
// downloads and converts the same lists into the same `path` (ProviderStore), so the core starts from
// the local file even before its first refresh.
func rewriteConvertProviders(raw map[string]any, o Overrides) {
	for _, key := range []string{"proxy-providers", "rule-providers"} {
		pv, ok := raw[key].(map[string]any)
		if !ok {
			continue
		}
		for _, v := range pv {
			m, ok := v.(map[string]any)
			if !ok {
				continue
			}
			kind, src := providerConvert(m)
			delete(m, "x-convert")
			if kind == "" || !strings.HasPrefix(src, "http") {
				continue
			}
			if str(m["x-source"]) == "" {
				m["x-source"] = src
			}
			if kind == "nodes" {
				m["url"] = fmt.Sprintf("http://127.0.0.1:%d/nodes/convert?%s", o.ControllerPort, url.Values{"url": {src}}.Encode())
			} else {
				m["url"] = ruleConvertURL(o, src, kind)
			}
			m["header"] = map[string]any{"Authorization": []any{"Bearer " + o.Secret}}
			m["proxy"] = "DIRECT"
		}
	}
}

// providerConvert returns the conversion kind and source URL of a provider ("" when none is needed).
func providerConvert(m map[string]any) (kind, src string) {
	u := str(m["url"])
	if strings.HasPrefix(u, convertScheme) {
		k, s, ok := strings.Cut(strings.TrimPrefix(u, convertScheme), ":")
		if ok {
			return k, s
		}
		return "", u
	}
	return str(m["x-convert"]), u
}

type qxServerRemote struct {
	URL      string
	Tag      string
	Interval int
	AsPolicy string // v0.11
}

// parseQXServerRemote reads a QX [server_remote] line: "<url>, tag=…, update-interval=…, enabled=…".
func parseQXServerRemote(line string) (qxServerRemote, bool) {
	parts := strings.Split(line, ",")
	u := strings.TrimSpace(parts[0])
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return qxServerRemote{}, false
	}
	sp := qxServerRemote{URL: u, Interval: 86400}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "tag":
			sp.Tag = strings.TrimSpace(v)
		case "as-policy":
			sp.AsPolicy = strings.TrimSpace(v)
		case "update-interval":
			if n := atoi(v, 0); n > 0 {
				sp.Interval = n
			}
		case "enabled":
			if !truthy(v) {
				return qxServerRemote{}, false
			}
		}
	}
	return sp, true
}

// qxRemoteURL returns the URL of an enabled QX remote line (rewrite_remote etc.).
func qxRemoteURL(line string) (string, bool) {
	sp, ok := parseQXServerRemote(line)
	return sp.URL, ok
}

// hadUnknown: the group listed members that are neither groups nor proxies of this file (remote servers).
func hadUnknown(members []string, groups, proxies map[string]bool) bool {
	for _, m := range members {
		u := strings.ToUpper(m)
		if u == "DIRECT" || strings.HasPrefix(u, "REJECT") || u == "PROXY" {
			continue
		}
		if !groups[m] && !proxies[m] {
			return true
		}
	}
	return false
}
