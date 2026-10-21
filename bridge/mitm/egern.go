package mitm

// Egern YAML modules (https://egernapp.com/docs/configuration/modules) — one more edge translator.
// The YAML is read once and turned into the same Rule / Task / Panel / core-rule model the Surge,
// QX, Loon and Stash parsers produce; nothing Egern-specific survives past this file.
//
// Supported: name / description, compat_arguments (+ {{{ARG}}} substitution, user values from the
// module's args), rules (domain*, ip_cidr*, geoip, asn, url_regex, dest_port, protocol, rule_set,
// and / or / not, default), url_rewrites (redirect / header / reject-*), header_rewrites
// (add / replace / delete), body_rewrites (request|response _regex / _jq), map_locals, scriptings
// (http_request / http_response / schedule / generic / network; Surge-compatible scripts with
// arguments._compat.$argument), mitm.hostnames (list or includes / excludes) and widgets (as panels
// filled by the generic script's $done({title, content})).
// Reported as unsupported: dns, http_captures, bypass_tunnel_proxy, real_ip_domains, env_schema,
// ssid / bssid / cellular / user_agent rules. Script `env` becomes ctx.env; Egern-native
// `export default async function(ctx)` scripts run through the ctx adapter (egernadapter.go).

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

var egernTopKeys = []string{"scriptings:", "url_rewrites:", "header_rewrites:", "body_rewrites:", "map_locals:",
	"compat_arguments:", "widgets:", "http_captures:", "real_ip_domains:", "bypass_tunnel_proxy:", "env_schema:"}

var egernRuleItemRe = regexp.MustCompile(`^\s*-\s+(domain|domain_suffix|domain_keyword|domain_regex|domain_wildcard|ip_cidr|ip_cidr6|geoip|asn|url_regex|user_agent|dest_port|protocol|rule_set|and|or|not|default|ssid)\s*:\s*$`)

// IsEgern reports whether text looks like an Egern YAML module (and not a Stash override).
func IsEgern(text string) bool {
	hasRulesKey := false
	for _, l := range strings.Split(text, "\n") {
		t := strings.TrimRight(l, " \t\r")
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if t == "http:" || strings.HasPrefix(t, "script-providers:") || t == "tiles:" {
			return false // Stash
		}
		if !strings.HasPrefix(t, " ") && !strings.HasPrefix(t, "-") {
			for _, k := range egernTopKeys {
				if strings.HasPrefix(t, k) {
					return true
				}
			}
			if t == "rules:" {
				hasRulesKey = true
			}
		}
		if hasRulesKey && egernRuleItemRe.MatchString(t) {
			return true
		}
		if strings.HasPrefix(t, "  hostnames:") || strings.HasPrefix(t, "    includes:") {
			return true
		}
	}
	return false
}

var egernPlaceholderRe = regexp.MustCompile(`\{\{\{\s*([A-Za-z0-9_.\-]+)\s*\}\}\}`)

func egernStr(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case int:
		return strconv.Itoa(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		return fmt.Sprint(x)
	}
}

func egernMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func egernList(v any) []any {
	l, _ := v.([]any)
	return l
}

func egernBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return truthy(x)
	case int:
		return x != 0
	}
	return false
}

func egernInt(v any, d int) int {
	switch x := v.(type) {
	case int:
		return x
	case float64:
		return int(x)
	case string:
		return atoiDef(x, d)
	}
	return d
}

// egernArgs reads compat_arguments defaults (placeholders neutralised so the YAML parses).
func egernArgs(text string) ([]ModArg, string) {
	neutral := egernPlaceholderRe.ReplaceAllString(text, "__egern_arg__")
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(neutral), &doc); err != nil {
		return nil, ""
	}
	defs := egernMap(doc["compat_arguments"])
	desc := egernStr(doc["compat_arguments_desc"])
	keys := make([]string, 0, len(defs))
	for k := range defs {
		keys = append(keys, k)
	}
	// Keep the file's order when possible: sort by first appearance in the text.
	sort.SliceStable(keys, func(i, j int) bool {
		return strings.Index(text, keys[i]+":") < strings.Index(text, keys[j]+":")
	})
	var out []ModArg
	for _, k := range keys {
		v := defs[k]
		a := ModArg{Key: k, Default: egernStr(v)}
		if _, ok := v.(bool); ok {
			a.Type = "switch"
		}
		for _, l := range strings.Split(desc, "\n") {
			if t := strings.TrimSpace(l); strings.HasPrefix(t, k) && len(t) > len(k) {
				a.Desc = t
				break
			}
		}
		out = append(out, a)
	}
	return out, desc
}

// parseEgern translates an Egern YAML module into rs.
func (rs *Ruleset) parseEgern(text, source string, user map[string]string) {
	rs.Format = "egern"
	args, _ := egernArgs(text)
	rs.Arguments = append(rs.Arguments, args...)
	if len(args) > 0 {
		vals := map[string]string{}
		for _, a := range args {
			vals[a.Key] = a.Default
			if u, ok := user[a.Key]; ok {
				vals[a.Key] = u
			}
		}
		text = egernPlaceholderRe.ReplaceAllStringFunc(text, func(m string) string {
			k := egernPlaceholderRe.FindStringSubmatch(m)[1]
			if v, ok := vals[k]; ok {
				return v
			}
			return m // undeclared arguments are left alone (Egern does the same)
		})
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		rs.Errors = append(rs.Errors, "Egern 模块 YAML 解析失败："+err.Error())
		return
	}
	if n := egernStr(doc["name"]); n != "" && rs.Name == "" {
		rs.Name = n
	}
	if d := egernStr(doc["description"]); d != "" && rs.Desc == "" {
		rs.Desc = d
	}
	for _, k := range []string{"dns", "http_captures", "bypass_tunnel_proxy", "real_ip_domains", "env_schema", "proxies", "policy_groups"} {
		if _, ok := doc[k]; ok {
			rs.Unsupported = append(rs.Unsupported, k+"（Egern 模块，暂不支持）")
		}
	}
	rs.egernMitM(doc["mitm"])
	for _, it := range egernList(doc["rules"]) {
		rs.egernRule(it, source)
	}
	for _, it := range egernList(doc["url_rewrites"]) {
		rs.egernURLRewrite(egernMap(it), source)
	}
	for _, it := range egernList(doc["header_rewrites"]) {
		rs.egernHeaderRewrite(egernMap(it), source)
	}
	for _, it := range egernList(doc["body_rewrites"]) {
		rs.egernBodyRewrite(egernMap(it), source)
	}
	for _, it := range egernList(doc["map_locals"]) {
		rs.egernMapLocal(egernMap(it), source)
	}
	for _, it := range egernList(doc["scriptings"]) {
		rs.egernScript(egernMap(it), source)
	}
	for _, it := range egernList(doc["widgets"]) {
		w := egernMap(it)
		name := egernStr(w["name"])
		if name == "" {
			continue
		}
		script := egernStr(w["script_name"])
		if script == "" {
			script = name
		}
		pn := &Panel{Name: name, Title: name, Script: script, Source: source, Format: "egern"}
		pn.ID = stableID(source, "panel", name)
		rs.Panels = append(rs.Panels, pn)
	}
}

// addCompiled compiles the rule's regexes and appends it (same checks as ParseLine).
func (rs *Ruleset) addCompiled(r *Rule, source, line string) {
	r.Source, r.Line = source, line
	if r.Pattern != "" {
		re, err := compileRe(r.Pattern)
		if err != nil {
			rs.Errors = append(rs.Errors, fmt.Sprintf("正则无效（%s）：%s", err.Error(), clip(line, 120)))
			return
		}
		r.re, r.fre = re, compileURLRe(r.Pattern)
	}
	for i := range r.Headers {
		if r.Headers[i].Regex != "" {
			re, err := compileRe(r.Headers[i].Regex)
			if err != nil {
				rs.Errors = append(rs.Errors, "正则无效："+clip(line, 120))
				return
			}
			r.Headers[i].re = re
		}
	}
	for i := range r.Body {
		re, err := compileRe(r.Body[i].Regex)
		if err != nil {
			rs.Errors = append(rs.Errors, "正则无效："+clip(line, 120))
			return
		}
		r.Body[i].re = re
		// r7 P2-3: same RE2 fast path as ParseLine (bodies > 512 KB were skipped, smaller ones paid the
		// backtracking engine's 4 B/char copy).
		r.Body[i].fast, r.Body[i].fastTmpl, _ = fastBodyRe(r.Body[i].Regex, r.Body[i].Repl)
	}
	if r.Desc == "" {
		r.Desc = describe(r)
	}
	rs.Rules = append(rs.Rules, r)
}

func (rs *Ruleset) egernMitM(v any) {
	m := egernMap(v)
	if m == nil {
		return
	}
	switch h := m["hostnames"].(type) {
	case []any:
		for _, x := range h {
			rs.addHosts(egernStr(x))
		}
	case map[string]any:
		for _, x := range egernList(h["includes"]) {
			rs.addHosts(egernStr(x))
		}
		for _, x := range egernList(h["excludes"]) {
			if s := strings.TrimSpace(egernStr(x)); s != "" {
				rs.addHosts("-" + strings.TrimPrefix(s, "-"))
			}
		}
	}
	if b, ok := m["skip_server_cert_verify"].(bool); ok {
		rs.SkipCertVerify = &b
	}
}

var egernCondTypes = map[string]string{
	"domain": "DOMAIN", "domain_suffix": "DOMAIN-SUFFIX", "domain_keyword": "DOMAIN-KEYWORD", "domain_regex": "DOMAIN-REGEX",
	"domain_wildcard": "DOMAIN-WILDCARD", "ip_cidr": "IP-CIDR", "ip_cidr6": "IP-CIDR6", "geoip": "GEOIP", "asn": "IP-ASN",
	"url_regex": "URL-REGEX", "dest_port": "DST-PORT", "protocol": "PROTOCOL", "rule_set": "RULE-SET",
}

// egernCond turns {type: {match: x}} into a Surge condition "TYPE,x" (no policy).
func egernCond(it any) (string, error) {
	m := egernMap(it)
	if len(m) != 1 {
		return "", fmt.Errorf("无法识别的 Egern 规则")
	}
	for k, v := range m {
		body := egernMap(v)
		switch k {
		case "and", "or", "not":
			var subs []string
			match := body["match"]
			items := egernList(match)
			if items == nil && match != nil {
				items = []any{match}
			}
			for _, s := range items {
				c, err := egernCond(s)
				if err != nil {
					return "", err
				}
				subs = append(subs, "("+c+")")
			}
			if len(subs) == 0 {
				return "", fmt.Errorf("逻辑规则缺少条件")
			}
			return strings.ToUpper(k) + ",(" + strings.Join(subs, ",") + ")", nil
		}
		t, ok := egernCondTypes[k]
		if !ok {
			return "", fmt.Errorf("Egern 规则类型 %s 暂不支持", k)
		}
		match := strings.TrimSpace(egernStr(body["match"]))
		if match == "" {
			return "", fmt.Errorf("%s 缺少 match", k)
		}
		switch k {
		case "asn":
			match = strings.TrimPrefix(strings.ToUpper(match), "AS")
		case "dest_port":
			match = strings.ReplaceAll(strings.ReplaceAll(match, " ", ""), ",", "/")
		case "protocol":
			match = strings.ToUpper(match)
		}
		c := t + "," + match
		if egernBool(body["no_resolve"]) {
			c += ",no-resolve"
		}
		return c, nil
	}
	return "", fmt.Errorf("无法识别的 Egern 规则")
}

func (rs *Ruleset) egernRule(it any, source string) {
	m := egernMap(it)
	if len(m) != 1 {
		rs.Unsupported = append(rs.Unsupported, fmt.Sprintf("rules: %v", it))
		return
	}
	for k, v := range m {
		body := egernMap(v)
		policy := strings.TrimSpace(egernStr(body["policy"]))
		var line string
		if k == "default" {
			rs.Unsupported = append(rs.Unsupported, "default（模块里的兜底规则不导入）")
			return
		}
		cond, err := egernCond(it)
		if err != nil {
			rs.Unsupported = append(rs.Unsupported, err.Error())
			return
		}
		if policy == "" {
			rs.Unsupported = append(rs.Unsupported, "规则缺少 policy："+cond)
			return
		}
		if strings.HasSuffix(cond, ",no-resolve") && k != "and" && k != "or" && k != "not" {
			line = strings.TrimSuffix(cond, ",no-resolve") + "," + policy + ",no-resolve"
		} else {
			line = cond + "," + policy
		}
		rs.parseCoreRule(line, func(r *Rule, err error) {
			if err != nil || r == nil {
				return
			}
			rs.addCompiled(r, source, line)
		})
	}
}

var egernRejects = map[string]string{"reject": "reject", "reject-200": "reject-200", "reject-dict": "reject-dict",
	"reject-array": "reject-array", "reject-img": "reject-img", "reject-video": "reject-200", "reject-drop": "reject-drop"}

func (rs *Ruleset) egernURLRewrite(m map[string]any, source string) {
	if m == nil || egernBool(m["disabled"]) {
		return
	}
	match, loc := egernStr(m["match"]), strings.TrimSpace(egernStr(m["location"]))
	line := fmt.Sprintf("url_rewrites: %s → %s", match, loc)
	if match == "" || loc == "" {
		rs.Errors = append(rs.Errors, "URL 重写缺少 match / location："+clip(line, 120))
		return
	}
	r := &Rule{Kind: KindURL, Phase: "request", Pattern: match}
	host := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(loc, "http://"), "https://"), "/")
	if a, ok := egernRejects[strings.ToLower(host)]; ok && strings.Contains(loc, "://") {
		r.Action = a
	} else {
		r.Target = loc
		switch egernInt(m["status_code"], 0) {
		case 0:
			r.Action = "header"
		case 307, 308:
			r.Action = "307"
		default:
			r.Action = "302"
		}
	}
	rs.addCompiled(r, source, line)
}

func (rs *Ruleset) egernHeaderRewrite(m map[string]any, source string) {
	for op, v := range m {
		b := egernMap(v)
		if b == nil || egernBool(b["disabled"]) {
			continue
		}
		phase := "request"
		if strings.EqualFold(egernStr(b["type"]), "response") {
			phase = "response"
		}
		name, value := egernStr(b["name"]), egernStr(b["value"])
		line := fmt.Sprintf("header_rewrites.%s: %s %s", op, egernStr(b["match"]), name)
		if name == "" {
			rs.Errors = append(rs.Errors, "头部重写缺少 name："+clip(line, 120))
			continue
		}
		r := &Rule{Kind: KindHeader, Phase: phase, Pattern: egernStr(b["match"])}
		ph := "请求头"
		if phase == "response" {
			ph = "响应头"
		}
		switch op {
		case "add", "replace":
			// Egern: set the header (replace if present, add otherwise).
			r.Headers = []HeaderOp{{Op: "del", Name: name}, {Op: "add", Name: name, Value: value}}
			r.Desc = ph + "设置 " + name
		case "delete":
			r.Headers = []HeaderOp{{Op: "del", Name: name}}
		default:
			rs.Unsupported = append(rs.Unsupported, line)
			continue
		}
		rs.addCompiled(r, source, line)
	}
}

func (rs *Ruleset) egernBodyRewrite(m map[string]any, source string) {
	for op, v := range m {
		b := egernMap(v)
		if b == nil || egernBool(b["disabled"]) {
			continue
		}
		phase := "request"
		if strings.HasPrefix(op, "response") {
			phase = "response"
		}
		line := fmt.Sprintf("body_rewrites.%s: %s", op, egernStr(b["match"]))
		switch op {
		case "request_regex", "response_regex":
			rs.addCompiled(&Rule{Kind: KindBody, Phase: phase, Pattern: egernStr(b["match"]),
				Body: []BodyOp{{Regex: egernStr(b["find"]), Repl: egernStr(b["replace"])}}}, source, line)
		case "request_jq", "response_jq":
			rs.addCompiled(&Rule{Kind: KindJQ, Phase: phase, Pattern: egernStr(b["match"]), JQ: egernStr(b["filter"])}, source, line)
		default:
			rs.Unsupported = append(rs.Unsupported, line)
		}
	}
}

func (rs *Ruleset) egernMapLocal(m map[string]any, source string) {
	if m == nil || egernBool(m["disabled"]) {
		return
	}
	line := "map_locals: " + egernStr(m["match"])
	r := &Rule{Kind: KindMapLocal, Phase: "request", Pattern: egernStr(m["match"]), Status: egernInt(m["status_code"], 200),
		RespHeaders: map[string]string{}, DataType: "base64"}
	for k, v := range egernMap(m["headers"]) {
		r.RespHeaders[k] = egernStr(v)
	}
	r.Data = base64.StdEncoding.EncodeToString([]byte(egernStr(m["body"])))
	r.Desc = "本地映射（Egern）"
	rs.addCompiled(r, source, line)
}

func (rs *Ruleset) egernScript(m map[string]any, source string) {
	for typ, v := range m {
		b := egernMap(v)
		if b == nil {
			continue
		}
		name := egernStr(b["name"])
		if egernBool(b["disabled"]) {
			continue
		}
		p := map[string]string{"script-path": egernStr(b["script_url"])}
		if n := egernInt(b["timeout"], 0); n > 0 {
			p["timeout"] = strconv.Itoa(n)
		}
		if n := egernInt(b["update_interval"], 0); n > 0 {
			p["script-update-interval"] = strconv.Itoa(n)
		}
		if n := egernInt(b["max_size"], 0); n > 0 {
			p["max-size"] = strconv.Itoa(n)
		}
		if egernBool(b["body_required"]) {
			p["requires-body"] = "1"
		}
		if egernBool(b["binary_body"]) {
			p["binary-body-mode"] = "1"
		}
		if a, ok := egernMap(b["arguments"])["_compat.$argument"]; ok {
			p["argument"] = egernStr(a)
		}
		var env map[string]string
		if em := egernMap(b["env"]); len(em) > 0 {
			env = map[string]string{}
			for k, v := range em {
				env[k] = egernStr(v)
			}
		}
		withEnv := func(sc *Script) *Script {
			if sc != nil && env != nil {
				sc.Env = env
			}
			return sc
		}
		line := fmt.Sprintf("scriptings.%s: %s %s", typ, name, p["script-path"])
		switch typ {
		case "http_request", "http_response":
			r, err := newScriptRule(name, strings.ReplaceAll(typ, "_", "-"), egernStr(b["match"]), p)
			if err != nil {
				rs.Errors = append(rs.Errors, err.Error()+"："+clip(line, 120))
				continue
			}
			withEnv(r.Script)
			rs.addCompiled(r, source, line)
		case "schedule":
			rs.addTask(TaskCron, egernStr(b["cron"]), "", withEnv(scriptFromParams(name, p)), source, line, "egern")
		case "generic":
			rs.addTask(TaskGeneric, "", "", withEnv(scriptFromParams(name, p)), source, line, "egern")
		case "network":
			rs.addTask(TaskEvent, "", "network-changed", withEnv(scriptFromParams(name, p)), source, line, "egern")
		default:
			rs.Unsupported = append(rs.Unsupported, line)
		}
	}
}

// ---------------- Egern rule-set files ----------------

var egernSetTypes = map[string]string{
	"domain_set": "DOMAIN", "domain_suffix_set": "DOMAIN-SUFFIX", "domain_keyword_set": "DOMAIN-KEYWORD",
	"domain_regex_set": "DOMAIN-REGEX", "domain_wildcard_set": "DOMAIN-WILDCARD", "ip_cidr_set": "IP-CIDR",
	"ip_cidr6_set": "IP-CIDR6", "geoip_set": "GEOIP", "asn_set": "IP-ASN", "dest_port_set": "DST-PORT",
	"protocol_set": "NETWORK",
}

// IsEgernRuleSet reports whether text is an Egern YAML rule set (domain_set: …).
func IsEgernRuleSet(text string) bool {
	// v0.19.6: walks lines without strings.Split (that allocated a slice of every line of a multi-MB list
	// to look at its first meaningful line).
	for rest := text; rest != ""; {
		var l string
		l, rest, _ = strings.Cut(rest, "\n")
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") || t == "no_resolve: true" || t == "no_resolve: false" {
			continue
		}
		k, _, ok := strings.Cut(t, ":")
		if ok && !strings.HasPrefix(t, "-") {
			if _, known := egernSetTypes[k]; known {
				return true
			}
			if strings.HasSuffix(k, "_set") {
				return true
			}
		}
		return false
	}
	return false
}

// ConvertEgernRuleSet turns an Egern YAML rule set into mihomo classical lines. It returns the lines
// and the number of entries skipped (unsupported set types).
func ConvertEgernRuleSet(text string) ([]string, int) {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, 0
	}
	noResolve := egernBool(doc["no_resolve"])
	var out []string
	skipped := 0
	keys := make([]string, 0, len(doc))
	for k := range doc {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		items := egernList(doc[k])
		t, ok := egernSetTypes[k]
		if !ok {
			skipped += len(items)
			continue
		}
		for _, it := range items {
			v := strings.TrimSpace(egernStr(it))
			if v == "" {
				continue
			}
			switch k {
			case "asn_set":
				v = strings.TrimPrefix(strings.ToUpper(v), "AS")
			case "dest_port_set":
				v = strings.ReplaceAll(strings.ReplaceAll(v, " ", ""), ",", "/")
			case "protocol_set":
				v = strings.ToUpper(v)
				if v != "TCP" && v != "UDP" {
					skipped++
					continue
				}
			}
			line := t + "," + v
			if noResolve && (t == "IP-CIDR" || t == "IP-CIDR6" || t == "GEOIP" || t == "IP-ASN") {
				line += ",no-resolve"
			}
			out = append(out, line)
		}
	}
	return out, skipped
}
