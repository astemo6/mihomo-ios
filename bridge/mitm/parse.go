// Package mitm implements the HTTP engine (MitM, rewrite, scripts, modules) that runs
// next to the mihomo core inside the PacketTunnel extension.
//
// parse.go: parsers for Surge (.sgmodule / [URL Rewrite] [Header Rewrite] [Body Rewrite]
// [Map Local] [Script] [MITM] [Rule]), Quantumult X (rewrite_local / snippet / filter_local),
// Loon (.plugin [Rewrite] [Script]) and Stash (.stoverride http: section) syntax.
package mitm

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"go.yaml.in/yaml/v3"
)

// Rule kinds.
const (
	KindURL      = "url"      // reject*/302/307/header (URL rewrite)
	KindHeader   = "header"   // header add/del/replace (Surge) or raw regex (QX)
	KindBody     = "body"     // regex replace on body
	KindJQ       = "jq"       // jq expression on JSON body
	KindJSON     = "json"     // Loon response-body-json-del/replace/add
	KindMapLocal = "maplocal" // local response
	KindScript   = "script"   // JS script
)

// HeaderOp is one header operation.
type HeaderOp struct {
	Op    string `json:"op"` // add / del / replace / replace-regex / raw (QX regex on header block)
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
	Regex string `json:"regex,omitempty"`
	re    *regexp2.Regexp
}

// BodyOp is a regex replacement pair.
type BodyOp struct {
	Regex string `json:"regex"`
	Repl  string `json:"repl"`
	re    *regexp2.Regexp
}

// JSONOp is a Loon style JSON path edit.
type JSONOp struct {
	Op    string `json:"op"` // del / replace / add
	Path  string `json:"path"`
	Value string `json:"value,omitempty"`
}

// Script describes a script rule.
type Script struct {
	Name           string `json:"name"`
	Type           string `json:"type"` // http-request / http-response / cron / generic
	Path           string `json:"path"`
	Argument       string `json:"argument,omitempty"`
	HasArgument    bool   `json:"hasArgument,omitempty"`
	RequiresBody   bool   `json:"requiresBody"`
	BinaryBody     bool   `json:"binaryBody,omitempty"`
	MaxSize        int    `json:"maxSize,omitempty"`
	Timeout        int    `json:"timeout,omitempty"` // seconds
	UpdateInterval int    `json:"updateInterval,omitempty"`
	Echo           bool   `json:"echo,omitempty"` // QX script-echo-response: request script that answers locally
	Cron           string `json:"cron,omitempty"`
	// Env is Egern's per-script `env` (ctx.env for native Egern scripts).
	Env map[string]string `json:"env,omitempty"`
	// Source is inline code for debug runs (脚本调试); nil = load Path.
	Source []byte `json:"-"`
}

// Rule is one parsed rewrite / script rule.
type Rule struct {
	Kind    string `json:"kind"`
	Phase   string `json:"phase"` // request / response
	Pattern string `json:"pattern"`
	Action  string `json:"action,omitempty"` // url: reject reject-200 reject-img reject-dict reject-array reject-drop 302 307 header
	Target  string `json:"target,omitempty"` // url: replacement / redirect target

	Headers []HeaderOp `json:"headers,omitempty"`
	Body    []BodyOp   `json:"body,omitempty"`
	JQ      string     `json:"jq,omitempty"`
	JSON    []JSONOp   `json:"json,omitempty"`

	// map local
	Data        string            `json:"data,omitempty"`
	DataType    string            `json:"dataType,omitempty"` // file / text / base64 / tiny-gif / json
	Status      int               `json:"status,omitempty"`
	RespHeaders map[string]string `json:"respHeaders,omitempty"`

	Script *Script `json:"script,omitempty"`

	Source string `json:"source"` // "用户" or module name
	Line   string `json:"line"`
	Desc   string `json:"desc"` // short Chinese description for the UI

	// HeaderPattern: QX url-and-header (v0.11) — the rule also needs this regex to match the request
	// line + headers ("GET /path HTTP/1.1\r\nHost: …\r\n…").
	HeaderPattern string `json:"headerPattern,omitempty"`

	re  *regexp2.Regexp
	hre *regexp2.Regexp
}

// Ruleset is the merged result of parsing user rules and modules.
type Ruleset struct {
	Rules          []*Rule  `json:"rules"`
	Hostnames      []string `json:"hostnames"`
	CoreRules      []string `json:"coreRules"` // mihomo rules from module [Rule] / filter_local (REJECT/DIRECT only)
	Errors         []string `json:"errors"`
	Unsupported    []string `json:"unsupported"`
	SkipCertVerify *bool    `json:"skipCertVerify,omitempty"`
	H2             *bool    `json:"h2,omitempty"`
	Name           string   `json:"name,omitempty"`
	Desc           string   `json:"desc,omitempty"`
	Arguments      []ModArg `json:"arguments,omitempty"`
	Format         string   `json:"format,omitempty"` // surge / qx / loon / stash / egern / list
	Tasks          []*Task  `json:"tasks,omitempty"`  // cron / event / generic scripts
	Panels         []*Panel `json:"panels,omitempty"` // Surge [Panel] / Stash tiles
}

// ModArg is a Surge #!arguments entry.
type ModArg struct {
	Key     string   `json:"key"`
	Default string   `json:"default"`
	Desc    string   `json:"desc,omitempty"`
	Type    string   `json:"type,omitempty"`    // Loon [Argument]: switch / select / input / text
	Options []string `json:"options,omitempty"` // Loon select choices
}

var loonArgKeyRe = regexp.MustCompile(`^[\p{L}_][\p{L}\p{N}_\-]*$`)

// loonEnableOptRe finds a Loon enable= option (any spacing, any case) after substitution.
var loonEnableOptRe = regexp.MustCompile(`(?i)(^|[,\s])enable\s*=\s*"?([^,\s"]*)"?`)

// parseLoonArguments reads a Loon plugin [Argument] section:
//
//	enableAd = switch,true,tag=去广告,desc=…
//	policy   = select,"DIRECT","PROXY",tag=策略
//	token    = input,"",tag=Token
func parseLoonArguments(text string) []ModArg {
	var out []ModArg
	in := false
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if m := sectionRe.FindStringSubmatch(t); m != nil {
			in = strings.EqualFold(strings.TrimSpace(m[1]), "argument")
			continue
		}
		if !in || t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		k, v, ok := strings.Cut(t, "=")
		k = strings.TrimSpace(k)
		if !ok || !loonArgKeyRe.MatchString(k) {
			continue
		}
		parts := splitArgList(strings.TrimSpace(v))
		if len(parts) == 0 {
			continue
		}
		a := ModArg{Key: k, Type: strings.ToLower(strings.TrimSpace(parts[0]))}
		var vals []string
		for _, p := range parts[1:] {
			p = strings.TrimSpace(p)
			if kk, vv, ok := strings.Cut(p, "="); ok && !strings.HasPrefix(p, `"`) {
				switch strings.ToLower(strings.TrimSpace(kk)) {
				case "tag":
					if a.Desc == "" {
						a.Desc = unquote(vv)
					} else {
						a.Desc = unquote(vv) + " · " + a.Desc
					}
				case "desc":
					if a.Desc == "" {
						a.Desc = unquote(vv)
					} else {
						a.Desc += " · " + unquote(vv)
					}
				}
				continue
			}
			vals = append(vals, unquote(p))
		}
		switch a.Type {
		case "switch":
			a.Default = "false"
			if len(vals) > 0 {
				a.Default = strings.ToLower(vals[0])
			}
			a.Options = []string{"true", "false"}
		case "select":
			a.Options = vals
			if len(vals) > 0 {
				a.Default = vals[0]
			}
		default:
			if len(vals) > 0 {
				a.Default = vals[0]
			}
		}
		out = append(out, a)
	}
	return out
}

// applyLoonArgs substitutes {key} for declared Loon arguments only (regexes keep their {n,m}) and drops
// lines whose enable= option resolves to false.
func applyLoonArgs(text string, args []ModArg, user map[string]string) string {
	if len(args) == 0 {
		return text
	}
	for _, a := range args {
		v := a.Default
		if u, ok := user[a.Key]; ok {
			v = u
		}
		// v0.13: cross-platform plugins sometimes use Surge's {{{key}}}; replace it before Loon's {key}.
		text = strings.ReplaceAll(text, "{{{"+a.Key+"}}}", v)
		text = strings.ReplaceAll(text, "{"+a.Key+"}", v)
	}
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if m := loonEnableOptRe.FindStringSubmatchIndex(l); m != nil {
			val := strings.ToLower(l[m[4]:m[5]])
			if val == "false" || val == "0" {
				continue
			}
			// Drop the option (and the comma that introduced it) from the line.
			start := m[0]
			if m[3] > m[2] && l[m[2]:m[3]] == "," {
				start = m[2]
			}
			l = strings.TrimRight(l[:start]+l[m[1]:], " ,")
			if strings.HasPrefix(strings.TrimSpace(l), ",") {
				l = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), ","))
			}
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func compileRe(p string) (*regexp2.Regexp, error) {
	re, err := regexp2.Compile(p, regexp2.None)
	if err != nil {
		return nil, err
	}
	re.MatchTimeout = 200 * time.Millisecond
	return re, nil
}

// tokenize splits on whitespace. A token that starts with " or ' and whose matching quote is followed
// by whitespace (or the end) is taken verbatim without the quotes, so "a b" stays one token while
// "ad":true stays as is.
func tokenize(s string) []string {
	var out []string
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		if q := s[i]; q == '"' || q == '\'' {
			found := -1
			for j := i + 1; j < len(s); j++ {
				if s[j] == '\\' && q == '"' {
					j++
					continue
				}
				if s[j] == q {
					if j+1 == len(s) || s[j+1] == ' ' || s[j+1] == '\t' {
						found = j
					}
					break
				}
			}
			if found > 0 {
				tok := s[i+1 : found]
				if q == '"' {
					tok = strings.ReplaceAll(tok, `\"`, `"`)
				}
				out = append(out, tok)
				i = found + 1
				continue
			}
		}
		j := i
		for j < len(s) && s[j] != ' ' && s[j] != '\t' {
			j++
		}
		out = append(out, s[i:j])
		i = j
	}
	return out
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

var scriptKeys = []string{"type", "pattern", "requires-body", "max-size", "binary-body-mode", "script-path",
	"argument", "timeout", "script-update-interval", "debug", "engine", "cronexp", "cron", "wake-system", "ability",
	"tag", "enable", "img-url", "event-name", "enabled", "binary-mode", "requires-header"}

var keyStartRe = regexp.MustCompile(`^\s*([a-zA-Z-]+)\s*=`)

// splitParams splits "a=1, b=x,y, c=2" on commas that start a known key, so regexes with commas survive.
func splitParams(s string, keys []string) map[string]string {
	known := map[string]bool{}
	for _, k := range keys {
		known[k] = true
	}
	out := map[string]string{}
	var parts []string
	start := 0
	inQ := false
	for i := 0; i < len(s); i++ {
		if s[i] == '"' {
			inQ = !inQ
		}
		if s[i] == ',' && !inQ {
			if m := keyStartRe.FindStringSubmatch(s[i+1:]); m != nil && known[strings.ToLower(m[1])] {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, s[start:])
	for _, p := range parts {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(k))] = unquote(v)
	}
	return out
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func atoiDef(s string, d int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return d
}

var surgeScriptRe = regexp.MustCompile(`^([^=]+?)\s*=\s*(type\s*=.*)$`)
var loonScriptRe = regexp.MustCompile(`^(http-request|http-response)\s+(\S+)\s+(script-path\s*=.*)$`)

func normScriptType(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	switch t {
	case "request", "http-request":
		return "http-request"
	case "response", "http-response":
		return "http-response"
	}
	return t
}

func newScriptRule(name, typ, pattern string, p map[string]string) (*Rule, error) {
	typ = normScriptType(typ)
	sc := &Script{Name: strings.TrimSpace(name), Type: typ, Path: p["script-path"], Timeout: atoiDef(p["timeout"], 10),
		MaxSize: atoiDef(p["max-size"], 0), UpdateInterval: atoiDef(p["script-update-interval"], 86400)}
	sc.RequiresBody = truthy(p["requires-body"])
	sc.BinaryBody = truthy(p["binary-body-mode"]) || truthy(p["binary-mode"])
	if a, ok := p["argument"]; ok {
		sc.Argument, sc.HasArgument = a, true
	}
	if c := p["cronexp"]; c != "" {
		sc.Cron = c
	} else if c := p["cron"]; c != "" {
		sc.Cron = c
	}
	if sc.Name == "" {
		sc.Name = p["tag"]
	}
	if sc.Name == "" {
		sc.Name = scriptNameFromPath(sc.Path)
	}
	if sc.Path == "" {
		return nil, fmt.Errorf("脚本缺少 script-path")
	}
	r := &Rule{Kind: KindScript, Pattern: pattern, Script: sc}
	switch typ {
	case "http-request":
		r.Phase = "request"
	case "http-response":
		r.Phase = "response"
	default:
		return r, errUnsupported
	}
	return r, nil
}

func scriptNameFromPath(p string) string {
	p = strings.TrimSuffix(p, "/")
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		p = p[i+1:]
	}
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	return strings.TrimSuffix(p, ".js")
}

var coreLineRe = regexp.MustCompile(`(?i)^(url-regex|domain|domain-suffix|domain-keyword|domain-wildcard|domain-regex|ip-cidr6?|geoip|ip-asn|dst-port|host|host-suffix|host-keyword|host-wildcard|ip6-cidr)\s*,[^,]+,`)

var errUnsupported = fmt.Errorf("unsupported")

var urlActions = map[string]bool{"reject": true, "reject-200": true, "reject-img": true, "reject-dict": true,
	"reject-array": true, "reject-drop": true, "reject-no-drop": true, "reject-tinygif": true, "reject-video": true,
	"302": true, "307": true, "301": true, "header": true}

func normURLAction(a string) string {
	a = strings.ToLower(a)
	switch a {
	case "reject-tinygif":
		return "reject-img"
	case "reject-no-drop":
		return "reject"
	case "reject-video":
		return "reject-200"
	case "301":
		return "302"
	}
	return a
}

var headerOps = map[string]string{"header-add": "add", "header-del": "del", "header-replace": "replace",
	"header-replace-regex": "replace-regex",
	// Stash header-rewrite
	"request-add": "add", "request-del": "del", "request-replace": "replace", "request-replace-regex": "replace-regex",
	"response-add": "add", "response-del": "del", "response-replace": "replace", "response-replace-regex": "replace-regex"}

func parseHeaderOp(op string, args []string) (HeaderOp, error) {
	h := HeaderOp{Op: headerOps[op]}
	switch h.Op {
	case "del":
		if len(args) < 1 {
			return h, fmt.Errorf("%s 需要头名", op)
		}
		h.Name = args[0]
	case "add", "replace":
		if len(args) < 1 {
			return h, fmt.Errorf("%s 需要头名和值", op)
		}
		h.Name = args[0]
		h.Value = strings.Join(args[1:], " ")
	case "replace-regex":
		if len(args) < 3 {
			return h, fmt.Errorf("%s 需要头名、正则和替换值", op)
		}
		h.Name, h.Regex, h.Value = args[0], args[1], strings.Join(args[2:], " ")
	default:
		return h, errUnsupported
	}
	return h, nil
}

// parseMapLocal parses Surge `regex data="..." data-type=text header="A:b|C:d" status-code=200`.
func parseMapLocal(pattern, rest string) (*Rule, error) {
	r := &Rule{Kind: KindMapLocal, Phase: "request", Pattern: pattern, Status: 200, RespHeaders: map[string]string{}}
	for _, tok := range tokenizeKV(rest) {
		k, v, _ := strings.Cut(tok, "=")
		v = strings.ReplaceAll(unquote(v), `\"`, `"`)
		switch strings.ToLower(k) {
		case "data":
			r.Data = v
		case "data-type":
			r.DataType = strings.ToLower(v)
		case "status-code":
			r.Status = atoiDef(v, 200)
		case "header":
			for _, kv := range strings.Split(v, "|") {
				if hk, hv, ok := strings.Cut(kv, ":"); ok {
					r.RespHeaders[strings.TrimSpace(hk)] = strings.TrimSpace(hv)
				}
			}
		}
	}
	if r.DataType == "" {
		if r.Data == "" {
			r.DataType = "text"
		} else {
			r.DataType = "file"
		}
	}
	return r, nil
}

// tokenizeKV splits `a="x y" b=z` into ["a=\"x y\"", "b=z"].
func tokenizeKV(s string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && inQ && i+1 < len(s) && s[i+1] == '"' {
			cur.WriteString(`\"`)
			i++
			continue
		}
		if c == '"' {
			inQ = !inQ
		}
		if (c == ' ' || c == '\t' || c == ',') && !inQ {
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteByte(c)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// ParseLine parses a single rule line. section is a lower-case section name hint ("" = autodetect).
// Returns rule (may be nil), hostnames, core rules.
func (rs *Ruleset) ParseLine(line, section, source string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
		return
	}
	add := func(r *Rule, err error) {
		if err == errUnsupported {
			rs.Unsupported = append(rs.Unsupported, line)
			return
		}
		if err != nil {
			rs.Errors = append(rs.Errors, fmt.Sprintf("%s：%s", err.Error(), clip(line, 120)))
			return
		}
		if r == nil {
			return
		}
		r.Source, r.Line = source, line
		if r.Pattern != "" {
			re, err := compileRe(r.Pattern)
			if err != nil {
				rs.Errors = append(rs.Errors, fmt.Sprintf("正则无效（%s）：%s", err.Error(), clip(line, 120)))
				return
			}
			r.re = re
		}
		if r.HeaderPattern != "" {
			re, err := compileRe(r.HeaderPattern)
			if err != nil {
				rs.Errors = append(rs.Errors, fmt.Sprintf("正则无效（%s）：%s", err.Error(), clip(line, 120)))
				return
			}
			r.hre = re
		}
		for i := range r.Headers {
			if r.Headers[i].Regex != "" {
				re, err := compileRe(r.Headers[i].Regex)
				if err != nil {
					rs.Errors = append(rs.Errors, fmt.Sprintf("正则无效：%s", clip(line, 120)))
					return
				}
				r.Headers[i].re = re
			}
		}
		for i := range r.Body {
			re, err := compileRe(r.Body[i].Regex)
			if err != nil {
				rs.Errors = append(rs.Errors, fmt.Sprintf("正则无效：%s", clip(line, 120)))
				return
			}
			r.Body[i].re = re
		}
		r.Desc = describe(r)
		rs.Rules = append(rs.Rules, r)
	}

	// MITM section / QX hostname line
	if k, v, ok := strings.Cut(line, "="); ok {
		key := strings.ToLower(strings.TrimSpace(k))
		switch key {
		case "hostname", "hostname-disabled":
			if key == "hostname" {
				rs.addHosts(v)
			}
			return
		case "skip-server-cert-verify", "skip-cert-verify", "skip_validating_cert": // v0.11: QX spelling
			b := truthy(v)
			rs.SkipCertVerify = &b
			return
		case "h2":
			b := truthy(v)
			rs.H2 = &b
			return
		case "tcp-connection", "ca-passphrase", "ca-p12", "passphrase", "p12", "client-source-address", "auto-quic-block", "skip_src_ip", "skip_dst_ip":
			return
		}
	}
	if section == "mitm" {
		return
	}
	if section == "rule" || section == "filter_local" || section == "filter_remote" {
		rs.parseCoreRule(line, add)
		return
	}
	if section == "panel" {
		rs.parsePanelLine(line, source)
		return
	}
	if section == "general" || section == "host" || section == "proxy" || section == "proxy group" {
		return
	}
	if rs.parseTaskLine(line, section, source) {
		return
	}
	// Surge script line: name = type=..., pattern=...
	if m := surgeScriptRe.FindStringSubmatch(line); m != nil && !strings.Contains(m[1], " url ") {
		p := splitParams(m[2], scriptKeys)
		add(newScriptRule(m[1], p["type"], p["pattern"], p))
		return
	}
	// Loon script line: http-response ^url script-path=..., requires-body=true, tag=x
	if m := loonScriptRe.FindStringSubmatch(line); m != nil {
		p := splitParams(m[3], scriptKeys)
		add(newScriptRule(p["tag"], m[1], m[2], p))
		return
	}
	toks := tokenize(line)
	if len(toks) == 0 {
		return
	}
	// Core rule lines (URL-REGEX,...,REJECT / DOMAIN,...,REJECT / host, x, reject) appearing outside [Rule].
	if coreLineRe.MatchString(line) {
		rs.parseCoreRule(line, add)
		return
	}
	// Prefixed phase lines: http-request / http-response (+ -jq)
	if t0 := strings.ToLower(toks[0]); t0 == "http-request" || t0 == "http-response" || t0 == "http-request-jq" || t0 == "http-response-jq" ||
		t0 == "request" || t0 == "response" || t0 == "response-jq" || t0 == "request-jq" {
		if len(toks) < 3 {
			add(nil, fmt.Errorf("参数不足"))
			return
		}
		phase := "request"
		if strings.Contains(t0, "response") {
			phase = "response"
		}
		pattern := toks[1]
		if strings.HasSuffix(t0, "-jq") {
			r := &Rule{Kind: KindJQ, Phase: phase, Pattern: pattern}
			rest := strings.TrimSpace(line[strings.Index(line, pattern)+len(pattern):])
			if strings.HasPrefix(rest, "jq-path=") {
				r.Data = unquote(strings.TrimPrefix(rest, "jq-path="))
			} else {
				r.JQ = unquote(rest)
			}
			add(r, nil)
			return
		}
		if _, ok := headerOps[strings.ToLower(toks[2])]; ok {
			h, err := parseHeaderOp(strings.ToLower(toks[2]), toks[3:])
			add(&Rule{Kind: KindHeader, Phase: phase, Pattern: pattern, Headers: []HeaderOp{h}}, err)
			return
		}
		r := &Rule{Kind: KindBody, Phase: phase, Pattern: pattern}
		rest := toks[2:]
		if len(rest)%2 != 0 {
			rest = append(rest, "")
		}
		for i := 0; i+1 < len(rest); i += 2 {
			r.Body = append(r.Body, BodyOp{Regex: rest[i], Repl: rest[i+1]})
		}
		add(r, nil)
		return
	}
	// Quantumult X: <regex> <header-regex> url-and-header <action> [args] (v0.11)
	if len(toks) >= 4 && strings.ToLower(toks[2]) == "url-and-header" {
		qt := append([]string{toks[0], "url"}, toks[3:]...)
		r, err := parseQX(qt, line)
		if r != nil {
			r.HeaderPattern = toks[1]
		}
		add(r, err)
		return
	}
	// Quantumult X: <regex> url <action> [args]
	if len(toks) >= 3 && strings.ToLower(toks[1]) == "url" {
		add(parseQX(toks, line))
		return
	}
	pattern := toks[0]
	if len(toks) >= 2 {
		t1 := strings.ToLower(toks[1])
		// Map Local (Surge)
		if section == "map local" || strings.HasPrefix(t1, "data=") || strings.HasPrefix(t1, "data-type=") || strings.Contains(line, " data=\"") {
			add(parseMapLocal(pattern, strings.TrimSpace(line[len(toks[0]):])))
			return
		}
		// Header Rewrite (old Surge syntax, request phase)
		if _, ok := headerOps[t1]; ok {
			h, err := parseHeaderOp(t1, toks[2:])
			phase := "request"
			if strings.HasPrefix(t1, "response-") {
				phase = "response"
			}
			add(&Rule{Kind: KindHeader, Phase: phase, Pattern: pattern, Headers: []HeaderOp{h}}, err)
			return
		}
		// Loon: <regex> <action> [target]
		if urlActions[t1] {
			r := &Rule{Kind: KindURL, Phase: "request", Pattern: pattern, Action: normURLAction(t1)}
			if len(toks) >= 3 {
				r.Target = toks[2]
			}
			if (r.Action == "302" || r.Action == "307" || r.Action == "header") && r.Target == "" {
				add(nil, fmt.Errorf("%s 缺少目标地址", r.Action))
				return
			}
			add(r, nil)
			return
		}
		switch t1 {
		case "response-body-json-del", "response-body-json-replace", "response-body-json-add",
			"request-body-json-del", "request-body-json-replace", "request-body-json-add":
			add(parseLoonJSON(pattern, t1, toks[2:]))
			return
		case "response-body-replace-regex", "request-body-replace-regex":
			r := &Rule{Kind: KindBody, Phase: strings.SplitN(t1, "-", 2)[0], Pattern: pattern}
			rest := toks[2:]
			if len(rest)%2 != 0 {
				rest = append(rest, "")
			}
			for i := 0; i+1 < len(rest); i += 2 {
				r.Body = append(r.Body, BodyOp{Regex: rest[i], Repl: rest[i+1]})
			}
			add(r, nil)
			return
		case "mock-response-body":
			add(parseMapLocal(pattern, strings.TrimSpace(line[len(toks[0])+len(toks[1])+1:])))
			return
		case "response-header-add", "response-header-del", "response-header-replace", "response-header-replace-regex",
			"request-header-add", "request-header-del", "request-header-replace", "request-header-replace-regex":
			phase, op, _ := strings.Cut(t1, "-header-")
			h, err := parseHeaderOp("header-"+op, toks[2:])
			add(&Rule{Kind: KindHeader, Phase: phase, Pattern: pattern, Headers: []HeaderOp{h}}, err)
			return
		}
	}
	// Surge URL Rewrite: <regex> <replacement> <type>
	if len(toks) >= 3 {
		a := strings.ToLower(toks[len(toks)-1])
		if urlActions[a] {
			add(&Rule{Kind: KindURL, Phase: "request", Pattern: pattern, Action: normURLAction(a), Target: toks[1]}, nil)
			return
		}
	}
	if len(toks) == 2 && urlActions[strings.ToLower(toks[1])] {
		add(&Rule{Kind: KindURL, Phase: "request", Pattern: pattern, Action: normURLAction(toks[1])}, nil)
		return
	}
	rs.Unsupported = append(rs.Unsupported, line)
}

func parseLoonJSON(pattern, op string, args []string) (*Rule, error) {
	phase, rest, _ := strings.Cut(op, "-body-json-")
	r := &Rule{Kind: KindJSON, Phase: phase, Pattern: pattern}
	switch rest {
	case "del":
		for _, a := range args {
			r.JSON = append(r.JSON, JSONOp{Op: "del", Path: a})
		}
	default:
		for i := 0; i+1 < len(args); i += 2 {
			r.JSON = append(r.JSON, JSONOp{Op: rest, Path: args[i], Value: args[i+1]})
		}
	}
	if len(r.JSON) == 0 {
		return nil, fmt.Errorf("JSON 操作缺少参数")
	}
	return r, nil
}

// parseQX handles `regex url <action> ...`.
func parseQX(toks []string, line string) (*Rule, error) {
	pattern := toks[0]
	act := strings.ToLower(toks[2])
	args := toks[3:]
	arg := func(i int) string {
		if i < len(args) {
			return args[i]
		}
		return ""
	}
	switch act {
	case "reject", "reject-200", "reject-img", "reject-dict", "reject-array", "reject-video", "reject-drop", "reject-no-drop":
		return &Rule{Kind: KindURL, Phase: "request", Pattern: pattern, Action: normURLAction(act)}, nil
	case "302", "307":
		if arg(0) == "" {
			return nil, fmt.Errorf("%s 缺少目标地址", act)
		}
		return &Rule{Kind: KindURL, Phase: "request", Pattern: pattern, Action: act, Target: arg(0)}, nil
	case "request-header", "response-header":
		// regex request-header REPLACEMENT  (QX: `url request-header A request-header B`)
		phase := strings.TrimSuffix(act, "-header")
		if len(args) >= 3 && strings.ToLower(args[1]) == act {
			return &Rule{Kind: KindHeader, Phase: phase, Pattern: pattern, Headers: []HeaderOp{{Op: "raw", Regex: args[0], Value: args[2]}}}, nil
		}
		if len(args) >= 2 {
			return &Rule{Kind: KindHeader, Phase: phase, Pattern: pattern, Headers: []HeaderOp{{Op: "raw", Regex: args[0], Value: args[1]}}}, nil
		}
		return nil, fmt.Errorf("参数不足")
	case "request-body", "response-body":
		phase := strings.TrimSuffix(act, "-body")
		if len(args) >= 3 && strings.ToLower(args[1]) == act {
			return &Rule{Kind: KindBody, Phase: phase, Pattern: pattern, Body: []BodyOp{{Regex: args[0], Repl: args[2]}}}, nil
		}
		if len(args) >= 2 {
			return &Rule{Kind: KindBody, Phase: phase, Pattern: pattern, Body: []BodyOp{{Regex: args[0], Repl: args[1]}}}, nil
		}
		return nil, fmt.Errorf("参数不足")
	case "script-response-body", "script-request-body", "script-response-header", "script-request-header",
		"script-echo-response", "script-analyze-echo-response":
		if arg(0) == "" {
			return nil, fmt.Errorf("缺少脚本路径")
		}
		sc := &Script{Path: arg(0), Name: scriptNameFromPath(arg(0)), Timeout: 10, UpdateInterval: 86400}
		r := &Rule{Kind: KindScript, Pattern: pattern, Script: sc}
		switch act {
		case "script-response-body":
			sc.Type, sc.RequiresBody, r.Phase = "http-response", true, "response"
		case "script-response-header":
			sc.Type, r.Phase = "http-response", "response"
		case "script-request-body":
			sc.Type, sc.RequiresBody, r.Phase = "http-request", true, "request"
		case "script-request-header":
			sc.Type, r.Phase = "http-request", "request"
		default:
			sc.Type, sc.Echo, r.Phase = "http-request", true, "request"
			sc.RequiresBody = act == "script-analyze-echo-response"
		}
		return r, nil
	case "jsonjq-response-body", "jsonjq-request-body":
		// v0.11: regex url jsonjq-response-body <jq expression> | jq-path=<url>. The expression is the rest
		// of the line (it usually contains spaces), quotes optional.
		phase := strings.TrimSuffix(strings.TrimPrefix(act, "jsonjq-"), "-body")
		i := strings.Index(strings.ToLower(line), act)
		rest := ""
		if i >= 0 {
			rest = strings.TrimSpace(line[i+len(act):])
		}
		if rest == "" {
			return nil, fmt.Errorf("%s 缺少 jq 表达式", act)
		}
		r := &Rule{Kind: KindJQ, Phase: phase, Pattern: pattern}
		if strings.HasPrefix(rest, "jq-path=") {
			r.Data = unquote(strings.TrimPrefix(rest, "jq-path="))
		} else {
			r.JQ = unquote(rest)
		}
		return r, nil
	case "echo-response":
		// regex url echo-response <content-type> echo-response <file-url>
		ct := arg(0)
		data := arg(2)
		if data == "" {
			data = arg(1)
		}
		return &Rule{Kind: KindMapLocal, Phase: "request", Pattern: pattern, Status: 200, DataType: "file", Data: data,
			RespHeaders: map[string]string{"Content-Type": ct}}, nil
	}
	return nil, errUnsupported
}

var qxFilterTypes = map[string]string{"host": "DOMAIN", "host-suffix": "DOMAIN-SUFFIX", "host-keyword": "DOMAIN-KEYWORD",
	"host-wildcard": "DOMAIN-WILDCARD", "ip-cidr": "IP-CIDR", "ip6-cidr": "IP-CIDR6", "geoip": "GEOIP", "ip-asn": "IP-ASN"}

var coreTypes = map[string]bool{"DOMAIN": true, "DOMAIN-SUFFIX": true, "DOMAIN-KEYWORD": true, "DOMAIN-WILDCARD": true,
	"IP-CIDR": true, "IP-CIDR6": true, "GEOIP": true, "IP-ASN": true, "DST-PORT": true, "DOMAIN-REGEX": true}

// parseCoreRule converts Surge [Rule] / QX filter / Loon [Rule] lines (translation in rules.go).
// Named policies are kept and resolved against the profile's groups when injected (ResolveCoreRules);
// URL-REGEX + REJECT becomes a URL rewrite reject.
func (rs *Ruleset) parseCoreRule(line string, add func(*Rule, error)) {
	parts := splitTop(line)
	if strings.EqualFold(parts[0], "URL-REGEX") && len(parts) >= 3 {
		policy := strings.ToUpper(parts[2])
		if strings.HasPrefix(policy, "REJECT") {
			act := "reject"
			if policy == "REJECT-TINYGIF" {
				act = "reject-img"
			} else if policy == "REJECT-DROP" {
				act = "reject-drop"
			} else if policy == "REJECT-200" {
				act = "reject-200"
			}
			add(&Rule{Kind: KindURL, Phase: "request", Pattern: parts[1], Action: act}, nil)
			return
		}
	}
	c, err := ConvertRuleLine(line)
	if err != nil || c.Rule == "" && c.RemoteURL == "" {
		rs.Unsupported = append(rs.Unsupported, line)
		return
	}
	if c.RemoteURL != "" {
		rs.CoreRules = append(rs.CoreRules, fmt.Sprintf("%s,%s,%s%s", strings.ToUpper(parts[0]), c.RemoteURL, c.Policy, c.Options))
		return
	}
	rs.CoreRules = append(rs.CoreRules, c.Format(c.Policy))
}

func (rs *Ruleset) addHosts(v string) {
	for _, h := range strings.Split(v, ",") {
		h = strings.TrimSpace(h)
		h = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(h, "%APPEND%"), "%INSERT%"))
		if h == "" || strings.HasPrefix(h, "%") {
			continue
		}
		rs.Hostnames = append(rs.Hostnames, strings.ToLower(h))
	}
}

var argHeaderRe = regexp.MustCompile(`(?m)^#!arguments\s*=\s*(.*)$`)
var argDescRe = regexp.MustCompile(`(?m)^#!arguments-desc\s*=\s*(.*)$`)

// ParseModuleArgs reads Surge `#!arguments=k1:v1,k2:"v 2"`.
func ParseModuleArgs(text string) []ModArg {
	m := argHeaderRe.FindStringSubmatch(text)
	if m == nil {
		return nil
	}
	var out []ModArg
	for _, kv := range splitArgList(m[1]) {
		k, v, _ := strings.Cut(kv, ":")
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		out = append(out, ModArg{Key: k, Default: unquote(v)})
	}
	if d := argDescRe.FindStringSubmatch(text); d != nil && len(out) > 0 {
		desc := strings.ReplaceAll(d[1], `\n`, "\n")
		for i := range out {
			for _, l := range strings.Split(desc, "\n") {
				if strings.HasPrefix(strings.TrimSpace(l), out[i].Key) {
					out[i].Desc = strings.TrimSpace(l)
				}
			}
		}
	}
	return out
}

func splitArgList(s string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inQ = !inQ
		}
		if c == ',' && !inQ {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// ApplyModuleArgs substitutes {{{key}}} with user values or defaults.
func ApplyModuleArgs(text string, user map[string]string) string {
	args := ParseModuleArgs(text)
	for _, a := range args {
		v := a.Default
		if u, ok := user[a.Key]; ok {
			v = u
		}
		text = strings.ReplaceAll(text, "{{{"+a.Key+"}}}", v)
	}
	return text
}

var metaRe = regexp.MustCompile(`(?m)^#!(name|desc)\s*=\s*(.*)$`)
var sectionRe = regexp.MustCompile(`^\[([^\]]+)\]\s*$`)

// ParseText parses a whole module / snippet / rule list into rs.
func (rs *Ruleset) ParseText(text, source string, args map[string]string) {
	text = strings.TrimPrefix(text, "\ufeff")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	if IsEgern(text) {
		rs.parseEgern(text, source, args)
		return
	}
	rs.Arguments = ParseModuleArgs(text)
	if len(rs.Arguments) > 0 {
		text = ApplyModuleArgs(text, args)
	}
	if la := parseLoonArguments(text); len(la) > 0 {
		rs.Arguments = append(rs.Arguments, la...)
		text = applyLoonArgs(text, la, args)
		rs.Format = "loon"
	}
	for _, m := range metaRe.FindAllStringSubmatch(text, -1) {
		if m[1] == "name" && rs.Name == "" {
			rs.Name = strings.TrimSpace(m[2])
		} else if m[1] == "desc" && rs.Desc == "" {
			rs.Desc = strings.TrimSpace(m[2])
		}
	}
	if isStash(normalizeStashKeys(text)) {
		rs.Format = "stash"
		rs.parseStash(text, source)
		return
	}
	section := ""
	sawSection := false
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if m := sectionRe.FindStringSubmatch(t); m != nil {
			section = strings.ToLower(strings.TrimSpace(m[1]))
			sawSection = true
			switch section {
			case "rewrite_local", "filter_local", "rewrite_remote":
				rs.Format = "qx"
			case "mitm":
				if strings.TrimSpace(m[1]) == "mitm" && rs.Format == "" {
					rs.Format = "qx"
				}
			case "rewrite", "plugin":
				if rs.Format == "" {
					rs.Format = "loon"
				}
			case "url rewrite", "header rewrite", "body rewrite", "map local", "script":
				if rs.Format == "" {
					rs.Format = "surge"
				}
			}
			continue
		}
		if section == "rewrite_remote" || section == "server_local" || section == "server_remote" || section == "policy" || section == "dns" || section == "argument" {
			continue
		}
		rs.ParseLine(t, section, source)
	}
	if !sawSection && rs.Format == "" {
		rs.Format = "list"
	}
}

func isStash(text string) bool {
	rulesKey := false
	for _, l := range strings.Split(text, "\n") {
		t := strings.TrimRight(l, " \t")
		if t == "http:" || strings.HasPrefix(t, "script-providers:") || t == "tiles:" || t == "cron:" || t == "rule-providers:" {
			return true
		}
		// v0.13: a rules-only override (rules: + "- TYPE,value,POLICY" lines).
		if t == "rules:" {
			rulesKey = true
		} else if rulesKey && stashRuleItemRe.MatchString(t) {
			return true
		}
	}
	return false
}

var stashRuleItemRe = regexp.MustCompile(`^\s*-\s+['"]?[A-Za-z][A-Za-z0-9\-]*,`)

// stashKeySuffixRe matches Stash override merge markers on keys ("rules#!replace:", "mitm#!append:").
var stashKeySuffixRe = regexp.MustCompile(`(?m)^(\s*[A-Za-z][A-Za-z0-9_\-]*)#![A-Za-z]*\s*:`)

// normalizeStashKeys drops Stash merge markers so the keys decode; a module's lists are always added
// to the profile (never replace it), which is what #!replace means for a module anyway.
func normalizeStashKeys(text string) string {
	return stashKeySuffixRe.ReplaceAllString(text, "$1:")
}

type stashDoc struct {
	Name string `yaml:"name"`
	Desc string `yaml:"desc"`
	HTTP struct {
		Mitm           []string `yaml:"mitm"`
		Rewrite        []string `yaml:"rewrite"`
		URLRewrite     []string `yaml:"url-rewrite"`
		HeaderRewrite  []string `yaml:"header-rewrite"`
		BodyRewrite    []string `yaml:"body-rewrite"`
		SkipCertVerify *bool    `yaml:"skip-cert-verify"`
		Script         []struct {
			Match       string `yaml:"match"`
			Name        string `yaml:"name"`
			Type        string `yaml:"type"`
			RequireBody bool   `yaml:"require-body"`
			Timeout     int    `yaml:"timeout"`
			Argument    string `yaml:"argument"`
			BinaryMode  bool   `yaml:"binary-mode"`
			MaxSize     int    `yaml:"max-size"`
		} `yaml:"script"`
	} `yaml:"http"`
	ScriptProviders map[string]struct {
		URL      string `yaml:"url"`
		Interval int    `yaml:"interval"`
	} `yaml:"script-providers"`
	Rules         []string `yaml:"rules"`
	RuleProviders map[string]struct {
		Behavior string `yaml:"behavior"`
		Type     string `yaml:"type"`
		URL      string `yaml:"url"`
		Format   string `yaml:"format"`
		Interval int    `yaml:"interval"`
	} `yaml:"rule-providers"`
	Cron struct {
		Script []struct {
			Name     string `yaml:"name"`
			Cron     string `yaml:"cron"`
			Timeout  int    `yaml:"timeout"`
			Argument string `yaml:"argument"`
		} `yaml:"script"`
	} `yaml:"cron"`
	Tiles []struct {
		Name            string `yaml:"name"`
		Interval        int    `yaml:"interval"`
		Title           string `yaml:"title"`
		Content         string `yaml:"content"`
		Icon            string `yaml:"icon"`
		BackgroundColor string `yaml:"backgroundColor"`
		Timeout         int    `yaml:"timeout"`
		Argument        string `yaml:"argument"`
	} `yaml:"tiles"`
}

func (rs *Ruleset) parseStash(text, source string) {
	text = normalizeStashKeys(text)
	var d stashDoc
	if err := yaml.Unmarshal([]byte(text), &d); err != nil {
		rs.Errors = append(rs.Errors, "Stash 覆写 YAML 解析失败："+err.Error())
		return
	}
	if d.Name != "" && rs.Name == "" {
		rs.Name = d.Name
	}
	if d.Desc != "" && rs.Desc == "" {
		rs.Desc = d.Desc
	}
	for _, h := range d.HTTP.Mitm {
		rs.addHosts(h)
	}
	if d.HTTP.SkipCertVerify != nil {
		rs.SkipCertVerify = d.HTTP.SkipCertVerify
	}
	for _, l := range append(d.HTTP.Rewrite, d.HTTP.URLRewrite...) {
		rs.ParseLine(l, "", source)
	}
	for _, l := range d.HTTP.HeaderRewrite {
		rs.ParseLine(l, "", source)
	}
	for _, l := range d.HTTP.BodyRewrite {
		rs.ParseLine(l, "", source)
	}
	for _, s := range d.HTTP.Script {
		prov, ok := d.ScriptProviders[s.Name]
		if !ok {
			rs.Errors = append(rs.Errors, "Stash 脚本缺少 script-provider："+s.Name)
			continue
		}
		p := map[string]string{"script-path": prov.URL, "timeout": strconv.Itoa(s.Timeout)}
		if s.RequireBody {
			p["requires-body"] = "1"
		}
		if s.BinaryMode {
			p["binary-body-mode"] = "1"
		}
		if s.MaxSize > 0 {
			p["max-size"] = strconv.Itoa(s.MaxSize)
		}
		if s.Argument != "" {
			p["argument"] = s.Argument
		}
		if prov.Interval > 0 {
			p["script-update-interval"] = strconv.Itoa(prov.Interval)
		}
		if s.Timeout == 0 {
			p["timeout"] = "10"
		}
		r, err := newScriptRule(s.Name, s.Type, s.Match, p)
		line := fmt.Sprintf("%s = type=%s,pattern=%s,script-path=%s", s.Name, s.Type, s.Match, prov.URL)
		if err != nil {
			rs.Errors = append(rs.Errors, err.Error()+"："+line)
			continue
		}
		r.Source, r.Line = source, line
		re, err := compileRe(r.Pattern)
		if err != nil {
			rs.Errors = append(rs.Errors, "正则无效："+line)
			continue
		}
		r.re = re
		r.Desc = describe(r)
		rs.Rules = append(rs.Rules, r)
	}
	stashScript := func(name string, timeout int, arg string) *Script {
		prov, ok := d.ScriptProviders[name]
		if !ok {
			rs.Errors = append(rs.Errors, "Stash 脚本缺少 script-provider："+name)
			return nil
		}
		sc := &Script{Name: name, Path: prov.URL, Timeout: timeout, UpdateInterval: 86400}
		if prov.Interval > 0 {
			sc.UpdateInterval = prov.Interval
		}
		if arg != "" {
			sc.Argument, sc.HasArgument = arg, true
		}
		return sc
	}
	for _, c := range d.Cron.Script {
		if sc := stashScript(c.Name, c.Timeout, c.Argument); sc != nil {
			rs.addTask(TaskCron, c.Cron, "", sc, source, fmt.Sprintf("cron %q %s", c.Cron, c.Name), "stash")
		}
	}
	for _, t := range d.Tiles {
		sc := stashScript(t.Name, t.Timeout, t.Argument)
		if sc == nil {
			continue
		}
		rs.addTask(TaskGeneric, "", "", sc, source, "tile "+t.Name, "stash")
		pn := &Panel{Name: t.Name, Title: t.Title, Content: t.Content, Icon: t.Icon, IconColor: t.BackgroundColor, Script: t.Name,
			Interval: t.Interval, Source: source, Format: "stash"}
		if pn.Title == "" {
			pn.Title = t.Name
		}
		pn.ID = stableID(source, "panel", pn.Name)
		rs.Panels = append(rs.Panels, pn)
	}
	for _, l := range d.Rules {
		// v0.13: RULE-SET,<provider name>,POLICY → the provider's URL (domain behaviour → DOMAIN-SET).
		if parts := splitTop(l); len(parts) >= 3 && strings.EqualFold(parts[0], "RULE-SET") && !strings.Contains(parts[1], "://") {
			if p, ok := d.RuleProviders[parts[1]]; ok {
				switch {
				case strings.EqualFold(p.Format, "mrs"):
					rs.Unsupported = append(rs.Unsupported, l+"（mrs 二进制规则集）")
					continue
				case p.URL == "":
					rs.Unsupported = append(rs.Unsupported, l+"（规则集没有 url）")
					continue
				}
				t := "RULE-SET"
				if strings.EqualFold(p.Behavior, "domain") {
					t = "DOMAIN-SET"
				}
				l = strings.Join(append([]string{t, p.URL}, parts[2:]...), ",")
			}
		}
		rs.parseCoreRule(l, func(r *Rule, err error) {
			if r != nil {
				r.Source, r.Line = source, l
				if re, e := compileRe(r.Pattern); e == nil {
					r.re = re
					r.Desc = describe(r)
					rs.Rules = append(rs.Rules, r)
				}
			}
		})
	}
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func describe(r *Rule) string {
	switch r.Kind {
	case KindURL:
		switch r.Action {
		case "reject":
			return "拒绝（404）"
		case "reject-200":
			return "拒绝（空 200）"
		case "reject-img":
			return "拒绝（1×1 GIF）"
		case "reject-dict":
			return "拒绝（{}）"
		case "reject-array":
			return "拒绝（[]）"
		case "reject-drop":
			return "拒绝（断开）"
		case "302", "307":
			return r.Action + " 重定向 → " + r.Target
		case "header":
			return "改写 URL → " + r.Target
		}
	case KindHeader:
		ph := "请求头"
		if r.Phase == "response" {
			ph = "响应头"
		}
		h := r.Headers[0]
		switch h.Op {
		case "add":
			return ph + "添加 " + h.Name
		case "del":
			return ph + "删除 " + h.Name
		case "replace":
			return ph + "替换 " + h.Name
		case "replace-regex":
			return ph + "正则替换 " + h.Name
		case "raw":
			return ph + "正则改写"
		}
	case KindBody:
		if r.Phase == "response" {
			return fmt.Sprintf("响应体替换（%d 组）", len(r.Body))
		}
		return fmt.Sprintf("请求体替换（%d 组）", len(r.Body))
	case KindJQ:
		if r.Phase == "response" {
			return "响应体 jq"
		}
		return "请求体 jq"
	case KindJSON:
		return fmt.Sprintf("JSON 改写（%d 项）", len(r.JSON))
	case KindMapLocal:
		return "本地映射（" + r.DataType + "）"
	case KindScript:
		t := "请求脚本"
		if r.Phase == "response" {
			t = "响应脚本"
		}
		if r.Script.RequiresBody {
			t += " · 含 body"
		}
		return t + " · " + r.Script.Name
	}
	return r.Kind
}
