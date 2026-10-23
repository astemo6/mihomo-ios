package mitm

// loonv2.go: Loon's expression syntax for [Rewrite] (3.5.1 build 978+) and [Script] (build 983+), used by
// .lpx plugins (可莉插件中心 and others):
//
//	request if ${url} ~= /^https:\/\/a\.com\/ad/i then reject_dict(200)
//	response if ${url} ~= /…/ then response.json.delete(["data.ads", "data.banner"]) | response.header.del("ETag")
//	request if ${url} ~= /^https:\/\/old\.com(\/.*)$/ as m then redirect(302, "https://new.com${m.1}")
//	response if ${url} ~= /…/ then script("a.js", {${region}, ${level}}) with tag="A", requires_body=true
//	cron ${cron} then script("task.js") with enable=${enabled}, timeout=300
//	generic then script("tool.js", "mode=1") with tag="Tool", img_url="https://…/icon.png"
//
// Each line is lexed with real string / raw string / regex / ${…} boundaries (never split on spaces or
// commas), plugin [Argument] values are bound as typed data (switch → Boolean, type=number → Number,
// otherwise String, never re-parsed), and the line becomes the same Rule / Task values the classic syntax
// produces, so the engine runs both the same way. What the engine cannot express exactly — conditions on
// the request method, headers or response status, request body mocks, plugin-relative resource files,
// capture variables outside redirect / url.replace — is reported as unsupported instead of being widened.
// Spec: https://nsloon.app/docs/Rewrite/rewrite_v2/ and https://nsloon.app/docs/Script/script_v2/

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// loonV2LineRe recognises a line in the expression syntax (and never a classic line: those have no
// `if` after the phase and no `then` after the trigger).
var loonV2LineRe = regexp.MustCompile(`^(?:(?:request|response)\s+if\s|(?:generic|network-changed)\s+then\s|cron\s+(?:"[^"]*"|\$\{[^}]*\})\s+then\s)`)

// IsLoonV2Line reports whether line uses Loon's expression syntax.
func IsLoonV2Line(line string) bool { return loonV2LineRe.MatchString(strings.TrimSpace(line)) }

// ---- lexer

type lv2Part struct {
	s string
	v bool // s is a ${…} variable name
}

type lv2Tok struct {
	k     byte // i ident, s string (template), r raw string, x regex, n number, v variable, p punctuation, 0 end
	s     string
	flags string
	parts []lv2Part
}

func lv2Lex(s string) ([]lv2Tok, error) {
	var out []lv2Tok
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '"':
			var parts []lv2Part
			var cur strings.Builder
			j := i + 1
			closed := false
			for j < len(s) {
				d := s[j]
				if d == '\\' && j+1 < len(s) {
					e := s[j+1]
					switch e {
					case '"', '\\':
						cur.WriteByte(e)
					case 'n':
						cur.WriteByte('\n')
					case 'r':
						cur.WriteByte('\r')
					case 't':
						cur.WriteByte('\t')
					case '$':
						cur.WriteByte('$')
					default: // unknown escape: kept as written (jq / regex text inside strings)
						cur.WriteByte('\\')
						cur.WriteByte(e)
					}
					j += 2
					continue
				}
				if d == '$' && j+1 < len(s) && s[j+1] == '{' {
					end := strings.IndexByte(s[j:], '}')
					if end < 0 {
						return nil, fmt.Errorf("变量缺少 }")
					}
					if cur.Len() > 0 {
						parts = append(parts, lv2Part{s: cur.String()})
						cur.Reset()
					}
					parts = append(parts, lv2Part{s: strings.TrimSpace(s[j+2 : j+end]), v: true})
					j += end + 1
					continue
				}
				if d == '"' {
					closed = true
					break
				}
				cur.WriteByte(d)
				j++
			}
			if !closed {
				return nil, fmt.Errorf("字符串缺少结尾的引号")
			}
			if cur.Len() > 0 || len(parts) == 0 {
				parts = append(parts, lv2Part{s: cur.String()})
			}
			out = append(out, lv2Tok{k: 's', parts: parts})
			i = j + 1
		case c == '`':
			var cur strings.Builder
			j := i + 1
			closed := false
			for j < len(s) {
				if s[j] == '`' {
					if j+1 < len(s) && s[j+1] == '`' {
						cur.WriteByte('`')
						j += 2
						continue
					}
					closed = true
					break
				}
				cur.WriteByte(s[j])
				j++
			}
			if !closed {
				return nil, fmt.Errorf("原始字符串缺少结尾的 `")
			}
			out = append(out, lv2Tok{k: 'r', s: cur.String()})
			i = j + 1
		case c == '/':
			j := i + 1
			inClass := false
			closed := false
			for j < len(s) {
				d := s[j]
				if d == '\\' {
					j += 2
					continue
				}
				if d == '[' {
					inClass = true
				} else if d == ']' {
					inClass = false
				} else if d == '/' && !inClass {
					closed = true
					break
				}
				j++
			}
			if !closed || j > len(s) {
				return nil, fmt.Errorf("正则缺少结尾的 /")
			}
			re := s[i+1 : j]
			j++
			f := j
			for j < len(s) && s[j] >= 'a' && s[j] <= 'z' {
				j++
			}
			out = append(out, lv2Tok{k: 'x', s: re, flags: s[f:j]})
			i = j
		case c == '$' && i+1 < len(s) && s[i+1] == '{':
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				return nil, fmt.Errorf("变量缺少 }")
			}
			out = append(out, lv2Tok{k: 'v', s: strings.TrimSpace(s[i+2 : i+end])})
			i += end + 1
		case strings.HasPrefix(s[i:], "&&") || strings.HasPrefix(s[i:], "||") || strings.HasPrefix(s[i:], "==") || strings.HasPrefix(s[i:], "~="):
			out = append(out, lv2Tok{k: 'p', s: s[i : i+2]})
			i += 2
		case strings.IndexByte("|(),[]{}=", c) >= 0:
			out = append(out, lv2Tok{k: 'p', s: string(c)})
			i++
		case c >= '0' && c <= '9' || c == '-' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9':
			j := i + 1
			for j < len(s) && (s[j] >= '0' && s[j] <= '9' || s[j] == '.') {
				j++
			}
			out = append(out, lv2Tok{k: 'n', s: s[i:j]})
			i = j
		case c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			j := i + 1
			for j < len(s) && (s[j] == '_' || s[j] == '.' || s[j] == '-' || s[j] >= 'a' && s[j] <= 'z' || s[j] >= 'A' && s[j] <= 'Z' || s[j] >= '0' && s[j] <= '9') {
				j++
			}
			out = append(out, lv2Tok{k: 'i', s: s[i:j]})
			i = j
		default:
			return nil, fmt.Errorf("无法识别的字符 %q", string(c))
		}
	}
	return out, nil
}

// ---- syntax tree

type lv2Val struct {
	k     byte // s string template, r raw, n number, b bool, z null, x regex, v variable, a array, o plugin object
	s     string
	flags string
	parts []lv2Part
	b     bool
	arr   []lv2Val
	obj   []string
}

type lv2Cond struct {
	op   string // and / or / cmp
	l, r *lv2Cond
	lhs  string // variable name (cmp)
	cmp  string // == / ~=
	rhs  lv2Val
	as   string
}

type lv2Call struct {
	name string
	args []lv2Val
}

type lv2Opt struct {
	name string
	val  lv2Val
}

type lv2Line struct {
	kind  string // request / response / cron / network-changed / generic
	cond  *lv2Cond
	cron  lv2Val
	calls []lv2Call
	with  []lv2Opt
}

type lv2Parser struct {
	t []lv2Tok
	i int
}

func (p *lv2Parser) peek() lv2Tok {
	if p.i < len(p.t) {
		return p.t[p.i]
	}
	return lv2Tok{}
}

func (p *lv2Parser) next() lv2Tok { t := p.peek(); p.i++; return t }

func (p *lv2Parser) isP(s string) bool { t := p.peek(); return t.k == 'p' && t.s == s }
func (p *lv2Parser) isI(s string) bool { t := p.peek(); return t.k == 'i' && t.s == s }

func (p *lv2Parser) expectP(s string) error {
	if !p.isP(s) {
		return fmt.Errorf("这里应为 %s", s)
	}
	p.i++
	return nil
}

func lv2ParseLine(line string) (*lv2Line, error) {
	toks, err := lv2Lex(line)
	if err != nil {
		return nil, err
	}
	p := &lv2Parser{t: toks}
	head := p.next()
	if head.k != 'i' {
		return nil, fmt.Errorf("无法识别的语句")
	}
	l := &lv2Line{kind: head.s}
	switch head.s {
	case "request", "response":
		if !p.isI("if") {
			return nil, fmt.Errorf("缺少 if")
		}
		p.i++
		if l.cond, err = p.parseOr(); err != nil {
			return nil, err
		}
	case "cron":
		t := p.next()
		switch t.k {
		case 's':
			l.cron = lv2Val{k: 's', parts: t.parts}
		case 'v':
			l.cron = lv2Val{k: 'v', s: t.s}
		default:
			return nil, fmt.Errorf("cron 表达式应为字符串或插件参数")
		}
	case "generic", "network-changed":
	default:
		return nil, fmt.Errorf("无法识别的语句 %s", head.s)
	}
	if !p.isI("then") {
		return nil, fmt.Errorf("缺少 then")
	}
	p.i++
	for {
		c, err := p.parseCall()
		if err != nil {
			return nil, err
		}
		l.calls = append(l.calls, c)
		if !p.isP("|") {
			break
		}
		p.i++
	}
	if p.isI("with") {
		p.i++
		for {
			n := p.next()
			if n.k != 'i' {
				return nil, fmt.Errorf("with 后应为字段名")
			}
			if err := p.expectP("="); err != nil {
				return nil, err
			}
			v, err := p.parseVal()
			if err != nil {
				return nil, err
			}
			l.with = append(l.with, lv2Opt{name: n.s, val: v})
			if !p.isP(",") {
				break
			}
			p.i++
		}
	}
	if p.i < len(p.t) {
		return nil, fmt.Errorf("多余的内容")
	}
	return l, nil
}

func (p *lv2Parser) parseOr() (*lv2Cond, error) {
	l, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.isP("||") {
		p.i++
		r, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		l = &lv2Cond{op: "or", l: l, r: r}
	}
	return l, nil
}

func (p *lv2Parser) parseAnd() (*lv2Cond, error) {
	l, err := p.parsePrim()
	if err != nil {
		return nil, err
	}
	for p.isP("&&") {
		p.i++
		r, err := p.parsePrim()
		if err != nil {
			return nil, err
		}
		l = &lv2Cond{op: "and", l: l, r: r}
	}
	return l, nil
}

func (p *lv2Parser) parsePrim() (*lv2Cond, error) {
	if p.isP("(") {
		p.i++
		c, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		return c, p.expectP(")")
	}
	t := p.next()
	if t.k != 'v' {
		return nil, fmt.Errorf("条件应以 ${…} 开头")
	}
	op := p.next()
	if op.k != 'p' || (op.s != "==" && op.s != "~=") {
		return nil, fmt.Errorf("条件只支持 == 和 ~=")
	}
	v, err := p.parseVal()
	if err != nil {
		return nil, err
	}
	c := &lv2Cond{op: "cmp", lhs: t.s, cmp: op.s, rhs: v}
	if p.isI("as") {
		p.i++
		n := p.next()
		if n.k != 'i' {
			return nil, fmt.Errorf("as 后应为名称")
		}
		if op.s != "~=" {
			return nil, fmt.Errorf("as 只能用于 ~= 正则条件")
		}
		c.as = n.s
	}
	return c, nil
}

func (p *lv2Parser) parseCall() (lv2Call, error) {
	n := p.next()
	if n.k != 'i' {
		return lv2Call{}, fmt.Errorf("then 后应为动作")
	}
	c := lv2Call{name: n.s}
	if err := p.expectP("("); err != nil {
		return c, err
	}
	if p.isP(")") {
		p.i++
		return c, nil
	}
	for {
		v, err := p.parseVal()
		if err != nil {
			return c, err
		}
		c.args = append(c.args, v)
		if p.isP(",") {
			p.i++
			continue
		}
		return c, p.expectP(")")
	}
}

func (p *lv2Parser) parseVal() (lv2Val, error) {
	t := p.next()
	switch t.k {
	case 's':
		return lv2Val{k: 's', parts: t.parts}, nil
	case 'r':
		return lv2Val{k: 'r', s: t.s}, nil
	case 'n':
		return lv2Val{k: 'n', s: t.s}, nil
	case 'x':
		return lv2Val{k: 'x', s: t.s, flags: t.flags}, nil
	case 'v':
		return lv2Val{k: 'v', s: t.s}, nil
	case 'i':
		switch t.s {
		case "true", "false":
			return lv2Val{k: 'b', b: t.s == "true"}, nil
		case "null":
			return lv2Val{k: 'z'}, nil
		}
		return lv2Val{}, fmt.Errorf("无法识别的值 %s", t.s)
	case 'p':
		switch t.s {
		case "[":
			v := lv2Val{k: 'a'}
			for !p.isP("]") {
				e, err := p.parseVal()
				if err != nil {
					return v, err
				}
				if e.k == 'a' || e.k == 'o' {
					return v, fmt.Errorf("数组不能嵌套")
				}
				v.arr = append(v.arr, e)
				if p.isP(",") {
					p.i++
				} else if !p.isP("]") {
					return v, fmt.Errorf("数组缺少 ]")
				}
			}
			p.i++
			if len(v.arr) == 0 {
				return v, fmt.Errorf("数组不能为空")
			}
			return v, nil
		case "{":
			v := lv2Val{k: 'o'}
			for !p.isP("}") {
				e := p.next()
				if e.k != 'v' {
					return v, fmt.Errorf("对象参数只能包含 ${参数}")
				}
				v.obj = append(v.obj, e.s)
				if p.isP(",") {
					p.i++
				} else if !p.isP("}") {
					return v, fmt.Errorf("对象参数缺少 }")
				}
			}
			p.i++
			if len(v.obj) == 0 {
				return v, fmt.Errorf("对象参数不能为空")
			}
			return v, nil
		}
	}
	return lv2Val{}, fmt.Errorf("缺少值")
}

// ---- binding

// lv2Ctx binds plugin arguments (declared [Argument] + the user's values) for one line.
type lv2Ctx struct {
	args map[string]ModArg
	user map[string]string
	// captures: `as` name → true when it is the line's single URL regex (usable as ${name.n} in
	// redirect / url.replace targets).
	captures map[string]bool
}

func (c *lv2Ctx) arg(name string) (ModArg, string, bool) {
	a, ok := c.args[name]
	if !ok {
		return a, "", false
	}
	v := a.Default
	if u, ok := c.user[name]; ok {
		v = u
	}
	return a, v, true
}

// typed returns a plugin argument as Loon binds it: switch → bool, type=number → number, else string.
func (c *lv2Ctx) typed(name string) (any, bool) {
	a, v, ok := c.arg(name)
	if !ok {
		return nil, false
	}
	switch {
	case a.Type == "switch":
		return truthy(v), true
	case a.ValueType == "number":
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			return json.Number(strconv.FormatFloat(f, 'f', -1, 64)), true
		}
		return v, true
	}
	return v, true
}

var errLv2Builtin = fmt.Errorf("builtin")

func lv2Builtin(name string) bool {
	return name == "url" || strings.HasPrefix(name, "request.") || strings.HasPrefix(name, "response.")
}

// tpl renders a string template. repl: the result is a regex replacement, so substituted values (and,
// with escLit, literal text) have $ doubled; captures are allowed there as ${n}.
func (c *lv2Ctx) tpl(v lv2Val, repl, escLit bool) (string, error) {
	switch v.k {
	case 'r':
		if repl && escLit {
			return strings.ReplaceAll(v.s, "$", "$$"), nil
		}
		return v.s, nil
	case 'n':
		return v.s, nil
	case 'v':
		v = lv2Val{k: 's', parts: []lv2Part{{s: v.s, v: true}}}
	case 's':
	default:
		return "", fmt.Errorf("这里应为字符串")
	}
	var b strings.Builder
	for _, p := range v.parts {
		if !p.v {
			if repl && escLit {
				b.WriteString(strings.ReplaceAll(p.s, "$", "$$"))
			} else {
				b.WriteString(p.s)
			}
			continue
		}
		if name, idx, ok := strings.Cut(p.s, "."); ok {
			if single, isCap := c.captures[name]; isCap {
				n, err := strconv.Atoi(idx)
				if err != nil || n < 0 {
					return "", fmt.Errorf("无效的捕获 ${%s}", p.s)
				}
				if !repl || !single {
					return "", errUnsupported
				}
				b.WriteString("${" + idx + "}")
				continue
			}
		}
		if lv2Builtin(p.s) {
			return "", errUnsupported
		}
		_, val, ok := c.arg(p.s)
		if !ok {
			return "", fmt.Errorf("未定义的参数 ${%s}", p.s)
		}
		if repl {
			val = strings.ReplaceAll(val, "$", "$$")
		}
		b.WriteString(val)
	}
	return b.String(), nil
}

// value returns v as Go data for JSON edits.
func (c *lv2Ctx) value(v lv2Val) (any, error) {
	switch v.k {
	case 'n':
		return json.Number(v.s), nil
	case 'b':
		return v.b, nil
	case 'z':
		return nil, nil
	case 'v':
		if lv2Builtin(v.s) {
			return nil, errUnsupported
		}
		t, ok := c.typed(v.s)
		if !ok {
			return nil, fmt.Errorf("未定义的参数 ${%s}", v.s)
		}
		return t, nil
	}
	return c.tpl(v, false, false)
}

func lv2Regex(re, flags string) string {
	f := ""
	for _, ch := range flags {
		if strings.ContainsRune("ims", ch) && !strings.ContainsRune(f, ch) {
			f += string(ch)
		}
	}
	if f == "" {
		return re
	}
	return "(?" + f + ")" + re
}

// ---- condition → URL pattern

// lv2URL is a condition reduced to what the engine can match: always, never, or a URL regex.
type lv2URL struct {
	state  byte // t always, f never, u URL regex
	re     string
	terms  int
	single string // the `as` name when the condition is exactly one URL regex
}

func lv2Group(re string) string { return "(?:" + re + ")" }

func (c *lv2Ctx) reduce(n *lv2Cond, phase string) (lv2URL, error) {
	switch n.op {
	case "and", "or":
		l, err := c.reduce(n.l, phase)
		if err != nil && err != errUnsupported {
			return l, err
		}
		r, err2 := c.reduce(n.r, phase)
		if err2 != nil && err2 != errUnsupported {
			return r, err2
		}
		if n.op == "and" {
			if (err == nil && l.state == 'f') || (err2 == nil && r.state == 'f') {
				return lv2URL{state: 'f'}, nil
			}
			if err != nil || err2 != nil {
				return lv2URL{}, errUnsupported
			}
			if l.state == 't' {
				return r, nil
			}
			if r.state == 't' {
				return l, nil
			}
			return lv2URL{state: 'u', terms: l.terms + r.terms,
				re: `^(?=[\s\S]*?` + lv2Group(l.re) + `)(?=[\s\S]*?` + lv2Group(r.re) + `)`}, nil
		}
		if (err == nil && l.state == 't') || (err2 == nil && r.state == 't') {
			return lv2URL{state: 't'}, nil
		}
		if err != nil || err2 != nil {
			return lv2URL{}, errUnsupported
		}
		if l.state == 'f' {
			return r, nil
		}
		if r.state == 'f' {
			return l, nil
		}
		return lv2URL{state: 'u', terms: l.terms + r.terms, re: lv2Group(l.re) + "|" + lv2Group(r.re)}, nil
	}
	// comparison
	if n.lhs == "url" {
		var re string
		switch {
		case n.cmp == "~=" && n.rhs.k == 'x':
			re = lv2Regex(n.rhs.s, n.rhs.flags)
		case n.cmp == "~=" && n.rhs.k == 'v' && !lv2Builtin(n.rhs.s):
			_, v, ok := c.arg(n.rhs.s)
			if !ok {
				return lv2URL{}, fmt.Errorf("未定义的参数 ${%s}", n.rhs.s)
			}
			re = v
		case n.cmp == "==":
			s, err := c.tpl(n.rhs, false, false)
			if err != nil {
				return lv2URL{}, err
			}
			re = "^" + regexp.QuoteMeta(s) + "$"
		default:
			return lv2URL{}, fmt.Errorf("${url} ~= 右侧应为正则")
		}
		u := lv2URL{state: 'u', re: re, terms: 1}
		if n.as != "" {
			u.single = n.as
		}
		return u, nil
	}
	if lv2Builtin(n.lhs) {
		if strings.HasPrefix(n.lhs, "response.") && phase == "request" {
			return lv2URL{}, fmt.Errorf("request 阶段不能引用 ${%s}", n.lhs)
		}
		return lv2URL{}, errUnsupported // method / header / status conditions: not expressible as a URL match
	}
	lv, ok := c.typed(n.lhs)
	if !ok {
		return lv2URL{}, fmt.Errorf("未定义的参数 ${%s}", n.lhs)
	}
	ls := fmt.Sprint(lv)
	if n.cmp == "~=" {
		var pat string
		switch n.rhs.k {
		case 'x':
			pat = lv2Regex(n.rhs.s, n.rhs.flags)
		case 'v':
			_, pat, ok = c.arg(n.rhs.s)
			if !ok {
				return lv2URL{}, fmt.Errorf("未定义的参数 ${%s}", n.rhs.s)
			}
		default:
			return lv2URL{}, fmt.Errorf("~= 右侧应为正则")
		}
		re, err := compileRe(pat)
		if err != nil {
			return lv2URL{}, fmt.Errorf("正则无效")
		}
		m, _ := re.MatchString(ls)
		return lv2URL{state: map[bool]byte{true: 't', false: 'f'}[m]}, nil
	}
	rv, err := c.value(n.rhs)
	if err != nil {
		return lv2URL{}, err
	}
	eq := fmt.Sprint(rv) == ls
	if rv == nil {
		eq = false
	}
	return lv2URL{state: map[bool]byte{true: 't', false: 'f'}[eq]}, nil
}

// ---- lines → rules / tasks

var lv2MockTypes = map[string]string{"json": "application/json", "text": "text/plain", "plain": "text/plain",
	"text/event-stream": "text/event-stream", "css": "text/css", "html": "text/html", "javascript": "application/javascript",
	"png": "image/png", "gif": "image/gif", "jpeg": "image/jpeg", "tiff": "image/tiff", "svg": "image/svg+xml",
	"mp4": "video/mp4", "form-data": "multipart/form-data"}

func lv2Status(v lv2Val, def int) (int, error) {
	if v.k == 0 {
		return def, nil
	}
	if v.k != 'n' {
		return 0, fmt.Errorf("状态码应为数字")
	}
	n, err := strconv.Atoi(v.s)
	if err != nil || n < 100 || n > 599 {
		return 0, fmt.Errorf("状态码应为 100…599 的整数")
	}
	return n, nil
}

func lv2Arg(c lv2Call, i int) lv2Val {
	if i < len(c.args) {
		return c.args[i]
	}
	return lv2Val{}
}

// lv2Batch zips a batch call's arguments: every argument an array of the same length, or all single.
func lv2Batch(c lv2Call, want int) ([][]lv2Val, error) {
	if len(c.args) != want {
		return nil, fmt.Errorf("%s 需要 %d 个参数", c.name, want)
	}
	if c.args[0].k != 'a' {
		for _, a := range c.args {
			if a.k == 'a' {
				return nil, fmt.Errorf("%s 不能混用数组和单值", c.name)
			}
		}
		return [][]lv2Val{c.args}, nil
	}
	n := len(c.args[0].arr)
	for _, a := range c.args {
		if a.k != 'a' || len(a.arr) != n {
			return nil, fmt.Errorf("%s 的数组长度应一致", c.name)
		}
	}
	out := make([][]lv2Val, n)
	for i := range out {
		for _, a := range c.args {
			out[i] = append(out[i], a.arr[i])
		}
	}
	return out, nil
}

func (rs *Ruleset) parseLoonV2(line, source string) {
	l, err := lv2ParseLine(line)
	if err != nil {
		rs.Errors = append(rs.Errors, fmt.Sprintf("%s：%s", err.Error(), clip(line, 120)))
		return
	}
	ctx := &lv2Ctx{args: rs.loonArgs, user: rs.loonUser, captures: map[string]bool{}}
	if ctx.args == nil {
		ctx.args = map[string]ModArg{}
	}
	fail := func(err error) {
		if err == errUnsupported {
			rs.Unsupported = append(rs.Unsupported, line)
			return
		}
		rs.Errors = append(rs.Errors, fmt.Sprintf("%s：%s", err.Error(), clip(line, 120)))
	}
	if len(l.calls) == 1 && l.calls[0].name == "script" {
		rs.loonV2Script(l, ctx, line, source, fail)
		return
	}
	for _, c := range l.calls {
		if c.name == "script" {
			fail(fmt.Errorf("script(…) 不能与其他动作组合"))
			return
		}
	}
	if l.kind != "request" && l.kind != "response" {
		fail(fmt.Errorf("%s 只能运行 script(…)", l.kind))
		return
	}
	u, err := ctx.reduce(l.cond, l.kind)
	if err != nil {
		fail(err)
		return
	}
	if u.state == 'f' {
		return // switched off by the plugin's arguments
	}
	pattern := "^"
	if u.state == 'u' {
		pattern = u.re
	}
	if u.single != "" && u.terms == 1 {
		ctx.captures[u.single] = true
	}
	collectAs(l.cond, ctx.captures)
	rules, err := ctx.rewriteRules(l, pattern, u)
	if err != nil {
		fail(err)
		return
	}
	for _, r := range rules {
		rs.addRule(line, source, r, nil)
	}
}

// collectAs registers every `as` name (non-single ones as unusable captures).
func collectAs(n *lv2Cond, m map[string]bool) {
	if n == nil {
		return
	}
	if n.as != "" {
		if _, ok := m[n.as]; !ok {
			m[n.as] = false
		}
	}
	collectAs(n.l, m)
	collectAs(n.r, m)
}

func (c *lv2Ctx) rewriteRules(l *lv2Line, pattern string, u lv2URL) ([]*Rule, error) {
	phase := l.kind
	// response.body.mock(_file): one local answer plus response header edits on it.
	var mock *Rule
	for _, call := range l.calls {
		if call.name == "response.body.mock" || call.name == "response.body.mock_file" {
			if mock != nil {
				return nil, fmt.Errorf("一条复写只能有一个 Mock")
			}
			typ, err := c.tpl(lv2Arg(call, 0), false, false)
			if err != nil {
				return nil, err
			}
			data, err := c.tpl(lv2Arg(call, 1), false, false)
			if err != nil {
				return nil, err
			}
			st, err := lv2Status(lv2Arg(call, 2), 200)
			if err != nil {
				return nil, err
			}
			b64 := lv2Arg(call, 3).k == 'b' && lv2Arg(call, 3).b
			mock = &Rule{Kind: KindMapLocal, Phase: "request", Pattern: pattern, Status: st, RespHeaders: map[string]string{}, Data: data}
			if ct := lv2MockTypes[strings.ToLower(typ)]; ct != "" {
				mock.RespHeaders["Content-Type"] = ct
			} else if strings.Contains(typ, "/") {
				mock.RespHeaders["Content-Type"] = typ
			}
			switch {
			case call.name == "response.body.mock_file":
				if b64 || !isRemote(data) {
					return nil, errUnsupported // base64 files / plugin-relative resource files
				}
				mock.DataType = "file"
			case b64:
				mock.DataType = "base64"
			default:
				mock.DataType = "text"
			}
		}
	}
	if mock != nil {
		for _, call := range l.calls {
			switch call.name {
			case "response.body.mock", "response.body.mock_file":
			case "response.header.add", "response.header.set", "response.header.del":
				want := 2
				if call.name == "response.header.del" {
					want = 1
				}
				sets, err := lv2Batch(call, want)
				if err != nil {
					return nil, err
				}
				for _, s := range sets {
					name, err := c.tpl(s[0], false, false)
					if err != nil {
						return nil, err
					}
					if want == 1 {
						delete(mock.RespHeaders, name)
						continue
					}
					val, err := c.tpl(s[1], false, false)
					if err != nil {
						return nil, err
					}
					mock.RespHeaders[name] = val
				}
			default:
				return nil, errUnsupported
			}
		}
		return []*Rule{mock}, nil
	}

	var out []*Rule
	urlRule := func(action, target string) *Rule {
		return &Rule{Kind: KindURL, Phase: "request", Pattern: pattern, Action: action, Target: target}
	}
	local := func(st int, typ, data, ctype string) *Rule {
		r := &Rule{Kind: KindMapLocal, Phase: "request", Pattern: pattern, Status: st, DataType: typ, Data: data, RespHeaders: map[string]string{}}
		if ctype != "" {
			r.RespHeaders["Content-Type"] = ctype
		}
		return r
	}
	for _, call := range l.calls {
		name := call.name
		cphase := phase
		if p, _, ok := strings.Cut(name, "."); ok && (p == "request" || p == "response") {
			cphase = p
			if cphase != phase {
				return nil, fmt.Errorf("%s 阶段不能使用 %s", phase, name)
			}
		}
		switch name {
		case "reject", "reject_img", "reject_dict", "reject_array", "reject_video":
			if phase != "request" {
				return nil, fmt.Errorf("%s 只能用于 request 阶段", name)
			}
			st, err := lv2Status(lv2Arg(call, 0), 0)
			if err != nil {
				return nil, err
			}
			if st == 0 {
				return nil, fmt.Errorf("%s 需要状态码", name)
			}
			switch name {
			case "reject":
				body := ""
				if len(call.args) > 1 {
					if body, err = c.tpl(call.args[1], false, false); err != nil {
						return nil, err
					}
				}
				switch {
				case body == "" && st == 404:
					out = append(out, urlRule("reject", ""))
				case body == "" && st == 200:
					out = append(out, urlRule("reject-200", ""))
				default:
					out = append(out, local(st, "text", body, "text/plain; charset=utf-8"))
				}
			case "reject_img":
				if st == 200 {
					out = append(out, urlRule("reject-img", ""))
				} else {
					out = append(out, local(st, "tiny-gif", "", "image/gif"))
				}
			case "reject_dict", "reject_array":
				body, action := "{}", "reject-dict"
				if name == "reject_array" {
					body, action = "[]", "reject-array"
				}
				if st == 200 {
					out = append(out, urlRule(action, ""))
				} else {
					out = append(out, local(st, "json", body, "application/json"))
				}
			case "reject_video":
				if st == 200 {
					out = append(out, urlRule("reject-200", ""))
				} else {
					out = append(out, local(st, "text", "", ""))
				}
			}
		case "redirect", "url.replace":
			if phase != "request" {
				return nil, fmt.Errorf("%s 只能用于 request 阶段", name)
			}
			if u.state != 'u' || u.terms != 1 {
				return nil, fmt.Errorf("%s 需要条件中有且只有一个 ${url} ~= 正则", name)
			}
			targetArg := lv2Arg(call, 0)
			action := "header"
			if name == "redirect" {
				st, err := lv2Status(lv2Arg(call, 0), 0)
				if err != nil {
					return nil, err
				}
				switch st {
				case 302, 301:
					action = "302"
				case 307, 308:
					action = "307"
				default:
					return nil, fmt.Errorf("redirect 只支持 302、307")
				}
				targetArg = lv2Arg(call, 1)
			}
			target, err := c.tpl(targetArg, true, true)
			if err != nil {
				return nil, err
			}
			if target == "" {
				return nil, fmt.Errorf("%s 缺少目标地址", name)
			}
			out = append(out, urlRule(action, target))
		case "request.header.add", "request.header.set", "request.header.del", "request.header.replace",
			"response.header.add", "response.header.set", "response.header.del", "response.header.replace":
			op := name[strings.LastIndexByte(name, '.')+1:]
			want := map[string]int{"add": 2, "set": 2, "del": 1, "replace": 3}[op]
			sets, err := lv2Batch(call, want)
			if err != nil {
				return nil, err
			}
			r := &Rule{Kind: KindHeader, Phase: cphase, Pattern: pattern}
			for _, s := range sets {
				hn, err := c.tpl(s[0], false, false)
				if err != nil {
					return nil, err
				}
				switch op {
				case "del":
					r.Headers = append(r.Headers, HeaderOp{Op: "del", Name: hn})
				case "add", "set":
					val, err := c.tpl(s[1], false, false)
					if err != nil {
						return nil, err
					}
					if op == "set" {
						r.Headers = append(r.Headers, HeaderOp{Op: "del", Name: hn})
					}
					r.Headers = append(r.Headers, HeaderOp{Op: "add", Name: hn, Value: val})
				case "replace":
					if s[1].k != 'x' {
						return nil, fmt.Errorf("%s 的第二个参数应为正则", name)
					}
					repl, err := c.tpl(s[2], true, false)
					if err != nil {
						return nil, err
					}
					r.Headers = append(r.Headers, HeaderOp{Op: "replace-regex", Name: hn, Regex: lv2Regex(s[1].s, s[1].flags), Value: repl})
				}
			}
			out = append(out, r)
		case "request.body.replace", "response.body.replace":
			sets, err := lv2Batch(call, 2)
			if err != nil {
				return nil, err
			}
			r := &Rule{Kind: KindBody, Phase: cphase, Pattern: pattern}
			for _, s := range sets {
				if s[0].k != 'x' {
					return nil, fmt.Errorf("%s 的第一个参数应为正则", name)
				}
				repl, err := c.tpl(s[1], true, false)
				if err != nil {
					return nil, err
				}
				r.Body = append(r.Body, BodyOp{Regex: lv2Regex(s[0].s, s[0].flags), Repl: repl})
			}
			out = append(out, r)
		case "request.json.add", "request.json.replace", "request.json.delete",
			"response.json.add", "response.json.replace", "response.json.delete":
			op := name[strings.LastIndexByte(name, '.')+1:]
			want := 2
			if op == "delete" {
				op, want = "del", 1
			}
			sets, err := lv2Batch(call, want)
			if err != nil {
				return nil, err
			}
			r := &Rule{Kind: KindJSON, Phase: cphase, Pattern: pattern}
			for _, s := range sets {
				path, err := c.tpl(s[0], false, false)
				if err != nil {
					return nil, err
				}
				o := JSONOp{Op: op, Path: path}
				if want == 2 {
					v, err := c.value(s[1])
					if err != nil {
						return nil, err
					}
					b, _ := json.Marshal(v)
					o.Value = string(b)
				}
				r.JSON = append(r.JSON, o)
			}
			out = append(out, r)
		case "request.json.jq", "response.json.jq", "request.json.jq_file", "response.json.jq_file":
			if len(call.args) != 1 {
				return nil, fmt.Errorf("%s 需要 1 个参数", name)
			}
			s, err := c.tpl(call.args[0], false, false)
			if err != nil {
				return nil, err
			}
			r := &Rule{Kind: KindJQ, Phase: cphase, Pattern: pattern}
			if strings.HasSuffix(name, "_file") {
				if !isRemote(s) {
					return nil, errUnsupported // plugin-relative resource file
				}
				r.Data = s
			} else {
				r.JQ = s
			}
			out = append(out, r)
		case "request.body.mock", "request.body.mock_file":
			return nil, errUnsupported
		default:
			return nil, fmt.Errorf("未知的动作 %s", name)
		}
	}
	return out, nil
}

func (rs *Ruleset) loonV2Script(l *lv2Line, ctx *lv2Ctx, line, source string, fail func(error)) {
	call := l.calls[0]
	if len(call.args) < 1 || len(call.args) > 2 || (call.args[0].k != 's' && call.args[0].k != 'r') {
		fail(fmt.Errorf("script(…) 需要脚本路径"))
		return
	}
	path, err := ctx.tpl(call.args[0], false, false)
	if err != nil || path == "" {
		fail(fmt.Errorf("脚本路径应为固定字符串"))
		return
	}
	http := l.kind == "request" || l.kind == "response"
	sc := &Script{Path: path, UpdateInterval: 86400, Timeout: 300}
	if http {
		sc.Timeout = 20
		sc.Type = "http-" + l.kind
	}
	if len(call.args) == 2 {
		a := call.args[1]
		if a.k == 'o' {
			var buf strings.Builder
			buf.WriteByte('{')
			seen := map[string]bool{}
			for i, k := range a.obj {
				if seen[k] {
					fail(fmt.Errorf("对象参数重复 ${%s}", k))
					return
				}
				seen[k] = true
				am, val, ok := ctx.arg(k)
				if !ok {
					fail(fmt.Errorf("未定义的参数 ${%s}", k))
					return
				}
				var v any = val
				if t, _ := ctx.typed(k); t != nil {
					v = t
				}
				if val == "" && am.Type != "switch" {
					v = nil
				}
				if i > 0 {
					buf.WriteByte(',')
				}
				kb, _ := json.Marshal(k)
				vb, _ := json.Marshal(v)
				buf.Write(kb)
				buf.WriteByte(':')
				buf.Write(vb)
			}
			buf.WriteByte('}')
			sc.Argument, sc.HasArgument, sc.ArgObject = buf.String(), true, true
		} else {
			s, err := ctx.tpl(a, false, false)
			if err != nil {
				fail(err)
				return
			}
			sc.Argument, sc.HasArgument = s, true
		}
	}
	enabled := true
	icon := ""
	seen := map[string]bool{}
	for _, o := range l.with {
		if seen[o.name] {
			fail(fmt.Errorf("with 字段重复：%s", o.name))
			return
		}
		seen[o.name] = true
		switch o.name {
		case "tag":
			s, err := ctx.tpl(o.val, false, false)
			if err != nil {
				fail(err)
				return
			}
			sc.Name = s
		case "img_url":
			icon, _ = ctx.tpl(o.val, false, false)
		case "timeout":
			v := o.val
			s := v.s
			if v.k == 'v' || v.k == 's' {
				s, err = ctx.tpl(v, false, false)
				if err != nil {
					fail(err)
					return
				}
			}
			if f, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil && f > 0 {
				sc.Timeout = int(f + 0.999)
			} else if v.k != 'v' {
				fail(fmt.Errorf("timeout 应为正数"))
				return
			}
		case "enable", "debug", "requires_body", "binary_body_mode":
			b := false
			switch o.val.k {
			case 'b':
				b = o.val.b
			case 'v':
				t, ok := ctx.typed(o.val.s)
				if !ok {
					fail(fmt.Errorf("未定义的参数 ${%s}", o.val.s))
					return
				}
				bb, isBool := t.(bool)
				if !isBool {
					fail(fmt.Errorf("%s 应引用开关参数", o.name))
					return
				}
				b = bb
			default:
				fail(fmt.Errorf("%s 应为 true 或 false", o.name))
				return
			}
			switch o.name {
			case "enable":
				enabled = b
			case "requires_body":
				sc.RequiresBody = b
			case "binary_body_mode":
				sc.BinaryBody = b
			}
			if !http && (o.name == "requires_body" || o.name == "binary_body_mode") {
				fail(fmt.Errorf("%s 不能使用 %s", l.kind, o.name))
				return
			}
		default:
			fail(fmt.Errorf("未知的 with 字段：%s", o.name))
			return
		}
	}
	if sc.Name == "" {
		sc.Name = scriptNameFromPath(path)
	}
	if !http {
		var t *Task
		switch l.kind {
		case "cron":
			expr, err := ctx.tpl(l.cron, false, false)
			if err != nil {
				fail(err)
				return
			}
			t = rs.addTask(TaskCron, expr, "", sc, source, line, "loon")
		case "network-changed":
			t = rs.addTask(TaskEvent, "", "network-changed", sc, source, line, "loon")
		default:
			t = rs.addTask(TaskGeneric, "", "", sc, source, line, "loon")
		}
		if t != nil {
			if strings.HasPrefix(icon, "http://") || strings.HasPrefix(icon, "https://") {
				t.Icon = icon
			}
			t.DisabledByLine = !enabled
		}
		return
	}
	u, err := ctx.reduce(l.cond, l.kind)
	if err != nil {
		fail(err)
		return
	}
	if !enabled || u.state == 'f' {
		return // enable=false / a condition the plugin's arguments switch off
	}
	if l.kind == "response" && u.state != 'u' {
		fail(fmt.Errorf("Response Script 需要 ${url} ~= 条件"))
		return
	}
	pattern := "^"
	if u.state == 'u' {
		pattern = u.re
	}
	rs.addRule(line, source, &Rule{Kind: KindScript, Phase: l.kind, Pattern: pattern, Script: sc}, nil)
}
