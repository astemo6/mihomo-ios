package mitm

// Body rewrite rules in the rewrite snapshot — native MitM stage 3b (design §14).
//
// The Swift engine (PacketTunnel/NativeMitM/Rewrite/NativeBodyRewrite.swift) runs body rewrites itself when
// Go marks them portable here. As with the URL patterns of stage 3a, Swift never parses the rule text: Go
// exports what it compiled, in a form Swift can execute with identical results.
//
//   - regex body ops (KindBody): only ops on Go's RE2 path (op.fast; regexp2-only ops stay with Go). The RE2
//     syntax tree is re-emitted as an ICU pattern built only from explicit pieces — every literal rune as
//     \x{…}, case folding expanded into explicit classes (unicode.SimpleFold orbits, what RE2 matches), every
//     class as its explicit rune ranges (\d \w \s are ASCII ranges in RE2 and stay so), `.` as [^\n], ^ as a
//     look-behind — so ICU flags, Unicode class tables and line-terminator rules play no part. Rejected:
//     word boundaries, repeats of something that can match empty (RE2 and backtracking engines then differ in
//     captures), nested / alternation-bearing unbounded repeats (backtracking blow-up), counts over 1000.
//     The replacement is exported as Go parsed it (parseRepl): literal runs and group numbers.
//   - Loon json ops (KindJSON): the path as splitJSONPath split it, the value as Go encodes parseJSONValue's
//     result (Swift parses that canonical JSON).
//   - jq (KindJQ): a subset compiled from gojq's own AST — pipes of `path = constant` and `del(path, …)` on
//     plain paths (.a, ."a", .["a"], .[n]). The constant is evaluated by gojq and exported as JSON. Anything
//     else (map / select / if / functions / optional / iteration, a jq file resource) stays with Go.
//
// Swift still hands a request back to Go whenever the body itself is uncertain (not UTF-8 for a regex, not
// JSON, a compression it cannot decode exactly, larger than 256 KB, a jq runtime error, a slow regex).

import (
	"encoding/json"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/itchyny/gojq"
)

// SnapBodyOp is one regex body op.
type SnapBodyOp struct {
	ICU   string         `json:"icu,omitempty"`
	Parts []SnapReplPart `json:"parts,omitempty"`
	Skip  bool           `json:"skip,omitempty"` // an op Go never applies (no usable regex): a no-op
}

// SnapReplPart is a literal run (G < 0) or a group reference.
type SnapReplPart struct {
	L string `json:"l,omitempty"`
	G int    `json:"g"`
}

// SnapJSONOp is one Loon json op with its path split and its value encoded the way Go builds them.
type SnapJSONOp struct {
	Op   string `json:"op"`
	Path []any  `json:"path"`
	V    string `json:"v"` // the value as Go's encodeJSON writes it (a JSON text inside a string: number literals stay exact)
}

// SnapJQStep is one step of a jq pipe: "set" (Path = V), "del" (Paths) or "filter" (Path |= map(select(Cond))).
type SnapJQStep struct {
	Op    string      `json:"op"`
	Path  []any       `json:"path,omitempty"`
	Paths [][]any     `json:"paths,omitempty"`
	V     string      `json:"v,omitempty"` // JSON text, as in SnapJSONOp
	Cond  *SnapJQCond `json:"cond,omitempty"`
}

// SnapJQCond is a select() condition: or / and (A, B), not (A), eq / ne (path P against the constant V: a string,
// boolean or null), truthy (path P), has (Key in the value at path P).
type SnapJQCond struct {
	K   string      `json:"k"`
	A   *SnapJQCond `json:"a,omitempty"`
	B   *SnapJQCond `json:"b,omitempty"`
	P   []any       `json:"p,omitempty"`
	V   string      `json:"v,omitempty"`
	Key string      `json:"key,omitempty"`
}

// snapBody fills the body fields of a body / jq / json rule.
func snapBody(sr *SnapRule, r *Rule) {
	why := ""
	switch r.Kind {
	case KindBody:
		for _, op := range r.Body {
			so, w := snapBodyOp(op)
			if w != "" && why == "" {
				why = w
			}
			sr.Body = append(sr.Body, so)
		}
	case KindJSON:
		for _, op := range r.JSON {
			v, err := encodeJSON(parseJSONValue(op.Value))
			if err != nil {
				why = "json value"
				break
			}
			sr.JSONOps = append(sr.JSONOps, SnapJSONOp{Op: op.Op, Path: jsonPathAny(splitJSONPath(op.Path)), V: string(v)})
		}
	case KindJQ:
		if r.JQ == "" {
			why = "jq file"
			break
		}
		steps, w := snapJQ(r.JQ)
		if w != "" {
			why = w
			break
		}
		sr.JQ = steps
	default:
		return
	}
	sr.BodyOK = why == ""
	sr.BodyWhy = why
}

func jsonPathAny(p []any) []any {
	if p == nil {
		return []any{}
	}
	return p
}

// snapBodyOp exports one regex op ("" why: Swift can run it).
func snapBodyOp(op BodyOp) (SnapBodyOp, string) {
	if op.fast == nil {
		if op.re == nil {
			return SnapBodyOp{Skip: true}, ""
		}
		return SnapBodyOp{}, "regexp2"
	}
	if !utf8.ValidString(op.Regex) || !utf8.ValidString(op.Repl) {
		return SnapBodyOp{}, "not utf-8"
	}
	icu, why := icuFromRE2(op.Regex)
	if why != "" {
		return SnapBodyOp{}, why
	}
	parts, ok := parseRepl(op.fast, op.Repl)
	if !ok {
		return SnapBodyOp{}, "replacement"
	}
	sp := []SnapReplPart{}
	for _, p := range parts {
		if p.group < 0 {
			sp = append(sp, SnapReplPart{L: p.lit, G: -1})
		} else {
			sp = append(sp, SnapReplPart{G: p.group})
		}
	}
	return SnapBodyOp{ICU: icu, Parts: sp}, ""
}

// icuFromRE2 re-emits an RE2 pattern (as regexp.Compile parses it) as an equivalent explicit ICU pattern.
func icuFromRE2(p string) (string, string) {
	re, err := syntax.Parse(p, syntax.Perl)
	if err != nil {
		return "", "re2 parse"
	}
	if reNullable(re) {
		return "", "nullable"
	}
	var b strings.Builder
	if why := emitICU(&b, re, 0); why != "" {
		return "", why
	}
	// sanity: same capture count as Go's regexp
	if g, err := regexp.Compile(p); err != nil || g.NumSubexp() != re.MaxCap() {
		return "", "captures"
	}
	return b.String(), ""
}

func reNullable(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpNoMatch, syntax.OpCharClass, syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		return false
	case syntax.OpLiteral:
		return len(re.Rune) == 0
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary, syntax.OpStar, syntax.OpQuest:
		return true
	case syntax.OpCapture, syntax.OpPlus:
		return reNullable(re.Sub[0])
	case syntax.OpRepeat:
		return re.Min == 0 || reNullable(re.Sub[0])
	case syntax.OpConcat:
		for _, s := range re.Sub {
			if !reNullable(s) {
				return false
			}
		}
		return true
	case syntax.OpAlternate:
		for _, s := range re.Sub {
			if reNullable(s) {
				return true
			}
		}
		return false
	}
	return true
}

// reHasRepeatOrAlt: the subtree holds a quantifier or an alternation (under an unbounded repeat these let a
// backtracking engine take exponential / high-polynomial time where RE2 is linear).
func reHasRepeatOrAlt(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat, syntax.OpAlternate:
		return true
	}
	for _, s := range re.Sub {
		if reHasRepeatOrAlt(s) {
			return true
		}
	}
	return false
}

const icuAll = `\x{0}-\x{10ffff}`

func icuRune(b *strings.Builder, r rune) {
	fmt.Fprintf(b, `\x{%x}`, r)
}

func icuClass(b *strings.Builder, ranges []rune) {
	if len(ranges) == 0 {
		b.WriteString(`(?!)`)
		return
	}
	b.WriteByte('[')
	for i := 0; i+1 < len(ranges); i += 2 {
		icuRune(b, ranges[i])
		if ranges[i+1] != ranges[i] {
			b.WriteByte('-')
			icuRune(b, ranges[i+1])
		}
	}
	b.WriteByte(']')
}

// foldOrbit is every rune RE2 matches for r under case folding (r's unicode.SimpleFold orbit), sorted.
func foldOrbit(r rune) []rune {
	out := []rune{r}
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		out = append(out, f)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func emitICU(b *strings.Builder, re *syntax.Regexp, unboundedDepth int) string {
	switch re.Op {
	case syntax.OpNoMatch:
		b.WriteString(`(?!)`)
	case syntax.OpEmptyMatch:
		b.WriteString(`(?:)`)
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if re.Flags&syntax.FoldCase != 0 {
				orbit := foldOrbit(r)
				if len(orbit) > 1 {
					rs := make([]rune, 0, 2*len(orbit))
					for _, o := range orbit {
						rs = append(rs, o, o)
					}
					icuClass(b, rs)
					continue
				}
			}
			icuRune(b, r)
		}
	case syntax.OpCharClass:
		icuClass(b, re.Rune)
	case syntax.OpAnyCharNotNL:
		b.WriteString(`[\x{0}-\x{9}\x{b}-\x{10ffff}]`)
	case syntax.OpAnyChar:
		b.WriteString(`[` + icuAll + `]`)
	case syntax.OpBeginLine:
		b.WriteString(`(?:(?<![` + icuAll + `])|(?<=\x{a}))`)
	case syntax.OpEndLine:
		b.WriteString(`(?=\x{a}|(?![` + icuAll + `]))`)
	case syntax.OpBeginText:
		b.WriteString(`(?<![` + icuAll + `])`)
	case syntax.OpEndText:
		b.WriteString(`(?![` + icuAll + `])`)
	case syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return "word boundary"
	case syntax.OpCapture:
		b.WriteByte('(')
		if w := emitICU(b, re.Sub[0], unboundedDepth); w != "" {
			return w
		}
		b.WriteByte(')')
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
		sub := re.Sub[0]
		if reNullable(sub) {
			return "repeat of nullable"
		}
		unbounded := re.Op == syntax.OpStar || re.Op == syntax.OpPlus || (re.Op == syntax.OpRepeat && re.Max < 0)
		if unbounded && reHasRepeatOrAlt(sub) {
			return "nested repeat"
		}
		if re.Op == syntax.OpRepeat && (re.Max > 1000 || re.Min > 1000) {
			return "repeat count"
		}
		b.WriteString(`(?:`)
		if w := emitICU(b, sub, unboundedDepth); w != "" {
			return w
		}
		b.WriteByte(')')
		switch re.Op {
		case syntax.OpStar:
			b.WriteByte('*')
		case syntax.OpPlus:
			b.WriteByte('+')
		case syntax.OpQuest:
			b.WriteByte('?')
		default:
			if re.Max < 0 {
				fmt.Fprintf(b, "{%d,}", re.Min)
			} else if re.Max == re.Min {
				fmt.Fprintf(b, "{%d}", re.Min)
			} else {
				fmt.Fprintf(b, "{%d,%d}", re.Min, re.Max)
			}
		}
		if re.Flags&syntax.NonGreedy != 0 {
			b.WriteByte('?')
		}
	case syntax.OpConcat:
		for _, s := range re.Sub {
			if w := emitICU(b, s, unboundedDepth); w != "" {
				return w
			}
		}
	case syntax.OpAlternate:
		b.WriteString(`(?:`)
		for i, s := range re.Sub {
			if i > 0 {
				b.WriteByte('|')
			}
			if w := emitICU(b, s, unboundedDepth); w != "" {
				return w
			}
		}
		b.WriteByte(')')
	default:
		return "op " + re.Op.String()
	}
	return ""
}

// ---- jq subset ----

// snapJQ compiles expr into set / del steps ("" why when it is outside the subset).
func snapJQ(expr string) ([]SnapJQStep, string) {
	q, err := gojq.Parse(expr)
	if err != nil {
		return nil, "jq parse"
	}
	var steps []SnapJQStep
	if why := jqSteps(q, &steps); why != "" {
		return nil, why
	}
	if steps == nil {
		steps = []SnapJQStep{}
	}
	return steps, ""
}

func jqPlain(q *gojq.Query) bool {
	return q != nil && q.Meta == nil && len(q.Imports) == 0 && len(q.FuncDefs) == 0 && len(q.Patterns) == 0
}

func jqSteps(q *gojq.Query, out *[]SnapJQStep) string {
	if !jqPlain(q) {
		return "jq form"
	}
	switch q.Op {
	case gojq.OpPipe:
		if w := jqSteps(q.Left, out); w != "" {
			return w
		}
		return jqSteps(q.Right, out)
	case gojq.OpAssign:
		path, w := jqPath(q.Left)
		if w != "" {
			return w
		}
		v, w := jqConst(q.Right)
		if w != "" {
			return w
		}
		*out = append(*out, SnapJQStep{Op: "set", Path: path, V: v})
		return ""
	case gojq.OpModify:
		// P |= map(select(C))
		path, w := jqPath(q.Left)
		if w != "" {
			return w
		}
		r := q.Right
		if !jqPlain(r) || r.Op != 0 || r.Term == nil || r.Term.Type != gojq.TermTypeFunc || len(r.Term.SuffixList) != 0 ||
			r.Term.Func.Name != "map" || len(r.Term.Func.Args) != 1 {
			return "jq modify"
		}
		a := r.Term.Func.Args[0]
		if !jqPlain(a) || a.Op != 0 || a.Term == nil || a.Term.Type != gojq.TermTypeFunc || len(a.Term.SuffixList) != 0 ||
			a.Term.Func.Name != "select" || len(a.Term.Func.Args) != 1 {
			return "jq modify"
		}
		c, w := jqCond(a.Term.Func.Args[0])
		if w != "" {
			return w
		}
		*out = append(*out, SnapJQStep{Op: "filter", Path: path, Cond: c})
		return ""
	case 0:
	default:
		return "jq operator " + q.Op.String()
	}
	t := q.Term
	if t == nil {
		return "jq form"
	}
	switch {
	case t.Type == gojq.TermTypeIdentity && len(t.SuffixList) == 0:
		return "" // `.`: the input as is
	case t.Type == gojq.TermTypeFunc && t.Func != nil && t.Func.Name == "del" && len(t.Func.Args) == 1 && len(t.SuffixList) == 0:
		var paths [][]any
		var collect func(a *gojq.Query) string
		collect = func(a *gojq.Query) string {
			if !jqPlain(a) {
				return "jq del form"
			}
			if a.Op == gojq.OpComma {
				if w := collect(a.Left); w != "" {
					return w
				}
				return collect(a.Right)
			}
			p, w := jqPath(a)
			if w != "" {
				return w
			}
			paths = append(paths, p)
			return ""
		}
		if w := collect(t.Func.Args[0]); w != "" {
			return w
		}
		*out = append(*out, SnapJQStep{Op: "del", Paths: paths})
		return ""
	}
	return "jq term"
}

// jqPath turns a plain path expression into its path components.
func jqPath(q *gojq.Query) ([]any, string) {
	if !jqPlain(q) || q.Op != 0 || q.Term == nil {
		return nil, "jq path form"
	}
	t := q.Term
	path := []any{}
	switch t.Type {
	case gojq.TermTypeIdentity:
	case gojq.TermTypeIndex:
		c, w := jqIndex(t.Index)
		if w != "" {
			return nil, w
		}
		path = append(path, c)
	default:
		return nil, "jq path term"
	}
	for _, s := range t.SuffixList {
		if s == nil || s.Iter || s.Optional || s.Index == nil {
			return nil, "jq path suffix"
		}
		c, w := jqIndex(s.Index)
		if w != "" {
			return nil, w
		}
		path = append(path, c)
	}
	return path, ""
}

func jqIndex(ix *gojq.Index) (any, string) {
	if ix == nil || ix.IsSlice || ix.End != nil {
		return nil, "jq slice"
	}
	switch {
	case ix.Name != "":
		return ix.Name, ""
	case ix.Str != nil:
		if len(ix.Str.Queries) != 0 {
			return nil, "jq interpolation"
		}
		return ix.Str.Str, ""
	case ix.Start != nil:
		s := ix.Start
		if !jqPlain(s) || s.Op != 0 || s.Term == nil || len(s.Term.SuffixList) != 0 {
			return nil, "jq index"
		}
		switch s.Term.Type {
		case gojq.TermTypeNumber:
			n, err := strconv.Atoi(s.Term.Number)
			if err != nil || n < 0 || n >= 0x20000000 {
				return nil, "jq index number"
			}
			return n, ""
		case gojq.TermTypeString:
			if s.Term.Str == nil || len(s.Term.Str.Queries) != 0 {
				return nil, "jq interpolation"
			}
			return s.Term.Str.Str, ""
		}
	}
	return nil, "jq index"
}

// jqConst evaluates a constant right-hand side with gojq (exactly one value) and encodes it as Go would.
func jqConst(q *gojq.Query) (string, string) {
	if !jqConstQuery(q, false) {
		return "", "jq value"
	}
	code, err := gojq.Compile(q)
	if err != nil {
		return "", "jq value"
	}
	it := code.Run(nil)
	v, ok := it.Next()
	if !ok {
		return "", "jq value"
	}
	if _, isErr := v.(error); isErr {
		return "", "jq value"
	}
	if _, more := it.Next(); more {
		return "", "jq value"
	}
	b, err := encodeJSON(v)
	if err != nil {
		return "", "jq value"
	}
	return string(b), ""
}

func jqConstQuery(q *gojq.Query, inArray bool) bool {
	if !jqPlain(q) {
		return false
	}
	if q.Op == gojq.OpComma {
		return inArray && jqConstQuery(q.Left, true) && jqConstQuery(q.Right, true)
	}
	if q.Op != 0 || q.Term == nil {
		return false
	}
	return jqConstTerm(q.Term)
}

func jqConstTerm(t *gojq.Term) bool {
	if len(t.SuffixList) != 0 {
		return false
	}
	switch t.Type {
	case gojq.TermTypeNull, gojq.TermTypeTrue, gojq.TermTypeFalse, gojq.TermTypeNumber:
		return true
	case gojq.TermTypeString:
		return t.Str != nil && len(t.Str.Queries) == 0 && t.Format == ""
	case gojq.TermTypeArray:
		return t.Array != nil && (t.Array.Query == nil || jqConstQuery(t.Array.Query, true))
	case gojq.TermTypeObject:
		if t.Object == nil {
			return false
		}
		for _, kv := range t.Object.KeyVals {
			if kv.KeyQuery != nil || kv.Val == nil || (kv.KeyString != nil && len(kv.KeyString.Queries) != 0) {
				return false
			}
			if kv.Key == "" && kv.KeyString == nil {
				return false
			}
			if strings.HasPrefix(kv.Key, "$") {
				return false // {$x}: a variable
			}
			if !jqConstQuery(kv.Val, false) {
				return false
			}
		}
		return true
	}
	return false
}

// jqCond compiles a select() condition of the supported forms.
func jqCond(q *gojq.Query) (*SnapJQCond, string) {
	if !jqPlain(q) {
		return nil, "jq cond"
	}
	switch q.Op {
	case gojq.OpOr, gojq.OpAnd:
		a, w := jqCond(q.Left)
		if w != "" {
			return nil, w
		}
		b, w := jqCond(q.Right)
		if w != "" {
			return nil, w
		}
		k := "and"
		if q.Op == gojq.OpOr {
			k = "or"
		}
		return &SnapJQCond{K: k, A: a, B: b}, ""
	case gojq.OpEq, gojq.OpNe:
		k := "eq"
		if q.Op == gojq.OpNe {
			k = "ne"
		}
		pq, cq := q.Left, q.Right
		if _, w := jqPath(pq); w != "" {
			pq, cq = q.Right, q.Left
		}
		p, w := jqPath(pq)
		if w != "" {
			return nil, w
		}
		v, w := jqConst(cq)
		if w != "" {
			return nil, w
		}
		if v != "null" && v != "true" && v != "false" && !strings.HasPrefix(v, `"`) {
			return nil, "jq cond value" // numbers compare numerically in jq (1 == 1.0): left to Go
		}
		return &SnapJQCond{K: k, P: p, V: v}, ""
	case gojq.OpPipe:
		r := q.Right
		if jqPlain(r) && r.Op == 0 && r.Term != nil && r.Term.Type == gojq.TermTypeFunc && len(r.Term.SuffixList) == 0 {
			switch {
			case r.Term.Func.Name == "not" && len(r.Term.Func.Args) == 0:
				a, w := jqCond(q.Left)
				if w != "" {
					return nil, w
				}
				return &SnapJQCond{K: "not", A: a}, ""
			case r.Term.Func.Name == "has" && len(r.Term.Func.Args) == 1:
				p, w := jqPath(q.Left)
				if w != "" {
					return nil, w
				}
				return jqHas(p, r.Term.Func.Args[0])
			}
		}
		return nil, "jq cond pipe"
	case 0:
	default:
		return nil, "jq cond operator"
	}
	t := q.Term
	if t == nil || len(t.SuffixList) != 0 && t.Type != gojq.TermTypeIndex && t.Type != gojq.TermTypeIdentity {
		return nil, "jq cond term"
	}
	switch {
	case t.Type == gojq.TermTypeQuery && len(t.SuffixList) == 0:
		return jqCond(t.Query)
	case t.Type == gojq.TermTypeFunc && t.Func.Name == "not" && len(t.Func.Args) == 0 && len(t.SuffixList) == 0:
		return &SnapJQCond{K: "not", A: &SnapJQCond{K: "truthy", P: []any{}}}, ""
	case t.Type == gojq.TermTypeFunc && t.Func.Name == "has" && len(t.Func.Args) == 1 && len(t.SuffixList) == 0:
		return jqHas([]any{}, t.Func.Args[0])
	case t.Type == gojq.TermTypeIndex || t.Type == gojq.TermTypeIdentity:
		p, w := jqPath(q)
		if w != "" {
			return nil, w
		}
		return &SnapJQCond{K: "truthy", P: p}, ""
	}
	return nil, "jq cond term"
}

func jqHas(p []any, arg *gojq.Query) (*SnapJQCond, string) {
	v, w := jqConst(arg)
	if w != "" || !strings.HasPrefix(v, `"`) {
		return nil, "jq has"
	}
	var key string
	if err := json.Unmarshal([]byte(v), &key); err != nil {
		return nil, "jq has"
	}
	return &SnapJQCond{K: "has", P: p, Key: key}, ""
}
