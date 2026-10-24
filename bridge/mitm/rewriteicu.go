package mitm

// regexp2 (.NET) → ICU translation for the native rewrite engine (native MitM stage 3, lane s3-full).
//
// The Swift engine runs rule patterns on NSRegularExpression (ICU). Instead of asking "does ICU read this pattern
// like Go?" (the old portableRegex whitelist), Go re-emits the pattern as an ICU pattern made only of explicit
// pieces, valid for ASCII input (Swift gates every input it matches to ASCII):
//
//   - every one-character atom (literal, escape, class, \p{…}, `.`, under the active i / s flags) becomes the
//     explicit set of ASCII code points regexp2 itself matches for it — computed by compiling the atom alone with
//     regexp2 and testing all 128 ASCII characters, so .NET class tables, case folding, class subtraction and
//     escapes are never re-implemented, and ICU flags / Unicode tables / line-terminator rules play no part;
//   - anchors are spelled out (^ $ \Z with and without m, \b \B as look-arounds over regexp2's \w set);
//   - every capture group becomes an unnamed ICU group in source order; slots maps regexp2's capture slots to
//     ICU group indices (regexp2 numbers named groups after the unnamed ones), backreferences are renumbered;
//   - replacement templates are parsed by regexp2 itself (syntax.NewReplacerData) into a small program
//     (literal / group slot / $` $' $+ $_), executed by Swift.
//
// What stays with Go (why != ""): x mode, conditionals, balancing groups, \G, octal / \c escapes, multi-digit
// backreferences, forward / self references, captures or backreferences inside look-behinds (.NET evaluates
// them right to left), quantified zero-width atoms, and — for patterns used to replace — repeats whose body can
// match empty (the engines may leave different captures from the last empty iteration). When Go matches a URL
// with RE2 (compileURLRe), the pattern must also mean the same there: syntax RE2 reads differently is refused and
// every class is checked against RE2 too.
//
// Exactness is tested, not argued: rx2DiffCases / TestRewriteICUDifferential generate patterns × ASCII inputs
// and record regexp2's matches and replacements (UnitTests/NativeMitmRegexFixtures.json); the Swift unit test
// replays them through NSRegularExpression.

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/dlclark/regexp2"
	"github.com/dlclark/regexp2/syntax"
)

// SnapTemplate is a replacement program (regexp2 syntax.ReplacerData): R[i] >= 0 → S[R[i]]; R[i] <= -5 → the
// capture with slot -5-R[i]; -4 the text before the match ($`), -3 the text after it ($'), -2 the last group
// ($+), -1 the whole input ($_).
type SnapTemplate struct {
	S []string `json:"s,omitempty"`
	R []int    `json:"r"`
}

type rx2Flags struct{ i, m, s, n bool }

type rx2Group struct {
	name   string // "" unnamed
	icu    int    // ICU group index
	closed bool
}

type rx2Parser struct {
	p         []rune
	pos       int
	b         strings.Builder
	groups    []*rx2Group
	byNum     map[int]*rx2Group // regexp2 group number → group (filled after numbering)
	re2       bool              // the URL matcher is RE2: classes must agree with it
	replace   bool              // the pattern is used to replace (captures / positions matter)
	why       string
	inLB      int // depth of look-behinds
	inLA      int // depth of look-aheads
	capInLook bool
	unnamed   int
	refs      []rx2Ref
}

type rx2Ref struct {
	at   int    // byte offset in b where the placeholder sits
	num  int    // regexp2 number (or -1 with name)
	name string //
	ci   bool
}

func (p *rx2Parser) fail(why string) {
	if p.why == "" {
		p.why = why
	}
}

// rx2Translation is the result for one pattern.
type rx2Translation struct {
	ICU   string
	Slots []int // slots[s] = ICU group index of regexp2 capture slot s
	Why   string
}

var (
	rx2Mu    sync.Mutex
	rx2Cache = map[string]rx2Translation{}
	rx2Sets  = map[string][]bool{}
)

// rx2Translate translates the regexp2 pattern p (compiled as re). re2 says Go matches URLs with RE2 (the
// translation must then also equal RE2's reading); replace says the pattern's captures / match positions are used.
func rx2Translate(re *regexp2.Regexp, p string, re2, replace bool) rx2Translation {
	key := fmt.Sprintf("%t%t%s", re2, replace, p)
	rx2Mu.Lock()
	if t, ok := rx2Cache[key]; ok {
		rx2Mu.Unlock()
		return t
	}
	rx2Mu.Unlock()
	t := rx2TranslateUncached(re, p, re2, replace)
	rx2Mu.Lock()
	if len(rx2Cache) > 8192 {
		rx2Cache = map[string]rx2Translation{}
	}
	rx2Cache[key] = t
	rx2Mu.Unlock()
	return t
}

func rx2TranslateUncached(re *regexp2.Regexp, p string, re2, replace bool) rx2Translation {
	if re == nil || p == "" {
		return rx2Translation{Why: "no pattern"}
	}
	if re.RightToLeft() {
		return rx2Translation{Why: "options"}
	}
	if re2 {
		for _, bad := range []string{"[:", `\Q`, `\x{`, "(?P", `\C`, "(?U"} {
			if strings.Contains(p, bad) {
				return rx2Translation{Why: "re2 syntax " + bad}
			}
		}
		for i := 0; i+2 < len(p); i++ {
			if p[i] == '\\' {
				if (p[i+1] == 'p' || p[i+1] == 'P') && p[i+2] != '{' {
					return rx2Translation{Why: "re2 \\p"}
				}
				i++
			}
		}
	}
	if strings.Contains(p, `\p{`) || strings.Contains(p, `\P{`) {
		// regexp2's first-character analysis mishandles Unicode categories in unions: `\P{Ll}|[\w-]` does not
		// match "b" (found by the differential fuzz). Categories stay native only where no union can arise.
		if strings.ContainsAny(p, "|?*") || strings.Contains(p, "{0") || strings.Contains(p, `\P{`) {
			return rx2Translation{Why: "unicode category in a union"}
		}
	}
	ps := &rx2Parser{p: []rune(p), re2: re2, replace: replace, byNum: map[int]*rx2Group{}}
	ps.alternation(rx2Flags{}, 0)
	if ps.why == "" && ps.pos < len(ps.p) {
		ps.fail("unbalanced )")
	}
	if ps.why == "" && ps.capInLook && len(ps.refs) > 0 {
		ps.fail("capture in look-around with backreferences")
	}
	if ps.why != "" {
		return rx2Translation{Why: ps.why}
	}
	// regexp2's numbering: unnamed groups 1..k in order, named ones by GroupNumberFromName.
	n := 0
	seen := map[string]bool{}
	for _, g := range ps.groups {
		if g.name == "" {
			n++
			ps.byNum[n] = g
			continue
		}
		if seen[g.name] {
			return rx2Translation{Why: "duplicate group name"}
		}
		seen[g.name] = true
		num := re.GroupNumberFromName(g.name)
		if num < 0 {
			return rx2Translation{Why: "group name"}
		}
		ps.byNum[num] = g
	}
	nums := re.GetGroupNumbers() // nums[slot] = group number
	if len(nums) != len(ps.groups)+1 {
		return rx2Translation{Why: fmt.Sprintf("groups %d vs %d", len(nums)-1, len(ps.groups))}
	}
	slots := make([]int, len(nums))
	for s, num := range nums {
		if num == 0 {
			slots[s] = 0
			continue
		}
		g := ps.byNum[num]
		if g == nil {
			return rx2Translation{Why: "group numbering"}
		}
		slots[s] = g.icu
	}
	// backreferences: placeholders → ICU indices
	out := ps.b.String()
	for i := len(ps.refs) - 1; i >= 0; i-- {
		r := ps.refs[i]
		var g *rx2Group
		if r.name != "" {
			num := re.GroupNumberFromName(r.name)
			g = ps.byNum[num]
		} else {
			g = ps.byNum[r.num]
		}
		if g == nil || !g.closed {
			return rx2Translation{Why: "backreference"}
		}
		ref := "\\" + strconv.Itoa(g.icu)
		if r.ci {
			ref = "(?i:" + ref + ")"
		} else {
			ref = "(?:" + ref + ")"
		}
		out = out[:r.at] + ref + out[r.at:]
	}
	return rx2Translation{ICU: out, Slots: slots}
}

// ---- parser (emits while parsing) ----

func (p *rx2Parser) peek() rune {
	if p.pos < len(p.p) {
		return p.p[p.pos]
	}
	return -1
}

func (p *rx2Parser) hasPrefix(s string) bool {
	r := []rune(s)
	if p.pos+len(r) > len(p.p) {
		return false
	}
	for i, c := range r {
		if p.p[p.pos+i] != c {
			return false
		}
	}
	return true
}

// alternation parses until ")" (depth > 0) or the end; flags set inside apply to the rest of this group.
func (p *rx2Parser) alternation(f rx2Flags, depth int) {
	for p.why == "" {
		f = p.sequence(f, depth)
		if p.why != "" {
			return
		}
		c := p.peek()
		if c == '|' {
			p.pos++
			p.b.WriteByte('|')
			continue
		}
		if c == ')' {
			if depth == 0 {
				p.fail("unbalanced )")
			}
			return
		}
		return // end
	}
}

// sequence parses atoms with quantifiers until "|" ")" or the end. It returns the flags in force at its end
// ((?i) inside a sequence lasts to the end of the enclosing group, across "|").
func (p *rx2Parser) sequence(f rx2Flags, depth int) rx2Flags {
	for p.why == "" && p.pos < len(p.p) {
		c := p.peek()
		if c == '|' || c == ')' {
			return f
		}
		start := p.b.Len()
		kind, nf := p.atom(f, depth)
		if p.why != "" {
			return f
		}
		if kind == atomFlags {
			f = nf
			continue
		}
		if kind == atomNone {
			continue
		}
		atomText := p.b.String()[start:]
		p.quantifier(kind, atomText)
	}
	return f
}

const (
	atomNone         = iota // nothing emitted (comment)
	atomFlags               // (?imsn) — flags changed
	atomChar                // one character
	atomZero                // zero-width (anchor, look-around)
	atomGroup               // a group (may be nullable / have captures)
	atomGroupNull           // a group that can match empty
	atomGroupCapNull        // a nullable group containing captures / backrefs
)

// quantifier reads a .NET quantifier after an atom (if any) and emits it.
func (p *rx2Parser) quantifier(kind int, atomText string) {
	c := p.peek()
	q := ""
	switch c {
	case '*', '+', '?':
		q = string(c)
		p.pos++
	case '{':
		// {n} {n,} {n,m}; anything else is a literal "{" (the next atom)
		j := p.pos + 1
		d1 := j
		for j < len(p.p) && p.p[j] >= '0' && p.p[j] <= '9' {
			j++
		}
		if j == d1 {
			return
		}
		if j < len(p.p) && p.p[j] == ',' {
			j++
			for j < len(p.p) && p.p[j] >= '0' && p.p[j] <= '9' {
				j++
			}
		}
		if j >= len(p.p) || p.p[j] != '}' {
			return
		}
		q = string(p.p[p.pos : j+1])
		p.pos = j + 1
	default:
		return
	}
	if kind == atomZero {
		p.fail("quantified zero-width atom")
		return
	}
	unbounded := q == "*" || q == "+" || strings.HasSuffix(q, ",}")
	repeats := q != "?" && q != "{0}" && q != "{1}" && q != "{0,1}" && q != "{1,1}"
	if repeats && (kind == atomGroupCapNull || p.replace && kind == atomGroupNull) {
		p.fail("repeat of a nullable group")
		return
	}
	if unbounded && kind == atomGroupNull {
		// ICU can spin on an unbounded (lazy) loop of something that matches empty (found by the fuzz)
		p.fail("unbounded repeat of a nullable group")
		return
	}
	if kind == atomGroup || kind == atomGroupNull || kind == atomGroupCapNull || kind == atomChar {
		// atom text is self-contained ("\x{..}", "[...]", "(...)", "(?:...)")
	}
	_ = atomText
	p.b.WriteString(q)
	if p.peek() == '?' {
		p.pos++
		p.b.WriteByte('?')
	}
	if c := p.peek(); c == '*' || c == '+' || c == '?' || c == '{' && p.looksQuant() {
		p.fail("nested quantifier")
	}
}

func (p *rx2Parser) looksQuant() bool {
	j := p.pos + 1
	d := j
	for j < len(p.p) && p.p[j] >= '0' && p.p[j] <= '9' {
		j++
	}
	return j > d
}

// atom parses one atom at p.pos and emits its ICU form.
func (p *rx2Parser) atom(f rx2Flags, depth int) (int, rx2Flags) {
	c := p.p[p.pos]
	switch c {
	case '(':
		return p.group(f, depth)
	case '[':
		end := p.classEnd(p.pos)
		if end < 0 {
			p.fail("class")
			return 0, f
		}
		text := string(p.p[p.pos : end+1])
		p.pos = end + 1
		p.emitSet(text, f)
		return atomChar, f
	case '.':
		p.pos++
		p.emitSet(".", f)
		return atomChar, f
	case '^':
		p.pos++
		if f.m {
			p.b.WriteString(`(?:\A|(?<=\x0a))`)
		} else {
			p.b.WriteString(`\A`)
		}
		return atomZero, f
	case '$':
		p.pos++
		if f.m {
			p.b.WriteString(`(?=\x0a|\z)`)
		} else {
			p.b.WriteString(`(?=\x0a?\z)`)
		}
		return atomZero, f
	case '\\':
		return p.escape(f)
	case '*', '+', '?':
		p.fail("quantifier without atom")
		return 0, f
	case '{':
		if p.looksQuant() {
			p.fail("quantifier without atom")
			return 0, f
		}
	case '#', ' ', '\t', '\n', '\r', '\f', '\v':
		// literal outside x mode (x mode is refused)
	}
	p.pos++
	p.emitSet(rx2Lit(c), f)
	return atomChar, f
}

func rx2Lit(c rune) string {
	if c < 0x10000 {
		return fmt.Sprintf(`\u%04X`, c)
	}
	return string(c) // astral: never matches ASCII input except via folding (none exist)
}

func (p *rx2Parser) escape(f rx2Flags) (int, rx2Flags) {
	if p.pos+1 >= len(p.p) {
		p.fail("trailing backslash")
		return 0, f
	}
	d := p.p[p.pos+1]
	switch {
	case d == 'b' || d == 'B':
		p.pos += 2
		w := rx2SetText(p.setOf(`\w`, rx2Flags{}))
		if d == 'b' {
			p.b.WriteString(`(?:(?<=` + w + `)(?!` + w + `)|(?<!` + w + `)(?=` + w + `))`)
		} else {
			p.b.WriteString(`(?:(?<=` + w + `)(?=` + w + `)|(?<!` + w + `)(?!` + w + `))`)
		}
		return atomZero, f
	case d == 'A':
		p.pos += 2
		p.b.WriteString(`\A`)
		return atomZero, f
	case d == 'z':
		p.pos += 2
		p.b.WriteString(`\z`)
		return atomZero, f
	case d == 'Z':
		p.pos += 2
		p.b.WriteString(`(?=\x0a?\z)`)
		return atomZero, f
	case d == 'G':
		p.fail(`\G`)
		return 0, f
	case strings.ContainsRune("wWsSdD", d):
		p.pos += 2
		p.emitSet(`\`+string(d), f)
		return atomChar, f
	case d == 'p' || d == 'P':
		j := p.pos + 2
		if j >= len(p.p) || p.p[j] != '{' {
			p.fail(`\p`)
			return 0, f
		}
		for j < len(p.p) && p.p[j] != '}' {
			j++
		}
		if j >= len(p.p) {
			p.fail(`\p`)
			return 0, f
		}
		text := string(p.p[p.pos : j+1])
		p.pos = j + 1
		p.emitSet(text, f)
		return atomChar, f
	case d >= '1' && d <= '9':
		if p.inLB > 0 {
			p.fail("backreference in look-behind")
			return 0, f
		}
		if p.pos+2 < len(p.p) && p.p[p.pos+2] >= '0' && p.p[p.pos+2] <= '9' {
			p.fail("multi-digit backreference")
			return 0, f
		}
		p.pos += 2
		p.refs = append(p.refs, rx2Ref{at: p.b.Len(), num: int(d - '0'), ci: f.i})
		return atomGroupCapNull, f
	case d == 'k':
		if p.inLB > 0 {
			p.fail("backreference in look-behind")
			return 0, f
		}
		j := p.pos + 2
		if j >= len(p.p) || (p.p[j] != '<' && p.p[j] != '\'') {
			p.fail(`\k`)
			return 0, f
		}
		close := '>'
		if p.p[j] == '\'' {
			close = '\''
		}
		k := j + 1
		for k < len(p.p) && p.p[k] != close {
			k++
		}
		if k >= len(p.p) {
			p.fail(`\k`)
			return 0, f
		}
		name := string(p.p[j+1 : k])
		if name == "" || name[0] >= '0' && name[0] <= '9' {
			p.fail(`\k number`)
			return 0, f
		}
		p.pos = k + 1
		p.refs = append(p.refs, rx2Ref{at: p.b.Len(), num: -1, name: name, ci: f.i})
		return atomGroupCapNull, f
	case d == 'x':
		if p.pos+3 >= len(p.p) || !isHexRune(p.p[p.pos+2]) || !isHexRune(p.p[p.pos+3]) {
			p.fail(`\x`)
			return 0, f
		}
		text := string(p.p[p.pos : p.pos+4])
		p.pos += 4
		p.emitSet(text, f)
		return atomChar, f
	case d == 'u':
		if p.pos+5 >= len(p.p) {
			p.fail(`\u`)
			return 0, f
		}
		for k := 2; k < 6; k++ {
			if !isHexRune(p.p[p.pos+k]) {
				p.fail(`\u`)
				return 0, f
			}
		}
		text := string(p.p[p.pos : p.pos+6])
		p.pos += 6
		p.emitSet(text, f)
		return atomChar, f
	case d == 'c':
		// \cX: a control character (membership computed by regexp2 like every other atom)
		if p.pos+2 >= len(p.p) || !(p.p[p.pos+2] >= 'a' && p.p[p.pos+2] <= 'z' || p.p[p.pos+2] >= 'A' && p.p[p.pos+2] <= 'Z') {
			p.fail(`\c`)
			return 0, f
		}
		text := string(p.p[p.pos : p.pos+3])
		p.pos += 3
		p.emitSet(text, f)
		return atomChar, f
	case strings.ContainsRune("tnrfvea", d):
		p.pos += 2
		p.emitSet(`\`+string(d), f)
		return atomChar, f
	case d >= 'a' && d <= 'z' || d >= 'A' && d <= 'Z' || d >= '0' && d <= '9' || d == '_':
		p.fail(fmt.Sprintf(`\%c`, d)) // \0 octal, \c, \_ (dropped by compileRe already), anything new
		return 0, f
	}
	p.pos += 2
	p.emitSet(rx2Lit(d), f)
	return atomChar, f
}

func isHexRune(c rune) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// classEnd finds the "]" closing the class opened at i (.NET rules: a leading "]" is literal, "\" escapes,
// "-[" starts a subtraction which must end right before the outer "]").
func (p *rx2Parser) classEnd(i int) int {
	j := i + 1
	if j < len(p.p) && p.p[j] == '^' {
		j++
	}
	first := true
	for j < len(p.p) {
		c := p.p[j]
		switch {
		case c == '\\':
			if j+1 < len(p.p) && (p.p[j+1] == 'p' || p.p[j+1] == 'P') {
				k := j + 2
				for k < len(p.p) && p.p[k] != '}' {
					k++
				}
				j = k + 1
			} else {
				j += 2
			}
			first = false
			continue
		case c == ']' && !first:
			return j
		case c == '[' && j+1 < len(p.p) && p.p[j+1] == ':':
			return -1
		case c == '-' && !first && j+1 < len(p.p) && p.p[j+1] == '[':
			if p.re2 {
				return -1
			}
			k := p.classEnd(j + 1)
			if k < 0 || k+1 >= len(p.p) || p.p[k+1] != ']' {
				return -1
			}
			return k + 1
		}
		first = false
		j++
	}
	return -1
}

// group parses "(" … ")".
func (p *rx2Parser) group(f rx2Flags, depth int) (int, rx2Flags) {
	p.pos++ // (
	inner := f
	kind := ""
	var g *rx2Group
	if p.peek() == '?' {
		p.pos++
		switch {
		case p.hasPrefix(":"):
			p.pos++
			kind = "(?:"
		case p.hasPrefix("="), p.hasPrefix("!"):
			kind = "(?" + string(p.peek())
			p.pos++
		case p.hasPrefix("<="), p.hasPrefix("<!"):
			kind = "(?" + string(p.p[p.pos:p.pos+2])
			p.pos += 2
		case p.hasPrefix(">"):
			p.pos++
			kind = "(?>"
		case p.hasPrefix("#"):
			for p.pos < len(p.p) && p.p[p.pos] != ')' {
				p.pos++
			}
			if p.pos >= len(p.p) {
				p.fail("comment")
				return 0, f
			}
			p.pos++
			return atomNone, f
		case p.hasPrefix("("):
			p.fail("conditional")
			return 0, f
		case p.hasPrefix("<"), p.hasPrefix("'"):
			close := '>'
			if p.peek() == '\'' {
				close = '\''
			}
			k := p.pos + 1
			for k < len(p.p) && p.p[k] != close {
				if !(p.p[k] == '_' || p.p[k] >= '0' && p.p[k] <= '9' || p.p[k] >= 'a' && p.p[k] <= 'z' || p.p[k] >= 'A' && p.p[k] <= 'Z') {
					p.fail("group name") // balancing groups (?<a-b>) and anything unusual
					return 0, f
				}
				k++
			}
			if k >= len(p.p) || k == p.pos+1 {
				p.fail("group name")
				return 0, f
			}
			name := string(p.p[p.pos+1 : k])
			if name[0] >= '0' && name[0] <= '9' {
				p.fail("numbered group name")
				return 0, f
			}
			p.pos = k + 1
			g = &rx2Group{name: name}
			kind = "("
		default:
			// flags: (?imsnx-imsnx) or (?imsnx-imsnx: …)
			on := true
			nf := f
			for p.pos < len(p.p) && p.p[p.pos] != ')' && p.p[p.pos] != ':' {
				switch p.p[p.pos] {
				case '-':
					on = false
				case 'i':
					nf.i = on
				case 'm':
					nf.m = on
				case 's':
					nf.s = on
				case 'n':
					nf.n = on
				default:
					p.fail("inline option")
					return 0, f
				}
				p.pos++
			}
			if p.pos >= len(p.p) {
				p.fail("inline option")
				return 0, f
			}
			if p.p[p.pos] == ')' {
				p.pos++
				return atomFlags, nf
			}
			p.pos++ // ':'
			inner = nf
			kind = "(?:"
		}
	} else if f.n {
		kind = "(?:"
	} else {
		g = &rx2Group{}
		kind = "("
	}
	lb := kind == "(?<=" || kind == "(?<!"
	la := kind == "(?=" || kind == "(?!"
	if g != nil {
		if p.inLB > 0 || p.inLA > 0 {
			// harmless for a match-only pattern without backreferences (nothing reads the capture);
			// otherwise the engines' capture rules inside look-arounds would matter
			if p.replace {
				p.fail("capture in look-around")
				return 0, f
			}
			p.capInLook = true
		}
		p.groups = append(p.groups, g)
		g.icu = len(p.groups)
	}
	if lb {
		p.inLB++
	}
	if la {
		p.inLA++
	}
	p.b.WriteString(kind)
	start := p.b.Len()
	refsBefore := len(p.refs)
	groupsBefore := len(p.groups)
	p.alternation(inner, depth+1)
	if p.why != "" {
		return 0, f
	}
	if p.peek() != ')' {
		p.fail("unclosed group")
		return 0, f
	}
	p.pos++
	body := p.b.String()[start:]
	p.b.WriteByte(')')
	if lb {
		p.inLB--
	}
	if la {
		p.inLA--
	}
	if g != nil {
		g.closed = true
	}
	switch kind {
	case "(?=", "(?!", "(?<=", "(?<!":
		return atomZero, f
	}
	hasCap := len(p.refs) > refsBefore || len(p.groups) > groupsBefore || g != nil
	if rx2Nullable(body, len(p.refs) > refsBefore) {
		if hasCap {
			return atomGroupCapNull, f
		}
		return atomGroupNull, f
	}
	return atomGroup, f
}

// rx2Nullable: can the emitted ICU body match the empty string? Decided by ICU syntax structure is hard; use
// Go's regexp on a version of the body with backreferences / look-arounds treated conservatively: any body with
// a backreference is nullable (a group may be empty), otherwise the emitted body (only explicit sets, groups,
// quantifiers, anchors and look-arounds) is checked with RE2 after look-arounds are removed.
func rx2Nullable(body string, hasRef bool) bool {
	if hasRef {
		return true
	}
	// strip look-arounds (zero-width: they never consume) and anchors
	s := rx2StripZero(body)
	re, err := regexp.Compile(`\A(?:` + s + `)\z`)
	if err != nil {
		return true // unsure
	}
	return re.MatchString("")
}

// rx2StripZero removes look-around groups, \A \z and our anchor spellings from an emitted body.
func rx2StripZero(s string) string {
	var b strings.Builder
	r := []rune(s)
	for i := 0; i < len(r); i++ {
		if r[i] == '\\' && i+1 < len(r) {
			if r[i+1] == 'A' || r[i+1] == 'z' {
				i++
				continue
			}
			b.WriteRune(r[i])
			b.WriteRune(r[i+1])
			i++
			continue
		}
		if r[i] == '[' { // copy a set verbatim
			j := i + 1
			for j < len(r) && r[j] != ']' {
				if r[j] == '\\' {
					j++
				}
				j++
			}
			b.WriteString(string(r[i : j+1]))
			i = j
			continue
		}
		if r[i] == '(' && i+2 < len(r) && r[i+1] == '?' && (r[i+2] == '=' || r[i+2] == '!' || r[i+2] == '<' && i+3 < len(r) && (r[i+3] == '=' || r[i+3] == '!')) {
			depth := 0
			j := i
			for ; j < len(r); j++ {
				if r[j] == '\\' {
					j++
					continue
				}
				if r[j] == '[' {
					for j < len(r) && r[j] != ']' {
						if r[j] == '\\' {
							j++
						}
						j++
					}
					continue
				}
				if r[j] == '(' {
					depth++
				} else if r[j] == ')' {
					depth--
					if depth == 0 {
						break
					}
				}
			}
			i = j
			continue
		}
		if r[i] == '(' && i+2 < len(r) && r[i+1] == '?' && r[i+2] == '>' {
			b.WriteString("(?:")
			i += 2
			continue
		}
		b.WriteRune(r[i])
	}
	return strings.ReplaceAll(b.String(), `(?i:`, `(?:`)
}

// emitSet emits the explicit ASCII set regexp2 matches for a one-character atom under flags f.
func (p *rx2Parser) emitSet(atom string, f rx2Flags) {
	set := p.setOf(atom, f)
	if set == nil {
		return
	}
	p.b.WriteString(rx2SetText(set))
}

// setOf computes which ASCII characters (0–127) the atom matches under flags i / s (nil + fail: unknown).
func (p *rx2Parser) setOf(atom string, f rx2Flags) []bool {
	set, why := rx2AtomSet(atom, rx2RE2Text(atom), f, p.re2)
	if why != "" {
		p.fail(why)
		return nil
	}
	return set
}

// rx2RE2Text spells a regexp2 one-character atom for RE2 (literals \uXXXX → \x{…}; the rest as is).
func rx2RE2Text(atom string) string {
	if len(atom) == 6 && strings.HasPrefix(atom, `\u`) {
		return `\x{` + atom[2:] + `}`
	}
	return atom
}

func rx2AtomSet(atom, atomRE2 string, f rx2Flags, re2 bool) ([]bool, string) {
	on, off := "", ""
	if f.i {
		on += "i"
	} else {
		off += "i"
	}
	if f.s {
		on += "s"
	} else {
		off += "s"
	}
	flags := "(?" + on
	if off != "" {
		flags += "-" + off
	}
	flags += ")"
	key := fmt.Sprintf("%t|%s|%s", re2, flags, atom)
	rx2Mu.Lock()
	if s, ok := rx2Sets[key]; ok {
		rx2Mu.Unlock()
		return s, ""
	}
	rx2Mu.Unlock()
	re, err := regexp2.Compile(`\A`+flags+`(?:`+atom+`)\z`, regexp2.None)
	if err != nil {
		return nil, "atom " + atom
	}
	set := make([]bool, 128)
	for c := 0; c < 128; c++ {
		ok, err := re.MatchString(string(rune(c)))
		if err != nil {
			return nil, "atom " + atom
		}
		set[c] = ok
	}
	if re2 {
		// Go matches URLs with RE2: the atom must mean the same there (printable ASCII is all a URL holds,
		// but compare every ASCII character anyway).
		r2, err := regexp.Compile(`\A` + flags + `(?:` + atomRE2 + `)\z`)
		if err != nil {
			return nil, "re2 atom " + atom
		}
		for c := 0x20; c < 0x7f; c++ {
			if r2.MatchString(string(rune(c))) != set[c] {
				return nil, "re2 differs " + atom
			}
		}
	}
	rx2Mu.Lock()
	rx2Sets[key] = set
	rx2Mu.Unlock()
	return set, ""
}

// rx2SetText spells a set of ASCII code points as ICU: one character, a [..] of ranges, or (?!) when empty.
// Letters and digits are written as themselves (no flags are ever set, so they mean only themselves), every
// other code point as \xHH.
func rx2SetText(set []bool) string {
	var ranges [][2]int
	for c := 0; c < 128; c++ {
		if !set[c] {
			continue
		}
		if n := len(ranges); n > 0 && ranges[n-1][1] == c-1 {
			ranges[n-1][1] = c
		} else {
			ranges = append(ranges, [2]int{c, c})
		}
	}
	switch {
	case len(ranges) == 0:
		return `(?!)`
	case len(ranges) == 1 && ranges[0][0] == ranges[0][1]:
		return rx2Char(ranges[0][0])
	}
	var b strings.Builder
	b.WriteByte('[')
	for _, r := range ranges {
		b.WriteString(rx2Char(r[0]))
		if r[1] > r[0] {
			if r[1] > r[0]+1 {
				b.WriteByte('-')
			}
			b.WriteString(rx2Char(r[1]))
		}
	}
	b.WriteByte(']')
	return b.String()
}

func rx2Char(c int) string {
	if c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
		return string(rune(c))
	}
	return fmt.Sprintf(`\x%02x`, c)
}

// ---- replacement templates ----

// rx2Template parses a replacement exactly as regexp2's Replace does (nil, false: regexp2 reports an error).
func rx2Template(re *regexp2.Regexp, repl string) (*SnapTemplate, bool) {
	caps, capsize, capnames, ok := rx2Internals(re)
	if !ok {
		return nil, false
	}
	data, err := func() (d *syntax.ReplacerData, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("%v", r)
			}
		}()
		return syntax.NewReplacerData(repl, caps, capsize, capnames, syntax.RegexOptions(0)) // compileRe: regexp2.None
	}()
	if err != nil {
		return nil, false
	}
	for _, r := range data.Rules {
		if r == -1 {
			// $_ : regexp2 inserts its runner's current text, which is not always the whole input on later
			// matches of a replace-all (found by the differential fuzz) — not reproduced; Go keeps the rule.
			return nil, false
		}
	}
	return &SnapTemplate{S: data.Strings, R: append([]int{}, data.Rules...)}, true
}

// rx2Internals reads the capture tables regexp2.Replace passes to NewReplacerData (unexported fields of the
// pinned regexp2 version; TestRewriteICUTemplateInternals checks them against Replace on real inputs).
func rx2Internals(re *regexp2.Regexp) (caps map[int]int, capsize int, capnames map[string]int, ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	v := reflect.ValueOf(re).Elem()
	fc, fs, fn := v.FieldByName("caps"), v.FieldByName("capsize"), v.FieldByName("capnames")
	if !fc.IsValid() || !fs.IsValid() || !fn.IsValid() {
		return nil, 0, nil, false
	}
	caps = *(*map[int]int)(unsafe.Pointer(fc.UnsafeAddr()))
	capsize = int(fs.Int())
	capnames = *(*map[string]int)(unsafe.Pointer(fn.UnsafeAddr()))
	return caps, capsize, capnames, true
}

// rx2SortedSlots is a stable debug view.
func rx2SortedSlots(m map[int]int) []int {
	var k []int
	for x := range m {
		k = append(k, x)
	}
	sort.Ints(k)
	return k
}
