package mitm

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/dlclark/regexp2"
)

// rwAllRules: the CI suites' rules plus, with TERN_QX_AUDIT_DIR, the user's corpus.
func rwAllRules(t *testing.T) []*Rule {
	var all []*Rule
	for _, s := range rwCISuitesRules(t) {
		all = append(all, s...)
	}
	if dir := os.Getenv("TERN_QX_AUDIT_DIR"); dir != "" {
		m, _ := filepath.Glob(filepath.Join(dir, "res/*"))
		m2, _ := filepath.Glob(filepath.Join(dir, "corpus/mod/*"))
		for _, f := range append(m, m2...) {
			b, _ := os.ReadFile(f)
			rs := &Ruleset{}
			rs.ParseText(string(b), "x", nil)
			all = append(all, rs.Rules...)
		}
	}
	return all
}

// TestRewriteICUCoverage logs how many rule patterns translate (and why the rest do not); every pattern the old
// whitelist accepted must still translate.
func TestRewriteICUCoverage(t *testing.T) {
	why := map[string]int{}
	ok, total, oldOK, lost := 0, 0, 0, 0
	for _, r := range rwAllRules(t) {
		if r.re == nil {
			continue
		}
		total++
		redirect := r.Kind == KindURL && (r.Action == "302" || r.Action == "307" || r.Action == "header")
		tr := rx2Translate(r.re, r.re.String(), r.fre != nil, redirect)
		old, _, _ := portableRegex(r.re.String())
		if old {
			oldOK++
		}
		if tr.Why == "" {
			ok++
		} else {
			why[tr.Why]++
			if old {
				lost++
				t.Logf("old-portable pattern no longer translates (%s): %q", tr.Why, r.re.String())
			}
		}
	}
	var ks []string
	for k := range why {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool { return why[ks[i]] > why[ks[j]] })
	for _, k := range ks {
		t.Logf("  %5d  %s", why[k], k)
	}
	t.Logf("patterns %d: translated %d (old whitelist %d), lost %d", total, ok, oldOK, lost)
}

// ---- differential fixture (regexp2 / RE2 → Swift ICU) ----

type rxFixInput struct {
	S string  `json:"s"`
	M bool    `json:"m"`           // the pattern matches (RE2 when re2, else regexp2)
	F *string `json:"f,omitempty"` // regexp2 Replace(s, tp, -1, 1) (absent: error)
	A *string `json:"a,omitempty"` // regexp2 Replace(s, tp, -1, -1)
}

type rxFixCase struct {
	Re   *SnapRegex    `json:"re"`
	RE2  bool          `json:"re2,omitempty"`
	Repl bool          `json:"repl,omitempty"`
	T    string        `json:"t,omitempty"` // template text
	TP   *SnapTemplate `json:"tp,omitempty"`
	In   []rxFixInput  `json:"in"`
}

type rxFixtures struct {
	Version int         `json:"version"`
	Cases   []rxFixCase `json:"cases"`
	// net/url escape tables Swift hard-codes (bit set: the byte is escaped): path (EscapedPath), query
	// component (QueryEscape).
	PathEsc  []int `json:"pathEsc"`
	QueryEsc []int `json:"queryEsc"`
	Net      rxNet `json:"net"`
}

// rxNet: net/url / net / net/http behaviour the Swift engine reproduces (GoNetSemantics.swift).
type rxNet struct {
	Targets []rxTarget        `json:"targets"`
	Queries [][2]string       `json:"queries"` // raw → flowCleanQuery
	Hosts   []rxHostPort      `json:"hosts"`
	Status  map[string]string `json:"status"`
	Sniff   [][2]string       `json:"sniff"` // base64 data → DetectContentType
}

type rxTarget struct {
	T     string `json:"t"`
	Err   bool   `json:"err,omitempty"`
	Host  string `json:"host,omitempty"`
	Path  string `json:"path,omitempty"`
	Query string `json:"query,omitempty"`
	Force bool   `json:"force,omitempty"`
}

type rxHostPort struct {
	HP   string `json:"hp"`
	Err  bool   `json:"err,omitempty"`
	Host string `json:"host,omitempty"`
	Port string `json:"port,omitempty"`
}

func rxBuildNet() rxNet {
	var n rxNet
	targets := []string{"/", "/a/b", "/plain/a b", "/plain/%zz", "/plain/a|b", "/plain#frag", "/plain/\u00e9", "/a%7cb", "/a%7Cb", "/a?",
		"/a??", "/a?b?", "/a?x=1&y=%G1", "/~user/(x)*!'", "/a[b]", "/a;b=c", "/a%2Fb", "/a%2fb", "/%41", "/a%", "/a%4", "//x/y",
		"*", "https://h.com/p?q", "http://h.com", "https://h.com:8443/a b?x", "https://u@h.com/", "/a\x7f", "/a\tb", "/\"q\"",
		"/<>^`{}", "/a\\b", "/a?q=\x01", "/\u00e4?\u00fc=1", "/a?b#c", "/%E4%B8%AD", "/a+b", "/@:,$&=+;"}
	for _, t := range targets {
		u, err := url.ParseRequestURI(t)
		if err != nil {
			n.Targets = append(n.Targets, rxTarget{T: t, Err: true})
			continue
		}
		n.Targets = append(n.Targets, rxTarget{T: t, Host: u.Host, Path: u.EscapedPath(), Query: u.RawQuery, Force: u.ForceQuery})
	}
	for _, q := range []string{"a=1", "a=1;b=2", "a=%G1", "b=2&a=1;x&a=3", "x=%zz&y=2", "k+v=a+b;", "%", "a=1&&b=2&=3&c", "é=ü;", "z=1&a=%20%41;",
		"a=%2", "a=b=c;"} {
		n.Queries = append(n.Queries, [2]string{q, flowCleanQuery(q)})
	}
	for _, hp := range []string{"h.com", "h.com:443", "h.com:", "2402:4e00::1", "[::1]:443", "[::1]", "[::1]x", "[::1]:", "a:b:c", ":80", "[a]b]:1", "h[x]:1", ""} {
		h, p, err := net.SplitHostPort(hp)
		if err != nil {
			n.Hosts = append(n.Hosts, rxHostPort{HP: hp, Err: true})
			continue
		}
		n.Hosts = append(n.Hosts, rxHostPort{HP: hp, Host: h, Port: p})
	}
	n.Status = map[string]string{}
	for c := 0; c < 1000; c++ {
		if t := http.StatusText(c); t != "" {
			n.Status[strconv.Itoa(c)] = t
		}
	}
	samples := [][]byte{nil, []byte(" "), []byte("hello"), []byte("  <html>x"), []byte("<HTML "), []byte("<!-- c"), []byte("<?xml v"),
		[]byte("\x00\x01"), []byte("GIF89a..."), []byte("\x89PNG\r\n\x1a\n...."), []byte("\xff\xd8\xff\xe0"), []byte("%PDF-1.4"),
		[]byte("{\"a\":1}"), []byte("\xef\xbb\xbfhi"), []byte("\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom"), []byte("PK\x03\x04"),
		[]byte("RIFF\x00\x00\x00\x00WEBPVP8 "), []byte("\x1f\x8b\x08\x00"), []byte("<p>x"), []byte("<pre>"), []byte("\t\n<b>bold"), []byte("ID3\x03"),
		[]byte(strings.Repeat("a", 600) + "\x00")}
	for _, b := range samples {
		n.Sniff = append(n.Sniff, [2]string{base64.StdEncoding.EncodeToString(b), http.DetectContentType(b)})
	}
	return n
}

type rxGen struct{ r *rand.Rand }

func (g *rxGen) pick(xs ...string) string { return xs[g.r.Intn(len(xs))] }

func (g *rxGen) atom(depth int, groups *int) string {
	switch k := g.r.Intn(20); {
	case k < 6:
		return g.pick("a", "b", "A", "B", "-", "/", `\.`, ".", "_", "1", "x", "k", "K", "i", "I", " ", `\-`, `\/`, `\?`, "%", "=", "&")
	case k < 9:
		return g.pick("[ab]", "[^a]", `\w`, `\d`, `\s`, `\W`, `\D`, `\S`, `\p{L}`, `\p{Lu}`, `\P{Ll}`, "[a-z]", "[A-Z0-9_]", `[a-z-[aeiou]]`, `[\w-]`, `[^\r\n]`, "[.]", `[\]]`, "[]a]", `\x41`, `\u0062`, `\t`, `\n`, `\r`)
	case k < 11:
		return g.pick("^", "$", `\b`, `\B`, `\A`, `\z`, `\Z`)
	case k < 16 && depth < 3:
		inner := g.alt(depth+1, groups)
		switch g.r.Intn(9) {
		case 0, 1, 2:
			*groups++
			return "(" + inner + ")"
		case 3:
			return "(?:" + inner + ")"
		case 4:
			*groups++
			return "(?<n" + strconv.Itoa(*groups) + ">" + inner + ")"
		case 5:
			return "(?" + g.pick("=", "!", "<=", "<!") + inner + ")"
		case 6:
			return "(?>" + inner + ")"
		case 7:
			return "(?" + g.pick("i", "m", "s", "-i", "n", "im") + ":" + inner + ")"
		default:
			return "(?" + g.pick("i", "m", "s", "-i") + ")"
		}
	case k < 18 && *groups > 0:
		n := 1 + g.r.Intn(*groups)
		if g.r.Intn(3) == 0 {
			return `\k<n` + strconv.Itoa(n) + `>`
		}
		return `\` + strconv.Itoa(n)
	}
	return g.pick("ab", "a", "/", "b")
}

func (g *rxGen) seq(depth int, groups *int) string {
	var b strings.Builder
	n := 1 + g.r.Intn(4)
	for i := 0; i < n; i++ {
		b.WriteString(g.atom(depth, groups))
		if g.r.Intn(3) == 0 {
			b.WriteString(g.pick("*", "+", "?", "{2}", "{1,3}", "{0,}", "*?", "+?", "??", "{2,}?"))
		}
	}
	return b.String()
}

func (g *rxGen) alt(depth int, groups *int) string {
	s := g.seq(depth, groups)
	if g.r.Intn(4) == 0 {
		s += "|" + g.seq(depth, groups)
	}
	return s
}

func (g *rxGen) input(visible bool) string {
	n := g.r.Intn(12)
	var b strings.Builder
	for i := 0; i < n; i++ {
		if visible {
			b.WriteString(g.pick("a", "b", "A", "B", "-", "/", ".", "_", "1", "x", "k", "K", "i", "I", "%", "=", "&", "?", "e", "z", "]"))
		} else {
			b.WriteString(g.pick("a", "b", "A", "B", "-", "/", ".", "_", "1", "x", "k", "K", "i", "I", " ", "\n", "\r", "\t", "e", "]"))
		}
	}
	return b.String()
}

func rxFixCaseFor(re *regexp2.Regexp, re2, repl bool, tmpl string, inputs []string) (rxFixCase, bool) {
	c := rxFixCase{RE2: re2, Repl: repl}
	c.Re = snapRegexOf(re, re2, repl)
	if !c.Re.OK {
		return c, false
	}
	var fre *regexp.Regexp
	if re2 {
		fre = compileURLRe(re.String())
		if fre == nil {
			return c, false
		}
	}
	if repl {
		c.T = tmpl
		tp, terr := snapTemplate(re, tmpl)
		if terr || tp == nil {
			return c, false
		}
		c.TP = tp
	}
	for _, s := range inputs {
		in := rxFixInput{S: s}
		if fre != nil {
			in.M = fre.MatchString(s)
		} else {
			m, err := re.MatchString(s)
			if err != nil {
				return c, false
			}
			in.M = m
		}
		if repl {
			if f, err := re.Replace(s, tmpl, -1, 1); err == nil {
				in.F = &f
			}
			if a, err := re.Replace(s, tmpl, -1, -1); err == nil {
				in.A = &a
			}
		}
		c.In = append(c.In, in)
	}
	return c, true
}

func rxBuildFixtures(t *testing.T) rxFixtures {
	fx := rxFixtures{Version: 1}
	seed, want := int64(20261024), 1500
	if v := os.Getenv("TERN_REGEX_FUZZ"); v != "" { // local stress runs: TERN_REGEX_FUZZ=<seed>
		seed, _ = strconv.ParseInt(v, 10, 64)
		want = 30000
	}
	g := &rxGen{r: rand.New(rand.NewSource(seed))}
	tmpls := []string{"$1", "${1}", "$0", "$&", "$$", "$`", "$'", "$+", "$_", "${n1}", "$9", "x$1y", "$", "${x}", "$12", "<$2>", "$1$1", "-"}
	made := 0
	for tries := 0; made < want && tries < want*20; tries++ {
		groups := 0
		p := g.alt(0, &groups)
		re, err := regexp2.Compile(p, regexp2.None)
		if err != nil {
			continue
		}
		re2 := g.r.Intn(3) == 0 && compileURLRe(p) != nil
		repl := !re2 && g.r.Intn(2) == 0
		var ins []string
		for i := 0; i < 10; i++ {
			ins = append(ins, g.input(re2))
		}
		c, ok := rxFixCaseFor(re, re2, repl, tmpls[g.r.Intn(len(tmpls))], ins)
		if !ok {
			continue
		}
		fx.Cases = append(fx.Cases, c)
		made++
	}
	// the CI suites' real patterns with sample URLs
	for _, r := range rwAllRulesCI(t) {
		if r.re == nil {
			continue
		}
		s := sampleURL(r.Pattern)
		if s == "" {
			continue
		}
		ins := []string{s, strings.Replace(s, "http://", "https://", 1), strings.ToUpper(s), s + "/x?y=1", ""}
		redirect := r.Kind == KindURL && (r.Action == "302" || r.Action == "307" || r.Action == "header")
		tmpl := r.Target
		if !redirect {
			tmpl = ""
		}
		if c, ok := rxFixCaseFor(r.re, r.fre != nil, redirect, tmpl, ins); ok {
			fx.Cases = append(fx.Cases, c)
		}
	}
	for c := 0; c < 256; c += 32 {
		pm, qm := 0, 0
		for i := 0; i < 32; i++ {
			b := string([]byte{byte(c + i)})
			if (&url.URL{Path: "/" + b}).EscapedPath() != "/"+b {
				pm |= 1 << i
			}
			if url.QueryEscape(b) != b {
				qm |= 1 << i
			}
		}
		fx.PathEsc = append(fx.PathEsc, pm)
		fx.QueryEsc = append(fx.QueryEsc, qm)
	}
	fx.Net = rxBuildNet()
	return fx
}

func rwAllRulesCI(t *testing.T) []*Rule {
	var all []*Rule
	for _, s := range rwCISuitesRules(t) {
		all = append(all, s...)
	}
	return all
}

// TestGenRegexFixtures writes UnitTests/NativeMitmRegexFixtures.json (TERN_GEN_REGEX_FIXTURES=<file>).
func TestGenRegexFixtures(t *testing.T) {
	out := os.Getenv("TERN_GEN_REGEX_FIXTURES")
	if out == "" {
		t.Skip("set TERN_GEN_REGEX_FIXTURES=<path to UnitTests/NativeMitmRegexFixtures.json>")
	}
	fx := rxBuildFixtures(t)
	b, err := json.Marshal(fx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d cases, %d KB", len(fx.Cases), len(b)>>10)
}

// TestRegexFixturesCurrent: the committed fixture is what Go generates now.
func TestRegexFixturesCurrent(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "UnitTests", "NativeMitmRegexFixtures.json"))
	if err != nil {
		t.Skip("no committed fixture")
	}
	now, _ := json.Marshal(rxBuildFixtures(t))
	if !bytes.Equal(bytes.TrimSpace(b), now) {
		t.Fatal("NativeMitmRegexFixtures.json is stale: regenerate (TestGenRegexFixtures)")
	}
}

// TestRewriteICUTemplateInternals: the replacement program read through rx2Internals reproduces Replace.
func TestRewriteICUTemplateInternals(t *testing.T) {
	if _, ok := rx2Template(regexp2.MustCompile(`a`, regexp2.None), "$_"); ok {
		t.Error("$_ must stay with Go (regexp2's runner text)")
	}
	for _, c := range [][3]string{
		{`(a)(?<n>b)(c)`, `[$1|$2|$3|${n}|$+|$&|$$|$9|${x}]`, "xabcx"},
		{`(?<n>b)`, `${n}$1$0`, "abc"},
		{`(\w+)-(\w+)`, "$2-$1 $` $'", "k aa-bb z"},
	} {
		re := regexp2.MustCompile(c[0], regexp2.None)
		want, err := re.Replace(c[2], c[1], -1, -1)
		if err != nil {
			t.Fatal(err)
		}
		tp, ok := rx2Template(re, c[1])
		if !ok {
			t.Fatalf("%q: no template", c[0])
		}
		m, _ := re.FindStringMatch(c[2])
		groups := m.Groups()
		var got strings.Builder
		got.WriteString(c[2][:m.Index])
		for _, r := range tp.R {
			switch {
			case r >= 0:
				got.WriteString(tp.S[r])
			case r < -4:
				got.WriteString(groups[-5-r].String())
			case r == -4:
				got.WriteString(c[2][:m.Index])
			case r == -3:
				got.WriteString(c[2][m.Index+m.Length:])
			case r == -2:
				got.WriteString(groups[len(groups)-1].String())
			case r == -1:
				got.WriteString(c[2])
			}
		}
		got.WriteString(c[2][m.Index+m.Length:])
		if got.String() != want {
			t.Errorf("%q / %q: program gives %q, Replace %q", c[0], c[1], got.String(), want)
		}
	}
}

// TestRewriteHeaderOpsHelper: the Go helper Swift calls for response header rules it cannot apply itself runs
// exactly applyHeaderOps for the snapshot generation's rules.
func TestRewriteHeaderOpsHelper(t *testing.T) {
	home := t.TempDir()
	e, rs := rwEngine(t, home, []rwModule{{"edge", "edge", rwEdgeModule}})
	defer e.Stop()
	gen := e.RewriteSnapshotGen()
	idx := -1
	for i, r := range rs.Rules {
		if r.Pattern == `^https://edge\.test\.com/r/rx` {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatal("no /r/rx rule")
	}
	out := e.RewriteHeaderOpsJSON(gen, fmt.Sprintf("[%d]", idx), 200, `[["Content-Type","application/json; charset=é"]]`)
	if out != `[["Content-Type","application/xml; charset=é"]]` {
		t.Fatalf("helper: %s", out)
	}
	if e.RewriteHeaderOpsJSON(gen+100, fmt.Sprintf("[%d]", idx), 200, `[]`) != "" {
		t.Fatal("unknown generation must fail")
	}
}
