package mitm

// Rewrite snapshot for the native (Swift) rewrite engine — native MitM stage 3a.
//
// The Swift engine (PacketTunnel/NativeMitM/Rewrite/) answers the request decisions it can make without Go —
// URL rewrite (reject*, 302 / 307, header), Map Local with inline data, request / response header rewrites —
// for a decrypted HTTP/1.1 connection, so such requests need no Go flow (no NativeFlow, pipes, request
// goroutine, http.Request, decision JSON). Everything else (scripts, body / jq / json rewrites, Map Local
// files, QX url-and-header conditions, QX raw header regex, any pattern or replacement whose meaning could
// differ between Go and ICU, any input Swift cannot prove it reads like Go) is handed back to the Go flow.
//
// Swift never parses Surge / Loon / QX / Egern / Stash text: it evaluates this snapshot of the Ruleset Go
// compiled (same rule order, same patterns as compiled by regexp2, Map Local answers already computed by Go),
// so there is still one parser. The snapshot is rebuilt when the engine's state changes (Reload); Swift
// polls RewriteSnapshotGen (cheap) per request and fetches the JSON only when the generation moved.
//
// Portability: Go matches URL patterns with RE2 when they mean the same there (compileURLRe) and with
// regexp2 (.NET) otherwise; Swift uses NSRegularExpression (ICU). portableRegex accepts only the syntax all
// three read alike on printable-ASCII input (Swift gates its inputs to that); the rest is marked ok=false
// and Swift defers to Go whenever such a rule could match. requiredLiteral gives a literal every match
// contains: Swift skips a rule (no regex, no compile) when the URL lacks it — exact, and it also lets a
// non-portable rule be ruled out without Go.

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

// RewriteSnapshotVersion is the snapshot schema; Swift ignores a snapshot whose version it does not know.
const RewriteSnapshotVersion = 1

// snapLocalMax caps an inline Map Local body carried in the snapshot (larger ones stay with Go).
const snapLocalMax = 64 << 10

// SnapRegex is one compiled pattern.
type SnapRegex struct {
	P      string `json:"p"`              // the pattern as regexp2 compiled it
	OK     bool   `json:"ok"`             // ICU matches it like Go on printable-ASCII input
	Lit    string `json:"lit,omitempty"`  // every match contains this literal ("" none known)
	Fold   bool   `json:"fold,omitempty"` // Lit is compared ASCII case-insensitively
	Groups int    `json:"groups"`         // numbered capture groups
	Named  bool   `json:"named,omitempty"`
	Empty  bool   `json:"empty,omitempty"` // can match the empty string (Go: RE2 says so, or unknown)
}

// SnapHeaderOp is one header operation (handler.go applyHeaderOps).
type SnapHeaderOp struct {
	Op    string     `json:"op"` // add / del / replace / replace-regex (raw is never ok)
	Name  string     `json:"name,omitempty"`
	Value string     `json:"value,omitempty"`
	Re    *SnapRegex `json:"re,omitempty"`
}

// SnapLocal is a Map Local answer Go computed (handler.go mapLocalData): status and the header map
// writeLocal starts from (canonical keys, sorted), body bytes.
type SnapLocal struct {
	Status  int         `json:"status"`
	Headers [][2]string `json:"headers"`
	Body    []byte      `json:"body"`
}

// SnapScript names a script rule (always handed to Go: the JSC host runs it there).
type SnapScript struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	RequiresBody bool   `json:"requiresBody,omitempty"`
}

// SnapRule is one rule of the Ruleset, in order.
type SnapRule struct {
	I     int        `json:"i"` // index in Ruleset.Rules
	Kind  string     `json:"kind"`
	Phase string     `json:"phase"`
	Re    *SnapRegex `json:"re,omitempty"` // nil: the rule never matches (no pattern)
	// HGate: a QX url-and-header condition (needs Go when the URL matches).
	HGate    bool           `json:"hgate,omitempty"`
	Action   string         `json:"action,omitempty"`
	Target   string         `json:"target,omitempty"`
	TargetOK bool           `json:"targetOK,omitempty"` // Target is a replacement Swift expands like regexp2
	Headers  []SnapHeaderOp `json:"headers,omitempty"`
	OpsOK    bool           `json:"opsOK,omitempty"` // every header op can be applied natively
	Local    *SnapLocal     `json:"local,omitempty"` // map local: inline answer (nil: Go serves it)
	Script   *SnapScript    `json:"script,omitempty"`
	// Body rewrites (bodysnap.go, stage 3b): BodyOK when Swift can run the rule exactly like Go.
	Body    []SnapBodyOp `json:"body,omitempty"`
	JSONOps []SnapJSONOp `json:"jsonOps,omitempty"`
	JQ      []SnapJQStep `json:"jq,omitempty"`
	BodyOK  bool         `json:"bodyOK,omitempty"`
	BodyWhy string       `json:"bodyWhy,omitempty"`
}

// SnapHost is one MitM hostname pattern (HostMatcher).
type SnapHost struct {
	Pat  string `json:"pat"`
	Port int    `json:"port,omitempty"`
}

// RewriteSnapshot is what Swift evaluates.
type RewriteSnapshot struct {
	Version  int        `json:"version"`
	Gen      int64      `json:"gen"`
	On       bool       `json:"on"`      // rewrite or scripts master switch (Config.AnyOn)
	Capture  bool       `json:"capture"` // Go records bodies (a native decision does not)
	Inc      []SnapHost `json:"inc"`
	Exc      []SnapHost `json:"exc"`
	Rules    []SnapRule `json:"rules"`
	Total    int        `json:"total"`
	Portable int        `json:"portable"` // rules whose patterns (and ops) Swift can evaluate
}

type snapCache struct {
	st  *state
	gen int64
	js  []byte
	// prevSt / prevGen: the state one reload back, so a native request record (nativerecord.go) that raced a
	// reload still finds its rule labels.
	prevSt  *state
	prevGen int64
}

var (
	snapGen    atomic.Int64
	snapMu     sync.Mutex
	snapCaches = map[*Engine]*snapCache{}
)

// rewriteSnap returns the snapshot of the engine's current state, rebuilding it after a reload.
func (e *Engine) rewriteSnap() *snapCache {
	st := e.state()
	snapMu.Lock()
	defer snapMu.Unlock()
	c := snapCaches[e]
	if c != nil && c.st == st {
		return c
	}
	gen := snapGen.Add(1)
	s := buildRewriteSnapshot(st)
	s.Gen = gen
	js, _ := json.Marshal(s)
	nc := &snapCache{st: st, gen: gen, js: js}
	if c != nil {
		nc.prevSt, nc.prevGen = c.st, c.gen
	}
	snapCaches[e] = nc
	c = nc
	return c
}

// RewriteSnapshotGen is the generation of the current snapshot (changes on every reload). 0: not running.
func (e *Engine) RewriteSnapshotGen() int64 {
	if e == nil || e.state() == nil {
		return 0
	}
	return e.rewriteSnap().gen
}

// RewriteSnapshotJSON is the current snapshot (JSON RewriteSnapshot).
func (e *Engine) RewriteSnapshotJSON() string {
	if e == nil || e.state() == nil {
		return ""
	}
	return string(e.rewriteSnap().js)
}

// forgetSnapshot drops an engine's cached snapshot (Stop).
func forgetSnapshot(e *Engine) {
	snapMu.Lock()
	delete(snapCaches, e)
	snapMu.Unlock()
	forgetNativeRecords(e)
}

// snapState is the state behind snapshot generation gen (nil: unknown — older than one reload back).
func (e *Engine) snapState(gen int64) *state {
	snapMu.Lock()
	defer snapMu.Unlock()
	c := snapCaches[e]
	switch {
	case c == nil || gen == 0:
		return nil
	case c.gen == gen:
		return c.st
	case c.prevGen == gen:
		return c.prevSt
	}
	return nil
}

func buildRewriteSnapshot(st *state) *RewriteSnapshot {
	s := &RewriteSnapshot{Version: RewriteSnapshotVersion, Inc: []SnapHost{}, Exc: []SnapHost{}, Rules: []SnapRule{}}
	if st == nil {
		return s
	}
	if st.cfg != nil {
		s.On = st.cfg.AnyOn()
		s.Capture = st.cfg.capture()
	}
	if st.hosts != nil {
		for _, p := range st.hosts.inc {
			s.Inc = append(s.Inc, SnapHost{Pat: p.pat, Port: p.port})
		}
		for _, p := range st.hosts.exc {
			s.Exc = append(s.Exc, SnapHost{Pat: p.pat, Port: p.port})
		}
	}
	if st.rs == nil {
		return s
	}
	for i, r := range st.rs.Rules {
		sr := snapRule(i, r)
		s.Total++
		if snapRulePortable(sr) {
			s.Portable++
		}
		s.Rules = append(s.Rules, sr)
	}
	return s
}

func snapRulePortable(sr SnapRule) bool {
	if sr.Re != nil && !sr.Re.OK {
		return false
	}
	switch sr.Kind {
	case KindURL:
		return sr.Action != "302" && sr.Action != "307" && sr.Action != "header" || sr.TargetOK
	case KindHeader:
		return sr.OpsOK
	case KindMapLocal:
		return sr.Local != nil
	}
	return true // body / jq / json / script: Swift knows when they match (and hands those requests to Go)
}

func snapRule(i int, r *Rule) SnapRule {
	sr := SnapRule{I: i, Kind: r.Kind, Phase: r.Phase, Action: r.Action, Target: r.Target, HGate: r.hre != nil}
	if r.re != nil {
		sr.Re = snapRegex(r.re.String())
	}
	switch r.Kind {
	case KindURL:
		if sr.Re != nil && (r.Action == "302" || r.Action == "307" || r.Action == "header") {
			sr.TargetOK = sr.Re.OK && portableRepl(r.Target, sr.Re)
		}
	case KindHeader:
		sr.OpsOK = true
		for _, op := range r.Headers {
			so := SnapHeaderOp{Op: op.Op, Name: op.Name, Value: op.Value}
			switch op.Op {
			case "add", "del", "replace":
			case "replace-regex":
				if op.re == nil {
					sr.OpsOK = false
					break
				}
				so.Re = snapRegex(op.re.String())
				if !so.Re.OK || so.Re.Empty || !portableRepl(op.Value, so.Re) {
					sr.OpsOK = false
				}
			default: // raw (QX header regex: Go walks a map, order not fixed) and anything new
				sr.OpsOK = false
			}
			sr.Headers = append(sr.Headers, so)
		}
	case KindMapLocal:
		sr.Local = snapMapLocal(r)
	case KindScript:
		if r.Script != nil {
			sr.Script = &SnapScript{Name: r.Script.Name, Type: r.Script.Type, RequiresBody: r.Script.RequiresBody}
		}
	case KindBody, KindJQ, KindJSON:
		snapBody(&sr, r)
	}
	return sr
}

// snapMapLocal computes the inline Map Local answer as requestPhase would start writeLocal (nil: Go).
func snapMapLocal(r *Rule) *SnapLocal {
	var body []byte
	var ctype string
	switch r.DataType {
	case "tiny-gif":
		body, ctype = tinyGIF, "image/gif"
	case "base64":
		b, err := base64.StdEncoding.DecodeString(r.Data)
		if err != nil {
			return nil // Go logs a warning and serves what decoded: keep that with Go
		}
		body, ctype = b, "application/octet-stream"
	case "text":
		body, ctype = []byte(r.Data), guessTextType(r.Data)
	case "json":
		body, ctype = []byte(r.Data), "application/json"
	default: // file / URL: the resource cache, large-file streaming — Go
		return nil
	}
	if len(body) > snapLocalMax {
		return nil
	}
	h := http.Header{}
	seen := map[string]bool{}
	for k, v := range r.RespHeaders {
		ck := http.CanonicalHeaderKey(k)
		if seen[ck] {
			return nil // two spellings of one header: Go's map order picks the winner
		}
		seen[ck] = true
		h.Set(k, v)
	}
	if h.Get("Content-Type") == "" && ctype != "" {
		h.Set("Content-Type", ctype)
	}
	st := r.Status
	if st == 0 {
		st = 200
	}
	if st < 100 || st > 999 {
		return nil
	}
	return &SnapLocal{Status: st, Headers: flowHeaderPairs(h), Body: body}
}

func snapRegex(p string) *SnapRegex {
	ok, named, groups := portableRegex(p)
	lit, fold := requiredLiteral(p)
	sr := &SnapRegex{P: p, OK: ok, Lit: lit, Fold: fold, Groups: groups, Named: named}
	sr.Empty = true
	if re := compileURLRe(p); re != nil {
		sr.Empty = re.MatchString("")
	}
	return sr
}

// portableRegex: the pattern uses only syntax that regexp2 (.NET), RE2 (when Go picked it) and ICU read
// alike on printable-ASCII input. Conservative: anything unusual is false. groups counts capturing groups
// (named ones included).
func portableRegex(p string) (ok, named bool, groups int) {
	if p == "" {
		return false, false, 0
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] > 0x7e {
			return false, false, 0
		}
	}
	inClass := false
	classStart := 0
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '\\' {
			if i+1 >= len(p) {
				return false, named, groups
			}
			d := p[i+1]
			i++
			switch {
			case strings.IndexByte("dDwWsStnrf", d) >= 0:
			case d == 'b' || d == 'B' || d == 'A' || d == 'z' || d == 'Z' || d == 'G':
				if inClass {
					return false, named, groups // \b in a class is backspace in .NET
				}
			case d == 'x':
				if i+2 >= len(p) || !isHex(p[i+1]) || !isHex(p[i+2]) {
					return false, named, groups
				}
				i += 2
			case d == 'u':
				if i+4 >= len(p) || !isHex(p[i+1]) || !isHex(p[i+2]) || !isHex(p[i+3]) || !isHex(p[i+4]) {
					return false, named, groups
				}
				i += 4
			case d >= 'a' && d <= 'z' || d >= 'A' && d <= 'Z' || d >= '0' && d <= '9':
				return false, named, groups // backrefs, \p, \k, \c, \e, \v, \h, octal …
			default: // escaped punctuation: a literal in all three
			}
			continue
		}
		if inClass {
			switch c {
			case ']':
				if i > classStart {
					inClass = false
				} else {
					return false, named, groups // []…] / [^]…]
				}
			case '[':
				return false, named, groups // nested set (ICU) / subtraction (.NET)
			case '&', '-', '~':
				if i+1 < len(p) && p[i+1] == c {
					return false, named, groups // ICU set operators && -- ~~
				}
			}
			continue
		}
		switch c {
		case '[':
			inClass = true
			classStart = i + 1
			if i+1 < len(p) && p[i+1] == '^' {
				classStart = i + 2
			}
		case '(':
			if i+1 < len(p) && p[i+1] == '?' {
				rest := p[i+2:]
				switch {
				case strings.HasPrefix(rest, ":"), strings.HasPrefix(rest, "="), strings.HasPrefix(rest, "!"),
					strings.HasPrefix(rest, "<="), strings.HasPrefix(rest, "<!"), strings.HasPrefix(rest, ">"):
				case strings.HasPrefix(rest, "<"):
					j := 1
					for j < len(rest) && (isWord(rest[j])) {
						j++
					}
					if j == 1 || j >= len(rest) || rest[j] != '>' || rest[1] >= '0' && rest[1] <= '9' {
						return false, named, groups
					}
					named = true
					groups++
				default:
					// inline flags (?i) (?i-s:…): only i, m, s
					j := 0
					for j < len(rest) && strings.IndexByte("ims-", rest[j]) >= 0 {
						j++
					}
					if j == 0 || j >= len(rest) || rest[j] != ')' && rest[j] != ':' {
						return false, named, groups
					}
				}
			} else {
				groups++
			}
		case '{':
			// a quantifier {n} {n,} {n,m}; anything else is a literal in .NET and an error in ICU
			j := i + 1
			for j < len(p) && p[j] >= '0' && p[j] <= '9' {
				j++
			}
			if j == i+1 {
				return false, named, groups
			}
			if j < len(p) && p[j] == ',' {
				j++
				for j < len(p) && p[j] >= '0' && p[j] <= '9' {
					j++
				}
			}
			if j >= len(p) || p[j] != '}' {
				return false, named, groups
			}
			i = j
			if i+1 < len(p) && p[i+1] == '+' {
				return false, named, groups
			}
		case '}':
			return false, named, groups
		case '*', '+', '?':
			if i+1 < len(p) && p[i+1] == '+' {
				return false, named, groups // possessive (ICU only)
			}
		}
	}
	if inClass {
		return false, named, groups
	}
	return true, named, groups
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }
func isWord(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}

// requiredLiteral returns a literal every match of p contains (the longest such run of top-level literal
// characters), fold true when it must be compared case-insensitively. Conservative: "" when unsure
// (alternation at the top level, x mode).
func requiredLiteral(p string) (string, bool) {
	if strings.Contains(p, "(?#") {
		return "", false // .NET comment groups may hold unbalanced parentheses
	}
	fold := false
	// any inline flag group: i anywhere folds (conservatively for the whole pattern), x disables
	for i := 0; i+2 < len(p); i++ {
		if p[i] == '\\' {
			i++
			continue
		}
		if p[i] == '(' && p[i+1] == '?' {
			j := i + 2
			for j < len(p) && (isWord(p[j]) || p[j] == '-') {
				if p[j] == 'i' {
					fold = true
				}
				if p[j] == 'x' {
					return "", false
				}
				j++
			}
		}
	}
	best := ""
	var cur []byte
	end := func() {
		if len(cur) > len(best) {
			best = string(cur)
		}
		cur = cur[:0]
	}
	depth := 0
	inClass := false
	for i := 0; i < len(p); i++ {
		c := p[i]
		if inClass {
			if c == '\\' {
				i++
			} else if c == ']' {
				inClass = false
			}
			continue
		}
		if depth > 0 {
			switch c {
			case '\\':
				i++
			case '[':
				inClass = true
			case '(':
				depth++
			case ')':
				depth--
			}
			continue
		}
		// top level: is this atom a literal character, and how is it quantified?
		var lit byte
		isLit := false
		switch c {
		case '\\':
			if i+1 >= len(p) {
				return "", false
			}
			d := p[i+1]
			i++
			if !isWord(d) && d >= 0x20 && d <= 0x7e {
				lit, isLit = d, true
			}
		case '|':
			return "", false
		case '(':
			end()
			depth++
			continue
		case '[':
			end()
			inClass = true
			continue
		case '.', '^', '$', ')', '{', '}', ']', '*', '+', '?':
		default:
			if c >= 0x20 && c <= 0x7e {
				lit, isLit = c, true
			}
		}
		if !isLit {
			end()
			continue
		}
		// quantifier after the atom
		q := byte(0)
		if i+1 < len(p) {
			q = p[i+1]
		}
		switch {
		case q == '?' || q == '*':
			end() // optional: not required
		case q == '{':
			j := i + 2
			n := 0
			digits := false
			for j < len(p) && p[j] >= '0' && p[j] <= '9' {
				n = n*10 + int(p[j]-'0')
				digits = true
				j++
			}
			if j < len(p) && p[j] == ',' {
				j++
				for j < len(p) && p[j] >= '0' && p[j] <= '9' {
					j++
				}
			}
			if !digits || j >= len(p) || p[j] != '}' {
				return "", false // a literal "{" in .NET, an error elsewhere: give up
			}
			if n >= 1 {
				cur = append(cur, lit) // at least once
			}
			end()
			i = j // past the quantifier
		case q == '+':
			cur = append(cur, lit)
			end()
		default:
			cur = append(cur, lit)
		}
	}
	end()
	if len(best) < 3 {
		return "", false
	}
	if fold {
		best = strings.ToLower(best)
	}
	return best, fold
}

// portableRepl: the replacement only uses forms Swift expands exactly like regexp2 (non-ECMAScript):
// literals, $$, $&, $n / ${n} (greedy digits, literal when no such group), "$" + anything else literal.
// Named groups, $` $' $+ $_ and ${name} are left to Go.
func portableRepl(repl string, re *SnapRegex) bool {
	if re == nil || !re.OK {
		return false
	}
	for i := 0; i < len(repl); i++ {
		if repl[i] != '$' || i+1 >= len(repl) {
			continue
		}
		if re.Named {
			return false
		}
		switch d := repl[i+1]; {
		case d == '`' || d == '\'' || d == '+' || d == '_':
			return false
		case d == '{' && i+2 < len(repl) && isWord(repl[i+2]) && !(repl[i+2] >= '0' && repl[i+2] <= '9'):
			return false
		}
	}
	return true
}
