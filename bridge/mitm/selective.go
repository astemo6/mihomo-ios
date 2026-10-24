package mitm

// Selective native MitM (feat/selective-native, Swift switch nativeMitmSelective).
//
// Measured on v0.19.23 (UnitTests/NativeMitmMemoryTests combo table): for plain MitM pass-through the Go path is
// the cheaper one per connection (Network.framework TLS server ≈ 44 KB malloc vs ≈ 24 KB Go heap), while the
// native engines save a lot per exchange when there is heavy body work (body / jq rewrite, scripts: the body never
// enters the Go heap). Selective mode hands the native front only the connections whose host can match such a rule;
// everything else is terminated in Go exactly as with the native front off.
//
// Which hosts: decided before the TLS handshake (tryNativeTLS), from the host alone —
//   1. static: every heavy rule's URL pattern is split at the scheme ("^https?:\/\/") and the host part (up to the
//      first top-level "/" or "\/") compiled as a host matcher; a host part that cannot be isolated leaves the rule
//      to (2);
//   2. learned: when a request on the Go path matches a heavy rule, its host is remembered (bounded, per rule
//      state), so the next connection to it goes native.
// A reload (new state) starts over. Any native failure still falls back to Go (first-byte fallback, breaker).

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dlclark/regexp2"
)

// Selective kinds (MitmSetNativeSelective): which rules make a host native.
const (
	SelectiveOff     = 0
	SelectiveHeavy   = 1 // body / jq / json rewrites and scripts
	SelectiveScripts = 2 // scripts only
)

var (
	selMode     atomic.Int32
	selHanded   atomic.Int64 // connections selective mode let through to the native front
	selSkipped  atomic.Int64 // connections kept on the Go path (no heavy rule for the host)
	selLearned  atomic.Int64 // hosts learned from Go-path matches
	selMu       sync.Mutex
	selIndexes  = map[*Engine]*selIndex{}
	selLearnMax = 512
)

// SetNativeSelective sets the selective mode (SelectiveOff: every eligible connection may go native, the stage 2
// behaviour).
func SetNativeSelective(mode int) {
	if mode < SelectiveOff || mode > SelectiveScripts {
		mode = SelectiveOff
	}
	selMode.Store(int32(mode))
}

// NativeSelective is the current selective mode.
func NativeSelective() int { return int(selMode.Load()) }

// SelectiveStats: connections handed / kept on Go by selective mode, hosts learned (diagnostics, bench).
func SelectiveStats() (handed, skipped, learned int64) {
	return selHanded.Load(), selSkipped.Load(), selLearned.Load()
}

type hostMatcher struct {
	re *regexp2.Regexp
}

type selIndex struct {
	st      *state
	mode    int32
	static  []hostMatcher
	unknown int // heavy rules whose host part could not be isolated (learned only)
	heavy   int
	mu      sync.Mutex
	hosts   map[string]bool // decision cache (static)
	learned map[string]struct{}
}

func selHeavyKind(mode int32, r *Rule) bool {
	switch r.Kind {
	case KindScript:
		return r.Script != nil
	case KindBody, KindJQ, KindJSON:
		return mode == SelectiveHeavy
	}
	return false
}

// selIndexFor returns the engine's index for its current state and mode, rebuilding it after a reload.
func (e *Engine) selIndexFor(mode int32) *selIndex {
	st := e.state()
	if st == nil {
		return nil
	}
	selMu.Lock()
	defer selMu.Unlock()
	if x := selIndexes[e]; x != nil && x.st == st && x.mode == mode {
		return x
	}
	x := &selIndex{st: st, mode: mode, hosts: map[string]bool{}, learned: map[string]struct{}{}}
	if st.rs != nil {
		seen := map[string]bool{}
		for _, r := range st.rs.Rules {
			if !selHeavyKind(mode, r) {
				continue
			}
			x.heavy++
			hp, anchored, ok := patternHostPart(r.Pattern)
			if !ok {
				x.unknown++
				continue
			}
			src := "^(?:" + hp + ")$"
			if !anchored {
				src = "(?:" + hp + ")$"
			}
			if seen[src] {
				continue
			}
			seen[src] = true
			re, err := regexp2.Compile(src, regexp2.IgnoreCase)
			if err != nil {
				x.unknown++
				continue
			}
			re.MatchTimeout = 50 * time.Millisecond
			x.static = append(x.static, hostMatcher{re: re})
		}
	}
	selIndexes[e] = x
	return x
}

func forgetSelective(e *Engine) {
	selMu.Lock()
	delete(selIndexes, e)
	selMu.Unlock()
}

func normHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	return h
}

// selectiveWants: whether selective mode lets host go to the native front. Off → always true.
func (e *Engine) selectiveWants(host string) bool {
	mode := selMode.Load()
	if mode == SelectiveOff {
		return true
	}
	x := e.selIndexFor(mode)
	if x == nil || x.heavy == 0 {
		selSkipped.Add(1)
		return false
	}
	h := normHost(host)
	x.mu.Lock()
	if _, ok := x.learned[h]; ok {
		x.mu.Unlock()
		selHanded.Add(1)
		return true
	}
	v, cached := x.hosts[h]
	x.mu.Unlock()
	if !cached {
		for _, m := range x.static {
			if ok, err := m.re.MatchString(h); err == nil && ok {
				v = true
				break
			}
		}
		x.mu.Lock()
		if len(x.hosts) > 4096 {
			x.hosts = map[string]bool{}
		}
		x.hosts[h] = v
		x.mu.Unlock()
	}
	if v {
		selHanded.Add(1)
	} else {
		selSkipped.Add(1)
	}
	return v
}

// selectiveLearn: a Go-path request on host matched rule; remember the host when the rule is heavy.
func (e *Engine) selectiveLearn(st *state, host string, r *Rule) {
	mode := selMode.Load()
	if mode == SelectiveOff || r == nil || !selHeavyKind(mode, r) {
		return
	}
	x := e.selIndexFor(mode)
	if x == nil || x.st != st {
		return
	}
	h := normHost(host)
	if h == "" {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.hosts[h] {
		return // static match already sends it native
	}
	if _, ok := x.learned[h]; ok {
		return
	}
	if len(x.learned) >= selLearnMax {
		for k := range x.learned { // drop an arbitrary one
			delete(x.learned, k)
			break
		}
	}
	x.learned[h] = struct{}{}
	selLearned.Add(1)
}

// selectiveLearnRules: selectiveLearn for the request's matched rules (host from the request URL).
func (e *Engine) selectiveLearnRules(st *state, host string, rules []*Rule) {
	if selMode.Load() == SelectiveOff {
		return
	}
	for _, r := range rules {
		e.selectiveLearn(st, host, r)
	}
}

// patternHostPart isolates the host part of a URL pattern: the text after "://" (written "://" or ":\/\/", the
// scheme before it only made of scheme-regex characters) up to the first top-level "/" or "\/". anchored: the
// pattern pins the host's start (it has a scheme); a pattern without a scheme that is not anchored with "^" is
// read as "<host part>/…" matched anywhere, so only the host's end is pinned. ok false: no host part found
// (e.g. "^/path", a scheme written some other way, a host part containing a slash inside a group).
func patternHostPart(p string) (hp string, anchored bool, ok bool) {
	s := strings.TrimPrefix(p, "(?i)")
	caret := strings.HasPrefix(s, "^")
	s = strings.TrimPrefix(s, "^")
	s = strings.TrimPrefix(s, "(?i)")
	rest := ""
	if i := strings.Index(s, ":\\/\\/"); i >= 0 && i <= 24 && schemeRegex(s[:i]) {
		rest, anchored = s[i+len(":\\/\\/"):], true
	} else if i := strings.Index(s, "://"); i >= 0 && i <= 24 && schemeRegex(s[:i]) {
		rest, anchored = s[i+len("://"):], true
	} else if !caret {
		rest = s // "host\.com\/path" anywhere
	} else {
		return "", false, false
	}
	depth, class := 0, false
	end := len(rest)
loop:
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		switch {
		case c == '\\' && i+1 < len(rest):
			if rest[i+1] == '/' && depth == 0 && !class {
				end = i
				break loop
			}
			i++
		case class:
			if c == ']' {
				class = false
			}
		case c == '[':
			class = true
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == '/' && depth == 0:
			end = i
			break loop
		}
	}
	hp = rest[:end]
	hp = strings.TrimSuffix(hp, "$")
	if hp == "" || strings.Contains(unescapeSlash(hp), "/") {
		return "", false, false
	}
	if !anchored && end == len(rest) {
		return "", false, false // no "/" after it: not a host part
	}
	return hp, anchored, true
}

func unescapeSlash(s string) string { return strings.ReplaceAll(s, "\\/", "/") }

// schemeRegex: s is a scheme written as a regex ("https?", "http", "(?:https?)", "http[s]?", "(https|http)", ".*").
func schemeRegex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("htpsHTPS?()[]|:.*+", c) {
			return false
		}
	}
	return true
}

// selRequestHost: the host tryNativeTLS sees for the request's connection (CONNECT host / SNI), else the Host header.
func selRequestHost(r *http.Request) string {
	if meta, _ := r.Context().Value(metaKey{}).(*connMeta); meta != nil && meta.host != "" {
		return meta.host
	}
	h := r.Host
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return h
}
