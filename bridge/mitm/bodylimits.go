package mitm

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// review5 P0-1 / P1-1: memory guards for everything that buffers a body in the extension.
//
//   - Decoded bodies are capped at the same limit as the raw read (MaxBody). A body that decodes past
//     it is passed through untouched (never truncated).
//   - All flows share one byte budget (bodyBudgetBytes) taken before the body is read, so a burst of
//     matching responses queues instead of all holding multi-MB bodies at once.
//   - Body work is skipped while the Go heap is already above 70 % of GOMEMLIMIT.
//   - Regex body rewrites run on Go's byte-based regexp when the pattern is RE2-compatible; the
//     backtracking engine (regexp2 converts the input to []rune, 4 B/char) only gets bodies up to
//     regexp2BodyLimit.

// errBodyTooBig is returned when a (decoded) body exceeds its cap. Callers must not use partial data.
var errBodyTooBig = errors.New("内容超过大小上限")

// readAllLimited reads r completely, failing with errBodyTooBig (instead of truncating) when it holds
// more than limit bytes.
func readAllLimited(r io.Reader, limit int) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, errBodyTooBig
	}
	return b, nil
}

// decodeBody decodes a Content-Encoding. The decoded result is capped at limit (errBodyTooBig).
func decodeBody(enc string, b []byte, limit int) ([]byte, error) {
	enc = strings.ToLower(strings.TrimSpace(enc))
	switch enc {
	case "", "identity":
		if len(b) > limit {
			return nil, errBodyTooBig
		}
		return b, nil
	case "gzip", "x-gzip":
		gr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		return readAllLimited(gr, limit)
	case "deflate":
		// RFC 9110: "deflate" is zlib-wrapped; some servers send raw deflate. Try both (P2-1).
		return inflateLimited(b, limit)
	case "br":
		return readAllLimited(brotli.NewReader(bytes.NewReader(b)), limit)
	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(b), zstd.WithDecoderLowmem(true), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(uint64(limit)+1))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		return readAllLimited(zr, limit)
	default:
		return nil, fmt.Errorf("不支持的编码 %s", enc)
	}
}

// inflateLimited accepts gzip, zlib or raw deflate; the output is capped at limit (errBodyTooBig).
func inflateLimited(b []byte, limit int) ([]byte, error) {
	if len(b) > 2 && b[0] == 0x1f && b[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		return readAllLimited(zr, limit)
	}
	if zr, err := zlib.NewReader(bytes.NewReader(b)); err == nil {
		out, err := readAllLimited(zr, limit)
		zr.Close()
		if err == nil || errors.Is(err, errBodyTooBig) {
			return out, err
		}
	}
	fr := flate.NewReader(bytes.NewReader(b))
	defer fr.Close()
	return readAllLimited(fr, limit)
}

// decodePrefix decodes the start of a compressed body that may have been cut (the capture keeps only
// the first captureLimit bytes of the stream), returning up to limit decoded bytes. A truncated stream
// is fine as long as some output came out (r7 P3-4).
func decodePrefix(enc string, b []byte, limit int) ([]byte, error) {
	var r io.Reader
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "gzip", "x-gzip":
		gr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		r = gr
	case "deflate":
		if len(b) > 2 && b[0] == 0x1f && b[1] == 0x8b {
			gr, err := gzip.NewReader(bytes.NewReader(b))
			if err != nil {
				return nil, err
			}
			r = gr
		} else if zr, err := zlib.NewReader(bytes.NewReader(b)); err == nil {
			r = zr
		} else {
			r = flate.NewReader(bytes.NewReader(b))
		}
	case "br":
		r = brotli.NewReader(bytes.NewReader(b))
	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(b), zstd.WithDecoderLowmem(true), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(uint64(limit)+1<<20))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	default:
		return nil, fmt.Errorf("不支持的编码 %s", enc)
	}
	buf := make([]byte, limit)
	n, err := io.ReadFull(r, buf)
	if n == 0 {
		if err == nil || err == io.EOF {
			return []byte{}, nil
		}
		return nil, err
	}
	return buf[:n], nil
}

// ---- global body budget ----

// bodyBudgetBytes bounds the body bytes all concurrent flows may hold for rewrites / scripts. With a
// 2 MB MaxBody that is three max-size bodies at a time; the heap cost of each is a small multiple.
const bodyBudgetBytes = 6 << 20

// bodyBudgetWait is how long a flow waits for budget before skipping its body rules.
var bodyBudgetWait = time.Second

type byteBudget struct {
	mu   sync.Mutex
	cap  int64
	used int64
	wake chan struct{} // closed and replaced on every release
}

func newByteBudget(n int64) *byteBudget {
	return &byteBudget{cap: n, wake: make(chan struct{})}
}

// acquire takes n bytes (clamped to the budget size), waiting up to wait. It returns a release func
// (safe to call more than once) or nil when the budget could not be had in time.
func (b *byteBudget) acquire(ctx context.Context, n int64, wait time.Duration) func() {
	if n <= 0 {
		n = 1
	}
	if n > b.cap {
		n = b.cap
	}
	var timer <-chan time.Time
	for {
		b.mu.Lock()
		if b.used+n <= b.cap {
			b.used += n
			b.mu.Unlock()
			var once sync.Once
			return func() { once.Do(func() { b.release(n) }) }
		}
		ch := b.wake
		b.mu.Unlock()
		if timer == nil {
			t := time.NewTimer(wait)
			defer t.Stop()
			timer = t.C
		}
		select {
		case <-ch:
		case <-timer:
			return nil
		case <-ctx.Done():
			return nil
		}
	}
}

func (b *byteBudget) release(n int64) {
	b.mu.Lock()
	b.used -= n
	close(b.wake)
	b.wake = make(chan struct{})
	b.mu.Unlock()
}

func (b *byteBudget) inUse() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

var bodyBudget = newByteBudget(bodyBudgetBytes)

// heapHigh reports whether the Go heap is above 70 % of GOMEMLIMIT (no limit set => never).
func heapHigh() bool {
	limit := memGuardLimit()
	if limit <= 0 || limit >= 1<<40 {
		return false
	}
	s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(s)
	return s[0].Value.Kind() == metrics.KindUint64 && s[0].Value.Uint64() > uint64(limit)/10*7
}

// ---- regex body rewrites ----

// regexp2BodyLimit caps bodies handed to the backtracking engine (lookaround / backreference patterns).
const regexp2BodyLimit = 512 << 10

// compileFastRe returns a Go (RE2) regexp for patterns that mean the same thing under RE2, or nil.
// Conservative: patterns using '$' (end-of-input vs. before-final-newline semantics differ) or \b / \B
// (Unicode vs ASCII word boundaries) stay on regexp2. \d \w \s are ASCII in RE2 and Unicode in .NET;
// rewrite rules match ASCII JSON / HTML in practice, so that difference is accepted.
func compileFastRe(p string) *regexp.Regexp {
	esc := false
	for _, c := range p {
		if esc {
			if c == 'b' || c == 'B' {
				return nil
			}
			esc = false
			continue
		}
		if c == '\\' {
			esc = true
			continue
		}
		if c == '$' {
			return nil
		}
	}
	re, err := regexp.Compile(p)
	if err != nil {
		return nil
	}
	return re
}

// compileURLRe is compileFastRe for URL matching only (r7 OPT-1). A URL has no newline, so '$' (end of
// input, or before a final newline in .NET) means the same as in RE2 and is allowed. Still refused:
// \b / \B (word boundaries), .NET class subtraction "-[" (RE2 would read a different class), and
// anything RE2 cannot compile (lookaround, backreferences, \Z …) — those stay on regexp2.
func compileURLRe(p string) *regexp.Regexp {
	if p == "" || strings.Contains(p, "-[") {
		return nil
	}
	esc := false
	for _, c := range p {
		if esc {
			if c == 'b' || c == 'B' {
				return nil
			}
			esc = false
			continue
		}
		if c == '\\' {
			esc = true
		}
	}
	re, err := regexp.Compile(p)
	if err != nil {
		return nil
	}
	return re
}

// replTemplate is a parsed .NET replacement pattern ($1, ${name}, $&, $0, $$). Patterns using $` $'
// $+ $_ are not supported on the Go path (ok=false keeps the rule on regexp2).
type replPart struct {
	lit   string
	group int // >= 0: group number; -1: literal
}

func parseRepl(re *regexp.Regexp, s string) ([]replPart, bool) {
	var parts []replPart
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			parts = append(parts, replPart{lit: lit.String(), group: -1})
			lit.Reset()
		}
	}
	n := re.NumSubexp()
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '$' || i+1 >= len(s) {
			lit.WriteByte(c)
			continue
		}
		d := s[i+1]
		switch {
		case d == '$':
			lit.WriteByte('$')
			i++
		case d == '&':
			flush()
			parts = append(parts, replPart{group: 0})
			i++
		case d >= '0' && d <= '9':
			// .NET (non-ECMAScript): the whole digit run names the group; no such group => literal.
			j := i + 1
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			g, err := strconv.Atoi(s[i+1 : j])
			if err != nil || g > n {
				lit.WriteString(s[i:j])
			} else {
				flush()
				parts = append(parts, replPart{group: g})
			}
			i = j - 1
		case d == '{':
			end := strings.IndexByte(s[i+2:], '}')
			if end < 0 {
				lit.WriteByte('$')
				continue
			}
			name := s[i+2 : i+2+end]
			if g, err := strconv.Atoi(name); err == nil {
				if g > n {
					lit.WriteString(s[i : i+3+end])
				} else {
					flush()
					parts = append(parts, replPart{group: g})
				}
			} else if re.SubexpIndex(name) >= 0 {
				flush()
				parts = append(parts, replPart{group: re.SubexpIndex(name)})
			} else {
				lit.WriteString(s[i : i+3+end])
			}
			i += 2 + end
		case d == '`' || d == '\'' || d == '+' || d == '_':
			return nil, false
		default:
			lit.WriteByte('$')
		}
	}
	flush()
	return parts, true
}

// goTemplate turns parsed parts into a Go Expand template.
func goTemplate(parts []replPart) []byte {
	var b strings.Builder
	for _, p := range parts {
		if p.group < 0 {
			b.WriteString(strings.ReplaceAll(p.lit, "$", "$$"))
		} else {
			b.WriteString("${" + strconv.Itoa(p.group) + "}")
		}
	}
	return []byte(b.String())
}

// fastBodyRe prepares the Go-regexp path for one body op; ok=false keeps the op on regexp2.
// Nullable patterns stay on regexp2 too: Go skips empty matches that abut a previous match, .NET
// does not.
func fastBodyRe(pattern, repl string) (*regexp.Regexp, []byte, bool) {
	re := compileFastRe(pattern)
	if re == nil || re.MatchString("") {
		return nil, nil, false
	}
	parts, ok := parseRepl(re, repl)
	if !ok {
		return nil, nil, false
	}
	return re, goTemplate(parts), true
}
