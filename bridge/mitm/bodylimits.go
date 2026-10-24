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
	"runtime"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	if strings.Contains(enc, ",") {
		parts := strings.Split(enc, ",")
		out := b
		for i := len(parts) - 1; i >= 0; i-- {
			d, err := decodeBody(parts[i], out, limit)
			if err != nil {
				return nil, err
			}
			out = d
		}
		return out, nil
	}
	switch enc {
	case "", "identity":
		if len(b) > limit {
			return nil, errBodyTooBig
		}
		return b, nil
	case "gzip", "x-gzip", "deflate", "br", "zstd":
	default:
		return nil, fmt.Errorf("不支持的编码 %s", enc)
	}
	// v0.19.22: a large compressed body is decoded twice — once only counting, then into a buffer of
	// exactly the decoded size. io.ReadAll grows by doubling, so a 3 MB body (YouTube's br protobuf,
	// 812 KB compressed) peaked at ~7 MB of heap (the 4 MB buffer plus the 2 MB one it replaced) right
	// when the script was about to copy it again. The second pass costs a few ms of CPU.
	if len(b) >= exactDecodeMin {
		d, err := newDecoder(enc, b, limit)
		if err != nil {
			return nil, err
		}
		defer d.close()
		n, err := io.Copy(io.Discard, io.LimitReader(d.r, int64(limit)+1))
		if err != nil {
			return nil, err
		}
		if n > int64(limit) {
			return nil, errBodyTooBig
		}
		// The same decoder again (brotli keeps its ring buffer, up to 4 MB, across Reset).
		if err := d.reset(); err != nil {
			return nil, err
		}
		out := make([]byte, n)
		if _, err := io.ReadFull(d.r, out); err != nil {
			return nil, err
		}
		return out, nil
	}
	d, err := newDecoder(enc, b, limit)
	if err != nil {
		return nil, err
	}
	defer d.close()
	return readAllLimited(d.r, limit)
}

// exactDecodeMin: compressed bodies from this size are decoded into an exactly sized buffer (decodeBody).
const exactDecodeMin = 64 << 10

// decoder is one Content-Encoding decoder over a body; reset starts it over on the same bytes.
type decoder struct {
	r     io.Reader
	reset func() error
	close func()
}

// newDecoder opens a decoder for one Content-Encoding over b. deflate: gzip / zlib / raw deflate, the
// way servers really send it.
func newDecoder(enc string, b []byte, limit int) (*decoder, error) {
	nop := func() {}
	switch enc {
	case "gzip", "x-gzip":
		gr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		return &decoder{r: gr, reset: func() error { return gr.Reset(bytes.NewReader(b)) }, close: func() { _ = gr.Close() }}, nil
	case "deflate":
		open := func() (io.ReadCloser, error) {
			if len(b) > 2 && b[0] == 0x1f && b[1] == 0x8b {
				return gzip.NewReader(bytes.NewReader(b))
			}
			if zr, err := zlib.NewReader(bytes.NewReader(b)); err == nil {
				// A zlib header followed by something else is raw deflate after all: check the stream.
				_, err := io.Copy(io.Discard, io.LimitReader(zr, int64(limit)+1))
				zr.Close()
				if err == nil {
					return zlib.NewReader(bytes.NewReader(b))
				}
			}
			return flate.NewReader(bytes.NewReader(b)), nil
		}
		rc, err := open()
		if err != nil {
			return nil, err
		}
		d := &decoder{r: rc}
		d.close = func() { _ = rc.Close() }
		d.reset = func() error {
			_ = rc.Close()
			n, err := open()
			if err != nil {
				return err
			}
			rc, d.r = n, n
			return nil
		}
		return d, nil
	case "br":
		// strict: a truncated br stream is a decode error, never a silently shorter body (brotlistrict.go)
		br := newStrictBrotli(bytes.NewReader(b))
		return &decoder{r: br, reset: func() error { return br.Reset(bytes.NewReader(b)) }, close: nop}, nil
	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(b), zstd.WithDecoderLowmem(true), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(uint64(limit)+1))
		if err != nil {
			return nil, err
		}
		return &decoder{r: zr, reset: func() error { return zr.Reset(bytes.NewReader(b)) }, close: zr.Close}, nil
	}
	return nil, fmt.Errorf("不支持的编码 %s", enc)
}

func inflateLimited(b []byte, limit int) ([]byte, error) {
	return decodeBody("deflate", b, limit)
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

// bodyBudgetMax: in the extension the budget grows with what iOS still allows (half of the memory above
// bodyAvailFloor, see capNow), up to this.
const bodyBudgetMax = 16 << 20

// bodyBudgetChunk is charged up front for a body of unknown length (chunked / HTTP/2 without
// Content-Length); the rest is charged once its size is known (bodyCharge.ensure).
const bodyBudgetChunk = 256 << 10

// bodyBudgetWait is how long a flow waits for budget before skipping its body rules.
var bodyBudgetWait = time.Second

type byteBudget struct {
	mu      sync.Mutex
	dynamic bool // grows with available memory (capLocked)
	cap     int64
	used    int64
	wake    chan struct{} // closed and replaced on every release
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
	var timer <-chan time.Time
	for {
		b.mu.Lock()
		c := b.capLocked()
		if n > c {
			n = c
		}
		if b.used+n <= c {
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

// capLocked is the budget size now: the fixed size, or — in the extension (available-memory probe) —
// what is in use plus half of the memory above bodyAvailFloor, between the fixed size and bodyBudgetMax.
// Only the global body budget is dynamic.
func (b *byteBudget) capLocked() int64 {
	if !b.dynamic {
		return b.cap
	}
	avail, known := availableMemory()
	if !known {
		return b.cap
	}
	room := avail - bodyAvailFloor
	c := b.used + room/2
	// v0.19.22: the fixed size is the floor only while there is room for it. With ~10 MB available (the
	// device at 40 MB footprint under critical pressure) the old floor still let flows hold 6 MB of
	// bodies (several times that in heap while decoded and scripted) — enough for jetsam.
	lo := b.cap
	if room < lo {
		lo = max(room, bodyBudgetChunk)
	}
	if c < lo {
		c = lo
	}
	if c > bodyBudgetMax {
		c = bodyBudgetMax
	}
	return c
}

// force charges n bytes without waiting, past the budget's size if need be (a granted large body). Release
// as acquire's.
func (b *byteBudget) force(n int64) func() {
	b.mu.Lock()
	b.used += n
	b.mu.Unlock()
	var once sync.Once
	return func() { once.Do(func() { b.release(n) }) }
}

func (b *byteBudget) capNow() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.capLocked()
}

func (b *byteBudget) inUse() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used
}

var bodyBudget = func() *byteBudget { b := newByteBudget(bodyBudgetBytes); b.dynamic = true; return b }()

// bodyCharge is one flow's share of the body budget, grown with ensure and given back by release.
type bodyCharge struct {
	ctx  context.Context
	mu   sync.Mutex
	held int64
	rels []func()
	big  func() // bigBodyLock held for this body (v0.19.22); released with the charge
	// small: the body is small work (fix/xmly-memory): totals up to smallWorkMax fall back to smallBudget.
	small bool
	// granted: fix/selective-largebody — bytes largeBodyRoom checked available memory for (after making room);
	// a total up to it is charged even when the shared budget (sized from the same memory reading, with a 6 MB
	// floor) cannot give it in time, so the gate that just made room does not turn the body away again.
	granted int64
}

// grant raises granted (the lane path's second chance).
func (c *bodyCharge) grant(n int64) {
	c.mu.Lock()
	c.granted = max(c.granted, n)
	c.mu.Unlock()
}

// ensure grows the charge to total bytes (waiting up to bodyBudgetWait for the difference).
func (c *bodyCharge) ensure(total int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	need := total - c.held
	if need <= 0 {
		return nil
	}
	var rel func()
	if c.small && total <= smallWorkMax {
		rel = acquireSmall(c.ctx, need, bodyBudgetWait)
	} else {
		wait := bodyBudgetWait
		if total <= c.granted {
			wait = 0 // forced below if the budget has no room right now
		}
		rel = bodyBudget.acquire(c.ctx, need, wait)
	}
	if rel == nil && total <= c.granted {
		rel = bodyBudget.force(need)
	}
	if rel == nil {
		return errors.New("body budget")
	}
	c.held += need
	c.rels = append(c.rels, rel)
	return nil
}

func (c *bodyCharge) release() {
	c.mu.Lock()
	rels := c.rels
	c.rels, c.held = nil, 0
	if c.big != nil {
		rels = append(rels, c.big)
		c.big = nil
	}
	c.mu.Unlock()
	for _, r := range rels {
		r()
	}
}

// heapHigh reports whether the Go heap is above 70 % of GOMEMLIMIT (no limit set => never).
// v0.19.21: in the extension it is judged on what iOS still allows (less than bodyAvailFloor available,
// memory.go); the heap test counted garbage and, against the 26 MB soft limit, skipped every body
// script and rewrite (「响应体超过上限或编码不支持」) with ~16 MB of live core heap. Without a probe the heap
// test stays, but garbage no longer counts: above the threshold it collects (at most every 500 ms) and
// judges the live heap.
func heapHigh() bool {
	if ok, known, _ := availableAtLeast(bodyAvailFloor); known {
		return !ok
	}
	limit := memGuardLimit()
	if limit <= 0 || limit >= 1<<40 {
		return false
	}
	s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(s)
	if s[0].Value.Kind() != metrics.KindUint64 {
		return false
	}
	th := uint64(limit) / 10 * 7
	if s[0].Value.Uint64() <= th {
		return false
	}
	if gcForHeapCheck() {
		metrics.Read(s)
	}
	return s[0].Value.Uint64() > th
}

var lastHeapGC atomic.Int64

// gcForHeapCheck runs a GC unless one ran for this purpose within the last 500 ms.
func gcForHeapCheck() bool {
	now := time.Now().UnixNano()
	last := lastHeapGC.Load()
	if now-last < int64(500*time.Millisecond) || !lastHeapGC.CompareAndSwap(last, now) {
		return false
	}
	runtime.GC()
	return true
}

// heapHighReason is the 「内存紧张」 text for logs: available memory when known.
func heapHighReason() string {
	if a, known := availableMemory(); known {
		return fmt.Sprintf("内存紧张（隧道可用 %.1f MB）", float64(a)/(1<<20))
	}
	return "内存紧张"
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
