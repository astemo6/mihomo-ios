package mitm

// Native body lane (feat/native-mitm, stage 1; design: work/native-mitm-design.md).
//
// The memory-heavy part of a response script is the body: the compressed bytes, the decoder's window (brotli:
// up to 4 MB), the decoded bytes, the script's copy and its output. With JavaScriptCore running the script
// (jsnative.go) all of that used to pass through the Go heap anyway: Go read and decoded the body, the Swift
// engine copied it in through ScriptRun.Take, and copied the result back out through ScriptRun.Put.
//
// With a lane registered (PacketTunnel/NativeBodyStore.swift, through libmihomo.SetNativeBodyStore) a response
// body that only scripts (and header rewrites) touch never accumulates in the Go heap:
//
//   - Go streams the upstream's still-encoded bytes into the lane in small chunks (Open / Write / Finish); the
//     lane decodes them as they arrive (Compression framework), enforcing the decoded-size limit;
//   - the script's $response.body / bodyBytes blob id is NativeBlobBase + handle: the Swift engine serves
//     __tern.take for such ids from the lane without asking Go;
//   - a large result the script hands back ($done body) is stored in the lane by the Swift engine and
//     registered with the run (host op "nblob"); the handler streams it to the client from the lane;
//   - the client's response body reads from the lane in laneChunk pieces; closing it frees the handle.
//
// Everything else (rule matching, the event loop, host APIs, admission, budgets) stays in Go and is shared with
// the Go path. Any lane failure falls back to the Go path: a refused Open before anything was read (no harm), a
// failure later (the bytes already went to the lane) passes through what the lane still has, and after
// laneBreakerFails internal failures in laneBreakerWindow the lane is switched off until the next reload.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// NativeBodies is the lane as the bridge registers it. All methods are synchronous and safe from any
// goroutine. Handles are > 0. gomobile turns the methods into Objective-C selectors, so names that collide
// with NSObject's memory management (Release, Retain, Autorelease, Dealloc, Copy, New…) are avoided: Free
// becomes `free:`.
type NativeBodies interface {
	// Open starts a body. enc: Content-Encoding as received ("" / identity / gzip / x-gzip / deflate / br);
	// limit: the largest decoded size accepted; hint: the announced length (-1 unknown). Returns a handle, or
	// 0 when the lane refuses (unsupported encoding, not enough memory): nothing has been read yet then.
	Open(enc string, limit int64, hint int64) int64
	// Write feeds the next encoded bytes. "" ok, else why it stopped ("too-big", "decode: …", "gone").
	Write(h int64, b []byte) string
	// Finish ends the input: the decoded length, or LaneErrDecode / LaneErrTooBig / LaneErrInternal.
	Finish(h int64) int64
	// Err is the message of the handle's last failure ("" none).
	Err(h int64) string
	// Len is the decoded (raw=false) or received encoded (raw=true) length so far; -1 unknown handle.
	Len(h int64, raw bool) int64
	// Read copies up to n bytes from off of the decoded (raw=false) or encoded original (raw=true) bytes.
	// nil / empty at the end; nil for an unknown handle.
	Read(h int64, raw bool, off int64, n int64) []byte
	// Free forgets the handle (idempotent).
	Free(h int64)
	// Stats is a free-text line for the memory log.
	Stats() string
}

// Finish results below zero.
const (
	LaneErrDecode   = -1
	LaneErrTooBig   = -2
	LaneErrInternal = -3
)

// NativeBlobBase: script blob ids at or above this name lane handles (NativeBlobBase + handle). 2^52 keeps the
// id an exact JavaScript number (ids travel through the prelude as numbers) and far above the per-run blob
// sequence.
const NativeBlobBase int64 = 1 << 52

// IsNativeBlob reports whether a script blob id names a lane handle; LaneHandle extracts it.
func IsNativeBlob(id int64) bool { return id >= NativeBlobBase }
func LaneHandle(id int64) int64  { return id - NativeBlobBase }
func NativeBlobID(h int64) int64 { return NativeBlobBase + h }

// laneChunk: the size of each Write into / Read out of the lane. Small enough that the Go side only ever
// holds a few of these (and gomobile's per-call copy stays cheap), large enough to keep calls per MB low.
const laneChunk = 32 << 10

// laneBreakerFails internal failures within laneBreakerWindow switch the lane off until reload.
const (
	laneBreakerFails  = 3
	laneBreakerWindow = 10 * time.Minute
)

type laneBox struct{ n NativeBodies }

var (
	laneReg     atomic.Value // laneBox
	laneOff     atomic.Bool  // breaker tripped
	laneFailMu  sync.Mutex
	laneFails   []time.Time
	laneOpened  atomic.Int64 // bodies taken by the lane (stats / tests)
	laneLive    atomic.Int64 // handles the Go side still holds
	laneRefused atomic.Int64
	laneFailed  atomic.Int64
)

// SetNativeBodies registers (nil: removes) the lane. Registering resets the breaker.
func SetNativeBodies(n NativeBodies) {
	if n == nil {
		laneReg.Store(laneBox{})
		return
	}
	laneOff.Store(false)
	laneFailMu.Lock()
	laneFails = nil
	laneFailMu.Unlock()
	laneReg.Store(laneBox{n})
}

// ResetLaneBreaker turns a tripped lane back on (config reload).
func ResetLaneBreaker() {
	laneOff.Store(false)
	laneFailMu.Lock()
	laneFails = nil
	laneFailMu.Unlock()
}

func laneNow() NativeBodies {
	b, _ := laneReg.Load().(laneBox)
	if b.n == nil || laneOff.Load() {
		return nil
	}
	return b.n
}

// laneUsable: the lane only pays off (and only works: the Swift engine serves native blob ids) when the
// JavaScriptCore engine runs the scripts.
func laneUsable() NativeBodies {
	n := laneNow()
	if n == nil || !nativeUsable() {
		return nil
	}
	return n
}

// laneFailure records an internal lane failure; the breaker trips after laneBreakerFails in the window.
func laneFailure(logf Logger, what string) {
	laneFailed.Add(1)
	now := time.Now()
	laneFailMu.Lock()
	keep := laneFails[:0]
	for _, t := range laneFails {
		if now.Sub(t) < laneBreakerWindow {
			keep = append(keep, t)
		}
	}
	laneFails = append(keep, now)
	trip := len(laneFails) >= laneBreakerFails
	if trip {
		laneFails = nil
	}
	laneFailMu.Unlock()
	if trip && laneOff.CompareAndSwap(false, true) && logf != nil {
		logf("warning", "[MitM] 原生响应体通道多次出错（"+what+"），本次运行改回 Go 处理响应体")
	} else if logf != nil {
		logf("debug", "[MitM] 原生响应体通道出错："+what)
	}
}

// LaneStats is the lane's memory-log fragment ("" when no lane is registered).
func LaneStats() string {
	b, _ := laneReg.Load().(laneBox)
	if b.n == nil {
		return ""
	}
	state := "on"
	if laneOff.Load() {
		state = "off (breaker)"
	} else if !nativeUsable() {
		state = "idle (goja)"
	}
	return fmt.Sprintf("lane %s: bodies %d, live %d, refused %d, failed %d; %s", state, laneOpened.Load(), laneLive.Load(), laneRefused.Load(), laneFailed.Load(), b.n.Stats())
}

// errLaneRefused: Open said no before anything was read — the caller takes the Go path.
var errLaneRefused = errors.New("lane refused")

// laneLoadResult describes a body streamed into the lane.
type laneLoadResult struct {
	h       int64 // handle (0: none)
	decoded int64 // decoded length (valid when err == nil)
	raw     int64 // encoded bytes received
	// consumed: the upstream body was (partly) read into the lane; a failure can no longer take the Go path
	// with the original reader — pass through the lane's raw bytes, then pending, then the upstream's rest.
	consumed bool
	// pending: the chunk read from the upstream that the lane did not take (its Write failed).
	pending []byte
}

// laneLoad streams r (encoded with enc) into the lane, decoding up to limit. Errors: errLaneRefused (nothing
// read), errBodyTooBig (decoded past limit, or the encoded body itself past limit), a decode error, the
// context's error (client gone), or a lane failure. The handle is freed on every error except decode /
// too-big errors with consumed set, where the caller passes the raw bytes through (laneRawReader) and frees.
func laneLoad(ctx context.Context, n NativeBodies, logf Logger, r io.Reader, enc string, limit, hint int64) (laneLoadResult, error) {
	var res laneLoadResult
	h := n.Open(enc, limit, hint)
	if h <= 0 {
		laneRefused.Add(1)
		return res, errLaneRefused
	}
	laneOpened.Add(1)
	laneLive.Add(1)
	res.h = h
	fail := func(err error) (laneLoadResult, error) { return res, err }
	buf := make([]byte, laneChunk)
	for {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		k, rerr := r.Read(buf)
		if k > 0 {
			res.consumed = true
			res.raw += int64(k)
			if res.raw > limit && enc == "" {
				res.pending = append([]byte(nil), buf[:k]...)
				return fail(errBodyTooBig)
			}
			if msg := n.Write(h, buf[:k]); msg != "" {
				res.pending = append([]byte(nil), buf[:k]...)
				switch {
				case msg == "too-big":
					return fail(errBodyTooBig)
				case len(msg) >= 7 && msg[:7] == "decode:":
					return fail(fmt.Errorf("%s", msg))
				default:
					laneFailure(logf, "write: "+msg)
					return fail(fmt.Errorf("lane: %s", msg))
				}
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return fail(rerr)
		}
	}
	d := n.Finish(h)
	switch {
	case d >= 0:
		res.decoded = d
		return res, nil
	case d == LaneErrTooBig:
		return fail(errBodyTooBig)
	case d == LaneErrDecode:
		return fail(fmt.Errorf("decode: %s", n.Err(h)))
	default:
		laneFailure(logf, "finish: "+n.Err(h))
		return fail(fmt.Errorf("lane: %s", n.Err(h)))
	}
}

// laneFree frees a handle the Go side held (counted).
func laneFree(n NativeBodies, h int64) {
	if n == nil || h <= 0 {
		return
	}
	n.Free(h)
	laneLive.Add(-1)
}

// laneReader streams a lane handle's bytes (decoded, or the encoded original with raw) to the client. Close
// frees the handle (once). A short read from the lane before the announced length is a lane failure: the
// reader returns io.ErrUnexpectedEOF so the client sees a cut response, never a silently truncated one.
type laneReader struct {
	n    NativeBodies
	h    int64
	raw  bool
	off  int64
	size int64
	logf Logger
	once sync.Once
	// afterClose runs once the handle is freed (tests).
	afterClose func()
}

func newLaneReader(n NativeBodies, h int64, raw bool, logf Logger) *laneReader {
	return &laneReader{n: n, h: h, raw: raw, size: n.Len(h, raw), logf: logf}
}

func (l *laneReader) Read(p []byte) (int, error) {
	if l.off >= l.size {
		return 0, io.EOF
	}
	want := int64(len(p))
	if want > laneChunk {
		want = laneChunk
	}
	if rest := l.size - l.off; want > rest {
		want = rest
	}
	b := l.n.Read(l.h, l.raw, l.off, want)
	if len(b) == 0 {
		laneFailure(l.logf, "read: short")
		return 0, io.ErrUnexpectedEOF
	}
	k := copy(p, b)
	l.off += int64(k)
	return k, nil
}

func (l *laneReader) Close() error {
	l.once.Do(func() {
		laneFree(l.n, l.h)
		if l.afterClose != nil {
			l.afterClose()
		}
	})
	return nil
}

// laneBytes materialises a handle's decoded bytes in the Go heap (goja fallback, body rewrites that run after
// a lane body, $httpClient bodies). nil when the lane lost the handle.
func laneBytes(n NativeBodies, h int64) []byte {
	if n == nil {
		b, _ := laneReg.Load().(laneBox) // a tripped breaker still lets existing handles be read
		n = b.n
	}
	if n == nil {
		return nil
	}
	size := n.Len(h, false)
	if size < 0 {
		return nil
	}
	out := make([]byte, 0, size)
	for int64(len(out)) < size {
		b := n.Read(h, false, int64(len(out)), min(int64(laneChunk)*8, size-int64(len(out))))
		if len(b) == 0 {
			return nil
		}
		out = append(out, b...)
	}
	return out
}

// lanePrefix is up to n decoded bytes from the start (request log capture).
func lanePrefix(n NativeBodies, h int64, max int) []byte {
	if n == nil {
		return nil
	}
	return n.Read(h, false, 0, int64(max))
}

// laneAny returns the registered lane even when the breaker is off (to read / free handles already held).
func laneAny() NativeBodies {
	b, _ := laneReg.Load().(laneBox)
	return b.n
}
