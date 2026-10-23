package mitm

// fakeLane is a NativeBodies that behaves like PacketTunnel/NativeBodyStore.swift, so the Go side of the native
// body lane (nativelane.go, handler_lane.go, the "nblob" host op) can be tested without a device:
//   - Open / Write / Finish / Read / Len / Free with the same results and error strings;
//   - bytes kept OFF the Go heap (anonymous mmap), so heap measurements see only what the Go side holds —
//     like the Swift store, whose buffers are malloc'd;
//   - store(): what the Swift engine does for a large __tern.put (fakenative_test.go uses it, and serves
//     __tern.take for native blob ids from all() without going through Go).
// Difference: the Swift store decodes as bytes arrive; the fake decodes at Finish (same results, the
// too-big verdict just comes later).

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/andybalholm/brotli"
)

// fakeLanePutMin mirrors NativeBodyStore.putMin: smaller puts stay ordinary Go blobs.
const fakeLanePutMin = 64 << 10

var activeFakeLane atomic.Pointer[fakeLane]

type offHeap struct{ b []byte }

func newOffHeap(capacity int) (*offHeap, error) {
	if capacity <= 0 {
		capacity = 1
	}
	b, err := syscall.Mmap(-1, 0, capacity, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		return nil, err
	}
	return &offHeap{b: b[:0]}, nil
}

func (o *offHeap) free() {
	if o != nil && cap(o.b) > 0 {
		_ = syscall.Munmap(o.b[:cap(o.b)])
		o.b = nil
	}
}

type fakeLaneBody struct {
	enc      string
	limit    int64
	raw, dec *offHeap
	err      string
	done     bool
}

type fakeLane struct {
	mu          sync.Mutex
	seq         int64
	m           map[int64]*fakeLaneBody
	refuse      atomic.Bool
	failWrite   atomic.Bool
	opened      atomic.Int64
	freed       atomic.Int64
	engineTakes atomic.Int64
	stored      atomic.Int64
}

func newFakeLane() *fakeLane { return &fakeLane{m: map[int64]*fakeLaneBody{}} }

// useFakeLane registers a fake lane and the native stand-in engine for the test.
func useFakeLane(t interface {
	Cleanup(func())
	Fatal(...any)
}) *fakeLane {
	l := newFakeLane()
	old, _ := nativeJS.Load().(nativeBox)
	if msg := SetNativeEngine(newFakeNative()); msg != "" {
		t.Fatal(msg)
	}
	SetNativeBodies(l)
	activeFakeLane.Store(l)
	t.Cleanup(func() {
		activeFakeLane.Store(nil)
		SetNativeBodies(nil)
		ResetLaneBreaker()
		if old.n != nil {
			nativeJS.Store(old)
		} else {
			SetNativeEngine(nil)
		}
	})
	return l
}

func (l *fakeLane) live() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.m)
}

func (l *fakeLane) Open(enc string, limit, hint int64) int64 {
	if l.refuse.Load() || !laneEncodingOK(enc) {
		return 0
	}
	raw, err := newOffHeap(int(limit) + 1)
	if err != nil {
		return 0
	}
	dec, err := newOffHeap(int(limit) + 1)
	if err != nil {
		raw.free()
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	l.m[l.seq] = &fakeLaneBody{enc: strings.ToLower(strings.TrimSpace(enc)), limit: limit, raw: raw, dec: dec}
	l.opened.Add(1)
	return l.seq
}

func (l *fakeLane) get(h int64) *fakeLaneBody {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.m[h]
}

func (l *fakeLane) Write(h int64, b []byte) string {
	if l.failWrite.Load() {
		return "internal: injected"
	}
	x := l.get(h)
	if x == nil {
		return "gone"
	}
	if len(x.raw.b)+len(b) > cap(x.raw.b) {
		x.err = "too-big"
		return "too-big"
	}
	x.raw.b = append(x.raw.b, b...)
	return ""
}

func (l *fakeLane) Finish(h int64) int64 {
	x := l.get(h)
	if x == nil {
		return LaneErrInternal
	}
	var r io.Reader = bytes.NewReader(x.raw.b)
	var err error
	switch x.enc {
	case "", "identity":
	case "gzip", "x-gzip":
		r, err = gzip.NewReader(r)
	case "deflate":
		// zlib-wrapped (RFC 1950) as HTTP says; raw DEFLATE when the header is not zlib's (like the Go path)
		if len(x.raw.b) >= 2 && (uint16(x.raw.b[0])<<8|uint16(x.raw.b[1]))%31 == 0 && x.raw.b[0]&0x0f == 8 {
			r, err = zlib.NewReader(r)
		} else {
			r = flate.NewReader(r)
		}
	case "br":
		r = brotli.NewReader(r)
	default:
		x.err = "unsupported " + x.enc
		return LaneErrDecode
	}
	if err != nil {
		x.err = err.Error()
		return LaneErrDecode
	}
	for {
		if len(x.dec.b) == cap(x.dec.b) {
			x.err = "too-big"
			return LaneErrTooBig
		}
		n, rerr := r.Read(x.dec.b[len(x.dec.b):cap(x.dec.b)])
		x.dec.b = x.dec.b[:len(x.dec.b)+n]
		if int64(len(x.dec.b)) > x.limit {
			x.err = "too-big"
			return LaneErrTooBig
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			x.err = rerr.Error()
			return LaneErrDecode
		}
	}
	x.done = true
	return int64(len(x.dec.b))
}

func (l *fakeLane) Err(h int64) string {
	if x := l.get(h); x != nil {
		return x.err
	}
	return "gone"
}

func (l *fakeLane) Len(h int64, raw bool) int64 {
	x := l.get(h)
	if x == nil {
		return -1
	}
	if raw {
		return int64(len(x.raw.b))
	}
	return int64(len(x.dec.b))
}

func (l *fakeLane) Read(h int64, raw bool, off, n int64) []byte {
	x := l.get(h)
	if x == nil {
		return nil
	}
	src := x.dec.b
	if raw {
		src = x.raw.b
	}
	if off >= int64(len(src)) {
		return []byte{}
	}
	end := min(off+n, int64(len(src)))
	return append([]byte(nil), src[off:end]...) // gomobile copies too
}

func (l *fakeLane) Free(h int64) {
	l.mu.Lock()
	x := l.m[h]
	delete(l.m, h)
	l.mu.Unlock()
	if x != nil {
		x.raw.free()
		x.dec.free()
		l.freed.Add(1)
	}
}

func (l *fakeLane) Stats() string { return fmt.Sprintf("fake live %d", l.live()) }

// store is the Swift engine's large-put path: a decoded-only body.
func (l *fakeLane) store(b []byte) int64 {
	raw, _ := newOffHeap(1)
	dec, err := newOffHeap(len(b) + 1)
	if err != nil {
		return 0
	}
	dec.b = append(dec.b, b...)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	l.m[l.seq] = &fakeLaneBody{limit: int64(len(b)), raw: raw, dec: dec, done: true}
	l.stored.Add(1)
	return l.seq
}

// all is a handle's decoded bytes (the Swift engine's take for native ids).
func (l *fakeLane) all(h int64) []byte {
	x := l.get(h)
	if x == nil {
		return nil
	}
	return append([]byte(nil), x.dec.b...)
}
