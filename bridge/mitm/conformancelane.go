package mitm

// Engine conformance through the native body lane (feat/native-mitm; requested by the JSC lane work, see
// work/native-lanes.md). A corpus case with "lane": true runs its response body the way modifyResponse does
// when a lane is registered: encoded with "encoding" (""/identity/gzip/deflate/br), streamed into the lane in
// laneChunk pieces (laneLoad), handed to the script as ScriptHTTP.NativeBody with the run allowed to keep
// large results in the lane (host op "nblob"), the result read back from the lane. goja runs the plain case
// as the reference; the native engine runs the lane case. Every handle must be gone afterwards.

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"fmt"
	"strings"

	"github.com/andybalholm/brotli"
)

// laneCase holds one debug run's lane handles: the response body (h) and the result the run handed over.
type laneCase struct {
	n   NativeBodies
	h   int64
	rc  *runCtx
	res int64
}

// laneEncodeBody encodes b with a Content-Encoding the lane decodes.
func laneEncodeBody(b []byte, enc string) ([]byte, error) {
	var buf bytes.Buffer
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "", "identity":
		return b, nil
	case "gzip", "x-gzip":
		w := gzip.NewWriter(&buf)
		_, _ = w.Write(b)
		if err := w.Close(); err != nil {
			return nil, err
		}
	case "deflate":
		w := zlib.NewWriter(&buf)
		_, _ = w.Write(b)
		if err := w.Close(); err != nil {
			return nil, err
		}
	case "br":
		w := brotli.NewWriterLevel(&buf, 5)
		_, _ = w.Write(b)
		if err := w.Close(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("lane: encoding %q not supported", enc)
	}
	return buf.Bytes(), nil
}

// laneCaseOpen moves resp's body into the lane (resp.Body nil, resp.NativeBody the handle).
func laneCaseOpen(resp *ScriptHTTP, enc string) (*laneCase, error) {
	n := laneAny()
	if n == nil {
		return nil, fmt.Errorf("lane not registered")
	}
	raw, err := laneEncodeBody(resp.Body, enc)
	if err != nil {
		return nil, err
	}
	res, err := laneLoad(context.Background(), n, nil, bytes.NewReader(raw), strings.ToLower(enc), MaxScriptBody, int64(len(raw)))
	if err != nil {
		if res.h > 0 {
			laneFree(n, res.h)
		}
		return nil, fmt.Errorf("lane load: %v", err)
	}
	if res.decoded != int64(len(resp.Body)) {
		laneFree(n, res.h)
		return nil, fmt.Errorf("lane load: decoded %d bytes, want %d", res.decoded, len(resp.Body))
	}
	resp.Body, resp.NativeBody = nil, res.h
	return &laneCase{n: n, h: res.h}, nil
}

// result takes over a lane result (res.NativeBody) and materialises it for the debug output.
func (lc *laneCase) result(res *ScriptResult) {
	if res == nil || res.NativeBody <= 0 {
		return
	}
	lc.res = res.NativeBody
	res.Body = laneBytes(lc.n, res.NativeBody)
	if res.Body == nil {
		res.Body = []byte{}
	}
}

// body is the response body as the lane still holds it.
func (lc *laneCase) body() []byte {
	b := laneBytes(lc.n, lc.h)
	if b == nil {
		return []byte{}
	}
	return b
}

// close frees every handle of the run: the ones the engine registered and the result did not take, the result,
// the body.
func (lc *laneCase) close() {
	if lc.rc != nil {
		lc.rc.releaseNatives(lc.res)
	}
	if lc.res > 0 && lc.res != lc.h {
		laneFree(lc.n, lc.res)
	}
	laneFree(lc.n, lc.h)
}

// LaneLiveHandles is the number of lane handles the Go side holds (0 when nothing is in flight).
func LaneLiveHandles() int64 { return laneLive.Load() }
