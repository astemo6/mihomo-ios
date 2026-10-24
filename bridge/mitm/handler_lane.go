package mitm

// Response bodies through the native lane (feat/native-mitm stage 1, nativelane.go): modifyResponse's loadBody
// calls loadBodyLane after the same admission as the Go path (heap check, announced length vs. limits, the body
// budget's first charge, the one-large-body-at-a-time lock), so every budget rule of v0.19.22 keeps applying.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	laneRefusedOutcome = iota // nothing read: take the Go path
	laneLoaded                // the body is in the lane
	laneSkipped               // the body passes through unchanged (respSkip says why)
)

// laneForRules is the lane to use for a response whose phase rules are rules: only when every body consumer
// is a script (body / jq / json rewrites run in Go on Go bytes) and the JavaScriptCore engine runs scripts.
func laneForRules(rules []*Rule) NativeBodies {
	n := laneUsable()
	if n == nil {
		return nil
	}
	scripts := false
	for _, r := range rules {
		switch r.Kind {
		case KindBody, KindJQ, KindJSON:
			return nil
		case KindScript:
			if r.Script != nil && r.Script.RequiresBody {
				if !r.Script.laneOK() {
					return nil
				}
				scripts = true
			}
		}
	}
	if !scripts {
		return nil
	}
	return n
}

// laneOK: a script that the native engine will run (the lane's blob ids only resolve there). A script the
// runner would hand to goja for its own reasons (none today; Language / engine pinning would go here) keeps
// Go bytes.
func (sc *Script) laneOK() bool { return sc != nil }

// laneEncodingOK: encodings the lane decodes (the same set the Go path decodes; anything else passes through).
func laneEncodingOK(enc string) bool {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "", "identity", "gzip", "x-gzip", "deflate", "br":
		return true
	}
	return false
}

// loadBodyLane streams resp's body into the lane. want is what the budget was charged up front; the rest of
// the decoded size is charged once known (like the Go path). takeBig takes bigBodyLock when the decoded body
// turns out large. On laneSkipped resp.Body has been replaced by something that yields the original bytes
// (the encoded bytes the lane received, then the rest of the upstream).
func (e *Engine) loadBodyLane(f *flow, resp *http.Response, lane NativeBodies, enc string, want int64, respCap int, capScript *Script, charge *bodyCharge, takeBig func() bool, respSkip *string) (int64, int64, int) {
	if !laneEncodingOK(enc) {
		return 0, 0, laneRefusedOutcome
	}
	ctx := resp.Request.Context()
	upstream := resp.Body
	res, err := laneLoad(ctx, lane, e.logf, upstream, enc, int64(respCap), resp.ContentLength)
	if errors.Is(err, errLaneRefused) {
		return 0, 0, laneRefusedOutcome
	}
	passRaw := func() {
		// what the lane received, then whatever the upstream still has (a too-big body stopped mid-way)
		rr := newLaneReader(lane, res.h, true, e.logf)
		resp.Body = &multiCloser{Reader: io.MultiReader(rr, bytes.NewReader(res.pending), upstream), closers: []io.Closer{rr, upstream}}
	}
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil:
			laneFree(lane, res.h)
			*respSkip = "客户端已断开"
			resp.Body = io.NopCloser(strings.NewReader("")) // nobody reads it any more
			_ = upstream.Close()
		case errors.Is(err, errBodyTooBig):
			*respSkip = fmt.Sprintf("响应体解压后超过 %d KB（%s；Content-Encoding: %s，已收 %d KB）", respCap>>10, bodyLimitNote(capScript, respCap), orNone(enc), res.raw>>10)
			e.logf("warning", fmt.Sprintf("[MitM] %s，原样放行：%s", *respSkip, clip(f.url, 100)))
			passRaw()
		case strings.HasPrefix(err.Error(), "decode:"):
			*respSkip = fmt.Sprintf("响应体解码失败（Content-Encoding: %s，%d KB）：%s", enc, res.raw>>10, strings.TrimPrefix(err.Error(), "decode: "))
			passRaw()
		default:
			// lane failure (counted by laneLoad) or an upstream read error: pass through what we have
			if strings.HasPrefix(err.Error(), "lane: ") {
				*respSkip = "原生响应体通道出错：" + shortErr(err)
			} else {
				*respSkip = "读取响应体出错：" + shortErr(err)
			}
			if res.consumed {
				passRaw()
			} else {
				laneFree(lane, res.h)
			}
		}
		return 0, 0, laneSkipped
	}
	_ = upstream.Close()
	if res.decoded > bigBodyThreshold && !takeBig() {
		passRawWhole(resp, lane, res.h, e.logf)
		return 0, 0, laneSkipped
	}
	if cerr := charge.ensure(res.decoded); cerr != nil {
		*respSkip = fmt.Sprintf("同时处理的响应体过多（需 %d KB，已占用 %d KB / %d KB）", res.decoded>>10, bodyBudget.inUse()>>10, bodyBudget.capNow()>>10)
		e.logf("warning", fmt.Sprintf("[MitM] %s，跳过：%s", *respSkip, clip(f.url, 100)))
		passRawWhole(resp, lane, res.h, e.logf)
		return 0, 0, laneSkipped
	}
	_ = want
	return res.h, res.decoded, laneLoaded
}

// passRawWhole: the whole encoded body is in the lane; send it as received (Content-Encoding kept).
func passRawWhole(resp *http.Response, lane NativeBodies, h int64, logf Logger) {
	resp.Body = newLaneReader(lane, h, true, logf)
}

type multiCloser struct {
	io.Reader
	closers []io.Closer
}

func (m *multiCloser) Close() error {
	for _, c := range m.closers {
		_ = c.Close()
	}
	return nil
}
