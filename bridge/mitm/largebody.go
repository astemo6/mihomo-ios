package mitm

// fix/selective-largebody — large script bodies under memory pressure (v0.19.25 device 2026-10-25 01:38, 喜马拉雅 +
// YouTube open together): 「跳过脚本：响应体解压后超过 970 KB（当前内存预算 970 KB，隧道可用 6.7 MB；
// Content-Encoding: br，已收 140 KB）」 ×2 — YouTube's protobuf answers (1–3 MB decoded, br ≈ 7–8×) were passed
// through and the ads came back. The budget was read once, at the moment the body arrived, while the 喜马拉雅
// scripts held JavaScriptCore garbage and Go pages, with a 4 MB reserve: (6.7 − 4) / 3 = 0.9 MB.
//
// Now:
//   - the dynamic budget keeps largeBodyReserve = 3 MB free (was 4): the running script is interrupted below
//     scriptAvailFloor (2.5 MB) and MemoryGuard starts closing connections at 3 MB, so 3 MB is the line nothing
//     crosses; bodyCopyFactor stays 3 (encoded + decoded + the script's copy / its output — measured, not slack:
//     NativeBodyStore now decodes into one buffer reserved up front, so the decoded copy no longer grows by
//     doubling with a transient old+new copy on top);
//   - before a body for a script with the dynamic budget is admitted, its decoded size is estimated (Content-Length
//     × the encoding's typical ratio, or what this script's bodies decoded to before when the length is unknown);
//     when the budget is short of it the engine makes room first — returns Go memory to the OS, reclaims caches and
//     JavaScriptCore garbage — and waits up to largeBodyWait for running scripts to finish (the HTTP script slot is
//     given back meanwhile, so the 喜马拉雅 scripts it would otherwise block run and end), then decides with the
//     budget it has then;
//   - a body that still decodes past the cap on the Go lane path (chunked: length unknown) gets one more chance:
//     room is made for twice the cap and the body re-decoded from the encoded bytes received so far.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// largeBodyWait bounds how long a large script body waits for memory before the budget it has is used.
var largeBodyWait = 4 * time.Second

// largeBodyStall: a wait that saw available memory stay flat this long settles for a budget covering the
// body's likely (low) size.
var largeBodyStall = time.Second

// largeBodyPoll is how often the wait re-reads the probe (and, rate limited, returns memory / reclaims).
var largeBodyPoll = 100 * time.Millisecond

// largeWaits / largeWaitsOK: waits for large-body headroom and the ones that got the room they wanted;
// largeRetries / largeRetriesOK: too-big lane loads re-decoded with a larger cap (diagnostics, tests).
var largeWaits, largeWaitsOK, largeRetries, largeRetriesOK atomic.Int64

// decodeRatio is the decoded / encoded size assumed for a body with a known Content-Length: br protobuf and JSON
// answers decode to 7–8× (YouTube: > 970 KB from 140 KB received), gzip / deflate ~5–6×.
func decodeRatio(enc string) int64 {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "", "identity":
		return 1
	case "br":
		return 8
	}
	return 6
}

// estimateDecoded is the decoded size a body is expected to have: exact for an identity body with a length,
// Content-Length × decodeRatio for an encoded one, and for an unknown length the size this script's bodies
// decoded to before (hint; 0 none). At most BodyHardMax.
func estimateDecoded(cl int64, enc string, hint int64) int64 {
	var est int64
	switch {
	case cl < 0:
		est = hint
	default:
		est = cl * decodeRatio(enc)
	}
	return min(est, BodyHardMax)
}

// bodyHints remembers, per script, how large its response bodies decode (bounded; per process).
var bodyHints = struct {
	sync.Mutex
	m map[string]int64
}{m: map[string]int64{}}

func bodyHint(sc *Script) int64 {
	if sc == nil {
		return 0
	}
	bodyHints.Lock()
	defer bodyHints.Unlock()
	return bodyHints.m[sc.Name]
}

func setBodyHint(sc *Script, v int64) {
	if sc == nil || sc.Name == "" {
		return
	}
	v = min(v, BodyHardMax)
	bodyHints.Lock()
	defer bodyHints.Unlock()
	if _, ok := bodyHints.m[sc.Name]; !ok && len(bodyHints.m) >= 256 {
		for k := range bodyHints.m {
			delete(bodyHints.m, k)
			break
		}
	}
	bodyHints.m[sc.Name] = v
}

// noteBodyDecoded records a decoded size (the hint decays towards smaller answers).
func noteBodyDecoded(sc *Script, n int64) {
	if prev := bodyHint(sc); n < prev*3/4 {
		n = prev * 3 / 4
	}
	setBodyHint(sc, n)
}

// noteBodyTooBig records a body that decoded past limit: at least twice that next time.
func noteBodyTooBig(sc *Script, limit int64) {
	setBodyHint(sc, max(bodyHint(sc), 2*limit))
}

// dynamicCapped reports whether the phase's read cap is the dynamic memory budget of a script (not MaxBody for
// a rewrite, not the script's own max-size): only then can making room raise it.
func dynamicCapped(by *Script, respCap int) bool {
	return by != nil && !(by.MaxSize > 0 && by.MaxSize == respCap)
}

// largeBodyNeed: the available memory a body of est decoded bytes needs for dynamicBodyMax to allow it.
func largeBodyNeed(est int64) int64 { return largeBodyReserve + bodyCopyFactor*est }

// roomFor reports whether the dynamic budget now allows est (and memory is not in the heapHigh zone).
func roomFor(est int64) bool {
	lim, _, known := dynamicBodyMax()
	if !known {
		return true
	}
	if int64(lim) < est {
		return false
	}
	ok, _, _ := availableAtLeast(bodyAvailFloor)
	return ok
}

// waitLargeHeadroom makes room for a body expected to decode to est bytes: Go memory back to the OS, the engine's
// caches and JavaScriptCore garbage reclaimed (both rate limited inside availableAtLeast), then waiting up to
// largeBodyWait (bounded by ctx) for running scripts to finish. The wait also ends once available memory has not
// risen for largeBodyStall and the budget already covers enough (the least the body is expected to need: est is
// a high estimate, waiting the full time for it would only delay the answer). park / unpark give the caller's
// HTTP script slot back for the wait (nil: none held). Returns whether the room was found, how long it waited,
// and unpark's error.
func waitLargeHeadroom(ctx context.Context, est, enough int64, park func(), unpark func() error) (ok bool, waited time.Duration, err error) {
	if _, known := availableMemory(); !known || est <= 0 {
		return true, 0, nil
	}
	if _, _, _ = availableAtLeast(largeBodyNeed(est)); roomFor(est) {
		return true, 0, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	largeWaits.Add(1)
	start := time.Now()
	if park != nil {
		park()
	}
	deadline := time.NewTimer(largeBodyWait)
	tick := time.NewTicker(largeBodyPoll)
	best, _ := availableMemory()
	rose := time.Now()
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-deadline.C:
			break loop
		case <-tick.C:
			availCache.Lock()
			availCache.at = time.Time{}
			availCache.Unlock()
			_, _, avail := availableAtLeast(largeBodyNeed(est))
			if roomFor(est) {
				ok = true
				break loop
			}
			if avail > best+256<<10 {
				best, rose = avail, time.Now()
			}
			if enough > 0 && time.Since(rose) >= largeBodyStall {
				// nothing more is coming back: settle for what covers the likely size (ok), or stop waiting
				// when only the tight fallback will (the caller decides)
				if roomFor(enough) {
					ok = true
					break loop
				}
				if int64(tightBodyMax()) >= enough {
					break loop
				}
			}
		}
	}
	deadline.Stop()
	tick.Stop()
	if !ok {
		ok = roomFor(est)
	}
	if ok {
		largeWaitsOK.Add(1)
	}
	if unpark != nil {
		err = unpark()
	}
	return ok, time.Since(start), err
}

// tightCopyFactor is the last resort after a full wait found no room at bodyCopyFactor: a body whose likely size
// fits (available − largeBodyReserve) / 2 still goes to its script. The running script is interrupted below
// scriptAvailFloor (2.5 MB, the body then passes through unchanged), so the tighter estimate risks a wasted run,
// not the extension.
const tightCopyFactor = 2

// tightBodyMax is dynamicBodyMax at tightCopyFactor (0 below the heapHigh floor or without a probe).
func tightBodyMax() int {
	avail, known := availableMemory()
	if !known || avail < bodyAvailFloor {
		return 0
	}
	n := (avail - largeBodyReserve) / tightCopyFactor
	return int(max(0, min(n, BodyHardMax)))
}

// estimateLow is the smallest decoded size a body is likely to have (the tight fallback must fit at least this):
// identity: its length; encoded: Content-Length × 3; unknown length: the script's hint.
func estimateLow(cl int64, enc string, hint int64) int64 {
	if cl < 0 {
		return min(hint, BodyHardMax)
	}
	if r := decodeRatio(enc); r > 1 {
		return min(cl*3, BodyHardMax)
	}
	return cl
}

// grantedLimit is a script's body limit once largeBodyRoom granted granted bytes (0: none): its own max-size
// stays the ceiling, the dynamic budget is raised to the grant.
func grantedLimit(sc *Script, granted int) int {
	l := scriptBodyLimit(sc)
	if granted > l && !(sc.MaxSize > 0 && sc.MaxSize < granted) {
		l = granted
	}
	if sc.MaxSize > 0 && l > sc.MaxSize {
		l = sc.MaxSize
	}
	return l
}

// largeBodyRoom is the admission step for a response body read for scripts: when the phase's cap is a script's
// dynamic budget and the body is expected to be larger than that budget allows now (or memory is in the heapHigh
// zone and the body is not small work), make room / wait (waitLargeHeadroom) and return the phase cap read again.
// granted > 0: the cap was decided by this step (room found, or the tight fallback); the body's budget charge may
// then go past the shared body budget up to it (bodyCharge.granted).
func (e *Engine) largeBodyRoom(ctx context.Context, rules []*Rule, respCap int, by *Script, cl int64, enc, url string, park func(), unpark func() error) (int, *Script, int, error) {
	if !dynamicCapped(by, respCap) {
		return respCap, by, 0, nil
	}
	hint := bodyHint(by)
	est := estimateDecoded(cl, enc, hint)
	if est <= smallWorkMax || (est <= int64(respCap) && !heapHigh()) {
		return respCap, by, 0, nil
	}
	return e.makeRoom(ctx, rules, respCap, by, est, estimateLow(cl, enc, hint), url, park, unpark)
}

// makeRoom waits for room for est decoded bytes (estLow: the least the body is expected to need) and returns the
// phase cap read again, with the tight fallback when the wait ran out.
func (e *Engine) makeRoom(ctx context.Context, rules []*Rule, respCap int, by *Script, est, estLow int64, url string, park func(), unpark func() error) (int, *Script, int, error) {
	ok, waited, err := waitLargeHeadroom(ctx, est, estLow, park, unpark)
	if err != nil {
		return respCap, by, 0, err
	}
	nc, nby := phaseBodyCapScript(rules, "")
	granted := 0
	mode := "已腾出"
	if ok {
		granted = nc
	} else if t := tightBodyMax(); t > nc && int64(t) >= estLow && estLow > 0 && dynamicCapped(nby, nc) {
		nc, granted, mode = t, t, "按紧凑预算处理"
		if nby.MaxSize > 0 && nc > nby.MaxSize {
			nc, granted = nby.MaxSize, nby.MaxSize
		}
	} else {
		mode = "仍不足"
	}
	if waited > 0 || granted > 0 {
		_, avail, _ := dynamicBodyMax()
		e.logf("info", fmt.Sprintf("[MitM] 大响应体（预计解压 %d KB）等待内存 %d ms，%s：预算 %d → %d KB，隧道可用 %.1f MB：%s",
			est>>10, waited.Milliseconds(), mode, respCap>>10, nc>>10, float64(avail)/(1<<20), clip(url, 100)))
	}
	return nc, nby, granted, nil
}
