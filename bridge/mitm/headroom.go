package mitm

// fix/xmly-memory (v0.19.22 device diagnostics 2026-10-24 11:25 / 11:34, 喜马拉雅): the extension sat at
// 42.7–45.5 MB with 4–7 MB available while the app was open (74–107 connections, 300–420 goroutines, Go
// heap 16 MB live / 22 MB in spans, stacks 5 MB). Every body gate refused at < 6 MB available
// (bodyAvailFloor) whatever the size, so small, essential work was turned away:
//   - the script's own $httpClient cookie request: 「获取Cookie失败:内存预算不足，已跳过下载」 — the global body
//     budget had collapsed to 256 KB (room < bodyBudgetChunk) and the response that started the script
//     held it, so the fetch waited 2 s and then hit heapHigh;
//   - baseInfo / homePage responses (small JSON) at 5.2–5.4 MB: 「内存紧张（隧道可用 5.4 MB），跳过响应体处理」.
// Now:
//   - small work (≤ smallWorkMax: a cookie / JSON answer, a small request body) is judged on its own size
//     against a lower floor, and charged to a small separate pool (smallBudget) when the global budget
//     cannot give it bytes, so a large body never starves it;
//   - before a gate says no, the engine reclaims what it can rebuild (idle compiled scripts, JavaScriptCore
//     garbage, captured bodies, in-memory sources) and returns memory to the OS, then reads the probe again
//     (reclaimForWork, rate limited).

import (
	"context"
	"sync/atomic"
	"time"
)

// smallWorkMax: bodies and $httpClient answers up to this size count as small work.
const smallWorkMax = 256 << 10

// smallBodyFloor: a small response / request body is still processed (and its script run) with this much
// available — the running script is interrupted below scriptAvailFloor, so a little above it.
// fix/xmly-memory-2: + 256 KB (was + 512 KB over a 4 MB run floor = 4.5 MB): a small 喜马拉雅 response is
// processed at the 3.1 MB the device showed while the app was open.
const smallBodyFloor = scriptAvailFloor + 256<<10

// smallFetchFloor: a small $httpClient download of a script that is already running goes ahead while the
// run itself may continue (the run is interrupted below scriptAvailFloor anyway).
const smallFetchFloor = scriptAvailFloor

// smallBudget is the pool small work falls back to when the global body budget is held by large bodies or
// has shrunk under memory pressure (fixed size: a few small bodies at a time).
var smallBudget = newByteBudget(1 << 20)

// smallWorkCost estimates what holding n bytes of small work costs (raw + decoded / script copies).
// fix/xmly-memory-2: at least 32 KB (was 64 KB): a cookie / JSON answer of a few KB was charged 192 KB.
func smallWorkCost(n int64) int64 {
	if n < 32<<10 {
		n = 32 << 10
	}
	return 3 * n
}

// smallUnknownEstimate: what small work of unknown length (chunked / HTTP/2 without Content-Length — the
// 喜马拉雅 API answers) is judged as. fix/xmly-memory-2: it used to count as smallWorkMax (256 KB → 768 KB of
// estimated cost) at the gates and as LARGE in the $httpClient gate, so a 2–20 KB JSON answer was refused at
// ~5 MB available (「付费接口异常：内存紧张，已跳过下载」). Its read stays capped at smallWorkMax, so the
// estimate can never be exceeded by more than that cap.
const smallUnknownEstimate = 64 << 10

// smallWorkOK reports whether small work of n bytes (n < 0: unknown, judged as smallUnknownEstimate; the
// caller caps the read at smallWorkMax) may run with floor bytes kept available. Without a probe (app
// process, tests, Android) never: the GOMEMLIMIT heuristic gates stay as they were.
func smallWorkOK(n, floor int64) bool {
	if n > smallWorkMax {
		return false
	}
	if n < 0 {
		n = smallUnknownEstimate
	}
	ok, known, _ := availableAtLeast(floor + smallWorkCost(n))
	return ok && known
}

// smallHeadroomWait: how long small work waits for headroom (reclaim + returning memory to the OS, the burst
// that took it ending) before it is refused. fix/xmly-memory-2: refusing at once turned a dip of a few hundred
// ms into a failed unlock; apps wait several seconds for an answer anyway.
var smallHeadroomWait = 1500 * time.Millisecond

// smallHeadroomPoll is how often waitSmallWork re-reads the probe.
var smallHeadroomPoll = 100 * time.Millisecond

// waitSmallWork is smallWorkOK that waits up to wait (bounded by ctx) for the headroom instead of refusing at
// once. Small work beyond smallWorkMax or without a probe: false at once (the caller's large / heuristic gate
// decides).
func waitSmallWork(ctx context.Context, n, floor int64, wait time.Duration) bool {
	if n > smallWorkMax {
		return false
	}
	if smallWorkOK(n, floor) {
		return true
	}
	if _, known := availableMemory(); !known || wait <= 0 {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	tick := time.NewTicker(smallHeadroomPoll)
	defer tick.Stop()
	smallWaits.Add(1)
	for {
		select {
		case <-ctx.Done():
			return false
		case <-deadline.C:
			return smallWorkOK(n, floor)
		case <-tick.C:
			availCache.Lock()
			availCache.at = time.Time{} // re-read the probe, not the 100 ms cached value
			availCache.Unlock()
			if smallWorkOK(n, floor) {
				smallWaitsOK.Add(1)
				return true
			}
		}
	}
}

// smallWaits / smallWaitsOK count waits for headroom and the ones that got it (diagnostics, tests).
var smallWaits, smallWaitsOK atomic.Int64

// acquireSmall charges n bytes (≤ smallWorkMax) of small work: from the global budget when it has room right
// now, else from smallBudget (waiting up to wait).
func acquireSmall(ctx context.Context, n int64, wait time.Duration) func() {
	if rel := bodyBudget.acquire(ctx, n, 0); rel != nil {
		return rel
	}
	return smallBudget.acquire(ctx, n, wait)
}

// reclaimHook frees what the running engine can rebuild (Engine.reclaim); set by Engine.Start.
var reclaimHook atomic.Pointer[func()]

var lastReclaim atomic.Int64

// reclaimEvery rate-limits reclaimNow (the avail guard of a running script asks every 50 ms).
var reclaimEvery = time.Second

// reclaimNow runs the engine's reclaim at most once per reclaimEvery; reports whether it ran.
func reclaimNow() bool {
	h := reclaimHook.Load()
	if h == nil {
		return false
	}
	now := time.Now().UnixNano()
	last := lastReclaim.Load()
	if now-last < int64(reclaimEvery) || !lastReclaim.CompareAndSwap(last, now) {
		return false
	}
	(*h)()
	return true
}

// reclaim frees caches the engine rebuilds on demand, before a memory gate refuses work: compiled programs
// not used in the last shedCriticalKeep (the script about to run stays), JavaScriptCore garbage (through
// DropIdle → nativeCollect), in-memory sources, captured request-log bodies above a quarter of the budget.
// Unlike Shed it closes no connections and turns no queued request away.
func (e *Engine) reclaim() {
	if e == nil {
		return
	}
	if e.scripts != nil {
		e.scripts.DropIdle(shedCriticalKeep)
	}
	if e.res != nil {
		e.res.mem.Reset()
	}
	if e.Requests != nil {
		e.Requests.DropBodies(DefaultCaptureBudget / 4)
	}
}
