package mitm

import (
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

// v0.19.21 (喜马拉雅 / YouTube on device, v0.19.20): every memory gate in the engine compared the Go heap
// against GOMEMLIMIT (26 MB by default). GOMEMLIMIT is the GC's soft target, not the extension's limit:
// iOS kills the packet tunnel at ~50 MB of phys_footprint (iOS 15+). With ~16 MB of live core heap the
// gates refused everything large —
//   - the compile gate: 16 MB live + 0.35 MB × 32 = 27–28 MB > 26 MB →「脚本过大（0.3 MB），在隧道内编译约需
//     28 MB 内存，超出 iOS 网络扩展的内存上限（26 MB），已跳过」on every 喜马拉雅 baseInfo request;
//   - the body gate (heapHigh: heap objects, garbage included, above 70 % of 26 MB = 18.2 MB) → body
//     scripts and rewrites skipped with「响应体超过上限或编码不支持，跳过脚本」(YouTube, 喜马拉雅, any
//     requires-body rule);
// while the extension still had well over 10 MB to spare. The extension now reports what iOS really
// allows (os_proc_available_memory, via the bridge's MemoryProbe) and the gates are judged on that.
// Without a probe (app process: 脚本调试, tests, Android) the GOMEMLIMIT heuristics stay as they were.

// availReserve is what a gate keeps free after its estimate: the Swift MemoryGuard starts closing
// connections below 3 MB available, jetsam kills at 0.
const availReserve = 4 << 20

// bodyAvailFloor: below this much available memory body work (rewrites, body scripts) is skipped.
const bodyAvailFloor = 6 << 20

// scriptAvailFloor: a running script is interrupted when available memory falls below this (after returning
// memory to the OS and reclaiming caches once).
// fix/xmly-memory-2 (v0.19.23 device 2026-10-24 22:14–22:16, 喜马拉雅): 4 MB refused every run and every
// small $httpClient request while the extension idled at 3–5 MB available (footprint 41 MB with only 2
// connections, peak 46.5 MB, never killed): 「跳过脚本：内存紧张（隧道可用 3.1 MB）」 ×6 and
// 「获取Cookie失败:内存紧张，已跳过下载」 at 3.1 MB, 「付费接口异常：内存紧张，已跳过下载」 at ~5 MB. iOS kills
// at 0, the Swift MemoryGuard starts closing connections at 3 MB; a run of the 喜马拉雅 script holds a few
// hundred KB of Go memory (JavaScriptCore reuses its warmed heap), so 2.5 MB keeps a margin.
const scriptAvailFloor = 5 << 19 // 2.5 MB

var availProbe atomic.Pointer[func() int64]

// SetAvailableMemoryProbe registers os_proc_available_memory of the extension (bytes, < 0 unknown);
// nil clears it.
func SetAvailableMemoryProbe(f func() int64) {
	if f == nil {
		availProbe.Store(nil)
		return
	}
	availProbe.Store(&f)
	availCache.Lock()
	availCache.at = time.Time{}
	availCache.Unlock()
}

var availCache struct {
	sync.Mutex
	at time.Time
	v  int64
}

// availableMemory is what iOS still lets the extension allocate, read at most every 100 ms (body gates
// run per request). ok=false when no probe is registered or it does not know.
func availableMemory() (int64, bool) {
	p := availProbe.Load()
	if p == nil {
		return 0, false
	}
	availCache.Lock()
	defer availCache.Unlock()
	if time.Since(availCache.at) < 100*time.Millisecond {
		return availCache.v, availCache.v >= 0
	}
	availCache.v, availCache.at = (*p)(), time.Now()
	return availCache.v, availCache.v >= 0
}

// availableMemoryNow reads the probe uncached (compile gate, after returning memory to the OS).
func availableMemoryNow() (int64, bool) {
	p := availProbe.Load()
	if p == nil {
		return 0, false
	}
	v := (*p)()
	availCache.Lock()
	availCache.v, availCache.at = v, time.Now()
	availCache.Unlock()
	return v, v >= 0
}

// freeOSMemoryEvery rate-limits debug.FreeOSMemory (a full GC + scavenge) done by the gates before they
// refuse: garbage and idle spans count in phys_footprint until returned.
var lastFreeOS atomic.Int64

func freeOSMemoryRateLimited() bool {
	now := time.Now().UnixNano()
	last := lastFreeOS.Load()
	if now-last < int64(500*time.Millisecond) || !lastFreeOS.CompareAndSwap(last, now) {
		return false
	}
	debug.FreeOSMemory()
	return true
}

// availableAtLeast reports whether at least need bytes are available (probe present), returning memory
// to the OS once before saying no. known=false: no probe, the caller uses its GOMEMLIMIT heuristic.
func availableAtLeast(need int64) (ok, known bool, avail int64) {
	avail, known = availableMemory()
	if !known {
		return false, false, 0
	}
	if avail >= need {
		return true, true, avail
	}
	if freeOSMemoryRateLimited() {
		avail, _ = availableMemoryNow()
	}
	// fix/xmly-memory: still short — free what the engine can rebuild (idle programs, JavaScriptCore
	// garbage, captured bodies) and return it to the OS before the caller refuses work.
	if avail < need && reclaimNow() {
		debug.FreeOSMemory()
		avail, _ = availableMemoryNow()
	}
	return avail >= need, true, avail
}

// borrowCap bounds how far borrowSoftLimit raises GOMEMLIMIT.
const borrowCap = 16 << 20

// loanKeepFree: v0.19.22 — the loan leaves at least this much of what iOS allows untouched, so nothing
// is lent once available memory is below it. The v0.19.21 loan left only availReserve + 2 MB (6 MB):
// on the device that sat at 40 MB footprint with ~10 MB available for hours (memory pressure critical),
// a script run could still raise GOMEMLIMIT by 4 MB and let the whole process — not only the script —
// keep that much more garbage, while non-Go memory (Swift, the packet flow, kernel buffers) and the
// Go heap overshoot the soft limit need headroom of their own. 10 MB keeps a full critical-pressure
// margin; at a normal ~20 MB available the loan is still ~10 MB (喜马拉雅 runs without GC thrash).
const loanKeepFree = 10 << 20

var loan struct {
	sync.Mutex
	n      int   // runs holding the loan
	orig   int64 // GOMEMLIMIT before the loan
	raised int64 // GOMEMLIMIT during the loan
}

// borrowSoftLimit raises the Go soft memory limit while scripts run, by what iOS still allows the
// extension (minus loanKeepFree, at most borrowCap), and returns the undo. Shared by
// concurrent runs (reference counted: the first raises, the last restores).
// v0.19.21: with ~16 MB of live core heap under the 26 MB GOMEMLIMIT every allocation-heavy script ran
// the GC back to back: the 喜马拉雅 script 4.3 s per request instead of 1.2 s (TestXimalayaTunnelMemoryGates),
// JSON feed scripts (redbook.ads on device: 866–981 ms) several times their normal time. The
// available-memory guard (startAvailGuard) still interrupts a script near the real limit. No probe or no
// limit set → no change.
func borrowSoftLimit() func() {
	loan.Lock()
	defer loan.Unlock()
	if loan.n == 0 {
		avail, known := availableMemoryNow()
		if !known {
			return func() {}
		}
		cur := debug.SetMemoryLimit(-1)
		if cur <= 0 || cur >= 1<<40 {
			return func() {}
		}
		extra := avail - loanKeepFree
		if extra <= 0 {
			return func() {}
		}
		if extra > borrowCap {
			extra = borrowCap
		}
		loan.orig, loan.raised = cur, cur+extra
		debug.SetMemoryLimit(loan.raised)
	}
	loan.n++
	var once sync.Once
	return func() {
		once.Do(func() {
			loan.Lock()
			defer loan.Unlock()
			loan.n--
			// restore unless someone (the app's 内存上限 setting) changed it meanwhile
			if loan.n == 0 && debug.SetMemoryLimit(-1) == loan.raised {
				debug.SetMemoryLimit(loan.orig)
			}
		})
	}
}

// LoanActive reports whether script runs currently hold a GOMEMLIMIT loan (the bridge's memory governor
// leaves the limit alone meanwhile).
func LoanActive() bool {
	loan.Lock()
	defer loan.Unlock()
	return loan.n > 0
}
