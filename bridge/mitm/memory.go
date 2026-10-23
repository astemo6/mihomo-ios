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

// scriptAvailFloor: a running script is interrupted when available memory falls below this.
const scriptAvailFloor = 4 << 20

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
	return avail >= need, true, avail
}

// borrowCap bounds how far borrowSoftLimit raises GOMEMLIMIT.
const borrowCap = 16 << 20

var loan struct {
	sync.Mutex
	n      int   // runs holding the loan
	orig   int64 // GOMEMLIMIT before the loan
	raised int64 // GOMEMLIMIT during the loan
}

// borrowSoftLimit raises the Go soft memory limit while scripts run, by what iOS still allows the
// extension (minus availReserve and a 2 MB margin, at most borrowCap), and returns the undo. Shared by
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
		extra := avail - availReserve - 2<<20
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
