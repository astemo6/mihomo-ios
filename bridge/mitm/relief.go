package mitm

// fix/xmly-memory-2 (device 2026-10-24 22:17, idle after the 喜马拉雅 attempts: footprint 41.1 MB with 2
// connections, Go heap 13.6 MB live / 42.5 MB sys, 8.9 MB available): what a burst of HTTP-script runs freed
// stayed resident — Go returns freed pages lazily (next GC cycle + background scavenger), so the next burst
// started 5–10 MB higher than it had to. Minimal page return: when the last running HTTP script ends while
// memory is tight, return Go's free memory to iOS once, shortly after (rate limited; skipped while another
// run is active or a new one starts). feat/go-pagereturn (bridge/pagereturn.go, a 1 s sampler for every
// kind of burst) is the general version; both only call the rate-limited debug.FreeOSMemory.

import (
	"sync/atomic"
	"time"
)

// reliefAvail: below this much available memory the end of a burst returns memory to the OS.
const reliefAvail = 12 << 20

// reliefDelay: how long after the last run the return happens (a run that starts meanwhile cancels it).
var reliefDelay = 750 * time.Millisecond

var (
	runsActive    atomic.Int64 // HTTP-script runs in progress
	reliefPending atomic.Bool
	reliefsDone   atomic.Int64 // returns made (diagnostics, tests)
)

// scheduleRunRelief is called when an HTTP-script run ends.
func scheduleRunRelief() {
	if runsActive.Load() > 0 {
		return
	}
	if a, known := availableMemory(); !known || a >= reliefAvail {
		return
	}
	if !reliefPending.CompareAndSwap(false, true) {
		return
	}
	time.AfterFunc(reliefDelay, func() {
		reliefPending.Store(false)
		if runsActive.Load() > 0 {
			return // a new burst: its last run schedules again
		}
		if freeOSMemoryRateLimited() {
			reliefsDone.Add(1)
		}
	})
}
