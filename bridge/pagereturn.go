package libmihomo

// feat/go-pagereturn: hand the Go heap's freed pages back to iOS shortly after a burst (app-group switch
// goPageReturn.enabled, read by PacketTunnelProvider and passed in through SetGoPageReturn).
//
// Why: after a burst of connections (喜马拉雅 opens 70–100 MitM connections at once) the Go heap holds the
// burst's garbage plus the spans it freed, and both count in phys_footprint until the runtime gives them back.
// Go does that lazily: the garbage waits for the next GC cycle (none comes while the extension is idle — the
// forced GC is every 2 minutes), and the background scavenger only returns what is above ~110 % of the heap
// goal of the *last* cycle, paced at ~1 % CPU. The only other return was startGC's 30 s ticker (when > 4 MB is
// idle). So the extension sat at its burst footprint for 30 s–2 min after every burst — the window in which
// the next burst lands on top of it.
//
// What Tailscale does (researched 2026-10-24):
//   - tailscale/go commit 38ab03e ("runtime: notify OS more aggressively about freed pages", 2020) added
//     mprotect(PROT_NONE) + mprotect(PROT_READ|PROT_WRITE) after madvise(MADV_FREE_REUSABLE) in sysUnused on
//     darwin, because iOS did not update the footprint accounting promptly. That patch is NOT in their current
//     forks (tailscale.go1.25 / go1.26 / go1.27 mem_darwin.go = upstream): upstream's MADV_FREE_REUSABLE +
//     MADV_FREE_REUSE pairing keeps task_info/phys_footprint accounting right, and our Go 1.25 already has it.
//     GODEBUG=madvdontneed=1 is a no-op on darwin (mem_darwin.go never reads it).
//   - tailscale/tailscale today calls debug.FreeOSMemory() on iOS right before a known burst (full netmap
//     rebuild, control/controlclient/map.go) and tightens the GC near 42 MB footprint (iOS app, 1.42).
//   So the part that still matters is *when* Go returns pages, not *how*: no toolchain patch, no GODEBUG.
//
// How: a 1 s sampler reads runtime/metrics (no stop-the-world) and tracks what Go keeps resident
// (total mapped − released). When that grew by at least prMinExcess since the last return and the Go side
// has been quiet (allocating less than prQuietAlloc per tick) for prQuietTicks ticks — the burst is over —
// it calls debug.FreeOSMemory() once (one GC + scavenge of everything free). A return that gave back less
// than prSmallReturn doubles the wait before the next one (up to prMaxBackoff), so steady live growth never
// turns into a GC loop. Traffic that keeps allocating is never interrupted (no quiet ticks, no GC from here).

import (
	"encoding/json"
	"fmt"
	"runtime/debug"
	"runtime/metrics"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/log"
)

const (
	prMinExcess   = 2 << 20   // resident growth since the last return before a return is worth a GC
	prQuietAlloc  = 512 << 10 // Go allocations per tick below which the tick counts as quiet
	prQuietTicks  = 2         // quiet ticks in a row = the burst is over
	prMinGap      = 3 * time.Second
	prSmallReturn = 512 << 10
	prMaxBackoff  = 2 * time.Minute
)

var (
	prMu       sync.Mutex
	prStopCh   chan struct{}
	prDoneCh   chan struct{}
	prInterval = time.Second // tests shorten it

	prReturns    atomic.Int64 // FreeOSMemory calls made by the sampler
	prFreedTotal atomic.Int64 // resident bytes they gave back (before − after)
	prLastFreed  atomic.Int64
)

var prSamples = []metrics.Sample{
	{Name: "/memory/classes/total:bytes"},
	{Name: "/memory/classes/heap/released:bytes"},
	{Name: "/gc/heap/allocs:bytes"},
}

// prRead returns what Go keeps resident (mapped − released) and its cumulative allocations.
func prRead() (resident, allocs uint64) {
	s := make([]metrics.Sample, len(prSamples))
	copy(s, prSamples)
	metrics.Read(s)
	total, rel := s[0].Value.Uint64(), s[1].Value.Uint64()
	if rel < total {
		resident = total - rel
	}
	return resident, s[2].Value.Uint64()
}

// SetGoPageReturn turns the post-burst page return on or off (idempotent). Exported for the tunnel and the
// memory bench.
func SetGoPageReturn(on bool) {
	prMu.Lock()
	defer prMu.Unlock()
	if !on {
		if prStopCh != nil {
			close(prStopCh)
			<-prDoneCh // the sampler has exited (no GC from it after this returns)
			prStopCh, prDoneCh = nil, nil
		}
		return
	}
	if prStopCh != nil {
		return
	}
	stop, done := make(chan struct{}), make(chan struct{})
	prStopCh, prDoneCh = stop, done
	go func() {
		defer close(done)
		prLoop(stop, prInterval)
	}()
}

// GoPageReturnOn reports whether the sampler runs.
func GoPageReturnOn() bool {
	prMu.Lock()
	defer prMu.Unlock()
	return prStopCh != nil
}

// GoPageReturnStats is JSON {on, returns, freedTotal, lastFreed} (bytes) for the log and the bench.
func GoPageReturnStats() string {
	b, _ := json.Marshal(map[string]any{"on": GoPageReturnOn(), "returns": prReturns.Load(),
		"freedTotal": prFreedTotal.Load(), "lastFreed": prLastFreed.Load()})
	return string(b)
}

// pageReturnSummary is the memory line's part: "page return off" / "page return on: 3 returns, 21.0 MB".
func pageReturnSummary() string {
	if !GoPageReturnOn() {
		return "page return off"
	}
	return fmt.Sprintf("page return on: %d returns, %s", prReturns.Load(), mbs(max(prFreedTotal.Load(), 0)))
}

// prState is the sampler's decision state (separate from the loop so tests can drive it tick by tick).
type prState struct {
	base       uint64 // resident right after the last return (or the lowest seen since)
	lastAllocs uint64
	quiet      int
	nextOK     time.Time
	gap        time.Duration
}

func newPRState(resident, allocs uint64, now time.Time) *prState {
	return &prState{base: resident, lastAllocs: allocs, gap: prMinGap, nextOK: now}
}

// tick feeds one sample; true = return pages now.
func (s *prState) tick(resident, allocs uint64, now time.Time) bool {
	d := allocs - s.lastAllocs
	s.lastAllocs = allocs
	if d < prQuietAlloc {
		s.quiet++
	} else {
		s.quiet = 0
	}
	if resident < s.base { // someone else (shed, scavenger, a GC) already gave pages back
		s.base = resident
	}
	return resident >= s.base+prMinExcess && s.quiet >= prQuietTicks && !now.Before(s.nextOK)
}

// returned records a return's result: the new base and the backoff.
func (s *prState) returned(before, after uint64, now time.Time) {
	s.base = after
	freed := int64(before) - int64(after)
	if freed < prSmallReturn {
		s.gap = min(s.gap*2, prMaxBackoff)
	} else {
		s.gap = prMinGap
	}
	s.nextOK = now.Add(s.gap)
	s.quiet = 0
}

var prFree = debug.FreeOSMemory // tests count calls

func prLoop(stop chan struct{}, every time.Duration) {
	res, al := prRead()
	st := newPRState(res, al, time.Now())
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		res, al := prRead()
		now := time.Now()
		if !st.tick(res, al, now) {
			continue
		}
		prFree()
		after, al2 := prRead()
		st.lastAllocs = al2
		st.returned(res, after, time.Now())
		freed := int64(res) - int64(after)
		prReturns.Add(1)
		prLastFreed.Store(freed)
		if freed > 0 {
			prFreedTotal.Add(freed)
		}
		log.Debugln("[Memory] page return after burst: go resident %s → %s (next in ≥ %s)", mbu(res), mbu(after), st.gap)
	}
}
