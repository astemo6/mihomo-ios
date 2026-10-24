package libmihomo

import (
	"runtime"
	"runtime/debug"
	"sync/atomic"
	"testing"
	"time"
)

// The decision: a return only after resident growth ≥ prMinExcess AND prQuietTicks quiet ticks, then backoff.
func TestPageReturnDecision(t *testing.T) {
	t0 := time.Unix(1000, 0)
	st := newPRState(10<<20, 0, t0)
	al := uint64(0)
	step := func(i int, res uint64, alloc uint64) bool {
		al += alloc
		return st.tick(res, al, t0.Add(time.Duration(i)*time.Second))
	}
	// burst: growth while allocating → never during the burst
	for i := 1; i <= 3; i++ {
		if step(i, uint64(10+3*i)<<20, 4<<20) {
			t.Fatalf("tick %d: returned during the burst", i)
		}
	}
	// first quiet tick: not yet
	if step(4, 19<<20, 0) {
		t.Fatal("returned after one quiet tick")
	}
	// second quiet tick: return
	if !step(5, 19<<20, 0) {
		t.Fatal("no return after the burst ended")
	}
	st.returned(19<<20, 11<<20, t0.Add(5*time.Second))
	if st.base != 11<<20 || st.gap != prMinGap {
		t.Fatalf("after a big return: base %d gap %s", st.base, st.gap)
	}
	// small growth (< prMinExcess) never triggers
	for i := 6; i <= 12; i++ {
		if step(i, 12<<20, 0) {
			t.Fatalf("tick %d: returned on 1 MB growth", i)
		}
	}
	// live growth that a return cannot give back → backoff doubles, quiet ticks restart
	if !step(13, 14<<20, 0) {
		t.Fatal("no return on 3 MB growth while quiet")
	}
	st.returned(14<<20, 14<<20-100<<10, t0.Add(13*time.Second))
	if st.gap != 2*prMinGap {
		t.Fatalf("small return: gap %s, want %s", st.gap, 2*prMinGap)
	}
	for i := 14; i <= 18; i++ { // within the 6 s backoff
		if step(i, 17<<20, 0) {
			t.Fatalf("tick %d: returned inside the backoff", i)
		}
	}
	if !step(19, 17<<20, 0) {
		t.Fatal("no return after the backoff")
	}
	// someone else returned pages: the base follows down, no return for that
	st.returned(17<<20, 16<<20, t0.Add(19*time.Second))
	st.gap, st.nextOK = prMinGap, t0
	if step(30, 8<<20, 0) || step(31, 8<<20, 0) || st.base != 8<<20 {
		t.Fatalf("base did not follow an outside return (base %d)", st.base)
	}
	for g := prMinGap; g < prMaxBackoff; g *= 2 {
		st.returned(10<<20, 10<<20, t0)
	}
	st.returned(10<<20, 10<<20, t0)
	if st.gap != prMaxBackoff {
		t.Fatalf("backoff not capped: %s", st.gap)
	}
}

var prSink [][]byte

// End to end: a burst of garbage, then quiet → the sampler returns it within a few ticks; off → never.
func TestPageReturnLoop(t *testing.T) {
	old := prInterval
	prInterval = 50 * time.Millisecond
	var calls atomic.Int64
	oldFree := prFree
	prFree = func() { debug.FreeOSMemory(); calls.Add(1) }
	defer func() { SetGoPageReturn(false); prInterval, prFree = old, oldFree }()
	debug.FreeOSMemory()

	burst := func() {
		for i := 0; i < 160; i++ { // 20 MB in 128 KB pieces, dropped right after
			prSink = append(prSink, make([]byte, 128<<10))
		}
		prSink = nil
	}

	// off: nothing returns
	SetGoPageReturn(false)
	burst()
	time.Sleep(400 * time.Millisecond)
	if calls.Load() != 0 {
		t.Fatalf("off: %d returns", calls.Load())
	}
	debug.FreeOSMemory()

	SetGoPageReturn(true)
	SetGoPageReturn(true) // idempotent: one sampler
	if !GoPageReturnOn() {
		t.Fatal("not on")
	}
	time.Sleep(120 * time.Millisecond)
	before, _ := prRead()
	burst()
	deadline := time.Now().Add(3 * time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if calls.Load() == 0 {
		res, _ := prRead()
		t.Fatalf("no return after a 20 MB burst (resident %s → %s)", mbu(before), mbu(res))
	}
	after, _ := prRead()
	// other goroutines of the package (earlier tests' engines) may hold memory too: report, don't fail
	t.Logf("resident before the burst %s, after the return %s", mbu(before), mbu(after))
	n := calls.Load()
	// idle afterwards: no GC loop
	time.Sleep(600 * time.Millisecond)
	if d := calls.Load() - n; d > 1 { // the backoff (TestPageReturnDecision) bounds this; 1 = background noise
		t.Fatalf("%d more returns while idle", d)
	}
	SetGoPageReturn(false)
	if GoPageReturnOn() {
		t.Fatal("still on")
	}
	runtime.GC()
	t.Logf("stats %s", GoPageReturnStats())
}
