package libmihomo

import (
	"encoding/json"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// feat/s3-mem: the native (Swift) governor's Go side.

func withNativeGov(t *testing.T, cfg int64) {
	t.Helper()
	old := debug.SetMemoryLimit(-1)
	oldNG := goNonGarbage
	t.Cleanup(func() {
		nativeGovOn.Store(false)
		goNonGarbage = oldNG
		debug.SetMemoryLimit(old)
		setConfiguredLimit(old)
	})
	debug.SetMemoryLimit(cfg)
	setConfiguredLimit(cfg)
	nativeGovOn.Store(true)
}

func TestS3NativeClamp(t *testing.T) {
	const cfg = 26 << 20
	cases := []struct {
		name            string
		want, ng, limit int64
	}{
		{"restore", 0, 10 << 20, cfg},
		{"never above configured", 40 << 20, 10 << 20, cfg},
		{"lowered", 20 << 20, 10 << 20, 20 << 20},
		{"hard floor 16 MB", 8 << 20, 4 << 20, memGovernFloor},
		{"anti-thrash floor above the ask", 18 << 20, 22 << 20, 24 << 20},
		// device 2026-10-24: ~34 MB non-garbage under a 26 MB limit → raised to 36 MB (≤ cfg + 16)
		{"anti-thrash raises above configured", 20 << 20, 34 << 20, 36 << 20},
		{"raise capped at configured + 16 MB", 20 << 20, 60 << 20, cfg + nativeGovMaxRaise},
	}
	for _, c := range cases {
		if got := nativeClamp(c.want, cfg, c.ng); got != c.limit {
			t.Errorf("%s: got %d MB, want %d MB", c.name, got>>20, c.limit>>20)
		}
	}
}

func TestS3NativeGovernLimit(t *testing.T) {
	withNativeGov(t, 26<<20)
	goNonGarbage = func() int64 { return 12 << 20 }
	if v := NativeGovernLimit(20 << 20); v != 20<<20 || debug.SetMemoryLimit(-1) != 20<<20 {
		t.Fatalf("lower: %d MB", v>>20)
	}
	// under 512 KB: no change (no flapping)
	if v := NativeGovernLimit(20<<20 + 256<<10); v != 20<<20 {
		t.Fatalf("small step applied: %d", v)
	}
	// floor rises with Go's non-garbage memory
	goNonGarbage = func() int64 { return 30 << 20 }
	if v := NativeGovernLimit(18 << 20); v != 32<<20 {
		t.Fatalf("anti-thrash: %d MB, want 32", v>>20)
	}
	// restore asks for the configured 26 MB, which is below the 32 MB floor: the floor stays
	if v := NativeGovernLimit(0); v != 32<<20 {
		t.Fatalf("restore with high non-garbage: %d MB", v>>20)
	}
	goNonGarbage = func() int64 { return 10 << 20 }
	if v := NativeGovernLimit(0); v != 26<<20 || debug.SetMemoryLimit(-1) != 26<<20 {
		t.Fatalf("restore: %d MB", v>>20)
	}
	// off: hands off
	nativeGovOn.Store(false)
	if v := NativeGovernLimit(18 << 20); v != 26<<20 {
		t.Fatalf("changed the limit while off: %d MB", v>>20)
	}
}

// With the native governor on, memTick's Go governor stands down (one coordinator); off restores the
// configured limit and the Go governor acts again.
func TestS3MemTickStandsDown(t *testing.T) {
	withNativeGov(t, 26<<20)
	goNonGarbage = func() int64 { return 8 << 20 }
	now := time.Now()
	for i := 0; i < 5; i++ {
		memTick(45<<20, 4<<20, now.Add(time.Duration(i)*time.Second))
	}
	if cur := debug.SetMemoryLimit(-1); cur != 26<<20 {
		t.Fatalf("Go governor moved GOMEMLIMIT while native drives: %d MB", cur>>20)
	}
	NativeGovernLimit(20 << 20)
	SetNativeMemoryGovernor(false)
	if cur := debug.SetMemoryLimit(-1); cur != 26<<20 {
		t.Fatalf("off did not restore the configured limit: %d MB", cur>>20)
	}
	memTick(45<<20, 4<<20, now.Add(10*time.Second))
	if cur := debug.SetMemoryLimit(-1); cur >= 26<<20 {
		t.Fatalf("Go governor idle after native off: %d MB", cur>>20)
	}
	if NativeMemoryGovernorOn() {
		t.Fatal("still on")
	}
}

// The native shed clears DNS caches only when flagged (calm critical: no clear in a burst) and runs at
// most one FreeOSMemory per second.
func TestS3NativeShedFlags(t *testing.T) {
	withMemProbe(t, 40<<20, 7<<20)
	var cleared atomic.Int32
	testHookShedDNS = func() { cleared.Add(1) }
	defer func() { testHookShedDNS = nil }()
	nativeFreeMu.Lock()
	nativeFreeAt = time.Time{}
	nativeFreeMu.Unlock()

	line := NativeShed(2, NativeShedFreeOS, "pressure critical")
	if cleared.Load() != 0 || strings.Contains(line, "DNS caches cleared") || !strings.Contains(line, "memory shed L2 native") {
		t.Fatalf("unflagged DNS clear: %d, %q", cleared.Load(), line)
	}
	line = NativeShed(2, NativeShedFreeOS|NativeShedDNS, "timer")
	if cleared.Load() != 1 || !strings.Contains(line, "DNS caches cleared") || !strings.Contains(line, "FreeOSMemory skipped") {
		t.Fatalf("flagged: %d, %q", cleared.Load(), line)
	}
	if NativeFreeOSMemory() {
		t.Fatal("second FreeOSMemory within 1 s ran")
	}
}

func TestS3NativeGoMemoryJSON(t *testing.T) {
	withNativeGov(t, 26<<20)
	goNonGarbage = func() int64 { return 20 << 20 }
	var m struct {
		Heap, NonGarbage, Floor, Limit, Configured int64
		Goroutines                                 int
		Loan                                       bool
	}
	if err := json.Unmarshal([]byte(NativeGoMemory()), &m); err != nil {
		t.Fatal(err)
	}
	if m.NonGarbage != 20<<20 || m.Floor != 22<<20 || m.Limit != 26<<20 || m.Configured != 26<<20 || m.Heap <= 0 || m.Goroutines <= 0 {
		t.Fatalf("%+v", m)
	}
}
