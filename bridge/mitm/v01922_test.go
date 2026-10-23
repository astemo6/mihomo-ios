package mitm

import (
	"net/http/httptest"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

// v0.19.22 memory plateau (device log 2026-10-23): Engine.Shed frees by level and says what; the body
// budget and the GOMEMLIMIT loan leave a real margin when the extension is already near its limit.

func TestV01922ShedFreesCachesByLevel(t *testing.T) {
	e := New(t.TempDir(), nil, nil)
	r := httptest.NewRequest("GET", "https://a.test/x", nil)
	for i := 0; i < 60; i++ {
		en := e.Requests.Start(r, "https://a.test/x", true)
		en.RespBody([]byte(strings.Repeat("b", 30<<10)), "")
	}
	e.res.mem.PutW("src1", []byte("var a=1"), 7)
	e.scripts.progs.PutW("old", nil, 1<<20)
	e.scripts.progs.PutW("recent", nil, 2<<20)
	e.scripts.markUsed("recent")
	e.scripts.mu.Lock()
	e.scripts.used["old"] = time.Now().Add(-2 * dropKeepRecent)
	e.scripts.mu.Unlock()

	st := e.Shed(ShedLight)
	if st.Programs != 1 || st.ProgramBytes != 1<<20 || st.Sources != 1 {
		t.Fatalf("light shed: %+v", st)
	}
	if got := e.Requests.CapturedBytes(); got > DefaultCaptureBudget/4 || st.BodyBytes == 0 {
		t.Fatalf("light shed left %d bytes of bodies (dropped %d)", got, st.BodyBytes)
	}
	if n, _ := e.scripts.progs.stats(); n != 1 {
		t.Fatalf("light shed dropped the program used just now (%d left)", n)
	}
	e.scripts.mu.Lock()
	e.scripts.used["recent"] = time.Now().Add(-shedCriticalKeep - time.Second)
	e.scripts.mu.Unlock()
	st = e.Shed(ShedCritical)
	if st.Programs != 1 || e.Requests.CapturedBytes() != 0 {
		t.Fatalf("critical shed: %+v, bodies left %d", st, e.Requests.CapturedBytes())
	}
	if s := st.String(); !strings.Contains(s, "scripts 1 (2.0 MB)") {
		t.Fatalf("stats line %q", s)
	}
	if cs := e.Stats().String(); !strings.Contains(cs, "mitm scripts 0") || !strings.Contains(cs, "request log 60") {
		t.Fatalf("cache stats %q", cs)
	}
}

func TestV01922BodyBudgetShrinksNearLimit(t *testing.T) {
	SetAvailableMemoryProbe(func() int64 { return 10 << 20 })
	defer SetAvailableMemoryProbe(nil)
	// 10 MB available (device plateau): room above the 6 MB floor is 4 MB, the old fixed 6 MB floor is gone
	if got := bodyBudget.capNow(); got != 4<<20 {
		t.Fatalf("10 MB available: cap %d MB, want 4", got>>20)
	}
	SetAvailableMemoryProbe(func() int64 { return 6 << 20 })
	if got := bodyBudget.capNow(); got != bodyBudgetChunk {
		t.Fatalf("6 MB available: cap %d, want one chunk", got)
	}
	SetAvailableMemoryProbe(func() int64 { return 20 << 20 })
	if got := bodyBudget.capNow(); got != 7<<20 {
		t.Fatalf("20 MB available: cap %d MB, want 7", got>>20)
	}
}

func TestV01922LoanKeepsMargin(t *testing.T) {
	old := debug.SetMemoryLimit(26 << 20)
	defer debug.SetMemoryLimit(old)
	for _, c := range []struct{ avail, want int64 }{
		{10 << 20, 26 << 20},           // device plateau: nothing lent
		{12 << 20, 28 << 20},           // 2 MB above the 10 MB kept free
		{21 << 20, 37 << 20},           // fresh session: 11 MB
		{40 << 20, 26<<20 + borrowCap}, // capped
	} {
		SetAvailableMemoryProbe(func() int64 { return c.avail })
		undo := borrowSoftLimit()
		if got := debug.SetMemoryLimit(-1); got != c.want {
			t.Errorf("available %d MB: GOMEMLIMIT %d MB during the run, want %d", c.avail>>20, got>>20, c.want>>20)
		}
		if !LoanActive() && c.want != 26<<20 {
			t.Errorf("LoanActive false during a loan")
		}
		undo()
		if got := debug.SetMemoryLimit(-1); got != 26<<20 {
			t.Fatalf("not restored: %d MB", got>>20)
		}
	}
	SetAvailableMemoryProbe(nil)
}
