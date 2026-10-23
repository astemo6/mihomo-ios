package mitm

import (
	"strings"
	"testing"
	"time"
)

// v0.19.3: unbounded recursion must end with a JS error, not grow the heap until jetsam.
func TestV0193RecursionBounded(t *testing.T) {
	home := t.TempDir()
	start := time.Now()
	out := DebugRun(home, DebugInput{Code: `function f(n){ return f(n+1) + 1 } f(0)`, Type: "generic", Timeout: 10}, nil)
	if out.OK || !strings.Contains(out.Error, "调用栈溢出") {
		t.Fatalf("want stack overflow error, got ok=%v err=%q", out.OK, out.Error)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("took %s (timeout path instead of stack limit?)", time.Since(start))
	}
	// Moderate recursion (JSON walkers etc.) still works.
	out = DebugRun(home, DebugInput{Code: `function f(n){ return n == 0 ? 0 : f(n-1) + 1 } $done({title: String(f(1500))})`, Type: "generic"}, nil)
	if !out.OK || !strings.Contains(out.DoneJSON, "1500") {
		t.Fatalf("depth 1500 should work: %+v", out)
	}
	// A recursive callback after an async boundary is caught in the event loop too.
	out = DebugRun(home, DebugInput{Code: `function f(){ f() } setTimeout(f, 1)`, Type: "generic", Timeout: 10}, nil)
	if !strings.Contains(out.Error, "调用栈溢出") {
		t.Fatalf("timer recursion: %q", out.Error)
	}
}

func TestV0193MemoryGuardInterrupts(t *testing.T) {
	old := memGuardLimit
	memGuardLimit = func() int64 { return 64 << 20 }
	defer func() { memGuardLimit = old }()
	home := t.TempDir()
	start := time.Now()
	out := DebugRun(home, DebugInput{Code: `var a = []; while (true) { a.push(new Array(100000).fill(1)) }`, Type: "generic", Timeout: 20}, nil)
	if out.OK || !strings.Contains(out.Error, "内存占用过高") {
		t.Fatalf("want memory interrupt, got ok=%v err=%q", out.OK, out.Error)
	}
	if time.Since(start) > 15*time.Second {
		t.Fatalf("guard too slow: %s", time.Since(start))
	}
}

func TestV0193StoreTotalCap(t *testing.T) {
	s := NewStore(t.TempDir())
	big := strings.Repeat("x", 900<<10)
	n := 0
	for i := 0; i < 20; i++ {
		if s.Write("k"+string(rune('a'+i)), big, false) {
			n++
		}
	}
	if n == 0 || n >= 20 {
		t.Fatalf("cap not applied: %d writes accepted", n)
	}
	// Overwriting an existing key with the same size still works at the cap.
	if !s.Write("ka", big, false) {
		t.Fatal("overwrite at cap refused")
	}
	if !s.Write("ka", "", true) || !s.Write("new", "small", false) {
		t.Fatal("delete then small write failed")
	}
}

func TestV0193QXFetchTimeoutMilliseconds(t *testing.T) {
	home := t.TempDir()
	out := DebugRun(home, DebugInput{Code: `
var t0 = Date.now();
$task.fetch({url: "http://10.255.255.1:81/", timeout: 300}).then(function(){ $done({title: "ok"}) }, function(e){ $done({title: "err", content: String(Date.now() - t0)}) })`, Type: "generic", Timeout: 10}, nil)
	if !out.OK || !strings.Contains(out.DoneJSON, "err") {
		t.Fatalf("%+v", out)
	}
}

func TestV0193ProgramCacheBudget(t *testing.T) {
	c := newLRU[int](16)
	c.maxW = 100
	c.PutW("a", 1, 40)
	c.PutW("b", 2, 40)
	c.PutW("c", 3, 40) // over budget: a goes
	if _, ok := c.Get("a"); ok || c.Weight() != 80 {
		t.Fatalf("a should be evicted, weight %d", c.Weight())
	}
	c.PutW("big", 4, 500) // larger than the budget alone: kept, everything else dropped
	if _, ok := c.Get("big"); !ok || c.Weight() != 500 {
		t.Fatalf("newest entry must stay, weight %d", c.Weight())
	}
	c.Reset()
	if c.Weight() != 0 {
		t.Fatal("reset weight")
	}
	// Runner: many large scripts do not accumulate past the budget.
	home := t.TempDir()
	e := New(home, nil, nil)
	big := strings.Repeat("var x = 1;\n", 60000) // ~660 KB
	for i := 0; i < 6; i++ {
		sc := &Script{Name: "s", Source: []byte(big + "// " + string(rune('a'+i)))}
		if _, err := e.scripts.program(sc); err != nil {
			t.Fatal(err)
		}
	}
	if w := e.scripts.progs.Weight(); w > progCacheBudget+int64(len(big)+8)*progBytesPerSourceByte {
		t.Fatalf("cache weight %d over budget", w)
	}
	dropKeepRecent = 0 // drop everything, in use or not
	defer func() { dropKeepRecent = 60 * time.Second }()
	e.DropCaches()
	if e.scripts.progs.Weight() != 0 {
		t.Fatal("DropCaches")
	}
}
