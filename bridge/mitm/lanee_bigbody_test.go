package mitm

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// E 线 #1: two large bodies waiting for bigBodyLock used to hold both HTTP script slots for up to
// bigBodyWait, so an unrelated small script waited (or timed out) behind them. Now the slot is parked
// for the wait: the small script runs at once, and the large ones still run once the lock frees.
func TestBigBodyWaitDoesNotHoldScriptSlot(t *testing.T) {
	old := bigBodyWait
	bigBodyWait = 2 * time.Second
	defer func() { bigBodyWait = old }()
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`big = type=http-response,pattern=^https://api\.test\.com/echo\?big,requires-body=1,max-size=-1,script-path=big.js`,
		`small = type=http-request,pattern=^https://api\.test\.com/echo\?small,script-path=small.js,timeout=1`,
	)}
	h := newHarness(t, cfg, map[string]string{
		"big.js":   `$done({body: "len=" + $response.body.length})`,
		"small.js": `$done({headers: Object.assign({}, $request.headers, {"X-Small": "1"})});`,
	})
	payload := strings.Repeat("a", 1500<<10)
	rel := acquireBigBody(context.Background())
	if rel == nil {
		t.Fatal("lock busy at start")
	}
	var wg sync.WaitGroup
	bodies := make([]string, 2)
	for i := range bodies {
		wg.Add(1)
		go func(i int) { defer wg.Done(); _, bodies[i] = h.do("POST", "https://api.test.com/echo?big", payload) }(i)
	}
	time.Sleep(400 * time.Millisecond) // both are now waiting for the lock
	start := time.Now()
	_, small := h.get("https://api.test.com/echo?small")
	took := time.Since(start)
	rel()
	wg.Wait()
	if !strings.Contains(strings.ToLower(small), "x-small") {
		t.Fatalf("small script did not run while two big bodies waited for the lock (%v): %s", took, clip(small, 200))
	}
	if took > time.Second {
		t.Fatalf("small script waited %v behind the big-body lock", took)
	}
	ran := 0
	for _, b := range bodies {
		if strings.HasPrefix(b, "len=") {
			ran++
		}
	}
	// The first waiter gets the lock once it is freed; the second waits for the first's run, which is
	// well inside bigBodyWait — both run.
	if ran != 2 {
		t.Fatalf("big scripts ran %d/2 after the lock was freed: %q / %q; notes %s", ran, clip(bodies[0], 40), clip(bodies[1], 40), entryNotes(h.e))
	}
	if len(bigBodyLock) != 0 || len(h.e.scripts.sem) != 0 {
		t.Fatalf("lock %d / slots %d still held", len(bigBodyLock), len(h.e.scripts.sem))
	}
	t.Logf("small script with two big bodies waiting: %v", took)
}

// park / unpark keep the slot accounting exact: Release after a failed unpark gives nothing back twice.
func TestSlotParkAccounting(t *testing.T) {
	e := New(t.TempDir(), nil, nil)
	h := struct{ e *Engine }{e}
	r := &Rule{Kind: KindScript, Phase: "response", Script: &Script{Name: "s", Type: "http-response", Path: "s.js", Source: []byte(`$done({})`)}}
	a, err := h.e.scripts.Reserve(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := h.e.scripts.Reserve(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	a.park()
	if len(h.e.scripts.sem) != 1 {
		t.Fatalf("parked: %d slots in use", len(h.e.scripts.sem))
	}
	c, err := h.e.scripts.Reserve(context.Background(), r) // takes a's slot while it is parked
	if err != nil {
		t.Fatal(err)
	}
	a.wait = 100 * time.Millisecond
	if err := a.unpark(context.Background()); err == nil {
		t.Fatal("unpark succeeded with both slots taken")
	}
	a.Release()
	if len(h.e.scripts.sem) != 2 {
		t.Fatalf("release of a parked slot gave one back: %d", len(h.e.scripts.sem))
	}
	c.Release()
	b.Release()
	if len(h.e.scripts.sem) != 0 {
		t.Fatalf("%d slots leaked", len(h.e.scripts.sem))
	}
	d, _ := h.e.scripts.Reserve(context.Background(), r)
	d.park()
	if err := d.unpark(context.Background()); err != nil {
		t.Fatal(err)
	}
	d.Release()
	if len(h.e.scripts.sem) != 0 {
		t.Fatalf("%d slots leaked after park/unpark", len(h.e.scripts.sem))
	}
}
