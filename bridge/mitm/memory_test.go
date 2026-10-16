package mitm

// v0.6 memory hardening: request-capture byte budget, goja runtimes released after every run, cron
// tasks never overlap, panels auto-refresh only while the app shows them.

import (
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func fillRing(l *RequestLog, n, bodySize int) []*Entry {
	body := []byte(strings.Repeat("x", bodySize))
	var out []*Entry
	for i := 0; i < n; i++ {
		r := httptest.NewRequest("POST", "https://a.test/x", nil)
		e := l.Start(r, "https://a.test/x", true)
		e.ReqBody(body)
		e.RespBody(body, "")
		out = append(out, e)
	}
	return out
}

func TestCaptureRingByteBudget(t *testing.T) {
	l := NewRequestLog(200)
	entries := fillRing(l, 200, captureLimit) // 200 × 2 × 32 KB = 12.8 MB without a budget
	got := l.CapturedBytes()
	if got > DefaultCaptureBudget {
		t.Fatalf("captured %d bytes > budget %d", got, DefaultCaptureBudget)
	}
	if got < DefaultCaptureBudget/2 {
		t.Fatalf("budget evicts too much: %d", got)
	}
	last := entries[len(entries)-1]
	if last.ReqBodyS == "" || last.RespBodyS == "" || last.Dropped {
		t.Fatal("newest entry lost its bodies")
	}
	if !entries[0].Dropped || entries[0].ReqBodyS != "" {
		t.Fatal("oldest entry kept its bodies")
	}
	// the summary of an evicted entry is still listed
	if len(l.List(0)) != 200 {
		t.Fatalf("list len %d", len(l.List(0)))
	}
	// ring length cap still holds
	fillRing(l, 50, 10)
	if n := len(l.List(0)); n != 200 {
		t.Fatalf("ring len %d", n)
	}
}

func TestReplayRefusesDroppedBody(t *testing.T) {
	e := &Engine{Requests: NewRequestLog(10)}
	e.Requests.budget = 40 * 1024
	entries := fillRing(e.Requests, 3, 30*1024)
	if !entries[0].Dropped {
		t.Fatal("expected eviction")
	}
	if _, err := e.Replay(entries[0].ID, nil); err == nil || !strings.Contains(err.Error(), "内存上限") {
		t.Fatalf("replay of dropped body: %v", err)
	}
}

func BenchmarkCaptureRing(b *testing.B) {
	l := NewRequestLog(200)
	body := []byte(strings.Repeat("y", 16*1024))
	r := httptest.NewRequest("GET", "https://a.test/", nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e := l.Start(r, "https://a.test/", true)
		e.RespBody(body, "")
	}
	b.ReportMetric(float64(l.CapturedBytes())/(1<<20), "MB-held")
}

const lateCallbackJS = `
$httpClient.get("https://slow.test/", function (err, resp, body) { console.log("late " + body); });
setTimeout(function () { console.log("never"); }, 60000);
$done({});
`

func TestScriptRuntimesReleased(t *testing.T) {
	cfg := &Config{Enabled: true, Scripts: items(`t = type=generic,script-path=late.js,timeout=5`)}
	h := newHarness(t, cfg, map[string]string{"late.js": lateCallbackJS})
	base := runtime.NumGoroutine()
	tk := h.e.tasks.find("t")
	if tk == nil {
		t.Fatal("task not found")
	}
	for i := 0; i < 20; i++ {
		if _, err := h.e.tasks.run(tk, nil); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	if n := LiveRuntimes(); n != 0 {
		t.Fatalf("live runtimes after runs: %d", n)
	}
	// late $httpClient callbacks finish and exit (they see the cancelled run context)
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > base+4 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if g := runtime.NumGoroutine(); g > base+4 {
		t.Fatalf("goroutines leaked: %d → %d", base, g)
	}
}

const slowTaskJS = `setTimeout(function () { $done({}); }, 400);`

func TestCronTasksDoNotOverlap(t *testing.T) {
	cfg := &Config{Enabled: true, Scripts: items(`慢 = type=cron,cronexp="0 0 1 1 *",script-path=slow.js,timeout=5`)}
	h := newHarness(t, cfg, map[string]string{"slow.js": slowTaskJS})
	tk := h.e.tasks.find("慢")
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, busy := 0, 0
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := h.e.tasks.run(tk, nil)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				ok++
			} else if strings.Contains(err.Error(), "正在运行") {
				busy++
			} else {
				t.Errorf("unexpected: %v", err)
			}
		}()
		time.Sleep(20 * time.Millisecond)
	}
	wg.Wait()
	if ok != 1 || busy != 4 {
		t.Fatalf("ok %d busy %d (one run at a time expected)", ok, busy)
	}
}

func TestPanelsRefreshOnlyWhenViewed(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tk := newTasker(nil)
	tk.now = func() time.Time { return now }
	tk.panels = []*Panel{{ID: "p", Script: "s", Interval: 60}}
	tk.pstates = map[string]*PanelState{"p": {Panel: tk.panels[0], Updated: float64(now.Add(-2 * time.Minute).Unix())}}

	if due := tk.duePanelsLocked(now, nil); len(due) != 0 {
		t.Fatalf("never viewed but due: %v", due)
	}
	tk.markViewed()
	if due := tk.duePanelsLocked(now, nil); len(due) != 1 {
		t.Fatalf("viewed but not due: %v", due)
	}
	// app went away: 10 minutes later nothing refreshes
	now = now.Add(10 * time.Minute)
	if due := tk.duePanelsLocked(now, nil); len(due) != 0 {
		t.Fatalf("refreshing while hidden: %v", due)
	}
	// long interval panels keep their window (2 × interval)
	tk.panels[0].Interval = 600
	tk.viewed = now.Add(-15 * time.Minute)
	tk.pstates["p"].Updated = float64(now.Add(-11 * time.Minute).Unix())
	if due := tk.duePanelsLocked(now, nil); len(due) != 1 {
		t.Fatalf("2×interval window: %v", due)
	}
}
