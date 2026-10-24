package mitm

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fix/xmly-memory (v0.19.22 device diagnostics 2026-10-24, 喜马拉雅 with 4–7 MB available): small, essential
// work goes ahead when the headroom covers its own size, the engine reclaims caches before refusing, and
// the critical shed no longer turns queued requests away or closes connections while there is still room.

// cookieScript is a response script in the shape of the 喜马拉雅 unlock: it fetches a small answer with
// $httpClient and only then rewrites the body.
const cookieScript = `
var o = JSON.parse($response.body);
$httpClient.get({url: "https://api.test.com/echo", headers: {"X-Want": "cookie"}, insecure: true}, function (err, resp, data) {
  if (err) { o.fetch = "failed: " + err; $done({body: JSON.stringify(o)}); return; }
  o.fetch = JSON.parse(data).headers["X-Want"];
  $done({body: JSON.stringify(o)});
});`

func headroomHarness(t *testing.T) *harness {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`ck = type=http-response,pattern=^https://api\.test\.com/json,requires-body=1,script-path=ck.js,timeout=10`)}
	return newHarness(t, cfg, map[string]string{"ck.js": cookieScript})
}

func fixedAvail(t *testing.T, f func() int64) {
	t.Helper()
	SetAvailableMemoryProbe(f)
	t.Cleanup(func() {
		SetAvailableMemoryProbe(nil)
		lastFreeOS.Store(0)
		lastHeapGC.Store(0)
		lastReclaim.Store(0)
	})
}

// holdBodyBudget takes everything the global body budget can give now (another flow's large body).
func holdBodyBudget(t *testing.T) {
	t.Helper()
	rel := bodyBudget.acquire(context.Background(), bodyBudget.capNow(), time.Second)
	if rel == nil {
		t.Fatal("could not take the body budget")
	}
	t.Cleanup(rel)
}

// The device case: 5.2 MB available (below bodyAvailFloor, so heapHigh), the global budget collapsed to one
// chunk and held by another body. The small JSON response is still handed to its script and the script's
// small $httpClient answer arrives — before: 「跳过响应体处理」 and 「获取Cookie失败:内存预算不足」.
func TestXmlyHeadroomSmallBodyAndFetch(t *testing.T) {
	h := headroomHarness(t)
	fixedAvail(t, func() int64 { return 5<<20 + 200<<10 })
	if !heapHigh() {
		t.Fatal("heapHigh should hold at 5.2 MB")
	}
	holdBodyBudget(t)
	start := time.Now()
	_, body := h.get("https://api.test.com/json")
	if !strings.Contains(body, `"fetch":"cookie"`) {
		t.Fatalf("small body / fetch refused at 5.2 MB: %s\nnotes: %s", body, entryNotes(h.e))
	}
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Errorf("took %s (waited for the held budget?)", d)
	}
}

// Below the small-work floor the body passes through unchanged, as before.
func TestXmlyHeadroomBelowFloorPassesThrough(t *testing.T) {
	h := headroomHarness(t)
	fixedAvail(t, func() int64 { return smallBodyFloor - 100<<10 })
	_, body := h.get("https://api.test.com/json")
	if strings.Contains(body, `"fetch"`) {
		t.Fatalf("script ran below the floor: %s", body)
	}
}

// A large download inside a script is still refused when memory is short.
func TestXmlyHeadroomLargeFetchRefused(t *testing.T) {
	fixedAvail(t, func() int64 { return 5 << 20 })
	if smallWorkOK(smallWorkMax+1, smallFetchFloor) {
		t.Fatal("work above smallWorkMax counted as small")
	}
	if !smallWorkOK(32<<10, smallFetchFloor) {
		t.Fatal("32 KB answer refused at 5 MB")
	}
}

// Before a gate refuses, the engine reclaims (idle programs, JS garbage, captured bodies) and reads the
// probe again: here the reclaim brings 4.3 MB up to 6.3 MB and the body is processed in full.
func TestXmlyHeadroomReclaimBeforeRefusing(t *testing.T) {
	h := headroomHarness(t)
	var reclaimed atomic.Int32
	orig := reclaimHook.Load()
	hook := func() {
		reclaimed.Add(1)
		(*orig)()
	}
	reclaimHook.Store(&hook)
	defer reclaimHook.Store(orig)
	fixedAvail(t, func() int64 {
		if reclaimed.Load() > 0 {
			return 6<<20 + 300<<10
		}
		return 4<<20 + 300<<10
	})
	_, body := h.get("https://api.test.com/json")
	if reclaimed.Load() == 0 {
		t.Fatal("no reclaim before refusing")
	}
	if !strings.Contains(body, `"fetch":"cookie"`) {
		t.Fatalf("body not processed after reclaim: %s\nnotes: %s", body, entryNotes(h.e))
	}
}

// Engine.reclaim keeps the program used just now and drops idle ones and captured bodies.
func TestXmlyReclaimKeepsRecentProgram(t *testing.T) {
	e := New(t.TempDir(), nil, nil)
	r := httptest.NewRequest("GET", "https://a.test/x", nil)
	for i := 0; i < 60; i++ {
		en := e.Requests.Start(r, "https://a.test/x", true)
		en.RespBody([]byte(strings.Repeat("b", 30<<10)), "")
	}
	e.scripts.progs.PutW("old", nil, 1<<20)
	e.scripts.progs.PutW("recent", nil, 2<<20)
	e.scripts.markUsed("recent")
	e.scripts.mu.Lock()
	e.scripts.used["old"] = time.Now().Add(-2 * shedCriticalKeep)
	e.scripts.mu.Unlock()
	e.reclaim()
	if _, ok := e.scripts.progs.Get("recent"); !ok {
		t.Fatal("reclaim dropped the program in use")
	}
	if _, ok := e.scripts.progs.Get("old"); ok {
		t.Fatal("reclaim kept an idle program")
	}
	if got := e.Requests.CapturedBytes(); got > DefaultCaptureBudget/4 {
		t.Fatalf("captured bodies left: %d", got)
	}
}

// A critical shed with 7 MB still available (iOS's "critical" event when an app opens) frees caches but
// keeps the queued script requests and the idle connections; below shedConnsAvail it turns them away.
func TestXmlyShedCriticalKeepsQueueWithRoom(t *testing.T) {
	h := headroomHarness(t)
	_, _ = h.get("https://api.test.com/json") // one client connection, idle afterwards
	time.Sleep(50 * time.Millisecond)
	old := clientIdleMin
	clientIdleMin = 0
	defer func() { clientIdleMin = old }()
	fixedAvail(t, func() int64 { return 7 << 20 })
	if st := h.e.Shed(ShedCritical); st.ClientIdleClosed || st.IdleClosed {
		t.Fatalf("connections closed with 7 MB available: %+v", st)
	}
	fixedAvail(t, func() int64 { return 4 << 20 })
	if st := h.e.Shed(ShedCritical); !st.ClientIdleClosed || !st.IdleClosed {
		t.Fatalf("idle connections kept at 4 MB: %+v", st)
	}
	// the client reconnects on its next request
	SetAvailableMemoryProbe(nil)
	time.Sleep(100 * time.Millisecond) // the client notices the close (an app's next request opens a new one)
	if _, body := h.get("https://api.test.com/json"); !strings.Contains(body, `"fetch":"cookie"`) {
		t.Fatalf("after closing idle connections: %s", body)
	}
}

// A burst (the app opening: 12 matching requests at once) at 5.2 MB available with the global budget held:
// every response is scripted and every script's small $httpClient answer arrives.
func TestXmlyHeadroomBurstFetches(t *testing.T) {
	h := headroomHarness(t)
	fixedAvail(t, func() int64 { return 5<<20 + 200<<10 })
	holdBodyBudget(t)
	const n = 12
	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := h.client.Get("https://api.test.com/json")
			if err != nil {
				return
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if strings.Contains(string(b), `"fetch":"cookie"`) {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != n {
		t.Fatalf("%d of %d scripted with their fetch; notes: %s", ok.Load(), n, entryNotes(h.e))
	}
}
