package mitm

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// v0.19.22 喜马拉雅 (「打开喜马拉雅后有问题，自动断连」): the large-bundle queue admits a request only when its
// turn can come in time, bounds how many wait (fewer when memory is short), and Shed at the critical
// level turns the waiters away.

func TestScriptQueueAdmission(t *testing.T) {
	SetAvailableMemoryProbe(nil)
	q := newScriptQueue()
	// Nothing running: always admitted.
	leave, _, err := q.admit("a.js", false)
	if err != nil {
		t.Fatal(err)
	}
	leave()
	leave() // idempotent
	if q.Waiting() != 0 {
		t.Fatalf("waiting %d", q.Waiting())
	}
	// Measured 2 s per run, one running: waiters 1–3 wait 2, 4, 6 s (within the 6 s budget), the 4th 8 s.
	q.observe("a.js", 2*time.Second)
	var leaves []func()
	for i := 0; i < 3; i++ {
		l, _, err := q.admit("a.js", true)
		if err != nil {
			t.Fatalf("waiter %d: %v", i, err)
		}
		leaves = append(leaves, l)
	}
	if _, _, err := q.admit("a.js", true); err == nil || !isQueueSkip(err) || !strings.Contains(err.Error(), "脚本排队过长，已跳过（前面还有 4 个，预计等待 8.0 秒）") {
		t.Fatalf("4th waiter: %v", err)
	}
	// A fast script: the count limit applies.
	for _, l := range leaves {
		l()
	}
	q2 := newScriptQueue()
	q2.observe("f.js", 10*time.Millisecond)
	n := 0
	for {
		_, _, err := q2.admit("f.js", true)
		if err != nil {
			if !strings.Contains(err.Error(), "最多排 6 个") {
				t.Fatalf("count limit: %v", err)
			}
			break
		}
		n++
	}
	if n != 6 {
		t.Fatalf("admitted %d, want 6", n)
	}
}

func TestScriptQueueShrinksUnderMemoryPressure(t *testing.T) {
	q := newScriptQueue()
	q.observe("a.js", 10*time.Millisecond)
	tunnelConditions(t, 0, 10<<20) // below queueTightAvail: one waiter
	if _, _, err := q.admit("a.js", true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := q.admit("a.js", true); err == nil || !strings.Contains(err.Error(), "最多排 1 个") {
		t.Fatalf("tight memory: %v", err)
	}
	q3 := newScriptQueue()
	tunnelConditions(t, 0, 2<<20) // below scriptAvailFloor (fix/xmly-memory-2; 3–6 MB: one waiter): nobody waits
	if _, _, err := q3.admit("a.js", true); err == nil || !strings.Contains(err.Error(), "内存紧张") {
		t.Fatalf("critical memory: %v", err)
	}
	if _, _, err := q3.admit("a.js", false); err != nil {
		t.Fatalf("an idle lock is still taken: %v", err)
	}
}

// bigScriptRig: a large bundle (≥ largeProgSource) as a response script on api.test.com/json.
func bigScriptRig(t *testing.T) *harness {
	t.Helper()
	big := "var x = 1;\n" + strings.Repeat("// pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad\n", (largeProgSource/66)+10) +
		`$done({body: "patched"});`
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`big = type=http-response,pattern=^https://api\.test\.com/json,requires-body=1,script-path=big.js`)}
	h := newHarness(t, cfg, map[string]string{"big.js": big})
	_, body := h.get("https://api.test.com/json") // compile + size the bundle
	if body != "patched" {
		t.Fatalf("warm-up: %q", body)
	}
	return h
}

// TestLargeQueueShedKicksWaiters: requests waiting for the large-bundle lock pass through unchanged as
// soon as Shed(ShedCritical) runs, instead of waiting their turn.
func TestLargeQueueShedKicksWaiters(t *testing.T) {
	h := bigScriptRig(t)
	h.e.scripts.bigSem <- struct{}{} // a run in progress
	released := false
	defer func() {
		if !released {
			<-h.e.scripts.bigSem
		}
	}()
	var wg sync.WaitGroup
	bodies := make([]string, 3)
	for i := range bodies {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, bodies[i] = h.get("https://api.test.com/json")
		}(i)
	}
	deadline := time.Now().Add(3 * time.Second)
	for h.e.scripts.queue.Waiting() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if w := h.e.scripts.queue.Waiting(); w != 3 {
		t.Fatalf("waiting %d", w)
	}
	if st := h.e.Shed(ShedLight); st.Dequeued != 0 {
		t.Fatalf("light shed dequeued %d", st.Dequeued)
	}
	start := time.Now()
	st := h.e.Shed(ShedCritical)
	wg.Wait()
	if st.Dequeued != 3 || time.Since(start) > 2*time.Second {
		t.Fatalf("dequeued %d after %s", st.Dequeued, time.Since(start))
	}
	for i, b := range bodies {
		if b == "patched" || !strings.Contains(b, `"keep":1`) {
			t.Fatalf("request %d: %q", i, b)
		}
	}
	if !strings.Contains(entryNotes(h.e), "内存紧张，已取消排队中的脚本") {
		t.Fatalf("notes %q", entryNotes(h.e))
	}
	<-h.e.scripts.bigSem
	released = true
	if h.e.scripts.queue.Waiting() != 0 {
		t.Fatal("waiters left")
	}
}

// TestLargeQueueSkipLoggedOncePerMinute: a burst the queue turns away writes one script-log line (the
// device log was a screenful of ERROR lines), while every request detail carries the note.
func TestLargeQueueSkipLoggedOncePerMinute(t *testing.T) {
	h := bigScriptRig(t)
	h.e.scripts.queue.observe("big.js", 30*time.Second) // a slow bundle: nobody can wait behind it
	h.e.scripts.bigSem <- struct{}{}
	defer func() { <-h.e.scripts.bigSem }()
	for i := 0; i < 4; i++ {
		_, body := h.get("https://api.test.com/json")
		if body == "patched" {
			t.Fatalf("request %d ran the script", i)
		}
	}
	lines := 0
	for _, l := range h.e.Logs.List(0, "big") {
		if strings.Contains(l.Msg, "脚本排队过长，已跳过") {
			lines += max(l.Count, 1)
		}
	}
	if lines != 1 {
		t.Fatalf("log lines %d", lines)
	}
	if n := countNotes(h.e, "跳过脚本：big — 脚本排队过长，已跳过"); n != 4 {
		t.Fatalf("notes %d: %q", n, entryNotes(h.e))
	}
}

// TestLargeQueueClientGoneLeavesQueue: a client that gives up while queued leaves the queue at once.
func TestLargeQueueClientGoneLeavesQueue(t *testing.T) {
	h := bigScriptRig(t)
	h.e.scripts.bigSem <- struct{}{}
	defer func() { <-h.e.scripts.bigSem }()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.test.com/json", nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if resp, err := h.client.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	for h.e.scripts.queue.Waiting() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	deadline = time.Now().Add(2 * time.Second)
	for h.e.scripts.queue.Waiting() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if w := h.e.scripts.queue.Waiting(); w != 0 {
		t.Fatalf("still waiting: %d", w)
	}
}

// TestSharedBodyRestoredAfterInPlaceChange: a large decoded body is lent to the script without a copy;
// a script that changes it in place and then fails (or does not hand it back) must not leak the change.
func TestSharedBodyRestoredAfterInPlaceChange(t *testing.T) {
	raw := bytes.Repeat([]byte("0123456789abcdef"), (1<<20)/16+4096) // > bigBodyThreshold
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	for _, js := range []string{
		`var u = $response.body; for (var i = 0; i < 16; i++) u[i] = 88; throw new Error("boom")`,
		`var u = $response.body; for (var i = 0; i < 16; i++) u[i] = 88; $done({})`,
	} {
		cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
			`b = type=http-response,pattern=^https://api\.test\.com/big,requires-body=1,binary-body-mode=1,max-size=-1,script-path=b.js`)}
		h := newHarness(t, cfg, map[string]string{"b.js": js})
		h.up.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(gz.Bytes())
		})
		resp, body := h.get("https://api.test.com/big")
		got := []byte(body)
		if resp.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(bytes.NewReader(got))
			if err != nil {
				t.Fatal(err)
			}
			got, _ = io.ReadAll(zr)
		}
		if !bytes.Equal(got, raw) {
			t.Fatalf("%s: body changed (%d vs %d bytes, head %q)", js, len(got), len(raw), clip(string(got), 20))
		}
	}
}
