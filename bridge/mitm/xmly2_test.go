package mitm

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fix/xmly-memory-2 (v0.19.23 build 330 on device, 2026-10-24 22:14–22:17, 喜马拉雅):
//   - 22:14 at 3.1 MB available: 「跳过脚本：内存紧张（隧道可用 3.1 MB）」 ×6, 「获取Cookie失败:内存紧张，已跳过下载」;
//   - 22:16 at ~5 MB: 「付费接口异常 / 免费接口异常：内存紧张，已跳过下载（保护隧道内存）」 (answers without
//     Content-Length counted as large), then 「跳过脚本：内存紧张（隧道可用 5.0 / 4.8 / 4.6 / 4.7 MB）」;
//   - 22:17 idle: footprint 41.1 MB, 2 connections, Go heap 13.6 MB / sys 42.5 MB.

// chunkedScript: like the 喜马拉雅 unlock — a small API answer without Content-Length, then the body rewrite.
const chunkedScript = `
var o = JSON.parse($response.body);
$httpClient.get({url: "https://api.test.com/chunked", headers: {"X-Want": "paid"}, insecure: true}, function (err, resp, data) {
  if (err) { o.fetch = "failed: " + err; $done({body: JSON.stringify(o)}); return; }
  o.fetch = JSON.parse(data).headers["X-Want"];
  $done({body: JSON.stringify(o)});
});`

const chunkedBigScript = `
var o = JSON.parse($response.body);
$httpClient.get({url: "https://api.test.com/chunkedbig", insecure: true}, function (err, resp, data) {
  o.fetch = err ? "failed: " + err : "got " + data.length;
  $done({body: JSON.stringify(o)});
});`

func xmly2Harness(t *testing.T, src string) *harness {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`x2 = type=http-response,pattern=^https://api\.test\.com/json,requires-body=1,script-path=x2.js,timeout=10`)}
	return newHarness(t, cfg, map[string]string{"x2.js": src})
}

// 22:16: the paid / free API answers (no Content-Length) at 5.0 MB available — before: refused as large.
func TestXmly2ChunkedFetchAt5MB(t *testing.T) {
	h := xmly2Harness(t, chunkedScript)
	fixedAvail(t, func() int64 { return 5 << 20 })
	if !heapHigh() {
		t.Fatal("heapHigh should hold at 5 MB")
	}
	_, body := h.get("https://api.test.com/json")
	if !strings.Contains(body, `"fetch":"paid"`) {
		t.Fatalf("chunked small answer refused at 5 MB: %s\nnotes: %s", body, entryNotes(h.e))
	}
}

// 22:14: the cookie request and the response body itself at 3.1 MB available — before: both refused.
func TestXmly2CookieFetchAt3_1MB(t *testing.T) {
	h := headroomHarness(t)
	fixedAvail(t, func() int64 { return 3<<20 + 100<<10 })
	_, body := h.get("https://api.test.com/json")
	if !strings.Contains(body, `"fetch":"cookie"`) {
		t.Fatalf("script / cookie fetch refused at 3.1 MB: %s\nnotes: %s", body, entryNotes(h.e))
	}
}

// A response body without Content-Length is scripted at 4.6 MB (22:16 「跳过脚本：内存紧张（隧道可用 4.6 MB）」).
func TestXmly2ChunkedResponseBodyAt4_6MB(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`x2 = type=http-response,pattern=^https://api\.test\.com/jsonchunked,requires-body=1,script-path=x2.js,timeout=10`)}
	h := newHarness(t, cfg, map[string]string{"x2.js": chunkedScript})
	fixedAvail(t, func() int64 { return 4<<20 + 600<<10 })
	_, body := h.get("https://api.test.com/jsonchunked")
	if !strings.Contains(body, `"fetch":"paid"`) {
		t.Fatalf("chunked response body skipped at 4.6 MB: %s\nnotes: %s", body, entryNotes(h.e))
	}
}

// A dip below the floor that recovers within the wait (the burst ends, reclaim returns memory): the fetch waits
// and goes ahead instead of failing at once.
func TestXmly2FetchWaitsForHeadroom(t *testing.T) {
	h := xmly2Harness(t, chunkedScript)
	var low atomic.Bool
	low.Store(true)
	fixedAvail(t, func() int64 {
		if low.Load() {
			return 2 << 20
		}
		return 3 << 20
	})
	// the response body itself waits too: lift the dip after 400 ms
	time.AfterFunc(400*time.Millisecond, func() { low.Store(false) })
	start := time.Now()
	_, body := h.get("https://api.test.com/json")
	if !strings.Contains(body, `"fetch":"paid"`) {
		t.Fatalf("not processed after the dip ended: %s\nnotes: %s", body, entryNotes(h.e))
	}
	if d := time.Since(start); d < 350*time.Millisecond {
		t.Errorf("did not wait (%s)", d)
	}
}

// Still refused when memory stays below the floor for the whole wait — and the wait is bounded.
func TestXmly2StaysLowRefusedAfterWait(t *testing.T) {
	old := smallHeadroomWait
	smallHeadroomWait = 300 * time.Millisecond
	defer func() { smallHeadroomWait = old }()
	fixedAvail(t, func() int64 { return 2 << 20 })
	start := time.Now()
	if waitSmallWork(context.Background(), 8<<10, smallBodyFloor, smallHeadroomWait) {
		t.Fatal("small work allowed at 2 MB")
	}
	if d := time.Since(start); d < 250*time.Millisecond || d > 2*time.Second {
		t.Fatalf("wait %s, want ~300 ms", d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitSmallWork(ctx, 8<<10, smallBodyFloor, time.Second) {
		t.Fatal("allowed after the client left")
	}
}

// An answer without Content-Length that turns out large is still refused while memory is short (read capped
// at smallWorkMax), and goes through with room.
func TestXmly2ChunkedLargeFetchCapped(t *testing.T) {
	h := xmly2Harness(t, chunkedBigScript)
	fixedAvail(t, func() int64 { return 5 << 20 })
	_, body := h.get("https://api.test.com/json")
	if !strings.Contains(body, `failed:`) || !strings.Contains(body, `256 KB`) {
		t.Fatalf("large chunked answer not refused at 5 MB: %s", body)
	}
	fixedAvail(t, func() int64 { return 30 << 20 })
	_, body = h.get("https://api.test.com/json")
	if !strings.Contains(body, `"fetch":"got `) {
		t.Fatalf("large chunked answer refused with room: %s", body)
	}
}

// Unknown length is judged as smallUnknownEstimate, not smallWorkMax.
func TestXmly2UnknownLengthEstimate(t *testing.T) {
	fixedAvail(t, func() int64 { return smallFetchFloor + smallWorkCost(smallUnknownEstimate) + 10<<10 })
	if !smallWorkOK(-1, smallFetchFloor) {
		t.Fatal("unknown length judged as more than smallUnknownEstimate")
	}
	if smallWorkOK(smallWorkMax, smallFetchFloor) {
		t.Fatal("256 KB allowed with only the 64 KB estimate's headroom")
	}
}

// Under pressure the large-bundle queue serializes (one waiter) instead of turning everyone away; only below
// scriptAvailFloor nobody waits.
func TestXmly2QueueSerializesUnderPressure(t *testing.T) {
	fixedAvail(t, func() int64 { return 5 << 20 })
	if n := queueLimit(); n != 1 {
		t.Fatalf("queueLimit at 5 MB = %d, want 1", n)
	}
	fixedAvail(t, func() int64 { return 2 << 20 })
	if n := queueLimit(); n != 0 {
		t.Fatalf("queueLimit at 2 MB = %d, want 0", n)
	}
	fixedAvail(t, func() int64 { return 40 << 20 })
	if n := queueLimit(); n != int(queueMaxWaitingN.Load()) {
		t.Fatalf("queueLimit with room = %d", n)
	}
}

// While memory is tight client handshakes take turns (hsTightConcurrent); a waiter proceeds when a turn frees
// up, and after hsMaxWait at the latest. With room nobody waits.
func TestXmly2HandshakeTurns(t *testing.T) {
	old := hsMaxWait
	hsMaxWait = 400 * time.Millisecond
	defer func() { hsMaxWait = old }()
	fixedAvail(t, func() int64 { return 40 << 20 })
	var rels []func()
	for i := 0; i < 2*hsTightConcurrent; i++ {
		rels = append(rels, handshakeTurn(context.Background()))
	}
	if len(hsSem) != 0 {
		t.Fatal("turns taken with room")
	}
	for _, r := range rels {
		r()
	}
	rels = nil
	fixedAvail(t, func() int64 { return 5 << 20 })
	for i := 0; i < hsTightConcurrent; i++ {
		rels = append(rels, handshakeTurn(context.Background()))
	}
	got := make(chan time.Duration, 1)
	go func() {
		s := time.Now()
		r := handshakeTurn(context.Background())
		got <- time.Since(s)
		r()
	}()
	time.Sleep(100 * time.Millisecond)
	rels[0]()
	if d := <-got; d < 80*time.Millisecond || d > 350*time.Millisecond {
		t.Fatalf("waiter got its turn after %s, want right after the release (~100 ms)", d)
	}
	for _, r := range rels[1:] {
		r()
	}
	rels = nil
	for i := 0; i < hsTightConcurrent; i++ {
		rels = append(rels, handshakeTurn(context.Background()))
	}
	start := time.Now()
	handshakeTurn(context.Background())() // all held: proceeds after hsMaxWait anyway
	if d := time.Since(start); d < 350*time.Millisecond || d > 2*time.Second {
		t.Fatalf("full gate: proceeded after %s, want ~hsMaxWait", d)
	}
	for _, r := range rels {
		r()
	}
	if len(hsSem) != 0 {
		t.Fatalf("turns leaked: %d", len(hsSem))
	}
}

// The end of an HTTP-script burst with little memory returns Go's free pages once; not while runs are active,
// not with room.
// waitReliefIdle waits for a relief scheduled by an earlier test (750 ms delay) to fire.
func waitReliefIdle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for (reliefPending.Load() || runsActive.Load() > 0) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	// The relief callback clears reliefPending before its FreeOSMemory (a full GC, hundreds of ms in a busy
	// test process) and only then counts the return: wait until reliefsDone holds still, or an earlier
	// test's relief lands inside the caller's window (local full run: "relief with room").
	for n := reliefsDone.Load(); time.Now().Before(deadline); {
		time.Sleep(150 * time.Millisecond)
		m := reliefsDone.Load()
		if m == n && !reliefPending.Load() {
			break
		}
		n = m
	}
}

func TestXmly2RunReliefAfterBurst(t *testing.T) {
	waitReliefIdle(t)
	oldDelay := reliefDelay
	reliefDelay = 50 * time.Millisecond
	defer func() { reliefDelay = oldDelay }()
	fixedAvail(t, func() int64 { return 40 << 20 })
	n0 := reliefsDone.Load()
	scheduleRunRelief()
	time.Sleep(150 * time.Millisecond)
	if reliefsDone.Load() != n0 {
		t.Fatal("relief with room")
	}
	fixedAvail(t, func() int64 { return 5 << 20 })
	runsActive.Add(1)
	scheduleRunRelief()
	time.Sleep(150 * time.Millisecond)
	if reliefsDone.Load() != n0 {
		t.Fatal("relief while a run is active")
	}
	runsActive.Add(-1)
	lastFreeOS.Store(0)
	scheduleRunRelief()
	scheduleRunRelief() // coalesced
	time.Sleep(200 * time.Millisecond)
	if got := reliefsDone.Load() - n0; got != 1 {
		t.Fatalf("reliefs after the burst = %d, want 1", got)
	}
}

// End to end: the script run through the harness schedules the relief when memory is tight.
func TestXmly2RunScheduledRelief(t *testing.T) {
	waitReliefIdle(t)
	oldDelay := reliefDelay
	reliefDelay = 20 * time.Millisecond
	defer func() { reliefDelay = oldDelay }()
	h := headroomHarness(t)
	fixedAvail(t, func() int64 { return 8 << 20 })
	n0 := reliefsDone.Load()
	lastFreeOS.Store(0)
	_, body := h.get("https://api.test.com/json")
	if !strings.Contains(body, `"fetch":"cookie"`) {
		t.Fatalf("not scripted at 8 MB: %s", body)
	}
	deadline := time.Now().Add(2 * time.Second)
	for reliefsDone.Load() == n0 && time.Now().Before(deadline) {
		lastFreeOS.Store(0) // a gate's own FreeOSMemory may have used the slot
		time.Sleep(20 * time.Millisecond)
	}
	if reliefsDone.Load() == n0 {
		t.Fatal("no relief after the run")
	}
}
