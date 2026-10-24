package mitm

// Native body lane hardening (feat/native-mitm B3): handle cleanup on every path, breaker window / reset,
// budget and big-body lock parity with the v0.19.22 Go path.

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// A body the lane skipped (too big: 33 KB of gzip decodes to 50 KB, above max-size 40000) is passed through from the lane; a later script without requires-body
// that replaces the body must free that handle (it used to stay allocated until the tunnel stopped).
func TestLaneSkippedBodyReplacedFreesHandle(t *testing.T) {
	l := useFakeLane(t)
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`vip = type=http-response,pattern=^https://api\.test\.com/body,requires-body=1,max-size=40000,script-path=vip.js`,
		`mock = type=http-response,pattern=^https://api\.test\.com/body,script-path=mock.js`)}
	h := newLaneHarness(t, cfg, map[string]string{"vip.js": vipJS, "mock.js": `$done({body: "replaced"})`})
	_, b := fetchBody(t, h, "https://api.test.com/body?enc=gzip&n=50000")
	if string(b) != "replaced" {
		t.Fatalf("got %q", clip(string(b), 60))
	}
	if l.opened.Load() != 1 {
		t.Fatalf("opened %d", l.opened.Load())
	}
	waitLive(t, l)
}

// Parity with readCapped: the bytes received are capped at the limit whatever the encoding, so a stored
// (level 0) gzip body whose decoded size fits but whose encoded size does not is passed through.
func TestLaneRawCapAnyEncoding(t *testing.T) {
	l := useFakeLane(t)
	doc := laneDoc(8000)
	var buf bytes.Buffer
	w, _ := gzip.NewWriterLevel(&buf, gzip.NoCompression)
	_, _ = w.Write(doc)
	_ = w.Close()
	raw := buf.Bytes()
	limit := int64(len(doc) + (len(raw)-len(doc))/2) // decoded fits, encoded does not
	res, err := laneLoad(context.Background(), l, nil, bytes.NewReader(raw), "gzip", limit, int64(len(raw)))
	if !errors.Is(err, errBodyTooBig) || !res.consumed {
		t.Fatalf("err %v consumed %v", err, res.consumed)
	}
	// the caller passes through what the lane received + pending + the rest: the original bytes
	rr := newLaneReader(l, res.h, true, nil)
	got, _ := io.ReadAll(io.MultiReader(rr, bytes.NewReader(res.pending)))
	_ = rr.Close()
	if !bytes.Equal(got, raw) {
		t.Fatalf("pass-through %d bytes, want %d", len(got), len(raw))
	}
	waitLive(t, l)
}

// Breaker: failures older than the window do not count; three inside it trip; a config reload resets it.
func TestLaneBreakerWindowAndReload(t *testing.T) {
	useFakeLane(t)
	laneFailure(nil, "a")
	laneFailure(nil, "b")
	laneFailMu.Lock()
	for i := range laneFails {
		laneFails[i] = laneFails[i].Add(-laneBreakerWindow - time.Second)
	}
	laneFailMu.Unlock()
	laneFailure(nil, "c")
	if laneOff.Load() {
		t.Fatal("tripped on failures outside the window")
	}
	laneFailure(nil, "d")
	laneFailure(nil, "e")
	if !laneOff.Load() || laneUsable() != nil {
		t.Fatal("three failures in the window did not trip")
	}
	if laneAny() == nil {
		t.Fatal("a tripped lane must still serve handles already held")
	}
	h := newLaneHarness(t, laneCfg(""), map[string]string{"vip.js": vipJS})
	h.e.Reload(laneCfg(""), Build(h.home, laneCfg("")))
	if laneOff.Load() || laneUsable() == nil {
		t.Fatal("reload did not reset the breaker")
	}
}

// A handle the store lost mid-stream: the client sees a cut response (never a silently short one) and the
// failure counts towards the breaker.
func TestLaneReaderShortReadIsError(t *testing.T) {
	l := useFakeLane(t)
	h := l.Open("", 1<<20, -1)
	_ = l.Write(h, laneDoc(100000))
	if l.Finish(h) <= 0 {
		t.Fatal("finish")
	}
	laneLive.Add(1) // as laneLoad would
	r := newLaneReader(l, h, false, nil)
	p := make([]byte, laneChunk)
	if _, err := r.Read(p); err != nil {
		t.Fatal(err)
	}
	l.Free(h) // the store dropped it
	failed := laneFailed.Load()
	if _, err := r.Read(p); err != io.ErrUnexpectedEOF {
		t.Fatalf("read after loss: %v", err)
	}
	if laneFailed.Load() != failed+1 {
		t.Fatal("short read not counted")
	}
	_ = r.Close()
	_ = r.Close() // once
	if laneLive.Load() != 0 {
		t.Fatalf("live %d", laneLive.Load())
	}
	ResetLaneBreaker()
}

// Budget / big-body parity: a large lane body takes the one-at-a-time lock like the Go path; while another
// holds it the answer passes through unchanged (from the lane) and the handle is freed; afterwards both the
// lock and the body budget are back to idle.
func TestLaneBigBodyLockAndBudgetParity(t *testing.T) {
	old := bigBodyWait
	bigBodyWait = 200 * time.Millisecond
	defer func() { bigBodyWait = old }()
	l := useFakeLane(t)
	h := newLaneHarness(t, laneCfg(""), map[string]string{"vip.js": vipJS})
	const n = 1500 << 10
	rel := acquireBigBody(context.Background())
	if rel == nil {
		t.Fatal("lock busy at start")
	}
	resp, b := fetchBody(t, h, "https://api.test.com/body?enc=br&n=1536000")
	if resp.Header.Get("Content-Encoding") != "br" {
		t.Fatalf("expected the br original while the lock is held, got encoding %q (%d bytes)", resp.Header.Get("Content-Encoding"), len(b))
	}
	if notes := entryNotes(h.e); !strings.Contains(notes, "另一个大响应体正在处理") {
		t.Fatalf("notes %q", notes)
	}
	waitLive(t, l)
	rel()
	_, b = fetchBody(t, h, "https://api.test.com/body?enc=br&n=1536000")
	if !bytes.HasPrefix(b, []byte(`{"vip":true,`)) || len(b) < n-16 {
		t.Fatalf("script did not run once the lock was free: %q", clip(string(b), 40))
	}
	waitLive(t, l)
	deadline := time.Now().Add(2 * time.Second)
	for len(bigBodyLock) != 0 || bodyBudget.inUse() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("after the response: big lock %d, budget in use %d", len(bigBodyLock), bodyBudget.inUse())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
