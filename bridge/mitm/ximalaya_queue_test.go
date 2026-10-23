package mitm

import (
	"strings"
	"testing"
	"time"
)

// v0.19.19 喜马拉雅: a large bundle's HTTP request waiting behind other runs of the same bundle (one at a
// time) must not lose its turn after the script's own timeout — the player page fires 6–10 matching
// requests and track/v4/baseInfo, the one that unlocks playback, came last.
func TestLargeScriptQueueOutlastsScriptTimeout(t *testing.T) {
	big := "var x = 1;\n" + strings.Repeat("// pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad\n", (largeProgSource/66)+10) +
		`$done({body: "patched"});`
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`big = type=http-response,pattern=^https://api\.test\.com/base,requires-body=1,script-path=big.js,timeout=1`,
	)}
	h := newHarness(t, cfg, map[string]string{"big.js": big})
	h.e.scripts.bigSem <- struct{}{} // earlier runs of the bundle hold the lock past the 1 s script timeout
	go func() { time.Sleep(1600 * time.Millisecond); <-h.e.scripts.bigSem }()
	_, body := h.get("https://api.test.com/base")
	if body != "patched" {
		for _, l := range h.e.Logs.List(0, "") {
			t.Logf("log %s %s %s", l.Script, l.Level, l.Msg)
		}
		t.Fatalf("queued large script did not run: %q", body)
	}
	found := false
	for _, l := range h.e.Logs.List(0, "") {
		if strings.Contains(l.Msg, "排队") && strings.Contains(l.Msg, "大脚本逐个运行") {
			found = true
		}
	}
	if !found {
		t.Error("queue wait not logged")
	}

	// The queue is still bounded (here by the script timeout, which is longer than largeQueueWait).
	old := largeQueueWait()
	largeQueueWaitNs.Store(int64(300 * time.Millisecond))
	defer largeQueueWaitNs.Store(int64(old))
	h.e.scripts.bigSem <- struct{}{}
	start := time.Now()
	_, body = h.get("https://api.test.com/base")
	<-h.e.scripts.bigSem
	if body == "patched" || time.Since(start) > 3*time.Second {
		t.Fatalf("bounded queue: body %q after %s", body, time.Since(start))
	}
}
