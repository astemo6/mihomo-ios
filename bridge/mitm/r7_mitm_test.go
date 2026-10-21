package mitm

// Review 7 (bridge/mitm lane) regression tests, from the probes in work/review7/mitm_probes.

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// P2-1: large-bundle HTTP scripts waiting for the large-bundle lock must not hold the HTTP script slots.
func TestR7BigSemDoesNotHoldHTTPSlot(t *testing.T) {
	big := "var x = 1;\n" + strings.Repeat("// pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad\n", (largeProgSource/66)+10) + "$done({});"
	small := `$done({headers: Object.assign({}, $request.headers, {"X-Small": "1"})});`
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`big = type=http-request,pattern=^https://api\.test\.com/big,script-path=big.js,timeout=3`,
		`small = type=http-request,pattern=^https://api\.test\.com/echo,script-path=small.js,timeout=1`,
	)}
	h := newHarness(t, cfg, map[string]string{"big.js": big, "small.js": small})
	h.e.scripts.bigSem <- struct{}{} // a long-running large task holds the lock
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); h.get("https://api.test.com/big") }()
	}
	time.Sleep(300 * time.Millisecond)
	_, body := h.get("https://api.test.com/echo")
	<-h.e.scripts.bigSem
	wg.Wait()
	if !strings.Contains(strings.ToLower(body), "x-small") {
		for _, l := range h.e.Logs.List(0, "") {
			t.Logf("log %s %s %s", l.Script, l.Level, l.Msg)
		}
		t.Fatalf("small script did not run while large scripts waited for the large-bundle lock: %s", body)
	}
}
