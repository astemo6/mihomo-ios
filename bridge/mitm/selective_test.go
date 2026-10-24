package mitm

import (
	"strings"
	"testing"

	"github.com/dlclark/regexp2"
)

func mustHostRe(t *testing.T, src string) *regexp2.Regexp {
	t.Helper()
	re, err := regexp2.Compile(src, regexp2.IgnoreCase)
	if err != nil {
		t.Fatalf("%s: %v", src, err)
	}
	return re
}

func TestPatternHostPart(t *testing.T) {
	for _, c := range []struct {
		p, host string
		ok      bool
		match   bool
	}{
		{`^https?:\/\/api\.example\.com\/v1\/feed`, "api.example.com", true, true},
		{`^https?:\/\/api\.example\.com\/v1\/feed`, "www.example.com", true, false},
		{`^https://heavy\.bench\.test/big`, "heavy.bench.test", true, true},
		{`^https?://(edith|rec|www)\.xiaohongshu\.com/api/`, "edith.xiaohongshu.com", true, true},
		{`^https?://(edith|rec|www)\.xiaohongshu\.com/api/`, "xiaohongshu.com", true, false},
		{`^https?:\/\/[\w-]+\.googlevideo\.com\/.+&oad`, "rr1---sn-a.googlevideo.com", true, true},
		{`^https?:\/\/.+\.example\.com(:\d+)?\/x`, "a.b.example.com", true, true},
		{`^https?:\/\/api\.x\.com(?::443)?\/`, "api.x.com", true, true},
		{`(?i)^HTTPS?:\/\/API\.X\.COM\/`, "api.x.com", true, true},
		{`^http[s]?:\/\/api\.x\.com\/`, "api.x.com", true, true},
		{`^(?:https?):\/\/api\.x\.com\/`, "api.x.com", true, true},
		{`api\.x\.com\/v2`, "m.api.x.com", true, true},
		{`api\.x\.com\/v2`, "api.x.com.cn", true, false},
		{`^https?:\/\/api\.x\.com(\/v1|\/v2)\/`, "api.x.com", false, false}, // slash inside a group: learned only
		{`^/path`, "", false, false},
		{`youtubei`, "", false, false},
		{`^https?:\/\/.*`, "anything.example", true, true},
	} {
		hp, anchored, ok := patternHostPart(c.p)
		if ok != c.ok {
			t.Fatalf("%s: ok %v (host part %q)", c.p, ok, hp)
		}
		if !ok {
			continue
		}
		src := "^(?:" + hp + ")$"
		if !anchored {
			src = "(?:" + hp + ")$"
		}
		re := mustHostRe(t, src)
		if got, _ := re.MatchString(c.host); got != c.match {
			t.Fatalf("%s: host part %q (anchored %v) on %q = %v", c.p, hp, anchored, c.host, got)
		}
	}
}

func selCfg() *Config {
	return &Config{Enabled: true, MitM: true, Hostnames: []string{"*.test.com"}, Rules: items(
		`http-response ^https://heavy\.test\.com/json header-add X-H 1`,
		`^https://plain\.test\.com/blocked - reject-200`,
		`http-response-jq ^https://jq\.test\.com/json '.combo = true'`,
		`http-response-jq ^https?://(?:api|cdn)\.test\.com(\/json|\/v2) '.learned = true'`,
	), Scripts: items(
		`heavy = type=http-response,pattern=^https://heavy\.test\.com/json,requires-body=1,script-path=heavy.js`,
	)}
}

func TestSelectiveHosts(t *testing.T) {
	h := newHarness(t, selCfg(), map[string]string{"heavy.js": `var o = JSON.parse($response.body); o.s = 1; $done({body: JSON.stringify(o)});`})
	defer SetNativeSelective(SelectiveOff)

	SetNativeSelective(SelectiveOff)
	if !h.e.selectiveWants("plain.test.com") {
		t.Fatal("selective off must not filter")
	}
	SetNativeSelective(SelectiveHeavy)
	for host, want := range map[string]bool{"heavy.test.com": true, "jq.test.com": true, "plain.test.com": false, "other.test.com": false, "HEAVY.test.com.": true} {
		if got := h.e.selectiveWants(host); got != want {
			t.Fatalf("heavy mode %s: %v", host, got)
		}
	}
	SetNativeSelective(SelectiveScripts)
	for host, want := range map[string]bool{"heavy.test.com": true, "jq.test.com": false, "plain.test.com": false} {
		if got := h.e.selectiveWants(host); got != want {
			t.Fatalf("scripts mode %s: %v", host, got)
		}
	}
	// learned: a pattern whose host part cannot be isolated; the Go path matches it once, then the host is native
	SetNativeSelective(SelectiveHeavy)
	if h.e.selectiveWants("cdn.test.com") {
		t.Fatal("cdn.test.com native before any match")
	}
	_, _, l0 := SelectiveStats()
	resp, body := h.get("https://cdn.test.com/json")
	if resp.StatusCode != 200 || !strings.Contains(body, `"learned":true`) {
		t.Fatalf("jq on the Go path: %d %q", resp.StatusCode, body)
	}
	if _, _, l1 := SelectiveStats(); l1 != l0+1 {
		t.Fatalf("learned %d", l1-l0)
	}
	if !h.e.selectiveWants("cdn.test.com") {
		t.Fatal("cdn.test.com not native after a heavy match on the Go path")
	}
	// a reload starts over
	cfg := selCfg()
	h.e.Reload(cfg, Build(h.home, cfg))
	if h.e.selectiveWants("cdn.test.com") {
		t.Fatal("learned host survived a reload")
	}
}

// Selective mode in front of the native terminator: only the heavy host is handed over; the plain host never
// reaches Listen and is served by Go with its rewrites.
func TestSelectiveHandoff(t *testing.T) {
	h := newHarness(t, selCfg(), map[string]string{"heavy.js": `$done({});`})
	f := useFakeTerm(t, h, "")
	SetNativeSelective(SelectiveHeavy)
	defer SetNativeSelective(SelectiveOff)
	if resp, _ := h.get("https://plain.test.com/blocked"); resp.StatusCode != 200 || resp.Header.Get("X-Native") != "" {
		t.Fatalf("plain host: %d native=%q", resp.StatusCode, resp.Header.Get("X-Native"))
	}
	if f.calls.Load() != 0 {
		t.Fatalf("plain host reached the native front (%d Listen calls)", f.calls.Load())
	}
	h.client.CloseIdleConnections()
	if resp, _ := h.get("https://jq.test.com/json"); resp.Header.Get("X-Native") != "1" {
		t.Fatalf("heavy host not handed to the native front: %v", resp.Header)
	}
	if f.calls.Load() != 1 {
		t.Fatalf("Listen calls %d", f.calls.Load())
	}
}
