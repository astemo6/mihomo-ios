package libmihomo

// v0.6.1 memory and rule fixes from the first device test (iPhone, iOS 18.7).

import (
	"net/url"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/astemo6/mihomo-android/core/mitm"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

const (
	steadyGOGC   = 75 // a little more eager than Go's 100: the NE has ~10 MB headroom, CPU is cheap by comparison
	startupGOGC  = 40 // while providers parse at start
	startupProcs = 2  // fewer parallel provider parses → lower peak heap
)

var disablePacing, testOldPacing bool // tests only (A/B measurement)

// startupPacing tightens GC and parallelism for the startup burst; the returned func restores them.
func startupPacing() func() {
	if disablePacing {
		return func() {}
	}
	prevProcs := runtime.GOMAXPROCS(startupProcs)
	debug.SetGCPercent(startupGOGC)
	return func() {
		runtime.GOMAXPROCS(prevProcs)
		debug.SetGCPercent(steadyGOGC)
		debug.FreeOSMemory()
	}
}

func validTestURL(s string) bool {
	u, err := url.Parse(strings.TrimSpace(s))
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// overrideHealthCheckURL points every group / provider health check at the user's test URL.
func overrideHealthCheckURL(raw map[string]any, testURL string) {
	for _, g := range asList(raw["proxy-groups"]) {
		m, ok := g.(map[string]any)
		if !ok {
			continue
		}
		switch strings.ToLower(str(m["type"])) {
		case "url-test", "fallback", "load-balance", "smart":
			m["url"] = testURL
		default:
			if _, has := m["url"]; has {
				m["url"] = testURL
			}
		}
	}
	for _, p := range asMap(raw["proxy-providers"]) {
		m, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if hc, ok := m["health-check"].(map[string]any); ok {
			hc["url"] = testURL
		}
	}
}

// UDPFallbackRule ends the rule list. mihomo skips a matched rule whose proxy has no UDP support and
// keeps looking; when nothing else matches it falls back to DIRECT ("doesn't match any rule using
// DIRECT") — even after MATCH. For QUIC that means a direct connection the user's rules never chose
// (fails or leaks in China). Rejecting UDP 443 instead makes the app fall back to TCP, which follows
// the rules through the proxy. Other UDP keeps mihomo's behaviour.
const UDPFallbackRule = "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"

// applyQUICBlock implements 连接方式 → 阻止 QUIC:
//   - "off": mihomo's own behaviour (no rule added);
//   - "nondirect" (default, = v0.6.1): UDP 443 that would otherwise fall back to DIRECT because the chosen
//     proxy has no UDP is rejected, so it never bypasses the rules; QUIC the rules send DIRECT, or through a
//     UDP-capable node, still works;
//   - "always": all QUIC is rejected up front (except the engine's own INNER traffic), apps use TCP.
func applyQUICBlock(raw map[string]any, mode string) {
	switch mode {
	case "off":
		return
	case "always":
		rules := asList(raw["rules"])
		if len(rules) == 0 {
			return
		}
		for _, r := range rules {
			if s, ok := r.(string); ok && s == mitm.QUICBlockAllRule {
				appendUDPFallback(raw)
				return
			}
		}
		raw["rules"] = append([]any{mitm.QUICBlockAllRule}, rules...)
		appendUDPFallback(raw)
	default:
		appendUDPFallback(raw)
	}
}

func appendUDPFallback(raw map[string]any) {
	rules := asList(raw["rules"])
	if len(rules) == 0 {
		return
	}
	raw["rules"] = append(rules, UDPFallbackRule)
}

// ShedConnections closes connections under memory pressure: the oldest first, at most `percent` of
// them (1–100). Long-lived idle connections (push, keep-alive) are typically the oldest, while the
// page the user is loading right now keeps its fresh connections.
func ShedConnections(percent int) int {
	if percent <= 0 {
		percent = 25
	}
	if percent > 100 {
		percent = 100
	}
	var all []statistic.Tracker
	statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
		all = append(all, c)
		return true
	})
	if len(all) == 0 {
		return 0
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Info().Start.Before(all[j].Info().Start) })
	n := (len(all)*percent + 99) / 100
	for _, c := range all[:n] {
		_ = c.Close()
	}
	log.Warnln("[Memory] closed %d of %d connections (oldest first) under memory pressure", n, len(all))
	return n
}
