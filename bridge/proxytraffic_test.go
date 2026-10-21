package libmihomo

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

// newTestTracker makes a real mihomo TCP tracker over a pipe whose far end discards / is closed by the test.
func newTestTracker(t *testing.T, chain C.Chain, push bool) (statistic.Tracker, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, b) }()
	conn := outbound.NewConn(a, outbound.NewDirect())
	tr := statistic.NewTCPTracker(conn, statistic.DefaultManager, &C.Metadata{NetWork: C.TCP}, nil, 0, 0, push)
	tr.Info().Chain = chain // classified on first sample, so the test can name the leaf freely
	t.Cleanup(func() { _ = tr.Close(); _ = b.Close() })
	return tr, b
}

func TestProxyTrafficAccounting(t *testing.T) {
	p := newProxyTraffic()
	// "直连节点" stands for a profile node of `type: direct`; every other non-built-in name is a proxy node.
	p.classify = func(leaf string) bool {
		if builtinNonProxy[leaf] || leaf == "直连节点" {
			return false
		}
		return true
	}
	direct, _ := newTestTracker(t, C.Chain{"DIRECT"}, true)
	directNode, _ := newTestTracker(t, C.Chain{"直连节点", "Proxy"}, true)
	reject, _ := newTestTracker(t, C.Chain{"REJECT-DROP"}, true)
	proxyA, _ := newTestTracker(t, C.Chain{"香港 01", "自动选择", "Proxy"}, true)
	proxyB, _ := newTestTracker(t, C.Chain{"日本 02", "Proxy"}, true)
	innerLeg, _ := newTestTracker(t, C.Chain{"香港 01"}, false) // dialer-proxy inner leg: not in the core's totals

	live := []statistic.Tracker{direct, directNode, reject, proxyA, proxyB, innerLeg}
	rng := func(f func(statistic.Tracker) bool) {
		for _, tr := range live {
			if !f(tr) {
				return
			}
		}
	}

	// Real bytes through the tracker: Write counts upload.
	if _, err := proxyA.(net.Conn).Write([]byte(strings.Repeat("x", 300))); err != nil {
		t.Fatal(err)
	}
	for _, tr := range []statistic.Tracker{direct, directNode, reject, innerLeg} {
		tr.Info().UploadTotal.Add(10_000)
		tr.Info().DownloadTotal.Add(50_000)
	}
	proxyB.Info().DownloadTotal.Add(2_000)

	t0 := time.Unix(1_700_000_000, 0)
	p.sample(rng, t0)
	if u, d := p.upTotal.Load(), p.downTotal.Load(); u != 300 || d != 2_000 {
		t.Fatalf("first sample: proxy totals %d/%d, want 300/2000", u, d)
	}

	// One more second: proxyB moves 4 KB down, then closes before the next sample with 1 KB more.
	proxyB.Info().DownloadTotal.Add(4_096)
	direct.Info().DownloadTotal.Add(1 << 20)
	p.sample(rng, t0.Add(time.Second))
	if r := p.downRate.Load(); r != 4_096 {
		t.Fatalf("down rate %d, want 4096", r)
	}
	proxyB.Info().DownloadTotal.Add(1_024)
	proxyB.Info().UploadTotal.Add(100)
	live = []statistic.Tracker{direct, directNode, reject, proxyA, innerLeg} // proxyB closed
	p.sample(rng, t0.Add(2*time.Second))
	if u, d := p.upTotal.Load(), p.downTotal.Load(); u != 400 || d != 2_000+4_096+1_024 {
		t.Fatalf("after close: proxy totals %d/%d, want 400/%d", u, d, 2_000+4_096+1_024)
	}
	if _, kept := p.entries[proxyB.Info()]; kept {
		t.Fatal("closed tracker still held after its final read")
	}
	if len(p.entries) != len(live) {
		t.Fatalf("entries %d, want %d (one per live connection)", len(p.entries), len(live))
	}

	// Nothing new: totals stay, rate drops to 0.
	p.sample(rng, t0.Add(3*time.Second))
	if p.upRate.Load() != 0 || p.downRate.Load() != 0 {
		t.Fatalf("idle rate %d/%d, want 0/0", p.upRate.Load(), p.downRate.Load())
	}
	if p.downTotal.Load() != 7_120 {
		t.Fatalf("idle total changed: %d", p.downTotal.Load())
	}
}

func TestProxyTrafficPushFlag(t *testing.T) {
	a, _ := newTestTracker(t, C.Chain{"n"}, true)
	b, _ := newTestTracker(t, C.Chain{"n"}, false)
	if !pushesToManager(a) || pushesToManager(b) {
		t.Fatalf("pushToManager read as %v/%v, want true/false (mihomo renamed the field?)", pushesToManager(a), pushesToManager(b))
	}
}

func TestProxyTrafficClassifyBuiltins(t *testing.T) {
	p := newProxyTraffic()
	for _, n := range []string{"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", ""} {
		if p.classifyLive(n) {
			t.Errorf("%q classified as proxy", n)
		}
	}
	if !p.classifyLive("某个节点") {
		t.Error("an unknown node name should count as proxy")
	}
}

// r7: stop → start in the same process: connections still open are seeded at their current counters,
// so their earlier bytes are not counted at once.
func TestR7ProxyTrafficSeedOnRestart(t *testing.T) {
	p := newProxyTraffic()
	p.classify = func(leaf string) bool { return !builtinNonProxy[leaf] }
	old, _ := newTestTracker(t, C.Chain{"香港 01", "Proxy"}, true)
	old.Info().DownloadTotal.Add(5 << 20)
	rng := func(f func(statistic.Tracker) bool) { f(old) }
	p.seed(rng)
	old.Info().DownloadTotal.Add(1_000)
	p.sample(rng, time.Unix(1_700_000_000, 0))
	if d := p.downTotal.Load(); d != 1_000 {
		t.Fatalf("down total %d after restart, want only the 1000 bytes moved since", d)
	}
}
