package libmihomo

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

// fakeTotals stands in for the manager's global counters (other tests push into the real one concurrently).
type fakeTotals struct{ up, down atomic.Int64 }

func (f *fakeTotals) read() (int64, int64) { return f.up.Load(), f.down.Load() }

func r7Range(live *[]statistic.Tracker) func(func(statistic.Tracker) bool) {
	return func(f func(statistic.Tracker) bool) {
		for _, tr := range *live {
			if !f(tr) {
				return
			}
		}
	}
}

// Review 7 P2-1: a proxy connection that opens and closes between two samples is counted.
func TestR7P21ShortLivedProxyConnCounted(t *testing.T) {
	p := newProxyTraffic()
	p.classify = func(string) bool { return true }
	ft := &fakeTotals{}
	p.totals = ft.read
	live := []statistic.Tracker{}
	t0 := time.Now()
	p.sample(r7Range(&live), t0)
	// A short connection the sampler never sees: only the manager totals grow.
	ft.up.Add(5000)
	ft.down.Add(100000)
	p.sample(r7Range(&live), t0.Add(time.Second))
	if p.upTotal.Load() != 5000 || p.downTotal.Load() != 100000 {
		t.Fatalf("short proxy conn not counted: up=%d down=%d", p.upTotal.Load(), p.downTotal.Load())
	}
}

// The residual is split by what the seen trackers did in the same interval: with only direct traffic seen,
// unseen short connections are not counted as proxy; with a 50/50 split, half is.
func TestR7P21ResidualSplitByShare(t *testing.T) {
	p := newProxyTraffic()
	p.classify = func(leaf string) bool { return leaf != "DIRECT" }
	ft := &fakeTotals{}
	p.totals = ft.read
	direct, _ := newTestTracker(t, C.Chain{"DIRECT"}, true)
	proxy, _ := newTestTracker(t, C.Chain{"香港 01", "Proxy"}, true)
	live := []statistic.Tracker{direct}
	t0 := time.Now()
	p.sample(r7Range(&live), t0)
	// interval 1: direct moves 1000 (seen), a short unseen conn moves 1000.
	direct.Info().DownloadTotal.Add(1000)
	ft.down.Add(2000)
	p.sample(r7Range(&live), t0.Add(time.Second))
	if got := p.downTotal.Load(); got != 0 {
		t.Fatalf("only direct seen: proxy down should stay 0, got %d", got)
	}
	// interval 2: direct 1000 + proxy 1000 seen, unseen 2000 → half proxy.
	live = append(live, proxy)
	p.sample(r7Range(&live), t0.Add(2*time.Second)) // first sight of proxy (0 bytes)
	direct.Info().DownloadTotal.Add(1000)
	proxy.Info().DownloadTotal.Add(1000)
	ft.down.Add(4000)
	p.sample(r7Range(&live), t0.Add(3*time.Second))
	if got := p.downTotal.Load(); got != 2000 {
		t.Fatalf("50/50 split: want proxy down 1000 seen + 1000 residual = 2000, got %d", got)
	}
}

// A tracker counted ahead of the totals read must not be counted twice in the next interval.
func TestR7P21CarryNoDoubleCount(t *testing.T) {
	p := newProxyTraffic()
	p.classify = func(string) bool { return true }
	ft := &fakeTotals{}
	p.totals = ft.read
	tr, _ := newTestTracker(t, C.Chain{"香港 01"}, true)
	live := []statistic.Tracker{tr}
	t0 := time.Now()
	p.sample(r7Range(&live), t0)
	_, _ = tr.(net.Conn).Write([]byte(strings.Repeat("x", 300))) // tracker sees it, totals (fake) lag behind
	p.sample(r7Range(&live), t0.Add(time.Second))
	ft.up.Add(300) // the totals catch up in the next interval
	p.sample(r7Range(&live), t0.Add(2*time.Second))
	if got := p.upTotal.Load(); got != 300 {
		t.Fatalf("want 300 (no double count), got %d", got)
	}
}

// Review 7 OPT-1: provider nodes are classified from a table built once per classes generation.
func TestR7OPT1ProviderTableRebuiltPerGeneration(t *testing.T) {
	p := newProxyTraffic()
	p.classes["x"] = true
	p.provTable = map[string]bool{"stale": false}
	_ = p.leafIsProxy(&statistic.TrackerInfo{Chain: C.Chain{"y"}})
	if p.provTable == nil {
		t.Fatal("table must survive within a generation")
	}
	p.resetClasses()
	_ = p.leafIsProxy(&statistic.TrackerInfo{Chain: C.Chain{"DIRECT"}})
	if p.provTable != nil {
		t.Fatal("a new classes generation must drop the provider table")
	}
	// Live classify with no core: unknown leaf builds an (empty) table once and counts as a proxy.
	if !p.classifyLive("香港 01") || p.provTable == nil {
		t.Fatal("unknown leaf: proxy, table built")
	}
	if p.classifyLive("DIRECT") {
		t.Fatal("DIRECT is never a proxy")
	}
}
