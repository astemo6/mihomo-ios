package libmihomo

// feat/traffic-scope (user 2026-10-21 「首页的流量是显示走代理的还是全部的 做个选项」): proxy-only traffic.
//
// mihomo's statistic manager only keeps one global up/down counter (everything the core relays, DIRECT
// included). The manager is a concrete type with no hook, so instead of forking the core we sample its
// trackers once a second inside the tunnel:
//
//   - every live tracker is classified once, when first seen: it is "proxy" when its chain's leaf (Chain[0],
//     the outbound that actually carried it) is a real proxy node, not DIRECT / REJECT / REJECT-DROP / PASS /
//     COMPATIBLE (looked up by adapter type, so a profile node of `type: direct` also counts as direct);
//   - trackers the core does not push into its global totals (dialer-proxy inner legs, DNS dialers) are
//     skipped exactly like the manager skips them, so "all" and "proxy" never double count;
//   - for proxy trackers we add the growth of the tracker's own byte counters since the last sample;
//   - a tracker that disappeared (connection closed) is read one last time through the *TrackerInfo we
//     kept, so the bytes it moved between the last sample and its close are counted too. The pointer is
//     dropped right after, so nothing is held past one sample.
//
// Memory: one small entry per LIVE connection (the core already holds far more for each), plus a name →
// class cache bounded by the profile's node count. No per-connection history, no allocation per byte.

import (
	"encoding/json"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/chi"
	mhttp "github.com/metacubex/http"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/route"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

type ptEntry struct {
	up, down int64 // counters at the last sample
	proxy    bool
	seen     uint32
}

type proxyTraffic struct {
	mu      sync.Mutex
	entries map[*statistic.TrackerInfo]*ptEntry
	classes map[string]bool // leaf name → is a proxy
	epoch   uint32
	last    time.Time

	upTotal, downTotal atomic.Int64
	upRate, downRate   atomic.Int64

	stop chan struct{}
	// classify is replaceable in tests (no running core there).
	classify func(leaf string) bool
}

var proxyTrafficStats = newProxyTraffic()

func newProxyTraffic() *proxyTraffic {
	p := &proxyTraffic{entries: map[*statistic.TrackerInfo]*ptEntry{}, classes: map[string]bool{}}
	p.classify = p.classifyLive
	return p
}

// builtinNonProxy are mihomo's built-in outbounds that never leave through a proxy node.
var builtinNonProxy = map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "COMPATIBLE": true}

func nonProxyType(t C.AdapterType) bool {
	switch t {
	case C.Direct, C.Reject, C.RejectDrop, C.Pass, C.Compatible, C.Dns:
		return true
	}
	return false
}

// classifyLive: true when leaf is a node that sends traffic out through a proxy.
func (p *proxyTraffic) classifyLive(leaf string) (proxy bool) {
	if leaf == "" || builtinNonProxy[leaf] {
		return false
	}
	defer func() {
		if recover() != nil {
			proxy = true
		}
	}()
	if px, ok := tunnel.Proxies()[leaf]; ok {
		return !nonProxyType(px.Type())
	}
	for _, pv := range tunnel.Providers() {
		for _, px := range pv.Proxies() {
			if px.Name() == leaf {
				return !nonProxyType(px.Type())
			}
		}
	}
	return true // an unknown leaf that is not a built-in is a node the core dialled
}

// pushesToManager reports whether the core adds this tracker's bytes to its global totals (the
// unexported pushToManager field on mihomo's tcp/udp trackers). Read through reflection, read-only.
func pushesToManager(t statistic.Tracker) bool {
	v := reflect.ValueOf(t)
	for v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return true
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return true
	}
	f := v.FieldByName("pushToManager")
	if !f.IsValid() || f.Kind() != reflect.Bool {
		return true
	}
	return f.Bool()
}

func (p *proxyTraffic) leafIsProxy(info *statistic.TrackerInfo) bool {
	if info == nil || len(info.Chain) == 0 {
		return false
	}
	leaf := info.Chain[0]
	if v, ok := p.classes[leaf]; ok {
		return v
	}
	v := p.classify(leaf)
	if len(p.classes) > 4096 {
		p.classes = map[string]bool{}
	}
	p.classes[leaf] = v
	return v
}

// sample runs one accounting pass over trackers (the manager's in production). now is the sample time.
func (p *proxyTraffic) sample(rangeTrackers func(func(statistic.Tracker) bool), now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.epoch++
	var dUp, dDown int64
	rangeTrackers(func(t statistic.Tracker) bool {
		info := t.Info()
		if info == nil {
			return true
		}
		e := p.entries[info]
		if e == nil {
			e = &ptEntry{}
			e.proxy = pushesToManager(t) && p.leafIsProxy(info)
			p.entries[info] = e
		}
		e.seen = p.epoch
		if e.proxy {
			u, d := info.UploadTotal.Load(), info.DownloadTotal.Load()
			if u > e.up {
				dUp += u - e.up
			}
			if d > e.down {
				dDown += d - e.down
			}
			e.up, e.down = u, d
		}
		return true
	})
	for info, e := range p.entries {
		if e.seen == p.epoch {
			continue
		}
		// Closed since the last sample: its counters are final now.
		if e.proxy {
			u, d := info.UploadTotal.Load(), info.DownloadTotal.Load()
			if u > e.up {
				dUp += u - e.up
			}
			if d > e.down {
				dDown += d - e.down
			}
		}
		delete(p.entries, info)
	}
	p.upTotal.Add(dUp)
	p.downTotal.Add(dDown)
	if !p.last.IsZero() {
		if dt := now.Sub(p.last).Seconds(); dt > 0.2 {
			p.upRate.Store(int64(float64(dUp) / dt))
			p.downRate.Store(int64(float64(dDown) / dt))
		}
	}
	p.last = now
}

func managerRange(f func(statistic.Tracker) bool) { statistic.DefaultManager.Range(f) }

// start resets the counters and samples once a second until stopRunning. Called from Start.
func (p *proxyTraffic) start() {
	p.stopRunning()
	p.mu.Lock()
	p.entries = map[*statistic.TrackerInfo]*ptEntry{}
	p.classes = map[string]bool{}
	p.last = time.Time{}
	p.upTotal.Store(0)
	p.downTotal.Store(0)
	p.upRate.Store(0)
	p.downRate.Store(0)
	stop := make(chan struct{})
	p.stop = stop
	p.mu.Unlock()
	// r7: connections still open from a previous run in this process (stop → start without the
	// extension exiting) start counting from now: seed them with their current counters, otherwise
	// their whole lifetime bytes landed in the first sample at once.
	p.seed(managerRange)
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case now := <-t.C:
				p.sample(managerRange, now)
			}
		}
	}()
}

// seed records every live tracker at its current counters without counting anything.
func (p *proxyTraffic) seed(rangeTrackers func(func(statistic.Tracker) bool)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	rangeTrackers(func(t statistic.Tracker) bool {
		info := t.Info()
		if info == nil {
			return true
		}
		if _, ok := p.entries[info]; !ok {
			p.entries[info] = &ptEntry{proxy: pushesToManager(t) && p.leafIsProxy(info),
				up: info.UploadTotal.Load(), down: info.DownloadTotal.Load(), seen: p.epoch}
		}
		return true
	})
}

// stopRunning ends the sampler (counters keep their last values for a final read).
func (p *proxyTraffic) stopRunning() {
	p.mu.Lock()
	if p.stop != nil {
		close(p.stop)
		p.stop = nil
	}
	p.upRate.Store(0)
	p.downRate.Store(0)
	p.mu.Unlock()
}

// resetClasses forgets leaf classifications (a reload can change what a node name means).
func (p *proxyTraffic) resetClasses() {
	p.mu.Lock()
	p.classes = map[string]bool{}
	p.mu.Unlock()
}

// AppTraffic is GET /app/traffic: every counter Home can show, both scopes.
type AppTraffic struct {
	Up             int64 `json:"up"`
	Down           int64 `json:"down"`
	UpTotal        int64 `json:"upTotal"`
	DownTotal      int64 `json:"downTotal"`
	ProxyUp        int64 `json:"proxyUp"`
	ProxyDown      int64 `json:"proxyDown"`
	ProxyUpTotal   int64 `json:"proxyUpTotal"`
	ProxyDownTotal int64 `json:"proxyDownTotal"`
}

func currentAppTraffic() AppTraffic {
	up, down := statistic.DefaultManager.Now()
	tu, td := statistic.DefaultManager.Total()
	p := proxyTrafficStats
	return AppTraffic{Up: up, Down: down, UpTotal: tu, DownTotal: td,
		ProxyUp: p.upRate.Load(), ProxyDown: p.downRate.Load(), ProxyUpTotal: p.upTotal.Load(), ProxyDownTotal: p.downTotal.Load()}
}

func appTrafficRoutes(r chi.Router) {
	r.Get("/app/traffic", func(w mhttp.ResponseWriter, req *mhttp.Request) {
		b, _ := json.Marshal(currentAppTraffic())
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(b)
	})
}

func init() { route.Register(appTrafficRoutes) }
