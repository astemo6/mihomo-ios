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
//   - review 7 P2-1: a connection that opened AND closed between two samples is never seen by Range. Its bytes
//     are still in the manager's global totals, so each sample also reads those totals: the part of their
//     growth that no seen tracker explains (the "residual") belongs to such short connections. It is split
//     between proxy and direct by the proxy share of the bytes seen in the same interval (lifetime share when
//     the interval saw nothing; all proxy when nothing was ever seen). Bytes a tracker read ahead of the
//     totals read are carried as a negative residual, so over time the split adds up exactly to the totals.
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
	// uncounted: the core does not push this tracker into its totals (dialer-proxy inner legs / DNS dialers).
	// Inverted on purpose so an entry made elsewhere with the zero value (e.g. a start-time seed) is counted.
	uncounted bool
	seen      uint32
	// P0-2 stats recorder: the connection's final policy (chains.last) and host, filled once (meta).
	policy, host string
	meta         bool
}

func (e *ptEntry) fillMeta(info *statistic.TrackerInfo) {
	if !e.meta {
		e.policy, e.host, e.meta = statsPolicy(info), statsHostName(info.Metadata), true
	}
}

type proxyTraffic struct {
	mu      sync.Mutex
	entries map[*statistic.TrackerInfo]*ptEntry
	classes map[string]bool // leaf name → is a proxy
	// provTable (review 7 OPT-1): provider node name → is a proxy, built once per classes generation on the
	// first leaf that is not a top-level proxy, instead of walking every provider for each unknown leaf.
	provTable map[string]bool
	epoch     uint32
	last      time.Time

	upTotal, downTotal atomic.Int64
	upRate, downRate   atomic.Int64

	stop chan struct{}
	// classify is replaceable in tests (no running core there).
	classify func(leaf string) bool

	// P2-1 residual accounting. totals reads the manager's global counters (nil in unit tests that do not
	// test the residual: other tests' trackers push into the same global manager).
	totals             func() (up, down int64)
	haveTot            bool
	totUp, totDown     int64 // manager totals at the last sample
	carryUp, carryDown int64 // <= 0: bytes seen trackers counted ahead of the totals read
	seenProxy, seenAll int64 // lifetime bytes of seen counted trackers (for the share fallback)

	// rec (P0-2) records connections, hits, per-policy / per-host bytes and the speed history from this same
	// pass. nil in unit tests that only test the accounting.
	rec *statsRecorder
}

var proxyTrafficStats = newLiveProxyTraffic()

func newLiveProxyTraffic() *proxyTraffic {
	p := newProxyTraffic()
	p.totals = statistic.DefaultManager.Total
	p.rec = statsRec
	return p
}

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
	if p.provTable == nil {
		t := map[string]bool{}
		for _, pv := range tunnel.Providers() {
			for _, px := range pv.Proxies() {
				if _, dup := t[px.Name()]; !dup { // first provider wins, like the old walk
					t[px.Name()] = !nonProxyType(px.Type())
				}
			}
		}
		p.provTable = t
	}
	if v, ok := p.provTable[leaf]; ok {
		return v
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
	if len(p.classes) == 0 {
		p.provTable = nil // new classes generation (start / reload / overflow): providers may have changed
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
	if p.last.IsZero() {
		p.haveTot = false // fresh start: the totals baseline is taken in this sample
	}
	rec := p.rec
	if rec != nil {
		rec.mu.Lock() // lock order: p.mu, then rec.mu (rec never takes p.mu)
		defer rec.mu.Unlock()
	}
	var tu, td int64
	if p.totals != nil {
		tu, td = p.totals() // before the trackers: their counters may only be ahead of this read, never behind
	}
	var dUp, dDown int64     // proxy bytes
	var allUp, allDown int64 // bytes of every counted tracker (proxy + direct)
	add := func(info *statistic.TrackerInfo, e *ptEntry) {
		u, d := info.UploadTotal.Load(), info.DownloadTotal.Load()
		var du, dd int64
		if u > e.up {
			du = u - e.up
		}
		if d > e.down {
			dd = d - e.down
		}
		e.up, e.down = u, d
		if !e.uncounted {
			allUp += du
			allDown += dd
			if rec != nil && (du > 0 || dd > 0) {
				e.fillMeta(info)
				rec.bytesLocked(e.policy, e.host, du, dd)
			}
		}
		if e.proxy {
			dUp += du
			dDown += dd
		}
	}
	rangeTrackers(func(t statistic.Tracker) bool {
		info := t.Info()
		if info == nil {
			return true
		}
		e := p.entries[info]
		if e == nil {
			e = &ptEntry{}
			e.uncounted = !pushesToManager(t)
			e.proxy = !e.uncounted && p.leafIsProxy(info)
			p.entries[info] = e
			if rec != nil {
				e.fillMeta(info)
				rec.openedLocked(info, e.policy)
			}
		}
		e.seen = p.epoch
		add(info, e)
		return true
	})
	for info, e := range p.entries {
		if e.seen == p.epoch {
			continue
		}
		// Closed since the last sample: its counters are final now.
		add(info, e)
		if rec != nil {
			rec.closedLocked(info, now)
		}
		delete(p.entries, info)
	}
	allRU, allRD := allUp, allDown // all-scope bytes this interval (the manager's totals when known)
	if p.totals != nil {
		if p.haveTot {
			allRU, allRD = tu-p.totUp, td-p.totDown
			ru := (tu - p.totUp) - allUp + p.carryUp
			rd := (td - p.totDown) - allDown + p.carryDown
			p.carryUp, p.carryDown = min(ru, 0), min(rd, 0)
			dUp += p.proxyShare(max(ru, 0), dUp, allUp)
			dDown += p.proxyShare(max(rd, 0), dDown, allDown)
		} else {
			p.carryUp, p.carryDown = 0, 0
		}
		p.totUp, p.totDown, p.haveTot = tu, td, true
	}
	p.upTotal.Add(dUp)
	p.downTotal.Add(dDown)
	if !p.last.IsZero() {
		if dt := now.Sub(p.last).Seconds(); dt > 0.2 {
			p.upRate.Store(int64(float64(dUp) / dt))
			p.downRate.Store(int64(float64(dDown) / dt))
			if rec != nil {
				rate := func(n int64) int64 { return int64(float64(max(n, 0)) / dt) }
				rec.speedLocked(now, rate(allRU), rate(allRD), rate(dUp), rate(dDown))
			}
		}
	}
	p.last = now
}

// proxyShare is the proxy part of residual bytes r, given the proxy / all bytes the seen trackers moved in the
// same interval (and the lifetime split when the interval saw nothing). Also updates the lifetime split.
func (p *proxyTraffic) proxyShare(r, proxy, all int64) int64 {
	p.seenProxy += proxy
	p.seenAll += all
	if r <= 0 {
		return 0
	}
	switch {
	case all > 0:
		return int64(float64(r) * float64(proxy) / float64(all))
	case p.seenAll > 0:
		return int64(float64(r) * float64(p.seenProxy) / float64(p.seenAll))
	}
	return r // nothing seen yet: short connections are the only traffic; "仅代理" assumes they are proxied
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
