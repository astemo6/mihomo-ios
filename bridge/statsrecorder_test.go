package libmihomo

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

// P0-2: the tunnel records the session stats the App used to sample only while it was open.

func TestStatsRecorderThroughSample(t *testing.T) {
	p := newProxyTraffic()
	p.classify = func(leaf string) bool { return !builtinNonProxy[leaf] }
	rec := newStatsRecorder()
	p.rec = rec

	a, _ := newTestTracker(t, C.Chain{"香港 01", "Proxy"}, true)
	a.Info().Metadata.Host = "a.example.com"
	a.Info().Metadata.DstPort = 443
	a.Info().Rule, a.Info().RulePayload = "DomainSuffix", "example.com"
	b, _ := newTestTracker(t, C.Chain{"DIRECT"}, true)
	b.Info().Metadata.DstIP = netip.MustParseAddr("1.2.3.4")
	b.Info().Rule = "Match"
	inner, _ := newTestTracker(t, C.Chain{"香港 01"}, false) // not in the core's totals: no bytes, still listed
	inner.Info().Metadata.Host = "inner.example"

	live := []statistic.Tracker{a, b, inner}
	rng := func(f func(statistic.Tracker) bool) {
		for _, tr := range live {
			if !f(tr) {
				return
			}
		}
	}
	t0 := time.Unix(1_700_000_000, 0)
	if _, err := a.(net.Conn).Write([]byte(strings.Repeat("x", 500))); err != nil {
		t.Fatal(err)
	}
	b.Info().DownloadTotal.Add(10_000)
	inner.Info().DownloadTotal.Add(99_999)
	p.sample(rng, t0)
	a.Info().DownloadTotal.Add(4_000)
	p.sample(rng, t0.Add(time.Second))
	a.Info().DownloadTotal.Add(1_000) // moved between the last sample and the close
	live = []statistic.Tracker{b, inner}
	p.sample(rng, t0.Add(2*time.Second))

	s := rec.snapshot(0, 0, 0, 0)
	if s.TotalConnections != 3 {
		t.Fatalf("totalConnections %d, want 3", s.TotalConnections)
	}
	pol := map[string]statsNameBytes{}
	for _, x := range s.Policies {
		pol[x.Name] = x
	}
	if x := pol["Proxy"]; x.Up != 500 || x.Down != 5_000 {
		t.Fatalf("Proxy policy %+v, want 500/5000", x)
	}
	if x := pol["DIRECT"]; x.Down != 10_000 {
		t.Fatalf("DIRECT policy %+v, want down 10000", x)
	}
	if _, ok := pol["香港 01"]; ok {
		t.Fatalf("uncounted inner leg must not add bytes: %+v", s.Policies)
	}
	hosts := map[string]statsNameBytes{}
	for _, x := range s.Hosts {
		hosts[x.Name] = x
	}
	if hosts["a.example.com"].Down != 5_000 || hosts["1.2.3.4"].Down != 10_000 || len(hosts) != 2 {
		t.Fatalf("hosts %+v", s.Hosts)
	}
	rules := map[string]int64{}
	for _, r := range s.Rules {
		rules[r.Rule+"|"+r.Policy] = r.Hits
	}
	if rules["DomainSuffix(example.com)|Proxy"] != 1 || rules["Match|DIRECT"] != 1 || rules["—|香港 01"] != 1 {
		t.Fatalf("rules %+v", s.Rules)
	}
	if len(s.Closed) != 1 || s.ClosedSeq != 1 || !s.Full {
		t.Fatalf("closed %+v seq %d full %v", s.Closed, s.ClosedSeq, s.Full)
	}
	c := s.Closed[0]
	if c.ID != a.ID() || c.Upload != 500 || c.Download != 5_000 || c.Metadata.Host != "a.example.com" ||
		c.Metadata.DestinationPort != "443" || c.Rule != "DomainSuffix" || c.RulePayload != "example.com" ||
		len(c.Chains) != 2 || c.Chains[1] != "Proxy" || c.ClosedAt != t0.Add(2*time.Second).UnixMilli() || c.Start == "" {
		t.Fatalf("closed item %+v", c)
	}
	var sb strings.Builder
	if err := writeAppStats(&sb, &s); err != nil {
		t.Fatal(err)
	}
	var back AppStats
	if err := json.Unmarshal([]byte(sb.String()), &back); err != nil {
		t.Fatalf("streamed /app/stats is not valid JSON: %v\n%s", err, sb.String())
	}
	if back.TotalConnections != 3 || len(back.Closed) != 1 || back.Closed[0].ID != a.ID() || len(back.Hosts) != 2 || !back.Full {
		t.Fatalf("round trip: %+v", back)
	}
	// The JSON must decode as the App's ConnectionItem: start is RFC 3339 like mihomo's own /connections.
	if _, err := time.Parse(time.RFC3339Nano, c.Start); err != nil {
		t.Fatalf("start %q: %v", c.Start, err)
	}
	sp := rec.speedHistory(0, true)
	if len(sp.Seconds) != 2 || sp.At != t0.Unix()+2 {
		t.Fatalf("speed seconds %+v at %d", sp.Seconds, sp.At)
	}
	// Second 1: proxy 4000 B/s down, all (seen trackers, no totals func in this test) 4000.
	if pt := sp.Seconds[0]; pt[2] != 4_000 || pt[4] != 4_000 {
		t.Fatalf("speed point %+v", pt)
	}
	if len(sp.Minutes) != 1 || sp.Minutes[0][5] != 2 || len(sp.Hours) != 1 {
		t.Fatalf("buckets %+v %+v", sp.Minutes, sp.Hours)
	}
}

func TestStatsRecorderIncrementalClosed(t *testing.T) {
	r := newStatsRecorder()
	now := time.Unix(1_700_000_000, 0)
	r.mu.Lock()
	for i := 0; i < 3; i++ {
		r.closedLocked(fakeInfo(i, 20), now)
	}
	r.mu.Unlock()
	s := r.snapshot(0, 0, 0, 0)
	if !s.Full || len(s.Closed) != 3 || s.Closed[0].Seq != 3 {
		t.Fatalf("first read: full %v n %d", s.Full, len(s.Closed))
	}
	s2 := r.snapshot(s.ClosedSeq, s.Session, 0, 0)
	if s2.Full || len(s2.Closed) != 0 {
		t.Fatalf("nothing new: full %v n %d", s2.Full, len(s2.Closed))
	}
	r.mu.Lock()
	r.closedLocked(fakeInfo(9, 20), now)
	r.mu.Unlock()
	s3 := r.snapshot(s.ClosedSeq, s.Session, 0, 0)
	if s3.Full || len(s3.Closed) != 1 || s3.Closed[0].Seq != 4 {
		t.Fatalf("one new: full %v %+v", s3.Full, s3.Closed)
	}
	// A seq that already left the ring gets the whole ring.
	r.mu.Lock()
	for i := 0; i < statsClosedCap+10; i++ {
		r.closedLocked(fakeInfo(i, 20), now)
	}
	r.mu.Unlock()
	s4 := r.snapshot(s3.ClosedSeq, s.Session, 0, 0)
	if !s4.Full || len(s4.Closed) != statsClosedCap {
		t.Fatalf("overrun: full %v n %d", s4.Full, len(s4.Closed))
	}
	// Reset: new session, the old session's seq gets a full (empty) answer.
	r.reset()
	s5 := r.snapshot(s4.ClosedSeq, s.Session, 0, 0)
	if !s5.Full || len(s5.Closed) != 0 || s5.Session == s.Session || s5.TotalConnections != 0 {
		t.Fatalf("after reset: %+v", s5)
	}
}

func TestStatsLRUEvictsOldest(t *testing.T) {
	l := newLRU[upDown](3)
	for _, k := range []string{"a", "b", "c"} {
		l.touch(k).Up = 1
	}
	l.touch("a").Up++ // a is now the newest; b the oldest
	l.touch("d")
	if l.len() != 3 {
		t.Fatalf("len %d", l.len())
	}
	var order []string
	l.each(func(k string, v *upDown) { order = append(order, k) })
	if strings.Join(order, ",") != "c,a,d" {
		t.Fatalf("order %v", order)
	}
	if v := l.touch("a"); v.Up != 2 {
		t.Fatalf("a kept its value: %+v", v)
	}
	if v := l.touch("b"); v.Up != 0 {
		t.Fatalf("b was evicted, must come back empty: %+v", v)
	}
}

func TestStatsSpeedRingsKeepTheirWindows(t *testing.T) {
	r := newStatsRecorder()
	t0 := time.Unix(1_700_000_000, 0)
	r.mu.Lock()
	for i := 0; i < 50*3600; i++ { // 50 h of seconds
		r.speedLocked(t0.Add(time.Duration(i)*time.Second), 1, 2, 3, 4)
	}
	r.mu.Unlock()
	h := r.speedHistory(0, true)
	if len(h.Seconds) != statsSecCap || len(h.Minutes) != statsMinCap || len(h.Hours) != statsHourCap {
		t.Fatalf("windows %d/%d/%d", len(h.Seconds), len(h.Minutes), len(h.Hours))
	}
	last := t0.Unix() + 50*3600 - 1
	if h.At != last || h.Seconds[len(h.Seconds)-1][0] != last || h.Seconds[0][0] != last-statsSecCap+1 {
		t.Fatalf("seconds window %d..%d at %d", h.Seconds[0][0], h.Seconds[len(h.Seconds)-1][0], h.At)
	}
	if m := h.Minutes[len(h.Minutes)-2]; m[5] != 60 || m[2] != 120 {
		t.Fatalf("full minute bucket %+v", m)
	}
	if hr := h.Hours[len(h.Hours)-2]; hr[5] != 3600 {
		t.Fatalf("full hour bucket %+v", hr)
	}
	if got := r.speedHistory(60, false); len(got.Seconds) != 60 || len(got.Minutes) != 0 {
		t.Fatalf("seconds=60&buckets=0: %d / %d", len(got.Seconds), len(got.Minutes))
	}
}

func TestStatsPersistAndResume(t *testing.T) {
	home := t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }

	r := newStatsRecorder()
	r.now = clock
	r.begin(home)
	r.mu.Lock()
	r.openedLocked(fakeInfo(1, 20), "Proxy")
	r.bytesLocked("Proxy", "a.example.com", 100, 2_000)
	r.closedLocked(fakeInfo(1, 20), now)
	r.speedLocked(now.Add(-5*time.Second), 10, 20, 5, 6)
	session := r.session
	r.mu.Unlock()
	r.save(false) // the 60 s saver
	r.end("", false)

	// Killed (no clean stop), restarted 2 min later: counters resume.
	now = now.Add(2 * time.Minute)
	r2 := newStatsRecorder()
	r2.now = clock
	r2.begin(home)
	s := r2.snapshot(0, 0, 0, 0)
	if s.Session != session || s.TotalConnections != 1 || len(s.Closed) != 1 || s.ClosedSeq != 1 ||
		len(s.Hosts) != 1 || s.Hosts[0].Down != 2_000 || len(s.Rules) != 1 {
		t.Fatalf("resume: %+v", s)
	}
	if sp := r2.speedHistory(0, true); len(sp.Minutes) != 1 || len(sp.Seconds) != 1 {
		t.Fatalf("speed restored: %+v", sp)
	}
	// Clean stop: the next start begins from zero, the speed history stays (within its windows).
	r2.end(home, true)
	now = now.Add(time.Minute)
	r3 := newStatsRecorder()
	r3.now = clock
	r3.begin(home)
	s3 := r3.snapshot(0, 0, 0, 0)
	if s3.TotalConnections != 0 || len(s3.Closed) != 0 || len(s3.Hosts) != 0 || s3.Session == session {
		t.Fatalf("after clean stop: %+v", s3)
	}
	sp := r3.speedHistory(0, true)
	if len(sp.Seconds) != 1 || len(sp.Minutes) != 1 || len(sp.Hours) != 1 { // the point is ~3 min old: inside every window
		t.Fatalf("speed after clean stop: %+v", sp)
	}
	r3.end("", false)

	// Unclean but saved too long ago: from zero.
	r4 := newStatsRecorder()
	r4.now = clock
	r4.begin(home)
	r4.mu.Lock()
	r4.openedLocked(fakeInfo(2, 20), "X")
	r4.mu.Unlock()
	r4.save(false)
	r4.end("", false)
	now = now.Add(statsResumeWindow + time.Minute)
	r5 := newStatsRecorder()
	r5.now = clock
	r5.begin(home)
	if s := r5.snapshot(0, 0, 0, 0); s.TotalConnections != 0 {
		t.Fatalf("stale file resumed: %+v", s)
	}
	r5.end("", false)

	// A damaged file is ignored.
	_ = os.WriteFile(filepath.Join(home, statsFile), []byte("{nope"), 0o644)
	r6 := newStatsRecorder()
	r6.begin(home)
	if s := r6.snapshot(0, 0, 0, 0); s.TotalConnections != 0 {
		t.Fatalf("damaged file: %+v", s)
	}
	r6.end("", false)
}

// fakeInfo builds a closed tracker's info with strings of about n bytes each.
func fakeInfo(i, n int) *statistic.TrackerInfo {
	pad := func(s string) string {
		if len(s) < n {
			s += strings.Repeat("x", n-len(s))
		}
		return s
	}
	info := &statistic.TrackerInfo{
		Metadata: &C.Metadata{NetWork: C.TCP, Type: C.TUN, Host: pad(fmt.Sprintf("h%d.", i)),
			SniffHost: pad(fmt.Sprintf("s%d.", i)), Process: pad("p"), RemoteDst: pad("r"),
			SrcIP: netip.MustParseAddr("198.18.0.1"), DstIP: netip.MustParseAddr("203.0.113.9"), SrcPort: 51000, DstPort: 443},
		Start: time.Unix(1_700_000_000, 0), Rule: pad("DomainSuffix"), RulePayload: pad(fmt.Sprintf("p%d", i)),
	}
	for k := 0; k < 12; k++ { // more hops than statsChainMax
		info.Chain = append(info.Chain, pad(fmt.Sprintf("hop%d-", k)))
	}
	info.UploadTotal.Store(int64(i))
	info.DownloadTotal.Store(int64(i * 3))
	return info
}

func heapInUse() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// fillStats fills every table of r to (and past) its cap with strings of strLen bytes, `rounds` times over, so
// the LRU tables and the ring evict and reuse.
func fillStats(r *statsRecorder, strLen, rounds int) {
	now := time.Unix(1_700_000_000, 0)
	pad := func(s string) string {
		if len(s) < strLen {
			s += strings.Repeat("y", strLen-len(s))
		}
		return s
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for round := 0; round < rounds; round++ {
		for i := 0; i < statsHostCap; i++ {
			r.bytesLocked(pad(fmt.Sprintf("pol%d-%d-", round, i%(statsPolicyCap+40))), pad(fmt.Sprintf("host%d-%d-", round, i)), 1, 1)
		}
		for i := 0; i < statsRuleCap; i++ {
			info := fakeInfo(round*statsRuleCap+i, strLen)
			r.openedLocked(info, pad(fmt.Sprintf("pol%d-", i)))
		}
		for i := 0; i < statsClosedCap; i++ {
			r.closedLocked(fakeInfo(round*statsClosedCap+i, strLen), now)
		}
	}
	for i := 0; i < 50*3600; i++ {
		r.speedLocked(now.Add(time.Duration(i)*time.Second), 1, 2, 3, 4)
	}
}

// TestStatsRecorderMemoryBound: every table filled to its cap (and churned past it) stays within a fixed heap
// budget, and the 60 s save / the REST answers allocate a bounded amount. Numbers are logged for the report.
// The extension runs with GOMEMLIMIT 26 MB inside a ~50 MB jetsam budget.
func TestStatsRecorderMemoryBound(t *testing.T) {
	for _, tc := range []struct {
		name          string
		strLen        int
		retainedLimit uint64
		encodeLimit   uint64
	}{
		{"realistic-32B-strings", 32, 2 << 20, 2 << 20},
		{"worst-case-256B-strings", 256, 8 << 20, 4 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := heapInUse()
			r := newStatsRecorder()
			fillStats(r, tc.strLen, 1)
			afterOne := heapInUse()
			fillStats(r, tc.strLen, 5) // 5 more rounds of evictions / slot reuse
			afterChurn := heapInUse()
			r.mu.Lock()
			hosts, rules, pols, closed := r.hosts.len(), r.rules.len(), r.policies.len(), r.closedN
			r.mu.Unlock()
			if hosts != statsHostCap || rules != statsRuleCap || pols != statsPolicyCap || closed != statsClosedCap {
				t.Fatalf("caps: hosts %d rules %d policies %d closed %d", hosts, rules, pols, closed)
			}
			retained := afterOne - base
			if afterOne < base {
				retained = 0
			}
			churned := int64(afterChurn) - int64(afterOne)

			var m0, m1 runtime.MemStats
			runtime.ReadMemStats(&m0)
			var cw statsCountWriter
			r.mu.Lock()
			err := r.encodeLocked(&cw, false)
			r.mu.Unlock()
			runtime.ReadMemStats(&m1)
			if err != nil {
				t.Fatal(err)
			}
			encodeAlloc := m1.TotalAlloc - m0.TotalAlloc
			fileSize := cw.n

			runtime.ReadMemStats(&m0)
			s := r.snapshot(0, 0, 600, 300)
			var pw statsCountWriter
			_ = writeAppStats(&pw, &s)
			runtime.ReadMemStats(&m1)
			pollAlloc := m1.TotalAlloc - m0.TotalAlloc
			pollSize := pw.n
			// The steady poll: nothing new closed since the App's last answer.
			runtime.ReadMemStats(&m0)
			s2 := r.snapshot(s.ClosedSeq, s.Session, 600, 300)
			var sw statsCountWriter
			_ = writeAppStats(&sw, &s2)
			runtime.ReadMemStats(&m1)
			steadyAlloc := m1.TotalAlloc - m0.TotalAlloc
			steadySize := sw.n

			runtime.ReadMemStats(&m0)
			sp, _ := json.Marshal(r.speedHistory(0, true))
			runtime.ReadMemStats(&m1)
			speedAlloc := m1.TotalAlloc - m0.TotalAlloc

			// Restore (Start after an unclean end) from the full file, token by token.
			home := t.TempDir()
			r.mu.Lock()
			r.home = home
			r.now = func() time.Time { return time.Unix(1_700_000_000+50*3600, 0) }
			r.mu.Unlock()
			r.save(false)
			r2 := newStatsRecorder()
			r2.now = func() time.Time { return time.Unix(1_700_000_000+50*3600, 0) }
			runtime.ReadMemStats(&m0)
			r2.mu.Lock()
			resumed := r2.restoreLocked(home, r2.now())
			r2.mu.Unlock()
			runtime.ReadMemStats(&m1)
			restoreAlloc := m1.TotalAlloc - m0.TotalAlloc
			if !resumed || r2.hosts.len() != statsHostCap || r2.closedN != statsClosedCap || r2.rules.len() != statsRuleCap {
				t.Fatalf("restore: resumed %v hosts %d closed %d rules %d", resumed, r2.hosts.len(), r2.closedN, r2.rules.len())
			}
			t.Logf("restore from the full file: allocated %.2f MB (includes the restored tables themselves)", float64(restoreAlloc)/(1<<20))

			t.Logf("retained heap at caps: %.2f MB (limit %.0f MB); after 5 more churn rounds: %+.2f MB",
				float64(retained)/(1<<20), float64(tc.retainedLimit)/(1<<20), float64(churned)/(1<<20))
			t.Logf("save: file %.0f KB, allocated %.2f MB (limit %.0f MB); first /app/stats?hosts=600&rules=300 (500 closed): %.0f KB, allocated %.2f MB; steady poll: %.0f KB, allocated %.2f MB; /app/stats/speed: %.0f KB, allocated %.2f MB",
				float64(fileSize)/1024, float64(encodeAlloc)/(1<<20), float64(tc.encodeLimit)/(1<<20),
				float64(pollSize)/1024, float64(pollAlloc)/(1<<20), float64(steadySize)/1024, float64(steadyAlloc)/(1<<20), float64(len(sp))/1024, float64(speedAlloc)/(1<<20))
			if retained > tc.retainedLimit {
				t.Fatalf("retained %d B > %d", retained, tc.retainedLimit)
			}
			if churned > int64(512<<10) {
				t.Fatalf("heap grew %d B under churn: a table is not bounded", churned)
			}
			if encodeAlloc > tc.encodeLimit {
				t.Fatalf("save allocated %d B > %d", encodeAlloc, tc.encodeLimit)
			}
			runtime.KeepAlive(r)
		})
	}
}

type statsCountWriter struct{ n int }

func (w *statsCountWriter) Write(p []byte) (int, error) { w.n += len(p); return len(p), nil }
