package libmihomo

// P0-2 (user task list 「App 进入后台或被杀后，流量和规则不再被记录」): session statistics recorded inside the tunnel.
//
// Before, Home's connection history (closed connections), rule hits, per-policy / per-host bytes and the 网络
// speed history (秒 / 分钟 / 小时) were all accumulated in the App from its /connections (2 s) and /app/traffic
// (1 s) polls, so nothing was recorded while the App was in the background or killed. The tunnel already looks at
// every tracker once a second (proxytraffic.go); the recorder rides on that same pass:
//
//   - a tracker seen for the first time counts one connection and one hit for its (rule, final policy) pair;
//   - the byte growth of every counted tracker (the ones the core puts in its own totals) is added to its final
//     policy (chains.last, the group the rule chose) and its host (host / sniffed host / destination IP);
//   - a tracker that disappeared is copied into the closed-connection ring with its final counters;
//   - each sample appends one speed point (both scopes) to the 1 s ring and folds it into 1 min / 1 h buckets.
//
// Like the App before it, a connection that opens and closes between two samples is not seen (its bytes are in the
// totals, see proxytraffic.go's residual) — the tunnel samples every second instead of every 2 s, and also in the
// background.
//
// Memory (tunnel jetsam ~50 MB, GOMEMLIMIT 26 MB): every table has a fixed capacity and evicts — no map grows past
// its cap. Closed connections: a 500-slot ring whose slots are reused; hosts 2000, rules 1000 and policies 256 in
// LRU tables (least recently updated evicted); speed 600 + 180 + 48 points in preallocated rings. Stored strings are
// cloned (never pin a larger buffer) and cut at 256 bytes, chains at 8 hops. statsrecorder_test.go fills every table
// to its cap and measures the heap.
//
// Persistence: <home>/tunnel-stats.json every 60 s, on FlushRuleHits (the extension's sleep / flushStats) and on
// Stop. On Start the speed history is always restored (time-stamped, pruned by age). Counters, hits and closed
// connections are restored only when the previous run did not stop cleanly (the extension was killed, e.g. jetsam)
// and saved less than statsResumeWindow ago — a user disconnect still starts the next connect from zero.

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/chi"
	mhttp "github.com/metacubex/http"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/route"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

const (
	statsClosedCap    = 500
	statsHostCap      = 2000
	statsRuleCap      = 1000
	statsPolicyCap    = 256
	statsSecCap       = 600 // 10 min of 1 s points
	statsMinCap       = 180 // 3 h of 1 min buckets
	statsHourCap      = 48  // 48 h of 1 h buckets
	statsStrMax       = 256
	statsChainMax     = 8
	statsFile         = "tunnel-stats.json"
	statsSaveInterval = 60 * time.Second
	statsResumeWindow = 10 * time.Minute
)

// MARK: - fixed-capacity LRU

type lruNode[V any] struct {
	key        string
	val        V
	prev, next int32
}

// lruTable keeps at most cap keys; touching a key moves it to the front, inserting into a full table reuses the
// least recently touched node. The map never holds more than cap keys.
type lruTable[V any] struct {
	cap        int
	idx        map[string]int32
	nodes      []lruNode[V]
	head, tail int32
}

func newLRU[V any](capacity int) *lruTable[V] {
	return &lruTable[V]{cap: capacity, idx: make(map[string]int32), head: -1, tail: -1}
}

func (t *lruTable[V]) len() int { return len(t.idx) }

func (t *lruTable[V]) unlink(i int32) {
	n := &t.nodes[i]
	if n.prev >= 0 {
		t.nodes[n.prev].next = n.next
	} else {
		t.head = n.next
	}
	if n.next >= 0 {
		t.nodes[n.next].prev = n.prev
	} else {
		t.tail = n.prev
	}
	n.prev, n.next = -1, -1
}

func (t *lruTable[V]) pushFront(i int32) {
	n := &t.nodes[i]
	n.prev, n.next = -1, t.head
	if t.head >= 0 {
		t.nodes[t.head].prev = i
	}
	t.head = i
	if t.tail < 0 {
		t.tail = i
	}
}

// touch returns the value for key (inserted zero when missing, evicting the oldest key when full) and marks it
// most recently used. key is cloned on insert.
func (t *lruTable[V]) touch(key string) *V {
	if i, ok := t.idx[key]; ok {
		if t.head != i {
			t.unlink(i)
			t.pushFront(i)
		}
		return &t.nodes[i].val
	}
	var i int32
	if len(t.nodes) < t.cap {
		t.nodes = append(t.nodes, lruNode[V]{prev: -1, next: -1})
		i = int32(len(t.nodes) - 1)
	} else {
		i = t.tail
		t.unlink(i)
		delete(t.idx, t.nodes[i].key)
	}
	var zero V
	t.nodes[i].key, t.nodes[i].val = strings.Clone(key), zero
	t.idx[t.nodes[i].key] = i
	t.pushFront(i)
	return &t.nodes[i].val
}

// each visits keys from least to most recently used (so a restore that touches them in this order keeps the order).
func (t *lruTable[V]) each(f func(key string, v *V)) {
	for i := t.tail; i >= 0; i = t.nodes[i].prev {
		f(t.nodes[i].key, &t.nodes[i].val)
	}
}

func (t *lruTable[V]) reset() {
	t.idx = make(map[string]int32)
	t.nodes = t.nodes[:0:0]
	t.head, t.tail = -1, -1
}

// MARK: - fixed-capacity ring

type ring[T any] struct {
	buf      []T // len == capacity, allocated once
	start, n int
}

func newRing[T any](capacity int) ring[T] { return ring[T]{buf: make([]T, capacity)} }

func (r *ring[T]) push(v T) {
	if r.n < len(r.buf) {
		r.buf[(r.start+r.n)%len(r.buf)] = v
		r.n++
		return
	}
	r.buf[r.start] = v
	r.start = (r.start + 1) % len(r.buf)
}

func (r *ring[T]) last() *T {
	if r.n == 0 {
		return nil
	}
	return &r.buf[(r.start+r.n-1)%len(r.buf)]
}

// at returns the i-th oldest element.
func (r *ring[T]) at(i int) *T { return &r.buf[(r.start+i)%len(r.buf)] }

func (r *ring[T]) clear() {
	var zero T
	for i := range r.buf {
		r.buf[i] = zero
	}
	r.start, r.n = 0, 0
}

// MARK: - records

type upDown struct{ Up, Down int64 }

type ruleHit struct {
	Rule, Policy string
	Hits         int64
}

type speedPoint struct{ T, Up, Down, PUp, PDown int64 }

type speedBucket struct{ Start, Up, Down, PUp, PDown, N int64 }

// closedConn is one closed connection, shaped for the same JSON as mihomo's /connections items.
type closedConn struct {
	Seq                          uint64
	ID                           string
	Network, Type                string
	SrcIP, DstIP                 string
	SrcPort, DstPort             uint16
	Host, Sniff, Process, Remote string
	Chains                       []string
	Rule, Payload                string
	Up, Down                     int64
	Start, Closed                int64 // unix ms
}

// clipFresh: for strings that are already their own allocation (just decoded): cut, clone only when cut.
func clipFresh(s string) string {
	if len(s) > statsStrMax {
		return strings.Clone(s[:statsStrMax])
	}
	return s
}

func clip(s string) string {
	if len(s) > statsStrMax {
		s = s[:statsStrMax]
	}
	return strings.Clone(s)
}

// statsHostName mirrors the App's ConnectionAnalytics.hostName: host, else sniffed host, else destination IP.
func statsHostName(m *C.Metadata) string {
	if m == nil {
		return "?"
	}
	if m.Host != "" {
		return m.Host
	}
	if m.SniffHost != "" {
		return m.SniffHost
	}
	if m.DstIP.IsValid() {
		return m.DstIP.String()
	}
	return "?"
}

// statsPolicy mirrors the App's chains.last ?? "DIRECT".
func statsPolicy(info *statistic.TrackerInfo) string {
	if info == nil || len(info.Chain) == 0 {
		return "DIRECT"
	}
	return info.Chain[len(info.Chain)-1]
}

// statsRuleText mirrors the App's ConnectionItem.ruleText (「—」 when empty).
func statsRuleText(info *statistic.TrackerInfo) string {
	if info == nil || info.Rule == "" {
		return "—"
	}
	if info.RulePayload != "" {
		return info.Rule + "(" + info.RulePayload + ")"
	}
	return info.Rule
}

// MARK: - recorder

type statsRecorder struct {
	mu sync.Mutex

	session int64 // unix ms; changes on every fresh start and on reset
	since   int64 // unix ms the counters start from
	total   int64 // connections seen
	version uint64

	policies *lruTable[upDown]
	hosts    *lruTable[upDown]
	rules    *lruTable[ruleHit]

	closed    [statsClosedCap]closedConn
	closedN   int
	closedPos int // next slot to write
	seq       uint64

	secs  ring[speedPoint]
	mins  ring[speedBucket]
	hours ring[speedBucket]

	home string
	stop chan struct{}
	now  func() time.Time
}

var statsRec = newStatsRecorder()

var statsSessionLast atomic.Int64

// nextStatsSession: a new session id (unix ms), never equal to one handed out before in this process.
func nextStatsSession(now time.Time) int64 {
	for {
		last := statsSessionLast.Load()
		ms := max(now.UnixMilli(), last+1)
		if statsSessionLast.CompareAndSwap(last, ms) {
			return ms
		}
	}
}

func newStatsRecorder() *statsRecorder {
	r := &statsRecorder{
		policies: newLRU[upDown](statsPolicyCap),
		hosts:    newLRU[upDown](statsHostCap),
		rules:    newLRU[ruleHit](statsRuleCap),
		secs:     newRing[speedPoint](statsSecCap),
		mins:     newRing[speedBucket](statsMinCap),
		hours:    newRing[speedBucket](statsHourCap),
		now:      time.Now,
	}
	r.resetCountersLocked(r.now())
	return r
}

func (r *statsRecorder) resetCountersLocked(now time.Time) {
	r.session, r.since, r.total = nextStatsSession(now), now.UnixMilli(), 0
	r.policies.reset()
	r.hosts.reset()
	r.rules.reset()
	for i := range r.closed {
		r.closed[i] = closedConn{}
	}
	r.closedN, r.closedPos, r.seq = 0, 0, 0
	r.version++
}

// opened: a tracker seen for the first time. Caller holds r.mu.
func (r *statsRecorder) openedLocked(info *statistic.TrackerInfo, policy string) {
	r.total++
	rule := statsRuleText(info)
	h := r.rules.touch(rule + "\x01" + policy)
	if h.Hits == 0 {
		h.Rule, h.Policy = clip(rule), clip(policy)
	}
	h.Hits++
	r.version++
}

// bytes: growth of a counted tracker. Caller holds r.mu.
func (r *statsRecorder) bytesLocked(policy, host string, du, dd int64) {
	if du == 0 && dd == 0 {
		return
	}
	p := r.policies.touch(policy)
	p.Up += du
	p.Down += dd
	if len(host) > statsStrMax {
		host = host[:statsStrMax]
	}
	h := r.hosts.touch(host)
	h.Up += du
	h.Down += dd
	r.version++
}

// closedLocked copies a closed tracker into the ring (its slot's chain slice is reused). Caller holds r.mu.
func (r *statsRecorder) closedLocked(info *statistic.TrackerInfo, now time.Time) {
	if info == nil {
		return
	}
	r.seq++
	c := &r.closed[r.closedPos]
	chains := c.Chains[:0]
	for i, s := range info.Chain {
		if i >= statsChainMax {
			break
		}
		chains = append(chains, clip(s))
	}
	*c = closedConn{Seq: r.seq, ID: info.UUID.String(), Chains: chains,
		Rule: clip(info.Rule), Payload: clip(info.RulePayload),
		Up: info.UploadTotal.Load(), Down: info.DownloadTotal.Load(),
		Start: info.Start.UnixMilli(), Closed: now.UnixMilli()}
	if m := info.Metadata; m != nil {
		c.Network, c.Type = m.NetWork.String(), m.Type.String()
		if m.SrcIP.IsValid() {
			c.SrcIP = m.SrcIP.String()
		}
		if m.DstIP.IsValid() {
			c.DstIP = m.DstIP.String()
		}
		c.SrcPort, c.DstPort = m.SrcPort, m.DstPort
		c.Host, c.Sniff, c.Process, c.Remote = clip(m.Host), clip(m.SniffHost), clip(m.Process), clip(m.RemoteDst)
	}
	r.closedPos = (r.closedPos + 1) % statsClosedCap
	if r.closedN < statsClosedCap {
		r.closedN++
	}
	r.version++
}

// speedLocked appends one speed point (bytes per second, both scopes) and folds it into the buckets.
func (r *statsRecorder) speedLocked(now time.Time, up, down, pUp, pDown int64) {
	t := now.Unix()
	if l := r.secs.last(); l != nil && l.T >= t {
		*l = speedPoint{T: l.T, Up: up, Down: down, PUp: pUp, PDown: pDown} // same second (ticker jitter): keep the newest
	} else {
		r.secs.push(speedPoint{T: t, Up: up, Down: down, PUp: pUp, PDown: pDown})
	}
	fold := func(rg *ring[speedBucket], step int64) {
		start := t - t%step
		if l := rg.last(); l != nil && l.Start == start {
			l.Up += up
			l.Down += down
			l.PUp += pUp
			l.PDown += pDown
			l.N++
			return
		}
		if l := rg.last(); l != nil && l.Start > start {
			return // clock went back: never write into the past
		}
		rg.push(speedBucket{Start: start, Up: up, Down: down, PUp: pUp, PDown: pDown, N: 1})
	}
	fold(&r.mins, 60)
	fold(&r.hours, 3600)
}

// MARK: - JSON shapes

type statsMetaJSON struct {
	Network           string `json:"network"`
	Type              string `json:"type"`
	SourceIP          string `json:"sourceIP"`
	DestinationIP     string `json:"destinationIP"`
	SourcePort        string `json:"sourcePort"`
	DestinationPort   string `json:"destinationPort"`
	Host              string `json:"host"`
	SniffHost         string `json:"sniffHost"`
	Process           string `json:"process"`
	RemoteDestination string `json:"remoteDestination"`
}

// statsClosedJSON: mihomo's /connections item fields the App decodes (ConnectionItem), plus seq and closedAt (ms).
type statsClosedJSON struct {
	Seq         uint64        `json:"seq"`
	ID          string        `json:"id"`
	Metadata    statsMetaJSON `json:"metadata"`
	Upload      int64         `json:"upload"`
	Download    int64         `json:"download"`
	Start       string        `json:"start"`
	Chains      []string      `json:"chains"`
	Rule        string        `json:"rule"`
	RulePayload string        `json:"rulePayload"`
	ClosedAt    int64         `json:"closedAt"`
}

func (c *closedConn) toJSON() statsClosedJSON {
	j := statsClosedJSON{Seq: c.Seq, ID: c.ID, Upload: c.Up, Download: c.Down, Chains: c.Chains,
		Rule: c.Rule, RulePayload: c.Payload, ClosedAt: c.Closed,
		Metadata: statsMetaJSON{Network: c.Network, Type: c.Type, SourceIP: c.SrcIP, DestinationIP: c.DstIP,
			Host: c.Host, SniffHost: c.Sniff, Process: c.Process, RemoteDestination: c.Remote}}
	if c.SrcPort != 0 {
		j.Metadata.SourcePort = strconv.Itoa(int(c.SrcPort))
	}
	if c.DstPort != 0 {
		j.Metadata.DestinationPort = strconv.Itoa(int(c.DstPort))
	}
	if j.Chains == nil {
		j.Chains = []string{}
	}
	if c.Start > 0 {
		j.Start = time.UnixMilli(c.Start).Format(time.RFC3339Nano) // the format mihomo's /connections uses
	}
	return j
}

func (j *statsClosedJSON) toConn() closedConn {
	c := closedConn{Seq: j.Seq, ID: clipFresh(j.ID), Up: j.Upload, Down: j.Download, Rule: clipFresh(j.Rule),
		Payload: clipFresh(j.RulePayload), Closed: j.ClosedAt,
		Network: clipFresh(j.Metadata.Network), Type: clipFresh(j.Metadata.Type), SrcIP: clipFresh(j.Metadata.SourceIP),
		DstIP: clipFresh(j.Metadata.DestinationIP), Host: clipFresh(j.Metadata.Host), Sniff: clipFresh(j.Metadata.SniffHost),
		Process: clipFresh(j.Metadata.Process), Remote: clipFresh(j.Metadata.RemoteDestination)}
	if p, err := strconv.Atoi(j.Metadata.SourcePort); err == nil {
		c.SrcPort = uint16(p)
	}
	if p, err := strconv.Atoi(j.Metadata.DestinationPort); err == nil {
		c.DstPort = uint16(p)
	}
	for i, s := range j.Chains {
		if i >= statsChainMax {
			break
		}
		c.Chains = append(c.Chains, clipFresh(s))
	}
	if t, err := time.Parse(time.RFC3339Nano, j.Start); err == nil {
		c.Start = t.UnixMilli()
	}
	return c
}

type statsNameBytes struct {
	Name string `json:"name"`
	Up   int64  `json:"up"`
	Down int64  `json:"down"`
}

type statsRuleJSON struct {
	Rule   string `json:"rule"`
	Policy string `json:"policy"`
	Hits   int64  `json:"hits"`
}

// AppStats is GET /app/stats.
type AppStats struct {
	Session          int64             `json:"session"`
	Since            int64             `json:"since"` // unix ms
	Version          uint64            `json:"version"`
	TotalConnections int64             `json:"totalConnections"`
	Policies         []statsNameBytes  `json:"policies"`
	Rules            []statsRuleJSON   `json:"rules"`
	RuleCount        int               `json:"ruleCount"`
	Hosts            []statsNameBytes  `json:"hosts"`
	HostCount        int               `json:"hostCount"`
	ClosedSeq        uint64            `json:"closedSeq"`
	Closed           []statsClosedJSON `json:"closed"` // seq > closedAfter, newest first
	// Full: Closed holds every recorded closed connection (session changed or closedAfter fell out of the ring).
	Full bool `json:"full"`
}

// AppSpeedHistory is GET /app/stats/speed: [t, up, down, proxyUp, proxyDown] per second (B/s) and
// [start, upSum, downSum, proxyUpSum, proxyDownSum, n] per minute / hour (sums of the 1 s rates, n points).
type AppSpeedHistory struct {
	At      int64      `json:"at"` // unix s of the newest point (0 = none)
	Seconds [][5]int64 `json:"seconds"`
	Minutes [][6]int64 `json:"minutes"`
	Hours   [][6]int64 `json:"hours"`
}

// statsFileJSON is tunnel-stats.json.
type statsFileJSON struct {
	SavedAt  int64             `json:"savedAt"` // unix ms
	Clean    bool              `json:"clean"`   // written by Stop
	Session  int64             `json:"session"`
	Since    int64             `json:"since"`
	Total    int64             `json:"total"`
	Seq      uint64            `json:"seq"`
	Policies []statsNameBytes  `json:"policies"` // oldest touched first
	Hosts    []statsNameBytes  `json:"hosts"`
	Rules    []statsRuleJSON   `json:"rules"`
	Closed   []statsClosedJSON `json:"closed"` // oldest first
	Speed    AppSpeedHistory   `json:"speed"`
}

// closedEachLocked visits the ring newest first; stop by returning false.
func (r *statsRecorder) closedEachLocked(f func(c *closedConn) bool) {
	for i := 0; i < r.closedN; i++ {
		idx := (r.closedPos - 1 - i + 2*statsClosedCap) % statsClosedCap
		if !f(&r.closed[idx]) {
			return
		}
	}
}

func nameBytesList(t *lruTable[upDown]) []statsNameBytes {
	out := make([]statsNameBytes, 0, t.len())
	t.each(func(k string, v *upDown) { out = append(out, statsNameBytes{Name: k, Up: v.Up, Down: v.Down}) })
	return out
}

// snapshot builds GET /app/stats. hostLimit / ruleLimit <= 0 means all.
func (r *statsRecorder) snapshot(closedAfter uint64, session int64, hostLimit, ruleLimit int) AppStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := AppStats{Session: r.session, Since: r.since, Version: r.version, TotalConnections: r.total,
		ClosedSeq: r.seq, RuleCount: r.rules.len(), HostCount: r.hosts.len()}
	s.Policies = nameBytesList(r.policies)
	sort.Slice(s.Policies, func(i, j int) bool {
		a, b := s.Policies[i], s.Policies[j]
		if a.Up+a.Down != b.Up+b.Down {
			return a.Up+a.Down > b.Up+b.Down
		}
		return a.Name < b.Name
	})
	s.Hosts = nameBytesList(r.hosts)
	sort.Slice(s.Hosts, func(i, j int) bool {
		a, b := s.Hosts[i], s.Hosts[j]
		if a.Up+a.Down != b.Up+b.Down {
			return a.Up+a.Down > b.Up+b.Down
		}
		return a.Name < b.Name
	})
	if hostLimit > 0 && len(s.Hosts) > hostLimit {
		s.Hosts = s.Hosts[:hostLimit]
	}
	s.Rules = make([]statsRuleJSON, 0, r.rules.len())
	r.rules.each(func(_ string, v *ruleHit) {
		s.Rules = append(s.Rules, statsRuleJSON{Rule: v.Rule, Policy: v.Policy, Hits: v.Hits})
	})
	sort.Slice(s.Rules, func(i, j int) bool {
		a, b := s.Rules[i], s.Rules[j]
		if a.Hits != b.Hits {
			return a.Hits > b.Hits
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return a.Policy < b.Policy
	})
	if ruleLimit > 0 && len(s.Rules) > ruleLimit {
		s.Rules = s.Rules[:ruleLimit]
	}
	// The App asks for what is new since its last answer; anything else (another session, a seq it cannot
	// have, or one that already left the ring) gets the whole ring.
	oldest := r.seq - uint64(r.closedN)
	s.Full = session != r.session || closedAfter > r.seq || closedAfter < oldest
	if s.Full {
		closedAfter = 0
	}
	s.Closed = []statsClosedJSON{}
	r.closedEachLocked(func(c *closedConn) bool {
		if c.Seq <= closedAfter {
			return false
		}
		s.Closed = append(s.Closed, c.toJSON())
		return true
	})
	return s
}

func (r *statsRecorder) speedHistoryLocked(lastSeconds int, buckets bool) AppSpeedHistory {
	h := AppSpeedHistory{Seconds: [][5]int64{}, Minutes: [][6]int64{}, Hours: [][6]int64{}}
	if l := r.secs.last(); l != nil {
		h.At = l.T
	}
	from := 0
	if lastSeconds > 0 && r.secs.n > lastSeconds {
		from = r.secs.n - lastSeconds
	}
	for i := from; i < r.secs.n; i++ {
		p := r.secs.at(i)
		h.Seconds = append(h.Seconds, [5]int64{p.T, p.Up, p.Down, p.PUp, p.PDown})
	}
	if buckets {
		for i := 0; i < r.mins.n; i++ {
			b := r.mins.at(i)
			h.Minutes = append(h.Minutes, [6]int64{b.Start, b.Up, b.Down, b.PUp, b.PDown, b.N})
		}
		for i := 0; i < r.hours.n; i++ {
			b := r.hours.at(i)
			h.Hours = append(h.Hours, [6]int64{b.Start, b.Up, b.Down, b.PUp, b.PDown, b.N})
		}
	}
	return h
}

func (r *statsRecorder) speedHistory(lastSeconds int, buckets bool) AppSpeedHistory {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.speedHistoryLocked(lastSeconds, buckets)
}

// reset clears counters, hits and closed connections (DELETE /app/stats, the App's 清零本次连接). The speed
// history stays: it is a time series, not a session total.
func (r *statsRecorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resetCountersLocked(r.now())
}

// MARK: - persistence

// jsonStream writes one JSON document element by element (json.Encoder buffers one whole value per Encode, so a
// big document encoded at once is held in memory in full, plus its growth copies).
type jsonStream struct {
	bw  *bufio.Writer
	enc *json.Encoder
	err error
}

func newJSONStream(w io.Writer) *jsonStream {
	bw := bufio.NewWriterSize(w, 32<<10)
	return &jsonStream{bw: bw, enc: json.NewEncoder(bw)}
}

func (j *jsonStream) raw(s string) {
	if j.err == nil {
		_, j.err = j.bw.WriteString(s)
	}
}

func (j *jsonStream) val(v any) {
	if j.err == nil {
		j.err = j.enc.Encode(v) // one value + "\n" (JSON whitespace)
	}
}

// field writes ,"name":v — or {"name":v for the first field.
func (j *jsonStream) field(first bool, name string, v any) {
	if first {
		j.raw(`{"` + name + `":`)
	} else {
		j.raw(`,"` + name + `":`)
	}
	j.val(v)
}

// list writes ,"name":[…] with the items each yields.
func (j *jsonStream) list(name string, each func(item func(v any))) {
	j.raw(`,"` + name + `":[`)
	first := true
	each(func(v any) {
		if !first {
			j.raw(",")
		}
		first = false
		j.val(v)
	})
	j.raw("]")
}

func (j *jsonStream) end() error {
	j.raw("}\n")
	if j.err == nil {
		j.err = j.bw.Flush()
	}
	return j.err
}

// writeAppStats streams GET /app/stats (the AppStats layout).
func writeAppStats(w io.Writer, s *AppStats) error {
	j := newJSONStream(w)
	j.field(true, "session", s.Session)
	j.field(false, "since", s.Since)
	j.field(false, "version", s.Version)
	j.field(false, "totalConnections", s.TotalConnections)
	j.field(false, "ruleCount", s.RuleCount)
	j.field(false, "hostCount", s.HostCount)
	j.field(false, "closedSeq", s.ClosedSeq)
	j.field(false, "full", s.Full)
	j.list("policies", func(item func(v any)) {
		for i := range s.Policies {
			item(&s.Policies[i])
		}
	})
	j.list("rules", func(item func(v any)) {
		for i := range s.Rules {
			item(&s.Rules[i])
		}
	})
	j.list("hosts", func(item func(v any)) {
		for i := range s.Hosts {
			item(&s.Hosts[i])
		}
	})
	j.list("closed", func(item func(v any)) {
		for i := range s.Closed {
			item(&s.Closed[i])
		}
	})
	return j.end()
}

// encodeLocked streams tunnel-stats.json (the statsFileJSON layout) to w. Caller holds r.mu.
func (r *statsRecorder) encodeLocked(w io.Writer, clean bool) error {
	j := newJSONStream(w)
	j.field(true, "savedAt", r.now().UnixMilli())
	j.field(false, "clean", clean)
	j.field(false, "session", r.session)
	j.field(false, "since", r.since)
	j.field(false, "total", r.total)
	j.field(false, "seq", r.seq)
	nb := func(t *lruTable[upDown]) func(item func(v any)) {
		return func(item func(v any)) {
			t.each(func(k string, v *upDown) { item(statsNameBytes{Name: k, Up: v.Up, Down: v.Down}) })
		}
	}
	j.list("policies", nb(r.policies))
	j.list("hosts", nb(r.hosts))
	j.list("rules", func(item func(v any)) {
		r.rules.each(func(_ string, v *ruleHit) { item(statsRuleJSON{Rule: v.Rule, Policy: v.Policy, Hits: v.Hits}) })
	})
	j.list("closed", func(item func(v any)) { // oldest first
		for i := r.closedN - 1; i >= 0; i-- {
			c := r.closed[(r.closedPos-1-i+2*statsClosedCap)%statsClosedCap].toJSON()
			item(&c)
		}
	})
	j.field(false, "speed", r.speedHistoryLocked(0, true)) // at most ~20 KB
	return j.end()
}

// save writes tunnel-stats.json (no-op without a home): streamed into a temp file under the lock, then synced and
// renamed outside it, so a slow flash write never holds up the 1 s sampler.
func (r *statsRecorder) save(clean bool) {
	r.mu.Lock()
	home := r.home
	if home == "" {
		r.mu.Unlock()
		return
	}
	p := filepath.Join(home, statsFile)
	f, err := os.CreateTemp(home, "."+statsFile+".tmp*")
	if err != nil {
		r.mu.Unlock()
		return
	}
	err = r.encodeLocked(f, clean)
	r.mu.Unlock()
	tmp := f.Name()
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		_ = os.Chmod(tmp, 0o644)
		err = os.Rename(tmp, p)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
}

// restoreLocked loads tunnel-stats.json: the speed history always (pruned by age), the counters only after an
// unclean end that saved less than statsResumeWindow ago. The file is read as a token stream, one list element at a
// time (it can be a few hundred KB, and this runs while the core starts). Returns true when the counters resumed.
func (r *statsRecorder) restoreLocked(home string, now time.Time) (resumed bool) {
	fh, err := os.Open(filepath.Join(home, statsFile))
	if err != nil {
		return false
	}
	defer fh.Close()
	dec := json.NewDecoder(bufio.NewReaderSize(fh, 16<<10))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return false
	}
	var (
		savedAt, session, since, total int64
		seq                            uint64
		clean                          = true
		decided, resume                bool
		speed                          AppSpeedHistory
		haveSpeed                      bool
	)
	decide := func() bool {
		if !decided {
			decided = true
			age := now.Sub(time.UnixMilli(savedAt))
			resume = !clean && session != 0 && age >= 0 && age <= statsResumeWindow
			if resume {
				r.session, r.since, r.total, r.seq = session, since, total, seq
			}
		}
		return resume
	}
	// eachElem decodes the array under the current key element by element into a fresh T and hands it to f.
	eachElem := func(f func(any) error, mk func() any) error {
		if tok, err := dec.Token(); err != nil {
			return err
		} else if tok == nil {
			return nil
		} else if tok != json.Delim('[') {
			return errors.New("not an array")
		}
		for dec.More() {
			v := mk()
			if err := dec.Decode(v); err != nil {
				return err
			}
			if err := f(v); err != nil {
				return err
			}
		}
		_, err := dec.Token() // ]
		return err
	}
	skip := func(any) error { return nil }
	ok := true
	for ok && dec.More() {
		tok, err := dec.Token()
		if err != nil {
			ok = false
			break
		}
		key, _ := tok.(string)
		switch key {
		case "savedAt":
			err = dec.Decode(&savedAt)
		case "clean":
			err = dec.Decode(&clean)
		case "session":
			err = dec.Decode(&session)
		case "since":
			err = dec.Decode(&since)
		case "total":
			err = dec.Decode(&total)
		case "seq":
			err = dec.Decode(&seq)
		case "policies", "hosts":
			t := r.policies
			if key == "hosts" {
				t = r.hosts
			}
			apply := skip
			if decide() {
				apply = func(v any) error {
					x := v.(*statsNameBytes)
					e := t.touch(clipFresh(x.Name))
					e.Up, e.Down = x.Up, x.Down
					return nil
				}
			}
			err = eachElem(apply, func() any { return &statsNameBytes{} })
		case "rules":
			apply := skip
			if decide() {
				apply = func(v any) error {
					x := v.(*statsRuleJSON)
					e := r.rules.touch(x.Rule + "\x01" + x.Policy)
					e.Rule, e.Policy, e.Hits = clipFresh(x.Rule), clipFresh(x.Policy), x.Hits
					return nil
				}
			}
			err = eachElem(apply, func() any { return &statsRuleJSON{} })
		case "closed": // oldest first
			apply := skip
			if decide() {
				apply = func(v any) error {
					c := v.(*statsClosedJSON).toConn()
					r.closed[r.closedPos] = c
					r.closedPos = (r.closedPos + 1) % statsClosedCap
					if r.closedN < statsClosedCap {
						r.closedN++
					}
					if c.Seq > r.seq {
						r.seq = c.Seq
					}
					return nil
				}
			}
			err = eachElem(apply, func() any { return &statsClosedJSON{} })
		case "speed":
			err = dec.Decode(&speed)
			haveSpeed = err == nil
		default:
			var discard json.RawMessage
			err = dec.Decode(&discard)
		}
		if err != nil {
			ok = false
		}
	}
	if !ok && resume {
		r.resetCountersLocked(now) // a damaged file never leaves half a session behind
		resume = false
	}
	if haveSpeed {
		nowS := now.Unix()
		r.secs.clear()
		r.mins.clear()
		r.hours.clear()
		for _, p := range speed.Seconds {
			if p[0] > nowS-statsSecCap && p[0] <= nowS {
				r.secs.push(speedPoint{T: p[0], Up: p[1], Down: p[2], PUp: p[3], PDown: p[4]})
			}
		}
		for _, p := range speed.Minutes {
			if p[0] > nowS-statsMinCap*60 && p[0] <= nowS {
				r.mins.push(speedBucket{Start: p[0], Up: p[1], Down: p[2], PUp: p[3], PDown: p[4], N: p[5]})
			}
		}
		for _, p := range speed.Hours {
			if p[0] > nowS-statsHourCap*3600 && p[0] <= nowS {
				r.hours.push(speedBucket{Start: p[0], Up: p[1], Down: p[2], PUp: p[3], PDown: p[4], N: p[5]})
			}
		}
	}
	if resume {
		r.version++
	}
	return resume
}

// begin starts a recording session for a core start: fresh counters (or the resumed ones after an unclean end),
// the restored speed history, and the 60 s saver.
func (r *statsRecorder) begin(home string) {
	r.end("", false)
	r.mu.Lock()
	now := r.now()
	r.resetCountersLocked(now)
	r.home = home
	resumed := false
	if home != "" {
		resumed = r.restoreLocked(home, now)
	}
	stop := make(chan struct{})
	r.stop = stop
	r.mu.Unlock()
	if resumed {
		stage("stats: resumed the previous session's counters (the extension did not stop cleanly)")
	}
	go func() {
		t := time.NewTicker(statsSaveInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				r.save(false)
			case <-stop:
				return
			}
		}
	}()
}

// end stops the saver; with write it saves first (clean marks a deliberate stop).
func (r *statsRecorder) end(home string, clean bool) {
	if home != "" {
		r.mu.Lock()
		r.home = home
		r.mu.Unlock()
		r.save(clean)
	}
	r.mu.Lock()
	if r.stop != nil {
		close(r.stop)
		r.stop = nil
	}
	r.mu.Unlock()
}

// MARK: - REST

func queryInt(req *mhttp.Request, k string, def int) int {
	if v := req.URL.Query().Get(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func writeJSONNoStore(w mhttp.ResponseWriter, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}

func appStatsRoutes(r chi.Router) {
	// GET /app/stats?session=&closedAfter=&hosts=&rules= — session counters recorded in the tunnel.
	r.Get("/app/stats", func(w mhttp.ResponseWriter, req *mhttp.Request) {
		q := req.URL.Query()
		after, _ := strconv.ParseUint(q.Get("closedAfter"), 10, 64)
		session, _ := strconv.ParseInt(q.Get("session"), 10, 64)
		st := statsRec.snapshot(after, session, queryInt(req, "hosts", 0), queryInt(req, "rules", 0))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = writeAppStats(w, &st) // streamed: the first answer of a session can carry 500 closed connections
	})
	// DELETE /app/stats — 清零本次连接 (speed history kept).
	r.Delete("/app/stats", func(w mhttp.ResponseWriter, req *mhttp.Request) {
		statsRec.reset()
		w.WriteHeader(204)
	})
	// GET /app/stats/speed?seconds=N&buckets=0|1 — the speed history (1 s / 1 min / 1 h).
	r.Get("/app/stats/speed", func(w mhttp.ResponseWriter, req *mhttp.Request) {
		writeJSONNoStore(w, statsRec.speedHistory(queryInt(req, "seconds", 0), queryInt(req, "buckets", 1) != 0))
	})
}

func init() { route.Register(appStatsRoutes) }
