package libmihomo

// v0.19.22 memory plateau (device log 2026-10-23, v0.19.20 build 291): after a few config reloads and two
// hours of use the packet tunnel sat at 40.0–40.4 MB of phys_footprint with 「memory pressure critical」
// (~10 MB available) and was killed by jetsam ~2.5 h later; a fresh session runs at 26–29 MB.
//
// What held it there:
//   - GOMEMLIMIT is 26 MB of *Go* memory and the extension carries ~13–15 MB that is not Go (Swift, the
//     frameworks, the packet flow). Once the live heap passes ~15 MB, GOGC 75 lets the heap goal reach the
//     soft limit, so the footprint settles at 26 + 14 ≈ 40 MB and stays there: every FreeOSMemory brings
//     it back to the live heap and the garbage regrows to the limit within seconds. The 40 MB plateau
//     was the soft limit, not a leak in the sense of a growing heap.
//   - What pushed the live heap from ~11 MB to past 15 MB is, most likely (the v0.19.20 log has no heap
//     breakdown; the periodic memory line below is there to confirm it next time), long-lived,
//     bounded-but-large state that a fresh session does not have yet: mihomo's DNS caches (4096 parsed answers per resolver by default,
//     stale entries never expire — main, proxy-server and direct resolvers each keep one: ~4 MB each when
//     full), idle TCP connections (gVisor endpoint buffers + relay state), and the MitM engine's caches
//     (compiled programs up to 8 MB, sources 2 MB, captured bodies 4 MB).
//   - The MemoryGuard's answer was FreeMemory every 3–4 s for two hours: a full GC + scavenge each time
//     (CPU, battery) that dropped nothing of the above.
//
// Now:
//   - the DNS cache is capped for the extension (dns.cache-max-size ≤ 1024, capDNSCache);
//   - ShedMemory(level) actually sheds — MitM caches by level, request-log bodies, DNS caches, idle
//     connections (no traffic for idleConnAge, only when available memory is low), then GC + scavenge —
//     logs what it freed, and backs off when a shed freed nothing (no FreeOSMemory loop);
//   - a governor lowers the effective GOMEMLIMIT while the footprint is above memGovernTarget, so the
//     garbage the GC keeps scales with what iOS still allows instead of the fixed 26 MB (restored when
//     the footprint is back under memGovernRelax);
//   - Reload sheds before building the new runtime (old and new coexist while it parses) and logs the
//     footprint before / after;
//   - while under pressure a detailed memory line goes to the startup log every 5 minutes (every 30
//     minutes otherwise), so the next device log names the holder.

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strings"
	"sync"
	"time"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

const (
	// iosDNSCacheMax caps dns.cache-max-size in the extension (mihomo's default is 4096 per resolver).
	iosDNSCacheMax = 1024

	// memPressureAvail: below this much available memory the extension counts as under pressure
	// (iOS reported "critical" at ~10 MB on the device).
	memPressureAvail = 12 << 20
	// memCriticalAvail: below this ShedMemory always sheds at the critical level.
	memCriticalAvail = 8 << 20
	// memCalmAvail: with at least this much available a critical request is shed at the light level.
	memCalmAvail = 16 << 20

	// idleConnAge: under pressure, connections that moved no bytes for this long are closed (keep-alive
	// sockets apps reopen on demand; a page loading now keeps its connections).
	idleConnAge = 3 * time.Minute

	// memGovernTarget / memGovernRelax: footprint band of the GOMEMLIMIT governor.
	memGovernTarget = 36 << 20
	memGovernRelax  = 32 << 20
	// memGovernFloor: the governor never sets GOMEMLIMIT below this, nor below live heap + memGovernHeadroom.
	memGovernFloor    = 16 << 20
	memGovernHeadroom = 6 << 20

	memLogPressureEvery = 5 * time.Minute
	memLogCalmEvery     = 30 * time.Minute
)

// capDNSCache keeps the profile's cache-max-size when it is set and not above iosDNSCacheMax.
func capDNSCache(dns map[string]any) {
	if n := intOf(dns["cache-max-size"]); n > 0 && n <= iosDNSCacheMax {
		return
	}
	dns["cache-max-size"] = iosDNSCacheMax
}

// ---------- connection activity (idle connections) ----------

type connSeen struct {
	bytes int64
	since time.Time // last time bytes changed (or first seen)
}

var (
	connActMu sync.Mutex
	connAct   = map[string]connSeen{}
)

// trackConnActivity samples every connection's byte count and returns the total and the connections
// idle for at least idle (no bytes moved since the earlier samples).
func trackConnActivity(now time.Time, idle time.Duration) (total int, idleConns []statistic.Tracker) {
	connActMu.Lock()
	defer connActMu.Unlock()
	live := make(map[string]struct{}, len(connAct))
	statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
		total++
		info := c.Info()
		id := c.ID()
		live[id] = struct{}{}
		b := info.UploadTotal.Load() + info.DownloadTotal.Load()
		s, ok := connAct[id]
		switch {
		case !ok:
			s = connSeen{bytes: b, since: now}
			if b == 0 && !info.Start.IsZero() && info.Start.Before(now) {
				s.since = info.Start // never moved a byte: idle since it opened
			}
		case s.bytes != b:
			s = connSeen{bytes: b, since: now}
		}
		connAct[id] = s
		if idle > 0 && now.Sub(s.since) >= idle {
			idleConns = append(idleConns, c)
		}
		return true
	})
	for id := range connAct {
		if _, ok := live[id]; !ok {
			delete(connAct, id)
		}
	}
	return
}

// closeIdleConnections closes connections without traffic for idle; returns how many.
func closeIdleConnections(idle time.Duration) int {
	_, conns := trackConnActivity(time.Now(), idle)
	for _, c := range conns {
		_ = c.Close()
	}
	return len(conns)
}

// ---------- shed ----------

type memReading struct {
	fp, avail int64 // -1 unknown
	heap      uint64
	inuse     uint64
	idle      uint64 // heap idle not yet returned
	released  uint64
	stacks    uint64
	sys       uint64
	numGC     uint32
	gor       int
}

func readMem() memReading {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	fp, avail, _ := probeNow()
	return memReading{fp: fp, avail: avail, heap: ms.HeapAlloc, inuse: ms.HeapInuse, idle: ms.HeapIdle - ms.HeapReleased,
		released: ms.HeapReleased, stacks: ms.StackSys, sys: ms.Sys, numGC: ms.NumGC, gor: runtime.NumGoroutine()}
}

func mbs(v int64) string {
	if v < 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f MB", float64(v)/(1<<20))
}

func mbu(v uint64) string { return fmt.Sprintf("%.1f MB", float64(v)/(1<<20)) }

var shedState struct {
	sync.Mutex
	last    time.Time
	backoff time.Duration
	lastFP  int64
}

const (
	shedMinGap     = 3 * time.Second
	shedMaxBackoff = 2 * time.Minute
)

// testHookShedDNS lets tests observe the DNS cache clear.
var testHookShedDNS func()

// shedNow frees what can be rebuilt, by level, and returns what it did (no rate limit).
func shedNow(level int, why string) string {
	before := readMem()
	var parts []string
	engMu.Lock()
	e := eng
	engMu.Unlock()
	if e != nil {
		st := e.Shed(level)
		parts = append(parts, st.String())
	}
	if level >= mitm.ShedCritical {
		// fix/xmly-memory (device 2026-10-24 11:34): a pressure *event* arrives while an app opens its
		// connections; clearing the DNS caches then made every one of them resolve again (the shed
		// line read footprint 39.8 → 42.1 MB). The caches are capped (iosDNSCacheMax) and go on the
		// timer / before a reload, on an event only near the limit, and at most every dnsClearEvery.
		if dnsClearDue(why, before.avail) {
			clearDNSCaches()
			parts = append(parts, "DNS caches cleared")
		}
		clearValidateCache()
		if before.avail >= 0 && before.avail < memPressureAvail {
			if n := closeIdleConnections(idleConnAge); n > 0 {
				parts = append(parts, fmt.Sprintf("%d idle connections closed (no traffic for %s)", n, idleConnAge))
			}
		}
	}
	debug.FreeOSMemory() // a full GC + scavenge (the runtime.GC() before it only doubled the stop)
	after := readMem()
	if v := governLimit(after.fp, after.heap); v > 0 {
		parts = append(parts, "GOMEMLIMIT "+mbs(v))
	}
	line := fmt.Sprintf("memory shed L%d (%s): footprint %s → %s, available %s → %s, go heap %s → %s; %s",
		level, why, mbs(before.fp), mbs(after.fp), mbs(before.avail), mbs(after.avail), mbu(before.heap), mbu(after.heap), strings.Join(parts, "; "))
	stage("%s", line)
	memLog.add(time.Now().Format("15:04:05") + " " + line)
	log.Warnln("[Memory] %s", line)
	return line
}

// ShedMemory is the MemoryGuard's answer to high footprint / memory-pressure events (v0.19.22, replaces
// calling FreeMemory every tick). level 1 = warning / footprint high, 2 = critical; it is raised to 2
// when less than memCriticalAvail is available and lowered to 1 with memCalmAvail or more. Rate limited: at most every 3 s, and when the previous
// shed returned less than 1 MB the next one waits twice as long (up to 2 min) unless the footprint grew
// by 2 MB since. Returns the log line, "" when skipped.
func ShedMemory(level int, reason string) string {
	if level < mitm.ShedLight {
		level = mitm.ShedLight
	}
	fp, avail, _ := probeNow()
	switch {
	case avail >= 0 && avail < memCriticalAvail:
		level = mitm.ShedCritical
	case level >= mitm.ShedCritical && avail >= memCalmAvail:
		// memory-pressure events are system-wide: with this much still allowed to the extension a
		// "critical" event is someone else's problem — idle caches only, DNS caches stay
		level = mitm.ShedLight
	}
	shedState.Lock()
	now := time.Now()
	gap := shedMinGap + shedState.backoff
	grew := fp >= 0 && shedState.lastFP >= 0 && fp-shedState.lastFP >= 2<<20
	if now.Sub(shedState.last) < gap && !grew {
		shedState.Unlock()
		return ""
	}
	shedState.last = now
	shedState.Unlock()

	before := fp
	line := shedNow(level, reason)
	afterFP, _, _ := probeNow()

	shedState.Lock()
	shedState.lastFP = afterFP
	if before >= 0 && afterFP >= 0 && before-afterFP < 1<<20 {
		if shedState.backoff == 0 {
			shedState.backoff = 5 * time.Second
		} else {
			shedState.backoff = min(shedState.backoff*2, shedMaxBackoff)
		}
	} else {
		shedState.backoff = 0
	}
	shedState.Unlock()
	return line
}

// dnsClearEvery: the critical shed clears the DNS caches at most this often.
var dnsClearEvery = 2 * time.Minute

var lastDNSClear struct {
	sync.Mutex
	at time.Time
}

// dnsClearEventAvail: a pressure event clears the DNS caches only below this much available.
const dnsClearEventAvail = 5 << 20

// dnsClearDue: on the timer / before a reload, on an event only below dnsClearEventAvail (or without a
// probe); not twice within dnsClearEvery.
func dnsClearDue(why string, avail int64) bool {
	if !(why == "timer" || why == "before reload" || avail < dnsClearEventAvail) {
		return false
	}
	lastDNSClear.Lock()
	defer lastDNSClear.Unlock()
	if !lastDNSClear.at.IsZero() && time.Since(lastDNSClear.at) < dnsClearEvery {
		return false
	}
	lastDNSClear.at = time.Now()
	return true
}

func clearDNSCaches() {
	if h := testHookShedDNS; h != nil {
		h()
	}
	seen := map[resolver.Resolver]bool{}
	for _, r := range []resolver.Resolver{resolver.DefaultResolver, resolver.ProxyServerHostResolver, resolver.DirectHostResolver} {
		if r == nil || seen[r] {
			continue
		}
		seen[r] = true
		r.ClearCache()
	}
}

func clearValidateCache() {
	validateMu.Lock()
	clear(validateCache)
	validateMu.Unlock()
}

// ---------- GOMEMLIMIT governor ----------

var govern struct {
	sync.Mutex
	configured int64 // the limit startGC set (overrides 内存上限)
	lowered    int64 // the value the governor set, 0 = not active
}

// setConfiguredLimit records the limit startGC / SetMemoryLimit applied (the governor's ceiling).
func setConfiguredLimit(b int64) {
	govern.Lock()
	govern.configured = b
	govern.lowered = 0
	govern.Unlock()
}

// governLimit adjusts GOMEMLIMIT from the footprint: above memGovernTarget it lowers the limit by the
// excess (never below memGovernFloor or live heap + memGovernHeadroom), under memGovernRelax it restores
// the configured value. It leaves the limit alone while a script holds a GOMEMLIMIT loan or when someone
// else changed it. Returns the limit now in effect when it changed it, else 0.
func governLimit(fp int64, liveHeap uint64) int64 {
	if fp < 0 || mitm.LoanActive() {
		return 0
	}
	govern.Lock()
	defer govern.Unlock()
	cfg := govern.configured
	if cfg <= 0 || cfg >= 1<<40 {
		return 0
	}
	cur := debug.SetMemoryLimit(-1)
	if govern.lowered != 0 && cur != govern.lowered {
		govern.lowered = 0 // changed by someone else (内存上限 setting): not ours to manage
		return 0
	}
	if govern.lowered == 0 && cur != cfg {
		return 0
	}
	// fix/xmly-memory (device 2026-10-24: gc 1158 cycles in the first 12 s, ~100 per second): GOMEMLIMIT
	// counts all Go memory — stacks (5 MB with 300–400 goroutines), span overhead and runtime metadata as
	// well as the heap — so with 22 MB of heap spans in use the 26 MB limit (and the governor's 22.7 MB)
	// sat below what Go holds even without any garbage. The GC then ran back to back (CPU limiter at 50 %)
	// without lowering the footprint, and slower requests kept their connections and goroutines longer.
	// The limit now stays at least antiThrashSlack above the non-garbage part of Go's memory.
	floor := goNonGarbage() + antiThrashSlack
	switch {
	case fp >= memGovernTarget:
		want := cur - (fp - memGovernTarget) - 1<<20
		lo := max(int64(memGovernFloor), int64(liveHeap)+memGovernHeadroom, floor)
		if want < lo {
			want = lo
		}
		if want >= cur || want >= cfg {
			return 0
		}
		debug.SetMemoryLimit(want)
		govern.lowered = want
		return want
	case fp < memGovernRelax && govern.lowered != 0 && floor <= cfg:
		debug.SetMemoryLimit(cfg)
		govern.lowered = 0
		return cfg
	}
	// anti-thrash: the limit (configured or lowered) is below what Go holds without garbage
	if cur < floor && floor > memGovernFloor {
		want := min(floor, cfg+antiThrashMaxRaise)
		if want > cur {
			debug.SetMemoryLimit(want)
			govern.lowered = want
			return want
		}
	}
	return 0
}

// antiThrashSlack: garbage the GC may keep above Go's non-garbage memory before it collects again.
const antiThrashSlack = 2 << 20

// antiThrashMaxRaise: the anti-thrash floor never raises the limit more than this above the configured one.
const antiThrashMaxRaise = 16 << 20

// goNonGarbage is the part of Go's memory (what GOMEMLIMIT counts: all mapped, minus released) that a GC
// cannot free: everything except the heap objects that were not live after the last cycle. Tests swap it.
var goNonGarbage = func() int64 {
	s := []metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/gc/heap/live:bytes"},
	}
	metrics.Read(s)
	for _, x := range s {
		if x.Value.Kind() != metrics.KindUint64 {
			return 0
		}
	}
	mapped := int64(s[0].Value.Uint64() - s[1].Value.Uint64())
	garbage := int64(s[2].Value.Uint64()) - int64(s[3].Value.Uint64())
	if garbage < 0 {
		garbage = 0
	}
	return mapped - garbage
}

// goMemClasses is the Go memory breakdown for the memory line (MB): span overhead in heap, free heap not
// yet returned, stacks, runtime metadata and other runtime memory.
func goMemClasses() string {
	s := []metrics.Sample{
		{Name: "/memory/classes/heap/unused:bytes"},
		{Name: "/memory/classes/heap/free:bytes"},
		{Name: "/memory/classes/heap/stacks:bytes"},
		{Name: "/memory/classes/os-stacks:bytes"},
		{Name: "/memory/classes/metadata/mspan/inuse:bytes"},
		{Name: "/memory/classes/metadata/mcache/inuse:bytes"},
		{Name: "/memory/classes/metadata/other:bytes"},
		{Name: "/memory/classes/other:bytes"},
		{Name: "/memory/classes/profiling/buckets:bytes"},
		{Name: "/gc/heap/live:bytes"},
	}
	metrics.Read(s)
	v := func(i int) float64 {
		if s[i].Value.Kind() != metrics.KindUint64 {
			return 0
		}
		return float64(s[i].Value.Uint64()) / (1 << 20)
	}
	return fmt.Sprintf("live %.1f, span slack %.1f, free %.1f, stacks %.1f, metadata %.1f, other %.1f, non-garbage %.1f MB",
		v(9), v(0), v(1), v(2)+v(3), v(4)+v(5)+v(6), v(7)+v(8), float64(goNonGarbage())/(1<<20))
}

// ---------- periodic memory line ----------

var memLogState struct {
	sync.Mutex
	last time.Time
}

// memDetail is the detailed memory line: footprint, Go heap classes, stacks, goroutines, connections
// (idle ones), MitM caches, GOMEMLIMIT.
func memDetail(r memReading, conns, idle int) string {
	engMu.Lock()
	e := eng
	engMu.Unlock()
	cs := "mitm off"
	if e != nil {
		cs = e.Stats().String()
	}
	js := ""
	engMu.Lock()
	se := scriptEngine
	engMu.Unlock()
	if se != nil {
		js = "; " + se.Stats()
	}
	return fmt.Sprintf("memory: footprint %s, available %s; go heap %s (in use %s, idle %s, released %s), stacks %s, go sys %s, gc %d, goroutines %d; go classes: %s; connections %d (idle ≥%s: %d); %s%s; dns cache ≤%d/resolver; GOMEMLIMIT %s; %s",
		mbs(r.fp), mbs(r.avail), mbu(r.heap), mbu(r.inuse), mbu(r.idle), mbu(r.released), mbu(r.stacks), mbu(r.sys), r.numGC, r.gor, goMemClasses(),
		conns, idleConnAge, idle, cs, js, iosDNSCacheMax, mbs(debug.SetMemoryLimit(-1)), pageReturnSummary())
}

// memTick runs on every MemoryGuard sample: connection activity, the governor, and the periodic line.
func memTick(footprint, available int64, now time.Time) {
	conns, idle := trackConnActivity(now, idleConnAge)
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	// feat/s3-mem: with the native (Swift) governor on, it owns GOMEMLIMIT (nativegov.go).
	if !nativeGovOn.Load() {
		if v := governLimit(footprint, ms.HeapAlloc); v > 0 {
			stage("memory governor: GOMEMLIMIT → %s at footprint %s, available %s, go heap %s", mbs(v), mbs(footprint), mbs(available), mbu(ms.HeapAlloc))
		}
	}
	pressure := (available >= 0 && available < memPressureAvail) || footprint >= memGovernTarget
	every := memLogCalmEvery
	if pressure {
		every = memLogPressureEvery
	}
	memLogState.Lock()
	due := now.Sub(memLogState.last) >= every
	if due {
		memLogState.last = now
	}
	memLogState.Unlock()
	if due {
		r := readMem()
		r.fp, r.avail = footprint, available
		stage("%s", memDetail(r, conns, len(idle)))
	}
}

// reloadShed runs before a Reload builds the new runtime; returns the reading taken before it.
func reloadShed() memReading {
	pre := readMem()
	level := mitm.ShedLight
	if pre.avail >= 0 && pre.avail < memPressureAvail {
		level = mitm.ShedCritical
	}
	if level < mitm.ShedCritical {
		clearDNSCaches() // critical clears them itself
	}
	shedNow(level, "before reload")
	return pre
}
