package libmihomo

// Native MitM stage 3b (feat/s3-mem): the extension's memory governor can run in Swift
// (PacketTunnel/NativeMitM/Memory/NativeMemoryGovernor.swift, app-group switch nativeMemGovernor, default
// OFF). It reads os_proc_available_memory + phys_footprint + the memory-pressure source itself and is then
// the ONE coordinator: it decides the shed level, the GOMEMLIMIT and when Go returns memory to the OS,
// through the calls below. While it is on, the Go-side governor (governLimit in memTick) stands down, so the
// two never fight over GOMEMLIMIT. Off (default) = everything in memshed.go exactly as before.
//
// Ported from fix/xmly-memory (897fffd, memshed.go): the anti-thrash floor — GOMEMLIMIT never below the
// non-garbage part of Go's memory (+2 MB), may rise up to configured + 16 MB (device 2026-10-24: a 26 MB
// limit below ~34 MB of non-garbage Go memory ran the GC ~100×/s) — and the calm critical shed (one
// FreeOSMemory, no runtime.GC() before it; DNS caches and the script queue only when the caller says so).

import (
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
	"github.com/metacubex/mihomo/log"
)

// nativeGovOn: the Swift governor owns GOMEMLIMIT and shedding (memTick skips governLimit).
var nativeGovOn atomic.Bool

const (
	// nativeGovSlack: garbage the GC may keep above Go's non-garbage memory before it collects again.
	nativeGovSlack = 2 << 20
	// nativeGovMaxRaise: the anti-thrash floor never raises the limit more than this above the configured one.
	nativeGovMaxRaise = 16 << 20
)

// Native shed flags (NativeShed).
const (
	NativeShedEngineCritical = 1 << 0 // engine caches at the critical level (kicks the script queue, closes the engine's upstream idle conns)
	NativeShedDNS            = 1 << 1 // clear the DNS caches
	NativeShedIdleConns      = 1 << 2 // close tunnel connections idle for idleConnAge
	NativeShedFreeOS         = 1 << 3 // one FreeOSMemory (GC + scavenge) after the shed
)

// SetNativeMemoryGovernor switches the Go governor off (on = true: Swift drives) or back on. Turning it off
// restores the configured GOMEMLIMIT (unless a script holds a GOMEMLIMIT loan; the loan restores its own).
func SetNativeMemoryGovernor(on bool) {
	was := nativeGovOn.Swap(on)
	if was == on {
		return
	}
	govern.Lock()
	cfg := govern.configured
	govern.lowered = 0
	govern.Unlock()
	if !on && cfg > 0 && !mitm.LoanActive() {
		debug.SetMemoryLimit(cfg)
	}
	stage("memory governor: %s", map[bool]string{true: "native (Swift) — Go governor stands down", false: "Go"}[on])
}

// NativeMemoryGovernorOn reports whether the Swift governor drives.
func NativeMemoryGovernorOn() bool { return nativeGovOn.Load() }

// The non-garbage part of Go's memory is memshed.go's goNonGarbage (fix/xmly-memory's anti-thrash floor): one
// definition for both governors since the native-final integration (s3-mem had its own copy, nonGarbageNow).

// NativeGoMemory is what the Swift governor needs to decide (JSON, bytes): live heap, non-garbage, the
// anti-thrash floor, GOMEMLIMIT now / configured, stacks, GC count, goroutines, loan.
func NativeGoMemory() string {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	govern.Lock()
	cfg := govern.configured
	govern.Unlock()
	ng := goNonGarbage()
	out := map[string]any{
		"heap":       ms.HeapAlloc,
		"nonGarbage": ng,
		"floor":      nativeFloor(ng),
		"limit":      debug.SetMemoryLimit(-1),
		"configured": cfg,
		"stacks":     ms.StackSys,
		"sys":        ms.Sys,
		"numGC":      ms.NumGC,
		"goroutines": runtime.NumGoroutine(),
		"loan":       mitm.LoanActive(),
	}
	b, _ := json.Marshal(out)
	return string(b)
}

func nativeFloor(nonGarbage int64) int64 {
	return max(int64(memGovernFloor), nonGarbage+nativeGovSlack)
}

// NativeGovernLimit sets GOMEMLIMIT for the Swift governor; want <= 0 restores the configured limit.
// Clamped to [anti-thrash floor, configured + nativeGovMaxRaise] (and never above the configured limit
// unless the floor needs it). Left alone while a script holds a GOMEMLIMIT loan, while the governor is off,
// or when the change is under 512 KB (no flapping). Returns the limit in effect.
func NativeGovernLimit(want int64) int64 {
	cur := debug.SetMemoryLimit(-1)
	if !nativeGovOn.Load() || mitm.LoanActive() {
		return cur
	}
	govern.Lock()
	cfg := govern.configured
	govern.Unlock()
	if cfg <= 0 || cfg >= 1<<40 {
		return cur
	}
	v := nativeClamp(want, cfg, goNonGarbage())
	if d := v - cur; d > -(512<<10) && d < 512<<10 {
		return cur
	}
	debug.SetMemoryLimit(v)
	govern.Lock()
	if v != cfg {
		govern.lowered = v
	} else {
		govern.lowered = 0
	}
	govern.Unlock()
	return v
}

// nativeClamp is NativeGovernLimit's arithmetic (tests).
func nativeClamp(want, cfg, nonGarbage int64) int64 {
	if want <= 0 {
		want = cfg
	}
	want = min(want, cfg)
	floor := nativeFloor(nonGarbage)
	if want < floor {
		want = min(floor, cfg+nativeGovMaxRaise)
	}
	return want
}

// NativeFreeOSMemory returns freed memory to the OS (one GC + scavenge; no cache drops — unlike FreeMemory).
// Rate limited to once per second: callers in a burst share one stop.
func NativeFreeOSMemory() bool {
	nativeFreeMu.Lock()
	if time.Since(nativeFreeAt) < time.Second {
		nativeFreeMu.Unlock()
		return false
	}
	nativeFreeAt = time.Now()
	nativeFreeMu.Unlock()
	debug.FreeOSMemory()
	return true
}

var (
	nativeFreeMu sync.Mutex
	nativeFreeAt time.Time
)

// NativeShed is the Swift governor's shed: engine caches (light, or critical with NativeShedEngineCritical),
// DNS caches / idle tunnel connections only when flagged, then at most one FreeOSMemory. No rate limit here
// (Swift rate-limits and backs off); returns the log line.
func NativeShed(level int, flags int, reason string) string {
	before := readMem()
	var parts []string
	engMu.Lock()
	e := eng
	engMu.Unlock()
	if e != nil {
		el := mitm.ShedLight
		if flags&NativeShedEngineCritical != 0 {
			el = mitm.ShedCritical
		}
		parts = append(parts, e.Shed(el).String())
	}
	if flags&NativeShedDNS != 0 {
		clearDNSCaches()
		parts = append(parts, "DNS caches cleared")
	}
	if level >= mitm.ShedCritical {
		clearValidateCache()
	}
	if flags&NativeShedIdleConns != 0 {
		if n := closeIdleConnections(idleConnAge); n > 0 {
			parts = append(parts, fmt.Sprintf("%d idle connections closed (no traffic for %s)", n, idleConnAge))
		}
	}
	freed := false
	if flags&NativeShedFreeOS != 0 {
		freed = NativeFreeOSMemory()
	}
	after := readMem()
	if !freed && flags&NativeShedFreeOS != 0 {
		parts = append(parts, "FreeOSMemory skipped (ran < 1 s ago)")
	}
	line := fmt.Sprintf("memory shed L%d native (%s): footprint %s → %s, available %s → %s, go heap %s → %s; %s",
		level, reason, mbs(before.fp), mbs(after.fp), mbs(before.avail), mbs(after.avail), mbu(before.heap), mbu(after.heap), strings.Join(parts, "; "))
	stage("%s", line)
	memLog.add(time.Now().Format("15:04:05") + " " + line)
	log.Warnln("[Memory] %s", line)
	return line
}
