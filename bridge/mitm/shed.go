package mitm

import (
	"fmt"
	"net"
	"net/http"
	"time"
)

// v0.19.22 (device log 2026-10-23, v0.19.20): the extension sat at 40 MB of phys_footprint with
// 「memory pressure critical」 for two hours and was then killed by jetsam. The MemoryGuard called
// FreeMemory → DropCaches every few seconds, which kept recently used programs and dropped only the
// in-memory sources: the engine could hold up to ~14 MB it does not need (compiled programs up to
// progCacheBudget, sources up to memCacheBudget, captured request/response bodies up to
// DefaultCaptureBudget) while iOS reported ~10 MB left. Shed frees them by level and says how much.

// ShedStats is what Engine.Shed released (diagnostics line in the startup log).
type ShedStats struct {
	Programs     int   // compiled programs dropped
	ProgramBytes int64 // their estimated size
	Sources      int   // in-memory script sources dropped
	SourceBytes  int64
	BodyBytes    int  // captured request-log body text dropped
	IdleClosed   bool // upstream keep-alive connections closed
	Dequeued     int  // requests waiting for a large script that were turned away (pass through)
	// ClientIdleClosed: idle client-side MitM connections were closed (fix/xmly-memory).
	ClientIdleClosed bool
}

// clientIdleMin: a client-side MitM connection idle at least this long may be closed by the critical shed.
var clientIdleMin = 5 * time.Second

// trackConnState is the MitM server's ConnState hook (HTTP/1 and HTTP/2).
func (e *Engine) trackConnState(c net.Conn, st http.ConnState) {
	switch st {
	case http.StateNew, http.StateActive:
		e.clientConns.Store(c, int64(0))
	case http.StateIdle:
		e.clientConns.Store(c, time.Now().UnixNano())
	case http.StateClosed, http.StateHijacked:
		e.clientConns.Delete(c)
	}
}

// closeIdleClients closes client-side MitM connections idle for at least minIdle; returns how many.
func (e *Engine) closeIdleClients(minIdle time.Duration) int {
	n := 0
	now := time.Now().UnixNano()
	e.clientConns.Range(func(k, v any) bool {
		if t, _ := v.(int64); t != 0 && now-t >= int64(minIdle) {
			_ = k.(net.Conn).Close()
			e.clientConns.Delete(k)
			n++
		}
		return true
	})
	return n
}

// shedConnsAvail: the critical shed turns queued script requests away and closes idle connections only
// below this much available memory (the running script is interrupted at scriptAvailFloor).
const shedConnsAvail = scriptAvailFloor + 1<<20

// shedConnsNow: below shedConnsAvail, or no probe (app process, tests: as before).
func shedConnsNow() bool {
	a, known := availableMemoryNow()
	return !known || a < shedConnsAvail
}

func (s ShedStats) String() string {
	conns := ""
	if s.IdleClosed || s.ClientIdleClosed {
		conns = ", idle MitM connections closed"
	}
	return fmt.Sprintf("scripts %d (%.1f MB), sources %d (%.1f MB), captured bodies %.1f MB, queued script requests %d%s",
		s.Programs, float64(s.ProgramBytes)/(1<<20), s.Sources, float64(s.SourceBytes)/(1<<20), float64(s.BodyBytes)/(1<<20), s.Dequeued, conns)
}

// CacheStats is what the engine holds now (periodic memory line).
type CacheStats struct {
	Programs     int
	ProgramBytes int64
	Sources      int
	SourceBytes  int64
	BodyBytes    int
	Requests     int
	Queued       int // requests waiting for a large script (v0.19.22)
}

func (c CacheStats) String() string {
	return fmt.Sprintf("mitm scripts %d (%.1f MB), sources %d (%.1f MB), request log %d (bodies %.1f MB), js runtimes %d (%s), script queue %d",
		c.Programs, float64(c.ProgramBytes)/(1<<20), c.Sources, float64(c.SourceBytes)/(1<<20), c.Requests, float64(c.BodyBytes)/(1<<20), LiveRuntimes(), ScriptEngineName(), c.Queued) + laneSuffix()
}

// laneSuffix adds the native body lane to the memory line when one is registered (feat/native-mitm).
func laneSuffix() string {
	if s := LaneStats(); s != "" {
		return ", " + s
	}
	return ""
}

// Stats reports the engine's caches (nil engine: zero).
func (e *Engine) Stats() CacheStats {
	var c CacheStats
	if e == nil {
		return c
	}
	if e.scripts != nil {
		c.Programs, c.ProgramBytes = e.scripts.progs.stats()
		if e.scripts.queue != nil {
			c.Queued = e.scripts.queue.Waiting()
		}
	}
	if e.res != nil {
		c.Sources, c.SourceBytes = e.res.mem.stats()
	}
	if e.Requests != nil {
		c.BodyBytes = e.Requests.CapturedBytes()
		e.Requests.mu.Lock()
		c.Requests = len(e.Requests.list)
		e.Requests.mu.Unlock()
	}
	return c
}

// Shed levels.
const (
	ShedLight    = 1 // memory getting high: idle caches only (programs used in the last minute stay)
	ShedCritical = 2 // close to the jetsam limit: everything the engine can rebuild
)

// shedCriticalKeep: at ShedCritical a program used this recently still stays (a script running right
// now, or one of a burst of requests — recompiling it costs more than it frees).
var shedCriticalKeep = dropKeepRecent / 6

// Shed releases engine memory by level and reports what it freed. Light: compiled programs idle for
// dropKeepRecent, all in-memory sources, captured bodies above a quarter of the budget. Critical:
// programs idle for 10 s, all sources and all captured bodies, upstream idle connections.
func (e *Engine) Shed(level int) ShedStats {
	var s ShedStats
	if e == nil {
		return s
	}
	keep := dropKeepRecent
	if level >= ShedCritical {
		keep = shedCriticalKeep
	}
	if e.scripts != nil {
		n0, w0 := e.scripts.progs.stats()
		e.scripts.DropIdle(keep)
		n1, w1 := e.scripts.progs.stats()
		s.Programs, s.ProgramBytes = n0-n1, w0-w1
	}
	if e.res != nil {
		s.Sources, s.SourceBytes = e.res.mem.stats()
		e.res.mem.Reset()
	}
	if e.Requests != nil {
		limit := DefaultCaptureBudget / 4
		if level >= ShedCritical {
			limit = 0
		}
		s.BodyBytes = e.Requests.DropBodies(limit)
	}
	// fix/xmly-memory (device 2026-10-24): the critical shed fired 4 s after the tunnel started, the moment
	// 喜马拉雅 opened its connections (iOS reports "critical" at ~10 MB available), turned the waiting script
	// request away (「内存紧张，已取消排队中的脚本（排队 547 ms）」) and closed the upstream connections the
	// burst was about to reuse — the footprint went UP (39.8 → 42.1 MB) while the requests reconnected.
	// Queued requests and connections now go only when memory is really near the limit.
	if level >= ShedCritical && shedConnsNow() {
		// v0.19.22: requests waiting for a large script hold their connection, goroutines and upstream
		// buffers; at the critical level they pass through unchanged now (the device log showed shed
		// L2 freeing ~1 MB while the queue kept growing).
		if e.scripts != nil && e.scripts.queue != nil {
			s.Dequeued = e.scripts.queue.kickAll()
		}
		// Client-side MitM connections without a request in flight (HTTP/2 or keep-alive): each holds
		// two TLS states, framer buffers and two goroutines; the app reconnects on its next request.
		s.ClientIdleClosed = e.closeIdleClients(clientIdleMin) > 0
		e.tmu.Lock()
		if e.transport != nil {
			e.transport.CloseIdleConnections()
			s.IdleClosed = true
		}
		for _, c := range e.clients {
			c.CloseIdleConnections()
		}
		e.tmu.Unlock()
	}
	return s
}

// DropBodies drops captured body text, oldest entries first, until at most keep bytes remain; returns
// the bytes dropped. Entries keep their headers and summary (marked bodiesDropped, as for the budget).
func (l *RequestLog) DropBodies(keep int) int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	total := 0
	for _, e := range l.list {
		e.mu.Lock()
		total += e.size
		e.mu.Unlock()
	}
	dropped := 0
	for _, e := range l.list {
		if total <= keep {
			break
		}
		e.mu.Lock()
		if e.size > 0 {
			total -= e.size
			dropped += e.size
			e.size = 0
			e.ReqBodyS, e.RespBodyS = "", ""
			e.Dropped = true
		}
		e.mu.Unlock()
	}
	return dropped
}

func (c *lru[V]) stats() (int, int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.l.Len(), c.w
}
