package mitm

import "fmt"

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
}

func (s ShedStats) String() string {
	return fmt.Sprintf("scripts %d (%.1f MB), sources %d (%.1f MB), captured bodies %.1f MB",
		s.Programs, float64(s.ProgramBytes)/(1<<20), s.Sources, float64(s.SourceBytes)/(1<<20), float64(s.BodyBytes)/(1<<20))
}

// CacheStats is what the engine holds now (periodic memory line).
type CacheStats struct {
	Programs     int
	ProgramBytes int64
	Sources      int
	SourceBytes  int64
	BodyBytes    int
	Requests     int
}

func (c CacheStats) String() string {
	return fmt.Sprintf("mitm scripts %d (%.1f MB), sources %d (%.1f MB), request log %d (bodies %.1f MB), js runtimes %d (%s)",
		c.Programs, float64(c.ProgramBytes)/(1<<20), c.Sources, float64(c.SourceBytes)/(1<<20), c.Requests, float64(c.BodyBytes)/(1<<20), LiveRuntimes(), ScriptEngineName())
}

// Stats reports the engine's caches (nil engine: zero).
func (e *Engine) Stats() CacheStats {
	var c CacheStats
	if e == nil {
		return c
	}
	if e.scripts != nil {
		c.Programs, c.ProgramBytes = e.scripts.progs.stats()
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
	if level >= ShedCritical {
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
