package libmihomo

// v0.19.8 日志 / DNS 日志 history: mihomo's /logs stream has no history, and the app only listened while the page
// was open, so both pages were empty right after launch (device report). The extension's one log subscriber
// (startDiagCapture, running from tunnel start) now also keeps two bounded rings — the general log and the DNS
// queries (DEBUG "[DNS] " events, as timeline.go reads them) — that the app reads through GET /hark/logs before it
// attaches the live stream. Memory: at most logRingCap entries per ring, each payload cut to logPayloadMax bytes.

import (
	"strconv"
	"strings"
	"sync"
	"time"

	mhttp "github.com/metacubex/http"

	"github.com/metacubex/chi"
	"github.com/metacubex/mihomo/hub/route"
	"github.com/metacubex/mihomo/log"
)

const (
	logRingCap    = 2000
	logPayloadMax = 512
)

type logEntry struct {
	Seq     uint64 `json:"seq"`
	Time    int64  `json:"time"` // unix ms
	Type    string `json:"type"`
	Payload string `json:"payload"`
}

type logRing struct {
	mu   sync.Mutex
	buf  []logEntry
	head int // index of the oldest entry once full
	cap  int
}

var (
	logSeqMu   sync.Mutex
	logSeq     uint64
	generalLog = &logRing{cap: logRingCap}
	dnsLog     = &logRing{cap: logRingCap}
)

func nextLogSeq() uint64 {
	logSeqMu.Lock()
	defer logSeqMu.Unlock()
	logSeq++
	return logSeq
}

func (r *logRing) add(e logEntry) {
	if len(e.Payload) > logPayloadMax {
		cut := logPayloadMax
		for cut > 0 && !utf8Start(e.Payload[cut]) {
			cut--
		}
		e.Payload = e.Payload[:cut] + "…"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buf) < r.cap {
		r.buf = append(r.buf, e)
		return
	}
	r.buf[r.head] = e // drop the oldest
	r.head = (r.head + 1) % r.cap
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// since returns the entries newer than seq, oldest first.
func (r *logRing) since(seq uint64) []logEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]logEntry, 0, len(r.buf))
	n := len(r.buf)
	for i := 0; i < n; i++ {
		e := r.buf[(r.head+i)%n]
		if e.Seq > seq {
			out = append(out, e)
		}
	}
	return out
}

func (r *logRing) clear() {
	r.mu.Lock()
	r.buf, r.head = nil, 0
	r.mu.Unlock()
}

// recordLogEvent is called by the extension's log subscriber for every core log event.
func recordLogEvent(ev log.Event, now time.Time) {
	e := logEntry{Time: now.UnixMilli(), Type: ev.Type(), Payload: ev.Payload}
	if ev.LogLevel == log.DEBUG && strings.HasPrefix(ev.Payload, "[DNS] ") {
		e.Seq = nextLogSeq()
		dnsLog.add(e)
		return // DNS queries flood the debug level; they have their own ring
	}
	// The user's level (the config's log-level), but never stricter than INFO, so the page's level picker has
	// warnings / info to show; debug lines only when the core logs at debug.
	if ev.LogLevel < min(log.LogLevel(diagLevel.Load()), log.INFO) {
		return
	}
	e.Seq = nextLogSeq()
	generalLog.add(e)
}

var logLevelRank = map[string]int{"debug": 0, "info": 1, "warning": 2, "error": 3, "silent": 4}

func init() { route.Register(logRoutes) }

// GET /hark/logs?kind=general|dns&since=<seq>&level=<debug|info|warning|error> → {"seq": last, "logs": [...]}
// DELETE /hark/logs?kind=… clears that ring (the pages' 清空).
func logRoutes(r chi.Router) {
	r.Route("/hark", func(r chi.Router) {
		r.Get("/logs", func(w mhttp.ResponseWriter, req *mhttp.Request) {
			q := req.URL.Query()
			since, _ := strconv.ParseUint(q.Get("since"), 10, 64)
			writeToolJSON(w, logHistory(q.Get("kind"), since, q.Get("level")))
		})
		r.Delete("/logs", func(w mhttp.ResponseWriter, req *mhttp.Request) {
			ringFor(req.URL.Query().Get("kind")).clear()
			w.WriteHeader(204)
		})
	})
}

func ringFor(kind string) *logRing {
	if kind == "dns" {
		return dnsLog
	}
	return generalLog
}

type logHistoryResult struct {
	Seq  uint64     `json:"seq"`
	Logs []logEntry `json:"logs"`
}

func logHistory(kind string, since uint64, level string) logHistoryResult {
	all := ringFor(kind).since(since)
	min, ok := logLevelRank[strings.ToLower(level)]
	out := all[:0:0]
	for _, e := range all {
		if ok && logLevelRank[e.Type] < min {
			continue
		}
		out = append(out, e)
	}
	logSeqMu.Lock()
	last := logSeq
	logSeqMu.Unlock()
	return logHistoryResult{Seq: last, Logs: out}
}
