package mitm

import (
	"container/list"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// ---- tiny generic LRU ----

type lru[V any] struct {
	mu  sync.Mutex
	max int
	l   *list.List
	m   map[string]*list.Element
}

type lruItem[V any] struct {
	k string
	v V
}

func newLRU[V any](max int) *lru[V] {
	return &lru[V]{max: max, l: list.New(), m: map[string]*list.Element{}}
}

func (c *lru[V]) Get(k string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[k]; ok {
		c.l.MoveToFront(el)
		return el.Value.(*lruItem[V]).v, true
	}
	var zero V
	return zero, false
}

func (c *lru[V]) Put(k string, v V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[k]; ok {
		el.Value.(*lruItem[V]).v = v
		c.l.MoveToFront(el)
		return
	}
	c.m[k] = c.l.PushFront(&lruItem[V]{k, v})
	for c.l.Len() > c.max {
		el := c.l.Back()
		c.l.Remove(el)
		delete(c.m, el.Value.(*lruItem[V]).k)
	}
}

func (c *lru[V]) Reset() {
	c.mu.Lock()
	c.l.Init()
	c.m = map[string]*list.Element{}
	c.mu.Unlock()
}

// ---- request log (请求 → HTTP) ----

// Entry is one HTTP request seen by the engine.
type Entry struct {
	mu        sync.Mutex
	ID        int64             `json:"id"`
	Time      float64           `json:"time"` // unix seconds
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Host      string            `json:"host"`
	MitM      bool              `json:"mitm"`
	Status    int               `json:"status"`
	Matched   []string          `json:"matched,omitempty"`
	Notes     []string          `json:"notes,omitempty"`
	IsLocal   bool              `json:"local,omitempty"` // answered by the engine
	Done      bool              `json:"done"`
	Duration  float64           `json:"duration,omitempty"` // ms
	Bytes     int64             `json:"bytes"`
	ReqHdr    map[string]string `json:"reqHeaders,omitempty"`
	RespHdr   map[string]string `json:"respHeaders,omitempty"`
	ReqBodyS  string            `json:"reqBody,omitempty"`
	RespBodyS string            `json:"respBody,omitempty"`
	ReqBin    int               `json:"reqBodyBinary,omitempty"`  // >0: binary body of this size (not shown)
	RespBin   int               `json:"respBodyBinary,omitempty"` // >0: binary / compressed body
	RespEnc   string            `json:"respEncoding,omitempty"`
	start     time.Time
	ring      *RequestLog
}

// Summary is the list view (no headers / bodies).
type Summary struct {
	ID       int64    `json:"id"`
	Time     float64  `json:"time"`
	Method   string   `json:"method"`
	URL      string   `json:"url"`
	Host     string   `json:"host"`
	MitM     bool     `json:"mitm"`
	Status   int      `json:"status"`
	Matched  []string `json:"matched,omitempty"`
	Notes    []string `json:"notes,omitempty"`
	Local    bool     `json:"local,omitempty"`
	Done     bool     `json:"done"`
	Duration float64  `json:"duration,omitempty"`
	Bytes    int64    `json:"bytes"`
}

// RequestLog is a ring of recent requests. Bodies are capped at captureLimit each.
type RequestLog struct {
	mu   sync.Mutex
	max  int
	list []*Entry
	seq  atomic.Int64
}

func NewRequestLog(max int) *RequestLog { return &RequestLog{max: max} }

func (l *RequestLog) push(e *Entry) {
	l.mu.Lock()
	l.list = append(l.list, e)
	if len(l.list) > l.max {
		copy(l.list, l.list[len(l.list)-l.max:])
		l.list = l.list[:l.max]
	}
	l.mu.Unlock()
}

// Start records a new request.
func (l *RequestLog) Start(r *http.Request, u string, mitm bool) *Entry {
	host := r.Host
	if i := strings.LastIndexByte(host, ':'); i > 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	e := &Entry{ID: l.seq.Add(1), Time: float64(time.Now().UnixMilli()) / 1000, Method: r.Method, URL: u, Host: host, MitM: mitm, start: time.Now(), ring: l}
	l.push(e)
	return e
}

// AddFailure records a TLS handshake failure (pinning) as a pseudo entry.
func (l *RequestLog) AddFailure(host, why string) {
	e := &Entry{ID: l.seq.Add(1), Time: float64(time.Now().UnixMilli()) / 1000, Method: "TLS", URL: "https://" + host + "/", Host: host,
		MitM: true, Done: true, Notes: []string{"握手失败，已放行：" + why}}
	l.push(e)
}

func (l *RequestLog) Clear() {
	l.mu.Lock()
	l.list = nil
	l.mu.Unlock()
}

// List returns summaries newer than since, newest first.
func (l *RequestLog) List(since int64) []Summary {
	l.mu.Lock()
	items := append([]*Entry(nil), l.list...)
	l.mu.Unlock()
	out := make([]Summary, 0, len(items))
	for i := len(items) - 1; i >= 0; i-- {
		e := items[i]
		if e.ID <= since {
			continue
		}
		e.mu.Lock()
		out = append(out, Summary{ID: e.ID, Time: e.Time, Method: e.Method, URL: e.URL, Host: e.Host, MitM: e.MitM, Status: e.Status,
			Matched: append([]string(nil), e.Matched...), Notes: append([]string(nil), e.Notes...), Local: e.IsLocal, Done: e.Done, Duration: e.Duration, Bytes: e.Bytes})
		e.mu.Unlock()
	}
	return out
}

// Get returns a full entry.
func (l *RequestLog) Get(id int64) *Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.list {
		if e.ID == id {
			return e
		}
	}
	return nil
}

// Hosts returns host -> matched-rule labels for recent requests (for marking connections).
func (l *RequestLog) Hosts() map[string][]string {
	l.mu.Lock()
	items := append([]*Entry(nil), l.list...)
	l.mu.Unlock()
	out := map[string][]string{}
	for _, e := range items {
		e.mu.Lock()
		set := out[e.Host]
		for _, m := range e.Matched {
			found := false
			for _, s := range set {
				if s == m {
					found = true
				}
			}
			if !found && len(set) < 6 {
				set = append(set, m)
			}
		}
		if set == nil {
			set = []string{}
		}
		out[e.Host] = set
		e.mu.Unlock()
	}
	return out
}

func (e *Entry) Match(label string) {
	e.mu.Lock()
	e.Matched = append(e.Matched, label)
	e.mu.Unlock()
}

func (e *Entry) Note(s string) {
	e.mu.Lock()
	e.Notes = append(e.Notes, s)
	e.mu.Unlock()
}

func (e *Entry) SetURL(u string) {
	e.mu.Lock()
	e.URL = u
	e.mu.Unlock()
}

func flatHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out[k] = strings.Join(h[k], ", ")
	}
	return out
}

func (e *Entry) ReqHeaders(method string, h http.Header) {
	e.mu.Lock()
	e.Method = method
	e.ReqHdr = flatHeaders(h)
	e.mu.Unlock()
}

func (e *Entry) Response(status int, h http.Header) {
	e.mu.Lock()
	e.Status = status
	e.RespHdr = flatHeaders(h)
	e.mu.Unlock()
}

func textOrBinary(b []byte) (string, int) {
	if len(b) > captureLimit {
		b = b[:captureLimit]
	}
	if utf8.Valid(b) || utf8.Valid(trimPartialRune(b)) {
		return string(b), 0
	}
	return "", len(b)
}

func trimPartialRune(b []byte) []byte {
	for i := 0; i < 3 && len(b) > 0; i++ {
		if utf8.Valid(b) {
			return b
		}
		b = b[:len(b)-1]
	}
	return b
}

func (e *Entry) ReqBody(b []byte) {
	s, bin := textOrBinary(b)
	e.mu.Lock()
	e.ReqBodyS, e.ReqBin = s, bin
	e.mu.Unlock()
}

func (e *Entry) RespBody(b []byte, enc string) {
	if enc != "" {
		if d, err := decodeBody(enc, b); err == nil {
			b = d
			enc = ""
		}
	}
	s, bin := textOrBinary(b)
	e.mu.Lock()
	e.RespBodyS, e.RespBin, e.RespEnc = s, bin, enc
	e.mu.Unlock()
}

func (e *Entry) AddBytes(n int) {
	e.mu.Lock()
	e.Bytes += int64(n)
	e.mu.Unlock()
}

// Local marks a response produced by the engine itself.
func (e *Entry) Local(status int, h http.Header, body []byte, capture bool) {
	e.mu.Lock()
	e.IsLocal = true
	e.Status = status
	e.RespHdr = flatHeaders(h)
	e.Bytes = int64(len(body))
	e.mu.Unlock()
	if capture && len(body) > 0 {
		e.RespBody(body, "")
	}
	e.Finish(-1, "")
}

// Finish closes the entry; status -1 keeps the recorded status.
func (e *Entry) Finish(status int, note string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.Done {
		return
	}
	e.Done = true
	if status >= 0 {
		e.Status = status
	}
	if note != "" {
		e.Notes = append(e.Notes, note)
	}
	if !e.start.IsZero() {
		e.Duration = float64(time.Since(e.start).Microseconds()) / 1000
	}
}

// ---- script log ----

// LogLine is a console / engine message from a script.
type LogLine struct {
	ID     int64   `json:"id"`
	Time   float64 `json:"time"`
	Script string  `json:"script"`
	Level  string  `json:"level"`
	Msg    string  `json:"msg"`
}

// LogRing keeps the last N script log lines.
type LogRing struct {
	mu    sync.Mutex
	max   int
	lines []LogLine
	seq   int64
	hook  func(LogLine)
}

func NewLogRing(max int) *LogRing { return &LogRing{max: max} }

func (l *LogRing) Add(script, level, msg string) {
	if len(msg) > 4000 {
		msg = msg[:4000] + "…"
	}
	l.mu.Lock()
	l.seq++
	ln := LogLine{ID: l.seq, Time: float64(time.Now().UnixMilli()) / 1000, Script: script, Level: level, Msg: msg}
	l.lines = append(l.lines, ln)
	if len(l.lines) > l.max {
		copy(l.lines, l.lines[len(l.lines)-l.max:])
		l.lines = l.lines[:l.max]
	}
	hook := l.hook
	l.mu.Unlock()
	if hook != nil {
		hook(ln)
	}
}

// SetHook forwards every new line (e.g. to mihomo's log).
func (l *LogRing) SetHook(h func(LogLine)) {
	l.mu.Lock()
	l.hook = h
	l.mu.Unlock()
}

func (l *LogRing) List(since int64, script string) []LogLine {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []LogLine{}
	for _, ln := range l.lines {
		if ln.ID > since && (script == "" || ln.Script == script) {
			out = append(out, ln)
		}
	}
	return out
}

func (l *LogRing) Clear() {
	l.mu.Lock()
	l.lines = nil
	l.mu.Unlock()
}
