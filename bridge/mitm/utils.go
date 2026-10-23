package mitm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// GeoLookup resolves an IP to (ISO country, ASN number, AS organisation). Installed by the bridge
// from mihomo's MMDB / ASN readers; nil (or empty results) when the databases are missing.
type GeoLookup func(ip string) (country, asn, org string)

// SetGeoLookup installs the $utils geo backend.
func (e *Engine) SetGeoLookup(g GeoLookup) { e.geo.Store(&g) }

func (e *Engine) lookup(ip string) (string, string, string) {
	if g := e.geo.Load(); g != nil && *g != nil {
		return (*g)(strings.TrimSpace(ip))
	}
	return "", "", ""
}

// inflateAny accepts gzip, zlib or raw deflate. Output past MaxBody is an error (review5 P1-1:
// never hand a script a silently truncated result).
func inflateAny(b []byte) ([]byte, error) {
	return inflateLimited(b, MaxBody)
}

// ---------------- notification history ----------------

// Notice is one $notification.post / $notify call, kept so the app can list what scripts posted
// (the extension also shows it as a local notification).
type Notice struct {
	Time     float64 `json:"time"`
	Script   string  `json:"script"`
	Title    string  `json:"title"`
	Subtitle string  `json:"subtitle,omitempty"`
	Body     string  `json:"body,omitempty"`
	URL      string  `json:"url,omitempty"`
}

// NoticeLog is a small ring persisted at <home>/engine/notifications.json.
type NoticeLog struct {
	mu   sync.Mutex
	path string
	max  int
}

func NewNoticeLog(home string, max int) *NoticeLog {
	return &NoticeLog{path: filepath.Join(EngineDir(home), "notifications.json"), max: max}
}

func (l *NoticeLog) read() []Notice {
	var out []Notice
	if b, err := os.ReadFile(l.path); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

const (
	noticeShortMax = 256              // title / subtitle
	noticeLongMax  = 4 << 10          // body / url
	noticeBurst    = 5                // per script ...
	noticeWindow   = 10 * time.Second // ... per window
)

// clipBytes cuts s to at most n bytes on a UTF-8 boundary.
func clipBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	i := n
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return s[:i] + "…"
}

// noticeLimiter allows noticeBurst notifications per script per noticeWindow.
type noticeLimiter struct {
	mu   sync.Mutex
	seen map[string][]time.Time
}

var noticeRate = &noticeLimiter{seen: map[string][]time.Time{}}

func (l *noticeLimiter) allow(script string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	ts := l.seen[script]
	keep := ts[:0]
	for _, t := range ts {
		if now.Sub(t) < noticeWindow {
			keep = append(keep, t)
		}
	}
	if len(keep) >= noticeBurst {
		l.seen[script] = keep
		return false
	}
	l.seen[script] = append(keep, now)
	if len(l.seen) > 256 { // forget idle scripts
		for k, v := range l.seen {
			if len(v) == 0 || now.Sub(v[len(v)-1]) >= noticeWindow {
				delete(l.seen, k)
			}
		}
	}
	return true
}

// Add appends (newest last) and trims to max. Fields are clipped (review5 P2-6).
func (l *NoticeLog) Add(n Notice) {
	n.Title, n.Subtitle = clipBytes(n.Title, noticeShortMax), clipBytes(n.Subtitle, noticeShortMax)
	n.Body, n.URL = clipBytes(n.Body, noticeLongMax), clipBytes(n.URL, noticeLongMax)
	l.mu.Lock()
	defer l.mu.Unlock()
	if n.Time == 0 {
		n.Time = float64(time.Now().UnixMilli()) / 1000
	}
	list := append(l.read(), n)
	if len(list) > l.max {
		list = list[len(list)-l.max:]
	}
	b, _ := json.Marshal(list)
	_ = os.MkdirAll(filepath.Dir(l.path), 0o755)
	_ = writeAtomic(l.path, b, 0o644)
}

// List returns newest first.
func (l *NoticeLog) List() []Notice {
	l.mu.Lock()
	defer l.mu.Unlock()
	list := l.read()
	for i, j := 0, len(list)-1; i < j; i, j = i+1, j-1 {
		list[i], list[j] = list[j], list[i]
	}
	if list == nil {
		list = []Notice{}
	}
	return list
}
