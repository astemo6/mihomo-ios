package mitm

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
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

// installUtils adds Surge / Loon $utils: geoip, ipasn, ipaso, ungzip.
func (rc *runCtx) installUtils(set func(string, any)) {
	rt := rc.rt
	u := rt.NewObject()
	_ = u.Set("geoip", func(call goja.FunctionCall) goja.Value {
		c, _, _ := rc.e.lookup(call.Argument(0).String())
		if c == "" {
			return goja.Null()
		}
		return rt.ToValue(c)
	})
	_ = u.Set("ipasn", func(call goja.FunctionCall) goja.Value {
		_, a, _ := rc.e.lookup(call.Argument(0).String())
		if a == "" {
			return goja.Null()
		}
		return rt.ToValue(a)
	})
	_ = u.Set("ipaso", func(call goja.FunctionCall) goja.Value {
		_, _, o := rc.e.lookup(call.Argument(0).String())
		if o == "" {
			return goja.Null()
		}
		return rt.ToValue(o)
	})
	_ = u.Set("ungzip", func(call goja.FunctionCall) goja.Value {
		b, ok := rc.bodyBytes(call.Argument(0))
		if !ok {
			return goja.Null()
		}
		out, err := inflateAny(b)
		if err != nil {
			return goja.Null()
		}
		return rc.uint8Array(out)
	})
	set("$utils", u)
}

// inflateAny accepts gzip, zlib or raw deflate.
func inflateAny(b []byte) ([]byte, error) {
	lim := func(r io.Reader) ([]byte, error) { return io.ReadAll(io.LimitReader(r, MaxBody)) }
	if len(b) > 2 && b[0] == 0x1f && b[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		return lim(zr)
	}
	if zr, err := zlib.NewReader(bytes.NewReader(b)); err == nil {
		defer zr.Close()
		if out, err := lim(zr); err == nil {
			return out, nil
		}
	}
	fr := flate.NewReader(bytes.NewReader(b))
	defer fr.Close()
	return lim(fr)
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

// Add appends (newest last) and trims to max.
func (l *NoticeLog) Add(n Notice) {
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
