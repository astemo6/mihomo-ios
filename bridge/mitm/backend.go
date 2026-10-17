package mitm

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dlclark/regexp2"
)

// QX [http_backend] (QX preview 5): a small local HTTP server inside the tunnel. Each backend is a
// script with a path regex; a request to http://127.0.0.1:<port>/<path> (default 9999) runs the first
// enabled backend whose regex matches the path, with $request like an http-request script, and answers
// with $done({status, headers, body}) or $done({response: {…}}).

// HTTPBackendConfig is the user's HTTP Backend page.
type HTTPBackendConfig struct {
	Enabled bool          `json:"enabled"`
	Port    int           `json:"port,omitempty"` // 0 = 9999
	Items   []BackendItem `json:"items,omitempty"`
}

// BackendItem is one [http_backend] line: "<script>, tag=…, path=<regex>, img-url=…, enabled=…".
type BackendItem struct {
	Tag     string `json:"tag"`
	Script  string `json:"script"`
	Path    string `json:"path"`
	ImgURL  string `json:"imgURL,omitempty"`
	Enabled bool   `json:"enabled"`
}

// DefaultBackendPort is QX's default.
const DefaultBackendPort = 9999

func (c *HTTPBackendConfig) port() int {
	if c == nil || c.Port <= 0 || c.Port > 65535 {
		return DefaultBackendPort
	}
	return c.Port
}

// Active reports whether the server should run.
func (c *HTTPBackendConfig) Active() bool {
	if c == nil || !c.Enabled {
		return false
	}
	for _, it := range c.Items {
		if it.Enabled && it.Script != "" {
			return true
		}
	}
	return false
}

// ParseBackendLine parses one QX [http_backend] line.
func ParseBackendLine(line string) (BackendItem, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
		return BackendItem{}, false
	}
	parts := strings.Split(line, ",")
	it := BackendItem{Script: strings.TrimSpace(parts[0]), Enabled: true}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "tag":
			it.Tag = v
		case "path":
			it.Path = v
		case "img-url":
			it.ImgURL = v
		case "enabled":
			it.Enabled = !strings.EqualFold(v, "false")
		}
	}
	if it.Script == "" || it.Path == "" {
		return BackendItem{}, false
	}
	if it.Tag == "" {
		it.Tag = scriptBaseName(it.Script)
	}
	return it, true
}

func scriptBaseName(p string) string {
	p = strings.SplitN(p, "?", 2)[0]
	if i := strings.LastIndex(p, "/"); i >= 0 {
		p = p[i+1:]
	}
	return strings.TrimSuffix(p, ".js")
}

type backendServer struct {
	mu    sync.Mutex
	e     *Engine
	ln    net.Listener
	srv   *http.Server
	port  int
	items []compiledBackend
	err   string
}

type compiledBackend struct {
	BackendItem
	re *regexp2.Regexp
}

func newBackendServer(e *Engine) *backendServer { return &backendServer{e: e} }

// reload starts, restarts (port change) or stops the listener and swaps the backends.
func (b *backendServer) reload(c *HTTPBackendConfig) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !c.Active() {
		b.stopLocked()
		b.err = ""
		return
	}
	var items []compiledBackend
	for _, it := range c.Items {
		if !it.Enabled || it.Script == "" {
			continue
		}
		re, err := regexp2.Compile(it.Path, regexp2.None)
		if err != nil {
			b.e.logf("warning", fmt.Sprintf("[HTTP Backend] %s：路径正则无效（%v）", it.Tag, err))
			continue
		}
		items = append(items, compiledBackend{BackendItem: it, re: re})
	}
	b.items = items
	port := c.port()
	if b.ln != nil && b.port == port {
		return
	}
	b.stopLocked()
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		b.err = fmt.Sprintf("端口 %d 无法监听：%v", port, err)
		b.e.logf("warning", "[HTTP Backend] "+b.err)
		return
	}
	b.err = ""
	b.ln, b.port = ln, port
	b.srv = &http.Server{
		Handler:           http.HandlerFunc(b.serve),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	srv := b.srv
	go func() { _ = srv.Serve(ln) }()
	b.e.logf("info", fmt.Sprintf("[HTTP Backend] 已启动 http://127.0.0.1:%d（%d 个后端）", port, len(items)))
}

func (b *backendServer) stop() {
	b.mu.Lock()
	b.stopLocked()
	b.mu.Unlock()
}

func (b *backendServer) stopLocked() {
	if b.srv != nil {
		_ = b.srv.Close()
	}
	b.srv, b.ln, b.port = nil, nil, 0
}

// Status is shown on the HTTP Backend page.
func (b *backendServer) status() map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	return map[string]any{"running": b.ln != nil, "port": b.port, "backends": len(b.items), "error": b.err}
}

func (b *backendServer) match(path string) *compiledBackend {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range b.items {
		if ok, _ := b.items[i].re.MatchString(path); ok {
			it := b.items[i]
			return &it
		}
	}
	return nil
}

func (b *backendServer) serve(w http.ResponseWriter, r *http.Request) {
	be := b.match(r.URL.RequestURI())
	if be == nil {
		be = b.match(r.URL.Path)
	}
	if be == nil {
		writeLocal(w, http.StatusNotFound, http.Header{"Content-Type": {"text/plain; charset=utf-8"}}, []byte("HTTP Backend: no backend matches "+r.URL.Path))
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	host := r.Host
	if host == "" {
		host = fmt.Sprintf("127.0.0.1:%d", b.port)
	}
	req := &ScriptHTTP{URL: "http://" + host + r.URL.RequestURI(), Method: r.Method, Header: r.Header.Clone(), Body: body, HasBody: len(body) > 0}
	sc := &Script{Name: be.Tag, Type: "http-request", Path: be.Script, RequiresBody: true, Echo: true, Timeout: 60}
	rule := &Rule{Kind: KindScript, Phase: "request", Pattern: be.Path, Script: sc, Source: "HTTP Backend", Desc: be.Tag}
	ctx, cancel := context.WithTimeout(r.Context(), 65*time.Second)
	defer cancel()
	res, err := b.e.scripts.Run(ctx, rule, req, nil)
	if err != nil {
		b.e.logf("warning", fmt.Sprintf("[HTTP Backend] %s：%v", be.Tag, err))
		writeLocal(w, http.StatusBadGateway, http.Header{"Content-Type": {"text/plain; charset=utf-8"}}, []byte(err.Error()))
		return
	}
	if res != nil && res.Response != nil {
		st := res.Response.Status
		if st == 0 {
			st = http.StatusOK
		}
		h := res.Response.Header
		if h == nil {
			h = http.Header{}
		}
		writeLocal(w, st, h, res.Response.Body)
		return
	}
	writeLocal(w, http.StatusNoContent, http.Header{}, nil)
}
