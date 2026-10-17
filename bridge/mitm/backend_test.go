package mitm

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

const backendJS = `
const p = $request.url.split('/api/')[1] || '';
$done({status: 201, headers: {'Content-Type': 'application/json'}, body: JSON.stringify({path: p, method: $request.method, body: $request.body || ''})});
`

func TestHTTPBackend(t *testing.T) {
	it, ok := ParseBackendLine("box.js, tag=BoxJS, path=^/api/, img-url=https://x/y.png, enabled=true")
	if !ok || it.Tag != "BoxJS" || it.Path != "^/api/" || !it.Enabled {
		t.Fatalf("parse: %+v %v", it, ok)
	}
	if _, ok := ParseBackendLine("# box.js, path=^/"); ok {
		t.Fatal("comment parsed")
	}
	cfg := &Config{HTTPBackend: &HTTPBackendConfig{Enabled: true, Port: 19999, Items: []BackendItem{it}}}
	h := newHarness(t, cfg, map[string]string{"box.js": backendJS})
	h.e.Reload(cfg, Build(h.home, cfg))
	defer h.e.Stop()
	if st := h.e.backend.status(); st["running"] != true {
		t.Fatalf("not running: %v", st)
	}
	resp, err := http.Post("http://127.0.0.1:19999/api/save", "text/plain", strings.NewReader("hi"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 201 || string(b) != `{"path":"save","method":"POST","body":"hi"}` {
		t.Fatalf("backend: %d %s", resp.StatusCode, b)
	}
	resp, err = http.Get("http://127.0.0.1:19999/other")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("unmatched: %d", resp.StatusCode)
	}
	cfg2 := &Config{HTTPBackend: &HTTPBackendConfig{Enabled: false, Items: []BackendItem{it}}}
	h.e.Reload(cfg2, Build(h.home, cfg2))
	if st := h.e.backend.status(); st["running"] != false {
		t.Fatalf("still running: %v", st)
	}
}
