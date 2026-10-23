package mitm

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// feat/native-mitm stage 1: response bodies that only scripts read go through the native lane (nativelane.go)
// instead of the Go heap. These tests drive the real engine with fakeLane (fakelane_test.go) standing in for
// PacketTunnel/NativeBodyStore.swift and the goja-backed native stand-in for JSCScriptEngine.swift.

// laneUpstream serves /body?enc=gzip|br|deflate|identity&n=<bytes> (a JSON document of about n bytes, encoded
// as asked, Content-Length set) and /slow (a body that trickles, for disconnects).
func laneUpstream(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	var mu sync.Mutex
	cache := map[string][]byte{} // encoded bodies made once (the heap test must not measure the upstream)
	mux.HandleFunc("/body", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		enc := r.URL.Query().Get("enc")
		if enc != "gzip" && enc != "deflate" && enc != "br" {
			enc = ""
		}
		key := enc + "/" + strconv.Itoa(n)
		mu.Lock()
		b, ok := cache[key]
		mu.Unlock()
		if !ok {
			b = laneEncode(laneDoc(n), enc)
			mu.Lock()
			cache[key] = b
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		if enc != "" {
			w.Header().Set("Content-Encoding", enc)
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fl, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, `{"pad":"`)
		for i := 0; i < 200; i++ {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(20 * time.Millisecond):
			}
			_, _ = w.Write(bytes.Repeat([]byte("x"), 4096))
			if fl != nil {
				fl.Flush()
			}
		}
		_, _ = io.WriteString(w, `"}`)
	})
	return mux
}

func laneEncode(doc []byte, enc string) []byte {
	var b []byte
	switch enc {
	case "gzip":
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(doc)
		_ = zw.Close()
		b = buf.Bytes()
	case "deflate":
		var buf bytes.Buffer
		zw := zlib.NewWriter(&buf)
		_, _ = zw.Write(doc)
		_ = zw.Close()
		b = buf.Bytes()
	case "br":
		b = brEncode(doc)
	default:
		b = doc
	}
	return b
}

// laneDoc is a JSON object {"vip":false,"pad":"…"} of about n bytes (n < 64: just the flag).
func laneDoc(n int) []byte {
	pad := max(n-30, 0)
	var b strings.Builder
	b.WriteString(`{"vip":false,"pad":"`)
	x := uint32(2463534242)
	for i := 0; i < pad; i++ {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b.WriteByte("abcdefghijklmnopqrstuvwxyz0123456789"[x%36])
	}
	b.WriteString(`"}`)
	return []byte(b.String())
}

func newLaneHarness(t *testing.T, cfg *Config, scripts map[string]string) *harness {
	t.Helper()
	home := t.TempDir()
	ca, err := GenerateCA(home)
	if err != nil {
		t.Fatal(err)
	}
	up := httptest.NewUnstartedServer(laneUpstream(t))
	up.EnableHTTP2 = true
	up.StartTLS()
	t.Cleanup(up.Close)
	upAddr := up.Listener.Addr().String()
	_ = os.MkdirAll(ScriptsDir(home), 0o755)
	for name, src := range scripts {
		if err := os.WriteFile(filepath.Join(ScriptsDir(home), name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dial := func(ctx context.Context, network, addr, policy string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", upAddr)
	}
	e := New(home, dial, func(level, msg string) {})
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)
	cfg.SkipCertVerify = true
	e.Reload(cfg, Build(home, cfg))
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", e.Port()))
	tr := &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: pool}, ForceAttemptHTTP2: true, DisableCompression: true}
	return &harness{t: t, home: home, e: e, ca: ca, up: up, client: &http.Client{Transport: tr, Timeout: 20 * time.Second}}
}

func laneCfg(extra string) *Config {
	return &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`vip = type=http-response,pattern=^https://api\.test\.com/body,requires-body=1,max-size=-1,script-path=vip.js` + extra)}
}

const vipJS = `var o = JSON.parse($response.body); o.vip = true; $done({body: JSON.stringify(o)});`

// fetchBody GETs u and returns the decoded body the client got plus the response.
func fetchBody(t *testing.T, h *harness, u string) (*http.Response, []byte) {
	t.Helper()
	resp, err := h.client.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	var r io.Reader = resp.Body
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		zr, err := gzip.NewReader(r)
		if err != nil {
			t.Fatal(err)
		}
		r = zr
	case "deflate":
		zr, err := zlib.NewReader(r)
		if err != nil {
			t.Fatal(err)
		}
		r = zr
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read %s: %v", u, err)
	}
	return resp, b
}

// waitLive waits for the lane to hold no handles (the client's body close frees them asynchronously).
func waitLive(t *testing.T, l *fakeLane) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for l.live() != 0 || laneLive.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("lane still holds %d handles (Go side counts %d)", l.live(), laneLive.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestLaneScriptRewritesEveryEncoding(t *testing.T) {
	l := useFakeLane(t)
	for _, mode := range []string{"", ",binary-body-mode=1"} {
		js := vipJS
		if mode != "" {
			js = `var o = JSON.parse(new TextDecoder().decode($response.body)); o.vip = true; $done({body: new TextEncoder().encode(JSON.stringify(o))});`
		}
		h := newLaneHarness(t, laneCfg(mode), map[string]string{"vip.js": js})
		for _, enc := range []string{"identity", "gzip", "deflate", "br"} {
			for _, n := range []int{100, 300 << 10} { // small result: ordinary put; large: stays in the lane
				opened, stored, takes := l.opened.Load(), l.stored.Load(), l.engineTakes.Load()
				resp, b := fetchBody(t, h, fmt.Sprintf("https://api.test.com/body?enc=%s&n=%d", enc, n))
				if !bytes.HasPrefix(b, []byte(`{"vip":true,`)) {
					t.Fatalf("mode %q enc %s n %d: script result missing: %q", mode, enc, n, clip(string(b), 60))
				}
				if resp.Header.Get("Content-Encoding") != "" {
					t.Fatalf("enc %s: Content-Encoding %q left on a decoded body", enc, resp.Header.Get("Content-Encoding"))
				}
				if cl := resp.Header.Get("Content-Length"); cl != "" && cl != strconv.Itoa(len(b)) {
					t.Fatalf("enc %s: Content-Length %s for %d bytes", enc, cl, len(b))
				}
				if l.opened.Load() != opened+1 {
					t.Fatalf("mode %q enc %s n %d: body did not go through the lane", mode, enc, n)
				}
				if l.engineTakes.Load() == takes {
					t.Fatalf("mode %q enc %s: the engine did not read the body from the lane", mode, enc)
				}
				if big := n > fakeLanePutMin; big != (l.stored.Load() > stored) {
					t.Fatalf("mode %q enc %s n %d: large result stored in lane = %v", mode, enc, n, l.stored.Load() > stored)
				}
				waitLive(t, l)
			}
		}
	}
}

func TestLaneUntouchedAndHeaderOnly(t *testing.T) {
	l := useFakeLane(t)
	h := newLaneHarness(t, laneCfg(""), map[string]string{"vip.js": `$response.headers["X-Seen"] = "1"; $done($response)`})
	resp, b := fetchBody(t, h, "https://api.test.com/body?enc=br&n=200000")
	if !bytes.Equal(b, laneDoc(200000)) {
		t.Fatalf("untouched body changed (%d bytes)", len(b))
	}
	if resp.Header.Get("X-Seen") != "1" {
		t.Fatal("header change lost")
	}
	if l.opened.Load() != 1 || l.stored.Load() != 0 {
		t.Fatalf("opened %d stored %d", l.opened.Load(), l.stored.Load())
	}
	waitLive(t, l)
}

func TestLaneRefusedTakesGoPath(t *testing.T) {
	l := useFakeLane(t)
	l.refuse.Store(true)
	h := newLaneHarness(t, laneCfg(""), map[string]string{"vip.js": vipJS})
	_, b := fetchBody(t, h, "https://api.test.com/body?enc=gzip&n=5000")
	if !bytes.HasPrefix(b, []byte(`{"vip":true,`)) {
		t.Fatalf("Go path after a refusal: %q", clip(string(b), 60))
	}
	if l.opened.Load() != 0 {
		t.Fatal("lane opened a body it refused")
	}
}

func TestLaneFailurePassesThroughAndTripsBreaker(t *testing.T) {
	l := useFakeLane(t)
	l.failWrite.Store(true)
	h := newLaneHarness(t, laneCfg(""), map[string]string{"vip.js": vipJS})
	for i := 0; i < laneBreakerFails; i++ {
		resp, b := fetchBody(t, h, "https://api.test.com/body?enc=gzip&n=5000")
		if !bytes.Equal(b, laneDoc(5000)) {
			t.Fatalf("attempt %d: original not passed through: %q", i, clip(string(b), 60))
		}
		if resp.Header.Get("Content-Encoding") != "gzip" {
			t.Fatalf("attempt %d: pass-through lost its Content-Encoding", i)
		}
	}
	if laneUsable() != nil {
		t.Fatal("breaker did not trip")
	}
	// tripped: the Go path runs the script again
	opened := l.opened.Load()
	_, b := fetchBody(t, h, "https://api.test.com/body?enc=gzip&n=5000")
	if !bytes.HasPrefix(b, []byte(`{"vip":true,`)) || l.opened.Load() != opened {
		t.Fatalf("after the breaker: %q (lane opened %d more)", clip(string(b), 60), l.opened.Load()-opened)
	}
	waitLive(t, l)
	ResetLaneBreaker()
	if laneUsable() == nil {
		t.Fatal("reset did not re-enable the lane")
	}
}

func TestLaneTooBigPassesOriginal(t *testing.T) {
	l := useFakeLane(t)
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`vip = type=http-response,pattern=^https://api\.test\.com/body,requires-body=1,max-size=4096,script-path=vip.js`)}
	h := newLaneHarness(t, cfg, map[string]string{"vip.js": vipJS})
	// chunked gzip (no announced decoded size): decodes past max-size inside the lane
	resp, b := fetchBody(t, h, "https://api.test.com/body?enc=gzip&n=50000")
	if !bytes.Equal(b, laneDoc(50000)) || resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("too-big body not passed through as received (enc %q, %d bytes)", resp.Header.Get("Content-Encoding"), len(b))
	}
	if notes := entryNotes(h.e); !strings.Contains(notes, "跳过脚本") {
		t.Fatalf("notes %q", notes)
	}
	waitLive(t, l)
}

func TestLaneClientGoneFreesHandle(t *testing.T) {
	l := useFakeLane(t)
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`vip = type=http-response,pattern=^https://api\.test\.com/slow,requires-body=1,max-size=-1,script-path=vip.js`)}
	h := newLaneHarness(t, cfg, map[string]string{"vip.js": vipJS})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.test.com/slow", nil)
	if resp, err := h.client.Do(req); err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if l.opened.Load() != 1 {
		t.Fatalf("opened %d", l.opened.Load())
	}
	waitLive(t, l)
}

// TestLaneGojaMaterialises: a lane body handed to goja (the native engine wedged mid-session) is copied into
// the Go heap on take, so the script still sees it.
func TestLaneGojaMaterialises(t *testing.T) {
	l := useFakeLane(t)
	h := l.Open("", 1<<20, -1)
	_ = l.Write(h, laneDoc(1000))
	if n := l.Finish(h); n != int64(len(laneDoc(1000))) {
		t.Fatalf("finish %d", n)
	}
	defer l.Free(h)
	SetNativeEngine(nil) // goja
	e := New(t.TempDir(), nil, nil)
	sc := &Script{Name: "t", Type: "http-response", Path: "t.js", RequiresBody: true, Source: []byte(vipJS)}
	res, err := e.scripts.Run(context.Background(), &Rule{Kind: KindScript, Phase: "response", Script: sc},
		&ScriptHTTP{URL: "https://x/", Method: "GET", Header: http.Header{}},
		&ScriptHTTP{Status: 200, Header: http.Header{}, HasBody: true, NativeBody: h})
	if err != nil {
		t.Fatal(err)
	}
	if !res.BodySet || res.NativeBody != 0 || !bytes.HasPrefix(res.Body, []byte(`{"vip":true,`)) {
		t.Fatalf("goja result: set=%v native=%d %q", res.BodySet, res.NativeBody, clip(string(res.Body), 40))
	}
}

// TestLaneKeepsGoHeapFlat: a 3 MB gzip body handed to a script through the lane leaves the Go heap almost
// untouched; through the Go path the decoded and the compressed bytes are both on it.
func TestLaneKeepsGoHeapFlat(t *testing.T) {
	const n = 3 << 20
	js := `$done({})` // reads nothing: measures what the host side holds for the body
	measure := func(withLane bool) uint64 {
		var l *fakeLane
		if withLane {
			l = useFakeLane(t)
		} else {
			old, _ := nativeJS.Load().(nativeBox)
			SetNativeEngine(newFakeNative())
			t.Cleanup(func() {
				if old.n != nil {
					nativeJS.Store(old)
				} else {
					SetNativeEngine(nil)
				}
			})
		}
		h := newLaneHarness(t, laneCfg(""), map[string]string{"vip.js": js})
		get := func() {
			resp, err := h.client.Get(fmt.Sprintf("https://api.test.com/body?enc=gzip&n=%d", n))
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		get() // warm: compile, TLS, h2, leaf certs
		base, peak := peakHeapDuring(get)
		if withLane {
			if l.opened.Load() != 2 {
				t.Fatalf("lane opened %d", l.opened.Load())
			}
			waitLive(t, l)
			activeFakeLane.Store(nil)
			SetNativeBodies(nil)
		}
		return peak - base
	}
	// aggressive GC: the peak then follows what is held, not the 32 KB chunk garbage both paths make
	defer debug.SetGCPercent(debug.SetGCPercent(5))
	goPath := measure(false)
	lane := measure(true)
	t.Logf("Go heap peak above base: Go path %.1f MB, lane %.1f MB", float64(goPath)/(1<<20), float64(lane)/(1<<20))
	if lane*2 > goPath || lane > 5<<19 { // lane: transient 32 KB chunk copies (gomobile hands each Read back as a new slice), collected by the next GC
		t.Fatalf("lane did not keep the body off the Go heap: lane +%d KB vs Go path +%d KB", lane>>10, goPath>>10)
	}
}
