package mitm

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// YouTube report (v0.19.20): Maasea's YouTube (Music) Enhance module
// (https://raw.githubusercontent.com/Maasea/sgmodule/master/YouTube.Enhance.sgmodule, saved as testdata
// with its two scripts) "does nothing". These tests run the real module and scripts through the engine.

const (
	ytModuleURL   = "https://raw.githubusercontent.com/Maasea/sgmodule/master/YouTube.Enhance.sgmodule"
	ytResponseURL = "https://raw.githubusercontent.com/Maasea/sgmodule/master/Script/Youtube/youtube.response.js"
	ytRequestURL  = "https://raw.githubusercontent.com/Maasea/sgmodule/master/Script/Youtube/youtube.request.js"
)

func ytFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// --- a tiny protobuf writer for synthetic YouTube responses ---

func pbVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func pbBytes(b []byte, field int, payload []byte) []byte {
	b = pbVarint(b, uint64(field)<<3|2)
	b = pbVarint(b, uint64(len(payload)))
	return append(b, payload...)
}

func pbInt(b []byte, field int, v uint64) []byte {
	b = pbVarint(b, uint64(field)<<3)
	return pbVarint(b, v)
}

// pbTopFields lists the top-level field numbers of a protobuf message.
func pbTopFields(b []byte) ([]int, error) {
	var out []int
	readVarint := func() (uint64, error) {
		var v uint64
		for s := 0; s < 64; s += 7 {
			if len(b) == 0 {
				return 0, io.ErrUnexpectedEOF
			}
			c := b[0]
			b = b[1:]
			v |= uint64(c&0x7f) << s
			if c < 0x80 {
				return v, nil
			}
		}
		return 0, fmt.Errorf("varint overflow")
	}
	for len(b) > 0 {
		tag, err := readVarint()
		if err != nil {
			return nil, err
		}
		out = append(out, int(tag>>3))
		switch tag & 7 {
		case 0:
			if _, err := readVarint(); err != nil {
				return nil, err
			}
		case 1:
			b = b[8:]
		case 2:
			n, err := readVarint()
			if err != nil || int(n) > len(b) {
				return nil, fmt.Errorf("bad length")
			}
			b = b[n:]
		case 5:
			b = b[4:]
		default:
			return nil, fmt.Errorf("wire type %d", tag&7)
		}
	}
	return out, nil
}

// ytPlayerWithAds is a youtubei/v1/player response with an ad placement (field 7) and an ad slot
// (field 68) beside the playability status (field 2) the script keeps.
func ytPlayerWithAds() []byte {
	var status []byte
	status = pbInt(status, 1, 0)              // status OK
	status = pbBytes(status, 4, []byte("ok")) // reason
	var adRenderer []byte
	adRenderer = pbBytes(adRenderer, 1, bytes.Repeat([]byte("ad"), 50))
	var placement []byte
	placement = pbBytes(placement, 84813246, adRenderer)
	var b []byte
	b = pbBytes(b, 2, status)
	b = pbBytes(b, 7, placement)
	b = pbBytes(b, 7, placement)
	b = pbBytes(b, 68, []byte{0x0a, 0x02, 'x', 'y'})
	return b
}

func hasField(fs []int, n int) bool {
	for _, f := range fs {
		if f == n {
			return true
		}
	}
	return false
}

// TestYouTubeModuleParse: the module imports into 3 binary-mode body scripts, a parsed JSON $argument
// with the #!arguments defaults substituted, and both MitM hosts.
func TestYouTubeModuleParse(t *testing.T) {
	rs := &Ruleset{}
	rs.ParseText(ApplyModuleArgs(string(ytFile(t, "yt_enhance.sgmodule")), nil), "YouTube", nil)
	if len(rs.Errors) != 0 || len(rs.Unsupported) != 0 {
		t.Fatalf("errors %v unsupported %v", rs.Errors, rs.Unsupported)
	}
	var resp *Rule
	n := 0
	for _, r := range rs.Rules {
		if r.Kind != KindScript {
			t.Errorf("unexpected rule %s", r.Line)
			continue
		}
		n++
		if !r.Script.BinaryBody || !r.Script.RequiresBody {
			t.Errorf("%s: binary %v requires-body %v", r.Script.Name, r.Script.BinaryBody, r.Script.RequiresBody)
		}
		if r.Phase == "response" {
			resp = r
		}
	}
	if n != 3 || resp == nil {
		t.Fatalf("%d scripts, response %v", n, resp != nil)
	}
	want := `{"captionLang":"off","blockUpload":true,"blockImmersive":true,"blockShorts":false,"debug":false}`
	if resp.Script.Argument != want {
		t.Errorf("argument %q, want %q", resp.Script.Argument, want)
	}
	for _, u := range []string{
		"https://youtubei.googleapis.com/youtubei/v1/player?prettyPrint=false",
		"https://youtubei.googleapis.com/youtubei/v1/browse",
		"https://youtubei.googleapis.com/youtubei/v1/reel/reel_watch_sequence?x=1",
	} {
		if !resp.match(u) {
			t.Errorf("response pattern misses %s", u)
		}
	}
	for _, h := range []string{"*.googlevideo.com", "youtubei.googleapis.com"} {
		if !hasHost(rs, h) {
			t.Errorf("hostname %s missing (%v)", h, rs.Hostnames)
		}
	}
	// QUIC to both hosts is rejected so the app falls back to TCP, which is decrypted.
	rs.Hostnames = dedupe(rs.Hostnames)
	raw := map[string]any{"rules": []any{"MATCH,DIRECT"}}
	Inject(raw, 12345, rs, &Config{Enabled: true, MitM: true})
	payload := fmt.Sprint(raw["rule-providers"].(map[string]any)["__mitm_hosts"].(map[string]any)["payload"])
	if !strings.Contains(payload, "DOMAIN-WILDCARD,*.googlevideo.com") || !strings.Contains(payload, "DOMAIN,youtubei.googleapis.com") {
		t.Errorf("payload %s", payload)
	}
	if !strings.Contains(fmt.Sprint(raw["rules"]), "AND,((NETWORK,UDP),(DST-PORT,443),(RULE-SET,__mitm_hosts)),REJECT") {
		t.Errorf("no QUIC reject: %v", raw["rules"])
	}
}

// ytEngine starts an engine with one module (text saved as testdata file modFile) whose scripts are
// seeded from testdata, upstream an HTTP/2 TLS server answering /youtubei/v1/player with
// ytPlayerWithAds (gzip-encoded when ?gz=1); it returns a client that talks to the engine as the
// YouTube app does (CONNECT, TLS for youtubei.googleapis.com, h2).
// ytPlayerHandler, when set, answers youtubei/v1/player in ytEngine (large / encoded bodies).
var ytPlayerHandler http.HandlerFunc

func ytEngine(t *testing.T, modFile, modURL string, scripts map[string]string) (*http.Client, *[]string) {
	t.Helper()
	c, hits, _ := ytEngineE(t, modFile, modURL, scripts)
	return c, hits
}

// ytEngineE is ytEngine that also returns the engine (request notes, script log).
func ytEngineE(t *testing.T, modFile, modURL string, scripts map[string]string) (*http.Client, *[]string, *Engine) {
	t.Helper()
	home := t.TempDir()
	ca, err := GenerateCA(home)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(ModulePath(home, "yt")), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ModulePath(home, "yt"), ytFile(t, modFile), 0o644); err != nil {
		t.Fatal(err)
	}
	for u, f := range scripts {
		seedScript(t, home, u, ytFile(t, f))
	}
	player := ytPlayerWithAds()
	browse := ytFile(t, "yt_browse_ad.bin")
	var mu sync.Mutex
	hits := &[]string{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*hits = append(*hits, r.Host+r.URL.String())
		mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/youtubei/v1/browse") {
			w.Header().Set("Content-Type", "application/x-protobuf")
			_, _ = w.Write(browse)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/youtubei/v1/player") {
			_, _ = io.WriteString(w, "upstream")
			return
		}
		if ytPlayerHandler != nil {
			ytPlayerHandler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		if r.URL.Query().Get("gz") == "1" {
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			_, _ = zw.Write(player)
			_ = zw.Close()
			return
		}
		_, _ = w.Write(player)
	})
	up := httptest.NewUnstartedServer(mux)
	up.EnableHTTP2 = true
	up.StartTLS()
	t.Cleanup(up.Close)
	dial := func(ctx context.Context, network, addr, policy string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", up.Listener.Addr().String())
	}
	// Background resource downloads can still log after the test returns; t.Logf then panics
	// ("Log in goroutine after … has completed"), so the logger goes quiet once cleanup starts.
	var logMu sync.Mutex
	logDone := false
	e := New(home, dial, func(level, msg string) {
		logMu.Lock()
		defer logMu.Unlock()
		if !logDone {
			t.Logf("[%s] %s", level, msg)
		}
	})
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)
	t.Cleanup(func() { logMu.Lock(); logDone = true; logMu.Unlock() }) // runs before e.Stop (LIFO)
	cfg := &Config{Enabled: true, MitM: true, SkipCertVerify: true, Modules: []Module{{ID: "yt", Name: "YouTube", URL: modURL, Enabled: true}}}
	rs := Build(home, cfg)
	if len(rs.Errors) > 0 || len(rs.Unsupported) > 0 {
		t.Fatalf("module errors %v unsupported %v", rs.Errors, rs.Unsupported)
	}
	e.Reload(cfg, rs)
	h := &harness{t: t, home: home, e: e, ca: ca, up: up}
	dumpScriptLogs(h)
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", e.Port()))
	tr := &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: pool},
		ForceAttemptHTTP2: true, DisableCompression: true}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}, hits, e
}

// ytPlayerStripped POSTs youtubei/v1/player (plain and gzip upstream) and fails when the protobuf the
// app gets still carries ad placements (7) / ad slots (68) or lost the playability status (2).
func ytPlayerStripped(t *testing.T, c *http.Client) {
	t.Helper()
	for _, q := range []string{"prettyPrint=false", "prettyPrint=false&gz=1"} {
		req, _ := http.NewRequest("POST", "https://youtubei.googleapis.com/youtubei/v1/player?"+q, bytes.NewReader([]byte{0x0a, 0x00}))
		req.Header.Set("Content-Type", "application/x-protobuf")
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("POST player %s: %v", q, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.ProtoMajor != 2 {
			t.Errorf("%s: client side is %s, want HTTP/2", q, resp.Proto)
		}
		if resp.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(bytes.NewReader(body))
			if err != nil {
				t.Fatalf("%s: gzip header but %v", q, err)
			}
			body, _ = io.ReadAll(zr)
		}
		fs, err := pbTopFields(body)
		if err != nil {
			t.Fatalf("%s: response is not protobuf (%v): %q", q, err, clip(string(body), 80))
		}
		if hasField(fs, 7) || hasField(fs, 68) || !hasField(fs, 2) {
			t.Errorf("%s: ads not stripped, top-level fields %v (%d bytes)", q, fs, len(body))
		}
	}
}

// ytBrowseStripped POSTs youtubei/v1/browse whose feed (yt_browse_ad.bin, made by yt_browse_gen.js with
// the script's own protobuf types: three richItemContents, the middle one an ad whose unknown field
// carries "pagead") must come back without the ad item and with both other items.
func ytBrowseStripped(t *testing.T, c *http.Client) {
	t.Helper()
	req, _ := http.NewRequest("POST", "https://youtubei.googleapis.com/youtubei/v1/browse?prettyPrint=false", bytes.NewReader([]byte{0x0a, 0x00}))
	req.Header.Set("Content-Type", "application/x-protobuf")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST browse: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if bytes.Contains(body, []byte("pagead")) || bytes.Count(body, bytes.Repeat([]byte("z"), 1300)) != 2 {
		t.Errorf("feed ad not removed: %d bytes, pagead=%v clean items=%d", len(body), bytes.Contains(body, []byte("pagead")),
			bytes.Count(body, bytes.Repeat([]byte("z"), 1300)))
	}
}

// TestYouTubeEndToEnd: Surge module (binary-body-mode=1) — the real youtube.response.js strips the ads
// from an HTTP/2 youtubei/v1/player answer.
func TestYouTubeEndToEnd(t *testing.T) {
	c, _ := ytEngine(t, "yt_enhance.sgmodule", ytModuleURL, map[string]string{
		ytResponseURL: "yt_youtube.response.js", ytRequestURL: "yt_youtube.request.js"})
	ytPlayerStripped(t, c)
	ytBrowseStripped(t, c)
}

const ytQXURL = "https://raw.githubusercontent.com/ddgksf2013/Rewrite/master/AdBlock/YoutubeAds.conf"

// TestYouTubeQXEndToEnd: the most used QX rewrite (ddgksf2013 YoutubeAds.conf) runs the same
// youtube.response.js as `url script-response-body` — no binary flag in QX syntax, the script reads
// $response.bodyBytes like it does in Quantumult X (which always provides it). v0.19.20 only set
// bodyBytes for binary-body-mode rules, so the script saw no body and exited: no ad was removed.
func TestYouTubeQXEndToEnd(t *testing.T) {
	c, hits := ytEngine(t, "yt_ddgksf2013_qx.conf", ytQXURL, map[string]string{
		"https://raw.githubusercontent.com/Maasea/sgmodule/refs/heads/master/Script/Youtube/youtube.response.js": "yt_youtube.response.js"})
	ytPlayerStripped(t, c)
	ytBrowseStripped(t, c)
	// url reject-200 lines answer locally.
	for _, u := range []string{"https://www.youtube.com/api/stats/ads?x=1", "https://s.youtube.com/pagead/conversion"} {
		resp, err := c.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || len(b) != 0 {
			t.Errorf("%s: %d %q, want local empty 200", u, resp.StatusCode, b)
		}
	}
	for _, h := range *hits {
		if strings.Contains(h, "/api/stats/ads") || strings.Contains(h, "/pagead") {
			t.Errorf("rejected request reached upstream: %s", h)
		}
	}
}

// TestTextModeBodyBytes: a text-mode body script also gets $response.bodyBytes / $request.bodyBytes
// (ArrayBuffer of the raw bytes, as in Quantumult X), lazily and non-enumerable; $done({bodyBytes})
// replaces the body; $done($response) after `$response.body = x` keeps x (the untouched original
// bodyBytes beside it must not win) in text and binary mode.
func TestTextModeBodyBytes(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`^https://api\.test\.com/bin\?bytes=1 url script-response-body bytes.js`,
		`^https://api\.test\.com/json\?keys=1 url script-response-body keys.js`,
		`^https://api\.test\.com/json\?self=1 url script-response-body self.js`,
		`selfbin = type=http-response,pattern=^https://api\.test\.com/json\?selfbin=1,requires-body=1,binary-body-mode=1,script-path=self.js`,
		`^https://api\.test\.com/json\?inplace=1 url script-response-body inplace.js`,
	)}
	h := newHarness(t, cfg, map[string]string{
		// reverse the raw bytes of a non-UTF-8 body through bodyBytes (QX style)
		"bytes.js": `var u = new Uint8Array($response.bodyBytes); var out = new Uint8Array(u.length);
			for (var i = 0; i < u.length; i++) out[i] = u[u.length - 1 - i];
			$done({bodyBytes: out.buffer});`,
		"keys.js": `$done({body: JSON.stringify({keys: Object.keys($response).indexOf("bodyBytes"),
			len: $response.bodyBytes.byteLength, spread: ({...$response}).bodyBytes === undefined})});`,
		"self.js":    `$response.body = "changed"; $done($response);`,
		"inplace.js": `var u = new Uint8Array($response.bodyBytes); u[2] = 0x41; $done($response);`,
	})
	if _, body := h.get("https://api.test.com/bin?bytes=1"); !bytes.Equal([]byte(body), []byte{251, 250, 3, 2, 1, 0}) {
		t.Errorf("text-mode bodyBytes round trip: %v", []byte(body))
	}
	if _, body := h.get("https://api.test.com/json?keys=1"); body != `{"keys":-1,"len":41,"spread":true}` {
		t.Errorf("bodyBytes accessor: %s", body)
	}
	for _, q := range []string{"self=1", "selfbin=1"} {
		if _, body := h.get("https://api.test.com/json?" + q); body != "changed" {
			t.Errorf("%s: $done($response) after body change: %q", q, body)
		}
	}
	if _, body := h.get("https://api.test.com/json?inplace=1"); !strings.HasPrefix(body, `{"A`) {
		t.Errorf("in-place bodyBytes edit lost: %q", body)
	}
}

const ytLoonURL = "https://example.com/YouTube_remove_ads.plugin"

// TestYouTubeLoonArgument: Loon's argument=[{captionLang},{blockUpload},…] reaches the script as an
// object with typed values; before it was the string "[off,true,true,false,false]".
func TestYouTubeLoonArgument(t *testing.T) {
	rs := &Ruleset{}
	rs.ParseText(string(ytFile(t, "yt_loon.plugin")), "YouTube", map[string]string{"blockShorts": "true"})
	if len(rs.Errors) != 0 || len(rs.Unsupported) != 0 {
		t.Fatalf("errors %v unsupported %v", rs.Errors, rs.Unsupported)
	}
	var sc *Script
	for _, r := range rs.Rules {
		if r.Kind == KindScript {
			sc = r.Script
		}
	}
	if sc == nil || !sc.BinaryBody || !sc.ArgObject {
		t.Fatalf("script %+v", sc)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(sc.Argument), &got); err != nil {
		t.Fatalf("argument %q: %v", sc.Argument, err)
	}
	want := map[string]any{"captionLang": "off", "blockUpload": true, "blockImmersive": true, "blockShorts": true, "debug": false}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("argument %v, want %v", got, want)
	}
	if len(rs.CoreRules) != 2 {
		t.Errorf("core rules %v", rs.CoreRules)
	}
	// an argument list naming an undeclared key stays as written
	rs2 := &Ruleset{}
	rs2.ParseText("[Argument]\na = switch,true\n[Script]\nhttp-request ^https://x\\.test/ script-path=https://x.test/a.js, argument=[{a},{zz}]\n", "t", nil)
	if len(rs2.Rules) != 1 || rs2.Rules[0].Script.ArgObject {
		t.Errorf("undeclared key: %+v", rs2.Rules)
	}
}

// TestYouTubeLoonEndToEnd: the Loon plugin layout strips the ads too, and $argument is an object in the
// script.
func TestYouTubeLoonEndToEnd(t *testing.T) {
	c, _ := ytEngine(t, "yt_loon.plugin", ytLoonURL, map[string]string{ytResponseURL: "yt_youtube.response.js"})
	ytPlayerStripped(t, c)
	ytBrowseStripped(t, c)
}

// TestLoonObjectArgumentInScript: $argument is a real object (typeof, property access, JSON.stringify).
func TestLoonObjectArgumentInScript(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}}
	h := newHarness(t, cfg, map[string]string{"arg.js": `$done({body: JSON.stringify({t: typeof $argument, n: $argument.n + 1, s: $argument.s, all: $argument})});`})
	mod := "#!name=t\n[Argument]\nn = input,\"41\",type=number\ns = switch,true\n[Script]\nhttp-response ^https://api\\.test\\.com/json\\?arg=1 script-path=arg.js, requires-body=true, argument=[{n},{s}]\n"
	_ = os.MkdirAll(filepath.Dir(ModulePath(h.home, "m")), 0o755)
	_ = os.WriteFile(ModulePath(h.home, "m"), []byte(mod), 0o644)
	cfg.Modules = []Module{{ID: "m", Name: "t", Enabled: true}}
	h.e.Reload(cfg, Build(h.home, cfg))
	if _, body := h.get("https://api.test.com/json?arg=1"); body != `{"t":"object","n":42,"s":true,"all":{"n":41,"s":true}}` {
		t.Errorf("object $argument: %s", body)
	}
}

// TestTypicalSurgeModuleHits: "all rewrites broken" regression guard — a typical Surge module (URL
// Rewrite reject types, Header Rewrite, Map Local, a text-mode response script, %APPEND% hostnames)
// loaded as a module, every rule answers / changes its request.
func TestTypicalSurgeModuleHits(t *testing.T) {
	mod := `#!name=Typical
[URL Rewrite]
^https?:\/\/api\.test\.com\/ad\b - reject
^https?:\/\/api\.test\.com\/r200 - reject-200
^https?:\/\/api\.test\.com\/rdict - reject-dict
^https?:\/\/api\.test\.com\/rimg - reject-img
[Header Rewrite]
^https?:\/\/api\.test\.com\/echo header-add X-Mod 1
[Map Local]
^https?:\/\/api\.test\.com\/ml data-type=text data="local" status-code=200
[Script]
s = type=http-response,pattern=^https?:\/\/api\.test\.com\/json,requires-body=1,script-path=s.js
[MITM]
hostname = %APPEND% api.test.com
`
	cfg := &Config{Enabled: true, MitM: true}
	h := newHarness(t, cfg, map[string]string{"s.js": `$done({body: $response.body.replace('"ad":true', '"ad":false')})`})
	_ = os.MkdirAll(filepath.Dir(ModulePath(h.home, "typ")), 0o755)
	_ = os.WriteFile(ModulePath(h.home, "typ"), []byte(mod), 0o644)
	cfg.Modules = []Module{{ID: "typ", Name: "Typical", Enabled: true}}
	rs := Build(h.home, cfg)
	if len(rs.Errors)+len(rs.Unsupported) > 0 || len(rs.Rules) != 7 {
		t.Fatalf("rules %d errors %v unsupported %v", len(rs.Rules), rs.Errors, rs.Unsupported)
	}
	h.e.Reload(cfg, rs)
	check := func(path string, code int, want string) {
		t.Helper()
		resp, body := h.get("https://api.test.com" + path)
		if resp.StatusCode != code || !strings.Contains(body, want) {
			t.Errorf("%s: %d %q", path, resp.StatusCode, clip(body, 120))
		}
	}
	check("/ad", 404, "")
	check("/r200", 200, "")
	check("/rdict", 200, "{}")
	check("/rimg", 200, "GIF89a")
	check("/echo", 200, `"X-Mod":"1"`)
	check("/ml", 200, "local")
	check("/json", 200, `"ad":false`)
}
