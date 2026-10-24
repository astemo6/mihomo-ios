package mitm

import (
	"bufio"
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
	"testing"
	"time"
)

func upstreamHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ad":true,"data":{"ads":[1,2],"keep":1}}`)
	})
	mux.HandleFunc("/gzip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_, _ = io.WriteString(gz, `{"ad":true,"vip":false}`)
		_ = gz.Close()
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		h := map[string]string{}
		for k, v := range r.Header {
			h[k] = strings.Join(v, ",")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"method": r.Method, "path": r.URL.Path, "headers": h, "body": string(b), "host": r.Host})
	})
	mux.HandleFunc("/brx", func(w http.ResponseWriter, r *http.Request) { // brotlistrict_test.go
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "br")
		_, _ = w.Write(brxBody.Load().([]byte))
	})
	mux.HandleFunc("/bin", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte{0, 1, 2, 3, 250, 251})
	})
	return mux
}

type harness struct {
	t      *testing.T
	home   string
	e      *Engine
	ca     *CA
	up     *httptest.Server
	client *http.Client
}

func newHarness(t *testing.T, cfg *Config, scripts map[string]string) *harness {
	t.Helper()
	home := t.TempDir()
	ca, err := GenerateCA(home)
	if err != nil {
		t.Fatal(err)
	}
	up := httptest.NewUnstartedServer(upstreamHandler())
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
		return d.DialContext(ctx, "tcp", upAddr) // every host => the test upstream
	}
	e := New(home, dial, func(level, msg string) { t.Logf("[%s] %s", level, msg) })
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
	c := &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &harness{t: t, home: home, e: e, ca: ca, up: up, client: c}
}

func (h *harness) get(u string, hdr ...string) (*http.Response, string) {
	h.t.Helper()
	req, _ := http.NewRequest("GET", u, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("GET %s: %v", u, err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func items(lines ...string) []Item {
	var out []Item
	for i, l := range lines {
		out = append(out, Item{ID: fmt.Sprint(i), Enabled: true, Line: l})
	}
	return out
}

func TestMitMRewriteRoundTrip(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"*.test.com", "-skip.test.com"}, Rules: items(
		`^https://api\.test\.com/ad - reject-dict`,
		`^https://api\.test\.com/old/(.*) https://api.test.com/new/$1 302`,
		`^https://api\.test\.com/gif - reject-img`,
		`^https://api\.test\.com/echo header-add X-Added hello`,
		`^https://api\.test\.com/echo header-del X-Remove`,
		`http-response ^https://api\.test\.com/json "ad":true "ad":false`,
		`http-response ^https://api\.test\.com/gzip "vip":false "vip":true`,
		`http-response-jq ^https://api\.test\.com/json 'del(.data.ads)'`,
		`^https://api\.test\.com/local data="{\"local\":1}" data-type=text header="Content-Type:application/json"`,
		`^https:\/\/api\.test\.com\/qx url reject-200`,
		`^https://api\.test\.com/urlx https://api.test.com/echo header`,
	)}
	h := newHarness(t, cfg, nil)

	resp, body := h.get("https://api.test.com/ad")
	if resp.StatusCode != 200 || body != "{}" {
		t.Errorf("reject-dict: %d %q", resp.StatusCode, body)
	}
	if resp.ProtoMajor != 2 {
		t.Errorf("expected h2 to client, got %s", resp.Proto)
	}
	resp, _ = h.get("https://api.test.com/old/x?y=1")
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "https://api.test.com/new/x?y=1" {
		t.Errorf("302: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, body = h.get("https://api.test.com/gif")
	if resp.Header.Get("Content-Type") != "image/gif" || !strings.HasPrefix(body, "GIF89a") {
		t.Errorf("reject-img: %s", resp.Header.Get("Content-Type"))
	}
	_, body = h.get("https://api.test.com/echo", "X-Remove", "1")
	if !strings.Contains(body, `"X-Added":"hello"`) || strings.Contains(body, "X-Remove") {
		t.Errorf("header rewrite: %s", body)
	}
	_, body = h.get("https://api.test.com/json")
	if body != `{"ad":false,"data":{"keep":1}}` {
		t.Errorf("body+jq: %s", body)
	}
	resp, body = h.get("https://api.test.com/gzip", "Accept-Encoding", "gzip")
	if body != `{"ad":true,"vip":true}` || resp.Header.Get("Content-Encoding") != "" {
		t.Errorf("gzip body rewrite: %q enc=%q", body, resp.Header.Get("Content-Encoding"))
	}
	resp, body = h.get("https://api.test.com/local")
	if body != `{"local":1}` || resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("map local: %q %s", body, resp.Header.Get("Content-Type"))
	}
	resp, body = h.get("https://api.test.com/qx")
	if resp.StatusCode != 200 || body != "" {
		t.Errorf("qx reject-200: %d %q", resp.StatusCode, body)
	}
	_, body = h.get("https://api.test.com/urlx")
	if !strings.Contains(body, `"path":"/echo"`) {
		t.Errorf("header-type url rewrite: %s", body)
	}

	// request log records matches
	list := h.e.Requests.List(0)
	if len(list) < 8 {
		t.Fatalf("request log too short: %d", len(list))
	}
	found := false
	for _, s := range list {
		if strings.HasSuffix(s.URL, "/json") && len(s.Matched) == 2 && s.MitM {
			found = true
			full := h.e.Requests.Get(s.ID)
			if !strings.Contains(full.RespBodyS, `"ad":false`) || full.ReqHdr == nil {
				t.Errorf("captured detail: %+v", full)
			}
		}
	}
	if !found {
		t.Errorf("no /json entry with 2 matches: %+v", list)
	}
}

func TestPassThroughAndPinning(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"*.test.com", "-skip.test.com"}, Rules: items(
		`^https://.*\.test\.com/ad - reject-dict`)}
	h := newHarness(t, cfg, nil)
	// excluded host: tunnelled untouched => upstream cert (not our CA) => verify with insecure client
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", h.e.Port()))
	insecure := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 10 * time.Second}
	resp, err := insecure.Get("https://skip.test.com/ad")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) == "{}" {
		t.Error("excluded host must not be rewritten")
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 || resp.TLS.PeerCertificates[0].Issuer.CommonName == h.ca.Cert.Subject.CommonName {
		t.Error("excluded host should present the upstream certificate")
	}
	// client that does not trust our CA => handshake fails => host pinned => next connection passes through
	strict := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool()}}, Timeout: 10 * time.Second}
	if _, err := strict.Get("https://pin.test.com/ad"); err == nil {
		t.Fatal("expected TLS failure for untrusting client")
	}
	time.Sleep(100 * time.Millisecond)
	if _, ok := h.e.pinned.Load("pin.test.com"); !ok {
		t.Fatal("host should be marked pinned")
	}
	resp, err = insecure.Get("https://pin.test.com/ad")
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) == "{}" {
		t.Error("pinned host must pass through")
	}
}

func TestPlainHTTPRewrite(t *testing.T) {
	home := t.TempDir()
	up := httptest.NewServer(upstreamHandler())
	defer up.Close()
	dial := func(ctx context.Context, network, addr, policy string) (net.Conn, error) {
		return net.Dial("tcp", up.Listener.Addr().String())
	}
	e := New(home, dial, nil)
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	cfg := &Config{Enabled: true, Rules: items(`^http://plain\.com/json - reject-array`, `http-response ^http://plain\.com/echo GET POST`)}
	e.Reload(cfg, Build(home, cfg))
	do := func(path string) string {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", e.Port()))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		fmt.Fprintf(c, "CONNECT plain.com:80 HTTP/1.1\r\nHost: plain.com:80\r\n\r\n")
		br := bufio.NewReader(c)
		resp, err := http.ReadResponse(br, nil)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("connect: %v", err)
		}
		fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: plain.com\r\nConnection: close\r\n\r\n", path)
		resp, err = http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	if b := do("/json"); b != "[]" {
		t.Errorf("plain reject-array: %q", b)
	}
	if b := do("/echo"); !strings.Contains(b, `"method":"POST"`) {
		t.Errorf("plain body rewrite: %q", b)
	}
}

const surgeScript = `
const obj = JSON.parse($response.body);
obj.ad = false;
obj.arg = $argument;
obj.ua = $request.headers['user-agent'] || $request.headers['User-Agent'];
let n = parseInt($persistentStore.read('count') || '0') + 1;
$persistentStore.write(String(n), 'count');
obj.count = n;
console.log('modified', obj.ad);
$done({ body: JSON.stringify(obj), headers: Object.assign({}, $response.headers, {'X-Script': 'surge'}) });
`

const qxScript = `
var body = JSON.parse($response.body);
body.qx = $prefs.valueForKey('k') || 'none';
$prefs.setValueForKey('v1', 'k');
$done({ status: 'HTTP/1.1 201 Created', body: JSON.stringify(body) });
`

const mockScript = `
if ($request.url.indexOf('/mock') > 0) {
  $done({ response: { status: 200, headers: { 'Content-Type': 'text/plain' }, body: 'mocked:' + $request.method } });
} else {
  const h = $request.headers; h['X-From-Script'] = '1';
  $done({ headers: h, url: $request.url.replace('/req', '/echo') });
}
`

const httpClientScript = `
$httpClient.get({ url: 'https://api.test.com/echo', insecure: true, headers: { 'X-Sub': 'a' } }, (err, resp, data) => {
  if (err) { $done({ body: 'err:' + err }); return; }
  const j = JSON.parse(data);
  $task.fetch({ url: 'https://api.test.com/json', insecure: true }).then(r => {
    setTimeout(() => {
      $done({ body: JSON.stringify({ sub: j.headers['X-Sub'], status: resp.status, fetched: JSON.parse(r.body).data.keep }) });
    }, 10);
  }, e => $done({ body: 'fetch err ' + e.error }));
});
`

// Chavyleung-style Env detection: must pick Surge and keep working.
const envScript = `
function Env(name) {
  this.name = name;
  this.isSurge = () => typeof $environment !== 'undefined' && $environment['surge-version'];
  this.isQuanX = () => typeof $task !== 'undefined' && !this.isSurge();
  this.isNode = () => typeof module !== 'undefined' && !!module.exports;
  this.getdata = (k) => this.isSurge() ? $persistentStore.read(k) : $prefs.valueForKey(k);
  this.done = (v) => $done(v);
}
const $ = new Env('demo');
if ($.isNode()) throw new Error('detected node');
$.done({ body: JSON.stringify({ env: $.isSurge() ? 'surge' : 'other', name: $script.name }) });
`

const binScript = `
const u8 = $response.body;
const out = new Uint8Array(u8.length);
for (let i = 0; i < u8.length; i++) out[i] = u8[u8.length - 1 - i];
const enc = new TextEncoder().encode('ok');
$done({ body: out, headers: { 'X-Len': String(u8.length) + ':' + enc.length } });
`

const slowScript = `while (true) {}`

func TestScripts(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`surge = type=http-response,pattern=^https://api\.test\.com/json\?s=1,requires-body=1,script-path=surge.js,argument=hello`,
		`^https://api\.test\.com/json\?qx=1 url script-response-body qx.js`,
		`mock = type=http-request,pattern=^https://api\.test\.com/(mock|req),script-path=mock.js`,
		`client = type=http-response,pattern=^https://api\.test\.com/json\?c=1,requires-body=1,script-path=client.js,timeout=10`,
		`env = type=http-response,pattern=^https://api\.test\.com/json\?env=1,requires-body=1,script-path=env.js`,
		`bin = type=http-response,pattern=^https://api\.test\.com/bin,requires-body=1,binary-body-mode=1,script-path=bin.js`,
		`slow = type=http-response,pattern=^https://api\.test\.com/json\?slow=1,requires-body=1,script-path=slow.js,timeout=1`,
	)}
	h := newHarness(t, cfg, map[string]string{"surge.js": surgeScript, "qx.js": qxScript, "mock.js": mockScript,
		"client.js": httpClientScript, "env.js": envScript, "bin.js": binScript, "slow.js": slowScript})

	resp, body := h.get("https://api.test.com/json?s=1", "User-Agent", "UA-1")
	var obj map[string]any
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		t.Fatalf("surge script body: %q", body)
	}
	if obj["ad"] != false || obj["arg"] != "hello" || obj["ua"] != "UA-1" || obj["count"] != float64(1) || resp.Header.Get("X-Script") != "surge" {
		t.Errorf("surge script: %v hdr=%v", obj, resp.Header)
	}
	_, body = h.get("https://api.test.com/json?s=1")
	if !strings.Contains(body, `"count":2`) {
		t.Errorf("persistentStore not persisted: %s", body)
	}
	if v, _ := h.e.Store.Read("count"); v != "2" {
		t.Errorf("store file value %q", v)
	}

	resp, body = h.get("https://api.test.com/json?qx=1")
	if resp.StatusCode != 201 || !strings.Contains(body, `"qx":"none"`) {
		t.Errorf("qx script: %d %s", resp.StatusCode, body)
	}
	_, body = h.get("https://api.test.com/json?qx=1")
	if !strings.Contains(body, `"qx":"v1"`) {
		t.Errorf("qx prefs: %s", body)
	}

	_, body = h.get("https://api.test.com/mock")
	if body != "mocked:GET" {
		t.Errorf("mock response: %q", body)
	}
	_, body = h.get("https://api.test.com/req")
	if !strings.Contains(body, `"path":"/echo"`) || !strings.Contains(body, `"X-From-Script":"1"`) {
		t.Errorf("request rewrite by script: %s", body)
	}

	_, body = h.get("https://api.test.com/json?c=1")
	if body != `{"sub":"a","status":200,"fetched":1}` {
		t.Errorf("$httpClient/$task.fetch: %s", body)
	}

	_, body = h.get("https://api.test.com/json?env=1")
	if body != `{"env":"surge","name":"env"}` {
		t.Errorf("env detection: %s", body)
	}

	resp, body = h.get("https://api.test.com/bin")
	if !bytes.Equal([]byte(body), []byte{251, 250, 3, 2, 1, 0}) || resp.Header.Get("X-Len") != "6:2" {
		t.Errorf("binary body: %v %s", []byte(body), resp.Header.Get("X-Len"))
	}

	start := time.Now()
	_, body = h.get("https://api.test.com/json?slow=1")
	if time.Since(start) > 5*time.Second || !strings.Contains(body, `"ad":true`) {
		t.Errorf("timeout script should fall back to original body quickly: %s", body)
	}
	logs := h.e.Logs.List(0, "")
	var sawLog, sawTimeout bool
	for _, l := range logs {
		if l.Script == "surge" && strings.Contains(l.Msg, "modified false") {
			sawLog = true
		}
		if l.Script == "slow" && strings.Contains(l.Msg, "超时") {
			sawTimeout = true
		}
	}
	if !sawLog || !sawTimeout {
		t.Errorf("script logs missing (log=%v timeout=%v): %+v", sawLog, sawTimeout, logs)
	}
}

func TestCALeafAndProfile(t *testing.T) {
	home := t.TempDir()
	ca, err := GenerateCA(home)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Leaf("www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(leaf.Certificate[0])
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "www.example.com", Roots: pool}); err != nil {
		t.Fatalf("leaf does not verify: %v", err)
	}
	if cert.NotAfter.Sub(cert.NotBefore) > 825*24*time.Hour {
		t.Error("leaf validity exceeds iOS limit")
	}
	again, _ := ca.Leaf("www.example.com")
	if again != leaf {
		t.Error("leaf cache miss")
	}
	ca2, err := LoadCA(home)
	if err != nil || !bytes.Equal(ca2.DER, ca.DER) {
		t.Fatal("reload CA")
	}
	mc := string(ca.MobileConfig())
	if !strings.Contains(mc, "com.apple.security.root") || !strings.Contains(mc, "<data>") {
		t.Error("mobileconfig payload")
	}
	p12, err := ca.ExportP12("pw")
	if err != nil || len(p12) == 0 {
		t.Fatalf("p12: %v", err)
	}
	home2 := t.TempDir()
	if err := ImportP12(home2, p12, "pw"); err != nil {
		t.Fatalf("import p12: %v", err)
	}
	ca3, err := LoadCA(home2)
	if err != nil || !bytes.Equal(ca3.DER, ca.DER) {
		t.Fatal("imported CA differs")
	}
	if fi, _ := os.Stat(filepath.Join(home, "engine", "ca", "ca.key")); fi.Mode().Perm() != 0o600 {
		t.Errorf("key perms %v", fi.Mode().Perm())
	}
}

func TestInjectRules(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"*.a.com", "-x.a.com", "b.com:8443"}}
	rs := Build(t.TempDir(), cfg)
	rs.Rules = append(rs.Rules, &Rule{Kind: KindURL})
	rs.CoreRules = []string{"DOMAIN-SUFFIX,ad.com,REJECT"}
	raw := map[string]any{"rules": []any{"MATCH,DIRECT"}}
	Inject(raw, 12345, rs, cfg)
	rules := raw["rules"].([]any)
	if len(rules) != 5 || rules[4] != "MATCH,DIRECT" {
		t.Fatalf("rules: %v", rules)
	}
	if !strings.Contains(rules[1].(string), "DST-PORT,443/8443") || !strings.Contains(rules[1].(string), "__mitm_skip") {
		t.Errorf("mitm rule: %s", rules[1])
	}
	if !strings.HasPrefix(rules[0].(string), "AND,((NETWORK,UDP)") {
		t.Errorf("quic block: %s", rules[0])
	}
	rp := raw["rule-providers"].(map[string]any)
	inc := rp["__mitm_hosts"].(map[string]any)["payload"].([]any)
	if inc[0] != "DOMAIN-WILDCARD,*.a.com" || inc[1] != "DOMAIN,b.com" {
		t.Errorf("payload: %v", inc)
	}
}
