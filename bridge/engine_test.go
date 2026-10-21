package libmihomo

import (
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

	"github.com/astemo6/mihomo-ios/bridge/mitm"
)

// End-to-end through the real mihomo core: client -> mixed inbound -> injected rule -> __MITM__
// outbound -> engine (TLS interception + rewrite) -> listener/inner -> rules -> DIRECT -> upstream.
func TestEngineThroughCore(t *testing.T) {
	home := t.TempDir()
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"path":%q,"ad":true}`, r.URL.Path)
	}))
	defer up.Close()
	_, upPort, _ := net.SplitHostPort(up.Listener.Addr().String())

	ca, err := mitm.GenerateCA(home)
	if err != nil {
		t.Fatal(err)
	}
	cfg := mitm.Config{Enabled: true, MitM: true, SkipCertVerify: true,
		Hostnames: []string{"mitm.test:" + upPort},
		Rules: []mitm.Item{
			{ID: "1", Enabled: true, Line: `^https://mitm\.test:\d+/ad - reject-dict`},
			{ID: "2", Enabled: true, Line: `http-response ^https://mitm\.test:\d+/body "ad":true "ad":false`},
		}}
	_ = os.MkdirAll(mitm.EngineDir(home), 0o755)
	b, _ := json.Marshal(cfg)
	_ = os.WriteFile(filepath.Join(mitm.EngineDir(home), "engine.json"), b, 0o644)
	ov := defaultOverrides()
	ov.AllowLan = true
	ov.ControllerPort = 19190
	ov.Secret = "s"
	ov.MixedPort = freeTCPPort(t) // B12: not the shared 7890 (another run / test may hold it)
	ob, _ := json.Marshal(ov)
	_ = os.WriteFile(filepath.Join(home, "overrides.json"), ob, 0o644)
	prof := filepath.Join(home, "p.yaml")
	_ = os.WriteFile(prof, []byte(`mode: rule
hosts:
  mitm.test: 127.0.0.1
proxies:
  - {name: demo, type: ss, server: 127.0.0.1, port: 1, cipher: aes-128-gcm, password: x}
rules:
  - MATCH,DIRECT
`), 0o644)
	if err := Start(home, prof, 0); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	rt, _ := os.ReadFile(filepath.Join(home, "runtime.yaml"))
	if !strings.Contains(string(rt), "__MITM__") {
		t.Fatalf("runtime has no injected outbound:\n%s", rt)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", ov.MixedPort))
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: pool}}, Timeout: 15 * time.Second}
	var resp *http.Response
	for i := 0; i < 30; i++ { // listener comes up asynchronously
		resp, err = c.Get("https://mitm.test:" + upPort + "/ad")
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "{}" {
		t.Errorf("reject-dict through core: %q", body)
	}
	resp, err = c.Get("https://mitm.test:" + upPort + "/body")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != `{"path":"/body","ad":false}` {
		t.Errorf("body rewrite through core: %q", body)
	}
	// controller exposes /mitm/requests
	req, _ := http.NewRequest("GET", "http://127.0.0.1:19190/mitm/requests", nil)
	req.Header.Set("Authorization", "Bearer s")
	r2, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	lb, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	if !strings.Contains(string(lb), "/body") {
		t.Errorf("/mitm/requests: %s", lb)
	}
}

func TestEngineOffAllocatesNothing(t *testing.T) {
	home := t.TempDir()
	inj, err := prepareEngine(home)
	if err != nil || inj != nil || eng != nil {
		t.Fatalf("engine should stay off without engine.json: inj=%v eng=%v err=%v", inj != nil, eng != nil, err)
	}
}

func TestParseExports(t *testing.T) {
	out := EngineParseText("hostname = a.com\n^https://a\\.com/x url reject\n", "")
	if !strings.Contains(out, `"hostnames":["a.com"]`) || !strings.Contains(out, `"kind":"url"`) {
		t.Errorf("EngineParseText: %s", out)
	}
	out = EngineParseLine("garbage line here", "")
	if !strings.Contains(out, `"unsupported":["garbage line here"]`) {
		t.Errorf("EngineParseLine: %s", out)
	}
}
