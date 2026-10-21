package libmihomo

import (
	"crypto/tls"
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

var v0141MixedPort int

func v0141Setup(t *testing.T, ctrlPort int, profile string, hosts []string) (home string) {
	t.Helper()
	home = t.TempDir()
	if _, err := mitm.GenerateCA(home); err != nil {
		t.Fatal(err)
	}
	cfg := mitm.Config{Enabled: true, MitM: true, SkipCertVerify: true, Hostnames: hosts}
	_ = os.MkdirAll(mitm.EngineDir(home), 0o755)
	b, _ := json.Marshal(cfg)
	_ = os.WriteFile(filepath.Join(mitm.EngineDir(home), "engine.json"), b, 0o644)
	ov := defaultOverrides()
	ov.AllowLan = true
	ov.ControllerPort = ctrlPort
	ov.Secret = "s"
	ov.MixedPort = freeTCPPort(t) // B12: not the shared 7890
	v0141MixedPort = ov.MixedPort
	ob, _ := json.Marshal(ov)
	_ = os.WriteFile(filepath.Join(home, "overrides.json"), ob, 0o644)
	prof := filepath.Join(home, "p.yaml")
	_ = os.WriteFile(prof, []byte(profile), 0o644)
	if err := Start(home, prof, 0); err != nil {
		t.Fatal(err)
	}
	return home
}

func ctrlGet(t *testing.T, port int, path string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d%s", port, path), nil)
	req.Header.Set("Authorization", "Bearer s")
	r, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(r.Body).Decode(&m)
	return m
}

// v0.14.1: a QX-style url-test group (include-all + server-tag-regex filter) and include-all-proxies select
// groups must not contain the injected __MITM__ outbound when MitM is on (device: 自动选择 picked it).
func TestV0141MitMNotInIncludeAllGroups(t *testing.T) {
	home := v0141Setup(t, 19241, `mode: rule
proxies:
  - {name: HK 01, type: ss, server: 127.0.0.1, port: 1, cipher: aes-128-gcm, password: x}
  - {name: JP CFT, type: ss, server: 127.0.0.1, port: 2, cipher: aes-128-gcm, password: x}
proxy-groups:
  - {name: 自动选择, type: url-test, include-all: true, filter: '^(?!.*CFT)(?!.*AZ).*?$', url: 'http://127.0.0.1:9/', interval: 600}
  - {name: 节点选择, type: select, include-all-proxies: true}
  - {name: proxy, type: select, proxies: [自动选择], include-all: true}
rules:
  - MATCH,节点选择
`, []string{"example.com"})
	defer Stop()
	rt, _ := os.ReadFile(filepath.Join(home, "runtime.yaml"))
	if !strings.Contains(string(rt), "__MITM__") {
		t.Fatalf("MitM outbound not injected:\n%s", rt)
	}
	for _, g := range []string{"自动选择", "节点选择", "proxy"} {
		m := ctrlGet(t, 19241, "/proxies/"+url.PathEscape(g))
		all, _ := m["all"].([]any)
		if len(all) == 0 {
			t.Fatalf("%s: no members: %v", g, m)
		}
		for _, n := range all {
			if n == mitm.ProxyName {
				t.Errorf("%s contains %s: %v", g, mitm.ProxyName, all)
			}
		}
		if m["now"] == mitm.ProxyName {
			t.Errorf("%s selects %s", g, mitm.ProxyName)
		}
	}
	m := ctrlGet(t, 19241, "/proxies/"+url.PathEscape("自动选择"))
	for _, n := range m["all"].([]any) {
		if strings.Contains(n.(string), "CFT") {
			t.Errorf("user filter lost: %v", m["all"])
		}
	}
}

// v0.14.1 defence: even if traffic is routed into __MITM__ again (here a rule sends everything there, the
// same effect as a group selecting it), the engine rejects its own upstream coming back instead of looping.
func TestV0141LoopRejected(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer up.Close()
	_, upPort, _ := net.SplitHostPort(up.Listener.Addr().String())
	v0141Setup(t, 19242, `mode: rule
hosts:
  loop.test: 127.0.0.1
proxies:
  - {name: demo, type: ss, server: 127.0.0.1, port: 1, cipher: aes-128-gcm, password: x}
rules:
  - MATCH,__MITM__
`, []string{"loop.test:" + upPort})
	defer Stop()
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", v0141MixedPort))
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 20 * time.Second}
	start := time.Now()
	var err error
	for i := 0; i < 30; i++ {
		var resp *http.Response
		resp, err = c.Get("https://loop.test:" + upPort + "/")
		if resp != nil {
			resp.Body.Close()
		}
		engMu.Lock()
		hits := int64(0)
		if eng != nil {
			hits = eng.LoopHits.Load()
		}
		engMu.Unlock()
		if hits > 0 {
			t.Logf("loop rejected after %v (hits %d, last err %v)", time.Since(start), hits, err)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("no loop rejection (last err %v)", err)
}
