package mitm

// TestAppCleanDialectsAgree: the B4 dialect samples (testdata/appclean.plugin / .sgmodule / _egern.yaml /
// _qx.conf) describe the same rewrites in Loon, Surge, Egern and QuantumultX syntax. Each one is imported
// through the normal module path (Build → ParseText picks the dialect), every script it names is served the
// same generic script, and every URL any of the four rules aims at is sent through the Go path and through
// the native flow API. Where two or more dialects intercept a URL they must answer identically; where all
// four do there must be such a URL and the script must have run. No per-script or per-URL knowledge here:
// URLs come from the rules' patterns (sampleURL), scripts from the rules.

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

var appCleanDialects = []string{"appclean.plugin", "appclean.sgmodule", "appclean_egern.yaml", "appclean_qx.conf"}

// appCleanScript works in either phase and either body mode (text or Uint8Array) and shows that it ran.
const appCleanScript = `
var s = function (b) {
  if (b == null) return '';
  if (typeof b === 'string') return b;
  var o = '';
  for (var i = 0; i < b.length; i++) o += String.fromCharCode(b[i]);
  return o;
};
if (typeof $response !== 'undefined') {
  $done({ body: s($response.body) + '|resp ' + $request.method });
} else {
  $done({ body: s($request.body) + '|req' });
}
`

type appCleanEngine struct {
	file string
	rs   *Ruleset
	c    *http.Client
	sim  *flowSim
}

func newAppCleanEngine(t *testing.T, file string) *appCleanEngine {
	t.Helper()
	text, err := os.ReadFile(filepath.Join("testdata", file))
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if _, err := GenerateCA(home); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Dir(ModulePath(home, "m")), 0o755)
	if err := os.WriteFile(ModulePath(home, "m"), text, 0o644); err != nil {
		t.Fatal(err)
	}
	// first pass: which scripts does this dialect name
	cfg := &Config{Enabled: true, MitM: true, SkipCertVerify: true, CaptureBodies: noCapture(), Modules: []Module{{ID: "m", Name: file, Enabled: true}}}
	for _, r := range Build(home, cfg).Rules {
		if r.Kind == KindScript && r.Script != nil && r.Script.Path != "" {
			seedScript(t, home, r.Script.Path, []byte(appCleanScript))
		}
	}
	rs := Build(home, cfg)
	if len(rs.Errors) > 0 || len(rs.Unsupported) > 0 {
		t.Fatalf("%s: errors %v unsupported %v", file, rs.Errors, rs.Unsupported)
	}
	if len(rs.Rules) == 0 {
		t.Fatalf("%s: no rules imported", file)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Up-Method", r.Method)
		w.Header().Set("X-Up-Body", clip(string(b), 500))
		_, _ = w.Write(genericBody(r.URL.String()))
	})
	up := httptest.NewUnstartedServer(mux)
	up.EnableHTTP2 = true
	up.StartTLS()
	t.Cleanup(up.Close)
	dial := func(ctx context.Context, network, addr, policy string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", up.Listener.Addr().String())
	}
	e := New(home, dial, nil)
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)
	e.Reload(cfg, rs)
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", e.Port()))
	tr := &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true, DisableCompression: true}
	t.Cleanup(tr.CloseIdleConnections)
	c := &http.Client{Transport: tr, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &appCleanEngine{file: file, rs: rs, c: c, sim: newFlowSim(t, e)}
}

// appCleanOutcome is what the client and the upstream saw, as one comparable string.
func appCleanOutcome(r simResult) string {
	if r.dropped {
		return "dropped"
	}
	return fmt.Sprintf("status %d | up %s %q | body %q", r.status, r.header.Get("X-Up-Method"), r.header.Get("X-Up-Body"), r.body)
}

func TestAppCleanDialectsAgree(t *testing.T) {
	var engines []*appCleanEngine
	for _, f := range appCleanDialects {
		engines = append(engines, newAppCleanEngine(t, f))
	}
	// every https URL any dialect's rules aim at; a URL a request-phase script reads gets a body
	urls := map[string]bool{}
	post := map[string]bool{}
	for _, ae := range engines {
		hm := NewHostMatcher(ae.rs.Hostnames)
		for _, r := range ae.rs.Rules {
			s := sampleURL(r.Pattern)
			if strings.HasPrefix(s, "http://") && r.match("https://"+s[7:]) {
				s = "https://" + s[7:]
			}
			su, err := url.Parse(s)
			if s == "" || err != nil || su.Scheme != "https" || !r.match(s) {
				t.Errorf("%s: no https sample URL for %q (got %q)", ae.file, r.Pattern, s)
				continue
			}
			if !hm.Match(su.Hostname(), 443) {
				t.Errorf("%s: %s is not in the module's MitM hostnames", ae.file, su.Hostname())
			}
			urls[s] = true
			if r.Kind == KindScript && strings.HasPrefix(r.Script.Type, "http-request") && r.Script.RequiresBody {
				post[s] = true
			}
		}
	}
	sorted := make([]string, 0, len(urls))
	for u := range urls {
		sorted = append(sorted, u)
	}
	sort.Strings(sorted)

	allFour := 0
	for _, u := range sorted {
		method, body := "GET", []byte(nil)
		if post[u] {
			method, body = "POST", []byte(`{"a":1,"keywords":["x"]}`)
		}
		hdr := http.Header{"User-Agent": {"Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X)"}}
		var covering []string
		outcomes := map[string]string{}
		for _, ae := range engines {
			hit := false
			for _, r := range ae.rs.Rules {
				if r.match(u) {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
			g := goDo(t, ae.c, method, u, hdr, body)
			f := ae.sim.do(method, u, hdr, body)
			if why := sameOutcome(g, f); why != "" {
				t.Errorf("%s %s %s: Go path and flow API differ: %s", ae.file, method, u, why)
			}
			covering = append(covering, ae.file)
			outcomes[ae.file] = appCleanOutcome(g)
		}
		ref := outcomes[covering[0]]
		for _, file := range covering[1:] {
			if outcomes[file] != ref {
				t.Errorf("%s %s: %s answered\n  %s\nbut %s answered\n  %s", method, u, covering[0], ref, file, outcomes[file])
			}
		}
		if len(covering) == len(engines) {
			allFour++
			if !strings.Contains(ref, "|resp ") && !strings.Contains(ref, "|req") {
				t.Errorf("%s %s: matched by all four dialects but no script ran: %s", method, u, ref)
			}
		}
		t.Logf("%s %s: %d dialect(s) %v → %s", method, u, len(covering), covering, clip(ref, 160))
	}
	if allFour == 0 {
		t.Fatalf("no URL is intercepted by all four dialects (%d URLs)", len(sorted))
	}
	t.Logf("%d URLs, %d intercepted by all %d dialects", len(sorted), allFour, len(engines))
	waitFlows(t)
}
