package libmihomo

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The simulator memory bench's Go half answers a MitM'd request end to end and tears down cleanly.
func TestMitmBenchRoundTrip(t *testing.T) {
	var st struct {
		EnginePort int    `json:"enginePort"`
		CA         string `json:"ca"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal([]byte(MitmBenchStart()), &st); err != nil || st.Error != "" {
		t.Fatalf("start: %v %s", err, st.Error)
	}
	defer MitmBenchStop()
	if !strings.Contains(MitmBenchStart(), "already running") {
		t.Fatal("second start accepted")
	}
	der, _ := base64.StdEncoding.DecodeString(st.CA)
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", st.EnginePort))
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: pool}}}
	resp, err := c.Get("https://api.bench.test/json")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), `"keep":1`) {
		t.Fatalf("body %q", b)
	}
	// The native session's half, minus Swift: Go's first decision for the bench request (the JSON GoMitmFlowDriver
	// sends) is a forward to the origin, and the native upstream's route — CONNECT through the relay, TLS to the
	// origin with the engine's skip-cert-verify, HTTP/1.1 — answers.
	if !MitmSkipCertVerify() {
		t.Fatal("bench engine: skip-cert-verify off")
	}
	var d struct {
		ID     int64  `json:"id"`
		Action string `json:"action"`
		URL    string `json:"url"`
		Note   string `json:"note"`
	}
	begin := `{"method":"GET","target":"/json","host":"api.bench.test","headers":[["Host","api.bench.test"],["Accept","*/*"]],"length":0,"connHost":"api.bench.test","connPort":443,"tls":true,"connId":1}`
	if err := json.Unmarshal([]byte(MitmFlowBegin(begin)), &d); err != nil || d.Action != "forward" || d.URL != "https://api.bench.test/json" {
		t.Fatalf("flow begin: %+v %v", d, err)
	}
	MitmFlowEnd(d.ID, 0, "")
	rp := MitmRelayPort()
	if rp == 0 {
		t.Fatal("relay not running")
	}
	rc, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", rp), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	_ = rc.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(rc, "CONNECT api.bench.test:443 HTTP/1.1\r\nHost: api.bench.test:443\r\n\r\n")
	br := bufio.NewReader(rc)
	cr, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil || cr.StatusCode != 200 {
		t.Fatalf("relay CONNECT: %v %v", cr, err)
	}
	tc := tls.Client(&bufferedConn{Conn: rc, r: br}, &tls.Config{ServerName: "api.bench.test", InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	_, _ = io.WriteString(tc, "GET /json HTTP/1.1\r\nHost: api.bench.test\r\n\r\n")
	ur, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatalf("origin through relay: %v", err)
	}
	ub, _ := io.ReadAll(io.LimitReader(ur.Body, 4096))
	if ur.StatusCode != 200 || !strings.Contains(string(ub), `"keep":1`) {
		t.Fatalf("origin through relay: %d %q", ur.StatusCode, ub)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(MitmBenchMem()), &m); err != nil || m["heapInuse"] == nil {
		t.Fatalf("mem %v %v", m, err)
	}
	if !strings.Contains(MemorySnapshot(1, 1, 1), `"native":{`) {
		t.Fatal("memory snapshot without native status")
	}
}

// The combo bench's rules (native-final): the Go path applies all three on the bench JSON.
type zeroProbe struct{}

func (zeroProbe) Footprint() int64 { return 1 << 20 }
func (zeroProbe) Available() int64 { return 0 }

func TestMitmBenchComboRules(t *testing.T) {
	// a probe left behind by an earlier test (the simulator's answers 0) must not turn the Go path's body gates off
	SetMemoryProbe(zeroProbe{})
	defer SetMemoryProbe(nil)
	var st struct {
		EnginePort int    `json:"enginePort"`
		CA         string `json:"ca"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal([]byte(MitmBenchStartRules(MitmBenchComboRules())), &st); err != nil || st.Error != "" {
		t.Fatalf("start: %v %s", err, st.Error)
	}
	defer MitmBenchStop()
	der, _ := base64.StdEncoding.DecodeString(st.CA)
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", st.EnginePort))
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: pool}}}
	resp, err := c.Get("https://api.bench.test/json")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.Header.Get("X-Bench-Resp") != "1" || !strings.Contains(string(b), `"keep":1`) || !strings.Contains(string(b), `"combo":true`) || !strings.Contains(string(b), `"list":[]`) {
		t.Fatalf("combo rules not applied: %v %q", resp.Header, b)
	}
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// The native session's sequence on the bench engine: response phase straight after a forward decision, many
// times (before the flow.go fix from feat/s3-rewrite 09a4223 it could get the request goroutine's leftover
// "request phase ended without a decision", which the session answers with 502).
func TestMitmBenchFlowResponseRightAfterForward(t *testing.T) {
	if js := MitmBenchStart(); strings.Contains(js, `"error"`) {
		t.Fatal(js)
	}
	defer MitmBenchStop()
	begin := `{"method":"GET","target":"/json","host":"api.bench.test","headers":[["Host","api.bench.test"]],"length":0,"connHost":"api.bench.test","connPort":443,"tls":true,"connId":1}`
	resp := `{"status":200,"headers":[["Content-Type","application/json"],["Content-Length","2"]],"length":2}`
	var d struct {
		ID     int64  `json:"id"`
		Action string `json:"action"`
		Note   string `json:"note"`
	}
	for i := 0; i < 2000; i++ {
		if err := json.Unmarshal([]byte(MitmFlowBegin(begin)), &d); err != nil || d.Action != "forward" {
			t.Fatalf("run %d begin: %+v %v", i, d, err)
		}
		id := d.ID
		d.Action, d.Note = "", ""
		if err := json.Unmarshal([]byte(MitmFlowResponse(id, resp)), &d); err != nil || d.Action == "error" || d.Action == "" {
			t.Fatalf("run %d response: %+v %v", i, d, err)
		}
		MitmFlowEnd(id, 0, "")
	}
}

// feat/selective-native: the large-body bench's rules on heavy.bench.test (jq on /jq, requires-body script on
// /script, both on N KB of JSON) apply on the Go path, and api.bench.test stays a plain pass-through.
func TestMitmBenchHeavyConf(t *testing.T) {
	SetMemoryProbe(zeroProbe{})
	defer SetMemoryProbe(nil)
	var st struct {
		EnginePort int    `json:"enginePort"`
		CA         string `json:"ca"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal([]byte(MitmBenchStartConf(MitmBenchHeavyConf())), &st); err != nil || st.Error != "" {
		t.Fatalf("start: %v %s", err, st.Error)
	}
	defer MitmBenchStop()
	der, _ := base64.StdEncoding.DecodeString(st.CA)
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", st.EnginePort))
	c := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: pool}}}
	get := func(u string) string {
		resp, err := c.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", u, resp.StatusCode)
		}
		return string(b)
	}
	for _, u := range []string{"https://heavy.bench.test/jq?kb=200", "https://heavy.bench.test/jq?kb=960", "https://heavy.bench.test/script?kb=2048", "https://heavy.bench.test/script?kb=3584"} {
		b := get(u)
		if !strings.Contains(b, `"combo":true`) || len(b) > 4096 {
			t.Logf("engine log: %s", MitmBenchLog())
			t.Fatalf("%s: rule not applied (%d bytes) %.200q", u, len(b), b)
		}
	}
	if b := get("https://api.bench.test/json"); !strings.Contains(b, `"keep":1`) || strings.Contains(b, "combo") {
		t.Fatalf("plain host: %q", b)
	}
	if b := get("https://api.bench.test/json?kb=64"); len(b) < 64<<10 {
		t.Fatalf("plain big: %d bytes", len(b))
	}
	var pk struct {
		HeapObjects uint64 `json:"heapObjects"`
		Mapped      uint64 `json:"mapped"`
	}
	if err := json.Unmarshal([]byte(MitmBenchMemPeek()), &pk); err != nil || pk.HeapObjects == 0 || pk.Mapped == 0 {
		t.Fatalf("peek: %v %+v", err, pk)
	}
}
