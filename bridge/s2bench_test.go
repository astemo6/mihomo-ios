package libmihomo

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
	var m map[string]any
	if err := json.Unmarshal([]byte(MitmBenchMem()), &m); err != nil || m["heapInuse"] == nil {
		t.Fatalf("mem %v %v", m, err)
	}
	if !strings.Contains(MemorySnapshot(1, 1, 1), `"native":{`) {
		t.Fatal("memory snapshot without native status")
	}
}
