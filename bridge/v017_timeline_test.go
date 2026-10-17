package libmihomo

import (
	"bufio"
	"context"
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

func TestTimelineDNSPairing(t *testing.T) {
	tl := &timelineRec{recs: map[string]*tlRecord{}, dns: map[string]*tlDNS{}, pending: map[string]time.Time{}}
	t0 := time.Now()
	tl.dnsEvent("[DNS] resolve example.com A from udp://223.5.5.5:53", t0)
	tl.dnsEvent("[DNS] resolve example.com A from tls://1.1.1.1:853", t0)
	tl.dnsEvent("[DNS] example.com --> [93.184.216.34] A from udp://223.5.5.5:53", t0.Add(37*time.Millisecond))
	tl.dnsEvent("[DNS] example.com --> [93.184.216.34] A from tls://1.1.1.1:853", t0.Add(60*time.Millisecond)) // slower parallel upstream
	d := tl.dns["example.com"]
	if d == nil || d.Ms != 37 || d.Upstream != "udp://223.5.5.5:53" || d.Cached {
		t.Fatalf("%+v", d)
	}
	tl.dnsEvent("[DNS] cache hit Apple.COM. --> [17.253.144.10] A, expire at 2026-10-18 01:00:00", t0)
	if c := tl.dns["apple.com"]; c == nil || !c.Cached || c.Ms != 0 {
		t.Fatalf("%+v", c)
	}
	// an answer without a matching resolve line is not a measurement
	tl.dnsEvent("[DNS] other.org --> [1.2.3.4] A from udp://8.8.8.8:53", t0)
	if tl.dns["other.org"] != nil {
		t.Fatal("unpaired answer recorded")
	}
	// tunnel's rule-matching line has no " from " → ignored
	tl.dnsEvent("[DNS] example.net --> 1.2.3.4", t0)
	if tl.dns["example.net"] != nil {
		t.Fatal("tunnel line recorded")
	}
}

func startTimelineCore(t *testing.T, port int, profile string) {
	home := t.TempDir()
	ov := defaultOverrides()
	ov.ControllerPort = port
	ov.Secret = "s"
	ob, _ := json.Marshal(ov)
	_ = os.WriteFile(filepath.Join(home, "overrides.json"), ob, 0o644)
	prof := filepath.Join(home, "p.yaml")
	_ = os.WriteFile(prof, []byte(profile), 0o644)
	if err := Start(home, prof, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { timeline.reset(); Stop() })
}

func TestTimelineProbeAndPassive(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(120 * time.Millisecond)
		w.WriteHeader(204)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	_, port, _ := net.SplitHostPort(u.Host)
	startTimelineCore(t, 19331, "hosts:\n  tl.test: 127.0.0.1\nrules:\n  - MATCH,DIRECT\n")

	// Active probe: IP target → no DNS; TLS + first byte measured.
	resp := controllerGet(t, 19331, "/timeline/probe?host=127.0.0.1&tls=1&chain=DIRECT&port="+port)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var p tlProbe
	_ = json.Unmarshal(b, &p)
	t.Logf("%s", b)
	if !p.OK || p.DNS.Ms != nil || p.Connect.Ms == nil || p.TLS.Ms == nil || p.FirstByte.Ms == nil || p.Status != "204" || !strings.Contains(p.Chain, "DIRECT") {
		t.Fatalf("%s", b)
	}
	if *p.FirstByte.Ms < 100 {
		t.Fatalf("first byte %v < server delay", *p.FirstByte.Ms)
	}
	// Domain + DIRECT → the core's direct resolver (hosts) is timed.
	resp = controllerGet(t, 19331, "/timeline/probe?host=tl.test&tls=1&chain=DIRECT&port="+port)
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	p = tlProbe{}
	_ = json.Unmarshal(b, &p)
	t.Logf("%s", b)
	if !p.OK || p.DNS.Ms == nil || p.Connect.Ms == nil {
		t.Fatalf("%s", b)
	}
	// Proxied chain → DNS is the proxy's, not shown.
	resp = controllerGet(t, 19331, "/timeline/probe?host=tl.test&tls=0&chain=SomeNode,Proxy&port="+port)
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	p = tlProbe{}
	_ = json.Unmarshal(b, &p)
	if p.DNS.Ms != nil || !strings.Contains(p.DNS.Note, "代理服务器") || p.FirstByte.Ms != nil {
		t.Fatalf("%s", b)
	}

	// Passive: start watching, then make a real request through the core.
	resp = controllerGet(t, 19331, "/timeline/conns")
	resp.Body.Close()
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		_, _ = io.WriteString(w, "ok")
	}))
	defer plain.Close()
	pu, _ := url.Parse(plain.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, info, _, err := dialThroughPolicy(ctx, pu.Host, "")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	_, _ = bufio.NewReader(c).ReadString('\n')
	time.Sleep(80 * time.Millisecond)
	resp = controllerGet(t, 19331, "/timeline/conns")
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	c.Close()
	var out struct {
		Records []tlRecord `json:"records"`
	}
	_ = json.Unmarshal(b, &out)
	var rec *tlRecord
	for i := range out.Records {
		if out.Records[i].ID == info.UUID.String() {
			rec = &out.Records[i]
		}
	}
	t.Logf("%s", b)
	if rec == nil || rec.Pre || rec.FirstUp == nil || rec.FirstDown == nil {
		t.Fatalf("record %+v", rec)
	}
	if rec.FirstUp.Lo < 40 || rec.FirstDown.Hi < 200 || rec.FirstDown.Hi-rec.FirstDown.Lo > 3*float64(tlTick/time.Millisecond) {
		t.Fatalf("bounds %+v %+v", rec.FirstUp, rec.FirstDown)
	}
}
