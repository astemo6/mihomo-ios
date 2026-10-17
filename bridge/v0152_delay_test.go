package libmihomo

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/hub/executor"
	"go.yaml.in/yaml/v3"
)

// v0152SlowProxy is an HTTPS CONNECT proxy that delays the CONNECT and every client→target chunk by lat,
// i.e. one simulated round trip per handshake step and per HTTP request.
func v0152SlowProxy(t *testing.T, lat time.Duration) (string, int) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		time.Sleep(lat)
		dst, err := net.Dial("tcp", r.Host)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		hj, _ := w.(http.Hijacker)
		c, brw, _ := hj.Hijack()
		_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() {
			rd := bufio.NewReader(brw)
			buf := make([]byte, 32<<10)
			for {
				n, err := rd.Read(buf)
				if n > 0 {
					time.Sleep(lat)
					_, _ = dst.Write(buf[:n])
				}
				if err != nil {
					_ = dst.Close()
					return
				}
			}
		}()
		_, _ = io.Copy(c, dst)
		_ = c.Close()
	}))
	srv.StartTLS()
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	p, _ := strconv.Atoi(u.Port())
	return u.Hostname(), p
}

// v0.15.2 device report: offline 测速 (app process, tunnel down — e.g. while QX is connected) showed
// far higher numbers than QX for the same URL. The app process never applied a config, so
// adapter.UnifiedDelay was false there and the number included every handshake. Now it is one round
// trip over the established connection, like the running core and QX.
func TestV0152OfflineDelayIsOneRoundTrip(t *testing.T) {
	const lat = 60 * time.Millisecond
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer target.Close()
	host, port := v0152SlowProxy(t, lat)
	node := fmt.Sprintf(`{"name":"slow","type":"http","server":%q,"port":%d,"tls":true,"skip-cert-verify":true}`, host, port)
	testURL := target.URL + "/generate_204"

	// Before (what v0.15.1 measured in the app process): first request incl. CONNECT + TLS.
	adapter.UnifiedDelay.Store(false)
	var m map[string]any
	_ = json.Unmarshal([]byte(node), &m)
	old, err := testDelayOnce(m, testURL, 5000)
	if err != nil {
		t.Fatal(err)
	}

	got := TestDelay(node, testURL, 5000)
	t.Logf("offline delay: before %d ms, after %d ms (simulated RTT %d ms)", old, got, lat.Milliseconds())
	if got < int(lat.Milliseconds())-5 || got > int(lat.Milliseconds())*3/2 {
		t.Fatalf("offline delay %d ms, want ≈ one round trip (%d ms)", got, lat.Milliseconds())
	}
	if old < int(lat.Milliseconds())*2-5 {
		t.Fatalf("baseline %d ms should include the CONNECT round trip", old)
	}
	if !adapter.UnifiedDelay.Load() {
		t.Fatal("TestDelay must leave unified delay on in the app process")
	}

	// A physical interface that does not exist (or cannot be bound) falls back to normal routing.
	SetOfflineTestInterface("nonexistent-if0")
	defer SetOfflineTestInterface("")
	if d := TestDelay(node, testURL, 5000); d <= 0 || d > int(lat.Milliseconds())*3/2 {
		t.Fatalf("bound-interface fallback: %d ms (%s)", d, LastError())
	}
	// Unreachable node still reports failure.
	if d := TestDelay(`{"name":"x","type":"http","server":"127.0.0.1","port":1}`, testURL, 800); d != -1 {
		t.Fatalf("dead node: %d", d)
	}
}

func TestV0152PlainNameserver(t *testing.T) {
	for s, want := range map[string]bool{
		"119.29.29.29": true, "119.29.29.29:53": true, "udp://223.5.5.5": true, "tcp://1.1.1.1:53": true,
		"[2400:3200::1]:53": true, "2400:3200::1": true, "system": true,
		"https://223.5.5.5/dns-query": false, "tls://dns.google": false, "quic://dns.adguard.com": false,
		"dhcp://en0": false, "8.8.8.8#proxy": false, "dns.google": false, "": false,
	} {
		if plainNameserver(s) != want {
			t.Errorf("plainNameserver(%q) = %v", s, !want)
		}
	}
}

// Node hostnames resolve with plain servers unless the profile / DNS page chose proxy-server-nameserver.
func TestV0152DefaultProxyServerNameserver(t *testing.T) {
	psn := func(profile string) []any {
		t.Helper()
		rt, err := buildRuntime([]byte(profile), defaultOverrides(), 0)
		if err != nil {
			t.Fatal(err)
		}
		raw := map[string]any{}
		_ = yaml.Unmarshal(rt, &raw)
		return asList(asMap(raw["dns"])["proxy-server-nameserver"])
	}
	base := "proxies:\n  - {name: a, type: ss, server: example.com, port: 1, cipher: aes-128-gcm, password: x}\nrules:\n  - MATCH,a\n"
	// No dns section: the app's DoH defaults → plain default-nameserver for node hostnames.
	if got := fmt.Sprint(psn(base)); got != "[223.5.5.5 119.29.29.29]" {
		t.Fatalf("default: %s", got)
	}
	// QX import shape: plain servers + system.
	qx := base + "dns:\n  nameserver: [1.2.4.8, 119.29.29.29, system]\n  default-nameserver: [1.2.4.8, 119.29.29.29]\n"
	if got := fmt.Sprint(psn(qx)); got != "[1.2.4.8 119.29.29.29 system]" {
		t.Fatalf("qx: %s", got)
	}
	// DoH-only with a plain bootstrap.
	doh := base + "dns:\n  nameserver: ['https://1.1.1.1/dns-query']\n  default-nameserver: ['tls://9.9.9.9', 1.0.0.1]\n"
	if got := fmt.Sprint(psn(doh)); got != "[1.0.0.1]" {
		t.Fatalf("doh: %s", got)
	}
	// The profile's own choice wins.
	own := base + "dns:\n  proxy-server-nameserver: ['https://dns.alidns.com/dns-query']\n"
	if got := fmt.Sprint(psn(own)); got != "[https://dns.alidns.com/dns-query]" {
		t.Fatalf("own: %s", got)
	}
	// Nothing plain anywhere → built-in plain pair.
	none := base + "dns:\n  nameserver: ['https://1.1.1.1/dns-query']\n  default-nameserver: ['tls://9.9.9.9']\n"
	if got := fmt.Sprint(psn(none)); got != "[223.5.5.5 119.29.29.29]" {
		t.Fatalf("none: %s", got)
	}
	// The runtime still parses (respect-rules needs a proxy-server-nameserver; now always present).
	rr := base + "dns:\n  respect-rules: true\n"
	rt, err := buildRuntime([]byte(rr), defaultOverrides(), 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := executor.ParseWithBytes(rt)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DNS.ProxyServerNameserver) == 0 {
		t.Fatal("proxy-server-nameserver not applied")
	}
}
