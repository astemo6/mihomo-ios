package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// feat/native-mitm stage 2 (Go side): connection handoff to a native TLS front with first-byte fallback, the
// upstream relay and per-host leaf identities. fakeTerm stands in for PacketTunnel/NativeMitM: a per-host TLS
// listener built from LeafIdentity (what SecPKCS12Import would get), HTTP/1.1 only, upstream through the relay.

type fakeTerm struct {
	e       *Engine
	mu      sync.Mutex
	ls      map[string]net.Listener
	calls   atomic.Int64
	lastALP atomic.Value
	mode    string // "" serve, "decline", "reset"
}

func (f *fakeTerm) Listen(host, alpn string) int64 {
	f.calls.Add(1)
	f.lastALP.Store(alpn)
	switch f.mode {
	case "decline":
		return 0
	case "reset":
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_ = c.Close() // reset before any ServerHello
			}
		}()
		f.mu.Lock()
		f.ls[host+"/reset"+fmt.Sprint(f.calls.Load())] = ln
		f.mu.Unlock()
		return int64(ln.Addr().(*net.TCPAddr).Port)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if ln, ok := f.ls[host]; ok {
		return int64(ln.Addr().(*net.TCPAddr).Port)
	}
	p12, err := f.e.LeafIdentity(host)
	if err != nil {
		return 0
	}
	key, leaf, chain, err := pkcs12.DecodeChain(p12, LeafIdentityPassword)
	if err != nil {
		return 0
	}
	cert := tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}
	for _, c := range chain {
		cert.Certificate = append(cert.Certificate, c.Raw)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		return 0
	}
	f.ls[host] = ln
	relay, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", f.e.RelayPort()))
	up := &http.Transport{Proxy: http.ProxyURL(relay), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out, _ := http.NewRequest(r.Method, "https://"+r.Host+r.URL.RequestURI(), r.Body)
		resp, err := up.RoundTrip(out)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.Header().Set("X-Native", "1")
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})}
	go func() { _ = srv.Serve(ln) }()
	return int64(ln.Addr().(*net.TCPAddr).Port)
}

func (f *fakeTerm) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ln := range f.ls {
		_ = ln.Close()
	}
}

func useFakeTerm(t *testing.T, h *harness, mode string) *fakeTerm {
	t.Helper()
	if _, err := h.e.StartRelay(); err != nil {
		t.Fatal(err)
	}
	f := &fakeTerm{e: h.e, ls: map[string]net.Listener{}, mode: mode}
	SetNativeTerminator(f)
	t.Cleanup(func() { SetNativeTerminator(nil); resetTermBreaker(); f.close() })
	return f
}

func termCfg() *Config {
	return &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(`^https://api\.test\.com/blocked - reject-200`)}
}

func TestNativeTermServesThroughRelay(t *testing.T) {
	h := newHarness(t, termCfg(), nil)
	f := useFakeTerm(t, h, "")
	handed, _ := TermStats()
	resp, body := h.get("https://api.test.com/json")
	if resp.Header.Get("X-Native") != "1" || !strings.Contains(body, `"keep":1`) {
		t.Fatalf("not served by the native front through the relay: %v %q", resp.Header, body)
	}
	if n, _ := TermStats(); n != handed+1 {
		t.Fatalf("handed %d", n-handed)
	}
	if f.calls.Load() != 1 {
		t.Fatalf("Listen called %d times", f.calls.Load())
	}
	if alpn, _ := f.lastALP.Load().(string); !strings.Contains(alpn, "http/1.1") {
		t.Fatalf("ALPN offer passed as %q", alpn)
	}
	h.e.tmu.Lock()
	dials := h.e.relay.Dials.Load()
	h.e.tmu.Unlock()
	if dials == 0 {
		t.Fatal("upstream did not go through the relay")
	}
}

func TestNativeTermFirstByteFallback(t *testing.T) {
	h := newHarness(t, termCfg(), nil)
	useFakeTerm(t, h, "reset")
	_, fell := TermStats()
	for i := 0; i < laneBreakerFails; i++ {
		h.client.CloseIdleConnections()
		resp, body := h.get("https://api.test.com/json")
		if resp.Header.Get("X-Native") != "" || !strings.Contains(body, `"keep":1`) {
			t.Fatalf("attempt %d: Go path did not take over: %q", i, body)
		}
	}
	if _, n := TermStats(); n != fell+int64(laneBreakerFails) {
		t.Fatalf("fell back %d times", n-fell)
	}
	if termNow() != nil {
		t.Fatal("breaker did not trip")
	}
	// Go's rewrites still apply on the fallback path
	h.client.CloseIdleConnections()
	if resp, _ := h.get("https://api.test.com/blocked"); resp.StatusCode != 200 {
		t.Fatalf("rewrite after fallback: %d", resp.StatusCode)
	}
}

func TestNativeTermDeclineAndH2Only(t *testing.T) {
	h := newHarness(t, termCfg(), nil)
	f := useFakeTerm(t, h, "decline")
	if resp, body := h.get("https://api.test.com/json"); resp.Header.Get("X-Native") != "" || !strings.Contains(body, `"keep":1`) {
		t.Fatalf("decline: %q", body)
	}
	if f.calls.Load() != 1 {
		t.Fatalf("Listen calls %d", f.calls.Load())
	}
	// an h2-only client (gRPC) is never offered to the HTTP/1.1 native front
	f.mode = ""
	pool := x509.NewCertPool()
	pool.AddCert(h.ca.Cert)
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", h.e.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "CONNECT api.test.com:443 HTTP/1.1\r\nHost: api.test.com:443\r\n\r\n")
	br := bufio.NewReader(c)
	if resp, err := http.ReadResponse(br, nil); err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v", err)
	}
	tc := tls.Client(&bufConn{Conn: c, r: br}, &tls.Config{ServerName: "api.test.com", RootCAs: pool, NextProtos: []string{"h2"}})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	if p := tc.ConnectionState().NegotiatedProtocol; p != "h2" || f.calls.Load() != 1 {
		t.Fatalf("h2-only client: negotiated %q, native Listen calls %d", p, f.calls.Load())
	}
}

func TestParseALPN(t *testing.T) {
	for _, protos := range [][]string{{"h2", "http/1.1"}, {"http/1.1"}, nil} {
		a, b := net.Pipe()
		go func() {
			_ = tls.Client(a, &tls.Config{ServerName: "x.test", NextProtos: protos, InsecureSkipVerify: true}).Handshake()
		}()
		br := bufio.NewReaderSize(b, 16<<10)
		_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
		hdr, err := br.Peek(5)
		if err != nil {
			t.Fatal(err)
		}
		rec, err := br.Peek(5 + (int(hdr[3])<<8 | int(hdr[4])))
		if err != nil {
			t.Fatal(err)
		}
		got := parseALPN(rec[5:])
		if strings.Join(got, ",") != strings.Join(protos, ",") {
			t.Fatalf("ALPN %v, want %v", got, protos)
		}
		if parseSNI(rec[5:]) != "x.test" {
			t.Fatal("SNI")
		}
		_ = a.Close()
		_ = b.Close()
	}
}

func TestLeafIdentityVerifies(t *testing.T) {
	h := newHarness(t, termCfg(), nil)
	p12, err := h.e.LeafIdentity("api.test.com")
	if err != nil {
		t.Fatal(err)
	}
	_, leaf, chain, err := pkcs12.DecodeChain(p12, LeafIdentityPassword)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(h.ca.Cert)
	if len(chain) != 1 || !chain[0].Equal(h.ca.Cert) {
		t.Fatal("chain must carry the CA")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "api.test.com", Roots: roots}); err != nil {
		t.Fatal(err)
	}
}

func TestRelayConnectOnly(t *testing.T) {
	h := newHarness(t, termCfg(), nil)
	if _, err := h.e.StartRelay(); err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", h.e.RelayPort())
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, "GET http://api.test.com/ HTTP/1.1\r\nHost: api.test.com\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != 405 {
		t.Fatalf("plain GET through the relay: %v %v", resp, err)
	}
	c.Close()
	c, _ = net.Dial("tcp", addr)
	_, _ = io.WriteString(c, "CONNECT api.test.com:443 HTTP/1.1\r\nHost: api.test.com:443\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err = http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v %v", resp, err)
	}
	tc := tls.Client(&bufConn{Conn: c, r: br}, &tls.Config{ServerName: "api.test.com", InsecureSkipVerify: true})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		t.Fatalf("TLS to the upstream through the relay: %v", err)
	}
	tc.Close()
	h.e.StopRelay()
	if h.e.RelayPort() != 0 {
		t.Fatal("relay still running")
	}
}

func TestNativeHandshakeFailurePins(t *testing.T) {
	h := newHarness(t, termCfg(), nil)
	if h.e.NativeHandshakeFailed("api.test.com", "timeout") {
		t.Fatal("timeout pinned")
	}
	for i := 0; i < pinStrikes-1; i++ {
		if h.e.NativeHandshakeFailed("api.test.com", "closed") {
			t.Fatalf("strike %d pinned early", i)
		}
	}
	if !h.e.NativeHandshakeFailed("api.test.com", "closed") {
		t.Fatal("strikes did not pin")
	}
	if h.e.shouldIntercept(h.e.state(), "api.test.com", 443) {
		t.Fatal("pinned host still intercepted")
	}
	if !h.e.NativeHandshakeFailed("other.test.com", "cert") {
		t.Fatal("certificate alert did not pin")
	}
}
