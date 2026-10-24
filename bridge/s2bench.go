package libmihomo

// Native MitM stage 2 memory bench (feat/s2-pipe): a self-contained MitM engine + origin for the simulator unit
// test UnitTests/NativeMitmMemoryTests.swift, which drives a burst of MitM connections through it with the Go
// path and with the native front, and reads the process footprint. Never used by the app or the tunnel; refuses
// to run while a real engine exists.

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

type s2bench struct {
	e      *mitm.Engine
	origin net.Listener
	srv    *http.Server
	home   string
}

var benchCur *s2bench

// nativeMitmStatus is the 隧道内存 snapshot's "native" object: whether stage 2 is live, connections handed over /
// fallen back since start (the tunnel adds its live session count).
func nativeMitmStatus() map[string]any {
	h, f := mitm.TermStats()
	return map[string]any{"on": mitm.NativeFrontActive(), "handed": h, "fellBack": f}
}

// benchRelay copies a ↔ b like mihomo's relay of one INNER connection (two goroutines, two 32 KiB buffers),
// standing in for the core the bench does not run.
func benchRelay(a, b net.Conn) {
	cp := func(dst, src net.Conn) {
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		_ = dst.Close()
		_ = src.Close()
	}
	go cp(a, b)
	go cp(b, a)
}

// MitmBenchStart starts the bench engine for host "api.bench.test" (every upstream reaches a local origin that
// answers small JSON, through a mihomo stand-in). Returns JSON {enginePort, ca (base64 DER)} or {error}.
func MitmBenchStart() string {
	fail := func(err error) string {
		b, _ := json.Marshal(map[string]string{"error": err.Error()})
		return string(b)
	}
	engMu.Lock()
	defer engMu.Unlock()
	if eng != nil || benchCur != nil {
		return fail(errors.New("engine already running"))
	}
	home, err := os.MkdirTemp("", "s2bench")
	if err != nil {
		return fail(err)
	}
	ca, err := mitm.GenerateCA(home)
	if err != nil {
		return fail(err)
	}
	b := &s2bench{home: home}
	var originAddr string
	dialOrigin := func() (net.Conn, error) { return net.Dial("tcp", originAddr) }
	e := mitm.New(home, func(ctx context.Context, network, addr, policy string) (net.Conn, error) {
		tc, err := dialOrigin()
		if err != nil {
			return nil, err
		}
		c1, c2 := net.Pipe() // inner.HandleTcp
		benchRelay(c2, tc)
		return c1, nil
	}, func(string, string) {})
	if err := e.Start(); err != nil {
		return fail(err)
	}
	b.e = e
	cfg := &mitm.Config{Enabled: true, MitM: true, Hostnames: []string{"api.bench.test"}, SkipCertVerify: true}
	_ = os.MkdirAll(mitm.ScriptsDir(home), 0o755)
	e.Reload(cfg, mitm.Build(home, cfg))
	p12, err := e.LeafIdentity("api.bench.test")
	if err != nil {
		e.Stop()
		return fail(err)
	}
	key, leaf, chain, err := pkcs12.DecodeChain(p12, mitm.LeafIdentityPassword)
	if err != nil {
		e.Stop()
		return fail(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}
	for _, c := range chain {
		cert.Certificate = append(cert.Certificate, c.Raw)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		e.Stop()
		return fail(err)
	}
	originAddr = ln.Addr().String()
	b.origin = ln
	b.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ret":0,"data":{"list":[1,2,3],"keep":1}}`)
	})}
	go func() { _ = b.srv.Serve(ln) }()
	if _, err := e.StartRelay(); err != nil {
		e.Stop()
		return fail(err)
	}
	e.SetRelayHandoff(func(c net.Conn, target, policy string) error {
		tc, err := dialOrigin()
		if err != nil {
			return err
		}
		benchRelay(c, tc) // tunnel.HandleTCPConn on the socket itself
		return nil
	})
	eng, benchCur = e, b
	out, _ := json.Marshal(map[string]any{"enginePort": e.Port(), "ca": base64.StdEncoding.EncodeToString(ca.DER)})
	return string(out)
}

// MitmBenchMem: Go runtime numbers after a GC (JSON: heapInuse, sys, stack, goroutines, handed, fellBack).
func MitmBenchMem() string {
	runtime.GC()
	debug.FreeOSMemory()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	h, f := mitm.TermStats()
	out, _ := json.Marshal(map[string]any{"heapInuse": m.HeapInuse, "sys": m.Sys - m.HeapReleased, "stack": m.StackInuse,
		"goroutines": runtime.NumGoroutine(), "handed": h, "fellBack": f})
	return string(out)
}

// MitmBenchStop tears the bench down.
func MitmBenchStop() {
	engMu.Lock()
	b := benchCur
	benchCur = nil
	if b != nil && eng == b.e {
		eng = nil
	}
	engMu.Unlock()
	if b == nil {
		return
	}
	mitm.SetNativeTerminator(nil)
	b.e.Stop()
	_ = b.srv.Close()
	_ = os.RemoveAll(filepath.Clean(b.home))
}
