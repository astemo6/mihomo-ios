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
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

type s2bench struct {
	e      *mitm.Engine
	origin net.Listener
	srv    *http.Server
	home   string
	// prevLimit: the Go memory limit before a bench with rules pinned it off (-1: not pinned)
	prevLimit   int64
	prevProbe   MemoryProbe
	probePinned bool
}

var benchCur *s2bench

// benchLog keeps the bench engine's last log lines (MitmBenchLog), so a failing bench run can say why.
var benchLog struct {
	sync.Mutex
	lines []string
}

func benchLogf(level, msg string) {
	benchLog.Lock()
	benchLog.lines = append(benchLog.lines, level+" "+msg)
	if n := len(benchLog.lines); n > 40 {
		benchLog.lines = append([]string(nil), benchLog.lines[n-40:]...)
	}
	benchLog.Unlock()
}

// MitmBenchLog returns (and clears) the bench engine's recent log lines, newline-separated.
func MitmBenchLog() string {
	benchLog.Lock()
	defer benchLog.Unlock()
	s := strings.Join(benchLog.lines, "\n")
	benchLog.lines = nil
	return s
}

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
func MitmBenchStart() string { return MitmBenchStartRules("") }

// benchComboRules: the combo bench's rule set (native-final) — a request header rule, a response header rule and a
// response jq rule on the bench JSON, all of which the native rewrite / body engines decide in Swift.
const benchComboRules = `http-request ^https://api\.bench\.test/json header-add X-Bench 1
http-response ^https://api\.bench\.test/json header-add X-Bench-Resp 1
http-response-jq ^https://api\.bench\.test/json '.data.list = [] | .data.combo = true'`

// MitmBenchComboRules returns benchComboRules (for MitmBenchStartRules).
func MitmBenchComboRules() string { return benchComboRules }

// MitmBenchStartRules is MitmBenchStart with rewrite rules (newline-separated [URL Rewrite] / [Header Rewrite] /
// body / jq lines) on the bench host — the combo memory bench (native-final) measures the rule engines too.
func MitmBenchStartRules(rules string) string {
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
	b := &s2bench{home: home, prevLimit: -1}
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
	}, benchLogf)
	if err := e.Start(); err != nil {
		return fail(err)
	}
	b.e = e
	cfg := &mitm.Config{Enabled: true, MitM: true, Hostnames: []string{"api.bench.test"}, SkipCertVerify: true}
	for i, l := range strings.Split(rules, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			cfg.Rules = append(cfg.Rules, mitm.Item{ID: "bench" + strconv.Itoa(i), Enabled: true, Line: l})
		}
	}
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
	if strings.TrimSpace(rules) != "" {
		// body rules: earlier tests in the same process may leave a Go memory limit behind (GOMEMLIMIT / the
		// governor), and heapHigh() would then skip the jq rule on the Go path — the bench compares paths, not gates
		b.prevLimit = debug.SetMemoryLimit(math.MaxInt64)
		// …and a registered available-memory probe (the simulator answers 0) would make every body gate say no
		if pb, _ := memProbe.Load().(probeBox); pb.p != nil {
			b.prevProbe, b.probePinned = pb.p, true
			mitm.SetAvailableMemoryProbe(nil)
		}
	}
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
	if b.prevLimit >= 0 {
		debug.SetMemoryLimit(b.prevLimit)
	}
	if b.probePinned {
		SetMemoryProbe(b.prevProbe)
	}
	b.e.Stop()
	_ = b.srv.Close()
	_ = os.RemoveAll(filepath.Clean(b.home))
}
