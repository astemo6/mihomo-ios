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
	"runtime/metrics"
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
	return map[string]any{"on": mitm.NativeFrontActive(), "handed": h, "fellBack": f, "selective": mitm.NativeSelective()}
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
func MitmBenchStartRules(rules string) string { return benchStart(rules, nil, nil) }

// benchHeavyConf (feat/selective-native): the large-body bench's rules on its second host heavy.bench.test — a
// response jq rule on /jq and a requires-body response script on /script, both on the bench origin's big JSON
// (/jq?kb=N, /script?kb=N: N KB). api.bench.test keeps no rules (plain MitM pass-through).
const benchHeavyConf = `rule: http-response-jq ^https://heavy\.bench\.test/jq '.data.list = [] | .data.combo = true'
heavy = type=http-response,pattern=^https://heavy\.bench\.test/script,requires-body=1,max-size=-1,script-path=heavy.js`

const benchHeavyScript = `var o = JSON.parse($response.body); o.data.list = o.data.list.slice(0, 1); o.data.combo = true; $done({body: JSON.stringify(o)});`

// MitmBenchHeavyConf returns benchHeavyConf (for MitmBenchStartConf).
func MitmBenchHeavyConf() string { return benchHeavyConf }

// MitmBenchStartConf starts the bench with conf lines as MitmScriptTestStart reads them ("rule: …" a rewrite rule,
// anything else a [Script] line) and the heavy bench's script file (heavy.js).
func MitmBenchStartConf(conf string) string {
	var rules []string
	var scripts []string
	for _, l := range strings.Split(conf, "\n") {
		if l = strings.TrimSpace(l); l == "" {
			continue
		}
		if r, ok := strings.CutPrefix(l, "rule:"); ok {
			rules = append(rules, strings.TrimSpace(r))
		} else {
			scripts = append(scripts, l)
		}
	}
	return benchStart(strings.Join(rules, "\n"), scripts, map[string]string{"heavy.js": benchHeavyScript})
}

// benchBig returns the bench origin's JSON of at least kb KB: {"ret":0,"data":{"list":[{…}, …],"keep":1}}.
var benchBigMu sync.Mutex
var benchBigs = map[int][]byte{}

func benchBig(kb int) []byte {
	benchBigMu.Lock()
	defer benchBigMu.Unlock()
	if b, ok := benchBigs[kb]; ok {
		return b
	}
	var sb strings.Builder
	sb.WriteString(`{"ret":0,"data":{"list":[`)
	for i := 0; sb.Len() < kb<<10; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`{"id":` + strconv.Itoa(i) + `,"title":"bench item ` + strconv.Itoa(i) + ` lorem ipsum dolor sit amet","tags":["a","b","c"],"score":1.5,"ad":false}`)
	}
	sb.WriteString(`],"keep":1}}`)
	b := []byte(sb.String())
	benchBigs[kb] = b
	return b
}

func benchStart(rules string, scriptLines []string, scriptFiles map[string]string) string {
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
	cfg := &mitm.Config{Enabled: true, MitM: true, Hostnames: []string{"api.bench.test", "heavy.bench.test"}, SkipCertVerify: true}
	for i, l := range strings.Split(rules, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			cfg.Rules = append(cfg.Rules, mitm.Item{ID: "bench" + strconv.Itoa(i), Enabled: true, Line: l})
		}
	}
	for i, l := range scriptLines {
		cfg.Scripts = append(cfg.Scripts, mitm.Item{ID: "benchs" + strconv.Itoa(i), Enabled: true, Line: l})
	}
	_ = os.MkdirAll(mitm.ScriptsDir(home), 0o755)
	for name, src := range scriptFiles {
		if err := os.WriteFile(filepath.Join(mitm.ScriptsDir(home), name), []byte(src), 0o644); err != nil {
			e.Stop()
			return fail(err)
		}
	}
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
		if kb, err := strconv.Atoi(r.URL.Query().Get("kb")); err == nil && kb > 0 {
			b := benchBig(kb) // Content-Length, not chunked: the native body engines need a known length
			w.Header().Set("Content-Length", strconv.Itoa(len(b)))
			_, _ = w.Write(b)
			return
		}
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
	if strings.TrimSpace(rules) != "" || len(scriptLines) > 0 {
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

// MitmBenchMemPeek: Go memory without a GC (cheap, no stop-the-world; the large-body bench samples it every 20 ms
// during a burst). JSON {heapObjects, mapped}: live + not-yet-swept heap objects, and Go's mapped memory minus what
// it released to the OS.
func MitmBenchMemPeek() string {
	s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}, {Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}}
	metrics.Read(s)
	v := func(i int) uint64 {
		if s[i].Value.Kind() == metrics.KindUint64 {
			return s[i].Value.Uint64()
		}
		return 0
	}
	out, _ := json.Marshal(map[string]any{"heapObjects": v(0), "mapped": v(1) - v(2)})
	return string(out)
}

// MitmBenchSelective: JSON {handed, skipped, learned} of selective mode (bridge/mitm/selective.go).
func MitmBenchSelective() string { return MitmNativeSelectiveStats() }

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
