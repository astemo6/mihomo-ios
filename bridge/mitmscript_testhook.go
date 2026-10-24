package libmihomo

// Test hooks for the native script dispatcher's conformance test (UnitTests/NativeMitmScriptTests.swift, lane
// s3-script): the unit-test host runs no tunnel, so the test starts a stand-alone MitM engine here and drives the
// same requests through the Go flow API (Go dispatch) and through the Swift dispatcher (native dispatch), both on
// the JavaScriptCore engine and the native body lane registered in the process. Never called by the app or the
// tunnel; refused while a real engine runs.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/astemo6/mihomo-ios/bridge/mitm"
)

var testHook struct {
	mu      sync.Mutex
	e       *mitm.Engine
	ln      net.Listener
	logSeq  int64
	reqSeq  int64
	started bool
}

// MitmScriptTestStart starts the test engine: conf holds [Script] lines (Surge syntax; lines starting with "rule:"
// are rewrite / header rules; script-path names a file of
// scriptsJSON, {"name.js": "source"}, written to the engine's scripts dir), hostnames the MitM host list
// (comma-separated). $httpClient requests of the scripts reach an in-process HTTP server whatever their host:
// /echo answers {"method","path","ua","body"} as JSON, /gz the same gzip-encoded. Returns "" or the error.
func MitmScriptTestStart(home, conf, scriptsJSON, hostnames string) string {
	testHook.mu.Lock()
	defer testHook.mu.Unlock()
	engMu.Lock()
	defer engMu.Unlock()
	if eng != nil && !testHook.started {
		return "a MitM engine is already running"
	}
	if testHook.started {
		stopTestEngineLocked()
	}
	var scripts map[string]string
	if err := json.Unmarshal([]byte(scriptsJSON), &scripts); err != nil {
		return "scripts: " + err.Error()
	}
	dir := mitm.ScriptsDir(home)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err.Error()
	}
	for name, src := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			return err.Error()
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err.Error()
	}
	go func() { _ = http.Serve(ln, http.HandlerFunc(testEcho)) }()
	addr := ln.Addr().String()
	dial := func(ctx context.Context, network, _ string, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	e := mitm.New(home, dial, nil)
	if err := e.Start(); err != nil {
		_ = ln.Close()
		return err.Error()
	}
	off := false
	cfg := &mitm.Config{Enabled: true, MitM: true, CaptureBodies: &off}
	for _, h := range strings.Split(hostnames, ",") {
		if h = strings.TrimSpace(h); h != "" {
			cfg.Hostnames = append(cfg.Hostnames, h)
		}
	}
	i := 0
	for _, l := range strings.Split(conf, "\n") {
		if l = strings.TrimSpace(l); l == "" {
			continue
		}
		it := mitm.Item{ID: fmt.Sprint(i), Enabled: true, Line: l}
		i++
		if r, ok := strings.CutPrefix(l, "rule:"); ok {
			it.Line = strings.TrimSpace(r) // a rewrite / header rule line ([URL Rewrite] / [Header Rewrite] syntax)
			cfg.Rules = append(cfg.Rules, it)
			continue
		}
		cfg.Scripts = append(cfg.Scripts, it)
	}
	rs := mitm.Build(home, cfg)
	if len(rs.Errors) > 0 {
		e.Stop()
		_ = ln.Close()
		return "build: " + strings.Join(rs.Errors, "; ")
	}
	e.Reload(cfg, rs)
	eng = e
	testHook.e, testHook.ln, testHook.started = e, ln, true
	testHook.logSeq, testHook.reqSeq = 0, 0
	return ""
}

func stopTestEngineLocked() {
	if testHook.e != nil {
		testHook.e.Stop()
		if eng == testHook.e {
			eng = nil
		}
	}
	if testHook.ln != nil {
		_ = testHook.ln.Close()
	}
	testHook.e, testHook.ln, testHook.started = nil, nil, false
}

// MitmScriptTestStop stops the test engine (no-op when none runs).
func MitmScriptTestStop() {
	testHook.mu.Lock()
	defer testHook.mu.Unlock()
	engMu.Lock()
	defer engMu.Unlock()
	if testHook.started {
		stopTestEngineLocked()
	}
}

// MitmScriptTestTake returns what the test engine logged since the last call: JSON {"logs": [{script, level, msg,
// count}], "requests": [{url, status, matched, notes, done, bytes}]} (request entries that are finished).
func MitmScriptTestTake() string {
	testHook.mu.Lock()
	defer testHook.mu.Unlock()
	e := testHook.e
	if e == nil {
		return `{"logs":[],"requests":[]}`
	}
	type logJS struct {
		Script string `json:"script"`
		Level  string `json:"level"`
		Msg    string `json:"msg"`
		Count  int    `json:"count,omitempty"`
	}
	type reqJS struct {
		URL     string   `json:"url"`
		Status  int      `json:"status"`
		Matched []string `json:"matched"`
		Notes   []string `json:"notes"`
		Bytes   int64    `json:"bytes"`
	}
	out := struct {
		Logs     []logJS `json:"logs"`
		Requests []reqJS `json:"requests"`
	}{Logs: []logJS{}, Requests: []reqJS{}}
	for _, l := range e.Logs.List(testHook.logSeq, "") {
		out.Logs = append(out.Logs, logJS{l.Script, l.Level, l.Msg, l.Count})
		if l.ID > testHook.logSeq {
			testHook.logSeq = l.ID
		}
	}
	for _, s := range e.Requests.List(testHook.reqSeq) {
		ent := e.Requests.Get(s.ID)
		if ent == nil {
			continue
		}
		b, _ := json.Marshal(ent)
		var full struct {
			Done  bool  `json:"done"`
			Bytes int64 `json:"bytes"`
		}
		_ = json.Unmarshal(b, &full)
		if !full.Done {
			break // keep it for the next call
		}
		out.Requests = append(out.Requests, reqJS{URL: s.URL, Status: s.Status, Matched: s.Matched, Notes: s.Notes, Bytes: full.Bytes})
		if s.ID > testHook.reqSeq {
			testHook.reqSeq = s.ID
		}
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// MitmScriptTestEncode encodes data with a Content-Encoding the engine decodes (gzip, deflate = zlib, br) for the
// test's upstream bodies; nil for an unknown one.
func MitmScriptTestEncode(enc string, data []byte) []byte {
	var buf bytes.Buffer
	var w io.WriteCloser
	switch enc {
	case "gzip":
		w = gzip.NewWriter(&buf)
	case "deflate":
		w = zlib.NewWriter(&buf)
	case "br":
		w = brotli.NewWriter(&buf)
	default:
		return nil
	}
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

// testEcho is the $httpClient test server.
func testEcho(w http.ResponseWriter, r *http.Request) {
	var body bytes.Buffer
	_, _ = body.ReadFrom(bufio.NewReader(r.Body))
	js, _ := json.Marshal(map[string]string{"method": r.Method, "path": r.URL.Path, "ua": r.Header.Get("User-Agent"), "body": body.String()})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Set-Cookie", "sid=1; Path=/")
	if strings.HasPrefix(r.URL.Path, "/gz") {
		var gz bytes.Buffer
		zw := gzip.NewWriter(&gz)
		_, _ = zw.Write(js)
		_ = zw.Close()
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(gz.Bytes())
		return
	}
	_, _ = w.Write(js)
}
