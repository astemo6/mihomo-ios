package mitm

// Opt-in: the user's real rewrite resources (work/qx-rewrite-remote.txt: QX [rewrite_remote] list, 29 entries,
// downloaded with their scripts by the v0.19.22 audit into TERN_QX_AUDIT_DIR=<dir>, see qxaudit_run_test.go)
// plus the 30-module Surge / Loon / Egern corpus (<dir>/corpus/mod) driven through the Go path and the native
// flow API side by side. Every rule of every resource — URL rewrites, rejects, redirects, Map Local, header
// and body rewrites, request and response scripts — gets a sample URL; both paths must answer alike.
// TERN_FLOW_PARITY_OUT=<file> writes the per-rule results as JSON. Not in CI (third-party files).

import (
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type flowParityRow struct {
	Entry, Kind, Rule, Sample string
	Status                    string // same / differ / nosample / nomitm / plainhttp
	Detail                    string `json:",omitempty"`
	Decisions                 string `json:",omitempty"`
}

func TestFlowQXCorpusParity(t *testing.T) {
	dir := os.Getenv("TERN_QX_AUDIT_DIR")
	if dir == "" {
		t.Skip("audit only (TERN_QX_AUDIT_DIR)")
	}
	only := os.Getenv("TERN_QX_AUDIT_ONLY")
	var lane *fakeLane
	if os.Getenv("TERN_FLOW_LANE") == "1" {
		// script bodies through the native lane (fake store + native engine stand-in), on both paths
		lane = useFakeLane(t)
	}
	urlFile := map[string]string{}
	if f, err := os.Open(filepath.Join(dir, "dl_all.tsv")); err == nil {
		r := csv.NewReader(f)
		r.Comma, r.FieldsPerRecord = '\t', -1
		rows, _ := r.ReadAll()
		f.Close()
		for _, row := range rows {
			if len(row) >= 4 && row[1] == "200" {
				urlFile[row[3]] = filepath.Join(dir, "scripts", row[0]+".js")
			}
		}
	}
	var files []string
	for _, g := range []string{"res/*", "corpus/mod/*"} {
		m, _ := filepath.Glob(filepath.Join(dir, g))
		sort.Strings(m)
		files = append(files, m...)
	}
	var rows []flowParityRow
	for _, f := range files {
		if only != "" && !strings.Contains(filepath.Base(f), only) {
			continue
		}
		text, _ := os.ReadFile(f)
		rows = append(rows, flowParityEntry(t, filepath.Base(f), text, urlFile)...)
	}
	count := map[string]int{}
	byKind := map[string]map[string]int{}
	for _, r := range rows {
		count[r.Status]++
		if byKind[r.Kind] == nil {
			byKind[r.Kind] = map[string]int{}
		}
		byKind[r.Kind][r.Status]++
	}
	t.Logf("resources %d, rules %d: %v; by kind %v", len(files), len(rows), count, byKind)
	if lane != nil {
		t.Logf("lane: %d bodies opened, %d handles live", lane.opened.Load(), lane.live())
		waitLive(t, lane)
	}
	if out := os.Getenv("TERN_FLOW_PARITY_OUT"); out != "" {
		j, _ := json.MarshalIndent(map[string]any{"summary": count, "byKind": byKind, "rows": rows}, "", " ")
		_ = os.WriteFile(out, j, 0o644)
	}
	if count["differ"] > 0 {
		t.Errorf("%d rules answered differently through the flow API", count["differ"])
	}
}

func flowParityEntry(t *testing.T, file string, text []byte, urlFile map[string]string) []flowParityRow {
	home := t.TempDir()
	if _, err := GenerateCA(home); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Dir(ModulePath(home, "m")), 0o755)
	_ = os.WriteFile(ModulePath(home, "m"), text, 0o644)
	for u, p := range urlFile {
		if b, err := os.ReadFile(p); err == nil {
			seedScript(t, home, u, b)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		// a deterministic answer per request that also shows what the upstream received
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Up-Method", r.Method)
		w.Header().Set("X-Up-Body-Len", strconv.Itoa(len(b)))
		keys := make([]string, 0, len(r.Header))
		for k := range r.Header {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var hs []string
		for _, k := range keys {
			hs = append(hs, k+"="+strings.Join(r.Header[k], ","))
		}
		w.Header().Set("X-Up-Headers", clip(strings.Join(hs, ";"), 2000))
		_, _ = w.Write(genericBody(r.URL.String()))
	})
	up := httptest.NewUnstartedServer(mux)
	up.EnableHTTP2 = true
	up.StartTLS()
	defer up.Close()
	dial := func(ctx context.Context, network, addr, policy string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", up.Listener.Addr().String())
	}
	e := New(home, dial, nil)
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	cfg := &Config{Enabled: true, MitM: true, SkipCertVerify: true, CaptureBodies: noCapture(), Modules: []Module{{ID: "m", Name: file, Enabled: true}}}
	rs := Build(home, cfg)
	e.Reload(cfg, rs)
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", e.Port()))
	tr := &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true, DisableCompression: true}
	c := &http.Client{Transport: tr, Timeout: 70 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer tr.CloseIdleConnections()
	hm := NewHostMatcher(rs.Hostnames)
	sim := newFlowSim(t, e)
	var out []flowParityRow
	seen := map[string]bool{}
	perScript := map[string]int{}
	var mu sync.Mutex
	for _, r := range rs.Rules {
		row := flowParityRow{Entry: file, Kind: string(r.Kind), Rule: clip(r.Pattern, 160)}
		if r.Kind == KindScript {
			row.Kind += ":" + r.Script.Type
			perScript[r.Script.Path]++
			if perScript[r.Script.Path] > 3 {
				continue // big snippets repeat one script for dozens of patterns
			}
		}
		s := sampleURL(r.Pattern)
		if strings.HasPrefix(s, "http://") && r.match("https://"+s[7:]) {
			s = "https://" + s[7:]
		}
		su, err := url.Parse(s)
		if s == "" || err != nil || !r.match(s) || su.Host == "" || su.Scheme != "https" && su.Scheme != "http" {
			row.Status, row.Sample = "nosample", s
			out = append(out, row)
			continue
		}
		row.Sample = s
		if su.Scheme != "https" {
			// the native front only ever sees decrypted TLS connections (plain HTTP stays on the Go path)
			row.Status = "plainhttp"
			out = append(out, row)
			continue
		}
		port := 443
		if p := su.Port(); p != "" {
			port, _ = strconv.Atoi(p)
		}
		if !hm.Match(su.Hostname(), port) {
			// not decrypted on the Go path either: such connections never reach the native front
			row.Status = "nomitm"
			out = append(out, row)
			continue
		}
		method, body := "GET", []byte(nil)
		if r.Kind == KindScript && strings.HasPrefix(r.Script.Type, "http-request") && r.Script.RequiresBody && !r.Script.Echo {
			method, body = "POST", []byte(`{"a":1,"keywords":["x"]}`)
		}
		if r.Kind == KindBody && r.Phase == "request" {
			method, body = "POST", []byte(`{"a":1,"keywords":["x"]}`)
		}
		key := method + " " + s
		if seen[key] {
			continue
		}
		seen[key] = true
		hdr := http.Header{"User-Agent": {"Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X)"}, "Cookie": {"uid=1; token=abc"}, "Authorization": {"Bearer abc"}}
		g := goDo(t, c, method, s, hdr, body)
		f := sim.do(method, s, hdr, body)
		why := sameOutcome(g, f)
		if why != "" {
			if g2 := goDo(t, c, method, s, hdr, body); sameOutcome(g2, f) == "" {
				why = ""
			}
		}
		mu.Lock()
		if why == "" {
			row.Status = "same"
		} else {
			row.Status, row.Detail = "differ", clip(why, 1500)
			b, _ := json.Marshal(f.decisions)
			row.Decisions = clip(string(b), 1500)
			t.Errorf("%s %s %s: %s", file, row.Kind, clip(s, 120), clip(why, 600))
		}
		out = append(out, row)
		mu.Unlock()
	}
	waitFlows(t)
	return out
}
