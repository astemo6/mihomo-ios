package mitm

// Opt-in audit of a user's real QX [rewrite_remote] list (TERN_QX_AUDIT_DIR=<dir> with res/, scripts/,
// dl.tsv, list.txt from the audit). Not part of CI: the resources and scripts are third-party files that
// are not committed. Every script rule of every resource is driven once (5× for warm timing) through a
// real engine, under the tunnel conditions of v01921_test.go (26 MB soft limit, 19 MB live core heap,
// 20 MB available per os_proc_available_memory).

import (
	"bytes"
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
	"regexp"
	"regexp/syntax"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dop251/goja"
)

var lookRe = regexp.MustCompile(`\(\?[!=<][^()]*(\([^()]*\)[^()]*)*\)`)

// sampleURL builds one string the rule pattern matches (first alternative, minimum repeats).
func sampleURL(p string) string {
	p = lookRe.ReplaceAllString(p, "")
	re, err := syntax.Parse(p, syntax.Perl)
	if err != nil {
		return ""
	}
	var b strings.Builder
	var gen func(r *syntax.Regexp)
	gen = func(r *syntax.Regexp) {
		switch r.Op {
		case syntax.OpLiteral:
			b.WriteString(string(r.Rune))
		case syntax.OpCharClass:
			pick := rune(-1)
			for _, c := range []rune{'a', 'x', '1', '0', 's'} {
				for i := 0; i+1 < len(r.Rune); i += 2 {
					if c >= r.Rune[i] && c <= r.Rune[i+1] && pick < 0 {
						pick = c
					}
				}
			}
			if pick < 0 && len(r.Rune) > 0 {
				pick = r.Rune[0]
			}
			if pick >= 0 {
				b.WriteRune(pick)
			}
		case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
			b.WriteString("x")
		case syntax.OpCapture:
			gen(r.Sub[0])
		case syntax.OpStar, syntax.OpQuest:
		case syntax.OpPlus:
			gen(r.Sub[0])
		case syntax.OpRepeat:
			for i := 0; i < r.Min; i++ {
				gen(r.Sub[0])
			}
		case syntax.OpConcat:
			for _, s := range r.Sub {
				gen(s)
			}
		case syntax.OpAlternate:
			gen(r.Sub[0])
		}
	}
	gen(re)
	return b.String()
}

type auditRun struct {
	Entry, Tag    string
	Enabled       bool
	Script, URL   string
	Type          string
	Sample        string
	Status        string // ok / error / skip / nosample / nodone
	Detail        string
	Modified      bool
	WarmMs        []int
	ColdMs        int
	ErrorLogs     []string
	ConsoleSample []string
}

func TestQXAuditRun(t *testing.T) {
	dir := os.Getenv("TERN_QX_AUDIT_DIR")
	if dir == "" {
		t.Skip("audit only")
	}
	if raceEnabled {
		t.Skip()
	}
	only := os.Getenv("TERN_QX_AUDIT_ONLY")
	// script URL → local file
	urlFile := map[string]string{}
	f, _ := os.Open(filepath.Join(dir, "dl_all.tsv"))
	rows, _ := func() ([][]string, error) { r := csv.NewReader(f); r.Comma = '\t'; r.FieldsPerRecord = -1; return r.ReadAll() }()
	f.Close()
	for _, r := range rows {
		if len(r) >= 4 && r[1] == "200" {
			urlFile[r[3]] = filepath.Join(dir, "scripts", r[0]+".js")
		}
	}
	samples := map[string]string{}
	if b, err := os.ReadFile(filepath.Join(dir, "samples.json")); err == nil {
		_ = json.Unmarshal(b, &samples)
	}
	bodies := map[string]string{} // script file name / pattern → body file (bodies/)
	if b, err := os.ReadFile(filepath.Join(dir, "bodies.json")); err == nil {
		_ = json.Unmarshal(b, &bodies)
	}
	list, _ := os.ReadFile(filepath.Join(dir, "list.txt"))
	var results []auditRun
	if rd := os.Getenv("TERN_AUDIT_RESDIR"); rd != "" {
		files, _ := filepath.Glob(filepath.Join(dir, rd, "*"))
		sort.Strings(files)
		for _, f := range files {
			if only != "" && !strings.Contains(filepath.Base(f), only) {
				continue
			}
			text, _ := os.ReadFile(f)
			results = append(results, runAuditEntry(t, filepath.Base(f), qxRemote{Tag: filepath.Base(f), Enabled: true}, text, urlFile, samples, bodies, dir)...)
		}
		j, _ := json.MarshalIndent(results, "", " ")
		_ = os.WriteFile(filepath.Join(dir, "run-corpus-"+only+".json"), j, 0o644)
		return
	}
	for i, line := range strings.Split(strings.TrimSpace(string(list)), "\n") {
		m, _ := qxRemoteLine(line)
		files, _ := filepath.Glob(filepath.Join(dir, "res", fmt.Sprintf("%02d_*", i+1)))
		if len(files) == 0 {
			continue
		}
		if only != "" && !strings.Contains(filepath.Base(files[0]), only) {
			continue
		}
		text, _ := os.ReadFile(files[0])
		res := runAuditEntry(t, filepath.Base(files[0]), m, text, urlFile, samples, bodies, dir)
		results = append(results, res...)
	}
	j, _ := json.MarshalIndent(results, "", " ")
	name := "run.json"
	if only != "" {
		name = "run-" + only + ".json"
	}
	_ = os.WriteFile(filepath.Join(dir, name), j, 0o644)
}

type qxRemote struct {
	Tag     string
	Enabled bool
}

func qxRemoteLine(l string) (qxRemote, string) {
	parts := strings.Split(l, ",")
	m := qxRemote{Enabled: true}
	for _, p := range parts[1:] {
		k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
		switch k {
		case "tag":
			m.Tag = v
		case "enabled":
			m.Enabled = v == "true"
		}
	}
	return m, strings.TrimSpace(parts[0])
}

func genericBody(u string) []byte {
	return []byte(`{"code":0,"ret":0,"status":0,"success":true,"msg":"ok","message":"ok","result":{"list":[],"items":[]},` +
		`"data":{"list":[{"id":1,"title":"t","type":"normal"}],"items":[],"ads":[{"id":2}],"banners":[],"isVip":false,"vip":false,"vipInfo":{"isVip":false},"user":{"id":1,"vip":0},"config":{},"result":{}}}`)
}

func runAuditEntry(t *testing.T, file string, m qxRemote, text []byte, urlFile, samples, bodies map[string]string, dir string) []auditRun {
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
	var mu sync.Mutex
	respFor := map[string][]byte{}
	ctFor := map[string]string{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		mu.Lock()
		b, ok := respFor[r.Host+r.URL.RequestURI()]
		ct := ctFor[r.Host+r.URL.RequestURI()]
		mu.Unlock()
		if !ok {
			b, ct = genericBody(r.URL.String()), "application/json; charset=utf-8"
		}
		if ct == "" {
			ct = "application/json; charset=utf-8"
		}
		w.Header().Set("Content-Type", ct)
		_, _ = w.Write(b)
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
	cfg := &Config{Enabled: true, MitM: true, SkipCertVerify: true, Modules: []Module{{ID: "m", Name: m.Tag, Enabled: true}}}
	rs := Build(home, cfg)
	e.Reload(cfg, rs)
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", e.Port()))
	tr := &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: true, DisableCompression: true}
	c := &http.Client{Transport: tr, Timeout: 70 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	hm := NewHostMatcher(rs.Hostnames)
	var out []auditRun
	seenScript := map[string]int{}
	for _, r := range rs.Rules {
		if r.Kind != KindScript {
			continue
		}
		sc := r.Script
		ar := auditRun{Entry: file, Tag: m.Tag, Enabled: m.Enabled, Script: sc.Name, URL: sc.Path, Type: sc.Type}
		if r.Script.Echo {
			ar.Type += "(echo)"
		}
		// one run per (script, rule) but at most 3 rules per script per entry (big snippets repeat a script)
		seenScript[sc.Path]++
		if seenScript[sc.Path] > 3 {
			continue
		}
		s := samples[r.Pattern]
		if s == "" {
			s = sampleURL(r.Pattern)
			if strings.HasPrefix(s, "http://") && r.match("https://"+s[7:]) {
				s = "https://" + s[7:]
			}
		}
		pu, err := url.Parse(s)
		if s == "" || err != nil || !r.match(s) || pu.Host == "" {
			ar.Status, ar.Sample, ar.Detail = "nosample", s, r.Pattern
			out = append(out, ar)
			continue
		}
		port := 443
		if pu.Scheme == "http" {
			port = 80
		}
		if pu.Scheme == "https" && !hm.Match(pu.Hostname(), port) {
			ar.Status, ar.Sample, ar.Detail = "nomitm", s, "MitM 主机名不含 "+pu.Hostname()+"（QX 同样不会处理）"
			out = append(out, ar)
			continue
		}
		ar.Sample = s
		body, ct := genericBody(s), "application/json; charset=utf-8"
		key := filepath.Base(sc.Path)
		for _, k := range []string{r.Pattern, key} {
			if bf, ok := bodies[k]; ok {
				if b, err := os.ReadFile(filepath.Join(dir, "bodies", bf)); err == nil {
					body = b
					if strings.HasSuffix(bf, ".bin") {
						ct = "application/x-protobuf"
					}
				}
				break
			}
		}
		mu.Lock()
		respFor[pu.Host+pu.RequestURI()] = body
		ctFor[pu.Host+pu.RequestURI()] = ct
		mu.Unlock()
		t.Run(fmt.Sprintf("%s-%d", sc.Name, len(out)), func(t *testing.T) {
			if os.Getenv("TERN_QX_AUDIT_NOTUNNEL") == "" {
				tunnelConditions(t, 19, 20<<20)
			}
			n := 1
			if os.Getenv("TERN_QX_AUDIT_WARM") != "" || sc.Type == "http-response" {
				n = 5
			}
			since := e.Logs.Seq()
			for i := 0; i < n; i++ {
				method := "GET"
				var rb io.Reader
				if strings.HasPrefix(sc.Type, "http-request") && sc.RequiresBody && !sc.Echo {
					method, rb = "POST", bytes.NewReader([]byte(`{"a":1,"keywords":["x"]}`))
				}
				req, _ := http.NewRequest(method, s, rb)
				req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X)")
				req.Header.Set("Cookie", "uid=1; token=abc")
				req.Header.Set("Authorization", "Bearer abc")
				t0 := time.Now()
				resp, err := c.Do(req)
				d := time.Since(t0)
				if err != nil {
					ar.Status, ar.Detail = "error", "请求失败："+err.Error()
					return
				}
				rbody, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if i == 0 {
					ar.ColdMs = int(d.Milliseconds())
					ar.Modified = !bytes.Equal(rbody, body) || resp.StatusCode != 200
				} else {
					ar.WarmMs = append(ar.WarmMs, int(d.Milliseconds()))
				}
			}
			var notes []string
			for _, en := range e.Requests.List(0) {
				if en.URL == s || strings.HasPrefix(en.URL, s) {
					notes = append(notes, en.Notes...)
				}
			}
			var runMs []int
			for _, l := range e.Logs.List(since, sc.Name) {
				switch l.Level {
				case "error", "warn", "warning":
					ar.ErrorLogs = append(ar.ErrorLogs, clip(l.Msg, 300))
				case "debug":
					var ms int
					if _, err := fmt.Sscanf(l.Msg, "执行完成，用时 %d ms", &ms); err == nil {
						runMs = append(runMs, ms)
					}
				default:
					if len(ar.ConsoleSample) < 4 {
						ar.ConsoleSample = append(ar.ConsoleSample, clip(l.Msg, 200))
					}
				}
			}
			_ = runMs
			j := strings.Join(dedupe(notes), " | ")
			switch {
			case strings.Contains(j, "脚本错误"):
				ar.Status, ar.Detail = "error", j
			case strings.Contains(j, "跳过脚本"):
				ar.Status, ar.Detail = "skip", j
			default:
				ar.Status = "ok"
				ar.Detail = j
			}
		})
		out = append(out, ar)
		t.Logf("%s | %s %s | %s | %s cold=%dms warm=%v mod=%v %s %v", file, sc.Name, sc.Type, clip(s, 90), ar.Status, ar.ColdMs, ar.WarmMs, ar.Modified, clip(ar.Detail, 300), ar.ErrorLogs)
	}
	return out
}

// TestQXAuditCompile: compile every downloaded script as the runner does, with the heap peak (GC off)
// and the retained program size, against the gate's estimates.
func TestQXAuditCompile(t *testing.T) {
	dir := os.Getenv("TERN_QX_AUDIT_DIR")
	if dir == "" {
		t.Skip("audit only")
	}
	heap := func() uint64 {
		s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
		metrics.Read(s)
		return s[0].Value.Uint64()
	}
	f, _ := os.Open(filepath.Join(dir, "dl.tsv"))
	r := csv.NewReader(f)
	r.Comma = '\t'
	r.FieldsPerRecord = -1
	rows, _ := r.ReadAll()
	f.Close()
	type cres struct {
		URL      string
		Size     int
		OK       bool
		Err      string
		PeakMB   float64
		KeptMB   float64
		Ms       int
		Gated    bool
		EstMB    float64
		Fallback bool
	}
	var out []cres
	sort.Slice(rows, func(i, j int) bool { return rows[i][3] < rows[j][3] })
	for _, row := range rows {
		if len(row) < 4 || row[1] != "200" {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, "scripts", row[0]+".js"))
		if err != nil {
			continue
		}
		code := strings.TrimPrefix(string(src), "\ufeff")
		runtime.GC()
		base := heap()
		old := debug.SetGCPercent(-1)
		t0 := time.Now()
		p, err := goja.Compile("x.js", "(function(){\n"+code+"\n}).call(this);", false)
		fb := false
		if err != nil {
			p2, err2 := goja.Compile("x.js", code, false)
			if err2 == nil {
				p, err, fb = p2, nil, true
			}
		}
		ms := time.Since(t0).Milliseconds()
		peak := heap() - base
		debug.SetGCPercent(old)
		runtime.GC()
		kept := heap() - base
		runtime.KeepAlive(p)
		c := cres{URL: row[3], Size: len(src), OK: err == nil, PeakMB: float64(peak) / (1 << 20), KeptMB: float64(kept) / (1 << 20), Ms: int(ms), Gated: len(src) >= largeProgSource, EstMB: float64(len(src)*compileBytesPerSourceByte) / (1 << 20), Fallback: fb}
		if err != nil {
			c.Err = clip(err.Error(), 300)
		}
		out = append(out, c)
		t.Logf("%-90s %7d ok=%v peak=%.1fMB kept=%.1fMB %dms gated=%v %s", clip(c.URL, 90), c.Size, c.OK, c.PeakMB, c.KeptMB, c.Ms, c.Gated, c.Err)
	}
	j, _ := json.MarshalIndent(out, "", " ")
	_ = os.WriteFile(filepath.Join(dir, "compile.json"), j, 0o644)
}
