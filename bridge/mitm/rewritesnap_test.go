package mitm

// Native rewrite (stage 3a) — Go side tests and the conformance corpus for the Swift engine.
//
// The Swift engine (PacketTunnel/NativeMitM/Rewrite/) must decide every request it claims exactly like the
// Go flow API (FlowBegin / FlowResponse). rwSuites builds engines from module text, generates requests for
// every rule (and requests that match nothing, and odd requests Swift has to hand back), and records what
// the real flow API answers. TERN_GEN_REWRITE_FIXTURES=<file> writes them as UnitTests/
// NativeMitmRewriteFixtures.json for UnitTests/NativeMitmRewriteTests.swift; with TERN_QX_AUDIT_DIR the
// user's real QX corpus (work/qx-rewrite-remote.txt resources + the 30-module corpus) is added.
// TestRewriteFixturesCurrent regenerates the suites CI can rebuild and compares them with the committed
// file, so a Go change that alters a decision fails here until the fixture is regenerated.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

type rwDecision struct {
	Action  string      `json:"action"`
	Status  int         `json:"status,omitempty"`
	Headers [][2]string `json:"headers,omitempty"`
	Body    string      `json:"body,omitempty"` // body mode
	Length  int64       `json:"length"`
	Method  string      `json:"method,omitempty"`
	URL     string      `json:"url,omitempty"`
	Host    string      `json:"host,omitempty"`
	Data    string      `json:"data,omitempty"` // base64 of a local body
	Note    string      `json:"note,omitempty"`
}

type rwResp struct {
	Status  int         `json:"status"`
	Headers [][2]string `json:"headers"`
	Length  int64       `json:"length"`
	Expect  rwDecision  `json:"expect"`
}

type rwCase struct {
	Name     string      `json:"name"`
	Method   string      `json:"method"`
	Target   string      `json:"target"`
	Host     string      `json:"host,omitempty"`
	Headers  [][2]string `json:"headers"`
	Length   int64       `json:"length"`
	ConnHost string      `json:"connHost"`
	ConnPort int         `json:"connPort"`
	// NeedsGo: Go would run a script / body rule for this request (not run here); Swift must defer.
	NeedsGo bool       `json:"needsGo,omitempty"`
	Expect  rwDecision `json:"expect"`
	Resp    *rwResp    `json:"resp,omitempty"`
	// Log: the request-log entry the Go flow left once the flow ended (native-answerable cases only): the native
	// driver's records must produce the same entry (UnitTests/NativeMitmRewriteTests testRequestLogMatchesGo).
	Log *rwLog `json:"log,omitempty"`
}

// rwLog is an Entry without its id / times.
type rwLog struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Host    string            `json:"host"`
	MitM    bool              `json:"mitm"`
	Status  int               `json:"status"`
	Matched []string          `json:"matched,omitempty"`
	Notes   []string          `json:"notes,omitempty"`
	Local   bool              `json:"local,omitempty"`
	Done    bool              `json:"done"`
	Bytes   int64             `json:"bytes"`
	ReqHdr  map[string]string `json:"reqHeaders,omitempty"`
	RespHdr map[string]string `json:"respHeaders,omitempty"`
}

func rwLogOf(e *Entry) *rwLog {
	e.mu.Lock()
	defer e.mu.Unlock()
	return &rwLog{Method: e.Method, URL: e.URL, Host: e.Host, MitM: e.MitM, Status: e.Status, Matched: append([]string(nil), e.Matched...),
		Notes: append([]string(nil), e.Notes...), Local: e.IsLocal, Done: e.Done, Bytes: e.Bytes, ReqHdr: e.ReqHdr, RespHdr: e.RespHdr}
}

type rwHostCase struct {
	Host  string `json:"host"`
	Port  int    `json:"port"`
	Match bool   `json:"match"`
}

type rwSuite struct {
	Name     string          `json:"name"`
	Snapshot json.RawMessage `json:"snapshot"`
	Cases    []rwCase        `json:"cases"`
	Hosts    []rwHostCase    `json:"hosts"`
	// Labels: the request-log label of every rule, by Ruleset index (what Entry.Matched shows).
	Labels []string `json:"labels"`
}

type rwFixtures struct {
	Version int       `json:"version"`
	Suites  []rwSuite `json:"suites"`
}

// rwEdgeModule exercises every native decision and every reason to defer.
const rwEdgeModule = `#!name=native rewrite edge cases
[URL Rewrite]
^https://edge\.test\.com/rej - reject
^https://edge\.test\.com/r200 - reject-200
^https://edge\.test\.com/img - reject-img
^https://edge\.test\.com/dict - reject-dict
^https://edge\.test\.com/arr - reject-array
^https://edge\.test\.com/drop - reject-drop
^https://edge\.test\.com/g/(\w+)/(\d+) https://edge.test.com/to/$2/$1?x=$$&all=$& 302
^https://edge\.test\.com/ten/(a)(b)(c)(d)(e)(f)(g)(h)(i)(j) https://edge.test.com/t/$10/$1x/${2}/$11 307
^https://edge\.test\.com/lit/(.*) https://edge.test.com/l/$9/${x}/$/end 302
^https://edge\.test\.com/hdr/(.*) https://edge.test.com/new/$1 header
^https://edge\.test\.com/hdrport https://edge.test.com:8443/p header
^https://edge\.test\.com/hdrhttp https://plain.test.com/p header
^https://edge\.test\.com/hdrbad https://edge.test.com/a b header
^https://edge\.test\.com/(?<n>named)/x https://edge.test.com/${n} 302
^https://edge\.test\.com/(?<=x)lb - reject
^https://edge\.test\.com/u/\p{L}+ - reject
^https://edge\.test\.com/bk/(a)\1 - reject
(?i)^https://EDGE\.test\.com/CASE - reject-dict
^https://edge\.test\.com/alt/(one|two)$ - reject-200
[Map Local]
^https://edge\.test\.com/ml/text data-type=text data="hello" header="X-ML:1|Cache-Control:no-store"
^https://edge\.test\.com/ml/json data-type=json data="{\"a\":1}" status-code=201
^https://edge\.test\.com/ml/b64 data-type=base64 data="AAEC/w=="
^https://edge\.test\.com/ml/gif data-type=tiny-gif
^https://edge\.test\.com/ml/204 data-type=text data="" status-code=204
^https://edge\.test\.com/ml/html data-type=text data="<p>x</p>" header="content-type:text/x-custom"
^https://edge\.test\.com/ml/file data="https://example.invalid/x.json"
[Header Rewrite]
http-request ^https://edge\.test\.com/h/add header-add X-New one
http-request ^https://edge\.test\.com/h/add header-add X-New two
http-request ^https://edge\.test\.com/h/del header-del Cookie
http-request ^https://edge\.test\.com/h/rep header-replace User-Agent TernUA
http-request ^https://edge\.test\.com/h/rep header-replace X-Absent nope
http-request ^https://edge\.test\.com/h/rx header-replace-regex User-Agent (\w+)/(\d+) $2-$1
http-request ^https://edge\.test\.com/h/host header-replace Host other.test.com
http-request ^https://edge\.test\.com/h/hostadd header-add host added.test.com
http-request ^https://edge\.test\.com/h/conn header-add Connection X-Hop
http-request ^https://edge\.test\.com/h/empty header-replace-regex User-Agent x* y
http-response ^https://edge\.test\.com/(h|r)/ header-add X-Resp yes
http-response ^https://edge\.test\.com/r/del header-del Set-Cookie
http-response ^https://edge\.test\.com/r/rep header-replace Content-Type text/plain
http-response ^https://edge\.test\.com/r/rx header-replace-regex Content-Type json(.*) xml$1
[Body Rewrite]
http-response ^https://edge\.test\.com/b/resp "a" "b"
http-request ^https://edge\.test\.com/b/req "a" "b"
[Script]
s1 = type=http-request,pattern=^https://edge\.test\.com/s/req,script-path=https://example.invalid/s1.js
s2 = type=http-response,pattern=^https://edge\.test\.com/s/resp,script-path=https://example.invalid/s2.js,requires-body=1
s3 = type=http-response,pattern=^https://edge\.test\.com/s/nobody,script-path=https://example.invalid/s3.js
[MITM]
hostname = edge.test.com, *.wild.test.com, -no.wild.test.com, port.test.com:8443, 10.0.*.*, single?.test.com
`

// rwQXEdge: QX forms that must go to Go (url-and-header, raw header regex) next to plain ones.
const rwQXEdge = `hostname = qx.test.com
^https://qx\.test\.com/uh User-Agent:\sMyApp url-and-header reject-dict
^https://qx\.test\.com/raw url request-header (\r\nUser-Agent:)[^\r\n]* request-header $1 QXUA
^https://qx\.test\.com/rej url reject
^https://qx\.test\.com/302/(.+) url 302 https://qx.test.com/n/$1
`

type rwModule struct{ id, name, text string }

func rwDial(ctx context.Context, network, addr, policy string) (net.Conn, error) {
	return nil, errors.New("no upstream in rewrite fixtures")
}

// rwEngine starts an engine with the modules installed (capture off: the native side never captures).
func rwEngine(t testing.TB, home string, mods []rwModule) (*Engine, *Ruleset) {
	t.Helper()
	cfg := &Config{Enabled: true, MitM: true, CaptureBodies: noCapture()}
	for _, m := range mods {
		if err := writeFileForTest(ModulePath(home, m.id), m.text); err != nil {
			t.Fatal(err)
		}
		cfg.Modules = append(cfg.Modules, Module{ID: m.id, Name: m.name, Enabled: true, Args: map[string]string{"word": "hello", "MODE": "b"}})
	}
	e := New(home, rwDial, nil)
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	rs := Build(home, cfg)
	e.Reload(cfg, rs)
	return e, rs
}

var rwBaseHeaders = [][2]string{{"User-Agent", "TernTest/1.0 (iPhone)"}, {"Accept", "*/*"}, {"accept-encoding", "gzip, br"}, {"Cookie", "uid=1; t=abc"}}

var rwHopHeaders = [][2]string{{"Connection", "keep-alive, X-Hop"}, {"X-Hop", "drop me"}, {"Keep-Alive", "timeout=5"},
	{"Te", "trailers, gzip"}, {"Forwarded", "for=1.2.3.4"}, {"X-Forwarded-For", "1.2.3.4"}, {"X-Forwarded-Proto", "https"},
	{"Proxy-Connection", "keep-alive"}, {"X-Dup", "a"}, {"x-dup", "b"}, {"Content-Type", "application/json"}}

// rwCannedResp is the upstream head the forward cases answer with.
var rwCannedResp = [][2]string{{"Content-Type", "application/json; charset=utf-8"}, {"Content-Length", "2"}, {"Connection", "keep-alive, X-Up-Hop"},
	{"X-Up-Hop", "1"}, {"Keep-Alive", "timeout=5"}, {"Set-Cookie", "a=1"}, {"set-cookie", "b=2"}, {"X-Up", "1"}}

func rwDecode(t testing.TB, s string) flowDecision {
	t.Helper()
	var d flowDecision
	if err := json.Unmarshal([]byte(s), &d); err != nil {
		t.Fatalf("decision %q: %v", s, err)
	}
	return d
}

func rwFrom(d flowDecision) rwDecision {
	return rwDecision{Action: d.Action, Status: d.Status, Headers: d.Headers, Body: d.Body, Length: d.Length, Method: d.Method, URL: d.URL, Host: d.Host, Note: d.Note}
}

// rwNeedsGo mirrors requestPhase's order with the real matchers: would Go run a script / body / jq / json
// rule (or Map Local from a file) for this request? Such requests are not run here (scripts need their
// files and an upstream) and Swift must hand them to Go.
func rwNeedsGo(st *state, r *http.Request, u string) bool {
	if !st.cfg.AnyOn() {
		return false
	}
	rules := st.rs.Rules
	for _, rule := range rules {
		if rule.Kind != KindURL || !rule.matchReq(u, r) {
			continue
		}
		if rule.Action != "header" {
			return false // answered locally before any script
		}
		if nu, err := rule.re.Replace(u, rule.Target, -1, 1); err == nil {
			if pu, err := url.Parse(nu); err == nil && pu.Host != "" {
				u = nu
			}
		}
		break
	}
	for _, rule := range rules {
		if rule.Kind == KindMapLocal && rule.matchReq(u, r) {
			return false
		}
	}
	for _, rule := range rules {
		switch rule.Kind {
		case KindScript, KindBody, KindJQ, KindJSON:
			if rule.matchReq(u, r) {
				return true
			}
		}
	}
	return false
}

// rwRun asks the flow API for c's decision (and the response decision for a forward).
func rwRun(t testing.TB, e *Engine, c *rwCase) {
	t.Helper()
	head := FlowHead{Method: c.Method, Target: c.Target, Host: c.Host, Headers: c.Headers, Length: c.Length, ConnHost: c.ConnHost, ConnPort: c.ConnPort, TLS: true}
	if r, err := head.request(); err == nil {
		meta := &connMeta{host: c.ConnHost, port: c.ConnPort, tls: true}
		if rwNeedsGo(e.state(), r, requestURL(r, meta)) {
			c.NeedsGo = true
			c.Expect = rwDecision{Action: "go"}
			return
		}
	}
	hj, _ := json.Marshal(head)
	d := rwDecode(t, e.FlowBegin(string(hj)))
	var ent *Entry
	if nf := lookupFlow(d.ID); nf != nil {
		nf.mu.Lock()
		ent = nf.ent
		nf.mu.Unlock()
	}
	defer func() {
		FlowEnd(d.ID, 0, "")
		if ent == nil || (d.Action != "local" && d.Action != "drop" && d.Action != "forward") {
			return
		}
		for i := 0; i < 2000; i++ {
			ent.mu.Lock()
			done := ent.Done
			ent.mu.Unlock()
			if done {
				break
			}
			time.Sleep(time.Millisecond)
		}
		c.Log = rwLogOf(ent)
	}()
	c.Expect = rwFrom(d)
	switch d.Action {
	case "local":
		if d.Body == "read" {
			var buf bytes.Buffer
			for i := 0; i < 10000; i++ {
				b := FlowRead(d.ID, flowResp, 32<<10)
				buf.Write(b)
				if len(b) == 0 {
					st := FlowReadState(d.ID, flowResp)
					if st == "eof" {
						break
					}
					if st != "" {
						t.Fatalf("%s: local body read: %s", c.Name, st)
					}
					time.Sleep(time.Millisecond)
				}
			}
			c.Expect.Data = base64.StdEncoding.EncodeToString(buf.Bytes())
		}
	case "forward":
		status := 200
		hs := rwCannedResp
		length := int64(2)
		switch {
		case c.Method == "HEAD":
			length = 2
		case strings.Contains(c.Target, "nocontent"):
			status, hs, length = 204, [][2]string{{"X-Up", "1"}}, 0
		case strings.Contains(c.Target, "sse"):
			hs = [][2]string{{"Content-Type", "text/event-stream"}, {"Transfer-Encoding", "chunked"}}
			length = -1
		}
		rh, _ := json.Marshal(FlowRespHead{Status: status, Headers: hs, Length: length})
		rd := rwDecode(t, FlowResponse(d.ID, string(rh)))
		if rd.Action == "need-body" {
			t.Fatalf("%s: response needs the body but rwNeedsGo said no", c.Name)
		}
		c.Resp = &rwResp{Status: status, Headers: hs, Length: length, Expect: rwFrom(rd)}
	}
}

// rwSampleHost turns a hostname pattern into a host it matches ("" none).
func rwSampleHost(pat string) string {
	if isIPv4Glob(pat) {
		return strings.ReplaceAll(strings.ReplaceAll(pat, "*", "1"), "?", "1")
	}
	h := strings.ReplaceAll(pat, "*", "a")
	return strings.ReplaceAll(h, "?", "b")
}

// rwSuiteFor builds one suite: snapshot, cases for every rule and every MitM host, host-match cases.
func rwSuiteFor(t testing.TB, name string, mods []rwModule, extra []rwCase, all bool) rwSuite {
	return rwSuiteLimited(t, name, mods, extra, all, 0)
}

// rwSuiteLimited: maxRules > 0 samples about that many rules (and MitM hosts) evenly (huge snippets).
func rwSuiteLimited(t testing.TB, name string, mods []rwModule, extra []rwCase, all bool, maxRules int) rwSuite {
	home := t.(interface{ TempDir() string }).TempDir()
	e, rs := rwEngine(t, home, mods)
	defer e.Stop()
	s := rwSuite{Name: name, Snapshot: json.RawMessage(e.RewriteSnapshotJSON())}
	st := e.state()
	s.Labels = []string{}
	for _, r := range st.rs.Rules {
		s.Labels = append(s.Labels, r.label())
	}
	seen := map[string]bool{}
	add := func(c rwCase) {
		key := c.Method + " " + c.ConnHost + " " + c.Target + " " + fmt.Sprint(c.Headers, c.Length, c.Host)
		if seen[key] {
			return
		}
		seen[key] = true
		if c.ConnPort == 0 {
			c.ConnPort = 443
		}
		rwRun(t, e, &c)
		s.Cases = append(s.Cases, c)
	}
	variants := func(label, host, target string, n int) {
		add(rwCase{Name: label, Method: "GET", Target: target, Headers: rwBaseHeaders, Length: 0, ConnHost: host})
		if all || n%4 == 0 {
			add(rwCase{Name: label + " POST hop", Method: "POST", Target: target, Headers: append(append([][2]string{}, rwBaseHeaders...), rwHopHeaders...), Length: 5, ConnHost: host})
		}
		if all || n%9 == 0 {
			add(rwCase{Name: label + " HEAD", Method: "HEAD", Target: target, Headers: [][2]string{{"Host", host}}, Length: 0, ConnHost: host})
			add(rwCase{Name: label + " chunked", Method: "PUT", Target: target, Headers: [][2]string{{"Host", host + ":443"}, {"Transfer-Encoding", "chunked"}}, Length: -1, ConnHost: host})
		}
		if all {
			add(rwCase{Name: label + " upgrade", Method: "GET", Target: target, Headers: [][2]string{{"Connection", "Upgrade"}, {"Upgrade", "websocket"}, {"Sec-WebSocket-Key", "x"}}, ConnHost: host})
		}
	}
	perScript := map[string]int{}
	stride := 1
	if maxRules > 0 && len(rs.Rules) > maxRules {
		stride = (len(rs.Rules) + maxRules - 1) / maxRules
	}
	for i, r := range rs.Rules {
		if i%stride != 0 {
			continue
		}
		if r.Kind == KindScript && r.Script != nil {
			perScript[r.Script.Path]++
			if perScript[r.Script.Path] > 3 {
				continue
			}
		}
		smp := sampleURL(r.Pattern)
		if strings.HasPrefix(smp, "http://") && r.match("https://"+smp[7:]) {
			smp = "https://" + smp[7:]
		}
		su, err := url.Parse(smp)
		if smp == "" || err != nil || su.Scheme != "https" || su.Host == "" || !r.match(smp) {
			continue
		}
		port := 443
		if p := su.Port(); p != "" {
			port, _ = strconv.Atoi(p)
		}
		target := su.RequestURI()
		if su.RawQuery == "" && strings.HasSuffix(smp, "?") {
			target += "?"
		}
		variants(fmt.Sprintf("rule %d %s %s", i, r.Kind, clip(r.Pattern, 60)), su.Hostname(), target, i)
		_ = port
	}
	// requests on every MitM host that match nothing in particular
	hstride := 1
	if maxRules > 0 && len(st.hosts.inc) > maxRules/4 {
		hstride = (len(st.hosts.inc) + maxRules/4 - 1) / (maxRules / 4)
	}
	for i, p := range st.hosts.inc {
		if i%hstride != 0 {
			continue
		}
		h := rwSampleHost(p.pat)
		if h == "" {
			continue
		}
		port := p.port
		c := rwCase{Name: "host " + p.pat, Method: "GET", Target: "/tern/native/probe?x=1", Headers: rwBaseHeaders, ConnHost: h, ConnPort: port}
		if port != 0 && port != 443 {
			c.Headers = append([][2]string{{"Host", h + ":" + strconv.Itoa(port)}}, rwBaseHeaders...)
		}
		add(c)
		if all || i%5 == 0 {
			variants("host "+p.pat, h, "/", i)
		}
	}
	for _, c := range extra {
		add(c)
	}
	// host matching (HostMatcher), every pattern with matching and non-matching neighbours
	hs := map[string]bool{}
	addHost := func(h string, port int) {
		k := h + ":" + strconv.Itoa(port)
		if hs[k] || h == "" {
			return
		}
		hs[k] = true
		s.Hosts = append(s.Hosts, rwHostCase{Host: h, Port: port, Match: st.hosts.Match(h, port)})
	}
	for i, p := range append(append([]hostPat{}, st.hosts.inc...), st.hosts.exc...) {
		if i%hstride != 0 && i < len(st.hosts.inc) {
			continue
		}
		h := rwSampleHost(p.pat)
		for _, port := range []int{443, 80, 8443, p.port} {
			addHost(h, port)
			addHost(strings.ToUpper(h), port)
			addHost(h+".", port)
			addHost("x"+h, port)
			addHost("x."+h, port)
		}
	}
	addHost("unrelated.example.org", 443)
	return s
}

// rwEdgeCases are requests Swift must either answer exactly or hand back (odd targets, hosts, framing).
func rwEdgeCases() []rwCase {
	h := "edge.test.com"
	g := func(name, target string, hdr ...[2]string) rwCase {
		return rwCase{Name: name, Method: "GET", Target: target, Headers: append(append([][2]string{}, rwBaseHeaders...), hdr...), ConnHost: h}
	}
	cs := []rwCase{
		g("space in path", "/plain/a b"),
		g("bad escape", "/plain/%zz"),
		g("good escape", "/plain/%7Ea%2Fb"),
		g("semicolon query", "/plain?a=1;b=2"),
		g("bad query escape", "/plain?a=%G1"),
		g("fragment", "/plain#frag"),
		g("non-ascii", "/plain/é"),
		g("pipe", "/plain/a|b"),
		g("empty query", "/plain?"),
		g("asterisk", "*"),
		g("absolute target", "https://edge.test.com/rej"),
		g("host with port 443", "/rej", [2]string{"Host", "edge.test.com:443"}),
		g("host with port 8443", "/rej", [2]string{"Host", "edge.test.com:8443"}),
		g("uppercase host", "/rej", [2]string{"Host", "EDGE.test.com"}),
		g("other host header", "/rej", [2]string{"Host", "other.test.com"}),
		g("case rule", "/CASE"),
		g("case rule lower", "/case", [2]string{"Host", "edge.test.com"}),
		g("lookbehind", "/xlb"),
		g("unicode class", "/u/abc"),
		g("backref", "/bk/aa"),
		g("alt one", "/alt/one"),
		g("alt three", "/alt/three"),
		g("named", "/named/x"),
		g("sse", "/plain/sse"),
		g("no content", "/plain/nocontent"),
		g("hdr bad target", "/hdrbad"),
		g("hdr http", "/hdrhttp"),
		g("hdr port", "/hdrport"),
		g("hdr then resp", "/hdr/h/x"),
		g("lit", "/lit/abc"),
		g("ten", "/ten/abcdefghij"),
		g("g", "/g/abc/123"),
		g("empty regex op", "/h/empty"),
		g("host op", "/h/host"),
		g("host add op", "/h/hostadd"),
		g("conn op", "/h/conn"),
		g("rx no match", "/h/rx", [2]string{"User-Agent", "plain"}),
		g("bad content-length", "/plain", [2]string{"Content-Length", "x"}),
		g("dup host headers", "/rej", [2]string{"Host", "edge.test.com"}, [2]string{"Host", "b.test.com"}),
		g("header name spaces", "/plain", [2]string{" X-Sp ", "v"}),
		g("header lower", "/h/add", [2]string{"x-new", "zero"}),
		g("te only", "/plain", [2]string{"Te", "trailers"}),
		g("upgrade keep", "/r/del", [2]string{"Connection", "upgrade"}, [2]string{"Upgrade", "websocket"}),
		{Name: "no host header", Method: "GET", Target: "/rej", Headers: [][2]string{{"User-Agent", "x"}}, ConnHost: h},
		{Name: "no host header port", Method: "GET", Target: "/plain", Headers: nil, ConnHost: "port.test.com", ConnPort: 8443},
		{Name: "empty method", Method: "", Target: "/plain", Headers: nil, ConnHost: h},
		{Name: "lowercase method", Method: "get", Target: "/rej", Headers: nil, ConnHost: h},
		{Name: "POST zero", Method: "POST", Target: "/plain", Headers: [][2]string{{"Content-Length", "0"}}, ConnHost: h},
		{Name: "POST length", Method: "POST", Target: "/rej", Headers: [][2]string{{"Content-Length", "12"}}, Length: 12, ConnHost: h},
		{Name: "GET chunked unknown", Method: "GET", Target: "/plain", Headers: nil, Length: -1, ConnHost: h},
		{Name: "DELETE unknown", Method: "DELETE", Target: "/plain", Headers: nil, Length: -1, ConnHost: h},
		{Name: "ip host", Method: "GET", Target: "/x", Headers: nil, ConnHost: "10.0.3.4"},
	}
	for _, p := range []string{"/rej", "/r200", "/img", "/dict", "/arr", "/drop", "/ml/text", "/ml/json", "/ml/b64", "/ml/gif", "/ml/204", "/ml/html",
		"/ml/file", "/h/add", "/h/del", "/h/rep", "/h/rx", "/r/del", "/r/rep", "/r/rx", "/b/resp", "/b/req", "/s/req", "/s/resp", "/s/nobody"} {
		cs = append(cs, g("path "+p, p))
		cs = append(cs, rwCase{Name: "path HEAD " + p, Method: "HEAD", Target: p, Headers: rwBaseHeaders, ConnHost: h})
	}
	return cs
}

// rwCISuites are the suites CI can rebuild (repo text only).
func rwCISuites(t testing.TB) []rwSuite {
	read := func(n string) string {
		b, err := os.ReadFile(filepath.Join("testdata", n))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	return []rwSuite{
		rwSuiteFor(t, "edge", []rwModule{{"edge", "edge", rwEdgeModule}, {"qx", "qx", rwQXEdge}}, rwEdgeCases(), true),
		rwSuiteFor(t, "compat", []rwModule{{"sg", "Surge", surgeCompatModule}, {"lo", "Loon", loonCompatModule}, {"qx", "QX", qxCompatModule}, {"eg", "Egern", egernCompatModule}}, nil, true),
		rwSuiteFor(t, "appclean", []rwModule{{"a1", "Surge", read("appclean.sgmodule")}, {"a2", "Loon", read("appclean.plugin")}, {"a3", "QX", read("appclean_qx.conf")}, {"a4", "Egern", read("appclean_egern.yaml")}}, nil, false),
		rwSuiteFor(t, "youtube", []rwModule{{"y1", "Surge", read("yt_enhance.sgmodule")}, {"y2", "Loon", read("yt_loon.plugin")}, {"y3", "QX", read("yt_ddgksf2013_qx.conf")}}, nil, false),
	}
}

// rwCorpusSuites: the user's QX corpus (TERN_QX_AUDIT_DIR, not in CI) — one suite per resource.
func rwCorpusSuites(t testing.TB, dir string) []rwSuite {
	var files []string
	for _, g := range []string{"res/*", "corpus/mod/*"} {
		m, _ := filepath.Glob(filepath.Join(dir, g))
		sort.Strings(m)
		files = append(files, m...)
	}
	var out []rwSuite
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		out = append(out, rwSuiteLimited(t, "corpus/"+filepath.Base(f), []rwModule{{"m", filepath.Base(f), string(b)}}, nil, false, 240))
	}
	return out
}

func rwStripGen(s rwSuite) rwSuite {
	var m map[string]any
	_ = json.Unmarshal(s.Snapshot, &m)
	delete(m, "gen")
	// Map Local file paths live under the test's temporary engine home: make them stable (and absent on the
	// Swift side, as they were for Go when the fixture was made: missing local file → empty body, missing
	// remote one → Go downloads).
	if rules, ok := m["rules"].([]any); ok {
		for _, r := range rules {
			if l, ok := r.(map[string]any)["local"].(map[string]any); ok {
				if f, ok := l["file"].(map[string]any); ok {
					if p, ok := f["path"].(string); ok {
						if i := strings.Index(p, "/engine/"); i >= 0 {
							f["path"] = "/nonexistent-tern-home" + p[i:]
						}
					}
				}
			}
		}
	}
	s.Snapshot, _ = json.Marshal(m)
	return s
}

// TestGenRewriteFixtures writes the Swift conformance corpus (opt-in).
func TestGenRewriteFixtures(t *testing.T) {
	out := os.Getenv("TERN_GEN_REWRITE_FIXTURES")
	if out == "" {
		t.Skip("set TERN_GEN_REWRITE_FIXTURES=<path to UnitTests/NativeMitmRewriteFixtures.json>")
	}
	fx := rwFixtures{Version: RewriteSnapshotVersion, Suites: rwCISuites(t)}
	if dir := os.Getenv("TERN_QX_AUDIT_DIR"); dir != "" {
		fx.Suites = append(fx.Suites, rwCorpusSuites(t, dir)...)
	}
	n, gos := 0, 0
	for i := range fx.Suites {
		fx.Suites[i] = rwStripGen(fx.Suites[i])
		n += len(fx.Suites[i].Cases)
		for _, c := range fx.Suites[i].Cases {
			if c.NeedsGo {
				gos++
			}
		}
	}
	b, err := json.Marshal(fx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d suites, %d cases (%d need Go scripts/bodies), %d KB", len(fx.Suites), n, gos, len(b)>>10)
	waitFlows(t)
}

// TestRewriteFixturesCurrent: the committed fixture's CI-rebuildable suites still match what Go decides.
func TestRewriteFixturesCurrent(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "UnitTests", "NativeMitmRewriteFixtures.json"))
	if err != nil {
		t.Skip("no committed fixture")
	}
	var fx rwFixtures
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	if fx.Version != RewriteSnapshotVersion {
		t.Fatalf("fixture version %d, snapshot version %d: regenerate (TestGenRewriteFixtures)", fx.Version, RewriteSnapshotVersion)
	}
	committed := map[string]rwSuite{}
	for _, s := range fx.Suites {
		committed[s.Name] = s
	}
	for _, s := range rwCISuites(t) {
		s = rwStripGen(s)
		c, ok := committed[s.Name]
		if !ok {
			t.Errorf("suite %s missing from the committed fixture", s.Name)
			continue
		}
		var a, b2 any
		_ = json.Unmarshal(s.Snapshot, &a)
		_ = json.Unmarshal(c.Snapshot, &b2)
		if fmt.Sprint(a) != fmt.Sprint(b2) {
			t.Errorf("suite %s: snapshot changed — regenerate the fixture", s.Name)
		}
		if fmt.Sprint(s.Labels) != fmt.Sprint(c.Labels) {
			t.Errorf("suite %s: rule labels changed — regenerate the fixture", s.Name)
		}
		if len(s.Cases) != len(c.Cases) {
			t.Errorf("suite %s: %d cases now, %d committed", s.Name, len(s.Cases), len(c.Cases))
			continue
		}
		for i := range s.Cases {
			x, _ := json.Marshal(s.Cases[i])
			y, _ := json.Marshal(c.Cases[i])
			if !bytes.Equal(x, y) {
				t.Errorf("suite %s case %q: Go now decides\n %s\ncommitted\n %s", s.Name, s.Cases[i].Name, x, y)
			}
		}
	}
	waitFlows(t)
}

func TestRewriteSnapshotReload(t *testing.T) {
	home := t.TempDir()
	e, rs := rwEngine(t, home, []rwModule{{"edge", "edge", rwEdgeModule}, {"qx", "qx", rwQXEdge}})
	defer e.Stop()
	g1 := e.RewriteSnapshotGen()
	if g1 == 0 || e.RewriteSnapshotGen() != g1 {
		t.Fatalf("generation %d not stable", g1)
	}
	var s RewriteSnapshot
	if err := json.Unmarshal([]byte(e.RewriteSnapshotJSON()), &s); err != nil {
		t.Fatal(err)
	}
	if s.Version != RewriteSnapshotVersion || s.Gen != g1 || !s.On || s.Capture || len(s.Rules) != len(rs.Rules) {
		t.Fatalf("snapshot head: %+v (rules %d)", s, len(rs.Rules))
	}
	byLine := map[string]SnapRule{}
	for i, r := range s.Rules {
		if r.I != i || r.Kind != rs.Rules[i].Kind {
			t.Fatalf("rule %d out of order: %+v", i, r)
		}
		byLine[rs.Rules[i].Pattern] = r
	}
	want := map[string]func(SnapRule) bool{
		`^https://edge\.test\.com/g/(\w+)/(\d+)`: func(r SnapRule) bool {
			return r.Re.OK && r.TargetOK && r.Re.Lit == "https://edge.test.com/g/" && r.Re.Groups == 2
		},
		`^https://edge\.test\.com/(?<n>named)/x`:  func(r SnapRule) bool { return r.Re.OK && r.Re.Named && r.TargetOK && r.TP != nil },
		`^https://edge\.test\.com/(?<=x)lb`:       func(r SnapRule) bool { return r.Re.OK }, // ICU decides at compile time (bounded lookbehind)
		`^https://edge\.test\.com/u/\p{L}+`:       func(r SnapRule) bool { return r.Re.OK && r.Re.ICU != "" && r.Re.Lit == "https://edge.test.com/u/" },
		`^https://edge\.test\.com/bk/(a)\1`:       func(r SnapRule) bool { return r.Re.OK && strings.Contains(r.Re.ICU, `(?:\1)`) },
		`(?i)^https://EDGE\.test\.com/CASE`:       func(r SnapRule) bool { return r.Re.OK && r.Re.Fold && r.Re.Lit == "https://edge.test.com/case" },
		`^https://edge\.test\.com/alt/(one|two)$`: func(r SnapRule) bool { return r.Re.OK && r.Re.Lit == "https://edge.test.com/alt/" },
		`^https://edge\.test\.com/ml/text`: func(r SnapRule) bool {
			return r.Local != nil && string(r.Local.Body) == "hello" && r.Local.Status == 200
		},
		`^https://edge\.test\.com/ml/file`: func(r SnapRule) bool {
			return r.Local != nil && r.Local.File != nil && r.Local.File.Remote && r.Local.File.CType == "application/json"
		},
		`^https://edge\.test\.com/h/empty`: func(r SnapRule) bool { return r.OpsOK && r.Headers[0].TP != nil },
		`^https://edge\.test\.com/h/rx`:    func(r SnapRule) bool { return r.OpsOK },
		`^https://qx\.test\.com/uh`:        func(r SnapRule) bool { return r.HGate && r.HRe != nil && r.HRe.OK },
		`^https://qx\.test\.com/raw`:       func(r SnapRule) bool { return r.OpsOK && r.Headers[0].Re != nil && r.Headers[0].TP != nil },
		`^https://edge\.test\.com/s/resp`:  func(r SnapRule) bool { return r.Script != nil && r.Script.RequiresBody },
	}
	for p, ok := range want {
		r, found := byLine[p]
		if !found || !ok(r) {
			b, _ := json.Marshal(r)
			t.Errorf("%s: %s", p, b)
		}
	}
	t.Logf("edge snapshot: %d rules, %d portable", s.Total, s.Portable)
	// a reload is a new generation; Stop forgets the engine
	cfg := &Config{Enabled: false, MitM: true}
	e.Reload(cfg, Build(home, cfg))
	g2 := e.RewriteSnapshotGen()
	if g2 == g1 {
		t.Fatal("generation unchanged after reload")
	}
	_ = json.Unmarshal([]byte(e.RewriteSnapshotJSON()), &s)
	if s.On || len(s.Rules) != 0 {
		t.Fatalf("rewrite off: %+v", s)
	}
}

func TestRewritePortableRegex(t *testing.T) {
	cases := map[string]bool{
		`^https?:\/\/api\.example\.com\/v1\/(ads|feed)\?`: true,
		`^https://a\.com/x(?!y)`:                          true,
		`^https://a\.com/[\w-]+/\d{2,4}`:                  true,
		`(?i)^https://a\.com/x`:                           true,
		`^https://a\.com/[a-z-[aeiou]]`:                   false,
		`^https://a\.com/[[a]]`:                           false,
		`^https://a\.com/\p{L}`:                           false,
		`^https://a\.com/(a)\1`:                           false,
		`^https://a\.com/x{`:                              false,
		`^https://a\.com/x{,3}`:                           false,
		`^https://a\.com/x*+`:                             false,
		`^https://a\.com/(?'n'x)`:                         false,
		`^https://a\.com/(?x) x`:                          false,
		`^https://a\.com/(?#c)`:                           false,
		`^https://a\.com/é`:                               false,
		`^https://a\.com/[\b]`:                            false,
		`^https://a\.com/\v`:                              false,
		`^https://a\.com/\x41\u0042`:                      true,
		`^https://a\.com/[]a]`:                            false,
		`^https://a\.com/[a&&b]`:                          false,
	}
	for p, want := range cases {
		if ok, _, _ := portableRegex(p); ok != want {
			t.Errorf("portableRegex(%q) = %v, want %v", p, ok, want)
		}
	}
	lits := map[string]string{
		`^https?:\/\/api\.example\.com\/v1`: "://api.example.com/v1",
		`^https://a\.com/(x|y)/zzzz`:        "https://a.com/",
		`^.+/(x|y)/zzzz`:                    "/zzzz",
		`a|b`:                               "",
		`^https://ab?cdef`:                  "https://a",
		`^.ab?cdef`:                         "cdef",
		`^https://xyz+w`:                    "https://xyz",
		`^.x{2}rst`:                         "rst",
		`^.x{0,2}rst`:                       "rst",
		`^.*\.(?:a|b)\.com/pathx`:           ".com/pathx",
	}
	for p, want := range lits {
		if got, _ := requiredLiteral(p); got != want {
			t.Errorf("requiredLiteral(%q) = %q, want %q", p, got, want)
		}
	}
}

// TestRewriteLiteralSound: for every rule of the repo's modules, a URL the rule matches contains its
// required literal (the Swift prefilter relies on it), over every rule's sample URL.
func TestRewriteLiteralSound(t *testing.T) {
	var all []*Rule
	for _, s := range rwCISuitesRules(t) {
		all = append(all, s...)
	}
	if dir := os.Getenv("TERN_QX_AUDIT_DIR"); dir != "" {
		m, _ := filepath.Glob(filepath.Join(dir, "res/*"))
		m2, _ := filepath.Glob(filepath.Join(dir, "corpus/mod/*"))
		for _, f := range append(m, m2...) {
			b, _ := os.ReadFile(f)
			rs := &Ruleset{}
			rs.ParseText(string(b), "x", nil)
			all = append(all, rs.Rules...)
		}
	}
	var samples []string
	for _, r := range all {
		if s := sampleURL(r.Pattern); s != "" {
			samples = append(samples, s, strings.Replace(s, "http://", "https://", 1), strings.ToUpper(s))
		}
	}
	checked, withLit := 0, 0
	for _, r := range all {
		if r.re == nil {
			continue
		}
		lit, fold := requiredLiteral(r.re.String())
		if lit == "" {
			continue
		}
		withLit++
		for _, s := range samples {
			if !r.match(s) {
				continue
			}
			checked++
			hay := s
			if fold {
				hay = strings.ToLower(s)
			}
			if !strings.Contains(hay, lit) {
				t.Errorf("pattern %q matches %q without its literal %q", r.Pattern, s, lit)
			}
		}
	}
	t.Logf("%d rules, %d with a literal, %d matches checked", len(all), withLit, checked)
}

func rwCISuitesRules(t *testing.T) [][]*Rule {
	var out [][]*Rule
	texts := []string{rwEdgeModule, rwQXEdge, surgeCompatModule, loonCompatModule, qxCompatModule, egernCompatModule}
	for _, n := range []string{"appclean.sgmodule", "appclean.plugin", "appclean_qx.conf", "appclean_egern.yaml", "yt_enhance.sgmodule", "yt_loon.plugin", "yt_ddgksf2013_qx.conf"} {
		b, err := os.ReadFile(filepath.Join("testdata", n))
		if err != nil {
			t.Fatal(err)
		}
		texts = append(texts, string(b))
	}
	for _, s := range texts {
		rs := &Ruleset{}
		rs.ParseText(s, "x", map[string]string{"word": "hello"})
		out = append(out, rs.Rules)
	}
	return out
}

// TestRewriteFlowCost measures what the Go flow costs per request that the native engine can answer
// alone (a request no rule touches, and a reject): bytes allocated per request, live heap and goroutines
// per in-flight flow. Logged for the stage-3a report; the native path's Go cost is zero by construction
// (no Go call besides MitmRewriteGeneration).
func TestRewriteFlowCost(t *testing.T) {
	home := t.TempDir()
	e, _ := rwEngine(t, home, []rwModule{{"edge", "edge", rwEdgeModule}})
	defer e.Stop()
	head := func(target string) string {
		b, _ := json.Marshal(FlowHead{Method: "GET", Target: target, Headers: rwBaseHeaders, ConnHost: "edge.test.com", ConnPort: 443, TLS: true})
		return string(b)
	}
	resp, _ := json.Marshal(FlowRespHead{Status: 200, Headers: rwCannedResp, Length: 2})
	one := func(target string) {
		d := rwDecode(t, e.FlowBegin(head(target)))
		if d.Action == "forward" {
			FlowResponse(d.ID, string(resp))
		}
		FlowEnd(d.ID, 0, "")
	}
	measure := func(name, target string) {
		for i := 0; i < 50; i++ {
			one(target)
		}
		waitFlows(t)
		const n = 400
		var a, b runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&a)
		for i := 0; i < n; i++ {
			one(target)
		}
		runtime.ReadMemStats(&b)
		perReq := float64(b.TotalAlloc-a.TotalAlloc) / n
		allocs := float64(b.Mallocs-a.Mallocs) / n
		// in flight: K flows parked between the request decision and the upstream's head
		const k = 200
		runtime.GC()
		var c, d runtime.MemStats
		runtime.ReadMemStats(&c)
		g0 := runtime.NumGoroutine()
		ids := make([]int64, 0, k)
		for i := 0; i < k; i++ {
			ids = append(ids, rwDecode(t, e.FlowBegin(head(target))).ID)
		}
		time.Sleep(50 * time.Millisecond)
		runtime.GC()
		runtime.ReadMemStats(&d)
		g1 := runtime.NumGoroutine()
		for _, id := range ids {
			FlowEnd(id, 0, "")
		}
		waitFlows(t)
		live := float64(int64(d.HeapAlloc)-int64(c.HeapAlloc)) / k
		t.Logf("%s: %.1f KB allocated / request (%.0f allocs), %.2f KB live heap and %.2f goroutines per in-flight flow",
			name, perReq/1024, allocs, live/1024, float64(g1-g0)/k)
	}
	measure("untouched forward", "/plain/x?a=1")
	measure("reject", "/rej")
	measure("header rewrite + response header", "/h/add")
}

// TestFlowResponseRightAfterForward: FlowResponse straight after a forward decision must run the response
// phase, not race the request goroutine's teardown (it answered "request phase ended without a decision").
func TestFlowResponseRightAfterForward(t *testing.T) {
	home := t.TempDir()
	e, _ := rwEngine(t, home, []rwModule{{"edge", "edge", rwEdgeModule}})
	defer e.Stop()
	hj, _ := json.Marshal(FlowHead{Method: "GET", Target: "/h/x", Headers: rwBaseHeaders, ConnHost: "edge.test.com", ConnPort: 443, TLS: true})
	rh, _ := json.Marshal(FlowRespHead{Status: 200, Headers: rwCannedResp, Length: 2})
	for i := 0; i < 2000; i++ {
		d := rwDecode(t, e.FlowBegin(string(hj)))
		if d.Action != "forward" {
			t.Fatalf("run %d: %+v", i, d)
		}
		r := rwDecode(t, FlowResponse(d.ID, string(rh)))
		FlowEnd(d.ID, 0, "")
		if r.Action != "respond" {
			t.Fatalf("run %d: response %+v", i, r)
		}
	}
	waitFlows(t)
}
