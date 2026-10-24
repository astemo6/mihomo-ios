package mitm

// Native body rewrite (stage 3b) — Go side tests and the byte-for-byte conformance corpus for the Swift engine.
//
// bdSuites builds engines from module text (CI modules + the user's QX corpus with TERN_QX_AUDIT_DIR), makes
// requests for every body / jq / json rule with request and response bodies in many shapes (matching, not
// matching, invalid UTF-8, not JSON, wrong types for jq paths, every Content-Encoding Go decodes and broken ones,
// bodies over 256 KB, chunked, HEAD / 204), and records what the real flow API sends: the outbound request and
// its body, the response decision and its body, the request-log entry. TERN_GEN_BODY_FIXTURES=<file> writes
// UnitTests/NativeMitmBodyFixtures.json for UnitTests/NativeMitmBodyTests.swift; TestBodyFixturesCurrent keeps the
// CI suites of the committed file in sync with Go.

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp/syntax"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
)

type bdResp struct {
	Status  int         `json:"status"`
	Headers [][2]string `json:"headers"`
	Length  int64       `json:"length"`
	Body    []byte      `json:"body"`           // the upstream's body as on the wire (de-framed, still encoded)
	Expect  rwDecision  `json:"expect"`         // Go's response decision
	Data    []byte      `json:"data,omitempty"` // the body Go sends the client (read mode; upstream mode: = Body, omitted)
	// Elided: Body / Data dropped from the file (bodies over 256 KB: Swift decides on the head alone).
	Elided bool `json:"elided,omitempty"`
}

type bdCase struct {
	Name     string      `json:"name"`
	Method   string      `json:"method"`
	Target   string      `json:"target"`
	Headers  [][2]string `json:"headers"`
	Length   int64       `json:"length"`
	ConnHost string      `json:"connHost"`
	ConnPort int         `json:"connPort"`
	ReqBody  []byte      `json:"reqBody,omitempty"`
	Expect   rwDecision  `json:"expect"`            // the request decision (after the body, when Go asked for it)
	ReqData  []byte      `json:"reqData,omitempty"` // the request body Go sends upstream (read mode)
	Resp     *bdResp     `json:"resp,omitempty"`
	Log      *rwLog      `json:"log,omitempty"`
}

type bdSuite struct {
	Name     string          `json:"name"`
	Snapshot json.RawMessage `json:"snapshot"`
	Labels   []string        `json:"labels"`
	Cases    []bdCase        `json:"cases"`
}

type bdFixtures struct {
	Version int       `json:"version"`
	Suites  []bdSuite `json:"suites"`
}

const bdEdgeModule = `#!name=native body edge
[Body Rewrite]
http-response ^https://body\.test\.com/r/plain "ad":true "ad":false
http-response ^https://body\.test\.com/r/multi (\w+)=(\d+) $2-$1-$$-$0-$9
http-response ^https://body\.test\.com/r/multi zh(.)x <$1>
http-response ^https://body\.test\.com/r/fold (?i)hello|straße WORLD
http-response ^https://body\.test\.com/r/line (?m)^x\d+ Y
http-response ^https://body\.test\.com/r/dot a.+?b X
http-response ^https://body\.test\.com/r/uni [\x{4e00}-\x{9fff}]+ 汉
http-response ^https://body\.test\.com/r/named (?P<k>key)=(?P<v>\w+) ${v}=${k}
http-response ^https://body\.test\.com/r/count a{2,4}c Z
http-response ^https://body\.test\.com/r/opt (x)?y $1Q
http-response ^https://body\.test\.com/r/start ^head X
http-response ^https://body\.test\.com/r/look foo(?=bar) X
http-response ^https://body\.test\.com/r/wordb \bad\b X
http-response ^https://body\.test\.com/r/dollar ad$ X
http-response ^https://body\.test\.com/r/nested (a+)+b X
http-response ^https://body\.test\.com/r/hdr "x":1 "x":2
http-response ^https://body\.test\.com/r/hdrce "x":1 "x":2
http-response ^https://body\.test\.com/r/empty \{.+\} {}
http-request ^https://body\.test\.com/q/plain aaa ccc
http-request ^https://body\.test\.com/q/all .+ ""
http-response-jq ^https://body\.test\.com/j/del 'del(.data.ads, .data.list[0])'
http-response-jq ^https://body\.test\.com/j/set '.data.list = [] | .data.flag = false | .data["a-b"] = {"x":[1,2.50,"中"]}'
http-response-jq ^https://body\.test\.com/j/root '. = {"ok":true}'
http-response-jq ^https://body\.test\.com/j/idx '.arr[3] = 1'
http-response-jq ^https://body\.test\.com/j/map '.data |= map(select(.ad | not))'
http-response-jq ^https://body\.test\.com/j/sel '.data.feeds |= map(select((.type == "EDITOR_PICK" or .name != "x") and (has("adCategory") | not))) | .data.n = null'
http-response-jq ^https://body\.test\.com/j/num '.data |= map(select(.n == 1.5))'
http-response-jq ^https://body\.test\.com/j/iter '.data |= map(select(.list[].x != "y"))'
http-request-jq ^https://body\.test\.com/q/jq '.k = 3'
[Header Rewrite]
http-response ^https://body\.test\.com/r/hdr header-add X-B 1
http-response ^https://body\.test\.com/r/hdr header-del Content-Type
http-response ^https://body\.test\.com/r/hdrce header-replace Content-Encoding gzip
[Script]
bs = type=http-response,pattern=^https://body\.test\.com/s/,script-path=https://example.invalid/s.js,requires-body=1
[MITM]
hostname = body.test.com
`

const bdLoonModule = `#!name=native body loon
[Rewrite]
^https://body\.test\.com/l/del response-body-json-del data.ads
^https://body\.test\.com/l/rep response-body-json-replace data.keep 9
^https://body\.test\.com/l/add response-body-json-add data.new.deep {"a":[1,{}],"n":12345678901234567890}
^https://body\.test\.com/l/idx response-body-json-replace data.list[1] "x"
^https://body\.test\.com/l/str response-body-json-add data.s hello
^https://body\.test\.com/l/req request-body-json-replace k 7
[MITM]
hostname = body.test.com
`

// bdExtras: a JSON member list inserted at the top of every object document — unicode, every escape Go writes,
// number spellings json.Number keeps, duplicate keys (last wins), keys that differ only in normalization.
const bdExtras = `"zz_extra":{"zh":"中文\u2028\u2029<&>\u00e9","esc":"a\"b\\c\/\n\t\u0001\u007f\b\f\r","nums":[0,-0,1.0,1e5,1E-7,12345678901234567890,-1.5e300,0.1,100],"deep":{"a":[{},[],null,true,false]},"dup":1,"dup":2,"e\u0301":1,"é":2,"emoji":"😀\ud83d\ude00"}`

func bdEncodings(plain []byte) map[string][]byte {
	out := map[string][]byte{}
	var g bytes.Buffer
	gw := gzip.NewWriter(&g)
	gw.Write(plain)
	gw.Close()
	out["gzip"] = append([]byte(nil), g.Bytes()...)
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write(plain)
	zw.Close()
	out["deflate-zlib"] = z.Bytes()
	var f bytes.Buffer
	fw, _ := flate.NewWriter(&f, 5)
	fw.Write(plain)
	fw.Close()
	out["deflate-raw"] = f.Bytes()
	var br bytes.Buffer
	bw := brotli.NewWriter(&br)
	bw.Write(plain)
	bw.Close()
	out["br"] = br.Bytes()
	// two gzip members
	var m bytes.Buffer
	h := len(plain) / 2
	for _, part := range [][]byte{plain[:h], plain[h:]} {
		w := gzip.NewWriter(&m)
		w.Write(part)
		w.Close()
	}
	out["gzip-multi"] = m.Bytes()
	out["gzip-trailing"] = append(append([]byte(nil), g.Bytes()...), 0, 0, 0)
	gb := g.Bytes()
	if len(gb) > 12 {
		out["gzip-truncated"] = append([]byte(nil), gb[:len(gb)-5]...)
	}
	// gzip with FNAME + FEXTRA
	var n bytes.Buffer
	nw := gzip.NewWriter(&n)
	nw.Name = "body.json"
	nw.Extra = []byte{1, 2, 3}
	nw.Write(plain)
	nw.Close()
	out["gzip-name"] = n.Bytes()
	return out
}

// bdSample: a string the RE2 pattern matches (first alternative, repeats twice), "" when it cannot tell.
func bdSample(p string, second bool) string {
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
			for _, c := range []rune{'a', 'x', '1', '0', 's', '中'} {
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
			b.WriteString("x中")
		case syntax.OpCapture:
			gen(r.Sub[0])
		case syntax.OpQuest:
			if second {
				gen(r.Sub[0])
			}
		case syntax.OpStar:
			if second {
				gen(r.Sub[0])
				gen(r.Sub[0])
			}
		case syntax.OpPlus:
			gen(r.Sub[0])
			if second {
				gen(r.Sub[0])
			}
		case syntax.OpRepeat:
			n := r.Min
			if second && (r.Max < 0 || r.Max > n) {
				n++
			}
			for i := 0; i < n; i++ {
				gen(r.Sub[0])
			}
		case syntax.OpConcat:
			for _, s := range r.Sub {
				gen(s)
			}
		case syntax.OpAlternate:
			if second && len(r.Sub) > 1 {
				gen(r.Sub[1])
			} else {
				gen(r.Sub[0])
			}
		}
	}
	gen(re)
	return b.String()
}

// bdDocs: JSON documents for rules editing paths: the paths present (objects / arrays / scalars), wrong types on
// the way, missing, not JSON, trailing data.
func bdDocs(paths [][]any) []string {
	var root any = map[string]any{}
	if len(paths) > 0 && len(paths[0]) > 0 {
		if _, ok := paths[0][0].(int); ok {
			root = []any{}
		}
	}
	set := func(v any, p []any, leaf any) any {
		var rec func(v any, p []any) any
		rec = func(v any, p []any) any {
			if len(p) == 0 {
				return leaf
			}
			switch k := p[0].(type) {
			case string:
				m, ok := v.(map[string]any)
				if !ok {
					m = map[string]any{}
				}
				m[k] = rec(m[k], p[1:])
				m["sib_"+k] = "keep"
				return m
			case int:
				a, ok := v.([]any)
				if !ok {
					a = []any{}
				}
				for len(a) <= k+1 {
					a = append(a, map[string]any{"filler": len(a)})
				}
				a[k] = rec(a[k], p[1:])
				return a
			}
			return v
		}
		return rec(v, p)
	}
	leaf := map[string]any{"keep": json.Number("1"), "ad": true, "list": []any{json.Number("1"), "two", nil}}
	item := func(ad bool, name, typ, id, title string) map[string]any {
		return map[string]any{"ad": ad, "name": name, "type": typ, "id": id, "title": title, "n": json.Number("1.50")}
	}
	arr := []any{item(true, "大赛", "EDITOR_PICK", "4154", "设置"), item(false, "x", "X", "1", "历史记录"),
		map[string]any{"adCategory": json.Number("3"), "name": nil}, map[string]any{}, item(false, "大赛2", "DISCOVERY_EPISODE_RECOMMEND", "4165", "y")}
	mixed := append(append([]any{}, arr...), "str", json.Number("5"))
	build := func(l any) any {
		v := root
		for _, p := range paths {
			v = set(v, p, l)
		}
		return v
	}
	full := build(leaf)
	full2 := build(arr)
	full3 := build(mixed)
	wrong := root
	for _, p := range paths {
		if len(p) > 1 {
			wrong = set(wrong, p[:len(p)-1], json.Number("42"))
		} else {
			wrong = set(wrong, p, json.Number("42"))
		}
	}
	enc := func(v any) string {
		b, _ := encodeJSON(v)
		s := string(b)
		if strings.HasPrefix(s, "{") {
			if s == "{}" {
				return "{" + bdExtras + "}"
			}
			return "{" + bdExtras + "," + s[1:]
		}
		return s
	}
	f := enc(full)
	return []string{f, enc(full2), enc(full3), enc(wrong), "{}", "[]", "<html>not json</html>", f + " x", "\ufeff" + f, " \n\t" + f + "\r\n", `{"a":"\ud800"}`, `{"a":1}{"b":2}`}
}

// bdPaths: the paths a body rule edits (json ops, jq steps).
func bdPaths(r *Rule) [][]any {
	var out [][]any
	switch r.Kind {
	case KindJSON:
		for _, op := range r.JSON {
			out = append(out, splitJSONPath(op.Path))
		}
	case KindJQ:
		if steps, why := snapJQ(r.JQ); why == "" {
			for _, s := range steps {
				if s.Path != nil {
					out = append(out, s.Path)
				}
				out = append(out, s.Paths...)
			}
		} else {
			out = append(out, []any{"data"}, []any{"feeds"}, []any{"listElements"})
		}
	}
	if len(out) == 0 {
		out = append(out, []any{"data"})
	}
	return out
}

// bdRegexBodies: bodies for a regex rule (from each op's pattern).
func bdRegexBodies(r *Rule) []string {
	var out []string
	for _, op := range r.Body {
		s1, s2 := bdSample(op.Regex, false), bdSample(op.Regex, true)
		if s1 == "" && s2 == "" {
			continue
		}
		out = append(out, "head 中文 ✓ "+s1+" mid\n"+s2+" tail\nx12 "+s1, s2, `{"a":"`+s1+`","b":[1,2],"c":"`+s2+`"}`)
	}
	out = append(out, "no match here 中文", "head\nhead x99\nhello Hello straße STRASSE ſtraße")
	if len(out) > 0 {
		out = append(out, out[0]+"\xff\xfe")
	}
	return out
}

func bdRun(t testing.TB, e *Engine, c *bdCase, respStatus int, respHeaders [][2]string, respBody []byte, respLength int64) {
	t.Helper()
	head := FlowHead{Method: c.Method, Target: c.Target, Headers: c.Headers, Length: c.Length, ConnHost: c.ConnHost, ConnPort: c.ConnPort, TLS: true}
	hj, _ := json.Marshal(head)
	d := rwDecode(t, e.FlowBegin(string(hj)))
	id := d.ID
	var ent *Entry
	if nf := lookupFlow(id); nf != nil {
		nf.mu.Lock()
		ent = nf.ent
		nf.mu.Unlock()
	}
	push := func(which int, b []byte) {
		for off := 0; off < len(b); off += 7 << 10 {
			end := min(off+7<<10, len(b))
			if r := FlowWrite(id, which, b[off:end]); r != "" {
				break
			}
		}
		FlowClose(id, which, "")
	}
	readAll := func(which int) []byte {
		var buf bytes.Buffer
		for i := 0; i < 100000; i++ {
			b := FlowRead(id, which, 32<<10)
			buf.Write(b)
			if len(b) == 0 {
				st := FlowReadState(id, which)
				if st == "eof" {
					break
				}
				if st != "" {
					t.Fatalf("%s: read %d: %s", c.Name, which, st)
				}
				time.Sleep(time.Millisecond)
			}
		}
		return buf.Bytes()
	}
	if d.Action == "need-body" {
		push(0, c.ReqBody)
		d = rwDecode(t, FlowAwait(id))
	}
	c.Expect = rwFrom(d)
	switch d.Action {
	case "local":
		if d.Body == "read" {
			c.Expect.Data = base64.StdEncoding.EncodeToString(readAll(1))
		}
	case "forward":
		if d.Body == "read" {
			c.ReqData = readAll(0)
		}
		rh, _ := json.Marshal(FlowRespHead{Status: respStatus, Headers: respHeaders, Length: respLength})
		rd := rwDecode(t, FlowResponse(id, string(rh)))
		if rd.Action == "need-body" {
			push(1, respBody)
			rd = rwDecode(t, FlowAwait(id))
		}
		rs := &bdResp{Status: respStatus, Headers: respHeaders, Length: respLength, Body: respBody, Expect: rwFrom(rd)}
		if rd.Body == "read" {
			rs.Data = readAll(1)
		}
		if len(respBody) > 256<<10 {
			rs.Body, rs.Data, rs.Elided = nil, nil, true
		}
		c.Resp = rs
	}
	FlowEnd(id, int64(len(respBody)), "")
	if ent != nil {
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
	}
}

// bdScriptMatches: a script rule would run for the request (scripts are not run here).
func bdScriptMatches(st *state, method, rawURL string) bool {
	r, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		return true
	}
	for _, rule := range st.rs.Rules {
		if rule.Kind == KindScript && rule.matchReq(rawURL, r) {
			return true
		}
	}
	return false
}

func bdSuiteFor(t testing.TB, name string, mods []rwModule, maxRules int) bdSuite {
	home := t.(interface{ TempDir() string }).TempDir()
	e, rs := rwEngine(t, home, mods)
	defer e.Stop()
	st := e.state()
	s := bdSuite{Name: name, Snapshot: json.RawMessage(e.RewriteSnapshotJSON()), Labels: []string{}, Cases: []bdCase{}}
	for _, r := range st.rs.Rules {
		s.Labels = append(s.Labels, r.label())
	}
	jsonCT := [][2]string{{"Content-Type", "application/json; charset=utf-8"}, {"X-Up", "1"}, {"Connection", "keep-alive"}, {"Set-Cookie", "a=1"}}
	add := func(c bdCase, status int, hs [][2]string, body []byte, length int64) {
		if c.ConnPort == 0 {
			c.ConnPort = 443
		}
		bdRun(t, e, &c, status, hs, body, length)
		s.Cases = append(s.Cases, c)
	}
	withLen := func(hs [][2]string, enc string, n int) [][2]string {
		out := append([][2]string{}, hs...)
		if enc != "" {
			out = append(out, [2]string{"Content-Encoding", enc})
		}
		return append(out, [2]string{"Content-Length", strconv.Itoa(n)})
	}
	stride := 1
	var bodyRules []int
	for i, r := range rs.Rules {
		if r.Kind == KindBody || r.Kind == KindJQ || r.Kind == KindJSON {
			bodyRules = append(bodyRules, i)
		}
	}
	if maxRules > 0 && len(bodyRules) > maxRules {
		stride = (len(bodyRules) + maxRules - 1) / maxRules
	}
	for n, i := range bodyRules {
		if n%stride != 0 {
			continue
		}
		r := rs.Rules[i]
		smp := sampleURL(r.Pattern)
		if strings.HasPrefix(smp, "http://") && r.match("https://"+smp[7:]) {
			smp = "https://" + smp[7:]
		}
		su, err := url.Parse(smp)
		if smp == "" || err != nil || su.Scheme != "https" || su.Host == "" || !r.match(smp) || !st.hosts.Match(su.Hostname(), 443) {
			continue
		}
		target := su.RequestURI()
		if bdScriptMatches(st, "GET", smp) || bdScriptMatches(st, "POST", smp) {
			continue
		}
		label := fmt.Sprintf("rule %d %s %s", i, r.Kind, clip(r.Pattern, 50))
		var bodies []string
		if r.Kind == KindBody {
			bodies = bdRegexBodies(r)
		} else {
			bodies = bdDocs(bdPaths(r))
		}
		base := bdCase{Method: "GET", Target: target, Headers: rwBaseHeaders, ConnHost: su.Hostname()}
		if r.Phase == "request" {
			for k, b := range bodies {
				c := base
				c.Name = fmt.Sprintf("%s req body %d", label, k)
				c.Method = "POST"
				c.Headers = append(append([][2]string{}, rwBaseHeaders...), [2]string{"Content-Type", "application/json"})
				c.ReqBody = []byte(b)
				c.Length = int64(len(b))
				add(c, 200, withLen(jsonCT, "", 2), []byte("ok"), 2)
			}
			c := base
			c.Name = label + " req GET no body"
			add(c, 200, withLen(jsonCT, "", 2), []byte("ok"), 2)
			c.Name = label + " req chunked"
			c.Method, c.Length = "PUT", -1
			c.Headers = append(append([][2]string{}, rwBaseHeaders...), [2]string{"Transfer-Encoding", "chunked"})
			c.ReqBody = []byte(bodies[0])
			add(c, 200, withLen(jsonCT, "", 2), []byte("ok"), 2)
			continue
		}
		for k, b := range bodies {
			plain := []byte(b)
			c := base
			c.Name = fmt.Sprintf("%s body %d identity", label, k)
			add(c, 200, withLen(jsonCT, "", len(plain)), plain, int64(len(plain)))
			encs := bdEncodings(plain)
			names := []string{"gzip", "br"}
			if k == 0 {
				names = []string{"gzip", "br", "deflate-zlib", "deflate-raw", "gzip-multi", "gzip-trailing", "gzip-truncated", "gzip-name"}
			}
			for _, en := range names {
				eb, ok := encs[en]
				if !ok {
					continue
				}
				hdr := strings.SplitN(en, "-", 2)[0]
				c := base
				c.Name = fmt.Sprintf("%s body %d %s", label, k, en)
				add(c, 200, withLen(jsonCT, hdr, len(eb)), eb, int64(len(eb)))
			}
			if k == 0 {
				for _, ce := range []string{"identity", "x-gzip", "compress", "GZIP", "gzip, identity"} {
					eb := plain
					if strings.Contains(strings.ToLower(ce), "gzip") {
						eb = encs["gzip"]
					}
					c := base
					c.Name = fmt.Sprintf("%s body %d ce %q", label, k, ce)
					add(c, 200, withLen(jsonCT, ce, len(eb)), eb, int64(len(eb)))
				}
			}
		}
		first := []byte(bodies[0])
		c := base
		c.Name = label + " chunked"
		add(c, 200, append(append([][2]string{}, jsonCT...), [2]string{"Transfer-Encoding", "chunked"}), first, -1)
		c.Name = label + " 204"
		add(c, 204, [][2]string{{"X-Up", "1"}}, nil, 0)
		c.Name = label + " HEAD"
		c.Method = "HEAD"
		add(c, 200, withLen(jsonCT, "", 77), nil, 77)
		c = base
		c.Name = label + " large"
		big := append(bytes.Repeat([]byte(" "), 300<<10), first...)
		add(c, 200, withLen(jsonCT, "", len(big)), big, int64(len(big)))
		c.Name = label + " zero length"
		add(c, 200, withLen(jsonCT, "", 0), nil, 0)
		c.Name = label + " POST client body"
		c.Method = "POST"
		c.ReqBody = []byte("hello")
		c.Length = 5
		add(c, 200, withLen(jsonCT, "", len(first)), first, int64(len(first)))
	}
	return s
}

func bdCISuites(t testing.TB) []bdSuite {
	read := func(n string) string {
		b, err := os.ReadFile(filepath.Join("testdata", n))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	return []bdSuite{
		bdSuiteFor(t, "body-edge", []rwModule{{"be", "edge", bdEdgeModule}, {"bl", "loon", bdLoonModule}}, 0),
		bdSuiteFor(t, "compat", []rwModule{{"sg", "Surge", surgeCompatModule}, {"lo", "Loon", loonCompatModule}, {"qx", "QX", qxCompatModule}, {"eg", "Egern", egernCompatModule}}, 0),
		bdSuiteFor(t, "appclean", []rwModule{{"a1", "Surge", read("appclean.sgmodule")}, {"a2", "Loon", read("appclean.plugin")}, {"a3", "QX", read("appclean_qx.conf")}, {"a4", "Egern", read("appclean_egern.yaml")}}, 0),
	}
}

func bdCorpusSuites(t testing.TB, dir string) []bdSuite {
	var files []string
	for _, g := range []string{"res/*", "corpus/mod/*"} {
		m, _ := filepath.Glob(filepath.Join(dir, g))
		sort.Strings(m)
		files = append(files, m...)
	}
	var out []bdSuite
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		s := bdSuiteFor(t, "corpus/"+filepath.Base(f), []rwModule{{"m", filepath.Base(f), string(b)}}, 40)
		if len(s.Cases) > 0 {
			out = append(out, s)
		}
	}
	return out
}

func bdStripGen(s bdSuite) bdSuite {
	var m map[string]any
	_ = json.Unmarshal(s.Snapshot, &m)
	delete(m, "gen")
	s.Snapshot, _ = json.Marshal(m)
	return s
}

// TestGenBodyFixtures writes the Swift body conformance corpus (opt-in).
func TestGenBodyFixtures(t *testing.T) {
	out := os.Getenv("TERN_GEN_BODY_FIXTURES")
	if out == "" {
		t.Skip("set TERN_GEN_BODY_FIXTURES=<path to UnitTests/NativeMitmBodyFixtures.json>")
	}
	fx := bdFixtures{Version: RewriteSnapshotVersion, Suites: bdCISuites(t)}
	if dir := os.Getenv("TERN_QX_AUDIT_DIR"); dir != "" {
		fx.Suites = append(fx.Suites, bdCorpusSuites(t, dir)...)
	}
	n := 0
	for i := range fx.Suites {
		fx.Suites[i] = bdStripGen(fx.Suites[i])
		n += len(fx.Suites[i].Cases)
	}
	b, err := json.Marshal(fx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d suites, %d cases, %d KB", len(fx.Suites), n, len(b)>>10)
	waitFlows(t)
}

// TestBodyFixturesCurrent: the committed body fixture's CI suites still match what Go does.
func TestBodyFixturesCurrent(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "UnitTests", "NativeMitmBodyFixtures.json"))
	if err != nil {
		t.Skip("no committed fixture")
	}
	var fx bdFixtures
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	committed := map[string]bdSuite{}
	for _, s := range fx.Suites {
		committed[s.Name] = s
	}
	for _, s := range bdCISuites(t) {
		s = bdStripGen(s)
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
		if len(s.Cases) != len(c.Cases) {
			t.Errorf("suite %s: %d cases now, %d committed", s.Name, len(s.Cases), len(c.Cases))
			continue
		}
		for i := range s.Cases {
			x, _ := json.Marshal(s.Cases[i])
			y, _ := json.Marshal(c.Cases[i])
			if !bytes.Equal(x, y) {
				t.Errorf("suite %s case %q: Go now does\n %s\ncommitted\n %s", s.Name, s.Cases[i].Name, clip(string(x), 600), clip(string(y), 600))
			}
		}
	}
	waitFlows(t)
}

// TestBodySnapshotExport: what Go marks portable for the body edge module.
func TestBodySnapshotExport(t *testing.T) {
	rs := &Ruleset{}
	rs.ParseText(bdEdgeModule+"\n"+bdLoonModule, "x", nil)
	want := map[string]bool{
		`^https://body\.test\.com/r/plain`: true, `^https://body\.test\.com/r/multi`: true, `^https://body\.test\.com/r/fold`: true,
		`^https://body\.test\.com/r/line`: true, `^https://body\.test\.com/r/named`: true, `^https://body\.test\.com/r/look`: false,
		`^https://body\.test\.com/r/wordb`: false, `^https://body\.test\.com/r/dollar`: false, `^https://body\.test\.com/r/nested`: false,
		`^https://body\.test\.com/j/del`: true, `^https://body\.test\.com/j/set`: true, `^https://body\.test\.com/j/map`: true, `^https://body\.test\.com/j/sel`: true, `^https://body\.test\.com/j/num`: false, `^https://body\.test\.com/j/iter`: false,
		`^https://body\.test\.com/l/add`: true, `^https://body\.test\.com/q/jq`: true,
	}
	seen := 0
	for i, r := range rs.Rules {
		sr := snapRule(i, r, nil)
		if w, ok := want[r.Pattern]; ok && (r.Kind == KindBody || r.Kind == KindJQ || r.Kind == KindJSON) {
			seen++
			if sr.BodyOK != w {
				t.Errorf("%s (%s): bodyOK %v (why %q), want %v", r.Pattern, r.Kind, sr.BodyOK, sr.BodyWhy, w)
			}
		}
	}
	if seen < len(want) {
		t.Errorf("only %d of %d rules seen", seen, len(want))
	}
}

// TestBodyFlowCost measures what the Go flow costs per body-rewrite request the native engine answers alone:
// bytes allocated per exchange, live heap / goroutines per in-flight flow holding its body, bridge calls. The
// native path costs Go nothing (MitmRewriteGeneration + a batched MitmRecordNative per ~64 requests).
func TestBodyFlowCost(t *testing.T) {
	home := t.TempDir()
	e, _ := rwEngine(t, home, []rwModule{{"be", "edge", bdEdgeModule}, {"bl", "loon", bdLoonModule}})
	defer e.Stop()
	mk := func(n int) []byte {
		var b strings.Builder
		b.WriteString(`{"data":{"ads":[1,2,3],"keep":1,"list":[`)
		for i := 0; b.Len() < n; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `{"id":%d,"title":"条目 %d","ad":%v}`, i, i, i%3 == 0)
		}
		b.WriteString(`]}}`)
		return []byte(b.String())
	}
	type exch struct {
		name, target string
		body         []byte
		enc          string
	}
	for _, size := range []int{8 << 10, 64 << 10} {
		plain := mk(size)
		gz := bdEncodings(plain)["gzip"]
		for _, x := range []exch{{"regex", "/r/plain", plain, ""}, {"regex gzip", "/r/plain", gz, "gzip"}, {"json del", "/l/del", plain, ""}, {"jq del", "/j/del", gz, "gzip"}} {
			hs := [][2]string{{"Content-Type", "application/json"}, {"Content-Length", strconv.Itoa(len(x.body))}}
			if x.enc != "" {
				hs = append(hs, [2]string{"Content-Encoding", x.enc})
			}
			calls := 0
			one := func() {
				c := bdCase{Name: x.name, Method: "GET", Target: x.target, Headers: rwBaseHeaders, ConnHost: "body.test.com", ConnPort: 443}
				head := FlowHead{Method: c.Method, Target: c.Target, Headers: c.Headers, ConnHost: c.ConnHost, ConnPort: 443, TLS: true}
				hj, _ := json.Marshal(head)
				d := rwDecode(t, e.FlowBegin(string(hj)))
				calls = 1
				rh, _ := json.Marshal(FlowRespHead{Status: 200, Headers: hs, Length: int64(len(x.body))})
				rd := rwDecode(t, FlowResponse(d.ID, string(rh)))
				calls++
				if rd.Action == "need-body" {
					for off := 0; off < len(x.body); off += 32 << 10 {
						FlowWrite(d.ID, 1, x.body[off:min(off+32<<10, len(x.body))])
						calls++
					}
					FlowClose(d.ID, 1, "")
					rd = rwDecode(t, FlowAwait(d.ID))
					calls += 2
				}
				if rd.Body != "read" {
					t.Fatalf("%s: %+v", x.name, rd)
				}
				for {
					b := FlowRead(d.ID, 1, 32<<10)
					calls++
					if len(b) == 0 {
						calls++
						if FlowReadState(d.ID, 1) == "eof" {
							break
						}
					}
				}
				FlowEnd(d.ID, 0, "")
				calls++
			}
			for i := 0; i < 20; i++ {
				one()
			}
			waitFlows(t)
			const n = 100
			var a, b runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&a)
			for i := 0; i < n; i++ {
				one()
			}
			runtime.ReadMemStats(&b)
			waitFlows(t)
			// in flight: flows parked after the response decision (body read and rewritten, not yet sent)
			const k = 40
			runtime.GC()
			var c, d runtime.MemStats
			runtime.ReadMemStats(&c)
			g0 := runtime.NumGoroutine()
			var ids []int64
			for i := 0; i < k; i++ {
				head := FlowHead{Method: "GET", Target: x.target, Headers: rwBaseHeaders, ConnHost: "body.test.com", ConnPort: 443, TLS: true}
				hj, _ := json.Marshal(head)
				dd := rwDecode(t, e.FlowBegin(string(hj)))
				rh, _ := json.Marshal(FlowRespHead{Status: 200, Headers: hs, Length: int64(len(x.body))})
				if rwDecode(t, FlowResponse(dd.ID, string(rh))).Action == "need-body" {
					FlowWrite(dd.ID, 1, x.body)
					FlowClose(dd.ID, 1, "")
					FlowAwait(dd.ID)
				}
				ids = append(ids, dd.ID)
			}
			time.Sleep(30 * time.Millisecond)
			runtime.GC()
			runtime.ReadMemStats(&d)
			g1 := runtime.NumGoroutine()
			for _, id := range ids {
				FlowEnd(id, 0, "")
			}
			waitFlows(t)
			t.Logf("%s %d KB body (%d KB on the wire): %.1f KB allocated / exchange (%.0f allocs), %.1f KB live heap and %.2f goroutines per in-flight flow, %d bridge calls / exchange",
				x.name, len(plain)>>10, len(x.body)>>10, float64(b.TotalAlloc-a.TotalAlloc)/n/1024, float64(b.Mallocs-a.Mallocs)/n,
				float64(int64(d.HeapAlloc)-int64(c.HeapAlloc))/k/1024, float64(g1-g0)/k, calls)
		}
	}
}
