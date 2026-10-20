package mitm

// review6 lane 2 (bridge/mitm) regression tests.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func r6JSON(n int) []byte {
	var b bytes.Buffer
	b.WriteString(`{"data":[`)
	for i := 0; b.Len() < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"id":%d,"ad":true,"name":"item%d"}`, i, i)
	}
	b.WriteString(`]}`)
	return b.Bytes()
}

// P1-1: JSON rules skip bodies over jsonBodyLimit (and when the heap estimate does not fit).
func TestR6JSONRuleSizeCap(t *testing.T) {
	big := r6JSON(jsonBodyLimit + 1000)
	small := r6JSON(50 << 10)
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(
		`http-response-jq ^https://api\.test\.com/j 'del(.data[0])'`,
		`^https://api\.test\.com/d response-body-json-del data[0]`)}
	h := newHarness(t, cfg, nil)
	var body []byte
	h.up.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) })
	for _, p := range []string{"/j", "/d"} {
		body = big
		_, got := h.get("https://api.test.com" + p)
		if got != string(big) {
			t.Fatalf("%s: big body changed (len %d → %d)", p, len(big), len(got))
		}
		body = small
		_, got = h.get("https://api.test.com" + p)
		if strings.Contains(got, `"id":0,`) || !strings.Contains(got, `"id":1,`) {
			t.Fatalf("%s: small body not edited: %.80s", p, got)
		}
	}
	old := memGuardLimit
	defer func() { memGuardLimit = old }()
	memGuardLimit = func() int64 { return 26 << 20 }
	if err := jsonBodyFits(1 << 20); err != nil && jsonHeapNow()+(1<<20)*jsonHeapPerByte <= (26<<20)/10*9 {
		t.Fatalf("fits but refused: %v", err)
	}
	memGuardLimit = func() int64 { return 4 << 20 }
	if jsonBodyFits(512<<10) == nil {
		t.Fatal("expected refusal under a 4 MB limit")
	}
}

// P1-4: jq / json-del keep 64-bit integers and don't HTML-escape.
func TestR6JSONBigIntAndHTML(t *testing.T) {
	src := `{"id":1234567890123456789,"ad":true,"h":"<a href=x>&","f":1.5}`
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(
		`http-response-jq ^https://api\.test\.com/j 'del(.ad)'`,
		`^https://api\.test\.com/d response-body-json-del ad`,
		`^https://api\.test\.com/r response-body-json-replace f 9007199254740993`)}
	h := newHarness(t, cfg, nil)
	h.up.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, src) })
	for _, p := range []string{"/j", "/d"} {
		_, got := h.get("https://api.test.com" + p)
		if got != `{"f":1.5,"h":"<a href=x>&","id":1234567890123456789}` {
			t.Fatalf("%s: %s", p, got)
		}
	}
	if _, got := h.get("https://api.test.com/r"); !strings.Contains(got, `"f":9007199254740993`) || !strings.Contains(got, `"id":1234567890123456789`) {
		t.Fatalf("replace: %s", got)
	}
	if _, err := decodeJSONNumber([]byte(`{"a":1} x`)); err == nil {
		t.Fatal("trailing data accepted")
	}
}

// P1-3: a script without requires-body that returns a body drops the upstream Content-Encoding.
func TestR6ScriptBodyDropsEncoding(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(
		`m = type=http-response,pattern=^https://api\.test\.com/gzip,script-path=m.js`,
		`k = type=http-response,pattern=^https://api\.test\.com/json,script-path=k.js`)}
	h := newHarness(t, cfg, map[string]string{
		"m.js": `$done({body: '{"vip":true}'})`,
		"k.js": `$done({headers: $response.headers})`,
	})
	resp, b := h.get("https://api.test.com/gzip", "Accept-Encoding", "gzip")
	if resp.Header.Get("Content-Encoding") != "" || b != `{"vip":true}` {
		t.Fatalf("ce=%q body=%q", resp.Header.Get("Content-Encoding"), b)
	}
	// headers-only script on a compressed response keeps the encoding (body untouched)
	h.up.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		_, _ = io.WriteString(zw, "zipped")
		_ = zw.Close()
	})
	resp, b = h.get("https://api.test.com/json", "Accept-Encoding", "gzip")
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("headers-only: ce=%q", resp.Header.Get("Content-Encoding"))
	}
	zr, err := gzip.NewReader(strings.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if plain, _ := io.ReadAll(zr); string(plain) != "zipped" {
		t.Fatalf("headers-only body %q", plain)
	}
}

// P2-1: out-of-range statuses from scripts are ignored instead of a 502.
func TestR6BadStatus(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(
		`a = type=http-response,pattern=^https://api\.test\.com/json,script-path=a.js`,
		`b = type=http-request,pattern=^https://api\.test\.com/x,script-path=b.js`,
		`c = type=http-request,pattern=^https://api\.test\.com/y,script-path=c.js`)}
	h := newHarness(t, cfg, map[string]string{
		"a.js": `$done({status: 1000})`,
		"b.js": `$done({response:{status: 42, body:'hi'}})`,
		"c.js": `$done({response:{status: "HTTP/1.1 418 I'm a teapot", body:'tea'}})`,
	})
	if resp, b := h.get("https://api.test.com/json"); resp.StatusCode != 200 || !strings.Contains(b, `"ad":true`) {
		t.Fatalf("response: %d %q", resp.StatusCode, b)
	}
	if resp, b := h.get("https://api.test.com/x"); resp.StatusCode != 200 || b != "hi" {
		t.Fatalf("mock: %d %q", resp.StatusCode, b)
	}
	if resp, b := h.get("https://api.test.com/y"); resp.StatusCode != 418 || b != "tea" {
		t.Fatalf("valid mock: %d %q", resp.StatusCode, b)
	}
}

// P2-2 / OPT-2: a corrupt store file is set aside, the in-memory store survives; size tracking.
func TestR6StoreCorruptAndSize(t *testing.T) {
	home := t.TempDir()
	s := NewStore(home)
	if !s.Write("boxjs", "big-data", false) {
		t.Fatal("write")
	}
	_ = s.Flush()
	p := filepath.Join(EngineDir(home), "store.json")
	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(p, []byte(`{"boxjs":"big-da`), 0o644); err != nil {
		t.Fatal(err)
	}
	if v, ok := s.Read("boxjs"); !ok || v != "big-data" {
		t.Fatalf("after corrupt read: %q %v", v, ok)
	}
	s.Write("counter", "1", false)
	_ = s.Flush()
	b, _ := os.ReadFile(p)
	if string(b) != `{"boxjs":"big-data","counter":"1"}` {
		t.Fatalf("file: %s", b)
	}
	if _, err := os.Stat(p + ".bad"); err != nil {
		t.Fatalf("no .bad copy: %v", err)
	}
	// a fresh store on a corrupt file starts empty without losing the file's bytes
	_ = os.WriteFile(p, []byte(`{"x":`), 0o644)
	s2 := NewStore(home)
	if _, ok := s2.Read("boxjs"); ok {
		t.Fatal("corrupt file read as data")
	}

	// size tracking: total cap enforced, replace and delete adjust the running total
	s3 := NewStore(t.TempDir())
	big := strings.Repeat("v", storeMaxTotal/2-1)
	if !s3.Write("a", big, false) || !s3.Write("b", big, false) {
		t.Fatal("two max values should fit")
	}
	if s3.Write("c", "x", false) {
		t.Fatal("total cap not enforced")
	}
	if !s3.Write("a", "small", false) || !s3.Write("c", "x", false) {
		t.Fatal("replace did not free space")
	}
	s3.Write("b", "", true)
	s3.mu.Lock()
	got := s3.size
	s3.recomputeSizeLocked()
	want := s3.size
	s3.mu.Unlock()
	if got != want || want != len("a")+len("small")+len("c")+1 {
		t.Fatalf("size %d, recomputed %d", got, want)
	}
	_ = s3.Flush()
}

// P2-3: Surge Header / Body Rewrite lines don't make a Surge module "loon"; Loon [Script] lines do.
func TestR6SurgeRewriteNotLoon(t *testing.T) {
	surge := "#!name=s\n[Header Rewrite]\nhttp-request ^https://a\\.com header-del X\n[Body Rewrite]\nhttp-response ^https://a\\.com a b\n[Script]\ns = type=http-response,pattern=^https://a\\.com,script-path=s.js\n[MITM]\nhostname = a.com\n"
	rs := &Ruleset{}
	rs.ParseText(surge, "t", nil)
	if rs.Format != "surge" {
		t.Fatalf("surge module classified %q", rs.Format)
	}
	loon := "#!name=l\n[Script]\nhttp-response ^https://a\\.com script-path=s.js, requires-body=true, tag=t\n[MITM]\nhostname = a.com\n"
	rs = &Ruleset{}
	rs.ParseText(loon, "t", nil)
	if rs.Format != "loon" {
		t.Fatalf("loon plugin classified %q", rs.Format)
	}
}

// P1-2: script downloads take a body-budget share, hand it back after the callback, and proceed when
// the budget is held elsewhere (no self-deadlock).
func TestR6FetchBudget(t *testing.T) {
	big := bytes.Repeat([]byte("y"), 1<<20)
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(
		`f = type=http-request,pattern=^https://api\.test\.com/go,script-path=f.js,timeout=30`)}
	h := newHarness(t, cfg, map[string]string{"f.js": `var n=0,l=0;for(let i=0;i<4;i++)$httpClient.get({url:'https://api.test.com/b'+i,insecure:true},(e,r,d)=>{n++;l+=d?d.length:0;if(n==4)$done({response:{status:200,body:String(l)}})})`})
	h.up.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(big) })
	if _, out := h.get("https://api.test.com/go"); out != fmt.Sprint(4<<20) {
		t.Fatalf("got %q", out)
	}
	if n := bodyBudget.inUse(); n != 0 {
		t.Fatalf("budget not returned: %d", n)
	}
	// budget fully held by someone else: the download still goes ahead after fetchBudgetWait
	oldWait := fetchBudgetWait
	fetchBudgetWait = 100 * time.Millisecond
	defer func() { fetchBudgetWait = oldWait }()
	rel := bodyBudget.acquire(t.Context(), bodyBudgetBytes, time.Second)
	if rel == nil {
		t.Fatal("could not take the budget")
	}
	if _, out := h.get("https://api.test.com/go"); out != fmt.Sprint(4<<20) {
		t.Fatalf("with budget held: %q", out)
	}
	rel()
	if n := bodyBudget.inUse(); n != 0 {
		t.Fatalf("budget after held run: %d", n)
	}
}

// OPT-4: readSized reads exact, longer-than-announced and over-limit bodies correctly.
func TestR6ReadSized(t *testing.T) {
	for _, c := range []struct {
		data string
		cl   int64
		lim  int
		want int
	}{{"hello", 5, 10, 5}, {"hello world", 5, 20, 11}, {"hello world", -1, 20, 11}, {"hello world", -1, 4, 5}, {"hello world", 5, 6, 7}} {
		b, err := readSized(strings.NewReader(c.data), c.cl, c.lim)
		if err != nil || len(b) != c.want {
			t.Fatalf("%+v: len %d err %v", c, len(b), err)
		}
	}
	if _, err := readSized(strings.NewReader("hi"), 5, 10); err == nil {
		t.Fatal("short body accepted")
	}
}

// OPT-1: binary-mode body and bodyBytes share one buffer.
func TestR6BinaryBodyShared(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(
		`b = type=http-response,pattern=^https://api\.test\.com/bin,requires-body=1,binary-body-mode=1,script-path=b.js`)}
	h := newHarness(t, cfg, map[string]string{"b.js": `var u=$response.body; $done({body: String(u.buffer === $response.bodyBytes) + ':' + u.length + ':' + u[4]})`})
	if _, b := h.get("https://api.test.com/bin"); b != "true:6:250" {
		t.Fatalf("got %q", b)
	}
}

// OPT-3: a remote source served from the memory cache still triggers a stale refresh.
func TestR6MemCacheStaleRefresh(t *testing.T) {
	h := newHarness(t, &Config{Enabled: true}, nil)
	r := h.e.res
	u := "https://api.test.com/s.js"
	cp := r.cachePath(u)
	_ = os.MkdirAll(filepath.Dir(cp), 0o755)
	_ = os.WriteFile(cp, []byte("1"), 0o644)
	old := time.Now().Add(-2 * time.Hour)
	_ = os.Chtimes(cp, old, old)
	r.mem.PutW(u, []byte("1"), 1)
	if _, err := r.Get(u, 60); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	_, tried := r.tried[u]
	r.mu.Unlock()
	if !tried {
		t.Fatal("mem-cache hit did not schedule a stale refresh")
	}
}

// P2-5: a client stalling mid-ClientHello after CONNECT to an IP is dropped after sniPeekTimeout.
func TestR6SNIPeekDeadline(t *testing.T) {
	old := sniPeekTimeoutNs.Swap(int64(200 * time.Millisecond))
	defer sniPeekTimeoutNs.Store(old)
	h := newHarness(t, &Config{Enabled: true, MitM: true, Hostnames: []string{"*"}}, nil)
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", h.e.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = io.WriteString(c, "CONNECT 1.2.3.4:443 HTTP/1.1\r\nHost: 1.2.3.4:443\r\n\r\n")
	buf := make([]byte, 64)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(buf); err != nil {
		t.Fatal(err)
	}
	// TLS record header announcing 512 bytes, then stall
	_, _ = c.Write([]byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01})
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	for {
		if _, err := c.Read(buf); err != nil {
			break
		}
	}
	if d := time.Since(start); d > 2500*time.Millisecond {
		t.Fatalf("connection not dropped after the SNI deadline (%s)", d)
	}
}

var _ = json.Valid
