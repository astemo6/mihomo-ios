package mitm

// review5 lane 2 (bridge/mitm) regression tests, built from the review's probes.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/dlclark/regexp2"
	"software.sslmate.com/src/go-pkcs12"
)

func bigJSONLines(n int) []byte {
	line := `{"ad":true,"pad":"` + strings.Repeat("x", 1000) + `"},` + "\n"
	var b bytes.Buffer
	b.WriteString("[")
	for b.Len() < n {
		b.WriteString(line)
	}
	b.WriteString(`{"end":1}]`)
	return b.Bytes()
}

func gzipBytes(b []byte) []byte {
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return out.Bytes()
}

// heapPeak runs fn while sampling HeapAlloc; returns base and peak.
func heapPeak(fn func()) (base, peak uint64) {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	base = ms.HeapAlloc
	var p atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var ms runtime.MemStats
		for {
			select {
			case <-stop:
				return
			default:
			}
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > p.Load() {
				p.Store(ms.HeapAlloc)
			}
			time.Sleep(time.Millisecond)
		}
	}()
	fn()
	close(stop)
	<-done
	return base, p.Load()
}

// P0-1 / P1-1: a gzip body that decodes past MaxBody passes through untouched (no truncation), for
// both a regex body rule and a requires-body script.
func TestR5DecodedOverCapPassesThrough(t *testing.T) {
	raw := bigJSONLines(3 << 20)
	gz := gzipBytes(raw)
	for _, script := range []bool{false, true} {
		cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(
			`http-response ^https://api\.test\.com/big "ad":true "ad":false`)}
		if script {
			cfg.Rules = items(`s = type=http-response,pattern=^https://api\.test\.com/big,requires-body=1,script-path=s.js`)
		}
		h := newHarness(t, cfg, map[string]string{"s.js": `$done({body: $response.body.replace(/"ad":true/g, '"ad":false')})`})
		h.up.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(gz)
		})
		var resp *http.Response
		var body string
		base, peak := heapPeak(func() { resp, body = h.get("https://api.test.com/big", "Accept-Encoding", "gzip") })
		if resp.Header.Get("Content-Encoding") != "gzip" {
			t.Fatalf("script=%v: Content-Encoding %q, want gzip kept", script, resp.Header.Get("Content-Encoding"))
		}
		zr, err := gzip.NewReader(strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		dec, err := io.ReadAll(zr)
		if err != nil || !bytes.Equal(dec, raw) {
			t.Fatalf("script=%v: body not passed through intact (err %v, %d vs %d B)", script, err, len(dec), len(raw))
		}
		t.Logf("script=%v heap base %d MB peak %d MB", script, base>>20, peak>>20)
		if peak > base+24<<20 {
			t.Errorf("script=%v: heap grew %d MB for a pass-through", script, (peak-base)>>20)
		}
	}
}

// P0-1: a 2 MB identity body rewritten by a plain (RE2) regex stays within a modest heap bound and
// is rewritten.
func TestR5IdentityBodyRewriteHeap(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(
		`http-response ^https://api\.test\.com/big "ad":true "ad":false`)}
	h := newHarness(t, cfg, nil)
	raw := bigJSONLines(MaxBody - 4096)
	h.up.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(raw) })
	var body string
	base, peak := heapPeak(func() { _, body = h.get("https://api.test.com/big") })
	if strings.Contains(body, `"ad":true`) || !strings.HasSuffix(body, `{"end":1}]`) {
		t.Fatalf("body not rewritten / truncated (%d B)", len(body))
	}
	t.Logf("identity %d KB: heap base %d MB peak %d MB (review: 4 → 35 MB)", len(raw)>>10, base>>20, peak>>20)
	if peak > base+20<<20 {
		t.Errorf("heap grew %d MB rewriting a 2 MB body", (peak-base)>>20)
	}
}

// P0-1: lookaround patterns (regexp2 only) are skipped above regexp2BodyLimit, applied below it.
func TestR5Regexp2PathCapped(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(
		`http-response ^https://api\.test\.com/(big|small) "ad":true(?=,) "ad":false`)}
	h := newHarness(t, cfg, nil)
	big := bigJSONLines(regexp2BodyLimit + 1024)
	small := bigJSONLines(4096)
	h.up.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "big") {
			_, _ = w.Write(big)
		} else {
			_, _ = w.Write(small)
		}
	})
	r := h.e.state().rs.Rules[0]
	if r.Body[0].fast != nil {
		t.Fatal("lookahead pattern must stay on regexp2")
	}
	if _, b := h.get("https://api.test.com/big"); b != string(big) {
		t.Fatal("big body must pass through untouched")
	}
	if _, b := h.get("https://api.test.com/small"); strings.Contains(b, `"ad":true`) {
		t.Fatal("small body must be rewritten")
	}
}

// P0-1: the Go regexp path produces the same output as regexp2 (.NET semantics).
func TestR5FastRegexMatchesRegexp2(t *testing.T) {
	body := `{"ad":true,"vip":false,"n":12,"list":[{"id":1,"ad":true},{"id":22}],"s":"a$b"}` + "\n" + `x=1 y=22`
	cases := [][2]string{
		{`"ad":true`, `"ad":false`},
		{`"vip":\w+`, `"vip":true`},
		{`"id":(\d+)`, `"id":$1$1`},
		{`"id":(\d+)`, `"id":${1}0`},
		{`"id":(?<num>\d+)`, `"id":${num}`},
		{`(\w)=(\d+)`, `$2=$1`},
		{`"n":\d+`, `$& and $0 and $$`},
		{`"n":(\d)(\d)`, `$12 $3 $9`},
		{`"s":"[^"]*"`, `"s":"$$x"`},
		{`(?i)"AD"`, `"AD"`},
		{`\[\{[^\]]*\]`, `[]`},
		{`"id":(\d+)`, `${7}`},
		{`"id":(\d+)`, `$1a $01`},
	}
	for _, c := range cases {
		re2, err := regexp2.Compile(c[0], regexp2.None)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := re2.Replace(body, c[1], -1, -1)
		fast, tmpl, ok := fastBodyRe(c[0], c[1])
		if !ok {
			t.Fatalf("%q / %q should use the Go regexp path", c[0], c[1])
		}
		if got := string(fast.ReplaceAll([]byte(body), tmpl)); got != want {
			t.Errorf("%q → %q:\n got  %q\n want %q", c[0], c[1], got, want)
		}
	}
	for _, p := range [][2]string{{`a*`, `x`}, {`"ad"(?=:)`, `x`}, {`true$`, `x`}, {`\btrue\b`, `x`}, {`(a)\1`, `x`}, {`"ad"`, "$`"}} {
		if _, _, ok := fastBodyRe(p[0], p[1]); ok {
			t.Errorf("%q / %q must stay on regexp2", p[0], p[1])
		}
	}
}

// P0-1: the global body budget bounds concurrent holders and hands bytes back on release.
func TestR5BodyBudget(t *testing.T) {
	b := newByteBudget(4 << 20)
	r1 := b.acquire(context.Background(), 3<<20, time.Second)
	if r1 == nil {
		t.Fatal("first acquire failed")
	}
	if r2 := b.acquire(context.Background(), 2<<20, 50*time.Millisecond); r2 != nil {
		t.Fatal("over-budget acquire should time out")
	}
	got := make(chan func(), 1)
	go func() { got <- b.acquire(context.Background(), 2<<20, 2*time.Second) }()
	time.Sleep(50 * time.Millisecond)
	r1()
	r1() // idempotent
	r3 := <-got
	if r3 == nil {
		t.Fatal("waiting acquire should succeed after release")
	}
	r3()
	if b.inUse() != 0 {
		t.Fatalf("budget leak: %d", b.inUse())
	}
	// Engine flows hand their budget back.
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(
		`http-response ^https://api\.test\.com/json "ad":true "ad":false`,
		`http-request ^https://api\.test\.com/echo hello world`)}
	h := newHarness(t, cfg, nil)
	h.get("https://api.test.com/json")
	req, _ := http.NewRequest("POST", "https://api.test.com/echo", strings.NewReader("hello"))
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	time.Sleep(100 * time.Millisecond)
	if n := bodyBudget.inUse(); n != 0 {
		t.Fatalf("engine leaked %d B of body budget", n)
	}
}

// P1-1: $utils.ungzip / Egern gunzip / unbrotli report an error past the cap instead of truncating.
func TestR5InflateNoTruncation(t *testing.T) {
	big := bytes.Repeat([]byte("a"), MaxBody+10)
	if _, err := inflateAny(gzipBytes(big)); !errors.Is(err, errBodyTooBig) {
		t.Fatalf("inflateAny: err %v, want errBodyTooBig", err)
	}
	if _, err := egernCompress("gunzip", gzipBytes(big)); !errors.Is(err, errBodyTooBig) {
		t.Fatalf("egern gunzip: err %v", err)
	}
	out, err := inflateAny(gzipBytes([]byte("ok")))
	if err != nil || string(out) != "ok" {
		t.Fatalf("small inflate: %q %v", out, err)
	}
	if _, err := readAllLimited(strings.NewReader("12345"), 4); !errors.Is(err, errBodyTooBig) {
		t.Fatal("readAllLimited must fail past the limit")
	}
	if b, err := readAllLimited(strings.NewReader("1234"), 4); err != nil || string(b) != "1234" {
		t.Fatal("readAllLimited at the limit must succeed")
	}
}

// P1-2: Reload while connections use e.pinned must not crash.
func TestR5PinnedReloadRace(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(`^https://api\.test\.com/x - reject`)}
	h := newHarness(t, cfg, nil)
	rs := Build(h.home, cfg)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			h.e.Reload(cfg, rs)
		}
	}()
	go func() {
		defer wg.Done()
		st := h.e.state()
		for i := 0; i < 2000; i++ {
			h.e.pinned.Store(fmt.Sprint("h", i), time.Now().Add(time.Minute))
			h.e.shouldIntercept(st, "api.test.com", 443)
			_ = h.e.Status()
		}
	}()
	wg.Wait()
}

// P1-3: a WebSocket upgrade to an h2-capable upstream is forwarded over HTTP/1.1.
func TestR5WebSocketUpgradeH2Upstream(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(`^https://api\.test\.com/never - reject`)}
	h := newHarness(t, cfg, nil)
	h.up.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			w.WriteHeader(400)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(500)
			return
		}
		c, brw, _ := hj.Hijack()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = brw.Flush()
		_ = c.Close()
	})
	req, _ := http.NewRequest("GET", "https://api.test.com/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d, want 101", resp.StatusCode)
	}
	// Normal requests still use h2 upstream.
	h.up.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.Proto) })
	if _, b := h.get("https://api.test.com/plain"); b != "HTTP/2.0" {
		t.Fatalf("plain request upstream proto %q, want HTTP/2.0", b)
	}
}

// P1-6: a client hanging up mid-handshake doesn't pin the host.
func TestR5NoPinOnClientAbort(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(`^https://api\.test\.com/ad - reject-dict`)}
	h := newHarness(t, cfg, nil)
	for i := 0; i < 5; i++ {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", h.e.Port()))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(c, "CONNECT api.test.com:443 HTTP/1.1\r\nHost: api.test.com:443\r\n\r\n")
		br := bufio.NewReader(c)
		_, _ = br.ReadString('\n')
		_, _ = br.ReadString('\n')
		_, _ = c.Write([]byte{0x16, 0x03, 0x01})
		_ = c.Close()
	}
	time.Sleep(300 * time.Millisecond)
	if p := h.e.Status().Pinned; len(p) != 0 {
		t.Fatalf("pinned after client aborts: %v", p)
	}
	if _, b := h.get("https://api.test.com/ad"); b != "{}" {
		t.Fatalf("rule not applied after aborts: %q", b)
	}
}

func TestR5PinClassification(t *testing.T) {
	alert := func(s string) error { return &net.OpError{Op: "remote error", Err: errors.New("tls: " + s)} }
	cases := []struct {
		err  error
		want int
	}{
		{alert("bad certificate"), rejectCert},
		{alert("unknown certificate authority"), rejectCert},
		{alert("unknown certificate"), rejectCert},
		{alert("protocol version not supported"), rejectNo},
		{io.EOF, rejectMaybe},
		{fmt.Errorf("x: %w", syscall.ECONNRESET), rejectMaybe},
		{context.DeadlineExceeded, rejectNo},
		{os.ErrDeadlineExceeded, rejectNo},
		{errors.New("tls: client offered only unsupported versions"), rejectNo},
	}
	for _, c := range cases {
		if got := tlsClientRejection(c.err); got != c.want {
			t.Errorf("%v: got %d want %d", c.err, got, c.want)
		}
	}
	e := &Engine{}
	if !e.shouldPin("a", alert("bad certificate"), true) {
		t.Fatal("cert alert must pin")
	}
	if e.shouldPin("b", io.EOF, false) {
		t.Fatal("EOF before our certificate must not pin")
	}
	pinned := false
	for i := 0; i < pinStrikes; i++ {
		pinned = e.shouldPin("c", io.EOF, true)
	}
	if !pinned {
		t.Fatalf("%d hang-ups right after our certificate should pin", pinStrikes)
	}
	if e.shouldPin("d", io.EOF, true) {
		t.Fatal("one hang-up must not pin")
	}
}

// P2-1: Content-Encoding: deflate (zlib) is decoded and rewritten.
func TestR5DeflateZlib(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(
		`http-response ^https://api\.test\.com/d "vip":false "vip":true`)}
	h := newHarness(t, cfg, nil)
	h.up.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "deflate")
		zw := zlib.NewWriter(w)
		_, _ = io.WriteString(zw, `{"vip":false}`)
		_ = zw.Close()
	})
	resp, body := h.get("https://api.test.com/d", "Accept-Encoding", "deflate")
	if resp.Header.Get("Content-Encoding") != "" || body != `{"vip":true}` {
		t.Fatalf("got %q ce=%q", body, resp.Header.Get("Content-Encoding"))
	}
}

// P2-2: a script with a small max-size neither blocks later body rules nor gets a larger body.
func TestR5LoadBodyNotSticky(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(
		`small = type=http-request,pattern=^https://api\.test\.com/echo,requires-body=1,max-size=4,script-path=s.js`,
		`http-request ^https://api\.test\.com/echo hello world`,
		`small2 = type=http-request,pattern=^https://api\.test\.com/echo,requires-body=1,max-size=4,script-path=s.js`)}
	h := newHarness(t, cfg, map[string]string{"s.js": `$done({body: 'SCRIPT'})`})
	req, _ := http.NewRequest("POST", "https://api.test.com/echo", strings.NewReader("hello hello"))
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var echo struct{ Body string }
	_ = json.Unmarshal(b, &echo)
	if echo.Body != "world world" {
		t.Fatalf("upstream got %q, want %q", echo.Body, "world world")
	}
}

// P2-3: multiple Set-Cookie lines survive a header-returning response script.
func TestR5SetCookie(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(
		`ck = type=http-response,pattern=^https://api\.test\.com/c$,script-path=c.js`,
		`ck2 = type=http-response,pattern=^https://api\.test\.com/c2,script-path=c2.js`)}
	h := newHarness(t, cfg, map[string]string{
		"c.js":  `var h = $response.headers; h['X-Seen'] = '1'; $done({headers: h})`,
		"c2.js": `var h = $response.headers; h['Set-Cookie'] = h['Set-Cookie'] + ', c=3; Path=/'; $done({headers: h})`,
	})
	h.up.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "a=1; Expires=Wed, 21 Oct 2027 07:28:00 GMT; Path=/")
		w.Header().Add("Set-Cookie", "b=2; Path=/")
		_, _ = io.WriteString(w, "ok")
	})
	resp, _ := h.get("https://api.test.com/c")
	if n := len(resp.Cookies()); n != 2 || resp.Header.Get("X-Seen") != "1" {
		t.Fatalf("unchanged headers: %d cookies %q", n, resp.Header.Values("Set-Cookie"))
	}
	resp, _ = h.get("https://api.test.com/c2")
	if n := len(resp.Cookies()); n != 3 {
		t.Fatalf("edited Set-Cookie: %d cookies %q", n, resp.Header.Values("Set-Cookie"))
	}
	got := splitSetCookie("a=1; Expires=Wed, 21 Oct 2027 07:28:00 GMT; Path=/, b=2, c=3;Secure")
	if len(got) != 3 || got[0] != "a=1; Expires=Wed, 21 Oct 2027 07:28:00 GMT; Path=/" || got[2] != "c=3;Secure" {
		t.Fatalf("split: %q", got)
	}
}

// P2-4: scripts see Host, and setting Host (script or header rewrite) changes the outbound Host.
func TestR5HostHeader(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(
		`h = type=http-request,pattern=^https://api\.test\.com/h,script-path=h.js`,
		`hs = type=http-request,pattern=^https://api\.test\.com/echo\?s,script-path=hs.js`,
		`^https://api\.test\.com/echo\?r header-replace Host rewritten.test.com`)}
	h := newHarness(t, cfg, map[string]string{
		"h.js":  `$done({response: {status: 200, body: 'Host=' + $request.headers['Host'] + ' host=' + $request.headers.host}})`,
		"hs.js": `var h = $request.headers; h['Host'] = 'script.test.com'; $done({headers: h})`,
	})
	if _, b := h.get("https://api.test.com/h"); b != "Host=api.test.com host=api.test.com" {
		t.Fatalf("script view: %q", b)
	}
	var echo struct{ Host string }
	_, b := h.get("https://api.test.com/echo?s")
	_ = json.Unmarshal([]byte(b), &echo)
	if echo.Host != "script.test.com" {
		t.Fatalf("script Host: upstream saw %q", echo.Host)
	}
	_, b = h.get("https://api.test.com/echo?r")
	_ = json.Unmarshal([]byte(b), &echo)
	if echo.Host != "rewritten.test.com" {
		t.Fatalf("header-replace Host: upstream saw %q", echo.Host)
	}
}

// P2-6: notification fields are clipped and posts are rate limited per script.
func TestR5NoticeClipAndRate(t *testing.T) {
	l := NewNoticeLog(t.TempDir(), 100)
	l.Add(Notice{Script: "s", Title: strings.Repeat("t", 1000), Body: strings.Repeat("中", 10000)})
	n := l.List()[0]
	if len(n.Title) > noticeShortMax+len("…") || len(n.Body) > noticeLongMax+len("…") {
		t.Fatalf("not clipped: %d / %d", len(n.Title), len(n.Body))
	}
	if !strings.HasPrefix(n.Body, "中") || strings.ContainsRune(n.Body, '\uFFFD') {
		t.Fatal("clip broke UTF-8")
	}
	lim := &noticeLimiter{seen: map[string][]time.Time{}}
	ok := 0
	for i := 0; i < 20; i++ {
		if lim.allow("s") {
			ok++
		}
	}
	if ok != noticeBurst || !lim.allow("other") {
		t.Fatalf("rate limit allowed %d", ok)
	}
}

// P2-8: a p12 whose key doesn't match its certificate is refused.
func TestR5ImportP12KeyMismatch(t *testing.T) {
	home := t.TempDir()
	ca, err := GenerateCA(home)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bad, err := pkcs12.Modern.Encode(other, ca.Cert, nil, "pw")
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	if err := ImportP12(dst, bad, "pw"); err == nil || !strings.Contains(err.Error(), "不匹配") {
		t.Fatalf("mismatched p12: err %v", err)
	}
	good, err := ca.ExportP12("pw")
	if err != nil {
		t.Fatal(err)
	}
	if err := ImportP12(dst, good, "pw"); err != nil {
		t.Fatalf("matching p12: %v", err)
	}
	if _, err := LoadCA(dst); err != nil {
		t.Fatalf("LoadCA after import: %v", err)
	}
}

// P0-1: body work is skipped (body passed through) while the heap is above 70 % of GOMEMLIMIT.
func TestR5HeapHighSkipsBodyWork(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(
		`http-response ^https://api\.test\.com/json "ad":true "ad":false`)}
	h := newHarness(t, cfg, nil)
	if _, b := h.get("https://api.test.com/json"); strings.Contains(b, `"ad":true`) {
		t.Fatal("rewrite should apply with room on the heap")
	}
	old := memGuardLimit
	memGuardLimit = func() int64 { return 1 << 20 } // any real heap is above 70 % of 1 MB
	defer func() { memGuardLimit = old }()
	if _, b := h.get("https://api.test.com/json"); !strings.Contains(b, `"ad":true`) {
		t.Fatal("rewrite must be skipped when the heap is high")
	}
}
