package libmihomo

// Native MitM stage 3 lane s3-h2: HTTP/2 on the native TLS front (PacketTunnel/NativeMitM/H2/, switch
// nativeMitmH2, default OFF; bridge/mitm/nativeh2.go).
//
// Also the loopback self-test the Swift unit tests drive (UnitTests/NativeMitmH2LoopbackTests.swift): a
// throwaway MitM engine with TLS origins (one HTTP/2, one HTTP/1.1 only) and Go's own HTTP/2 client, so the
// same requests can be sent once through the Go path (Go terminates TLS and serves h2) and once through the
// Swift front (Go hands the connection over, Swift serves h2 and asks the real flow API for every stream),
// and the answers compared. MitmH2SelfTestStart refuses while a real engine runs, so it can never replace the
// tunnel's engine.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
)

// MitmSetNativeH2 tells the engine whether the registered native front serves HTTP/2 (Swift: the nativeMitmH2
// switch, set when the front is installed). Off: "h2" is never offered to the native front and h2-only
// clients stay on the Go path (stage 2 behaviour).
func MitmSetNativeH2(on bool) { mitm.SetNativeH2(on) }

// MitmNativeH2Enabled reports MitmSetNativeH2's value.
func MitmNativeH2Enabled() bool { return mitm.NativeH2() }

// ---- self-test ----

type h2SelfTest struct {
	e        *mitm.Engine
	home     string
	origin2  *httptest.Server
	origin1  *httptest.Server
	ownsEng  bool
	requests atomic.Int64
}

var (
	h2stMu sync.Mutex
	h2st   *h2SelfTest
)

// h2SelfTestRules are used when MitmH2SelfTestStart gets "".
const h2SelfTestRules = `^https://h2\.test/r200 url reject-200
^https://h2\.test/old/(.*) https://h2.test/json?from=$1 302
^https://h2\.test/echo header-add X-Added hello
^https://h2\.test/json\?rb url response-body "ad":true response-body "ad":false
^https://h2\.test/json\?jd response-body-json-del data.ads
^https://h1\.test/echo header-add X-Added h1`

func h2SelfTestHandler(proto string, st *h2SelfTest) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		st.requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ad":true,"data":{"ads":[1,2],"keep":1}}`)
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		st.requests.Add(1)
		b, _ := io.ReadAll(r.Body)
		var hs []string
		for k, v := range r.Header {
			hs = append(hs, strings.ToLower(k)+": "+strings.Join(v, ","))
		}
		sort.Strings(hs)
		sum := sha256.Sum256(b)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"origin": proto, "method": r.Method, "path": r.URL.RequestURI(),
			"host": r.Host, "headers": hs, "bodyLen": len(b), "bodySHA": hex.EncodeToString(sum[:])})
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		st.requests.Add(1)
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		if n < 0 || n > 64<<20 {
			n = 0
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(n))
		if r.Method == http.MethodHead {
			return
		}
		buf := make([]byte, 32<<10)
		for i := range buf {
			buf[i] = byte(i % 251)
		}
		for n > 0 {
			k := min(n, len(buf))
			if _, err := w.Write(buf[:k]); err != nil {
				return
			}
			n -= k
		}
	})
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) { // no Content-Length, flushed pieces
		st.requests.Add(1)
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		w.Header().Set("Content-Type", "text/plain")
		for i := 0; i < n && i < 1000; i++ {
			_, _ = fmt.Fprintf(w, "piece %d\n", i)
			w.(http.Flusher).Flush()
		}
	})
	mux.HandleFunc("/trailers", func(w http.ResponseWriter, r *http.Request) {
		st.requests.Add(1)
		w.Header().Set("Trailer", "Grpc-Status, X-Trailer")
		w.Header().Set("Content-Type", "application/grpc")
		_, _ = io.WriteString(w, "ok")
		w.Header().Set("Grpc-Status", "0")
		w.Header().Set("X-Trailer", "t")
	})
	mux.HandleFunc("/gzip", func(w http.ResponseWriter, r *http.Request) {
		st.requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_, _ = io.WriteString(gz, `{"ad":true,"vip":false}`)
		_ = gz.Close()
	})
	mux.HandleFunc("/nocontent", func(w http.ResponseWriter, r *http.Request) {
		st.requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		st.requests.Add(1)
		ms, _ := strconv.Atoi(r.URL.Query().Get("ms"))
		time.Sleep(time.Duration(min(ms, 5000)) * time.Millisecond)
		_, _ = io.WriteString(w, "slow "+r.URL.Query().Get("ms"))
	})
	return mux
}

// MitmH2SelfTestStart starts the self-test engine and origins (rules: one rewrite line per line, "" = the
// built-in set). JSON: {"proxy":engine CONNECT port,"h2":h2 origin port,"h1":h1-only origin port} or
// {"error":…}. Hosts: h2.test → the h2 origin, h1.test → the h1 origin (both MitM'd).
func MitmH2SelfTestStart(rules string) string {
	h2stMu.Lock()
	defer h2stMu.Unlock()
	if h2st != nil {
		return h2stJSON()
	}
	engMu.Lock()
	running := eng != nil
	engMu.Unlock()
	if running {
		return `{"error":"a MitM engine is running"}`
	}
	if rules == "" {
		rules = h2SelfTestRules
	}
	home, err := os.MkdirTemp("", "tern-h2-selftest")
	if err != nil {
		return errJSON(err)
	}
	st := &h2SelfTest{home: home}
	st.origin2 = httptest.NewUnstartedServer(h2SelfTestHandler("h2", st))
	st.origin2.EnableHTTP2 = true
	st.origin2.StartTLS()
	st.origin1 = httptest.NewUnstartedServer(h2SelfTestHandler("h1", st))
	st.origin1.StartTLS()
	if _, err := mitm.GenerateCA(home); err != nil {
		st.close()
		return errJSON(err)
	}
	a2, a1 := st.origin2.Listener.Addr().String(), st.origin1.Listener.Addr().String()
	dial := func(ctx context.Context, network, addr, policy string) (net.Conn, error) {
		var d net.Dialer
		if strings.HasPrefix(addr, "h1.test:") {
			return d.DialContext(ctx, "tcp", a1)
		}
		return d.DialContext(ctx, "tcp", a2)
	}
	e := mitm.New(home, dial, func(string, string) {})
	if err := e.Start(); err != nil {
		st.close()
		return errJSON(err)
	}
	st.e = e
	_ = os.MkdirAll(mitm.ScriptsDir(home), 0o755)
	var items []mitm.Item
	for i, l := range strings.Split(rules, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			items = append(items, mitm.Item{ID: strconv.Itoa(i), Enabled: true, Line: l})
		}
	}
	noCapture := false
	cfg := &mitm.Config{Enabled: true, MitM: true, SkipCertVerify: true, CaptureBodies: &noCapture,
		Hostnames: []string{"h2.test", "h1.test"}, Rules: items}
	e.Reload(cfg, mitm.Build(home, cfg))
	if _, err := e.StartRelay(); err != nil {
		st.close()
		return errJSON(err)
	}
	engMu.Lock()
	if eng == nil {
		eng = e
		st.ownsEng = true
	}
	engMu.Unlock()
	// Body rules must run whatever the host process's heap looks like (without a probe the gates fall back to
	// the GOMEMLIMIT heuristics, which refuse body work once earlier tests left the heap high — CI run
	// 40077591151). Never set inside the tunnel: the self-test refuses while a real engine runs.
	mitm.SetAvailableMemoryProbe(func() int64 { return 1 << 30 })
	h2st = st
	return h2stJSON()
}

func h2stJSON() string {
	b, _ := json.Marshal(map[string]any{"proxy": h2st.e.Port(), "h2": h2st.origin2.Listener.Addr().(*net.TCPAddr).Port,
		"h1": h2st.origin1.Listener.Addr().(*net.TCPAddr).Port, "relay": h2st.e.RelayPort()})
	return string(b)
}

func errJSON(err error) string {
	b, _ := json.Marshal(map[string]string{"error": err.Error()})
	return string(b)
}

func (st *h2SelfTest) close() {
	if st.e != nil {
		st.e.StopRelay()
		st.e.Stop()
	}
	if st.origin2 != nil {
		st.origin2.Close()
	}
	if st.origin1 != nil {
		st.origin1.Close()
	}
	_ = os.RemoveAll(st.home)
}

// MitmH2SelfTestStop tears the self-test down (and unregisters any native front it used).
func MitmH2SelfTestStop() {
	h2stMu.Lock()
	defer h2stMu.Unlock()
	if h2st == nil {
		return
	}
	mitm.SetNativeTerminator(nil)
	mitm.SetNativeH2(false)
	mitm.SetAvailableMemoryProbe(nil)
	engMu.Lock()
	if h2st.ownsEng && eng == h2st.e {
		eng = nil
	}
	engMu.Unlock()
	h2st.close()
	h2st = nil
}

// MitmH2SelfTestOriginRequests counts requests the origins served (a local answer must not reach them).
func MitmH2SelfTestOriginRequests() int64 {
	h2stMu.Lock()
	defer h2stMu.Unlock()
	if h2st == nil {
		return 0
	}
	return h2st.requests.Load()
}

type h2stRequest struct {
	Method  string      `json:"method"`
	Host    string      `json:"host"`
	Path    string      `json:"path"`
	Headers [][2]string `json:"headers"`
	Body    string      `json:"body"`
	Repeat  int         `json:"repeat"` // body repeated this many times (large uploads)
}

type h2stSpec struct {
	Port       int           `json:"port"`   // 0: through the self-test engine's CONNECT front; else dial this TLS port
	Protos     []string      `json:"protos"` // ALPN offer (default h2, http/1.1)
	Concurrent bool          `json:"concurrent"`
	Requests   []h2stRequest `json:"requests"`
}

type h2stResult struct {
	Status   int         `json:"status"`
	Proto    string      `json:"proto"`
	Headers  [][2]string `json:"headers"`
	Body     string      `json:"body,omitempty"`
	BodyLen  int         `json:"bodyLen"`
	BodySHA  string      `json:"bodySHA"`
	Trailers [][2]string `json:"trailers,omitempty"`
	Error    string      `json:"error,omitempty"`
}

// skipped response headers: they differ run to run.
var h2stVolatile = map[string]bool{"date": true}

func sortedPairs(h http.Header) [][2]string {
	var out [][2]string
	for k, vs := range h {
		lk := strings.ToLower(k)
		if h2stVolatile[lk] {
			continue
		}
		for _, v := range vs {
			out = append(out, [2]string{lk, v})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i][0] != out[j][0] {
			return out[i][0] < out[j][0]
		}
		return out[i][1] < out[j][1]
	})
	return out
}

// MitmH2SelfTestFetch runs requests with Go's HTTP/2-capable client (one connection, reused; concurrent
// streams when asked) and returns {"conns":n,"results":[…]} or {"error":…}. Bodies: text when valid UTF-8
// and ≤ 4 KB, plus length and SHA-256 always. Certificates are not verified (the test CA is not trusted).
func MitmH2SelfTestFetch(specJSON string) string {
	var spec h2stSpec
	if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
		return errJSON(err)
	}
	h2stMu.Lock()
	st := h2st
	h2stMu.Unlock()
	if spec.Port == 0 && st == nil {
		return `{"error":"self-test not started"}`
	}
	protos := spec.Protos
	if len(protos) == 0 {
		protos = []string{"h2", "http/1.1"}
	}
	// http.Protocols, not TLSClientConfig.NextProtos: the transport adds "http/1.1" back to an explicit
	// NextProtos, so an h2-only client (gRPC) can only be expressed this way (CI run 40077591151).
	var pr http.Protocols
	for _, p := range protos {
		switch p {
		case "h2":
			pr.SetHTTP2(true)
		case "http/1.1":
			pr.SetHTTP1(true)
		}
	}
	var conns atomic.Int64
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		Protocols:           &pr,
		DisableCompression:  true,
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 1,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conns.Add(1)
			var d net.Dialer
			if spec.Port != 0 {
				return d.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", spec.Port))
			}
			return d.DialContext(ctx, network, addr)
		},
	}
	if spec.Port == 0 {
		pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", st.e.Port()))
		tr.Proxy = http.ProxyURL(pu)
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	results := make([]h2stResult, len(spec.Requests))
	run := func(i int) {
		q := spec.Requests[i]
		host := q.Host
		if host == "" {
			host = "h2.test"
		}
		var body io.Reader
		if q.Body != "" {
			rep := max(q.Repeat, 1)
			body = bytes.NewReader(bytes.Repeat([]byte(q.Body), rep))
		}
		method := q.Method
		if method == "" {
			method = http.MethodGet
		}
		req, err := http.NewRequest(method, "https://"+host+q.Path, body)
		if err != nil {
			results[i] = h2stResult{Error: err.Error()}
			return
		}
		for _, h := range q.Headers {
			req.Header.Add(h[0], h[1])
		}
		resp, err := c.Do(req)
		if err != nil {
			results[i] = h2stResult{Error: err.Error()}
			return
		}
		b, rerr := io.ReadAll(resp.Body)
		resp.Body.Close()
		sum := sha256.Sum256(b)
		r := h2stResult{Status: resp.StatusCode, Proto: resp.Proto, Headers: sortedPairs(resp.Header), BodyLen: len(b),
			BodySHA: hex.EncodeToString(sum[:]), Trailers: sortedPairs(resp.Trailer)}
		if len(b) <= 4096 && utf8.Valid(b) {
			r.Body = string(b)
		}
		if rerr != nil {
			r.Error = "body: " + rerr.Error()
		}
		results[i] = r
	}
	if spec.Concurrent && len(spec.Requests) > 1 {
		run(0) // open the connection first so the rest share it
		var wg sync.WaitGroup
		for i := 1; i < len(spec.Requests); i++ {
			wg.Add(1)
			go func(i int) { defer wg.Done(); run(i) }(i)
		}
		wg.Wait()
	} else {
		for i := range spec.Requests {
			run(i)
		}
	}
	b, _ := json.Marshal(map[string]any{"conns": conns.Load(), "results": results})
	return string(b)
}
