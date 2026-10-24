package mitm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// DialFunc opens an upstream TCP connection. In the extension it goes through the mihomo
// tunnel (listener/inner) so the user's rules and policies still apply.
type DialFunc func(ctx context.Context, network, addr, policy string) (net.Conn, error)

// Logger receives engine log lines (forwarded to mihomo's log).
type Logger func(level, msg string)

// Notifier posts a user notification (from $notification.post / $notify).
type Notifier func(title, subtitle, body, url string)

type state struct {
	cfg     *Config
	rs      *Ruleset
	hosts   *HostMatcher
	ca      *CA
	caErr   string
	hasBody bool // any rule that needs response bodies
}

// Engine is the local HTTP(S) engine. It listens on 127.0.0.1 as an HTTP CONNECT proxy that the
// injected mihomo outbound __MITM__ points to.
type Engine struct {
	home   string
	dial   DialFunc
	logf   Logger
	notify atomic.Pointer[Notifier]

	ln   net.Listener
	port int
	// livePort mirrors port for readers outside Start/Stop (r7 P3-8: /mitm/status read ln/port unlocked
	// while Stop wrote them — a data race under -race). 0 = not running.
	livePort atomic.Int32

	st atomic.Pointer[state]

	tmu       sync.Mutex
	transport *http.Transport
	tSkip     bool
	clients   map[string]*http.Client

	pinned  sync.Map // host -> time.Time (pass-through until)
	strikes sync.Map // host -> *pinStrike (review5 P1-6)

	srv     *http.Server
	tlsLn   atomic.Pointer[chanListener] // feeds intercepted connections to srv (handOff; atomic: handOff may race a restart)
	closing atomic.Bool

	Requests *RequestLog
	Logs     *LogRing
	Store    *Store
	Notices  *NoticeLog
	res      *Resources
	scripts  *ScriptRunner
	tasks    *tasker
	geo      atomic.Pointer[GeoLookup]
	api      atomic.Pointer[APIFunc]

	relay   *Relay                          // feat/native-mitm: upstream relay for the native front (relay.go), under tmu
	relayTo atomic.Pointer[ConnHandoffFunc] // feat/s2-pipe: relay hands its socket to the core (relay.go)

	loop     atomic.Pointer[LoopFunc]
	loopLog  atomic.Int64 // unix seconds of the last loop warning
	LoopHits atomic.Int64
}

// LoopFunc reports whether a CONNECT to target (host:port as mihomo's http outbound sends it) is the
// engine's own upstream coming back: the core already tracks an INNER connection to that target whose
// chain ends at __MITM__ (only a proxy group selecting __MITM__ can produce one).
type LoopFunc func(target string) bool

// SetLoopCheck installs the loop detector (v0.14.1 hotfix defence).
func (e *Engine) SetLoopCheck(f LoopFunc) {
	if f == nil {
		e.loop.Store(nil)
		return
	}
	e.loop.Store(&f)
}

// New creates an engine (not started).
func New(home string, dial DialFunc, logf Logger) *Engine {
	if logf == nil {
		logf = func(level, msg string) { log.Printf("[%s] %s", level, msg) }
	}
	e := &Engine{home: home, dial: dial, logf: logf, clients: map[string]*http.Client{}}
	e.Requests = NewRequestLog(200)
	e.Logs = NewLogRing(500)
	e.Store = NewStore(home)
	e.res = NewResources(home, e)
	e.scripts = NewScriptRunner(e)
	e.Notices = NewNoticeLog(home, 100)
	e.tasks = newTasker(e)
	e.st.Store(&state{cfg: &Config{}, rs: &Ruleset{}, hosts: NewHostMatcher(nil)})
	return e
}

// SetNotifier installs the notification callback.
func (e *Engine) SetNotifier(n Notifier) { e.notify.Store(&n) }

// Port returns the listening port (0 when not started).
func (e *Engine) Port() int { return int(e.livePort.Load()) }

// Start opens the listener on 127.0.0.1:0 (idempotent).
func (e *Engine) Start() error {
	if e.ln != nil {
		return nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	e.ln = ln
	e.port = ln.Addr().(*net.TCPAddr).Port
	e.livePort.Store(int32(e.port))
	tl := &chanListener{ch: make(chan net.Conn, 16), done: make(chan struct{}), addr: ln.Addr(), closed: &e.closing}
	e.tlsLn.Store(tl)
	e.srv = &http.Server{
		Handler:           http.HandlerFunc(e.serveHTTP),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       90 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if tc, ok := c.(*tls.Conn); ok {
				c = tc.NetConn()
			}
			if mc, ok := c.(*metaConn); ok {
				return context.WithValue(ctx, metaKey{}, mc.meta)
			}
			return ctx
		},
	}
	e.srv.SetKeepAlivesEnabled(true)
	srv := e.srv // r7 P3-8: the goroutine must not read fields a later Stop/Start rewrites
	go func() { _ = srv.Serve(tl) }()
	go e.acceptLoop(ln)
	e.logf("info", fmt.Sprintf("[MitM] 引擎已启动 127.0.0.1:%d", e.port))
	return nil
}

// Stop closes the listener and all state.
func (e *Engine) Stop() {
	forgetSnapshot(e) // stage 3a: the native rewrite snapshot of this engine (rewritesnap.go)
	e.StopRelay()
	e.tasks.shutdown()
	_ = e.Store.Flush() // v0.19.9: coalesced $persistentStore writes reach the file before the tunnel goes
	if e.ln == nil {
		return
	}
	e.closing.Store(true)
	_ = e.ln.Close()
	if e.srv != nil {
		_ = e.srv.Close()
	}
	e.tmu.Lock()
	if e.transport != nil {
		e.transport.CloseIdleConnections()
	}
	e.transport = nil
	e.clients = map[string]*http.Client{}
	e.tmu.Unlock()
	e.ln = nil
	e.port = 0
	e.livePort.Store(0)
	e.closing.Store(false)
	e.scripts.Reset()
}

// DropCaches frees what the engine can rebuild on demand: compiled scripts and in-memory script sources
// (v0.19.3, called from FreeMemory when the extension nears its memory limit).
func (e *Engine) DropCaches() {
	if e == nil {
		return
	}
	if e.scripts != nil {
		e.scripts.DropIdle(dropKeepRecent)
	}
	if e.res != nil {
		e.res.mem.Reset()
	}
}

// Reload swaps config + rules (cheap; listener keeps running).
func (e *Engine) Reload(cfg *Config, rs *Ruleset) {
	s := &state{cfg: cfg, rs: rs, hosts: NewHostMatcher(rs.Hostnames)}
	if cfg.MitM {
		ca, err := LoadCA(e.home)
		if err != nil {
			s.caErr = "未生成 CA 证书"
			e.logf("warning", "[MitM] 未找到 CA 证书，HTTPS 解密不可用：请在 更多 → 高级设置 → HTTPS 解密 中生成并安装证书")
		} else {
			s.ca = ca
		}
	}
	for _, r := range rs.Rules {
		if r.Phase == "response" && (r.Kind == KindBody || r.Kind == KindJQ || r.Kind == KindJSON || (r.Kind == KindScript && r.Script.RequiresBody)) {
			s.hasBody = true
		}
	}
	e.st.Store(s)
	// The app's resource manager may have refreshed cached scripts on disk: re-read them.
	if e.res != nil {
		e.res.mem.Reset()
	}
	// review5 P1-2: Clear, never reassign: connection goroutines use the map concurrently and
	// overwriting a Go 1.24+ sync.Map (HashTrieMap) mid-use crashes the extension.
	e.pinned.Clear()
	e.strikes.Clear()
	ResetLaneBreaker() // feat/native-mitm: a reload gives a tripped native body lane another chance
	e.tmu.Lock()
	skip := cfg.SkipCertVerify || (rs.SkipCertVerify != nil && *rs.SkipCertVerify)
	if e.transport != nil && e.tSkip != skip {
		e.transport.CloseIdleConnections()
		e.transport = nil
	}
	e.tSkip = skip
	e.tmu.Unlock()
	for _, err := range rs.Errors {
		e.logf("warning", "[MitM] "+err)
	}
	e.logf("info", fmt.Sprintf("[MitM] 已加载：%d 条重写/脚本规则，%d 个 MitM 主机，HTTPS 解密%s", len(rs.Rules), len(rs.Hostnames), onOff(cfg.MitM && s.ca != nil)))
	go e.res.Prefetch(rs)
	e.tasks.reload(rs)
}

// NetworkChanged runs the event (network-changed) scripts; info becomes $network. Returns how many ran.
func (e *Engine) NetworkChanged(info map[string]any) int { return e.tasks.networkChanged(info) }

func onOff(b bool) string {
	if b {
		return "开启"
	}
	return "关闭"
}

func (e *Engine) state() *state { return e.st.Load() }

// ---- connection handling ----

type connMeta struct {
	host   string // CONNECT target host (or SNI)
	port   int
	tls    bool
	connID int64
}

type metaKey struct{}

type metaConn struct {
	net.Conn
	r    *bufio.Reader
	meta *connMeta
}

func (c *metaConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// chanListener hands intercepted connections to the engine's http.Server. ch is never closed (a send racing a
// close was a data race, and a panic the sender had to recover from); done ends Accept and refuses new ones.
type chanListener struct {
	ch     chan net.Conn
	done   chan struct{}
	addr   net.Addr
	closed *atomic.Bool
	once   sync.Once
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// send queues c for Accept; false (c closed) once the listener is closed.
func (l *chanListener) send(c net.Conn) bool {
	select {
	case <-l.done:
	default:
		select {
		case l.ch <- c:
			select { // Close may have drained ch just before this send landed: drain again so c is not stranded
			case <-l.done:
				l.drain()
			default:
			}
			return true
		case <-l.done:
		}
	}
	_ = c.Close()
	return false
}

func (l *chanListener) drain() {
	for {
		select {
		case c := <-l.ch:
			_ = c.Close()
		default:
			return
		}
	}
}

func (l *chanListener) Close() error {
	l.once.Do(func() {
		close(l.done)
		l.drain() // connections queued but never accepted
	})
	return nil
}
func (l *chanListener) Addr() net.Addr { return l.addr }

func (e *Engine) acceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go e.handleConn(c)
	}
}

var connSeq atomic.Int64

func (e *Engine) handleConn(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReaderSize(c, 8192)
	req, err := http.ReadRequest(br)
	if err != nil {
		_ = c.Close()
		return
	}
	if req.Method != http.MethodConnect {
		_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
		_ = c.Close()
		return
	}
	target := req.Host
	host, ps, err := net.SplitHostPort(target)
	if err != nil {
		host, ps = target, "443"
	}
	port, _ := strconv.Atoi(ps)
	if lf := e.loop.Load(); lf != nil && (*lf)(target) {
		e.LoopHits.Add(1)
		if now := time.Now().Unix(); e.loopLog.Swap(now) < now-30 {
			e.logf("warning", fmt.Sprintf("[MitM] 已拒绝回环连接 %s：有策略组选中了内部出站 %s，请检查策略组", target, ProxyName))
		}
		_, _ = io.WriteString(c, "HTTP/1.1 508 Loop Detected\r\nConnection: close\r\n\r\n")
		_ = c.Close()
		return
	}
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		_ = c.Close()
		return
	}
	first, err := br.Peek(1)
	if err != nil {
		_ = c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	st := e.state()
	meta := &connMeta{host: host, port: port, connID: connSeq.Add(1)}
	mc := &metaConn{Conn: c, r: br, meta: meta}

	if first[0] == 0x16 { // TLS ClientHello
		// mihomo may hand us an IP (hosts / redir-host). Match on the SNI then.
		if net.ParseIP(host) != nil {
			// review6 P2-5: peekSNI blocks until the whole ClientHello record arrived; a client that stalls
			// mid-hello kept this goroutine forever (the read deadline was already cleared).
			_ = c.SetReadDeadline(time.Now().Add(sniPeekTimeout()))
			// r7: a ClientHello record larger than the 8 KB reader (post-quantum key shares, big
			// extensions) was parsed from a cut buffer, so an SNI placed late was missed. Grow the reader
			// to the record (TLS caps a plaintext record at 16 KB); the wrapper keeps the buffered bytes.
			br = growForClientHello(br)
			mc.r = br
			sni := peekSNI(br)
			if sni == "" && br.Buffered() < min(5+tlsRecordLen(br), br.Size()) {
				_ = c.Close() // stalled (or closed) mid-ClientHello
				return
			}
			_ = c.SetReadDeadline(time.Time{})
			if sni != "" {
				host = sni
				meta.host = sni
			}
		}
		if os.Getenv("MITM_DEBUG") != "" {
			log.Printf("CONNECT %s host=%s port=%d intercept=%v", target, host, port, e.shouldIntercept(st, host, port))
		}
		if !e.shouldIntercept(st, host, port) {
			e.passThrough(mc, target)
			return
		}
		meta.tls = true
		e.interceptTLS(st, mc, target)
		return
	}
	if looksLikeHTTP(br) && st.cfg.AnyOn() {
		// P0-1 (v0.19.17): WeChat's mmtls short links are plain-HTTP POSTs to port 80 whose binary body (and
		// the Upgrade: mmtls header, a hop-by-hop header for net/http) must reach the server byte for byte.
		// Through the HTTP handler the request was re-serialised (Upgrade dropped, header case changed), and
		// WeChat kept spinning. No rewrite can do anything useful with them: tunnel them untouched.
		_ = c.SetReadDeadline(time.Now().Add(sniPeekTimeout()))
		opaque := isOpaqueHTTP(peekHTTPHead(br))
		_ = c.SetReadDeadline(time.Time{})
		if !opaque {
			e.handOff(mc)
			return
		}
	}
	e.passThrough(mc, target)
}

// peekHTTPHead returns the buffered request head (up to the blank line, or as much as the reader holds)
// without consuming it.
func peekHTTPHead(br *bufio.Reader) []byte {
	for {
		n := br.Buffered()
		b, _ := br.Peek(n)
		if i := bytes.Index(b, []byte("\r\n\r\n")); i >= 0 {
			return b[:i+4]
		}
		if n >= br.Size() {
			return b
		}
		if _, err := br.Peek(n + 1); err != nil {
			b, _ = br.Peek(br.Buffered())
			return b
		}
	}
}

// isOpaqueHTTP: a plain-HTTP request whose body is an opaque binary protocol that must not be re-encoded
// (WeChat mmtls: POST /mmtls/<hex> with Upgrade: mmtls).
func isOpaqueHTTP(head []byte) bool {
	line, rest, _ := bytes.Cut(head, []byte("\r\n"))
	if f := bytes.Fields(line); len(f) >= 2 {
		target := f[1]
		if i := bytes.Index(target, []byte("://")); i >= 0 { // absolute-form
			if j := bytes.IndexByte(target[i+3:], '/'); j >= 0 {
				target = target[i+3+j:]
			}
		}
		if bytes.HasPrefix(target, []byte("/mmtls/")) {
			return true
		}
	}
	for _, h := range bytes.Split(rest, []byte("\r\n")) {
		k, v, ok := bytes.Cut(h, []byte(":"))
		if ok && strings.EqualFold(strings.TrimSpace(string(k)), "Upgrade") && strings.Contains(strings.ToLower(string(v)), "mmtls") {
			return true
		}
	}
	return false
}

func looksLikeHTTP(br *bufio.Reader) bool {
	b, _ := br.Peek(8)
	s := string(b)
	for _, m := range []string{"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE "} {
		if strings.HasPrefix(s, m) || strings.HasPrefix(m, s) && len(s) < len(m) {
			return true
		}
	}
	return false
}

func (e *Engine) shouldIntercept(st *state, host string, port int) bool {
	if !st.cfg.MitM || st.ca == nil {
		return false
	}
	if !st.hosts.Match(host, port) {
		return false
	}
	if v, ok := e.pinned.Load(host); ok {
		if time.Now().Before(v.(time.Time)) {
			return false
		}
		e.pinned.Delete(host)
	}
	return true
}

func (e *Engine) interceptTLS(st *state, mc *metaConn, target string) {
	// feat/native-mitm stage 2: the native TLS front may take the connection (nativeterm.go); when it
	// declines or fails before its first byte nothing was consumed and Go terminates TLS as before.
	if e.tryNativeTLS(mc, mc.meta.host) {
		return
	}
	nextProtos := []string{"http/1.1"}
	if st.cfg.h2() {
		nextProtos = []string{"h2", "http/1.1"}
	}
	host := mc.meta.host
	var certSent atomic.Bool
	cfg := &tls.Config{
		NextProtos: nextProtos,
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = host
				if net.ParseIP(host) != nil {
					// v0.19.17: no SNI to an IP (HTTPDNS apps put the IP in the URL and verify the
					// certificate against their domain): cover the MitM hostname list's domains too.
					certSent.Store(true)
					return st.ca.LeafWithNames(name, st.hosts.CertNames())
				}
			} else if net.ParseIP(host) != nil {
				// CONNECT carried an IP (no domain known): use SNI for matching and the URL.
				mc.meta.host = name
			}
			certSent.Store(true)
			return st.ca.Leaf(name)
		},
	}
	tc := tls.Server(mc, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	err := tc.HandshakeContext(ctx)
	cancel()
	if err != nil {
		if e.shouldPin(host, err, certSent.Load()) {
			e.pinned.Store(host, time.Now().Add(30*time.Minute))
			e.logf("warning", fmt.Sprintf("[MitM] %s TLS 握手失败（%s）。可能是证书固定（pinning）或 CA 未被信任，30 分钟内对该主机直接放行", host, shortErr(err)))
		} else {
			e.logf("debug", fmt.Sprintf("[MitM] %s TLS 握手中断（%s），不放行", host, shortErr(err)))
		}
		e.Requests.AddFailure(host, shortErr(err))
		_ = tc.Close()
		return
	}
	e.handOff(tc)
}

// pinStrikes / pinStrikeWindow: a client that receives our certificate and then hangs up without a
// TLS alert (some pinning stacks do that) gets the host pinned after this many such failures.
const (
	pinStrikes      = 3
	pinStrikeWindow = 2 * time.Minute
)

type pinStrike struct {
	mu    sync.Mutex
	n     int
	first time.Time
}

// shouldPin decides whether a failed client handshake means "this client rejects our certificate"
// (review5 P1-6). A TLS alert about the certificate pins at once; an EOF / reset after our
// certificate went out counts as a strike; timeouts, and hang-ups before the certificate was sent
// (cancelled requests, network handovers), never pin.
func (e *Engine) shouldPin(host string, err error, certSent bool) bool {
	switch tlsClientRejection(err) {
	case rejectCert:
		return true
	case rejectMaybe:
		if !certSent {
			return false
		}
		v, _ := e.strikes.LoadOrStore(host, &pinStrike{})
		ps := v.(*pinStrike)
		ps.mu.Lock()
		defer ps.mu.Unlock()
		now := time.Now()
		if ps.n == 0 || now.Sub(ps.first) > pinStrikeWindow {
			ps.n, ps.first = 0, now
		}
		ps.n++
		if ps.n >= pinStrikes {
			ps.n = 0
			return true
		}
	}
	return false
}

const (
	rejectNo = iota
	rejectCert
	rejectMaybe
)

// tlsClientRejection classifies a server-side handshake error.
func tlsClientRejection(err error) int {
	if err == nil {
		return rejectNo
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || (errors.As(err, &ne) && ne.Timeout()) {
		return rejectNo
	}
	// crypto/tls reports a received alert as &net.OpError{Op: "remote error", Err: alert}.
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Op == "remote error" {
		msg := oe.Err.Error()
		for _, a := range []string{"bad certificate", "unsupported certificate", "revoked certificate", "expired certificate", "unknown certificate", "unknown certificate authority", "access denied", "error decrypting message", "certificate required"} {
			if strings.Contains(msg, a) {
				return rejectCert
			}
		}
		return rejectNo
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EPIPE) {
		return rejectMaybe
	}
	return rejectNo
}

func (e *Engine) handOff(c net.Conn) {
	if l := e.tlsLn.Load(); l != nil {
		l.send(c)
		return
	}
	_ = c.Close()
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

func (e *Engine) passThrough(mc *metaConn, target string) {
	up, err := e.dial(context.Background(), "tcp", target, "")
	if err != nil {
		_ = mc.Close()
		return
	}
	pipe(mc, up)
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		buf := make([]byte, 16*1024)
		_, _ = io.CopyBuffer(dst, src, buf)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.SetReadDeadline(time.Now().Add(5 * time.Second))
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
	_ = a.Close()
	_ = b.Close()
}

// ---- upstream ----

func (e *Engine) upstream() *http.Transport {
	e.tmu.Lock()
	defer e.tmu.Unlock()
	if e.transport != nil {
		return e.transport
	}
	skip := e.tSkip
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return e.dial(ctx, network, addr, "")
	}
	// review5 P1-3: no custom DialTLSContext. Go's own TLS path (DialContext + TLSClientConfig) sets
	// ServerName from the address and offers only http/1.1 for Upgrade (WebSocket) requests; with a
	// custom DialTLS the h2 connection was used and the http2 transport rejected the Upgrade (502).
	t := &http.Transport{
		DialContext:           dial,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: skip},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
		ReadBufferSize:        16 * 1024,
		WriteBufferSize:       16 * 1024,
		// v0.19.22: Go's HTTP/2 client advertises a 4 MB window per stream and 1 GB per connection, so
		// a response waiting for its script (large-bundle queue, body budget) could have megabytes pushed
		// into transport buffers before anyone read it. 1 MB / 4 MB still keeps video at > 10 MB/s per
		// stream at 100 ms RTT.
		HTTP2: &http.HTTP2Config{MaxReceiveBufferPerStream: 1 << 20, MaxReceiveBufferPerConnection: 4 << 20},
	}
	e.transport = t
	return t
}

// client returns an http.Client for scripts ($httpClient / $task.fetch), optionally pinned to a policy.
func (e *Engine) client(policy string, insecure bool) *http.Client {
	key := policy
	if insecure {
		key += "|insecure"
	}
	e.tmu.Lock()
	defer e.tmu.Unlock()
	if c, ok := e.clients[key]; ok {
		return c
	}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return e.dial(ctx, network, addr, policy)
	}
	t := &http.Transport{
		DialContext:         dial,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     15 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecure},
	}
	c := &http.Client{Transport: t, Timeout: 60 * time.Second}
	e.clients[key] = c
	return c
}

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// maxTLSRecord is the largest TLS plaintext record (2^14) — a ClientHello record never exceeds it.
const maxTLSRecord = 16384

// growForClientHello returns br, or a larger reader over it when the buffered ClientHello record does
// not fit br's buffer (capped at a maximum TLS record).
func growForClientHello(br *bufio.Reader) *bufio.Reader {
	if _, err := br.Peek(5); err != nil {
		return br
	}
	if need := 5 + tlsRecordLen(br); need > br.Size() {
		return bufio.NewReaderSize(br, min(need, maxTLSRecord+5))
	}
	return br
}

// tlsRecordLen is the length announced by the buffered TLS record header (0 when not buffered).
func tlsRecordLen(br *bufio.Reader) int {
	if br.Buffered() < 5 {
		return 0
	}
	h, _ := br.Peek(5)
	return int(h[3])<<8 | int(h[4])
}

// peekSNI extracts the server_name from a buffered TLS ClientHello without consuming it.
func peekSNI(br *bufio.Reader) string {
	hdr, err := br.Peek(5)
	if err != nil || hdr[0] != 0x16 {
		return ""
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	if n+5 > br.Size() {
		n = br.Size() - 5
	}
	b, err := br.Peek(5 + n)
	if err != nil {
		return ""
	}
	return parseSNI(b[5:])
}

func parseSNI(b []byte) string {
	// handshake header
	if len(b) < 4 || b[0] != 0x01 {
		return ""
	}
	b = b[4:]
	if len(b) < 34 {
		return ""
	}
	b = b[34:] // version + random
	skip := func(lenBytes int) bool {
		if len(b) < lenBytes {
			return false
		}
		l := 0
		for i := 0; i < lenBytes; i++ {
			l = l<<8 | int(b[i])
		}
		if len(b) < lenBytes+l {
			return false
		}
		b = b[lenBytes+l:]
		return true
	}
	if !skip(1) || !skip(2) || !skip(1) { // session id, cipher suites, compression
		return ""
	}
	if len(b) < 2 {
		return ""
	}
	b = b[2:]
	for len(b) >= 4 {
		typ := int(b[0])<<8 | int(b[1])
		l := int(b[2])<<8 | int(b[3])
		b = b[4:]
		if len(b) < l {
			return ""
		}
		if typ == 0 {
			d := b[:l]
			if len(d) < 5 || d[2] != 0 {
				return ""
			}
			nl := int(d[3])<<8 | int(d[4])
			if len(d) < 5+nl {
				return ""
			}
			return strings.ToLower(string(d[5 : 5+nl]))
		}
		b = b[l:]
	}
	return ""
}
