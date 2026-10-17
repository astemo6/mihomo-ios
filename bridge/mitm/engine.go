package mitm

import (
	"bufio"
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

	st atomic.Pointer[state]

	tmu       sync.Mutex
	transport *http.Transport
	tSkip     bool
	clients   map[string]*http.Client

	pinned sync.Map // host -> time.Time (pass-through until)

	srv     *http.Server
	tlsCh   chan net.Conn
	closing atomic.Bool

	Requests *RequestLog
	Logs     *LogRing
	Store    *Store
	Notices  *NoticeLog
	res      *Resources
	scripts  *ScriptRunner
	tasks    *tasker
	backend  *backendServer
	geo      atomic.Pointer[GeoLookup]
	api      atomic.Pointer[APIFunc]
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
	e.backend = newBackendServer(e)
	e.st.Store(&state{cfg: &Config{}, rs: &Ruleset{}, hosts: NewHostMatcher(nil)})
	return e
}

// SetNotifier installs the notification callback.
func (e *Engine) SetNotifier(n Notifier) { e.notify.Store(&n) }

// Port returns the listening port (0 when not started).
func (e *Engine) Port() int { return e.port }

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
	e.tlsCh = make(chan net.Conn, 16)
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
	go func() { _ = e.srv.Serve(&chanListener{ch: e.tlsCh, addr: ln.Addr(), closed: &e.closing}) }()
	go e.acceptLoop(ln)
	e.logf("info", fmt.Sprintf("[MitM] 引擎已启动 127.0.0.1:%d", e.port))
	return nil
}

// Stop closes the listener and all state.
func (e *Engine) Stop() {
	e.tasks.shutdown()
	e.backend.stop()
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
	e.closing.Store(false)
	e.scripts.Reset()
}

// Reload swaps config + rules (cheap; listener keeps running).
func (e *Engine) Reload(cfg *Config, rs *Ruleset) {
	s := &state{cfg: cfg, rs: rs, hosts: NewHostMatcher(rs.Hostnames)}
	if cfg.MitM {
		ca, err := LoadCA(e.home)
		if err != nil {
			s.caErr = "未生成 CA 证书"
			e.logf("warning", "[MitM] 未找到 CA 证书，HTTPS 解密不可用：请在 更多 → MitM 中生成并安装证书")
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
	e.pinned = sync.Map{}
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
	e.backend.reload(cfg.HTTPBackend)
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

type chanListener struct {
	ch     chan net.Conn
	addr   net.Addr
	closed *atomic.Bool
	once   sync.Once
}

func (l *chanListener) Accept() (net.Conn, error) {
	c, ok := <-l.ch
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}
func (l *chanListener) Close() error {
	l.once.Do(func() { defer func() { recover() }(); close(l.ch) })
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
			if sni := peekSNI(br); sni != "" {
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
	if looksLikeHTTP(br) && st.cfg.Enabled {
		e.handOff(mc)
		return
	}
	e.passThrough(mc, target)
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
	nextProtos := []string{"http/1.1"}
	if st.cfg.h2() {
		nextProtos = []string{"h2", "http/1.1"}
	}
	host := mc.meta.host
	cfg := &tls.Config{
		NextProtos: nextProtos,
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = host
			} else if net.ParseIP(host) != nil {
				// CONNECT carried an IP (no domain known): use SNI for matching and the URL.
				mc.meta.host = name
			}
			return st.ca.Leaf(name)
		},
	}
	tc := tls.Server(mc, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	err := tc.HandshakeContext(ctx)
	cancel()
	if err != nil {
		e.pinned.Store(host, time.Now().Add(30*time.Minute))
		e.logf("warning", fmt.Sprintf("[MitM] %s TLS 握手失败（%s）。可能是证书固定（pinning）或 CA 未被信任，30 分钟内对该主机直接放行", host, shortErr(err)))
		e.Requests.AddFailure(host, shortErr(err))
		_ = tc.Close()
		return
	}
	e.handOff(tc)
}

func (e *Engine) handOff(c net.Conn) {
	defer func() {
		if recover() != nil {
			_ = c.Close()
		}
	}()
	e.tlsCh <- c
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
	t := &http.Transport{
		DialContext: dial,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			host, _, _ := net.SplitHostPort(addr)
			tc := tls.Client(raw, &tls.Config{ServerName: host, NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: skip})
			if err := tc.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return tc, nil
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
		ReadBufferSize:        16 * 1024,
		WriteBufferSize:       16 * 1024,
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
