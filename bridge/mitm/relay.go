package mitm

// Upstream relay for the native MitM front (feat/native-mitm stage 2; nativeterm.go, design §4.4).
//
// A loopback HTTP CONNECT proxy whose dials go through e.dial — mihomo's INNER listener, the user's rules and
// policies, never back into __MITM__ (rules exclude IN-TYPE INNER) — exactly like the Go path's upstream. The
// Swift handler points its upstream client at it (URLSession's connectionProxyDictionary HTTPS proxy, or
// NWConnection with ProxyConfiguration(httpCONNECTProxy:) on iOS 17).
//
// Only CONNECT is accepted, only from 127.0.0.1 / ::1. An optional "X-Tern-Policy" request header pins the dial
// to a policy (unused by URLSession, which cannot add CONNECT headers; kept for an NWConnection client).

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Relay is the running relay listener.
type Relay struct {
	e      *Engine
	ln     net.Listener
	closed atomic.Bool
	wg     sync.WaitGroup
	Dials  atomic.Int64
}

// StartRelay opens the relay on 127.0.0.1:0 (one per engine; idempotent).
func (e *Engine) StartRelay() (*Relay, error) {
	e.tmu.Lock()
	defer e.tmu.Unlock()
	if e.relay != nil {
		return e.relay, nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	r := &Relay{e: e, ln: ln}
	e.relay = r
	r.wg.Add(1)
	go r.accept()
	return r, nil
}

// RelayPort is the relay's port (0: not running).
// SkipCertVerify reports the engine's upstream certificate setting (MitM skip-cert-verify, global or from a
// module): the native front's upstream TLS follows it so the two paths accept the same origins.
func (e *Engine) SkipCertVerify() bool {
	e.tmu.Lock()
	defer e.tmu.Unlock()
	return e.tSkip
}

func (e *Engine) RelayPort() int {
	e.tmu.Lock()
	defer e.tmu.Unlock()
	if e.relay == nil {
		return 0
	}
	return e.relay.ln.Addr().(*net.TCPAddr).Port
}

// StopRelay closes the relay (connections already piped finish on their own).
func (e *Engine) StopRelay() {
	e.tmu.Lock()
	r := e.relay
	e.relay = nil
	e.tmu.Unlock()
	if r != nil {
		r.closed.Store(true)
		_ = r.ln.Close()
		r.wg.Wait()
	}
}

func (r *Relay) accept() {
	defer r.wg.Done()
	for {
		c, err := r.ln.Accept()
		if err != nil {
			if r.closed.Load() || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go r.serve(c)
	}
}

func loopbackPeer(c net.Conn) bool {
	a, ok := c.RemoteAddr().(*net.TCPAddr)
	return ok && a.IP.IsLoopback()
}

func (r *Relay) serve(c net.Conn) {
	if !loopbackPeer(c) {
		_ = c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReaderSize(c, 4096)
	req, err := http.ReadRequest(br)
	if err != nil {
		_ = c.Close()
		return
	}
	if req.Method != http.MethodConnect || req.Host == "" {
		_, _ = io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
		_ = c.Close()
		return
	}
	target := req.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}
	policy := req.Header.Get("X-Tern-Policy")
	if h := r.e.relayTo.Load(); h != nil && br.Buffered() == 0 {
		// feat/s2-pipe: hand the socket itself to the core (no pipe, no goroutine of ours). The dial happens
		// inside the core after the 200, so a failed dial closes the connection instead of answering 502 —
		// the native upstream treats both the same (502 to its client).
		_ = c.SetReadDeadline(time.Time{})
		if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			_ = c.Close()
			return
		}
		if err := (*h)(c, target, policy); err != nil {
			_ = c.Close()
			return
		}
		r.Dials.Add(1)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	up, err := r.e.dial(ctx, "tcp", target, policy)
	cancel()
	if err != nil {
		_, _ = fmt.Fprintf(c, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nX-Tern-Error: %s\r\n\r\n", sanitizeHeader(shortErr(err)))
		_ = c.Close()
		return
	}
	r.Dials.Add(1)
	_ = c.SetReadDeadline(time.Time{})
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		_ = c.Close()
		_ = up.Close()
		return
	}
	handoffPipe(&bufConn{Conn: c, r: br}, up) // lean: leanpipe.go
}

// ConnHandoffFunc takes over c (an accepted relay socket, CONNECT already answered) and connects it to target
// through the core with policy ("" = rules), exactly like a dial would — mihomo's tunnel.HandleTCPConn with an
// INNER metadata, minus the in-memory pipe inner.HandleTcp adds. It must not block on the connection's life;
// an error means c was not taken (the relay closes it).
type ConnHandoffFunc func(c net.Conn, target, policy string) error

// SetRelayHandoff installs (nil: removes) the relay's socket handoff. Without one the relay dials through
// e.dial and pipes, as before.
func (e *Engine) SetRelayHandoff(h ConnHandoffFunc) {
	if h == nil {
		e.relayTo.Store(nil)
		return
	}
	e.relayTo.Store(&h)
}

func sanitizeHeader(s string) string {
	b := []byte(s)
	for i, ch := range b {
		if ch < 0x20 || ch == 0x7f {
			b[i] = ' '
		}
	}
	return string(b)
}
