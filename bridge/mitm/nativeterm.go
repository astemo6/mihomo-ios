package mitm

// Native TLS termination handoff (feat/native-mitm stage 2, Go side; design: work/native-mitm-design.md §4).
//
// mihomo keeps routing: MitM hosts still reach the engine's CONNECT listener through the __MITM__ outbound, and
// the engine still does everything before the TLS handshake (loop check, SNI peek for IP targets, the MitM host
// list, pinning memory, mmtls). Only then, instead of crypto/tls, a registered NativeTerminator (Swift,
// PacketTunnel/NativeMitM/) may take the connection:
//
//  1. Go peeks the whole ClientHello (not consumed) and reads the client's ALPN offer;
//  2. Listen(host, alpn) returns the loopback port of a native TLS listener presenting a leaf for host (signed
//     by the same CA, LeafIdentity), or 0 to decline;
//  3. Go dials it, writes the peeked ClientHello, and waits for the native side's first bytes (ServerHello);
//  4. bytes arrived: the ClientHello is discarded from the reader and both directions are piped;
//     nothing arrived (refused, reset, timeout): the native connection is dropped and Go terminates TLS itself
//     on the untouched reader — the client never notices (first-byte fallback).
//
// Failures before the first byte count towards a breaker like the body lane's; once tripped every connection
// takes the Go path until the next reload. After the first byte the connection belongs to the native side.
//
// Upstream: the native handler reaches origins through the Relay (relay.go): a loopback CONNECT proxy whose
// dials go through e.dial, i.e. through mihomo as INNER connections with the user's rules — exactly like the Go
// path's own upstream.

import (
	"bufio"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// NativeTerminator is the Swift TLS front as the bridge registers it.
type NativeTerminator interface {
	// Listen returns the loopback port of a TLS listener for host (SNI, or the CONNECT host), given the ALPN
	// protocols the client offered (comma separated, may be empty). 0 declines: Go terminates TLS itself.
	Listen(host string, alpn string) int64
}

type termBox struct{ t NativeTerminator }

var (
	termReg      atomic.Value // termBox
	termOff      atomic.Bool
	termFailMu   sync.Mutex
	termFails    []time.Time
	termHanded   atomic.Int64 // connections the native side took (stats / tests)
	termFellBack atomic.Int64 // connections that fell back to Go after a native failure
)

// termFirstByteWait bounds the wait for the native side's ServerHello.
var termFirstByteWait = 3 * time.Second

// SetNativeTerminator registers (nil: removes) the native TLS front; registering resets its breaker.
func SetNativeTerminator(t NativeTerminator) {
	if t == nil {
		termReg.Store(termBox{})
		return
	}
	resetTermBreaker()
	termReg.Store(termBox{t})
}

func resetTermBreaker() {
	termOff.Store(false)
	termFailMu.Lock()
	termFails = nil
	termFailMu.Unlock()
}

func termNow() NativeTerminator {
	b, _ := termReg.Load().(termBox)
	if b.t == nil || termOff.Load() {
		return nil
	}
	return b.t
}

func (e *Engine) termFailure(what string) {
	termFellBack.Add(1)
	now := time.Now()
	termFailMu.Lock()
	keep := termFails[:0]
	for _, t := range termFails {
		if now.Sub(t) < laneBreakerWindow {
			keep = append(keep, t)
		}
	}
	termFails = append(keep, now)
	trip := len(termFails) >= laneBreakerFails
	if trip {
		termFails = nil
	}
	termFailMu.Unlock()
	if trip && termOff.CompareAndSwap(false, true) {
		e.logf("warning", "[MitM] 原生 TLS 解密多次失败（"+what+"），本次运行改回 Go 处理")
	} else {
		e.logf("debug", "[MitM] 原生 TLS 解密失败，已由 Go 处理："+what)
	}
}

// TermStats: connections handed to the native front / fallen back to Go (diagnostics).
func TermStats() (handed, fellBack int64) { return termHanded.Load(), termFellBack.Load() }

// nativeEligible decides whether the native front may take a connection whose ClientHello offered alpn.
// Stage 2 serves HTTP/1.1 only: a client that offers only h2 (gRPC) stays on the Go path, which speaks h2.
func nativeEligible(alpn []string) bool {
	if len(alpn) == 0 {
		return true // no ALPN: HTTP/1.1
	}
	for _, p := range alpn {
		if p == "http/1.1" {
			return true
		}
	}
	return false
}

// tryNativeTLS hands mc to the native front. true: the native side owns the connection (or it is closed);
// false: nothing was consumed from mc — terminate TLS in Go.
func (e *Engine) tryNativeTLS(mc *metaConn, host string) bool {
	t := termNow()
	if t == nil {
		return false
	}
	br := mc.r
	if _, err := br.Peek(5); err != nil {
		return false
	}
	recLen := 5 + tlsRecordLen(br)
	if recLen > br.Size() {
		return false // a ClientHello split across records larger than the reader: Go path
	}
	hello, err := br.Peek(recLen)
	if err != nil {
		return false
	}
	alpn := parseALPN(hello[5:])
	if !nativeEligible(alpn) {
		return false
	}
	port := t.Listen(host, strings.Join(alpn, ","))
	if port <= 0 || port > 65535 {
		return false
	}
	nc, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.FormatInt(port, 10)), time.Second)
	if err != nil {
		e.termFailure("dial: " + shortErr(err))
		return false
	}
	if _, err := nc.Write(hello); err != nil {
		_ = nc.Close()
		e.termFailure("write: " + shortErr(err))
		return false
	}
	_ = nc.SetReadDeadline(time.Now().Add(termFirstByteWait))
	nbr := bufio.NewReaderSize(nc, 4096)
	if _, err := nbr.Peek(1); err != nil {
		_ = nc.Close()
		e.termFailure("no ServerHello: " + shortErr(err))
		return false
	}
	_ = nc.SetReadDeadline(time.Time{})
	if _, err := br.Discard(recLen); err != nil {
		_ = nc.Close()
		_ = mc.Close()
		return true
	}
	termHanded.Add(1)
	pipe(mc, &bufConn{Conn: nc, r: nbr})
	return true
}

// bufConn is a net.Conn whose reads go through r (bytes already peeked stay readable).
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *bufConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// parseALPN returns the protocols of a ClientHello's ALPN extension (b: the handshake message, after the
// record header). nil when absent or malformed.
func parseALPN(b []byte) []string {
	if len(b) < 4 || b[0] != 0x01 {
		return nil
	}
	b = b[4:]
	if len(b) < 34 {
		return nil
	}
	b = b[34:]
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
	if !skip(1) || !skip(2) || !skip(1) {
		return nil
	}
	if len(b) < 2 {
		return nil
	}
	b = b[2:]
	for len(b) >= 4 {
		typ := int(b[0])<<8 | int(b[1])
		l := int(b[2])<<8 | int(b[3])
		b = b[4:]
		if len(b) < l {
			return nil
		}
		if typ == 16 { // application_layer_protocol_negotiation
			d := b[:l]
			if len(d) < 2 {
				return nil
			}
			d = d[2:]
			var out []string
			for len(d) > 0 {
				n := int(d[0])
				if len(d) < 1+n {
					return nil
				}
				out = append(out, string(d[1:1+n]))
				d = d[1+n:]
			}
			return out
		}
		b = b[l:]
	}
	return nil
}

// LeafIdentityPassword protects the PKCS#12 blobs LeafIdentity returns (they never leave the process; the
// password only satisfies SecPKCS12Import).
const LeafIdentityPassword = "tern"

// LeafIdentity is a PKCS#12 (leaf + CA chain + the shared leaf key) for host, for the native front's
// SecIdentity (SecPKCS12Import, then sec_protocol_options_set_local_identity). For an IP without SNI the leaf
// also covers the MitM hostname list (like the Go path). Legacy encryption: SecPKCS12Import on iOS 16 / 17
// reads it everywhere (the modern AES profile needs iOS 17.4+ in some reports — device check, design §4.2).
func (e *Engine) LeafIdentity(host string) ([]byte, error) {
	st := e.state()
	if st.ca == nil {
		return nil, errNoCA
	}
	var names []string
	if net.ParseIP(host) != nil {
		names = st.hosts.CertNames()
	}
	c, err := st.ca.LeafWithNames(host, names)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return nil, err
	}
	return pkcs12.Legacy.Encode(c.PrivateKey, leaf, []*x509.Certificate{st.ca.Cert}, LeafIdentityPassword)
}

var errNoCA = errors.New("未生成 CA 证书")

// NativeHandshakeFailed is the native front's report of a client handshake that failed after the connection was
// handed over, so pinning memory works as on the Go path (review5 P1-6): kind "cert" (a certificate alert from
// the client) pins the host for 30 minutes at once; "closed" (EOF / reset after our certificate went out) is a
// strike, pinStrikes of them within pinStrikeWindow pin; anything else ("timeout", "cancelled") never pins.
func (e *Engine) NativeHandshakeFailed(host, kind string) bool {
	pin := false
	switch kind {
	case "cert":
		pin = true
	case "closed":
		pin = e.shouldPin(host, io.EOF, true)
	}
	if pin {
		e.pinned.Store(host, time.Now().Add(30*time.Minute))
		e.logf("warning", "[MitM] "+host+" TLS 握手失败（原生）。可能是证书固定（pinning）或 CA 未被信任，30 分钟内对该主机直接放行")
	}
	e.Requests.AddFailure(host, "native handshake: "+kind)
	return pin
}
