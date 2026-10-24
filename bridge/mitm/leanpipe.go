package mitm

// Lean byte pipe for the native MitM front's two loopback hops (feat/s2-pipe): client ↔ native TLS front
// (nativeterm.go tryNativeTLS) and native upstream ↔ origin (relay.go). Both only shovel bytes, and on the old
// pipe() each cost three goroutines and two 16 KiB copy buffers for the whole life of the connection, idle or
// not — 3 goroutines + ~47 KiB per MitM connection, more than the Go path's 1 goroutine + ~16 KiB it was meant
// to save (s2cost_test.go).
//
// pipeLean keeps the same semantics as pipe (EOF or error on one side → half-close the other side, both closed
// when both directions ended, no idle timeout) but holds nothing while a direction waits for bytes:
//
//   - a direction whose source is a socket (TCP: the client conn from mihomo, the native front, the relay's
//     client) waits in the shared readiness poller (leanpoll_*.go: one epoll / kqueue for the process) — no
//     goroutine, no buffer. When bytes arrive a short-lived goroutine copies with a pooled 16 KiB buffer until
//     the socket would block, gives the buffer back and re-arms;
//   - a direction whose source is an in-memory pipe (mihomo's inner.HandleTcp, net.Pipe: the relay's upstream)
//     waits with a zero-length Read — the pipe's writer is matched without anything being consumed — and only
//     then borrows a buffer for the one read it needs;
//   - anything else (or a platform without the poller) runs a goroutine per direction as before, but the
//     caller's goroutine is reused for one of them, buffers come from the pool, and a socket source waits in
//     the runtime poller through RawConn before it borrows a buffer.
//
// Bytes already buffered in a bufio.Reader in front of either side (the CONNECT reader, the peeked ServerHello)
// are forwarded first, so the readers themselves can be dropped.
//
// pipeLean may return before the connection ends (everything waits in the poller); callers must not touch a or
// b afterwards. The Go path (passThrough) keeps pipe() unchanged.

import (
	"bufio"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const leanBufSize = 16 * 1024

var leanBufs = sync.Pool{New: func() any { b := make([]byte, leanBufSize); return &b }}

func getLeanBuf() *[]byte  { return leanBufs.Get().(*[]byte) }
func putLeanBuf(b *[]byte) { leanBufs.Put(b) }

// leanPipeOff routes the native hops through the old pipe() (s2cost_test.go measures before/after with it).
var leanPipeOff atomic.Bool

// handoffPipe is the pipe of the native front's hops.
func handoffPipe(a, b net.Conn) {
	if leanPipeOff.Load() {
		pipe(a, b)
		return
	}
	pipeLean(a, b)
}

// leanStats: directions currently parked in the poller / running a copy (tests, diagnostics).
var (
	leanParked  atomic.Int64
	leanCopying atomic.Int64
)

type leanPipe struct {
	a, b   net.Conn
	fa, fb int // their fds when sockets (-1 otherwise)
	left   atomic.Int32
	once   sync.Once
}

const (
	dirIdle    = 0 // running or not started
	dirArmed   = 1 // waiting in the poller
	dirRunning = 2
)

type leanDir struct {
	p        *leanPipe
	src, dst net.Conn
	rc       syscall.RawConn // src's, when it is a socket
	fd       int             // src's fd (poll mode)
	poll     bool
	state    atomic.Int32
}

// unbuffer splits off a bufio.Reader the engine put in front of c: the raw conn and the bytes it still holds.
func unbuffer(c net.Conn) (net.Conn, []byte) {
	var r *bufio.Reader
	var raw net.Conn
	switch x := c.(type) {
	case *metaConn:
		r, raw = x.r, x.Conn
	case *bufConn:
		r, raw = x.r, x.Conn
	default:
		return c, nil
	}
	if r == nil {
		return raw, nil
	}
	n := r.Buffered()
	if n == 0 {
		return raw, nil
	}
	b, _ := r.Peek(n)
	return raw, append([]byte(nil), b...)
}

func isMemPipe(c net.Conn) bool {
	a := c.RemoteAddr()
	return a != nil && a.Network() == "pipe"
}

func socketOf(c net.Conn) (syscall.RawConn, int, bool) {
	if !leanSockets {
		return nil, -1, false
	}
	sc, ok := c.(syscall.Conn)
	if !ok {
		return nil, -1, false
	}
	switch c.(type) {
	case *net.TCPConn, *net.UnixConn:
	default:
		return nil, -1, false // a wrapper exposing SyscallConn may still buffer (tls.Conn does not, but be strict)
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return nil, -1, false
	}
	fd := -1
	if rc.Control(func(f uintptr) { fd = int(f) }) != nil || fd < 0 {
		return nil, -1, false
	}
	return rc, fd, true
}

// pipeLean copies a ↔ b until both directions ended, then closes both (see the file comment).
func pipeLean(a, b net.Conn) {
	ra, pendA := unbuffer(a) // pendA: read from a's side already, goes to b
	rb, pendB := unbuffer(b)
	if len(pendB) > 0 {
		if _, err := ra.Write(pendB); err != nil {
			_ = ra.Close()
			_ = rb.Close()
			return
		}
	}
	if len(pendA) > 0 {
		if _, err := rb.Write(pendA); err != nil {
			_ = ra.Close()
			_ = rb.Close()
			return
		}
	}
	p := &leanPipe{a: ra, b: rb}
	p.left.Store(2)
	ab := p.newDir(ra, rb)
	ba := p.newDir(rb, ra)
	p.fa, p.fb = ab.fd, ba.fd
	var inline *leanDir
	for _, d := range []*leanDir{ab, ba} {
		if d.poll && d.arm() {
			continue
		}
		d.poll = false
		if inline == nil {
			inline = d
		} else {
			go d.block()
		}
	}
	if inline != nil {
		inline.block()
	}
}

func (p *leanPipe) newDir(src, dst net.Conn) *leanDir {
	d := &leanDir{p: p, src: src, dst: dst, fd: -1}
	if rc, fd, ok := socketOf(src); ok {
		d.rc, d.fd = rc, fd
		d.poll = leanPollOK()
	}
	return d
}

// arm parks d in the poller (false: the poller is unavailable or refused the fd).
func (d *leanDir) arm() bool {
	d.state.Store(dirArmed)
	leanParked.Add(1)
	if err := leanPollArm(d); err != nil {
		leanParked.Add(-1)
		d.state.Store(dirIdle)
		return false
	}
	return true
}

// fire is the poller's callback: src is readable (or closed). Runs at most once per arm.
func (d *leanDir) fire() {
	if !d.state.CompareAndSwap(dirArmed, dirRunning) {
		return // spurious (fd number reused after a close, or already firing)
	}
	leanParked.Add(-1)
	go d.drain()
}

// drain copies until src would block (then re-arms) or ends.
func (d *leanDir) drain() {
	leanCopying.Add(1)
	defer leanCopying.Add(-1)
	var buf *[]byte
	defer func() {
		if buf != nil {
			putLeanBuf(buf)
		}
	}()
	for {
		if buf == nil {
			buf = getLeanBuf()
		}
		var n int
		var rerr error
		if err := d.rc.Read(func(fd uintptr) bool {
			n, rerr = leanSysRead(fd, *buf)
			return true
		}); err != nil {
			rerr = err
		}
		if n < 0 {
			n = 0
		}
		if n > 0 {
			if _, err := d.dst.Write((*buf)[:n]); err != nil {
				d.end()
				return
			}
			continue
		}
		switch rerr {
		case syscall.EINTR:
			continue
		case syscall.EAGAIN:
			putLeanBuf(buf)
			buf = nil
			d.state.Store(dirIdle)
			if !d.arm() {
				d.poll = false
				d.block()
			}
			return
		}
		d.end() // EOF (n == 0, no error) or a read error
		return
	}
}

// block runs the direction on the calling goroutine until it ends.
func (d *leanDir) block() {
	leanCopying.Add(1)
	defer leanCopying.Add(-1)
	switch {
	case d.rc != nil:
		d.blockSocket()
	case isMemPipe(d.src):
		d.blockMemPipe()
	default:
		buf := getLeanBuf()
		_, _ = io.CopyBuffer(writerOnly{d.dst}, readerOnly{d.src}, *buf)
		putLeanBuf(buf)
	}
	d.end()
}

// blockSocket: the runtime poller waits for readability; a buffer is borrowed only for the read itself.
func (d *leanDir) blockSocket() {
	for {
		var buf *[]byte
		var n int
		var rerr error
		err := d.rc.Read(func(fd uintptr) bool {
			if buf == nil {
				buf = getLeanBuf()
			}
			n, rerr = leanSysRead(fd, *buf)
			if rerr == syscall.EAGAIN {
				putLeanBuf(buf)
				buf = nil
				return false // wait for readability, holding nothing
			}
			return true
		})
		if buf == nil {
			return // closed while waiting
		}
		if err != nil {
			rerr = err
		}
		if n > 0 {
			_, werr := d.dst.Write((*buf)[:n])
			putLeanBuf(buf)
			if werr != nil {
				return
			}
			continue
		}
		putLeanBuf(buf)
		if rerr == syscall.EINTR {
			continue
		}
		return // EOF or error
	}
}

// blockMemPipe: a zero-length Read on an in-memory pipe returns once a writer is waiting, consuming nothing.
func (d *leanDir) blockMemPipe() {
	var zero [0]byte
	for {
		if _, err := d.src.Read(zero[:]); err != nil {
			return
		}
		buf := getLeanBuf()
		n, err := d.src.Read(*buf)
		if n > 0 {
			if _, werr := d.dst.Write((*buf)[:n]); werr != nil {
				putLeanBuf(buf)
				return
			}
		}
		putLeanBuf(buf)
		if err != nil {
			return
		}
	}
}

// end: this direction is over — half-close dst like pipe(), and close both once both directions ended.
func (d *leanDir) end() {
	if cw, ok := d.dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		_ = d.dst.SetReadDeadline(time.Now().Add(5 * time.Second))
	}
	if d.p.left.Add(-1) == 0 {
		d.p.closeAll()
	}
}

func (p *leanPipe) closeAll() {
	p.once.Do(func() {
		for _, fd := range []int{p.fa, p.fb} {
			if fd >= 0 {
				leanPollForget(fd)
			}
		}
		_ = p.a.Close()
		_ = p.b.Close()
	})
}

// readerOnly / writerOnly hide ReaderFrom / WriterTo so io.CopyBuffer uses the pooled buffer.
type readerOnly struct{ io.Reader }
type writerOnly struct{ io.Writer }
