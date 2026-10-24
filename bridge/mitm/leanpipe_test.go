package mitm

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"
)

// leanPair returns two connected sockets (near is the accepted side).
func leanPair(t testing.TB, ln net.Listener) (near, far net.Conn) {
	t.Helper()
	far, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	near, err = ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	return near, far
}

func leanListener(t testing.TB) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// leanSetup pipes two fresh hops and returns the far ends: x talks through a, y through b.
func leanSetup(t testing.TB, ln net.Listener, kind string) (x, y net.Conn) {
	a, x := leanPair(t, ln)
	var b net.Conn
	switch kind {
	case "mem":
		b, y = net.Pipe()
	default:
		b, y = leanPair(t, ln)
	}
	go pipeLean(a, b)
	return x, y
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		_ = c.Close()
	}
}

func TestLeanPipeBulkBothWays(t *testing.T) {
	ln := leanListener(t)
	for _, kind := range []string{"tcp", "mem"} {
		x, y := leanSetup(t, ln, kind)
		const size = 6 << 20
		up, down := make([]byte, size), make([]byte, size)
		_, _ = rand.Read(up)
		_, _ = rand.Read(down)
		var wg sync.WaitGroup
		var gotUp, gotDown []byte
		var errUp, errDown error
		wg.Add(4)
		go func() { defer wg.Done(); _, _ = x.Write(up); closeWrite(x) }()
		go func() {
			defer wg.Done()
			_, _ = y.Write(down)
			if kind != "mem" { // net.Pipe has no half-close; the pipe ends it after x's EOF (5 s read deadline, as pipe())
				closeWrite(y)
			}
		}()
		go func() { defer wg.Done(); gotUp, errUp = io.ReadAll(y) }()
		go func() { defer wg.Done(); gotDown, errDown = io.ReadAll(x) }()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Fatalf("%s: stuck", kind)
		}
		if errUp != nil && !errors.Is(errUp, io.EOF) {
			t.Fatalf("%s up: %v", kind, errUp)
		}
		if sha256.Sum256(gotUp) != sha256.Sum256(up) || sha256.Sum256(gotDown) != sha256.Sum256(down) {
			t.Fatalf("%s: corrupted (up %d/%d, down %d/%d, %v)", kind, len(gotUp), size, len(gotDown), size, errDown)
		}
		x.Close()
		y.Close()
	}
	leanWaitIdle(t)
}

// Half-close: x shuts its write side, y still gets EOF and can keep talking back; then y closes.
func TestLeanPipeHalfClose(t *testing.T) {
	ln := leanListener(t)
	x, y := leanSetup(t, ln, "tcp")
	defer x.Close()
	defer y.Close()
	_, _ = x.Write([]byte("req"))
	closeWrite(x)
	got, err := io.ReadAll(y)
	if err != nil || string(got) != "req" {
		t.Fatalf("y got %q %v", got, err)
	}
	time.Sleep(50 * time.Millisecond)
	_, _ = y.Write([]byte("late response"))
	closeWrite(y)
	_ = x.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err = io.ReadAll(x)
	if err != nil || string(got) != "late response" {
		t.Fatalf("x got %q %v", got, err)
	}
	leanWaitIdle(t)
}

// A reset / close of one far end tears the whole pipe down.
func TestLeanPipeCloseTearsDown(t *testing.T) {
	ln := leanListener(t)
	for _, kind := range []string{"tcp", "mem"} {
		x, y := leanSetup(t, ln, kind)
		_, _ = x.Write([]byte("a"))
		one := make([]byte, 1)
		if _, err := io.ReadFull(y, one); err != nil {
			t.Fatal(err)
		}
		if tc, ok := x.(*net.TCPConn); ok {
			_ = tc.SetLinger(0) // RST
		}
		x.Close()
		_ = y.SetReadDeadline(time.Now().Add(8 * time.Second))
		if _, err := io.ReadAll(y); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatalf("%s: y never saw the close", kind)
			}
		}
		y.Close()
	}
	leanWaitIdle(t)
}

// Bytes buffered in front of either side (peeked ServerHello, CONNECT reader) go first, in order.
func TestLeanPipeForwardsBuffered(t *testing.T) {
	ln := leanListener(t)
	a, x := leanPair(t, ln)
	b, y := leanPair(t, ln)
	defer x.Close()
	defer y.Close()
	_, _ = x.Write([]byte("client-early|client-more"))
	_, _ = y.Write([]byte("server-hello|server-more"))
	ar := bufio.NewReaderSize(a, 4096)
	br := bufio.NewReaderSize(b, 4096)
	time.Sleep(50 * time.Millisecond)
	if _, err := ar.Peek(13); err != nil {
		t.Fatal(err)
	}
	if _, err := br.Peek(13); err != nil {
		t.Fatal(err)
	}
	_, _ = ar.Discard(0)
	go pipeLean(&metaConn{Conn: a, r: ar, meta: &connMeta{}}, &bufConn{Conn: b, r: br})
	_, _ = x.Write([]byte("|client-late"))
	_, _ = y.Write([]byte("|server-late"))
	want := func(c net.Conn, s string) {
		buf := make([]byte, len(s))
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != s {
			t.Fatalf("got %q %v, want %q", buf, err, s)
		}
	}
	want(y, "client-early|client-more|client-late")
	want(x, "server-hello|server-more|server-late")
}

// Slow reader: the writer's bytes all arrive, in order, with the copy parked on the destination.
func TestLeanPipeBackpressure(t *testing.T) {
	ln := leanListener(t)
	x, y := leanSetup(t, ln, "tcp")
	defer x.Close()
	defer y.Close()
	data := make([]byte, 8<<20)
	_, _ = rand.Read(data)
	go func() { _, _ = x.Write(data); closeWrite(x) }()
	var got bytes.Buffer
	buf := make([]byte, 1000)
	for {
		n, err := y.Read(buf)
		got.Write(buf[:n])
		if err != nil {
			break
		}
		if got.Len() < 1<<20 {
			time.Sleep(time.Millisecond) // slow at first, so the pipe meets a full socket buffer
		}
	}
	if !bytes.Equal(got.Bytes(), data) {
		t.Fatalf("corrupted: %d of %d bytes", got.Len(), len(data))
	}
}

// Many connections at once, each echoing a few messages in both directions (run with -race).
func TestLeanPipeConcurrent(t *testing.T) {
	ln := leanListener(t)
	const conns = 150
	var wg sync.WaitGroup
	errs := make(chan error, conns)
	for i := 0; i < conns; i++ {
		kind := "tcp"
		if i%3 == 0 {
			kind = "mem"
		}
		x, y := leanSetup(t, ln, kind)
		wg.Add(1)
		go func(x, y net.Conn) {
			defer wg.Done()
			defer x.Close()
			defer y.Close()
			_ = x.SetDeadline(time.Now().Add(20 * time.Second))
			_ = y.SetDeadline(time.Now().Add(20 * time.Second))
			for r := 0; r < 5; r++ {
				msg := bytes.Repeat([]byte{byte(r)}, 1+r*7000)
				go func() { _, _ = x.Write(msg) }()
				in := make([]byte, len(msg))
				if _, err := io.ReadFull(y, in); err != nil || !bytes.Equal(in, msg) {
					errs <- err
					return
				}
				go func() { _, _ = y.Write(in) }()
				back := make([]byte, len(msg))
				if _, err := io.ReadFull(x, back); err != nil || !bytes.Equal(back, msg) {
					errs <- err
					return
				}
				time.Sleep(time.Duration(r) * time.Millisecond)
			}
		}(x, y)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("echo failed: %v", err)
	}
	leanWaitIdle(t)
}

// An idle piped socket pair holds no goroutine and no copy buffer.
func TestLeanPipeIdleHoldsNothing(t *testing.T) {
	if !leanPollOK() {
		t.Skip("no poller on this platform")
	}
	ln := leanListener(t)
	x, y := leanSetup(t, ln, "tcp")
	defer x.Close()
	defer y.Close()
	_, _ = x.Write([]byte("hi"))
	in := make([]byte, 2)
	if _, err := io.ReadFull(y, in); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && (leanCopying.Load() != 0 || leanParked.Load() < 2) {
		time.Sleep(10 * time.Millisecond)
	}
	if c, p := leanCopying.Load(), leanParked.Load(); c != 0 || p < 2 {
		t.Fatalf("idle pipe: copying %d parked %d", c, p)
	}
}

func leanWaitIdle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if leanParked.Load() == 0 && leanCopying.Load() == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("pipes left behind: parked %d copying %d", leanParked.Load(), leanCopying.Load())
}

// feat/s2-pipe: with a socket handoff installed the relay answers 200 and gives the socket itself away (no pipe
// of its own); a refused handoff closes the connection; the native front still serves end to end through it.
func TestRelaySocketHandoff(t *testing.T) {
	h := newHarness(t, termCfg(), nil)
	if _, err := h.e.StartRelay(); err != nil {
		t.Fatal(err)
	}
	upAddr := h.up.Listener.Addr().String()
	var mu sync.Mutex
	var seen []string
	h.e.SetRelayHandoff(func(c net.Conn, target, policy string) error {
		mu.Lock()
		seen = append(seen, target+"|"+policy)
		mu.Unlock()
		if target == "refuse.test:443" {
			return errors.New("no")
		}
		if _, ok := c.(*net.TCPConn); !ok {
			t.Errorf("handoff got %T, want the raw socket", c)
		}
		tc, err := net.Dial("tcp", upAddr)
		if err != nil {
			return err
		}
		go pipe(c, tc) // stands in for the core's own relay
		return nil
	})
	defer h.e.SetRelayHandoff(nil)
	addr := net.JoinHostPort("127.0.0.1", itoa(h.e.RelayPort()))

	c, _ := net.Dial("tcp", addr)
	_, _ = io.WriteString(c, "CONNECT refuse.test:443 HTTP/1.1\r\nHost: refuse.test:443\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v %v", resp, err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("refused handoff left the connection open")
	}
	c.Close()

	h2 := newHarness(t, termCfg(), nil) // end to end: native front's upstream through the handing-off relay
	if _, err := h2.e.StartRelay(); err != nil {
		t.Fatal(err)
	}
	up2 := h2.up.Listener.Addr().String()
	h2.e.SetRelayHandoff(func(c net.Conn, target, policy string) error {
		tc, err := net.Dial("tcp", up2)
		if err != nil {
			return err
		}
		go pipe(c, tc)
		return nil
	})
	f := useFakeTerm(t, h2, "")
	_ = f
	dials := h2.e.relay.Dials.Load()
	resp2, body := h2.get("https://api.test.com/json")
	if resp2.Header.Get("X-Native") != "1" || !bytes.Contains([]byte(body), []byte(`"keep":1`)) {
		t.Fatalf("not served through the handoff relay: %v %q", resp2.Header, body)
	}
	if h2.e.relay.Dials.Load() == dials {
		t.Fatal("relay handoff not used")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] != "refuse.test:443|" {
		t.Fatalf("handoff targets %v", seen)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
