package mitm

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// P0-1 (v0.19.17): with 重写 enabled every plain-HTTP port-80 connection goes through the engine. WeChat's
// mmtls short links (POST /mmtls/<hex>, Upgrade: mmtls, binary body) must reach the server byte for byte,
// and the server's raw response must come back unchanged.
func TestMMTLSPlainHTTPPassesThroughUntouched(t *testing.T) {
	body := make([]byte, 600)
	for i := range body {
		body[i] = byte(i*7 + 3) // binary, includes \r \n and NUL
	}
	req := []byte("POST /mmtls/3a9f01b2 HTTP/1.1\r\n" +
		"Accept: */*\r\n" +
		"Cache-Control: no-cache\r\n" +
		"Connection: close\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"Content-Type: application/octet-stream\r\n" +
		"Upgrade: mmtls\r\n" +
		"User-Agent: MicroMessenger Client\r\n" +
		"Host: szshort.weixin.qq.com\r\n" +
		"x-online-host: szshort.weixin.qq.com\r\n\r\n")
	req = append(req, body...)
	respBody := []byte{0x19, 0xf1, 0x03, 0x00, 0x00, 0x0d, 0x0a, 0xff, 0x00, 0x42}
	resp := append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\naccept-ranges: bytes\r\ncontent-type: application/octet-stream\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(respBody))), respBody...)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 0, len(req))
		tmp := make([]byte, 4096)
		for len(buf) < len(req) {
			n, err := c.Read(tmp)
			buf = append(buf, tmp[:n]...)
			if err != nil {
				break
			}
		}
		got <- buf
		_, _ = c.Write(resp)
	}()

	home := t.TempDir()
	dial := func(ctx context.Context, network, addr, policy string) (net.Conn, error) {
		return net.Dial("tcp", ln.Addr().String())
	}
	e := New(home, dial, nil)
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	// A rewrite rule exists, so port 80 is steered into the engine (mitm.Inject httpPlain).
	cfg := &Config{Enabled: true, Rules: items(`^http://ads\.example\.com/ - reject`)}
	e.Reload(cfg, Build(home, cfg))

	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", e.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "CONNECT szshort.weixin.qq.com:80 HTTP/1.1\r\nHost: szshort.weixin.qq.com:80\r\n\r\n")
	br := bufio.NewReader(c)
	cr, err := http.ReadResponse(br, nil)
	if err != nil || cr.StatusCode != 200 {
		t.Fatalf("connect: %v %v", err, cr)
	}
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	back, _ := io.ReadAll(br)
	select {
	case up := <-got:
		if !bytes.Equal(up, req) {
			t.Fatalf("upstream got a re-encoded request:\n%q\nwant\n%q", up, req)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("upstream never got the request")
	}
	if !bytes.Equal(back, resp) {
		t.Fatalf("client got a re-encoded response:\n%q\nwant\n%q", back, resp)
	}
}

func TestIsOpaqueHTTP(t *testing.T) {
	for head, want := range map[string]bool{
		"POST /mmtls/00aa HTTP/1.1\r\nHost: a\r\n\r\n":                          true,
		"POST http://szshort.weixin.qq.com/mmtls/1 HTTP/1.1\r\nHost: a\r\n\r\n": true,
		"POST /x HTTP/1.1\r\nupgrade: MMTLS\r\n\r\n":                            true,
		"GET /mmtlsx HTTP/1.1\r\nHost: a\r\n\r\n":                               false,
		"GET /chat HTTP/1.1\r\nUpgrade: websocket\r\n\r\n":                      false,
		"GET / HTTP/1.1\r\nHost: plain.com\r\n\r\n":                             false,
	} {
		if got := isOpaqueHTTP([]byte(head)); got != want {
			t.Errorf("%q: %v, want %v", head, got, want)
		}
	}
}
