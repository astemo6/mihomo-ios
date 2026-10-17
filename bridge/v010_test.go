package libmihomo

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stunTestServer answers Binding requests on 2 IPs × 2 ports (RFC 5780 OTHER-ADDRESS + CHANGE-REQUEST).
type stunTestServer struct {
	conns map[[2]int]*net.UDPConn // [ipIndex][portIndex]
	ips   [2]string
	ports [2]int
	// dropChanged makes the server ignore CHANGE-REQUEST (to emulate a filtering NAT on the client side).
	dropChanged atomic.Bool
}

func newStunTestServer(t *testing.T) *stunTestServer {
	s := &stunTestServer{conns: map[[2]int]*net.UDPConn{}, ips: [2]string{"127.0.0.1", "127.0.0.2"}}
	// Find two free ports usable on both loopback IPs.
	for attempt := 0; attempt < 20 && len(s.conns) < 4; attempt++ {
		for _, c := range s.conns {
			c.Close()
		}
		s.conns = map[[2]int]*net.UDPConn{}
		p1 := 30000 + attempt*7 + int(time.Now().UnixNano()%5000)
		s.ports = [2]int{p1, p1 + 1}
		ok := true
		for i := 0; i < 2 && ok; i++ {
			for j := 0; j < 2 && ok; j++ {
				c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(s.ips[i]), Port: s.ports[j]})
				if err != nil {
					ok = false
					break
				}
				s.conns[[2]int{i, j}] = c
			}
		}
	}
	if len(s.conns) < 4 {
		t.Skip("cannot bind 127.0.0.2")
	}
	for k, c := range s.conns {
		go s.serve(k, c)
	}
	return s
}

func (s *stunTestServer) close() {
	for _, c := range s.conns {
		c.Close()
	}
}

func (s *stunTestServer) serve(k [2]int, c *net.UDPConn) {
	buf := make([]byte, 1500)
	for {
		n, from, err := c.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 20 || binary.BigEndian.Uint16(buf) != stunBindingRequest {
			continue
		}
		var txid [12]byte
		copy(txid[:], buf[8:20])
		changeIP, changePort := false, false
		if n >= 28 && binary.BigEndian.Uint16(buf[20:]) == attrChangeRequest {
			v := binary.BigEndian.Uint32(buf[24:])
			changeIP, changePort = v&4 != 0, v&2 != 0
		}
		if (changeIP || changePort) && s.dropChanged.Load() {
			continue
		}
		out := k
		if changeIP {
			out[0] ^= 1
		}
		if changePort {
			out[1] ^= 1
		}
		resp := s.response(txid, from)
		_, _ = s.conns[out].WriteToUDP(resp, from)
	}
}

func (s *stunTestServer) response(txid [12]byte, from *net.UDPAddr) []byte {
	xor := make([]byte, 8)
	xor[1] = 1
	binary.BigEndian.PutUint16(xor[2:], uint16(from.Port)^uint16(stunMagic>>16))
	ip4 := from.IP.To4()
	var m [4]byte
	binary.BigEndian.PutUint32(m[:], stunMagic)
	for i := 0; i < 4; i++ {
		xor[4+i] = ip4[i] ^ m[i]
	}
	other := make([]byte, 8)
	other[1] = 1
	binary.BigEndian.PutUint16(other[2:], uint16(s.ports[1]))
	copy(other[4:], net.ParseIP(s.ips[1]).To4())
	attr := func(t uint16, v []byte) []byte {
		h := make([]byte, 4)
		binary.BigEndian.PutUint16(h, t)
		binary.BigEndian.PutUint16(h[2:], uint16(len(v)))
		return append(h, v...)
	}
	body := append(attr(attrXorMapped, xor), attr(attrOtherAddress, other)...)
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b, stunBindingSuccess)
	binary.BigEndian.PutUint16(b[2:], uint16(len(body)))
	binary.BigEndian.PutUint32(b[4:], stunMagic)
	copy(b[8:], txid[:])
	return append(b, body...)
}

func TestStunCodec(t *testing.T) {
	var tx [12]byte
	copy(tx[:], "abcdefghijkl")
	req := stunRequest(tx, true, false)
	if len(req) != 28 || binary.BigEndian.Uint32(req[24:]) != 4 {
		t.Fatalf("%x", req)
	}
	s := &stunTestServer{ips: [2]string{"127.0.0.1", "127.0.0.2"}, ports: [2]int{3478, 3479}}
	r, err := parseStunResponse(s.response(tx, &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 61000}))
	if err != nil || r.Mapped != "203.0.113.9:61000" || r.Other != "127.0.0.2:3479" || r.TxID != tx {
		t.Fatalf("%+v %v", r, err)
	}
	for _, c := range []struct{ m, f, want string }{
		{"endpoint-independent", "endpoint-independent", "full-cone"},
		{"endpoint-independent", "address-dependent", "restricted-cone"},
		{"endpoint-independent", "address-port-dependent", "port-restricted-cone"},
		{"address-port-dependent", "endpoint-independent", "symmetric"},
		{"unknown", "unknown", "unknown"},
	} {
		if got := classifyNAT(c.m, c.f); got != c.want {
			t.Fatalf("%v → %s", c, got)
		}
	}
}

func startTestCore(t *testing.T, port int) {
	home := t.TempDir()
	ov := defaultOverrides()
	ov.ControllerPort = port
	ov.Secret = "s"
	ob, _ := json.Marshal(ov)
	_ = os.WriteFile(filepath.Join(home, "overrides.json"), ob, 0o644)
	prof := filepath.Join(home, "p.yaml")
	_ = os.WriteFile(prof, []byte("rules:\n  - MATCH,DIRECT\n"), 0o644)
	if err := Start(home, prof, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(Stop)
}

func controllerGet(t *testing.T, port int, path string) *http.Response {
	req, _ := http.NewRequest("GET", "http://127.0.0.1:"+strconv.Itoa(port)+path, nil)
	req.Header.Set("Authorization", "Bearer s")
	var resp *http.Response
	var err error
	for i := 0; i < 30; i++ {
		if resp, err = http.DefaultClient.Do(req); err == nil {
			return resp
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal(err)
	return nil
}

// NAT test through the real core (DIRECT): an unconnected UDP socket behaves like a full cone; when the
// server never answers from changed addresses the filtering is address+port dependent.
func TestNATThroughCore(t *testing.T) {
	srv := newStunTestServer(t)
	defer srv.close()
	startTestCore(t, 19293)
	server := net.JoinHostPort(srv.ips[0], strconv.Itoa(srv.ports[0]))
	resp := controllerGet(t, 19293, "/tools/stun?timeout=900&server="+server)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var r natResult
	_ = json.Unmarshal(b, &r)
	t.Logf("%s", b)
	if r.Type != "full-cone" || r.Mapping != "endpoint-independent" || !strings.Contains(r.Chain, "DIRECT") || !strings.HasPrefix(r.Mapped, "127.0.0.1:") {
		t.Fatalf("%s", b)
	}
	srv.dropChanged.Store(true)
	r = natTest(context.Background(), []string{server}, "", 600*time.Millisecond)
	if r.Type != "port-restricted-cone" {
		t.Fatalf("%+v", r)
	}
	r = natTest(context.Background(), []string{"127.0.0.1:9"}, "", 300*time.Millisecond)
	if r.Type != "blocked" || r.Error == "" {
		t.Fatalf("%+v", r)
	}
}

func TestSpeedThroughCore(t *testing.T) {
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			n, _ := io.Copy(io.Discard, r.Body)
			_, _ = io.WriteString(w, strconv.FormatInt(n, 10))
			return
		}
		n, _ := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		buf := make([]byte, 64<<10)
		for n > 0 {
			k := int64(len(buf))
			if n < k {
				k = n
			}
			if _, err := w.Write(buf[:k]); err != nil {
				return
			}
			n -= k
		}
	}))
	defer hs.Close()
	startTestCore(t, 19294)
	resp := controllerGet(t, 19294, "/tools/speed?seconds=2&streams=2&down="+hs.URL+"/down%3Fbytes%3D200000000&up="+hs.URL+"/up")
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	var phases []string
	var last speedEvent
	for sc.Scan() {
		var e speedEvent
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(sc.Text())
		}
		if len(phases) == 0 || phases[len(phases)-1] != e.Phase {
			phases = append(phases, e.Phase)
		}
		last = e
	}
	t.Logf("phases %v last %+v", phases, last)
	if last.Phase != "done" || last.DownBps <= 0 || last.UpBps <= 0 || !strings.Contains(last.Chain, "DIRECT") {
		t.Fatalf("%v %+v", phases, last)
	}
	if strings.Join(phases, ",") != "latency,down,up,done" {
		t.Fatalf("%v", phases)
	}
}
