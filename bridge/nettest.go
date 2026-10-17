package libmihomo

// v0.10 network tests on the external controller, both running through the core's rules (Type INNER):
//   GET /tools/stun   NAT type (RFC 5780 mapping + filtering) of the UDP path the current policy gives.
//   GET /tools/speed  download / upload bandwidth through the current policy, streamed as NDJSON.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mhttp "github.com/metacubex/http"

	"github.com/metacubex/chi"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/route"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

func init() { route.Register(netTestRoutes) }

// ── STUN (RFC 5389 / 5780) ────────────────────────────────────────────────

const (
	stunMagic          = 0x2112A442
	stunBindingRequest = 0x0001
	stunBindingSuccess = 0x0101
	attrMappedAddress  = 0x0001
	attrChangeRequest  = 0x0003
	attrChangedAddress = 0x0005 // RFC 3489
	attrXorMapped      = 0x0020
	attrOtherAddress   = 0x802C // RFC 5780
	attrXorMappedOld   = 0x8020
)

// stunRequest builds a Binding request with an optional CHANGE-REQUEST (changeIP / changePort).
func stunRequest(txid [12]byte, changeIP, changePort bool) []byte {
	var body []byte
	if changeIP || changePort {
		var v uint32
		if changeIP {
			v |= 0x4
		}
		if changePort {
			v |= 0x2
		}
		body = make([]byte, 8)
		binary.BigEndian.PutUint16(body[0:], attrChangeRequest)
		binary.BigEndian.PutUint16(body[2:], 4)
		binary.BigEndian.PutUint32(body[4:], v)
	}
	b := make([]byte, 20+len(body))
	binary.BigEndian.PutUint16(b[0:], stunBindingRequest)
	binary.BigEndian.PutUint16(b[2:], uint16(len(body)))
	binary.BigEndian.PutUint32(b[4:], stunMagic)
	copy(b[8:20], txid[:])
	copy(b[20:], body)
	return b
}

type stunResponse struct {
	TxID   [12]byte
	Mapped string // ip:port as seen by the server
	Other  string // OTHER-ADDRESS / CHANGED-ADDRESS, "" when the server does not support RFC 5780
}

func parseStunAddr(v []byte, xor bool, txid [12]byte) (string, bool) {
	if len(v) < 8 {
		return "", false
	}
	family := v[1]
	port := binary.BigEndian.Uint16(v[2:4])
	if xor {
		port ^= uint16(stunMagic >> 16)
	}
	var ip net.IP
	switch family {
	case 0x01:
		ip = make(net.IP, 4)
		copy(ip, v[4:8])
		if xor {
			var m [4]byte
			binary.BigEndian.PutUint32(m[:], stunMagic)
			for i := range ip {
				ip[i] ^= m[i]
			}
		}
	case 0x02:
		if len(v) < 20 {
			return "", false
		}
		ip = make(net.IP, 16)
		copy(ip, v[4:20])
		if xor {
			var m [16]byte
			binary.BigEndian.PutUint32(m[:4], stunMagic)
			copy(m[4:], txid[:])
			for i := range ip {
				ip[i] ^= m[i]
			}
		}
	default:
		return "", false
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), true
}

func parseStunResponse(b []byte) (*stunResponse, error) {
	if len(b) < 20 || binary.BigEndian.Uint16(b[0:]) != stunBindingSuccess {
		return nil, errors.New("not a binding success response")
	}
	n := int(binary.BigEndian.Uint16(b[2:]))
	if 20+n > len(b) {
		return nil, errors.New("short STUN message")
	}
	r := &stunResponse{}
	copy(r.TxID[:], b[8:20])
	var mapped, xorMapped string
	for p := 20; p+4 <= 20+n; {
		t := binary.BigEndian.Uint16(b[p:])
		l := int(binary.BigEndian.Uint16(b[p+2:]))
		if p+4+l > 20+n {
			break
		}
		v := b[p+4 : p+4+l]
		switch t {
		case attrXorMapped, attrXorMappedOld:
			if s, ok := parseStunAddr(v, true, r.TxID); ok {
				xorMapped = s
			}
		case attrMappedAddress:
			if s, ok := parseStunAddr(v, false, r.TxID); ok {
				mapped = s
			}
		case attrOtherAddress, attrChangedAddress:
			if s, ok := parseStunAddr(v, false, r.TxID); ok && r.Other == "" {
				r.Other = s
			}
		}
		p += 4 + (l+3)&^3
	}
	r.Mapped = xorMapped
	if r.Mapped == "" {
		r.Mapped = mapped
	}
	if r.Mapped == "" {
		return nil, errors.New("no mapped address")
	}
	return r, nil
}

// stunClient sends UDP datagrams into the core as one INNER "socket" (one NAT table key), so every
// request leaves through the same outbound UDP session, like a real app socket would.
type stunClient struct {
	marker string
	local  *net.UDPAddr
	mu     sync.Mutex
	wait   map[[12]byte]chan *stunResponse
	policy string
	first  atomic.Bool
}

type toolPacket struct {
	c    *stunClient
	data []byte
}

func (p *toolPacket) Data() []byte        { return p.data }
func (p *toolPacket) Drop()               {}
func (p *toolPacket) LocalAddr() net.Addr { return p.c.local }
func (p *toolPacket) WriteBack(b []byte, _ net.Addr) (int, error) {
	r, err := parseStunResponse(b)
	if err != nil {
		return len(b), nil
	}
	p.c.mu.Lock()
	ch := p.c.wait[r.TxID]
	p.c.mu.Unlock()
	if ch != nil {
		select {
		case ch <- r:
		default:
		}
	}
	return len(b), nil
}

func newStunClient(policy string) *stunClient {
	seq := toolSeq.Add(1)
	return &stunClient{
		marker: "mihomo-ios-stun-" + strconv.FormatInt(seq, 10),
		// A unique, never-routed source address keeps this test's NAT entry apart from real traffic.
		local:  &net.UDPAddr{IP: net.IPv4(127, 77, byte(seq>>8), byte(seq)), Port: 40000 + int(seq%20000)},
		wait:   map[[12]byte]chan *stunResponse{},
		policy: policy,
	}
}

func (c *stunClient) send(addr string, payload []byte) error {
	md := &C.Metadata{NetWork: C.UDP, Type: C.INNER, DNSMode: C.DNSNormal, Process: C.MihomoName, InName: c.marker}
	if c.policy != "" {
		md.SpecialProxy = c.policy
	}
	if err := md.SetRemoteAddress(addr); err != nil {
		return err
	}
	ip, _ := netip.AddrFromSlice(c.local.IP.To4())
	md.SrcIP, md.SrcPort = ip, uint16(c.local.Port)
	tunnel.Tunnel.HandleUDPPacket(&toolPacket{c: c, data: payload}, md)
	return nil
}

// query sends one Binding request (retransmitted) and waits for the answer.
func (c *stunClient) query(ctx context.Context, addr string, changeIP, changePort bool, timeout time.Duration) (*stunResponse, error) {
	var txid [12]byte
	_, _ = rand.Read(txid[:])
	ch := make(chan *stunResponse, 1)
	c.mu.Lock()
	c.wait[txid] = ch
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.wait, txid); c.mu.Unlock() }()
	req := stunRequest(txid, changeIP, changePort)
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	resend := time.NewTicker(timeout / 3)
	defer resend.Stop()
	if err := c.send(addr, req); err != nil {
		return nil, err
	}
	for {
		select {
		case r := <-ch:
			return r, nil
		case <-resend.C:
			_ = c.send(addr, req)
		case <-deadline.C:
			return nil, errTimeout
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

var errTimeout = errors.New("timeout")

// trackerInfo finds this client's UDP session in the statistic manager.
func (c *stunClient) trackerInfo() *statistic.TrackerInfo {
	var info *statistic.TrackerInfo
	statistic.DefaultManager.Range(func(t statistic.Tracker) bool {
		if i := t.Info(); i != nil && i.Metadata != nil && i.Metadata.InName == c.marker {
			info = i
			return false
		}
		return true
	})
	return info
}

// close drops the NAT entry and closes the outbound UDP session.
func (c *stunClient) close() {
	tunnel.NatTable().Delete(c.local.String())
	statistic.DefaultManager.Range(func(t statistic.Tracker) bool {
		if i := t.Info(); i != nil && i.Metadata != nil && i.Metadata.InName == c.marker {
			_ = t.Close()
		}
		return true
	})
}

type natResult struct {
	Type      string   `json:"type"`      // full-cone / restricted-cone / port-restricted-cone / symmetric / cone / blocked
	Mapping   string   `json:"mapping"`   // endpoint-independent / address-dependent / address-port-dependent / unknown
	Filtering string   `json:"filtering"` // endpoint-independent / address-dependent / address-port-dependent / unknown
	Server    string   `json:"server,omitempty"`
	Mapped    string   `json:"mapped,omitempty"` // public ip:port of the UDP path
	Chain     string   `json:"chain,omitempty"`
	Rule      string   `json:"rule,omitempty"`
	Payload   string   `json:"rulePayload,omitempty"`
	Steps     []string `json:"steps"`
	Ms        float64  `json:"ms"`
	Error     string   `json:"error,omitempty"`
}

var defaultStunServers = []string{"stun.miwifi.com:3478", "stun.stunprotocol.org:3478", "stun.l.google.com:19302", "stun.cloudflare.com:3478"}

func hostOf(hp string) string { h, _, _ := net.SplitHostPort(hp); return h }
func portOf(hp string) string { _, p, _ := net.SplitHostPort(hp); return p }

// natTest runs RFC 5780 behaviour discovery through the core. servers are tried in order for test I;
// when none answers with OTHER-ADDRESS, mapping is compared across two different servers instead and
// filtering stays unknown.
func natTest(ctx context.Context, servers []string, policy string, timeout time.Duration) (res natResult) {
	start := time.Now()
	res = natResult{Mapping: "unknown", Filtering: "unknown", Steps: []string{}}
	defer func() { res.Ms = float64(time.Since(start).Microseconds()) / 1000 }()
	if tunnel.Status() == tunnel.Suspend {
		res.Type, res.Error = "blocked", "内核未运行"
		return res
	}
	c := newStunClient(policy)
	defer c.close()
	step := func(f string, a ...any) { res.Steps = append(res.Steps, fmt.Sprintf(f, a...)) }

	var first *stunResponse
	var firstServer string
	var plain []struct{ server, mapped string } // answers from servers without OTHER-ADDRESS
	for _, s := range servers {
		r, err := c.query(ctx, s, false, false, timeout)
		if err != nil {
			step("I %s: %v", s, err)
			continue
		}
		step("I %s → %s (other %s)", s, r.Mapped, orDash(r.Other))
		if res.Mapped == "" {
			res.Mapped = r.Mapped
		}
		if r.Other != "" && hostOf(r.Other) != "" && hostOf(r.Other) != "0.0.0.0" {
			first, firstServer = r, s
			break
		}
		plain = append(plain, struct{ server, mapped string }{s, r.Mapped})
		if len(plain) >= 2 {
			break
		}
	}
	if info := c.trackerInfo(); info != nil {
		res.Chain, res.Rule, res.Payload = chainText(info), info.Rule, info.RulePayload
	}
	if first == nil {
		switch len(plain) {
		case 0:
			res.Type, res.Error = "blocked", "所有 STUN 服务器都没有响应（UDP 可能被策略拒绝或节点不支持 UDP）"
		case 1:
			res.Type, res.Server = "unknown", plain[0].server
		default:
			res.Server = plain[0].server
			if plain[0].mapped == plain[1].mapped {
				res.Mapping, res.Type = "endpoint-independent", "cone"
			} else {
				res.Mapping, res.Type = "address-port-dependent", "symmetric"
			}
		}
		return res
	}
	res.Server, res.Mapped = firstServer, first.Mapped
	// The server's primary address as resolved by the first answer is unknown here (it may be a
	// hostname), so test II/III address the alternate IP the server reported.
	altIP, altPort := hostOf(first.Other), portOf(first.Other)
	primaryPort := portOf(firstServer)

	// Mapping: II = alt IP, primary port; III = alt IP, alt port.
	r2, err := c.query(ctx, net.JoinHostPort(altIP, primaryPort), false, false, timeout)
	if err != nil {
		step("II %s:%s: %v", altIP, primaryPort, err)
	} else {
		step("II %s:%s → %s", altIP, primaryPort, r2.Mapped)
		if r2.Mapped == first.Mapped {
			res.Mapping = "endpoint-independent"
		} else {
			r3, err := c.query(ctx, net.JoinHostPort(altIP, altPort), false, false, timeout)
			if err != nil {
				step("III %s:%s: %v", altIP, altPort, err)
				res.Mapping = "address-port-dependent"
			} else {
				step("III %s:%s → %s", altIP, altPort, r3.Mapped)
				if r3.Mapped == r2.Mapped {
					res.Mapping = "address-dependent"
				} else {
					res.Mapping = "address-port-dependent"
				}
			}
		}
	}

	// Filtering: II = change IP + port; III = change port only.
	if _, err := c.query(ctx, firstServer, true, true, timeout); err == nil {
		step("F-II change ip+port → answered")
		res.Filtering = "endpoint-independent"
	} else {
		step("F-II change ip+port: %v", err)
		if _, err := c.query(ctx, firstServer, false, true, timeout); err == nil {
			step("F-III change port → answered")
			res.Filtering = "address-dependent"
		} else {
			step("F-III change port: %v", err)
			res.Filtering = "address-port-dependent"
		}
	}
	res.Type = classifyNAT(res.Mapping, res.Filtering)
	return res
}

func classifyNAT(mapping, filtering string) string {
	switch {
	case mapping == "address-dependent" || mapping == "address-port-dependent":
		return "symmetric"
	case mapping != "endpoint-independent":
		return "unknown"
	case filtering == "endpoint-independent":
		return "full-cone"
	case filtering == "address-dependent":
		return "restricted-cone"
	case filtering == "address-port-dependent":
		return "port-restricted-cone"
	}
	return "cone"
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// ── Bandwidth ─────────────────────────────────────────────────────────────

type speedEvent struct {
	Phase   string  `json:"phase"` // latency / down / up / done / error
	Bps     float64 `json:"bps,omitempty"`
	Bytes   int64   `json:"bytes,omitempty"`
	Seconds float64 `json:"seconds,omitempty"`
	Ms      float64 `json:"ms,omitempty"`
	DownBps float64 `json:"downBps,omitempty"`
	UpBps   float64 `json:"upBps,omitempty"`
	Chain   string  `json:"chain,omitempty"`
	Rule    string  `json:"rule,omitempty"`
	Payload string  `json:"rulePayload,omitempty"`
	Error   string  `json:"error,omitempty"`
}

const (
	defaultDownURL = "https://speed.cloudflare.com/__down?bytes=200000000"
	defaultUpURL   = "https://speed.cloudflare.com/__up"
)

type policyDialer struct {
	policy string
	mu     sync.Mutex
	info   *statistic.TrackerInfo
}

func (d *policyDialer) client(timeout time.Duration) (*http.Client, *http.Transport) {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, inf, _, err := dialThroughPolicy(ctx, addr, d.policy)
			if inf != nil {
				d.mu.Lock()
				d.info = inf
				d.mu.Unlock()
			}
			return c, err
		},
		TLSHandshakeTimeout: timeout,
		MaxIdleConnsPerHost: 8,
		DisableCompression:  true,
	}
	return &http.Client{Transport: tr}, tr
}

func (d *policyDialer) route() (string, string, string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.info == nil {
		return "", "", ""
	}
	return chainText(d.info), d.info.Rule, d.info.RulePayload
}

// measure runs `streams` parallel transfers for at most `dur`, reporting bytes/s through tick every
// interval. work moves data and adds to the shared counter until ctx ends.
func measure(ctx context.Context, streams int, dur, interval time.Duration, work func(ctx context.Context, n *atomic.Int64) error, tick func(bps float64, bytes int64, secs float64)) (float64, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, dur)
	defer cancel()
	var n atomic.Int64
	var wg sync.WaitGroup
	errs := make(chan error, streams)
	start := time.Now()
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				if err := work(ctx, &n); err != nil {
					if ctx.Err() == nil {
						errs <- err
						cancel()
					}
					return
				}
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	t := time.NewTicker(interval)
	defer t.Stop()
	var lastB int64
	lastT := start
	for {
		select {
		case <-done:
			secs := time.Since(start).Seconds()
			total := n.Load()
			var err error
			select {
			case err = <-errs:
			default:
			}
			if total == 0 && err != nil {
				return 0, 0, err
			}
			if secs <= 0 {
				secs = 0.001
			}
			return float64(total) / secs, total, nil
		case now := <-t.C:
			b := n.Load()
			dt := now.Sub(lastT).Seconds()
			if dt > 0 {
				tick(float64(b-lastB)/dt, b, now.Sub(start).Seconds())
			}
			lastB, lastT = b, now
		}
	}
}

type randReader struct{}

func (randReader) Read(p []byte) (int, error) { return len(p), nil } // zeros are fine; TLS encrypts them anyway

type countingReader struct {
	r   io.Reader
	n   *atomic.Int64
	ctx context.Context
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.ctx.Err() != nil {
		return 0, c.ctx.Err()
	}
	k, err := c.r.Read(p)
	c.n.Add(int64(k))
	return k, err
}

func speedTest(ctx context.Context, downURL, upURL, policy string, dur time.Duration, streams int, emit func(speedEvent)) {
	d := &policyDialer{policy: policy}
	cl, tr := d.client(10 * time.Second)
	defer tr.CloseIdleConnections()
	// Latency: time to response headers of a tiny download (the connection is reused afterwards).
	lat := strings.Replace(downURL, "bytes=200000000", "bytes=0", 1)
	t0 := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, lat, nil)
	if err != nil {
		emit(speedEvent{Phase: "error", Error: err.Error()})
		return
	}
	resp, err := cl.Do(req)
	if err != nil {
		emit(speedEvent{Phase: "error", Error: err.Error()})
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	chain, rule, payload := d.route()
	emit(speedEvent{Phase: "latency", Ms: float64(time.Since(t0).Microseconds()) / 1000, Chain: chain, Rule: rule, Payload: payload})

	interval := 400 * time.Millisecond
	downBps, downBytes, err := measure(ctx, streams, dur, interval, func(ctx context.Context, n *atomic.Int64) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, downURL, nil)
		if err != nil {
			return err
		}
		resp, err := cl.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		_, err = io.Copy(io.Discard, &countingReader{r: resp.Body, n: n, ctx: ctx})
		if err == io.EOF {
			err = nil
		}
		return err
	}, func(bps float64, b int64, s float64) { emit(speedEvent{Phase: "down", Bps: bps, Bytes: b, Seconds: s}) })
	if err != nil {
		emit(speedEvent{Phase: "error", Error: "下载：" + err.Error(), Chain: chain, Rule: rule, Payload: payload})
		return
	}
	upBps := 0.0
	if upURL != "" && ctx.Err() == nil {
		const chunk = 25 << 20
		upBps, _, err = measure(ctx, streams, dur, interval, func(ctx context.Context, n *atomic.Int64) error {
			body := &countingReader{r: io.LimitReader(randReader{}, chunk), n: n, ctx: ctx}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, upURL, body)
			if err != nil {
				return err
			}
			req.ContentLength = chunk
			req.Header.Set("Content-Type", "application/octet-stream")
			resp, err := cl.Do(req)
			if err != nil {
				return err
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode >= 400 {
				return fmt.Errorf("HTTP %d", resp.StatusCode)
			}
			return nil
		}, func(bps float64, b int64, s float64) { emit(speedEvent{Phase: "up", Bps: bps, Bytes: b, Seconds: s}) })
		if err != nil {
			emit(speedEvent{Phase: "error", Error: "上传：" + err.Error(), DownBps: downBps, Chain: chain, Rule: rule, Payload: payload})
			return
		}
	}
	emit(speedEvent{Phase: "done", DownBps: downBps, UpBps: upBps, Bytes: downBytes, Chain: chain, Rule: rule, Payload: payload})
}

func netTestRoutes(r chi.Router) {
	{
		// GET /tools/stun?server=host:port,host:port&policy=&timeout=2500
		r.Get("/tools/stun", func(w mhttp.ResponseWriter, req *mhttp.Request) {
			q := req.URL.Query()
			servers := defaultStunServers
			if s := strings.TrimSpace(q.Get("server")); s != "" {
				servers = nil
				for _, x := range strings.Split(s, ",") {
					x = strings.TrimSpace(x)
					if x == "" {
						continue
					}
					if _, _, err := net.SplitHostPort(x); err != nil {
						x = net.JoinHostPort(x, "3478")
					}
					servers = append(servers, x)
				}
			}
			timeout := time.Duration(clamp(atoi(q.Get("timeout"), 2500), 500, 8000)) * time.Millisecond
			ctx, cancel := context.WithTimeout(req.Context(), 60*time.Second)
			defer cancel()
			writeToolJSON(w, natTest(ctx, servers, q.Get("policy"), timeout))
		})
		// GET /tools/speed?down=&up=&seconds=8&streams=4&policy=  → NDJSON speedEvent lines.
		// up=none skips the upload phase.
		r.Get("/tools/speed", func(w mhttp.ResponseWriter, req *mhttp.Request) {
			q := req.URL.Query()
			down := q.Get("down")
			if down == "" {
				down = defaultDownURL
			}
			up := q.Get("up")
			switch up {
			case "":
				up = defaultUpURL
			case "none":
				up = ""
			}
			dur := time.Duration(clamp(atoi(q.Get("seconds"), 8), 2, 30)) * time.Second
			streams := clamp(atoi(q.Get("streams"), 4), 1, 8)
			w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			fl, _ := w.(mhttp.Flusher)
			var mu sync.Mutex
			emit := func(e speedEvent) {
				mu.Lock()
				defer mu.Unlock()
				var buf bytes.Buffer
				_ = json.NewEncoder(&buf).Encode(e)
				_, _ = w.Write(buf.Bytes())
				if fl != nil {
					fl.Flush()
				}
			}
			if tunnel.Status() == tunnel.Suspend {
				emit(speedEvent{Phase: "error", Error: "内核未运行"})
				return
			}
			speedTest(req.Context(), down, up, q.Get("policy"), dur, streams, emit)
		})
	}
}
