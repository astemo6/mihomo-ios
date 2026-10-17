package libmihomo

// v0.17 请求时间线 (parity #8, Surge Dashboard style). mihomo v1.19.32 does not keep per-phase timings for a
// connection: its tracker only has Start, which is set AFTER the outbound dial (and the proxy handshake)
// succeeded, plus upload / download counters. Without forking the core this file records what can be
// measured honestly, on the controller (same Bearer secret):
//
//   GET /timeline/conns   passive records, renewing a 20 s watch lease. While the lease is held a ticker
//                         samples statistic.DefaultManager every 20 ms (first upload / download byte of each
//                         new tracker, as a lower–upper bound relative to the core's Start) and a log
//                         subscription pairs mihomo's own "[DNS] resolve d T from U" / "[DNS] d --> … from U"
//                         debug events (upstream exchange time) and "cache hit" lines per domain. Nothing runs
//                         when the 请求 page is closed.
//   GET /timeline/probe   one active measurement for a host through the connection's outbound: DNS (only
//                         when the last hop is DIRECT and the host is a name: the core's direct resolver),
//                         connect (until the core's tracker exists, 2 ms ticks), TLS handshake (SNI = host),
//                         first response byte of a HEAD / over HTTP/1.1. Phases that do not apply are omitted
//                         with a reason; nothing is estimated.
//
// What is impossible without a core fork: the inbound arrival time of a real connection (so the real
// connection's DNS → connect split before Start) and its TLS completion (TLS is end-to-end between the
// app and the server; the core only sees encrypted bytes).

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	mhttp "github.com/metacubex/http"

	"github.com/metacubex/chi"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/hub/route"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

func init() { route.Register(timelineRoutes) }

const (
	tlTick      = 20 * time.Millisecond
	tlLease     = 20 * time.Second
	tlMaxRecs   = 600
	tlMaxDNS    = 400
	tlDNSWindow = 10 * time.Second // a lookup counts for a connection that started at most this long after it
)

// tlBound is a time relative to the tracker's Start, known to lie in [Lo, Hi] ms (sampling interval).
type tlBound struct {
	Lo float64 `json:"lo"`
	Hi float64 `json:"hi"`
}

type tlDNS struct {
	Ms       float64 `json:"ms"`                 // upstream exchange time measured between the core's own log events
	Cached   bool    `json:"cached,omitempty"`   // answered from the core's DNS cache
	Upstream string  `json:"upstream,omitempty"` // the upstream that answered first
	BeforeMs float64 `json:"beforeMs"`           // how long before the tracker's Start the answer arrived
	at       time.Time
}

type tlRecord struct {
	ID        string   `json:"id"`
	Host      string   `json:"host"`
	Start     string   `json:"start"`
	Network   string   `json:"network"`
	Pre       bool     `json:"preexisting,omitempty"` // already open when recording started: no timings
	FirstUp   *tlBound `json:"firstUp,omitempty"`
	FirstDown *tlBound `json:"firstDown,omitempty"`
	DNS       *tlDNS   `json:"dns,omitempty"`
	Closed    bool     `json:"closed,omitempty"`
	start     time.Time
	seen      time.Time
	info      *statistic.TrackerInfo
}

type timelineRec struct {
	mu      sync.Mutex
	running bool
	lease   time.Time
	recs    map[string]*tlRecord
	order   []string
	dns     map[string]*tlDNS    // domain → newest answer
	pending map[string]time.Time // domain|upstream → resolve start
	lastTk  time.Time
	stop    chan struct{}
}

var timeline = &timelineRec{recs: map[string]*tlRecord{}, dns: map[string]*tlDNS{}, pending: map[string]time.Time{}}

func normHost(h string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".") }

// renew extends the lease and starts the sampler and the log subscription when they are not running.
func (t *timelineRec) renew() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lease = time.Now().Add(tlLease)
	if t.running {
		return
	}
	t.running = true
	t.stop = make(chan struct{})
	t.lastTk = time.Now()
	// Connections that are already open are listed without timings.
	statistic.DefaultManager.Range(func(tr statistic.Tracker) bool {
		if inf := tr.Info(); inf != nil {
			t.addLocked(inf, true, time.Now())
		}
		return true
	})
	sub := log.Subscribe()
	stop := t.stop
	go func() {
		for {
			select {
			case <-stop:
				log.UnSubscribe(sub)
				return
			case ev, ok := <-sub:
				if !ok {
					return
				}
				if ev.LogLevel == log.DEBUG && strings.HasPrefix(ev.Payload, "[DNS] ") {
					t.dnsEvent(ev.Payload, time.Now())
				}
			}
		}
	}()
	go t.loop(stop)
}

func (t *timelineRec) loop(stop chan struct{}) {
	tk := time.NewTicker(tlTick)
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-tk.C:
			if !t.sample(now) {
				return
			}
		}
	}
}

// sample runs one tick; false when the lease ran out (sampler and subscription stop, records stay).
func (t *timelineRec) sample(now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if now.After(t.lease) {
		t.running = false
		close(t.stop)
		return false
	}
	prev := t.lastTk
	t.lastTk = now
	alive := map[string]bool{}
	statistic.DefaultManager.Range(func(tr statistic.Tracker) bool {
		if inf := tr.Info(); inf != nil {
			alive[inf.UUID.String()] = true
			if t.recs[inf.UUID.String()] == nil {
				t.addLocked(inf, false, now)
			}
		}
		return true
	})
	// Counters are read through the kept TrackerInfo, so a connection that closed between two ticks still
	// gets its first bytes (bounded by the tick that noticed the close).
	for id, r := range t.recs {
		if r.info == nil {
			continue
		}
		if !r.Pre {
			// The data arrived after max(previous tick, Start) and at or before this tick.
			lo := ms(maxTime(prev, r.start).Sub(r.start))
			hi := ms(now.Sub(r.start))
			if r.FirstUp == nil && r.info.UploadTotal.Load() > 0 {
				r.FirstUp = &tlBound{Lo: lo, Hi: hi}
			}
			if r.FirstDown == nil && r.info.DownloadTotal.Load() > 0 {
				r.FirstDown = &tlBound{Lo: lo, Hi: hi}
			}
		}
		if !alive[id] {
			r.Closed = true
			r.info = nil
		}
	}
	return true
}

func (t *timelineRec) addLocked(inf *statistic.TrackerInfo, pre bool, now time.Time) *tlRecord {
	host, network := "", ""
	if inf.Metadata != nil {
		host = inf.Metadata.Host
		if host == "" {
			host = inf.Metadata.SniffHost
		}
		if host == "" && inf.Metadata.DstIP.IsValid() {
			host = inf.Metadata.DstIP.String()
		}
		network = inf.Metadata.NetWork.String()
	}
	r := &tlRecord{ID: inf.UUID.String(), Host: normHost(host), Start: inf.Start.Format(time.RFC3339Nano), Network: network,
		Pre: pre, start: inf.Start, seen: now, info: inf}
	if !pre {
		if d := t.dns[r.Host]; d != nil && !d.at.After(inf.Start) && inf.Start.Sub(d.at) <= tlDNSWindow {
			c := *d
			c.BeforeMs = ms(inf.Start.Sub(d.at))
			r.DNS = &c
		}
	}
	t.recs[r.ID] = r
	t.order = append(t.order, r.ID)
	for len(t.order) > tlMaxRecs {
		delete(t.recs, t.order[0])
		t.order = t.order[1:]
	}
	return r
}

// dnsEvent pairs the core's batchExchange debug lines: "[DNS] resolve <d> <T> from <U>" then
// "[DNS] <d> --> <answer> from <U>"; "[DNS] cache hit <d> --> …" is a 0 ms cached answer.
func (t *timelineRec) dnsEvent(p string, now time.Time) {
	body := strings.TrimPrefix(p, "[DNS] ")
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case strings.HasPrefix(body, "cache hit "):
		rest := strings.TrimPrefix(body, "cache hit ")
		if i := strings.Index(rest, " --> "); i > 0 {
			t.putDNSLocked(normHost(rest[:i]), &tlDNS{Cached: true, at: now})
		}
	case strings.HasPrefix(body, "resolve ") && strings.Contains(body, " from "):
		f := strings.Fields(strings.TrimPrefix(body, "resolve "))
		if len(f) >= 4 && f[2] == "from" {
			if len(t.pending) > tlMaxDNS {
				t.pending = map[string]time.Time{}
			}
			t.pending[normHost(f[0])+"|"+f[3]] = now
		}
	case strings.Contains(body, " --> ") && strings.Contains(body, " from "):
		i := strings.Index(body, " --> ")
		d := normHost(body[:i])
		up := strings.TrimSpace(body[strings.LastIndex(body, " from ")+6:])
		key := d + "|" + up
		if st, ok := t.pending[key]; ok {
			delete(t.pending, key)
			if old := t.dns[d]; old != nil && !old.Cached && now.Sub(old.at) < 50*time.Millisecond {
				return // a slower parallel upstream of the same lookup
			}
			t.putDNSLocked(d, &tlDNS{Ms: ms(now.Sub(st)), Upstream: up, at: now})
		}
	}
}

func (t *timelineRec) putDNSLocked(d string, v *tlDNS) {
	if d == "" {
		return
	}
	if len(t.dns) > tlMaxDNS {
		cut := time.Now().Add(-tlDNSWindow)
		for k, x := range t.dns {
			if x.at.Before(cut) {
				delete(t.dns, k)
			}
		}
	}
	t.dns[d] = v
}

func (t *timelineRec) snapshot() []tlRecord {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]tlRecord, 0, len(t.order))
	for _, id := range t.order {
		if r := t.recs[id]; r != nil {
			out = append(out, *r)
		}
	}
	return out
}

func (t *timelineRec) reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.running {
		close(t.stop)
		t.running = false
	}
	t.recs, t.order = map[string]*tlRecord{}, nil
	t.dns, t.pending = map[string]*tlDNS{}, map[string]time.Time{}
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// ── Active probe ──────────────────────────────────────────────────────────

type tlPhase struct {
	Ms   *float64 `json:"ms,omitempty"`
	Note string   `json:"note,omitempty"` // why the phase is missing or how to read it (Chinese, localized in the app)
	Err  string   `json:"error,omitempty"`
}

type tlProbe struct {
	Host      string  `json:"host"`
	Port      string  `json:"port"`
	Policy    string  `json:"policy,omitempty"`
	Chain     string  `json:"chain,omitempty"`
	Remote    string  `json:"remote,omitempty"`
	DNS       tlPhase `json:"dns"`
	Connect   tlPhase `json:"connect"`
	TLS       tlPhase `json:"tls"`
	FirstByte tlPhase `json:"firstByte"`
	TotalMs   float64 `json:"totalMs"`
	TLSInfo   string  `json:"tlsInfo,omitempty"`
	Status    string  `json:"status,omitempty"`
	OK        bool    `json:"ok"`
	Error     string  `json:"error,omitempty"`
}

func fptr(v float64) *float64 { return &v }

// probePolicy picks the policy to dial with from the connection's chain (outbound first, as mihomo lists
// it): the first name the core knows as a top-level proxy or group. Provider nodes are not addressable
// by name, so their group is used. Empty = let the rules decide.
func probePolicy(chain []string) string {
	known := tunnel.Proxies()
	for _, n := range chain {
		if _, ok := known[n]; ok {
			return n
		}
	}
	return ""
}

func isHTTPPort(port string, tlsOn bool) bool {
	if tlsOn {
		return true // ALPN http/1.1 is offered; a non-HTTP TLS service simply does not answer
	}
	switch port {
	case "80", "8080", "8000", "8888":
		return true
	}
	return false
}

func timelineProbe(ctx context.Context, host, port string, chain []string, tlsMode string, timeout time.Duration) (p tlProbe) {
	p.Host, p.Port = host, port
	if tunnel.Status() == tunnel.Suspend {
		p.Error = "内核未运行"
		return
	}
	policy := probePolicy(chain)
	p.Policy = policy
	direct := len(chain) > 0 && chain[0] == "DIRECT"
	_, ipErr := netip.ParseAddr(host)
	isName := ipErr != nil
	target := host

	switch {
	case !isName:
		p.DNS.Note = "目标是 IP 地址，无需解析"
	case direct:
		dctx, cancel := context.WithTimeout(ctx, timeout)
		t0 := time.Now()
		ip, err := resolver.ResolveIPWithResolver(dctx, host, resolver.DirectHostResolver)
		cancel()
		d := ms(time.Since(t0))
		if err != nil {
			p.DNS = tlPhase{Ms: fptr(d), Err: err.Error()}
			p.Error = "DNS: " + err.Error()
			p.TotalMs = d
			return
		}
		p.DNS = tlPhase{Ms: fptr(d), Note: "内核直连解析器（命中缓存时接近 0）"}
		p.TotalMs += d
		target = ip.String()
	default:
		p.DNS.Note = "经代理时域名由代理服务器解析，本机看不到这段耗时"
	}

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, info, d, err := dialThroughPolicy(cctx, net.JoinHostPort(target, port), policy)
	if err != nil {
		p.Connect = tlPhase{Ms: fptr(ms(d)), Err: err.Error()}
		p.Error = err.Error()
		p.TotalMs += ms(d)
		return
	}
	defer conn.Close()
	p.TotalMs += ms(d)
	note := "到目标的 TCP 连接"
	if !direct {
		note = "到代理服务器的连接与代理握手；部分协议在发送数据时才连目标，这部分计入下一阶段"
	}
	p.Connect = tlPhase{Ms: fptr(ms(d)), Note: note}
	if info != nil {
		p.Chain = chainText(info)
		if info.Metadata != nil {
			p.Remote = info.Metadata.RemoteAddress()
		}
	}

	tlsOn := tlsMode == "1" || (tlsMode != "0" && (port == "443" || port == "8443"))
	var rw net.Conn = conn
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if tlsOn {
		cfg := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}} // #nosec - timing probe only, nothing is sent but HEAD /
		if isName {
			cfg.ServerName = host
		}
		tc := tls.Client(conn, cfg)
		t0 := time.Now()
		err := tc.HandshakeContext(cctx)
		d := ms(time.Since(t0))
		p.TotalMs += d
		if err != nil {
			p.TLS = tlPhase{Ms: fptr(d), Err: err.Error()}
			p.Error = "TLS: " + err.Error()
			return
		}
		st := tc.ConnectionState()
		p.TLS = tlPhase{Ms: fptr(d)}
		p.TLSInfo = tls.VersionName(st.Version)
		if st.NegotiatedProtocol != "" {
			p.TLSInfo += " · " + st.NegotiatedProtocol
		}
		rw = tc
	} else {
		p.TLS.Note = "非 TLS 端口"
	}

	if !isHTTPPort(port, tlsOn) {
		p.FirstByte.Note = "非 HTTP 端口，不发送请求"
		p.OK = true
		return
	}
	hostHdr := host
	if (tlsOn && port != "443") || (!tlsOn && port != "80") {
		hostHdr = net.JoinHostPort(host, port)
	}
	t0 := time.Now()
	if _, err := fmt.Fprintf(rw, "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mihomo-iOS-Timeline\r\nAccept: */*\r\nConnection: close\r\n\r\n", hostHdr); err != nil {
		p.FirstByte = tlPhase{Err: err.Error()}
		p.Error = err.Error()
		return
	}
	br := bufio.NewReaderSize(rw, 256)
	if _, err := br.Peek(1); err != nil {
		d := ms(time.Since(t0))
		p.TotalMs += d
		p.FirstByte = tlPhase{Ms: fptr(d), Err: err.Error()}
		p.Error = err.Error()
		return
	}
	d = time.Since(t0)
	p.TotalMs += ms(d)
	p.FirstByte = tlPhase{Ms: fptr(ms(d)), Note: "HEAD / 到第一个响应字节"}
	if line, err := br.ReadString('\n'); err == nil || len(line) > 0 {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "HTTP/") {
			if f := strings.Fields(line); len(f) >= 2 {
				p.Status = f[1]
			}
		}
	}
	p.OK = true
	return
}

func timelineRoutes(r chi.Router) {
	r.Route("/timeline", func(r chi.Router) {
		// GET /timeline/conns → {"watching":true,"resolutionMs":20,"records":[…]} and renews the lease.
		r.Get("/conns", func(w mhttp.ResponseWriter, req *mhttp.Request) {
			timeline.renew()
			writeToolJSON(w, map[string]any{"watching": true, "resolutionMs": int(tlTick / time.Millisecond), "records": timeline.snapshot()})
		})
		r.Delete("/conns", func(w mhttp.ResponseWriter, req *mhttp.Request) {
			timeline.reset()
			w.WriteHeader(mhttp.StatusNoContent)
		})
		// GET /timeline/probe?host=&port=443&chain=Node,Group&tls=auto|1|0&timeout=8000
		r.Get("/probe", func(w mhttp.ResponseWriter, req *mhttp.Request) {
			q := req.URL.Query()
			host := strings.TrimSpace(q.Get("host"))
			port := q.Get("port")
			if port == "" {
				port = "443"
			}
			var chain []string
			for _, c := range strings.Split(q.Get("chain"), ",") {
				if c = strings.TrimSpace(c); c != "" {
					chain = append(chain, c)
				}
			}
			timeout := time.Duration(clamp(atoi(q.Get("timeout"), 8000), 1000, 20000)) * time.Millisecond
			if host == "" {
				writeToolJSON(w, tlProbe{Error: "缺少主机"})
				return
			}
			ctx, cancel := context.WithTimeout(req.Context(), 3*timeout)
			defer cancel()
			writeToolJSON(w, timelineProbe(ctx, host, port, chain, q.Get("tls"), timeout))
		})
	})
}
