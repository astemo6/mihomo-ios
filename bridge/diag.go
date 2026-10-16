package libmihomo

// Runtime helpers for the extension and the app: traffic totals, memory shedding, saved selections,
// manual-node merge, offline latency tests and the /tools routes (TCP / HTTP test through the current
// policy) mounted on the external controller.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	mhttp "github.com/metacubex/http"

	"github.com/metacubex/chi"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/component/mmdb"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/route"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"go.yaml.in/yaml/v3"
)

func init() { route.Register(toolsRoutes) }

// TrafficTotals returns "up,down" bytes since the core started (for the daily history).
func TrafficTotals() string {
	up, down := statistic.DefaultManager.Total()
	return strconv.FormatInt(up, 10) + "," + strconv.FormatInt(down, 10)
}

// ShedConnections closes every tracked connection (memory guard, critical pressure). Returns the count.
func ShedConnections() int {
	n := 0
	statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
		_ = c.Close()
		n++
		return true
	})
	if n > 0 {
		log.Warnln("[Memory] closed %d connections under memory pressure", n)
	}
	return n
}

// ReloadGeo makes the core reopen geoip.metadb / ASN.mmdb on next use after the app replaced them.
func ReloadGeo() {
	mmdb.ReloadIP()
	mmdb.ReloadASN()
}

// applySelections restores group → node choices saved in the app while disconnected.
func applySelections(profilePath string) int {
	sel := readSelections(profilePath)
	if len(sel) == 0 {
		return 0
	}
	proxies := tunnel.Proxies()
	n := 0
	for g, node := range sel {
		p, ok := proxies[g]
		if !ok {
			continue
		}
		if s, ok := p.Adapter().(outboundgroup.SelectAble); ok && p.Type() == C.Selector {
			if err := s.Set(node); err == nil {
				n++
			} else {
				log.Warnln("[Bridge] restore selection %s → %s: %v", g, node, err)
			}
		}
	}
	return n
}

// mergeManualNodes adds the manual-nodes profile's proxies and a 手动节点 select group, listed first in
// the profile's first select group.
func mergeManualNodes(raw map[string]any, manualPath string) {
	man, err := loadYAML(manualPath)
	if err != nil {
		return
	}
	nodes := proxiesOf(man)
	if len(nodes) == 0 {
		return
	}
	groups, _ := raw["proxy-groups"].([]any)
	for _, g := range groups {
		if m, ok := g.(map[string]any); ok && str(m["name"]) == ManualGroupName {
			return // this is the manual profile itself (or already merged)
		}
	}
	existing := map[string]bool{}
	list, _ := raw["proxies"].([]any)
	for _, p := range list {
		if m, ok := p.(map[string]any); ok {
			existing[str(m["name"])] = true
		}
	}
	var names []any
	for _, n := range nodes {
		name := str(n["name"])
		if name == "" {
			continue
		}
		if existing[name] {
			name = name + " (手动)"
			n["name"] = name
		}
		list = append(list, n)
		names = append(names, name)
	}
	raw["proxies"] = list
	mg := map[string]any{"name": ManualGroupName, "type": "select", "proxies": names}
	for _, g := range groups {
		if m, ok := g.(map[string]any); ok && strings.EqualFold(str(m["type"]), "select") {
			m["proxies"] = append([]any{ManualGroupName}, asList(m["proxies"])...)
			break
		}
	}
	raw["proxy-groups"] = append(groups, mg)
}

// TestDelay measures an HTTP round trip through one node parsed from JSON (offline latency tests in
// the app, which talks to the network directly while the tunnel is down). Returns ms, or -1.
func TestDelay(proxyJSON, url string, timeoutMs int) int {
	var m map[string]any
	if err := json.Unmarshal([]byte(proxyJSON), &m); err != nil {
		lastError = err.Error()
		return -1
	}
	p, err := adapter.ParseProxy(m)
	if err != nil {
		lastError = err.Error()
		return -1
	}
	defer func() { _ = p.Close() }()
	if timeoutMs <= 0 {
		timeoutMs = 5000
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()
	d, err := p.URLTest(ctx, url, nil)
	if err != nil {
		lastError = err.Error()
		return -1
	}
	return int(d)
}

// ---------------- /tools ----------------

var toolSeq atomic.Int64

type probeResult struct {
	Seq     int     `json:"seq"`
	OK      bool    `json:"ok"`
	Ms      float64 `json:"ms"`
	Error   string  `json:"error,omitempty"`
	Chain   string  `json:"chain,omitempty"`
	Rule    string  `json:"rule,omitempty"`
	Status  int     `json:"status,omitempty"`
	Remote  string  `json:"remote,omitempty"`
	Payload string  `json:"rulePayload,omitempty"`
}

// dialThroughPolicy opens a TCP connection to addr through the core's rules (Type INNER, like
// listener/inner) and waits until the outbound dial finished, which is when the connection shows up in
// the statistic manager. Returns the conn, the tracker info and the elapsed time.
func dialThroughPolicy(ctx context.Context, addr, policy string) (net.Conn, *statistic.TrackerInfo, time.Duration, error) {
	if tunnel.Status() == tunnel.Suspend {
		return nil, nil, 0, fmt.Errorf("内核未运行")
	}
	marker := "mihomo-ios-tool-" + strconv.FormatInt(toolSeq.Add(1), 10)
	c1, c2 := net.Pipe()
	md := &C.Metadata{NetWork: C.TCP, Type: C.INNER, DNSMode: C.DNSNormal, Process: C.MihomoName, InName: marker}
	if policy != "" {
		md.SpecialProxy = policy
	}
	if err := md.SetRemoteAddress(addr); err != nil {
		return nil, nil, 0, err
	}
	start := time.Now()
	go tunnel.Tunnel.HandleTCPConn(c2, md)
	closed := make(chan struct{})
	go func() {
		// The tunnel closes its side when the dial fails; a read error before the tracker appears = failure.
		_ = c1.SetReadDeadline(time.Time{})
		var b [1]byte
		_, _ = c1.Read(b[:0])
		close(closed)
	}()
	tick := time.NewTicker(2 * time.Millisecond)
	defer tick.Stop()
	for {
		var info *statistic.TrackerInfo
		statistic.DefaultManager.Range(func(t statistic.Tracker) bool {
			if i := t.Info(); i != nil && i.Metadata != nil && i.Metadata.InName == marker {
				info = i
				return false
			}
			return true
		})
		if info != nil {
			return c1, info, time.Since(start), nil
		}
		select {
		case <-ctx.Done():
			_ = c1.Close()
			return nil, nil, time.Since(start), fmt.Errorf("超时")
		case <-closed:
			_ = c1.Close()
			return nil, nil, time.Since(start), fmt.Errorf("连接失败（被拒绝或策略为 REJECT）")
		case <-tick.C:
		}
	}
}

func chainText(info *statistic.TrackerInfo) string {
	s := ""
	for i := len(info.Chain) - 1; i >= 0; i-- {
		if s != "" {
			s += " → "
		}
		s += info.Chain[i]
	}
	return s
}

func toolsRoutes(r chi.Router) {
	r.Route("/tools", func(r chi.Router) {
		// GET /tools/tcp?host=&port=&count=4&timeout=5000&policy=  TCP connect through the rules.
		r.Get("/tcp", func(w mhttp.ResponseWriter, req *mhttp.Request) {
			q := req.URL.Query()
			host := q.Get("host")
			port := q.Get("port")
			if port == "" {
				port = "443"
			}
			count := clamp(atoi(q.Get("count"), 4), 1, 10)
			timeout := time.Duration(clamp(atoi(q.Get("timeout"), 5000), 500, 15000)) * time.Millisecond
			tlsProbe := q.Get("tls") == "1"
			out := []probeResult{}
			for i := 1; i <= count; i++ {
				ctx, cancel := context.WithTimeout(req.Context(), timeout)
				conn, info, d, err := dialThroughPolicy(ctx, net.JoinHostPort(host, port), q.Get("policy"))
				res := probeResult{Seq: i, Ms: float64(d.Microseconds()) / 1000}
				if err != nil {
					res.Error = err.Error()
				} else {
					res.OK = true
					res.Chain, res.Rule, res.Payload = chainText(info), info.Rule, info.RulePayload
					if info.Metadata != nil {
						res.Remote = info.Metadata.RemoteAddress()
					}
					if tlsProbe {
						t0 := time.Now()
						tc := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true}) // #nosec - latency probe only
						_ = tc.SetDeadline(time.Now().Add(timeout))
						if err := tc.HandshakeContext(ctx); err != nil {
							res.OK, res.Error = false, "TLS: "+err.Error()
						}
						res.Ms += float64(time.Since(t0).Microseconds()) / 1000
						conn = tc
					}
					_ = conn.Close()
				}
				cancel()
				out = append(out, res)
				if i < count {
					time.Sleep(300 * time.Millisecond)
				}
			}
			writeToolJSON(w, out)
		})
		// GET /tools/http?url=&count=3  full HTTP(S) request through the rules (time to response headers).
		r.Get("/http", func(w mhttp.ResponseWriter, req *mhttp.Request) {
			q := req.URL.Query()
			target := q.Get("url")
			count := clamp(atoi(q.Get("count"), 3), 1, 10)
			timeout := time.Duration(clamp(atoi(q.Get("timeout"), 8000), 1000, 20000)) * time.Millisecond
			out := []probeResult{}
			for i := 1; i <= count; i++ {
				var info *statistic.TrackerInfo
				tr := &http.Transport{
					DisableKeepAlives: true,
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						c, inf, _, err := dialThroughPolicy(ctx, addr, q.Get("policy"))
						info = inf
						return c, err
					},
					TLSHandshakeTimeout: timeout,
				}
				cl := &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
				t0 := time.Now()
				res := probeResult{Seq: i}
				resp, err := cl.Get(target)
				res.Ms = float64(time.Since(t0).Microseconds()) / 1000
				if err != nil {
					res.Error = err.Error()
				} else {
					res.OK, res.Status = true, resp.StatusCode
					_ = resp.Body.Close()
				}
				if info != nil {
					res.Chain, res.Rule, res.Payload = chainText(info), info.Rule, info.RulePayload
				}
				tr.CloseIdleConnections()
				out = append(out, res)
			}
			writeToolJSON(w, out)
		})
		r.Post("/reload-geo", func(w mhttp.ResponseWriter, req *mhttp.Request) {
			ReloadGeo()
			w.WriteHeader(mhttp.StatusNoContent)
		})
	})
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func writeToolJSON(w mhttp.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

// TestDelayByName tests one node of the profile at profilePath by name (offline 策略 page). Nodes from
// proxy providers are looked up in the providers' cached files. Returns ms or -1 (LastError has why).
func TestDelayByName(homeDir, profilePath, name, url string, timeoutMs int) int {
	raw := profileRaw(homeDir, profilePath)
	for _, p := range proxiesOf(raw) {
		if str(p["name"]) == name {
			b, _ := json.Marshal(p)
			return TestDelay(string(b), url, timeoutMs)
		}
	}
	if pv, ok := raw["proxy-providers"].(map[string]any); ok {
		for _, v := range pv {
			m, ok := v.(map[string]any)
			if !ok {
				continue
			}
			var nodes []map[string]any
			if strings.EqualFold(str(m["type"]), "inline") {
				nodes = proxiesOf(map[string]any{"proxies": m["payload"]})
			} else if b, err := os.ReadFile(providerCache("proxy", m)); err == nil {
				pr := map[string]any{}
				if yaml.Unmarshal(b, &pr) == nil && pr != nil {
					nodes = proxiesOf(pr)
				}
				if len(nodes) == 0 {
					nodes, _ = parseNodeText(string(b))
				}
			}
			for _, p := range nodes {
				if str(p["name"]) == name {
					b, _ := json.Marshal(p)
					return TestDelay(string(b), url, timeoutMs)
				}
			}
		}
	}
	lastError = "未找到节点 " + name
	return -1
}
