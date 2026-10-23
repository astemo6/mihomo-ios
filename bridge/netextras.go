package libmihomo

// Loon parity for 连接方式 / 测速 (feat/loon-net-route, 2026-10-23):
//
//   - 直连时丢弃 STUN (stunDropDirect): UDP to a STUN port is rejected when the rules would send it DIRECT.
//     A rule-text approach can only reject STUN everywhere; this is a Go rule inserted at the top of the
//     running rule list (hub.Parse option) that looks ahead: it runs the remaining rules the way the tunnel's
//     match() does (PASS, groups resolved to their current member, the "proxy has no UDP → keep looking" skip,
//     the final DIRECT when nothing matches) and only matches when the result is the DIRECT outbound.
//     FaceTime 走代理 prepends its UDP 3478-3497 rules to the proxy group, so with that switch on FaceTime's
//     STUN resolves to the proxy and is never dropped here (unless the group itself currently selects DIRECT).
//   - 阻止 WebRTC (blockWebRTC, feat/tunnel-include-options): the same rule rejects every STUN / TURN UDP on those
//     ports whatever the policy (stops apps using the device as a PCDN node through hole punching and WebRTC IP
//     leaks). It supersedes 直连时丢弃 STUN: with both on only the WebRTC rule is inserted. Both exempt Apple
//     destinations (17.0.0.0/8, Apple's IPv6 blocks, *.apple.com / *.icloud.com): FaceTime's STUN (3478-3497)
//     then follows the rules as before — FaceTime 走代理's proxy rules, or the profile's own.
//   - UDP 回落 (udpFallback): mihomo skips a matched rule whose policy has no UDP and, when nothing else
//     matches, falls back to DIRECT. "reject" ends the rule list with a REJECT for that leftover UDP.
//   - DNS 劫持 (dnsHijack): the tun dns-hijack list. mihomo always adds the tun DNS address (198.18.0.2:53).
//   - TCP 握手延迟: the time of a TCP connect to the node's server (DNS excluded), for nodes whose transport
//     is TCP; others fall back to the normal URL test.

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/metacubex/chi"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/route"
	RW "github.com/metacubex/mihomo/rules/wrapper"
	"github.com/metacubex/mihomo/tunnel"

	mhttp "github.com/metacubex/http"
)

func init() { route.Register(tcpDelayRoutes) }

// ── 直连时丢弃 STUN ─────────────────────────────────────────────────────────

// stunPorts: STUN / TURN (3478, 3479), STUN over TLS (5349, 5350) and Google's WebRTC STUN (19302-19309).
func isSTUNPort(p uint16) bool {
	switch {
	case p == 3478 || p == 3479 || p == 5349 || p == 5350:
		return true
	case p >= 19302 && p <= 19309:
		return true
	}
	return false
}

// appleNets: Apple's own address space (AS714). FaceTime relays and its STUN servers live there.
var appleNets = []netip.Prefix{
	netip.MustParsePrefix("17.0.0.0/8"),
	netip.MustParsePrefix("2620:149::/32"),
	netip.MustParsePrefix("2403:300::/32"),
	netip.MustParsePrefix("2a01:b740::/32"),
}

// isAppleDest: FaceTime (and other Apple services) — never treated as WebRTC by the STUN rules.
func isAppleDest(md *C.Metadata) bool {
	h := strings.ToLower(strings.TrimSuffix(md.Host, "."))
	for _, s := range []string{"apple.com", "icloud.com", "apple-cloudkit.com", "push-apple.com.akadns.net"} {
		if h == s || strings.HasSuffix(h, "."+s) {
			return true
		}
	}
	ip := md.DstIP.Unmap()
	if !ip.IsValid() {
		return false
	}
	for _, p := range appleNets {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// stunDropRule is the injected rule. Shown by the controller as Network(STUN) → REJECT (直连时丢弃 STUN), or
// Network(WebRTC) → REJECT when all is set (阻止 WebRTC: every STUN / TURN, whatever the policy).
type stunDropRule struct{ all bool }

func (stunDropRule) RuleType() C.RuleType { return C.Network }
func (stunDropRule) Adapter() string      { return "REJECT" }
func (r stunDropRule) Payload() string {
	if r.all {
		return "WebRTC"
	}
	return "STUN"
}
func (stunDropRule) ProviderNames() []string { return nil }
func (r stunDropRule) Match(md *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	if md == nil || md.NetWork != C.UDP || md.Type == C.INNER || !isSTUNPort(md.DstPort) || isAppleDest(md) {
		return false, ""
	}
	if r.all || resolvesDirect(md, helper, tunnel.Rules(), tunnel.Proxies()) {
		return true, "REJECT"
	}
	return false, ""
}

func isSTUNDropRule(r C.Rule) bool {
	if w, ok := r.(C.RuleWrapper); ok {
		r = w.Unwrap()
	}
	_, ok := r.(stunDropRule)
	return ok
}

// resolvesDirect mirrors tunnel.match for UDP: true when the rules (without the STUN rule itself) end on the
// DIRECT outbound. A REMATCH policy can't be predicted without dialing it, so it counts as not direct.
func resolvesDirect(md *C.Metadata, helper C.RuleMatchHelper, rules []C.Rule, proxies map[string]C.Proxy) bool {
next:
	for _, rule := range rules {
		if isSTUNDropRule(rule) {
			continue
		}
		if w, ok := rule.(C.RuleWrapper); ok {
			if w.IsDisabled() {
				continue
			}
			rule = w.Unwrap() // no hit / miss counts for the look-ahead
		}
		matched, name := rule.Match(md, helper)
		if !matched {
			continue
		}
		p, ok := proxies[name]
		if !ok {
			continue
		}
		last := p
		for a := p; a != nil; a = a.Unwrap(md, false) {
			switch a.Type() {
			case C.Pass:
				continue next
			case C.Rematch:
				return false
			}
			last = a
		}
		if md.NetWork == C.UDP && !p.SupportUDP() {
			continue
		}
		return last.Type() == C.Direct
	}
	return true // "doesn't match any rule using DIRECT"
}

// stunDropOption is the hub.Parse option: puts the STUN rule first when a switch is on and there are rules.
// 阻止 WebRTC (all) supersedes 直连时丢弃 STUN (direct): one rule either way.
func stunDropOption(direct, all bool) func(*config.Config) {
	return func(cfg *config.Config) {
		if !(direct || all) || cfg == nil || len(cfg.Rules) == 0 {
			return
		}
		for _, r := range cfg.Rules {
			if isSTUNDropRule(r) {
				return
			}
		}
		cfg.Rules = append([]C.Rule{RW.NewRuleWrapper(stunDropRule{all: all})}, cfg.Rules...)
		if all {
			stage("阻止 WebRTC: on")
		} else {
			stage("直连时丢弃 STUN: on")
		}
	}
}

// ── UDP 回落 ───────────────────────────────────────────────────────────────

// UDPFallbackRejectRule ends the list for UDP回落 "reject": only UDP that every matched rule skipped (policy
// without UDP) reaches it; the engine's own INNER traffic keeps mihomo's behaviour.
const UDPFallbackRejectRule = "AND,((NETWORK,UDP),(NOT,((IN-TYPE,INNER)))),REJECT"

func applyUDPFallback(raw map[string]any, mode string) {
	if mode != "reject" {
		return
	}
	rules := asList(raw["rules"])
	if len(rules) == 0 {
		return
	}
	raw["rules"] = append(rules, UDPFallbackRejectRule)
}

// ── DNS 劫持 ──────────────────────────────────────────────────────────────

var defaultDNSHijack = []string{"any:53"}

// validDNSHijack accepts what mihomo's tun listener parses: [scheme://]any|IP:port.
func validDNSHijack(s string) bool {
	d := strings.TrimSpace(s)
	if _, after, ok := strings.Cut(d, "://"); ok {
		d = after
	}
	d = strings.Replace(d, "any", "0.0.0.0", 1)
	ap, err := netip.ParseAddrPort(d)
	return err == nil && ap.Port() != 0
}

// dnsHijackList: nil (older overrides.json) = any:53; invalid lines are dropped.
func dnsHijackList(list []string) []any {
	if list == nil {
		list = defaultDNSHijack
	}
	out := []any{}
	seen := map[string]bool{}
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] || !validDNSHijack(s) {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// ── TCP 握手延迟 ──────────────────────────────────────────────────────────

// tcpTransport: protocols whose connection to the server is a TCP connection (UDP based ones — Hysteria,
// TUIC, WireGuard, MASQUE … — and groups / built-ins fall back to the URL test).
func tcpTransport(t string) bool {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "ss", "shadowsocks", "ssr", "shadowsocksr", "snell", "socks5", "socks", "http", "vmess", "vless", "trojan", "ssh", "anytls":
		return true
	}
	return false
}

var errNotTCP = errors.New("not a TCP node")

// tcpHandshake resolves host (not timed), then times one TCP connect to it.
func tcpHandshake(ctx context.Context, host string, port int, opts ...dialer.Option) (int, error) {
	if host == "" || port <= 0 || port > 65535 {
		return -1, errNotTCP
	}
	ip, err := resolver.ResolveIPWithResolver(ctx, host, resolver.ProxyServerHostResolver)
	if err != nil {
		return -1, err
	}
	t0 := time.Now()
	c, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)), opts...)
	if err != nil {
		return -1, err
	}
	ms := int(time.Since(t0).Milliseconds())
	_ = c.Close()
	if ms < 1 {
		ms = 1
	}
	return ms, nil
}

// nodeTCPDelay: the TCP connect time for a node config (offline tests in the app). Not a TCP node, behind a
// 前置代理 (the handshake would not be with the server the traffic goes through first) → URL test instead.
func nodeTCPDelay(m map[string]any, url string, timeoutMs int) int {
	if timeoutMs <= 0 {
		timeoutMs = 5000
	}
	if !tcpTransport(str(m["type"])) || str(m["dialer-proxy"]) != "" {
		b, _ := json.Marshal(m)
		return TestDelay(string(b), url, timeoutMs)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()
	port := atoi(strings.TrimSpace(anyString(m["port"])), 0)
	var opts []dialer.Option
	if iface := str(m["interface-name"]); iface != "" {
		opts = append(opts, dialer.WithInterface(iface))
	} else if iface := offlineIface(); iface != "" {
		if d, err := tcpHandshake(ctx, str(m["server"]), port, dialer.WithInterface(iface)); err == nil {
			return d
		}
		// Interface gone / bind refused: normal routing below.
	}
	d, err := tcpHandshake(ctx, str(m["server"]), port, opts...)
	if err != nil {
		setLastError(err.Error())
		return -1
	}
	return d
}

func anyString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatInt(int64(x), 10)
	case json.Number:
		return x.String()
	}
	return ""
}

// TestTCPDelay is TestDelay with 测速设置 → TCP 握手延迟 on. Returns ms, or -1.
func TestTCPDelay(proxyJSON, url string, timeoutMs int) int {
	var m map[string]any
	if err := json.Unmarshal([]byte(proxyJSON), &m); err != nil {
		setLastError(err.Error())
		return -1
	}
	return nodeTCPDelay(m, url, timeoutMs)
}

// NodeTCPDelayIn is NodeTestDelayIn with TCP 握手延迟 on.
func NodeTCPDelayIn(homeDir, profilePath, provider, name, url string, timeoutMs int) int {
	raw := cachedRuntimeRaw(homeDir, profilePath)
	m, ok := findRuntimeNodeIn(raw, provider, name)
	if !ok {
		setLastError("在当前配置里找不到这个节点")
		return -1
	}
	return nodeTCPDelay(m, url, timeoutMs)
}

// TCPDelayByName is TestDelayByName with TCP 握手延迟 on.
func TCPDelayByName(homeDir, profilePath, name, url string, timeoutMs int) int {
	raw := cachedRuntimeRaw(homeDir, profilePath)
	m, _, ok := findRuntimeNode(raw, name)
	if !ok {
		return TestDelayByName(homeDir, profilePath, name, url, timeoutMs)
	}
	return nodeTCPDelay(m, url, timeoutMs)
}

// liveProxy finds a node of the running core: under its provider when given, else the config's proxies.
func liveProxy(provider, name string) C.Proxy {
	if provider != "" {
		if pv, ok := tunnel.Providers()[provider]; ok {
			for _, p := range pv.Proxies() {
				if p.Name() == name {
					return p
				}
			}
		}
		return nil
	}
	return tunnel.Proxies()[name]
}

// liveTCPCapable: a plain TCP node (not a group / built-in / UDP transport) whose dialer goes straight to its
// server. A 前置代理 is not visible on the adapter; applyConfig records which nodes / providers have one.
func liveTCPCapable(p C.Proxy, provider string) bool {
	switch p.Type() {
	case C.Shadowsocks, C.ShadowsocksR, C.Snell, C.Socks5, C.Http, C.Vmess, C.Vless, C.Trojan, C.Ssh, C.AnyTLS:
	default:
		return false
	}
	ch, _ := liveChained.Load().(chainedSet)
	if provider != "" {
		return !ch.providers[provider]
	}
	return !ch.nodes[p.Name()]
}

// chainedSet: proxies with dialer-proxy, and proxy-providers whose override sets one, in the live config.
type chainedSet struct {
	nodes     map[string]bool
	providers map[string]bool
}

var liveChained atomic.Value // chainedSet

func recordChained(raw map[string]any) {
	ch := chainedSet{nodes: map[string]bool{}, providers: map[string]bool{}}
	for _, p := range proxiesOf(raw) {
		if str(p["dialer-proxy"]) != "" {
			ch.nodes[str(p["name"])] = true
		}
	}
	if pv, ok := raw["proxy-providers"].(map[string]any); ok {
		for name, v := range pv {
			m, _ := v.(map[string]any)
			if str(asMap(m["override"])["dialer-proxy"]) != "" {
				ch.providers[name] = true
			}
		}
	}
	liveChained.Store(ch)
}

func tcpDelayRoutes(r chi.Router) {
	// GET /tern/node-tcp-delay?name=&provider=&url=&timeout=  → {"delay": ms} (0 = timeout / failure).
	// TCP connect time to the node's server for TCP nodes; the URL test (as /proxies/{name}/delay) otherwise.
	r.Get("/tern/node-tcp-delay", func(w mhttp.ResponseWriter, req *mhttp.Request) {
		q := req.URL.Query()
		name := q.Get("name")
		timeout := time.Duration(clamp(atoi(q.Get("timeout"), 5000), 500, 30000)) * time.Millisecond
		p := liveProxy(q.Get("provider"), name)
		if p == nil {
			w.WriteHeader(404)
			writeToolJSON(w, map[string]any{"message": "resource not found"})
			return
		}
		ctx, cancel := context.WithTimeout(req.Context(), timeout)
		defer cancel()
		ms := 0
		if liveTCPCapable(p, q.Get("provider")) {
			host, port, err := net.SplitHostPort(p.Addr())
			if err == nil {
				if d, err := tcpHandshake(ctx, host, atoi(port, 0)); err == nil {
					ms = d
				}
			}
		} else if u := strings.TrimSpace(q.Get("url")); validTestURL(u) {
			if d, err := p.URLTest(ctx, u, nil); err == nil {
				ms = int(d)
			}
		}
		writeToolJSON(w, map[string]any{"delay": ms})
	})
}
