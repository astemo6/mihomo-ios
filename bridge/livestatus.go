package libmihomo

// v0.11: one cheap call for the Live Activity path. The tunnel extension samples it every few seconds
// while the activity is on and stores the result in the App Group; the app (in the background via its
// refresh button / background refresh) pushes it into ActivityKit, which only an app process may call.

import (
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/metacubex/mihomo/adapter/outboundgroup"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
)

// LiveStatus returns "up\tdown\ttotalUp\ttotalDown\tnode\tproxyUp\tproxyDown\tproxyUpTotal\tproxyDownTotal":
// current speed (bytes/s), totals since start, the node the main policy resolves to (global mode →
// GLOBAL, else the first group in GLOBAL's order, followed down to a leaf; empty when the core is not
// running), then (feat/traffic-scope) the same speed / totals for traffic that left through a proxy node
// only. Older parsers read the first five fields and ignore the rest.
func LiveStatus() string {
	t := currentAppTraffic()
	f := func(v int64) string { return strconv.FormatInt(v, 10) }
	return f(t.Up) + "\t" + f(t.Down) + "\t" + f(t.UpTotal) + "\t" + f(t.DownTotal) + "\t" + strings.ReplaceAll(liveNode(), "\t", " ") +
		"\t" + f(t.ProxyUp) + "\t" + f(t.ProxyDown) + "\t" + f(t.ProxyUpTotal) + "\t" + f(t.ProxyDownTotal)
}

func liveNode() (name string) {
	defer func() {
		if recover() != nil {
			name = ""
		}
	}()
	proxies := tunnel.Proxies()
	global, ok := proxies["GLOBAL"]
	if !ok {
		return ""
	}
	start := "GLOBAL"
	if tunnel.Mode() != tunnel.Global {
		if n := mainRuleGroup(proxies); n != "" {
			start = n
		} else if g, ok := global.Adapter().(outboundgroup.ProxyGroup); ok {
			for _, p := range g.Proxies() {
				if _, isGroup := p.Adapter().(outboundgroup.ProxyGroup); isGroup && !p.Adapter().(outboundgroup.ProxyGroup).Hidden() {
					start = p.Name()
					break
				}
			}
		}
	}
	name = start
	for hops := 0; hops < 8; hops++ {
		p, ok := proxies[name]
		if !ok {
			break
		}
		g, ok := p.Adapter().(outboundgroup.ProxyGroup)
		if !ok {
			break
		}
		now := g.Now()
		if now == "" || now == name {
			break
		}
		name = now
	}
	return name
}

// liveGroupOrder is the last applied runtime's proxy-groups order (runtime-groups.json, v0.19.8).
var liveGroupOrder atomic.Value // []string

// mainRuleGroup (v0.19.11, review 6 P2-3): the main policy the app shows first — the first visible group in
// the runtime order. GLOBAL's own member list is not that order once a profile or 策略组编辑 defines GLOBAL.
func mainRuleGroup(proxies map[string]C.Proxy) string {
	order, _ := liveGroupOrder.Load().([]string)
	for _, n := range order {
		if n == "GLOBAL" {
			continue
		}
		p, ok := proxies[n]
		if !ok {
			continue
		}
		if g, ok := p.Adapter().(outboundgroup.ProxyGroup); ok && !g.Hidden() {
			return n
		}
	}
	return ""
}
