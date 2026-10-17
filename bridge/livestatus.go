package libmihomo

// v0.11: one cheap call for the Live Activity path. The tunnel extension samples it every few seconds
// while the activity is on and stores the result in the App Group; the app (in the background via its
// refresh button / background refresh) pushes it into ActivityKit, which only an app process may call.

import (
	"strconv"

	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

// LiveStatus returns "up\tdown\ttotalUp\ttotalDown\tnode": current speed (bytes/s), totals since start,
// and the node the main policy resolves to (global mode → GLOBAL, else the first group in GLOBAL's
// order, followed down to a leaf). Empty node when the core is not running.
func LiveStatus() string {
	up, down := statistic.DefaultManager.Now()
	tu, td := statistic.DefaultManager.Total()
	return strconv.FormatInt(up, 10) + "\t" + strconv.FormatInt(down, 10) + "\t" + strconv.FormatInt(tu, 10) + "\t" +
		strconv.FormatInt(td, 10) + "\t" + liveNode()
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
		if g, ok := global.Adapter().(outboundgroup.ProxyGroup); ok {
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
