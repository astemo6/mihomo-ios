package libmihomo

// v0.19.22 更多 → 高级设置 → 网络 → Tailscale: the live Tailscale nodes of the running core and the tailnet
// addresses tsnet got (only once a node's tsnet server started and has a netmap — nothing is guessed).

import (
	"encoding/json"
	"sort"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
)

type tailnetNode struct {
	Name    string `json:"name"`
	Started bool   `json:"started"`           // its tsnet server is running
	Stopped bool   `json:"stopped,omitempty"` // stopped by the memory watchdog
	IPv4    string `json:"ipv4,omitempty"`
	IPv6    string `json:"ipv6,omitempty"`
}

// TailscaleNodes returns JSON [{name, started, stopped, ipv4, ipv6}] for the Tailscale nodes of the live config
// ("[]" when the core is not running or has none).
func TailscaleNodes() string {
	out := []tailnetNode{}
	if running.Load() {
		for name, p := range tunnel.Proxies() {
			ap, ok := p.(*adapter.Proxy)
			if !ok || ap.ProxyAdapter == nil || ap.Type() != C.Tailscale {
				continue
			}
			n := tailnetNode{Name: name}
			inner := ap.ProxyAdapter
			if g, ok := inner.(*tsGuard); ok {
				g.mu.Lock()
				n.Stopped = g.stopped || g.closed
				g.mu.Unlock()
				inner = g.ProxyAdapter
			}
			if !n.Stopped {
				n.Started, n.IPv4, n.IPv6 = tailnetAddrs(inner)
			}
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	b, _ := json.Marshal(out)
	return string(b)
}
