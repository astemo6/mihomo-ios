package libmihomo

// 接管所有网络流量 (NETunnelProviderProtocol.includeAllNetworks).
//
// With includeAllNetworks on, iOS scopes every connection to the tunnel, the packet tunnel's own sockets
// included: an unbound socket from the extension is routed into utun (its own tunnel) instead of out of
// the Wi-Fi / cellular interface, so every proxy server connection, every DIRECT connection and every
// DNS query of the core goes nowhere and the whole device loses its network. (Without the switch iOS
// exempts the provider's unbound sockets, which is why the default mode works.) The only sockets the
// system lets out are those explicitly scoped to the physical interface (IP_BOUND_IF / IPV6_BOUND_IF).
//
// So while the switch is on, every outbound socket the core opens to a routable address is bound to the
// physical interface the extension's NWPathMonitor reports (SetPhysicalInterface), with a scan of the
// interfaces as fallback before the first report. mihomo's dialer consults dialer.DefaultInterfaceFinder
// for each dial / ListenPacket that has no interface-name of its own (TCP, UDP relays, QUIC, DNS
// clients, health checks, provider downloads), and its darwin bind skips loopback / link-local targets.
// Nothing changes while the switch is off.

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/iface"
)

var (
	bindPhysical   atomic.Bool
	physMu         sync.Mutex
	physReported   string    // name from NWPathMonitor ("" = none yet / no path)
	physScanned    string    // cached answer of currentPhysical
	physScannedAt  time.Time // when physScanned was taken
	physSource     string    // where physScanned came from
	physLastLogged string    // last interface written to the stage log (one line per change)
	physBoundDials atomic.Uint64
	physUnbound    atomic.Uint64 // dials that found no physical interface (left unbound)
)

// physScanTTL: how long currentPhysical's answer is reused.
const physScanTTL = 5 * time.Second

// tunnel-side ranges never bound to the physical interface (fake-ip pool / tunnel addresses).
var tunnelPrefixes = []netip.Prefix{
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("fdfe:dcba:9876::/48"),
}

// SetBindPhysicalInterface turns physical-interface binding on (includeAllNetworks) or off. Called by the
// extension before Start from the VPN configuration's includeAllNetworks value.
func SetBindPhysicalInterface(on bool) {
	bindPhysical.Store(on)
	if on {
		dialer.DefaultInterfaceFinder.Store(physFinder{})
		name, src := currentPhysical()
		stage("includeAllNetworks on: core sockets bind to the physical interface (now %s, %s)", ifaceOrDash(name), src)
	} else {
		// Only clear our own finder (mihomo's tun auto-detect-interface is off on iOS, but never steal another).
		if _, ok := dialer.DefaultInterfaceFinder.Load().(physFinder); ok {
			dialer.DefaultInterfaceFinder.Store(nil)
		}
	}
}

// SetPhysicalInterface records the interface NWPathMonitor reports as the extension's path (en0,
// pdp_ip0, …; "" when there is no usable path). Interface indexes are re-read on a change.
func SetPhysicalInterface(name string) {
	name = strings.TrimSpace(name)
	physMu.Lock()
	changed := physReported != name
	physReported = name
	if changed {
		physScannedAt = time.Time{} // re-resolve on the next dial
	}
	physMu.Unlock()
	if changed {
		iface.FlushCache()
		if bindPhysical.Load() {
			n, src := currentPhysical()
			logPhysical(n, src)
		}
	}
}

// PhysicalInterfaceStatus is a one-line summary for 诊断 / the startup log.
func PhysicalInterfaceStatus() string {
	if !bindPhysical.Load() {
		return "physical bind off (includeAllNetworks off)"
	}
	name, src := currentPhysical()
	return fmt.Sprintf("physical bind on: %s (%s), bound dials %d, unbound %d", ifaceOrDash(name), src, physBoundDials.Load(), physUnbound.Load())
}

type physFinder struct{}

func (physFinder) FindInterfaceName(dst netip.Addr) string {
	if !bindPhysical.Load() {
		return ""
	}
	dst = dst.Unmap()
	if dst.IsValid() && (!dst.IsGlobalUnicast() || inTunnelRange(dst)) {
		return "" // loopback, link-local, multicast, fake-ip / tunnel addresses
	}
	name, src := currentPhysical()
	if name == "" {
		physUnbound.Add(1)
		return ""
	}
	if physBoundDials.Add(1) == 1 {
		stage("first core dial bound to %s (%s), destination %s", name, src, dst)
	}
	logPhysical(name, src)
	return name
}

func inTunnelRange(a netip.Addr) bool {
	for _, p := range tunnelPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// currentPhysical returns the interface to bind and where the name came from. The answer is cached for
// physScanTTL (dials are frequent; an interface lookup is a sysctl), SetPhysicalInterface resets it.
func currentPhysical() (string, string) {
	physMu.Lock()
	defer physMu.Unlock()
	if !physScannedAt.IsZero() && time.Since(physScannedAt) < physScanTTL {
		return physScanned, physSource
	}
	physScannedAt = time.Now()
	if physReported != "" && interfaceUsable(physReported) {
		physScanned, physSource = physReported, "NWPathMonitor"
	} else if n := scanPhysical(net.Interfaces); n != "" {
		physScanned, physSource = n, "interface scan"
	} else {
		physScanned, physSource = "", "none found"
	}
	return physScanned, physSource
}

func interfaceUsable(name string) bool {
	ifi, err := net.InterfaceByName(name)
	return err == nil && ifi.Flags&net.FlagUp != 0
}

// scanPhysical picks the physical interface before NWPathMonitor reported one: Wi-Fi / Ethernet (en*) with
// a routable IPv4 first, then cellular (pdp_ip*), then any en* / pdp_ip* with a global IPv6 address.
// utun / ipsec / loopback / awdl / llw / bridge / ap are never picked.
func scanPhysical(list func() ([]net.Interface, error)) string {
	ifs, err := list()
	if err != nil {
		return ""
	}
	type cand struct {
		name string
		rank int
	}
	var cs []cand
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		kind := 0
		switch {
		case strings.HasPrefix(ifi.Name, "en"):
			kind = 1
		case strings.HasPrefix(ifi.Name, "pdp_ip"):
			kind = 2
		default:
			continue
		}
		v4, v6 := interfaceAddrKinds(ifi)
		rank := 0
		switch {
		case v4 && kind == 1:
			rank = 1
		case v4 && kind == 2:
			rank = 2
		case v6 && kind == 1:
			rank = 3
		case v6 && kind == 2:
			rank = 4
		default:
			continue
		}
		cs = append(cs, cand{ifi.Name, rank})
	}
	if len(cs) == 0 {
		return ""
	}
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].rank != cs[j].rank {
			return cs[i].rank < cs[j].rank
		}
		return cs[i].name < cs[j].name
	})
	return cs[0].name
}

// interfaceAddrKinds: routable IPv4 / global IPv6 present (link-local and loopback ignored).
var interfaceAddrKinds = func(ifi net.Interface) (v4, v6 bool) {
	addrs, err := ifi.Addrs()
	if err != nil {
		return false, false
	}
	for _, a := range addrs {
		pfx, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		ip := pfx.Addr().Unmap()
		if !ip.IsGlobalUnicast() {
			continue
		}
		if ip.Is4() {
			v4 = true
		} else {
			v6 = true
		}
	}
	return
}

func logPhysical(name, src string) {
	physMu.Lock()
	if physLastLogged == name {
		physMu.Unlock()
		return
	}
	prev := physLastLogged
	physLastLogged = name
	physMu.Unlock()
	if prev == "" {
		stage("core sockets bound to %s (%s)", ifaceOrDash(name), src)
	} else {
		stage("core sockets now bound to %s (%s; was %s)", ifaceOrDash(name), src, prev)
	}
}

func ifaceOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// dnsPlanLine summarises which resolvers the core uses for node (proxy server) hostnames and for
// everything else, for the startup log. A "system" entry reads /etc/resolv.conf; the tunnel's own DNS
// address (198.18.0.2) is skipped there by mihomo, so system falls back to 114.114.114.114 / 8.8.8.8.
func dnsPlanLine(dns map[string]any) string {
	list := func(k string) string {
		var out []string
		for _, e := range asList(dns[k]) {
			s := strings.TrimSpace(fmt.Sprint(e))
			if s != "" {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return "-"
		}
		if len(out) > 4 {
			out = append(out[:4], fmt.Sprintf("+%d", len(out)-4))
		}
		return strings.Join(out, ", ")
	}
	return fmt.Sprintf("dns: node hostnames via [%s], queries via [%s], bootstrap [%s], mode %v",
		list("proxy-server-nameserver"), list("nameserver"), list("default-nameserver"), dns["enhanced-mode"])
}
