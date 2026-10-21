package libmihomo

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
)

func resetPhys(t *testing.T) {
	t.Helper()
	SetBindPhysicalInterface(false)
	physMu.Lock()
	physReported, physScanned, physSource, physLastLogged = "", "", "", ""
	physScannedAt = time.Time{}
	physMu.Unlock()
	physBoundDials.Store(0)
	physUnbound.Store(0)
}

func TestScanPhysicalPrefersWiFiThenCellular(t *testing.T) {
	addrs := map[string][2]bool{ // v4, v6
		"en0": {true, true}, "pdp_ip0": {true, false}, "utun4": {true, true}, "lo0": {true, true},
		"awdl0": {false, true}, "en2": {false, false}, "pdp_ip1": {false, true}, "ipsec0": {true, false},
	}
	orig := interfaceAddrKinds
	defer func() { interfaceAddrKinds = orig }()
	interfaceAddrKinds = func(ifi net.Interface) (bool, bool) { a := addrs[ifi.Name]; return a[0], a[1] }
	mk := func(names ...string) func() ([]net.Interface, error) {
		return func() ([]net.Interface, error) {
			var out []net.Interface
			for i, n := range names {
				f := net.FlagUp
				if strings.HasPrefix(n, "lo") {
					f |= net.FlagLoopback
				}
				out = append(out, net.Interface{Index: i + 1, Name: n, Flags: f})
			}
			return out, nil
		}
	}
	cases := []struct {
		names []string
		want  string
	}{
		{[]string{"lo0", "utun4", "pdp_ip0", "en0", "awdl0"}, "en0"},     // Wi-Fi with IPv4 wins
		{[]string{"lo0", "utun4", "pdp_ip0", "en2", "awdl0"}, "pdp_ip0"}, // Wi-Fi without address: cellular
		{[]string{"utun4", "ipsec0", "awdl0", "pdp_ip1"}, "pdp_ip1"},     // IPv6-only cellular
		{[]string{"utun4", "ipsec0", "lo0", "awdl0"}, ""},                // nothing physical
	}
	for _, c := range cases {
		if got := scanPhysical(mk(c.names...)); got != c.want {
			t.Errorf("scanPhysical(%v) = %q, want %q", c.names, got, c.want)
		}
	}
	if got := scanPhysical(func() ([]net.Interface, error) { return nil, errors.New("x") }); got != "" {
		t.Errorf("scan error: %q", got)
	}
}

func TestPhysFinderOnlyWhileIncludeAllNetworks(t *testing.T) {
	resetPhys(t)
	defer resetPhys(t)
	lo := loopbackName(t)
	SetPhysicalInterface(lo) // a real, up interface on the test host stands in for en0
	if dialer.DefaultInterfaceFinder.Load() != nil {
		t.Fatal("finder installed while includeAllNetworks is off")
	}
	SetBindPhysicalInterface(true)
	f := dialer.DefaultInterfaceFinder.Load()
	if f == nil {
		t.Fatal("finder not installed")
	}
	for _, tc := range []struct {
		dst  string
		want string
	}{
		{"1.1.1.1", lo}, {"2606:4700::1111", lo}, {"192.168.1.10", lo}, // routable (incl. LAN): bound
		{"127.0.0.1", ""}, {"::1", ""}, {"169.254.1.1", ""}, {"fe80::1", ""}, {"224.0.0.251", ""},
		{"198.18.0.2", ""}, {"198.19.3.4", ""}, {"fdfe:dcba:9876::1", ""}, // tunnel DNS / fake-ip / tun v6
		{"::ffff:8.8.8.8", lo},
	} {
		if got := f.FindInterfaceName(netip.MustParseAddr(tc.dst)); got != tc.want {
			t.Errorf("FindInterfaceName(%s) = %q, want %q", tc.dst, got, tc.want)
		}
	}
	if !strings.Contains(PhysicalInterfaceStatus(), "physical bind on: "+lo+" (NWPathMonitor)") {
		t.Errorf("status: %s", PhysicalInterfaceStatus())
	}
	SetBindPhysicalInterface(false)
	if dialer.DefaultInterfaceFinder.Load() != nil {
		t.Fatal("finder left installed after includeAllNetworks off")
	}
	if got := f.FindInterfaceName(netip.MustParseAddr("1.1.1.1")); got != "" {
		t.Errorf("stale finder still binds: %q", got)
	}
}

func TestPhysReportedGoneFallsBackToScan(t *testing.T) {
	resetPhys(t)
	defer resetPhys(t)
	SetBindPhysicalInterface(true)
	SetPhysicalInterface("en-does-not-exist9")
	name, src := currentPhysical()
	if name == "en-does-not-exist9" || src == "NWPathMonitor" {
		t.Fatalf("missing interface used: %s (%s)", name, src)
	}
	// Changing the report re-resolves immediately (no TTL wait).
	lo := loopbackName(t)
	SetPhysicalInterface(lo)
	if name, src := currentPhysical(); name != lo || src != "NWPathMonitor" {
		t.Fatalf("after report: %s (%s)", name, src)
	}
	// No path: the next dials are left unbound (counted), never bound to a stale name.
	SetPhysicalInterface("")
	physMu.Lock()
	physScannedAt = time.Now()
	physScanned, physSource = "", "none found"
	physMu.Unlock()
	if got := (physFinder{}).FindInterfaceName(netip.MustParseAddr("1.1.1.1")); got != "" || physUnbound.Load() == 0 {
		t.Fatalf("no path: %q unbound=%d", got, physUnbound.Load())
	}
}

func TestDNSPlanLine(t *testing.T) {
	line := dnsPlanLine(map[string]any{
		"proxy-server-nameserver": []any{"13.78.100.57", "119.29.29.29", "system"},
		"nameserver":              []any{"https://223.5.5.5/dns-query", "a", "b", "c", "d", "e"},
		"enhanced-mode":           "fake-ip",
	})
	for _, want := range []string{"node hostnames via [13.78.100.57, 119.29.29.29, system]", "queries via [https://223.5.5.5/dns-query, a, b, c, +2]", "bootstrap [-]", "mode fake-ip"} {
		if !strings.Contains(line, want) {
			t.Errorf("%q missing %q", line, want)
		}
	}
}

func loopbackName(t *testing.T) string {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Skip(err)
	}
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 && i.Flags&net.FlagUp != 0 {
			return i.Name
		}
	}
	t.Skip("no loopback interface")
	return ""
}
