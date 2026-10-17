package libmihomo

// Android port hooks (mihomo-android). bridge.go is synced from the iOS repo by scripts/sync-core.sh,
// which inserts two calls: platformMemoryLimit and platformTun. Their default (iOS) behaviour is a no-op;
// platform_android.go replaces them when built with GOOS=android (gomobile -target=android).

var (
	platformMemoryLimitHook func(mb int) int
	platformTunHook         func(raw map[string]any, o Overrides)
)

func platformMemoryLimit(mb int) int {
	if platformMemoryLimitHook != nil {
		return platformMemoryLimitHook(mb)
	}
	return mb
}

func platformTun(raw map[string]any, o Overrides) {
	if platformTunHook != nil {
		platformTunHook(raw, o)
	}
}

// Android VpnService layout. The Kotlin side (MihomoVpnService) builds the interface with exactly these
// values: address 198.18.0.1/30, DNS 198.18.0.2 (hijacked by the core), IPv6 fdfe:dcba:9876::1/126.
const (
	AndroidTunAddress4 = "198.18.0.1"
	AndroidTunPrefix4  = 30
	AndroidTunDNS4     = "198.18.0.2"
	AndroidTunAddress6 = "fdfe:dcba:9876::1"
	AndroidTunPrefix6  = 126
	AndroidTunMTU      = 9000
	androidFakeIPRange = "198.18.0.1/16"
	androidMemLimitMB  = 192
)

// androidTun rewrites the iOS tun block for an Android VpnService file descriptor: a real tun device
// (raw IP packets, no utun 4-byte header), so the darwin-only recvmsg_x/sendmsg_x options go, the MTU
// follows the VpnService builder, and the tun /30 (mihomo derives it from fake-ip-range) is pinned to
// 198.18.0.1/30 so it always matches the address the service assigns.
func androidTun(raw map[string]any, o Overrides) {
	tun := asMap(raw["tun"])
	if len(tun) == 0 {
		return
	}
	delete(tun, "recvmsgx")
	delete(tun, "sendmsgx")
	tun["mtu"] = AndroidTunMTU
	tun["stack"] = androidStack(o)
	tun["auto-route"] = false
	tun["auto-detect-interface"] = false
	tun["dns-hijack"] = []any{"any:53", "tcp://any:53"}
	raw["tun"] = tun
	dns := asMap(raw["dns"])
	dns["fake-ip-range"] = androidFakeIPRange
	raw["dns"] = dns
}

func androidStack(o Overrides) string {
	switch androidStackPref {
	case "system", "mixed":
		return androidStackPref
	}
	return "gvisor"
}

// androidStackPref is set by SetTunStack from the app (连接方式 → 协议栈).
var androidStackPref = "gvisor"

// SetTunStack selects the tun network stack on Android: "gvisor" (default), "system" or "mixed".
// Takes effect on the next Start / Reload.
func SetTunStack(stack string) { androidStackPref = stack }
