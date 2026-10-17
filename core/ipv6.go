package libmihomo

import "sync/atomic"

// networkHasIPv6 is what the extension found on the physical network at tunnel start (IPv6 mode "auto").
var networkHasIPv6 atomic.Bool

// SetNetworkIPv6 is called by the extension before Start: whether the physical network has a global IPv6
// address. Only used when overrides.json ipv6Mode is "auto".
func SetNetworkIPv6(on bool) { networkHasIPv6.Store(on) }

// applyIPPreference sets ip-version on every inline proxy that has none and adds it to each proxy
// provider's override (unless the provider already overrides it). "" = leave the profile alone.
func applyIPPreference(raw map[string]any, pref string) {
	if pref == "" {
		return
	}
	for _, p := range asList(raw["proxies"]) {
		m, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if _, has := m["ip-version"]; !has {
			m["ip-version"] = pref
		}
	}
	for _, v := range asMap(raw["proxy-providers"]) {
		pm, ok := v.(map[string]any)
		if !ok {
			continue
		}
		ov := asMap(pm["override"])
		if _, has := ov["ip-version"]; !has {
			ov["ip-version"] = pref
		}
		pm["override"] = ov
	}
}
