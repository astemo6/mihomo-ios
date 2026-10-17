package libmihomo

import "fmt"

// v0.8 节点探测 (exit IP per node, 解锁检测).
//
// The app sends probe requests itself (main app process, nothing extra runs in the extension): through a
// loopback-only mixed listener whose traffic always goes to one hidden select group. The app picks the
// policy to test with PUT /proxies/<ProbeGroup> {name} on the controller, then makes plain HTTP(S)
// requests through 127.0.0.1:<probe port>. The group holds references only (include-all + every group),
// and the listener is one idle accept loop, so the extension's memory does not change measurably.
const (
	ProbeGroup    = "MIHOMO-PROBE"
	probeListener = "mihomo-ios-probe"
)

// ProbePort returns the loopback port of the probe listener: 7899, or the next free one below it when
// the mixed or controller port already uses it. The Swift side (CoreOverrides.probePort) uses the same rule.
func probePort(o Overrides) int {
	for p := 7899; p > 7800; p-- {
		if p != o.MixedPort && p != o.ControllerPort {
			return p
		}
	}
	return 7899
}

// applyProbe adds the hidden probe group (all proxies, all provider proxies, every other group, DIRECT)
// and the loopback listener that sends everything to it.
func applyProbe(raw map[string]any, o Overrides) {
	groups := asList(raw["proxy-groups"])
	members := []any{}
	kept := make([]any, 0, len(groups)+1)
	for _, g := range groups {
		m := asMap(g)
		name, _ := m["name"].(string)
		if name == ProbeGroup {
			continue // a profile copied from a runtime config
		}
		kept = append(kept, g)
		if name != "" {
			members = append(members, name)
		}
	}
	members = append(members, "DIRECT")
	kept = append(kept, map[string]any{
		"name":        ProbeGroup,
		"type":        "select",
		"include-all": true,
		"proxies":     members,
		"hidden":      true,
	})
	raw["proxy-groups"] = kept

	ls := []any{}
	for _, l := range asList(raw["listeners"]) {
		if n, _ := asMap(l)["name"].(string); n == probeListener {
			continue
		}
		ls = append(ls, l)
	}
	ls = append(ls, map[string]any{
		"name":   probeListener,
		"type":   "mixed",
		"listen": "127.0.0.1",
		"port":   probePort(o),
		"udp":    false,
		"proxy":  ProbeGroup,
	})
	raw["listeners"] = ls
}

// ProbePort is exported for the app (diagnostics / settings display).
func ProbePort(home string) string { return fmt.Sprint(probePort(readOverrides(home))) }

// countUserGroups counts proxy-groups of a runtime config without the hidden probe group.
func countUserGroups(raw map[string]any) int {
	n := 0
	for _, g := range asList(raw["proxy-groups"]) {
		if name, _ := asMap(g)["name"].(string); name != ProbeGroup {
			n++
		}
	}
	return n
}
