package libmihomo

// 按网络切换策略 (v0.9): per select group, which member to use on Wi-Fi, on cellular and on named Wi-Fi
// networks (SSID). It is an option stored in our override store, not a change to the profile:
//
//	<home>/netpolicy.json {"<profile id>": [{"group": "节点选择", "wifi": "DIRECT", "cellular": "🇭🇰 HK",
//	                                          "ssids": {"Home-WiFi": "DIRECT"}}]}
//
// The extension reports the physical network (type + SSID when it can read it) with SetNetworkState on
// every path change; the switch is applied in-process through the group's own Set — the same thing the
// controller's PUT /proxies/{group} does — so nothing runs in between changes (flat memory). An SSID rule
// wins over the Wi-Fi rule; when no rule matches the group keeps its current member. The user's saved
// selection (<profile>.selected.json) is not touched: the next connect restores it and the policy applies
// on top. Last result: <home>/netpolicy-state.json (read by the app).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/outboundgroup"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
)

type netPolicyRule struct {
	Group    string            `json:"group"`
	WiFi     string            `json:"wifi,omitempty"`
	Cellular string            `json:"cellular,omitempty"`
	SSIDs    map[string]string `json:"ssids,omitempty"`
}

type netPolicyApplied struct {
	Group  string `json:"group"`
	Node   string `json:"node"`
	Reason string `json:"reason"` // "ssid" | "wifi" | "cellular"
	Error  string `json:"error,omitempty"`
}

type netPolicyState struct {
	At      int64              `json:"at"`
	Type    string             `json:"type"`
	SSID    string             `json:"ssid,omitempty"`
	Trigger string             `json:"trigger"`
	Applied []netPolicyApplied `json:"applied"`
}

var (
	npMu      sync.Mutex
	npType    string
	npSSID    string
	npKnown   bool
	npProfile string // config path of the running core
)

func netPolicyPath(home string) string      { return filepath.Join(home, "netpolicy.json") }
func netPolicyStatePath(home string) string { return filepath.Join(home, "netpolicy-state.json") }

func readNetPolicy(home, profilePath string) []netPolicyRule {
	b, err := os.ReadFile(netPolicyPath(home))
	if err != nil {
		return nil
	}
	m := map[string][]netPolicyRule{}
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m[profileIDFromPath(profilePath)]
}

// pickNetPolicy returns the member a rule wants for the network, and why ("" = no opinion).
func pickNetPolicy(r netPolicyRule, netType, ssid string) (node, reason string) {
	switch netType {
	case "wifi":
		if ssid != "" {
			if n := strings.TrimSpace(r.SSIDs[ssid]); n != "" {
				return n, "ssid"
			}
		}
		if n := strings.TrimSpace(r.WiFi); n != "" {
			return n, "wifi"
		}
	case "cellular":
		if n := strings.TrimSpace(r.Cellular); n != "" {
			return n, "cellular"
		}
	}
	return "", ""
}

// applyNetPolicy selects the members the rules want for the last reported network. Returns the
// number of groups switched. Safe mode leaves the profile alone.
func applyNetPolicy(home, profilePath, trigger string) int {
	if home == "" || profilePath == "" {
		return 0
	}
	if overridesFor(home, profilePath).SafeMode {
		return 0
	}
	npMu.Lock()
	netType, ssid, known := npType, npSSID, npKnown
	npMu.Unlock()
	rules := readNetPolicy(home, profilePath)
	st := netPolicyState{At: time.Now().Unix(), Type: netType, SSID: ssid, Trigger: trigger, Applied: []netPolicyApplied{}}
	if !known || len(rules) == 0 {
		writeNetPolicyState(home, st)
		return 0
	}
	proxies := tunnel.Proxies()
	n := 0
	for _, r := range rules {
		node, reason := pickNetPolicy(r, netType, ssid)
		if node == "" {
			continue
		}
		a := netPolicyApplied{Group: r.Group, Node: node, Reason: reason}
		p, ok := proxies[r.Group]
		if !ok {
			a.Error = "group not found"
		} else if s, ok := p.Adapter().(outboundgroup.SelectAble); !ok || p.Type() != C.Selector {
			a.Error = "not a select group"
		} else if g, ok := p.Adapter().(interface{ Now() string }); ok && g.Now() == node {
			// already there
		} else if err := s.Set(node); err != nil {
			a.Error = err.Error()
		} else {
			n++
			log.Infoln("[NetPolicy] %s → %s (%s %s)", r.Group, node, netType, reason)
		}
		st.Applied = append(st.Applied, a)
	}
	writeNetPolicyState(home, st)
	return n
}

func writeNetPolicyState(home string, st netPolicyState) {
	b, _ := json.Marshal(st)
	_ = os.WriteFile(netPolicyStatePath(home), b, 0o644)
}

func setNetPolicyProfile(path string) {
	npMu.Lock()
	npProfile = path
	npMu.Unlock()
}

// SetNetworkState records the physical network the extension sees ("wifi" / "cellular" / "wired" /
// "other"; ssid "" when unknown) and, when it changed, applies 按网络切换策略. Returns a short log line
// ("" when nothing changed). Cheap to call on every path update.
func SetNetworkState(netType, ssid string) string {
	npMu.Lock()
	changed := !npKnown || npType != netType || npSSID != ssid
	npType, npSSID, npKnown = netType, ssid, true
	profile := npProfile
	npMu.Unlock()
	if !changed || !running {
		return ""
	}
	home := curHome
	if n := applyNetPolicy(home, profile, "network"); n > 0 {
		return "network policy: switched " + itoa(n) + " group(s) for " + netType
	}
	return ""
}

// ApplyNetworkPolicy re-applies the rules for the current network now (after the user edited them).
func ApplyNetworkPolicy() int {
	npMu.Lock()
	profile := npProfile
	npMu.Unlock()
	if !running {
		return 0
	}
	return applyNetPolicy(curHome, profile, "edit")
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
