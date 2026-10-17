package libmihomo

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// LocalDNS mirrors <home>/localdns.json written by the DNS page (v0.7): 本地 DNS 映射 (mihomo `hosts:`)
// and 真实 IP 域名 (added to `dns.fake-ip-filter`). Both apply on top of the profile whether or not the
// custom DNS override is on; the profile file itself is never rewritten.
type LocalDNS struct {
	Hosts  []HostEntry `json:"hosts"`
	RealIP []string    `json:"realIP"`
}

// HostEntry: Domain is a name, "+.suffix" or "*.wildcard"; Value is one or more IPs separated by commas,
// or a single domain name (mihomo resolves it in place of the original).
type HostEntry struct {
	Domain   string `json:"domain"`
	Value    string `json:"value"`
	Disabled bool   `json:"disabled,omitempty"`
}

func readLocalDNS(home string) *LocalDNS {
	if home == "" {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(home, "localdns.json"))
	if err != nil {
		return nil
	}
	l := &LocalDNS{}
	if json.Unmarshal(b, l) != nil {
		return nil
	}
	return l
}

// hostValue turns "1.1.1.1, 2.2.2.2" into a list, keeps a single IP or domain as a string.
// Returns nil for an unusable value.
func hostValue(v string) any {
	var parts []string
	for _, p := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		if p = strings.TrimSpace(p); p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return nil
	}
	allIP := true
	for _, p := range parts {
		if _, err := netip.ParseAddr(p); err != nil {
			allIP = false
		}
	}
	if !allIP {
		if len(parts) == 1 && validHostName(parts[0]) {
			return parts[0]
		}
		return nil
	}
	if len(parts) == 1 {
		return parts[0]
	}
	out := make([]any, len(parts))
	for i, p := range parts {
		out[i] = p
	}
	return out
}

func validHostName(s string) bool {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "+."), "*.")
	if s == "" || len(s) > 253 || strings.ContainsAny(s, " /:\\@") {
		return false
	}
	return true
}

// ValidateHostEntry is used by the app's editor: "" when the entry is usable, else a Chinese reason.
func ValidateHostEntry(domain, value string) string {
	if !validHostName(strings.TrimSpace(domain)) {
		return "域名无效"
	}
	if hostValue(value) == nil {
		return "映射值应为一个或多个 IP（用逗号分隔），或一个域名"
	}
	return ""
}

func applyLocalDNS(raw, dns map[string]any, l *LocalDNS, mode string) {
	if l == nil {
		return
	}
	n := 0
	hosts := asMap(raw["hosts"])
	for _, h := range l.Hosts {
		d := strings.ToLower(strings.TrimSpace(h.Domain))
		if h.Disabled || !validHostName(d) {
			continue
		}
		if v := hostValue(h.Value); v != nil {
			hosts[d] = v
			n++
		}
	}
	if n > 0 {
		raw["hosts"] = hosts
		dns["use-hosts"] = true
	}
	if mode != "fake-ip" || len(l.RealIP) == 0 {
		return
	}
	if m, _ := dns["fake-ip-filter-mode"].(string); m == "whitelist" {
		return // in whitelist mode the list means the opposite; the page says so
	}
	existing := asList(dns["fake-ip-filter"])
	seen := map[string]bool{}
	for _, e := range existing {
		if s, ok := e.(string); ok {
			seen[s] = true
		}
	}
	for _, d := range l.RealIP {
		d = strings.TrimSpace(d)
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		existing = append(existing, d)
	}
	dns["fake-ip-filter"] = existing
}

// applyInbound sets the local mixed port for 局域网共享, proxy-only and 混合 mode.
func applyInbound(raw map[string]any, o Overrides) {
	needLocal := o.TunnelMode == "proxy" || o.TunnelMode == "mix"
	switch {
	case o.AllowLan:
		raw["mixed-port"] = o.MixedPort
		raw["bind-address"] = "*"
		if o.LanAuth.Username != "" && o.LanAuth.Password != "" {
			raw["authentication"] = []any{o.LanAuth.Username + ":" + o.LanAuth.Password}
		}
		if o.LanLocalOnly {
			raw["lan-allowed-ips"] = lanPrivatePrefixes
		} else {
			delete(raw, "lan-allowed-ips")
		}
		delete(raw, "lan-disallowed-ips")
	case needLocal:
		// iOS sends HTTP/HTTPS through NEProxySettings to this local port.
		raw["mixed-port"] = o.MixedPort
		raw["bind-address"] = "127.0.0.1"
	default:
		return
	}
	// This device's own system proxy (proxy-only / 混合) never needs the LAN password.
	raw["skip-auth-prefixes"] = loopbackPrefixes
}
