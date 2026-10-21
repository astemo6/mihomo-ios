package libmihomo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// DNSOverride mirrors <home>/dns.json written by the app's DNS settings page. When Enabled it replaces
// the profile's resolver settings (applied as an override in buildRuntime).
type DNSOverride struct {
	Enabled           bool         `json:"enabled"`
	Nameserver        []string     `json:"nameserver"`        // domestic (国内) servers
	Foreign           []string     `json:"foreign"`           // foreign (国外) servers, used by the split
	Split             bool         `json:"split"`             // geosite:cn,private → domestic, everything else → foreign
	DefaultNameserver []string     `json:"defaultNameserver"` // plain IPs to bootstrap DoH/DoT/DoQ hostnames
	DirectNameserver  []string     `json:"directNameserver"`  // optional: resolve DIRECT traffic with these
	ProxyNameserver   []string     `json:"proxyNameserver"`   // proxy-server-nameserver (resolve node hostnames)
	Fallback          []string     `json:"fallback"`
	FallbackFilter    FallbackRule `json:"fallbackFilter"`
	FakeIPRange       string       `json:"fakeIPRange"`
	FakeIPFilter      []string     `json:"fakeIPFilter"`
	FakeIPFilterMode  string       `json:"fakeIPFilterMode"` // blacklist | whitelist
	Policy            []DNSPolicy  `json:"policy"`
	PreferH3          bool         `json:"preferH3"`
	RespectRules      bool         `json:"respectRules"`
	UseHosts          *bool        `json:"useHosts,omitempty"`
	UseSystemHosts    *bool        `json:"useSystemHosts,omitempty"`
	CacheAlgorithm    string       `json:"cacheAlgorithm"` // lru | arc
}

// FallbackRule is dns.fallback-filter.
type FallbackRule struct {
	GeoIP     bool     `json:"geoip"`
	GeoIPCode string   `json:"geoipCode"`
	IPCIDR    []string `json:"ipcidr"`
	Domain    []string `json:"domain"`
	GeoSite   []string `json:"geosite"`
}

// DNSPolicy is one nameserver-policy entry: match is a domain / "+.suffix" / "geosite:code" / "rule-set:name"
// (several separated by commas), servers the resolvers to use.
type DNSPolicy struct {
	Match   string   `json:"match"`
	Servers []string `json:"servers"`
}

func readDNSOverride(home string) *DNSOverride {
	if home == "" {
		return nil
	}
	b, err := os.ReadFile(dnsOverridePath(home))
	if err != nil {
		return nil
	}
	d := &DNSOverride{}
	if json.Unmarshal(b, d) != nil || !d.Enabled {
		return nil
	}
	return d
}

func cleanList(in []string) []any {
	var out []any
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// applyDNSOverride writes the user's DNS page on top of the profile's dns section.
func applyDNSOverride(dns map[string]any, d *DNSOverride, mode string) {
	if d == nil {
		return
	}
	domestic := cleanList(d.Nameserver)
	foreign := cleanList(d.Foreign)
	if len(domestic) == 0 && len(foreign) == 0 {
		return // nothing usable, keep the profile's resolvers
	}
	if len(domestic) == 0 {
		domestic = foreign
	}
	if len(foreign) == 0 {
		foreign = domestic
	}
	// Policies are rebuilt from scratch so the page is the single source of truth.
	policy := yamlOrderedPolicy{}
	if d.Split {
		dns["nameserver"] = foreign
		policy.add("geosite:cn,private", domestic)
		if _, ok := dns["proxy-server-nameserver"]; !ok || len(d.ProxyNameserver) == 0 {
			dns["proxy-server-nameserver"] = domestic
		}
	} else {
		dns["nameserver"] = domestic
	}
	for _, p := range d.Policy {
		if m := strings.TrimSpace(p.Match); m != "" {
			if sv := cleanList(p.Servers); len(sv) > 0 {
				policy.add(m, sv)
			}
		}
	}
	if len(policy.keys) > 0 {
		dns["nameserver-policy"] = orderedPolicyNode(policy.keys, policy.toMap())
	} else {
		delete(dns, "nameserver-policy")
	}
	if v := cleanList(d.DefaultNameserver); len(v) > 0 {
		dns["default-nameserver"] = v
	}
	if v := cleanList(d.ProxyNameserver); len(v) > 0 {
		dns["proxy-server-nameserver"] = v
	}
	if v := cleanList(d.DirectNameserver); len(v) > 0 {
		dns["direct-nameserver"] = v
	} else {
		delete(dns, "direct-nameserver")
	}
	if v := cleanList(d.Fallback); len(v) > 0 {
		dns["fallback"] = v
		ff := map[string]any{"geoip": d.FallbackFilter.GeoIP}
		code := strings.ToUpper(strings.TrimSpace(d.FallbackFilter.GeoIPCode))
		if code == "" {
			code = "CN"
		}
		ff["geoip-code"] = code
		if x := cleanList(d.FallbackFilter.IPCIDR); len(x) > 0 {
			ff["ipcidr"] = x
		}
		if x := cleanList(d.FallbackFilter.Domain); len(x) > 0 {
			ff["domain"] = x
		}
		if x := cleanList(d.FallbackFilter.GeoSite); len(x) > 0 {
			ff["geosite"] = x
		}
		dns["fallback-filter"] = ff
	} else {
		delete(dns, "fallback")
		delete(dns, "fallback-filter")
	}
	if mode == "fake-ip" {
		if r := strings.TrimSpace(d.FakeIPRange); r != "" {
			if p, err := netip.ParsePrefix(r); err == nil && p.Addr().Is4() && p.Bits() <= 24 {
				dns["fake-ip-range"] = r
			}
		}
		if f := cleanList(d.FakeIPFilter); len(f) > 0 {
			dns["fake-ip-filter"] = f
		}
		if d.FakeIPFilterMode == "whitelist" || d.FakeIPFilterMode == "blacklist" {
			dns["fake-ip-filter-mode"] = d.FakeIPFilterMode
		}
	}
	dns["prefer-h3"] = d.PreferH3
	dns["respect-rules"] = d.RespectRules && len(cleanList(d.ProxyNameserver))+len(asList(dns["proxy-server-nameserver"])) > 0
	if d.UseHosts != nil {
		dns["use-hosts"] = *d.UseHosts
	}
	if d.UseSystemHosts != nil {
		dns["use-system-hosts"] = *d.UseSystemHosts
	}
	if d.CacheAlgorithm == "lru" || d.CacheAlgorithm == "arc" {
		dns["cache-algorithm"] = d.CacheAlgorithm
	}
}

func asList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return nil
}

type yamlOrderedPolicy struct {
	keys []string
	vals map[string][]any
}

func (p *yamlOrderedPolicy) add(k string, v []any) {
	if p.vals == nil {
		p.vals = map[string][]any{}
	}
	if _, ok := p.vals[k]; !ok {
		p.keys = append(p.keys, k)
	}
	p.vals[k] = v
}

// orderedPolicyNode writes nameserver-policy as a YAML mapping in the given key order. mihomo keeps this
// section ordered and the first matching entry wins; a Go map is written sorted by key, so before v0.19.4
// the DNS page's order (and the profile's own order) was silently replaced by the alphabetical one
// ("geosite:…" ahead of "rule-set:…", the 国内/国外分流 entry moved behind user entries, …).
func orderedPolicyNode(keys []string, vals map[string]any) any {
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, k := range keys {
		v, ok := vals[k]
		if !ok {
			continue
		}
		var vn yaml.Node
		if err := vn.Encode(v); err != nil {
			return vals
		}
		n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}, &vn)
	}
	return n
}

// profilePolicyOrder returns the key order of dns.nameserver-policy as written in the profile, nil when
// the profile has none (cheap check first: most profiles do not).
func profilePolicyOrder(profile []byte) []string {
	if !bytes.Contains(profile, []byte("nameserver-policy")) {
		return nil
	}
	var doc struct {
		DNS struct {
			Policy yaml.Node `yaml:"nameserver-policy"`
		} `yaml:"dns"`
	}
	if yaml.Unmarshal(profile, &doc) != nil || doc.DNS.Policy.Kind != yaml.MappingNode {
		return nil
	}
	var keys []string
	for i := 0; i+1 < len(doc.DNS.Policy.Content); i += 2 {
		keys = append(keys, doc.DNS.Policy.Content[i].Value)
	}
	return keys
}

// keepProfilePolicyOrder re-applies the profile's own nameserver-policy order to the decoded map.
func keepProfilePolicyOrder(dns map[string]any, profile []byte) {
	m, ok := dns["nameserver-policy"].(map[string]any)
	if !ok || len(m) < 2 {
		return
	}
	order := profilePolicyOrder(profile)
	if len(order) == 0 {
		return
	}
	seen := map[string]bool{}
	var keys []string
	for _, k := range order {
		if _, ok := m[k]; ok && !seen[k] {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	var rest []string
	for k := range m {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	dns["nameserver-policy"] = orderedPolicyNode(append(keys, rest...), m)
}

func (p *yamlOrderedPolicy) toMap() map[string]any {
	m := map[string]any{}
	for _, k := range p.keys {
		m[k] = p.vals[k]
	}
	return m
}

// defaultProxyServerNameserver (v0.15.2): when neither the profile nor the DNS page names a
// proxy-server-nameserver, node hostnames are resolved with plain UDP servers — the profile's own plain
// nameservers (IP or "system", the QX import's system resolver) or else its default-nameserver — the
// way QX resolves servers with the system resolver. Without it mihomo resolves node hostnames with the
// main resolver: DoH by default (TLS + HTTP round trips before the first dial) and the nameserver-policy
// rules. Encrypted, "#proxy" and rule-bound entries are never copied.
func defaultProxyServerNameserver(dns map[string]any) {
	if len(asList(dns["proxy-server-nameserver"])) > 0 || dns["proxy-server-nameserver-policy"] != nil {
		return
	}
	pick := func(v any) []any {
		var out []any
		seen := map[string]bool{}
		for _, e := range asList(v) {
			s := strings.TrimSpace(fmt.Sprint(e))
			if s == "" || seen[s] || !plainNameserver(s) {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
		return out
	}
	ps := pick(dns["nameserver"])
	if len(ps) == 0 {
		ps = pick(dns["default-nameserver"])
	}
	if len(ps) == 0 {
		ps = []any{"223.5.5.5", "119.29.29.29"}
	}
	dns["proxy-server-nameserver"] = ps
}

// plainNameserver: "1.2.3.4", "1.2.3.4:53", "[::1]:53", "udp://…", "tcp://…" with an IP host, or "system".
func plainNameserver(s string) bool {
	if s == "system" {
		return true
	}
	if strings.Contains(s, "#") {
		return false // "#proxy", "#DIRECT", interface hints: keep the profile's routing semantics out of it
	}
	h := s
	if i := strings.Index(h, "://"); i >= 0 {
		switch strings.ToLower(h[:i]) {
		case "udp", "tcp":
			h = h[i+3:]
		default:
			return false
		}
	}
	if ap, err := netip.ParseAddrPort(h); err == nil {
		return ap.Addr().IsValid()
	}
	_, err := netip.ParseAddr(strings.Trim(h, "[]"))
	return err == nil
}
