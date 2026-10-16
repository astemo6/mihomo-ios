package libmihomo

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
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
	b, err := os.ReadFile(filepath.Join(home, "dns.json"))
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
		dns["nameserver-policy"] = policy.toMap()
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

func (p *yamlOrderedPolicy) toMap() map[string]any {
	m := map[string]any{}
	for _, k := range p.keys {
		m[k] = p.vals[k]
	}
	return m
}
