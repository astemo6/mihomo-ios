package libmihomo

// v0.11: the remaining Quantumult X profile keys ([dns] and [general]) for ImportConf. Translation
// only: everything ends up as ordinary mihomo keys, or as connection settings the import sheet offers
// to apply (confSettings); what has no equivalent is listed in the report.

import (
	"net/netip"
	"strings"
)

// qxLineOpts reads the key=value options of a QX resource line ("<url>, tag=…, force-policy=…").
func qxLineOpts(line string) map[string]string {
	out := map[string]string{}
	parts := strings.Split(line, ",")
	for _, p := range parts[1:] {
		if k, v, ok := strings.Cut(strings.TrimSpace(p), "="); ok {
			out[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	return out
}

// qxDomainServer splits "/domain/value" (QX per-domain syntax) into a mihomo policy key and value.
// "*.example.com" and "example.com" both mean the domain and its subdomains in QX → "+.example.com".
func qxDomainServer(s string) (domain, value string, ok bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "/") {
		return "", "", false
	}
	rest := s[1:]
	i := strings.Index(rest, "/")
	if i <= 0 {
		return "", "", false
	}
	domain, value = strings.TrimSpace(rest[:i]), strings.TrimSpace(rest[i+1:])
	if domain == "" || value == "" {
		return "", "", false
	}
	return domain, value, true
}

func qxPolicyDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	switch {
	case strings.HasPrefix(d, "*."):
		return "+." + d[2:]
	case strings.HasPrefix(d, "+.") || strings.Contains(d, "*"):
		return d
	}
	return "+." + d
}

// qxHostDomain: QX address= / alias= domains match the name and its subdomains only with "*.".
func qxHostDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	if strings.HasPrefix(d, "*.") {
		return "+." + d[2:]
	}
	return d
}

// importQXDNS maps a QX [dns] section onto the profile's dns / hosts keys.
func importQXDNS(cfg map[string]any, lines []string, rep *confReport) {
	var plain, encrypted []any
	policy := map[string]any{}
	var policyOrder []string
	hosts := map[string]any{}
	noSystem, preferH3, noIPv6 := false, false, false
	addPolicy := func(d, v string) {
		k := qxPolicyDomain(d)
		if _, ok := policy[k]; !ok {
			policyOrder = append(policyOrder, k)
			policy[k] = []any{}
		}
		policy[k] = append(policy[k].([]any), v)
	}
	for _, l := range lines {
		k, v, hasEq := strings.Cut(l, "=")
		key := strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if !hasEq {
			switch key {
			case "no-system":
				noSystem = true
			case "prefer-doh3":
				preferH3 = true
			case "no-ipv6":
				noIPv6 = true
			case "circumvent-ipv4-answer", "circumvent-ipv6-answer":
				rep.Notes = append(rep.Notes, "[dns] "+key+" 没有对应项，已忽略")
			}
			continue
		}
		// SSID conditions can't be evaluated after re-signing; keep the server without them.
		if i := strings.Index(strings.ToLower(v), "cluded_ssids"); i > 0 {
			if c := strings.LastIndex(v[:i], ","); c > 0 {
				v = strings.TrimSpace(v[:c])
				rep.Notes = append(rep.Notes, "[dns] 按 Wi-Fi 生效的服务器已按全局导入："+v)
			}
		}
		switch key {
		case "server":
			if d, val, ok := qxDomainServer(v); ok {
				addPolicy(d, val)
				continue
			}
			if v != "" {
				plain = append(plain, v)
			}
		case "doh-server", "doq-server":
			if d, val, ok := qxDomainServer(v); ok {
				addPolicy(d, val)
				continue
			}
			for _, x := range strings.Split(v, ",") {
				if x = strings.TrimSpace(x); x != "" && !strings.Contains(x, "=") {
					encrypted = append(encrypted, x)
				}
			}
		case "address", "alias":
			if d, val, ok := qxDomainServer(v); ok {
				if key == "address" {
					if _, err := netip.ParseAddr(strings.Trim(val, "[]")); err != nil && val != "" {
						rep.Notes = append(rep.Notes, "[dns] address 的值不是 IP，已跳过："+v)
						continue
					}
				}
				hosts[qxHostDomain(d)] = val
			}
		}
	}
	d, _ := cfg["dns"].(map[string]any)
	if d == nil {
		d = map[string]any{}
	}
	// QX: when any DoH / DoQ server is set, plain servers and the system resolver are not used.
	var ns []any
	if len(encrypted) > 0 {
		ns = encrypted
	} else {
		ns = plain
		if !noSystem {
			ns = append(ns, "system")
		}
	}
	if len(encrypted) > 0 || len(plain) > 0 {
		d["enable"] = true
		d["nameserver"] = ns
		if len(plain) > 0 {
			d["default-nameserver"] = plain
		}
	}
	if len(policyOrder) > 0 {
		d["enable"] = true
		d["nameserver-policy"] = policy
		if d["nameserver"] == nil {
			d["nameserver"] = []any{"system"}
		}
	}
	if preferH3 {
		d["prefer-h3"] = true
	}
	if noIPv6 {
		d["ipv6"] = false
	}
	if len(d) > 0 {
		cfg["dns"] = d
	}
	if len(hosts) > 0 {
		cfg["hosts"] = hosts
		if dd, ok := cfg["dns"].(map[string]any); ok {
			dd["use-hosts"] = true
		}
	}
}

// importQXGeneral maps QX [general] keys. Profile keys go into cfg; connection settings into res.Settings.
func importQXGeneral(cfg map[string]any, g map[string]string, res *confResult, rep *confReport) {
	set := res.Settings
	if set == nil {
		set = &confSettings{}
	}
	if v := g["dns_exclusion_list"]; v != "" {
		var list []any
		for _, x := range strings.Split(v, ",") {
			if x = strings.TrimSpace(x); x != "" {
				list = append(list, qxPolicyDomain(x))
			}
		}
		if len(list) > 0 {
			d, _ := cfg["dns"].(map[string]any)
			if d == nil {
				d = map[string]any{}
			}
			d["fake-ip-filter"] = append(asList(d["fake-ip-filter"]), list...)
			cfg["dns"] = d
		}
	}
	if v := g["excluded_routes"]; v != "" {
		for _, x := range strings.Split(v, ",") {
			x = strings.TrimSpace(x)
			if p, err := netip.ParsePrefix(x); err == nil {
				set.ExcludedRoutes = append(set.ExcludedRoutes, p.Masked().String())
			}
		}
	}
	if v := g["ssid_suspended_list"]; v != "" {
		for _, x := range strings.Split(v, ",") {
			if x = strings.TrimSpace(x); x != "" {
				set.TrustedSSIDs = append(set.TrustedSSIDs, x)
			}
		}
	}
	if u := g["server_check_url"]; strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
		set.TestURL = u
	}
	if n := atoi(g["server_check_timeout"], 0); n > 0 {
		set.TestTimeoutMs = min(n, 5000)
	}
	for _, k := range []string{"running_mode_trigger", "enhanced_compatibility_ssid_list", "resource_parser_url", "geo_location_checker", "dns_reject_domain_behavior", "icmp_auto_reply", "server_check_user_agent", "doh_user_agent"} {
		if g[k] != "" {
			rep.Notes = append(rep.Notes, "[general] "+k+" 没有对应设置，已忽略")
		}
	}
	if !set.empty() {
		res.Settings = set
	}
}
