package mitm

// Rule-line translation: Surge / Quantumult X / Loon / Stash rule syntax → mihomo rules.
// Policies are kept as written and resolved later against the running profile's groups
// (ResolvePolicy), so modules and the custom rules editor can target named policy groups.

import (
	"fmt"
	"net/netip"
	"strings"
)

// RuleConv is one translated line.
type RuleConv struct {
	Rule        string `json:"rule"`              // mihomo rule without the policy
	Type        string `json:"type"`              // mihomo rule type
	Policy      string `json:"policy"`            // policy as written (Surge/QX name)
	Options     string `json:"options,omitempty"` // ",no-resolve"
	RemoteURL   string `json:"remoteURL,omitempty"`
	RemoteKind  string `json:"remoteKind,omitempty"` // list | domainset
	Unsupported string `json:"unsupported,omitempty"`
	Note        string `json:"note,omitempty"`
}

// Format renders the mihomo rule with a resolved policy.
func (c RuleConv) Format(policy string) string {
	if c.Type == "MATCH" {
		return "MATCH," + policy
	}
	return c.Rule + "," + policy + c.Options
}

var surgeTypeMap = map[string]string{
	"DOMAIN": "DOMAIN", "DOMAIN-SUFFIX": "DOMAIN-SUFFIX", "DOMAIN-KEYWORD": "DOMAIN-KEYWORD", "DOMAIN-WILDCARD": "DOMAIN-WILDCARD",
	"DOMAIN-REGEX": "DOMAIN-REGEX", "IP-CIDR": "IP-CIDR", "IP-CIDR6": "IP-CIDR6", "IP6-CIDR": "IP-CIDR6", "GEOIP": "GEOIP",
	"IP-ASN": "IP-ASN", "GEOSITE": "GEOSITE", "DEST-PORT": "DST-PORT", "DST-PORT": "DST-PORT", "SRC-PORT": "SRC-PORT",
	"IN-PORT": "IN-PORT", "SRC-IP": "SRC-IP-CIDR", "SRC-IP-CIDR": "SRC-IP-CIDR", "PROCESS-NAME": "PROCESS-NAME",
	"PROCESS-PATH": "PROCESS-PATH", "NETWORK": "NETWORK", "IP-SUFFIX": "IP-SUFFIX", "SRC-GEOIP": "SRC-GEOIP",
	"SRC-IP-ASN": "SRC-IP-ASN", "DSCP": "DSCP", "UID": "UID", "IN-TYPE": "IN-TYPE", "IN-NAME": "IN-NAME",
	// Quantumult X filter types
	"HOST": "DOMAIN", "HOST-SUFFIX": "DOMAIN-SUFFIX", "HOST-KEYWORD": "DOMAIN-KEYWORD", "HOST-WILDCARD": "DOMAIN-WILDCARD",
	"IP6-CIDR6": "IP-CIDR6",
}

var unsupportedTypes = map[string]string{
	"USER-AGENT":     "mihomo 不支持 USER-AGENT 规则（可用 MitM 重写代替）",
	"URL-REGEX":      "mihomo 规则不匹配 URL；REJECT 类策略会转为 MitM URL 重写",
	"CELLULAR-RADIO": "iOS 扩展内无法获取蜂窝制式",
	"DEVICE-NAME":    "不支持",
	"SUBNET":         "不支持（Surge 网络条件规则）",
	"SCRIPT":         "不支持脚本规则",
	"HOSTNAME-TYPE":  "不支持",
}

// splitTop splits on commas outside parentheses.
func splitTop(s string) []string {
	var out []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	out = append(out, strings.TrimSpace(s[start:]))
	return out
}

// convertLogicBody converts "((DOMAIN,a),(DEST-PORT,443))" type names recursively.
func convertLogicBody(body string) (string, error) {
	body = strings.TrimSpace(body)
	if !strings.HasPrefix(body, "(") || !strings.HasSuffix(body, ")") {
		return "", fmt.Errorf("逻辑规则格式错误")
	}
	inner := body[1 : len(body)-1]
	var parts []string
	for _, sub := range splitTop(inner) {
		sub = strings.TrimSpace(sub)
		if !strings.HasPrefix(sub, "(") || !strings.HasSuffix(sub, ")") {
			return "", fmt.Errorf("逻辑规则子项格式错误：%s", sub)
		}
		fields := splitTop(sub[1 : len(sub)-1])
		t := strings.ToUpper(fields[0])
		if t == "AND" || t == "OR" || t == "NOT" {
			if len(fields) < 2 {
				return "", fmt.Errorf("逻辑规则缺少条件")
			}
			nb, err := convertLogicBody(strings.Join(fields[1:], ","))
			if err != nil {
				return "", err
			}
			parts = append(parts, "("+t+","+nb+")")
			continue
		}
		if t == "PROTOCOL" && len(fields) > 1 {
			p := strings.ToUpper(fields[1])
			if p == "UDP" || p == "QUIC" {
				parts = append(parts, "(NETWORK,UDP)")
			} else {
				parts = append(parts, "(NETWORK,TCP)")
			}
			continue
		}
		mt, ok := surgeTypeMap[t]
		if !ok {
			if why, bad := unsupportedTypes[t]; bad {
				return "", fmt.Errorf("%s：%s", t, why)
			}
			return "", fmt.Errorf("不支持的规则类型 %s", t)
		}
		if len(fields) < 2 {
			return "", fmt.Errorf("%s 缺少内容", t)
		}
		parts = append(parts, "("+mt+","+fixValue(mt, fields[1])+")")
	}
	return "(" + strings.Join(parts, ",") + ")", nil
}

func fixValue(t, v string) string {
	v = strings.TrimSpace(v)
	switch t {
	case "SRC-IP-CIDR", "IP-CIDR", "IP-CIDR6":
		if !strings.Contains(v, "/") {
			if a, err := netip.ParseAddr(v); err == nil {
				if a.Is4() {
					return v + "/32"
				}
				return v + "/128"
			}
		}
	case "IP-ASN", "SRC-IP-ASN":
		return strings.TrimPrefix(strings.ToUpper(v), "AS")
	}
	return v
}

func noResolve(opts []string) string {
	for _, o := range opts {
		if strings.EqualFold(strings.TrimSpace(o), "no-resolve") {
			return ",no-resolve"
		}
	}
	return ""
}

// ConvertRuleLine translates one Surge / QX / Loon / Stash / mihomo rule line. Comments return an
// empty Rule and no error.
func ConvertRuleLine(line string) (RuleConv, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
		return RuleConv{}, nil
	}
	line = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "- "), "-"))
	parts := splitTop(line)
	t := strings.ToUpper(parts[0])
	switch t {
	case "FINAL", "MATCH":
		pol := "DIRECT"
		if len(parts) > 1 {
			pol = parts[1]
		}
		return RuleConv{Type: "MATCH", Rule: "MATCH", Policy: pol}, nil
	case "AND", "OR", "NOT":
		if len(parts) < 3 {
			return RuleConv{}, fmt.Errorf("逻辑规则缺少策略")
		}
		body, err := convertLogicBody(parts[1])
		if err != nil {
			return RuleConv{Unsupported: err.Error()}, err
		}
		return RuleConv{Type: t, Rule: t + "," + body, Policy: parts[2]}, nil
	case "RULE-SET", "DOMAIN-SET":
		if len(parts) < 3 {
			return RuleConv{}, fmt.Errorf("%s 缺少策略", t)
		}
		src := parts[1]
		kind := "list"
		if t == "DOMAIN-SET" {
			kind = "domainset"
		}
		if strings.Contains(src, "://") {
			return RuleConv{Type: "RULE-SET", Policy: parts[2], RemoteURL: src, RemoteKind: kind, Options: noResolve(parts[3:])}, nil
		}
		if strings.EqualFold(src, "SYSTEM") || strings.EqualFold(src, "LAN") {
			return RuleConv{Type: "GEOIP", Rule: "GEOIP,private", Policy: parts[2], Note: "Surge 内置 LAN/SYSTEM 规则集按 GEOIP,private 处理", Options: ",no-resolve"}, nil
		}
		return RuleConv{Type: "RULE-SET", Rule: "RULE-SET," + src, Policy: parts[2], Options: noResolve(parts[3:])}, nil
	case "PROTOCOL":
		if len(parts) < 3 {
			return RuleConv{}, fmt.Errorf("PROTOCOL 缺少策略")
		}
		n := "TCP"
		if p := strings.ToUpper(parts[1]); p == "UDP" || p == "QUIC" {
			n = "UDP"
		}
		return RuleConv{Type: "NETWORK", Rule: "NETWORK," + n, Policy: parts[2], Note: "PROTOCOL 近似为 NETWORK"}, nil
	}
	if why, bad := unsupportedTypes[t]; bad {
		pol := ""
		if len(parts) > 2 {
			pol = parts[2]
		}
		return RuleConv{Type: t, Policy: pol, Unsupported: why}, fmt.Errorf("%s：%s", t, why)
	}
	mt, ok := surgeTypeMap[t]
	if !ok {
		return RuleConv{Type: t, Unsupported: "不支持的规则类型 " + parts[0]}, fmt.Errorf("不支持的规则类型 %s", parts[0])
	}
	if len(parts) < 3 {
		return RuleConv{}, fmt.Errorf("%s 缺少策略", t)
	}
	c := RuleConv{Type: mt, Rule: mt + "," + fixValue(mt, parts[1]), Policy: parts[2], Options: noResolve(parts[3:])}
	if mt == "PROCESS-NAME" || mt == "PROCESS-PATH" || mt == "UID" {
		c.Note = "iOS 上无法识别进程，该规则不会命中"
	}
	return c, nil
}

// ResolvePolicy maps a Surge / QX policy name onto the profile: built-ins, then groups / proxies
// (case-insensitive), then QX's generic "proxy" → the profile's first select group.
func ResolvePolicy(name string, groups []string, proxies []string, firstSelect string) (string, bool) {
	n := strings.TrimSpace(name)
	u := strings.ToUpper(n)
	switch {
	case u == "DIRECT":
		return "DIRECT", true
	case u == "REJECT-DROP":
		return "REJECT-DROP", true
	case strings.HasPrefix(u, "REJECT"):
		return "REJECT", true
	case u == "PASS":
		return "PASS", true
	}
	for _, g := range groups {
		if g == n {
			return g, true
		}
	}
	for _, g := range groups {
		if strings.EqualFold(g, n) {
			return g, true
		}
	}
	for _, p := range proxies {
		if strings.EqualFold(p, n) {
			return p, true
		}
	}
	if (u == "PROXY" || u == "PROXIES") && firstSelect != "" {
		return firstSelect, true
	}
	return "", false
}

// ProfileNames lists group and proxy names and the first select group of a raw config map.
func ProfileNames(raw map[string]any) (groups, proxies []string, firstSelect string) {
	if gl, ok := raw["proxy-groups"].([]any); ok {
		for _, x := range gl {
			if m, ok := x.(map[string]any); ok {
				n, _ := m["name"].(string)
				if n == "" || n == ProxyName {
					continue
				}
				groups = append(groups, n)
				if t, _ := m["type"].(string); firstSelect == "" && strings.EqualFold(t, "select") {
					firstSelect = n
				}
			}
		}
	}
	if pl, ok := raw["proxies"].([]any); ok {
		for _, x := range pl {
			if m, ok := x.(map[string]any); ok {
				if n, _ := m["name"].(string); n != "" && n != ProxyName {
					proxies = append(proxies, n)
				}
			}
		}
	}
	return
}

// ConvertListLine converts one line of a remote rule list (Surge RULE-SET .list, Loon / Stash classical
// lists, QX filter_remote) to mihomo classical text (no policy). DOMAIN-SET lines map to domain text.
func ConvertListLine(line, kind string) (string, bool) {
	l := strings.TrimSpace(line)
	if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, ";") || strings.HasPrefix(l, "//") || l == "payload:" {
		return "", false
	}
	l = strings.TrimSpace(strings.TrimPrefix(l, "- "))
	l = strings.Trim(l, `'"`)
	if kind == "domainset" {
		if strings.HasPrefix(l, ".") {
			return "+" + l, true
		}
		return l, true
	}
	parts := splitTop(l)
	if len(parts) < 2 {
		// v0.13: Clash / Stash ipcidr providers list bare CIDRs (or addresses).
		if pfx, err := netip.ParsePrefix(l); err == nil {
			if pfx.Addr().Is4() {
				return "IP-CIDR," + pfx.Masked().String() + ",no-resolve", true
			}
			return "IP-CIDR6," + pfx.Masked().String() + ",no-resolve", true
		}
		if a, err := netip.ParseAddr(l); err == nil {
			if a.Is4() {
				return "IP-CIDR," + a.String() + "/32,no-resolve", true
			}
			return "IP-CIDR6," + a.String() + "/128,no-resolve", true
		}
		if !strings.ContainsAny(l, " ,") && strings.Contains(l, ".") {
			return "DOMAIN," + l, true
		}
		return "", false
	}
	t := strings.ToUpper(parts[0])
	var withPol string
	if t == "AND" || t == "OR" || t == "NOT" {
		withPol = parts[0] + "," + parts[1] + ",X"
	} else {
		// QX lines carry a policy as the 3rd field ("host-suffix, a.com, proxy"); Surge lists may carry options.
		opts := []string{}
		for _, o := range parts[2:] {
			if strings.EqualFold(o, "no-resolve") {
				opts = append(opts, o)
			}
		}
		withPol = strings.Join(append([]string{parts[0], parts[1], "X"}, opts...), ",")
	}
	c, err := ConvertRuleLine(withPol)
	if err != nil || c.Rule == "" || c.Type == "MATCH" || c.RemoteURL != "" {
		return "", false
	}
	return c.Rule + c.Options, true
}
