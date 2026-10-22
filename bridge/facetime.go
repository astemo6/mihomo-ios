package libmihomo

// 连接方式 → FaceTime 走代理 (user 2026-10-22). The app turns includeAllNetworks on and keeps APNs inside the
// tunnel; here the FaceTime signalling (APNs, Apple ID identity services) and media ports are sent to the
// profile's main proxy group, ahead of every other rule.

import (
	"strings"

	"github.com/metacubex/mihomo/log"
)

var faceTimeMatchers = []string{
	"DOMAIN-SUFFIX,push.apple.com",
	"DOMAIN-SUFFIX,push-apple.com.akadns.net",
	"DOMAIN-SUFFIX,ess.apple.com",
	"DOMAIN-SUFFIX,facetime.apple.com",
	"DOMAIN-SUFFIX,ids.apple.com",
	"AND,((NETWORK,TCP),(DST-PORT,5223))",
	"AND,((NETWORK,UDP),(DST-PORT,3478-3497))",
	"AND,((NETWORK,UDP),(DST-PORT,16384-16387))",
	"AND,((NETWORK,UDP),(DST-PORT,16393-16402))",
}

func applyFaceTimeRules(raw map[string]any) {
	pol := faceTimePolicy(raw)
	if pol == "" {
		log.Warnln("[FaceTime] no proxy group or node in the profile; FaceTime rules not added")
		return
	}
	pre := make([]any, 0, len(faceTimeMatchers))
	for _, m := range faceTimeMatchers {
		pre = append(pre, m+","+pol)
	}
	existing, _ := raw["rules"].([]any)
	raw["rules"] = append(pre, existing...)
	stage("FaceTime 走代理: %d rules → %s", len(pre), pol)
}

// faceTimePolicy: the MATCH rule's target when it is a proxy group, else the first select group, else the first
// group, else the first node.
func faceTimePolicy(raw map[string]any) string {
	groups := map[string]bool{}
	var firstSelect, firstGroup string
	for _, g := range asList(raw["proxy-groups"]) {
		m, _ := g.(map[string]any)
		name := str(m["name"])
		if name == "" {
			continue
		}
		groups[name] = true
		if firstGroup == "" {
			firstGroup = name
		}
		if firstSelect == "" && str(m["type"]) == "select" {
			firstSelect = name
		}
	}
	rules := asList(raw["rules"])
	for i := len(rules) - 1; i >= 0; i-- {
		r := strings.TrimSpace(str(rules[i]))
		if strings.HasPrefix(r, "MATCH,") || strings.HasPrefix(r, "FINAL,") {
			t := strings.TrimSpace(strings.SplitN(r, ",", 3)[1])
			if groups[t] {
				return t
			}
			break
		}
	}
	if firstSelect != "" {
		return firstSelect
	}
	if firstGroup != "" {
		return firstGroup
	}
	for _, p := range asList(raw["proxies"]) {
		if m, ok := p.(map[string]any); ok && str(m["name"]) != "" {
			return str(m["name"])
		}
	}
	return ""
}
