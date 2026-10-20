package libmihomo

import (
	"regexp"
	"strings"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
)

// qxConfSectionRe: sections only a full Quantumult X config has (modules / snippets never do).
var qxConfSectionRe = regexp.MustCompile(`(?mi)^[ \t]*\[(server_local|server_remote|policy|filter_local|filter_remote)\][ \t]*\r?$`)

// isQXConf reports whether text is a full Quantumult X configuration.
func isQXConf(t string) bool { return qxConfSectionRe.MatchString(t) }

var (
	classifyConfRe = regexp.MustCompile(`(?mi)^[ \t]*\[(Proxy|Proxy Group|General|server_local|server_remote|policy|filter_local|filter_remote)\][ \t]*\r?$`)
	// v0.19.11 (review 6 P1-1): sections only full configs have; a module never carries nodes or groups.
	confOnlySectionRe = regexp.MustCompile(`(?mi)^[ \t]*\[(Proxy|Proxy Group|server_local|server_remote)\][ \t]*\r?$`)
	moduleSectionRe   = regexp.MustCompile(`(?mi)^\[(Script|URL Rewrite|Header Rewrite|Body Rewrite|Map Local|MITM|Rule|Rewrite|rewrite_local|mitm|Panel|task_local|Plugin)\]\s*$`)
)

// ClassifyText tells the app what pasted / opened text is, so it can route it into the one internal
// model: "profile" (mihomo / Clash YAML), "conf" (a full Surge / QX config), "module:<format>"
// (Surge / QX / Loon / Stash / Egern module or rewrite snippet), "nodes" (share links / proxy
// lines) or "" (not recognised).
func ClassifyText(text string) string {
	t := strings.TrimSpace(strings.TrimPrefix(text, "\ufeff"))
	if t == "" {
		return ""
	}
	if isQXConf(t) {
		return "conf"
	}
	if mitm.IsEgern(t) {
		return "module:egern"
	}
	if strings.Contains(t, "\nhttp:") || strings.HasPrefix(t, "http:\n") || strings.Contains(t, "script-providers:") {
		return "module:stash"
	}
	if strings.Contains(t, "proxies:") || strings.Contains(t, "proxy-providers:") || strings.Contains(t, "proxy-groups:") {
		return "profile"
	}
	if mitm.IsStash(t) {
		return "module:stash" // v0.13: rules-only / rule-providers overrides
	}
	// v0.19.9: a module header wins over [General] (BoxJS's Surge module has a [General] section with
	// force-http-engine-hosts and was taken for a full config).
	// v0.19.11 (review 6 P1-1): but #!MANAGED-CONFIG (the first line of nearly every Surge subscription) is a
	// config marker, and [Proxy] / [Proxy Group] only exist in full configs.
	if classifyConfRe.MatchString(t) && (!strings.HasPrefix(t, "#!") || isManagedConf(t) || confOnlySectionRe.MatchString(t)) {
		return "conf"
	}
	if moduleSectionRe.MatchString(t) || strings.HasPrefix(t, "#!") {
		rs := &mitm.Ruleset{}
		rs.ParseText(t, "", nil)
		if rs.Format != "" && rs.Format != "list" {
			return "module:" + rs.Format
		}
		return "module:surge"
	}
	if ps, _ := parseNodeText(t); len(ps) > 0 {
		return "nodes"
	}
	// v0.19.9: section-less rewrite snippets (QX `.snippet`, e.g. Sub-Store's QX.snippet:
	// `hostname=…` + `… url script-analyze-echo-response …`) and QX task gallery JSON (QX-Task.json).
	rs := &mitm.Ruleset{}
	rs.ParseText(t, "", nil)
	if len(rs.Tasks) > 0 || (len(rs.Rules) > 0 && len(rs.Hostnames) > 0) {
		f := rs.Format
		if f == "" || f == "list" {
			f = "qx"
		}
		return "module:" + f
	}
	return ""
}

// isManagedConf: Surge's managed-profile header ("#!MANAGED-CONFIG <url> interval=… strict=…").
func isManagedConf(t string) bool {
	return len(t) >= 16 && strings.EqualFold(t[:16], "#!MANAGED-CONFIG")
}
