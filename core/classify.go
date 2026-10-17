package libmihomo

import (
	"regexp"
	"strings"

	"github.com/astemo6/mihomo-android/core/mitm"
)

// qxConfSectionRe: sections only a full Quantumult X config has (modules / snippets never do).
var qxConfSectionRe = regexp.MustCompile(`(?mi)^[ \t]*\[(server_local|server_remote|policy|filter_local|filter_remote)\][ \t]*\r?$`)

// isQXConf reports whether text is a full Quantumult X configuration.
func isQXConf(t string) bool { return qxConfSectionRe.MatchString(t) }

var (
	classifyConfRe  = regexp.MustCompile(`(?mi)^[ \t]*\[(Proxy|Proxy Group|General|server_local|server_remote|policy|filter_local|filter_remote)\][ \t]*\r?$`)
	moduleSectionRe = regexp.MustCompile(`(?mi)^\[(Script|URL Rewrite|Header Rewrite|Body Rewrite|Map Local|MITM|Rule|Rewrite|rewrite_local|mitm|Panel|task_local|Plugin)\]\s*$`)
)

// ClassifyText tells the app what pasted / opened text is, so it can route it into the one internal
// model: "profile" (mihomo / Clash YAML), "conf" (a full Surge / QX config), "module:<format>"
// (Surge / QX / Loon / Stash / Egern module or rewrite snippet), "nodes" (share links / proxy
// lines, or a Shadowsocks SIP008
// JSON document) or "" (not recognised).
func ClassifyText(text string) string {
	t := strings.TrimSpace(strings.TrimPrefix(text, "\ufeff"))
	if t == "" {
		return ""
	}
	if looksSIP008(t) { // Shadowsocks SIP008 online config (JSON)
		return "nodes"
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
	if classifyConfRe.MatchString(t) {
		return "conf"
	}
	if moduleSectionRe.MatchString(t) || strings.HasPrefix(t, "#!name") {
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
	return ""
}
