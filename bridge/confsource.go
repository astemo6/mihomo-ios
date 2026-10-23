package libmihomo

// P0-1 (v0.19.17): Quantumult X / Surge configs must keep their policy groups and rules wherever they enter
// the app, and rules the import could not carry over must stay recoverable.
//
//   - ConvertShareLinks is what ProfileStore.normalize runs on every downloaded 配置订阅 body that is not
//     mihomo YAML. A QX / Surge config there used to be read as a list of node lines: the nodes survived, every
//     [policy] group and every filter_local / filter_remote rule (e.g. the WeChat list on 微信消息) was
//     replaced by a generic 节点选择 + GEOIP,CN template, silently, on each refresh. Full configs now go
//     through ImportConf; the import report is kept as comments at the top of the profile.
//   - SaveConfSource keeps the original text of an imported .conf next to the profile (<profile>.source.conf);
//     RestoreConfRules re-imports it and puts back rule lists / rules / policy groups that the profile no
//     longer has (lost on an older build, deleted by an edit, …). ForgetProfile removes the sidecar.

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

// confProfileFormat reports "qx" / "surge" when text is a whole QX / Surge config (with policy groups or
// rules), "" otherwise. A Surge [Proxy]-only node list is left to the node-line converter.
func confProfileFormat(text string) string {
	if !strings.Contains(text, "[") {
		return ""
	}
	has := map[string]bool{}
	for _, raw := range strings.Split(strings.TrimPrefix(text, "\ufeff"), "\n") {
		t := strings.TrimSpace(raw)
		if !strings.HasPrefix(t, "[") || len(t) > 64 {
			continue
		}
		if m := confSectionRe.FindStringSubmatch(t); m != nil {
			has[strings.ToLower(strings.TrimSpace(m[1]))] = true
		}
	}
	switch {
	case has["filter_local"] || has["filter_remote"] || has["policy"]:
		return "qx"
	case has["rule"] || has["proxy group"]:
		return "surge"
	}
	return ""
}

// confAsProfile converts a whole QX / Surge config for a profile file: the YAML with the import report as
// leading comments (rules the conversion left out are listed there, never dropped silently).
func confAsProfile(text string) (string, bool) {
	res := importConf(text)
	if res.Error != "" || strings.TrimSpace(res.YAML) == "" {
		return "", false
	}
	var head strings.Builder
	name := "Surge"
	if res.Report.Format == "qx" {
		name = "Quantumult X"
	}
	head.WriteString("# Tern: converted from a " + name + " config (" + name + " 配置转换)\n")
	line := func(s string) {
		s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
		head.WriteString("#   " + s + "\n")
	}
	if res.Report.RulesSkipped > 0 {
		line(fmt.Sprintf("未导入的分流规则 / 规则列表：%d", res.Report.RulesSkipped))
	}
	if res.Module != "" || len(res.RewriteRemotes) > 0 {
		line("重写 / MitM / 脚本段不随配置订阅导入；需要时请用「导入配置」导入该文件")
	}
	for _, n := range res.Report.Notes {
		line("说明：" + n)
	}
	for _, s := range res.Report.Skipped {
		line("未转换：" + s)
	}
	return head.String() + res.YAML, true
}

func confSourcePath(profilePath string) string { return profilePath + ".source.conf" }

// SaveConfSource stores the original .conf text of an imported profile next to it. Returns "" or an error.
func SaveConfSource(profilePath, text string) string {
	if profilePath == "" || strings.TrimSpace(text) == "" {
		return ""
	}
	if err := writeFileAtomic(confSourcePath(profilePath), []byte(text)); err != nil {
		return err.Error()
	}
	return ""
}

// HasConfSource reports whether an imported profile still has its original .conf.
func HasConfSource(profilePath string) bool {
	st, err := os.Stat(confSourcePath(profilePath))
	return err == nil && st.Size() > 0
}

type restoreResult struct {
	Providers []string `json:"providers"` // rule lists put back
	Groups    []string `json:"groups"`    // policy groups put back
	Rules     []string `json:"rules"`     // rules put back
	Skipped   []string `json:"skipped"`   // still not importable (with the reason from the import report)
	Error     string   `json:"error,omitempty"`
}

// RestoreConfRules re-imports the profile's original .conf (SaveConfSource) and puts back what the profile
// lacks: rule-providers (matched by source URL), the rules that use them, other rules of the original, and
// the policy groups those rules need. apply=false only reports. The profile is written only when something
// is restored. Returns JSON restoreResult.
func RestoreConfRules(profilePath string, apply bool) string {
	out := restoreResult{Providers: []string{}, Groups: []string{}, Rules: []string{}, Skipped: []string{}}
	done := func() string { b, _ := json.Marshal(out); return string(b) }
	src, err := os.ReadFile(confSourcePath(profilePath))
	if err != nil || len(strings.TrimSpace(string(src))) == 0 {
		out.Error = "没有保存这份配置的原始 .conf（v0.19.17 之前导入的配置请重新导入原文件）"
		return done()
	}
	res := importConf(string(src))
	if res.Error != "" {
		out.Error = res.Error
		return done()
	}
	for _, s := range res.Report.Skipped {
		if strings.HasPrefix(s, "[filter_") || strings.HasPrefix(s, "[rule]") || strings.HasPrefix(s, "[policy]") {
			out.Skipped = append(out.Skipped, s)
		}
	}
	unlock := lockPath(profilePath)
	defer unlock()
	cur, err := os.ReadFile(profilePath)
	if err != nil {
		out.Error = err.Error()
		return done()
	}
	raw := map[string]any{}
	if err := yaml.Unmarshal(cur, &raw); err != nil || raw == nil {
		out.Error = "配置无法解析"
		return done()
	}
	imp := map[string]any{}
	if err := yaml.Unmarshal([]byte(res.YAML), &imp); err != nil {
		out.Error = err.Error()
		return done()
	}
	changed := restoreInto(raw, imp, &out)
	if !changed || !apply {
		return done()
	}
	b, err := yaml.Marshal(raw)
	if err == nil {
		err = writeFileAtomic(profilePath, b)
	}
	if err != nil {
		out.Error = err.Error()
	}
	return done()
}

// restoreInto merges the missing parts of imp (a fresh import) into raw (the profile). See RestoreConfRules.
func restoreInto(raw, imp map[string]any, out *restoreResult) bool {
	changed := false
	curRP, _ := raw["rule-providers"].(map[string]any)
	if curRP == nil {
		curRP = map[string]any{}
	}
	impRP, _ := imp["rule-providers"].(map[string]any)
	srcOf := func(v any) string {
		m, _ := v.(map[string]any)
		if s := str(m["x-source"]); s != "" {
			return s
		}
		_, u := providerConvert(m)
		return u
	}
	byURL := map[string]string{} // source URL → provider name in the profile
	for n, v := range curRP {
		if u := srcOf(v); u != "" {
			byURL[u] = n
		}
	}
	rename := map[string]string{} // imported provider name → name in the profile
	for n, v := range impRP {
		u := srcOf(v)
		if have, ok := byURL[u]; ok && u != "" {
			rename[n] = have
			continue
		}
		nn := uniqueProviderName(n, func(s string) bool { _, ok := curRP[s]; return ok })
		curRP[nn] = v
		rename[n] = nn
		byURL[u] = nn
		out.Providers = append(out.Providers, nn)
		changed = true
	}
	if len(curRP) > 0 {
		raw["rule-providers"] = curRP
	}

	groupsOf := func(m map[string]any) ([]any, map[string]map[string]any) {
		gl, _ := m["proxy-groups"].([]any)
		by := map[string]map[string]any{}
		for _, g := range gl {
			if gm, ok := g.(map[string]any); ok {
				by[str(gm["name"])] = gm
			}
		}
		return gl, by
	}
	curGL, curG := groupsOf(raw)
	_, impG := groupsOf(imp)
	proxyNames := map[string]bool{}
	if pl, ok := raw["proxies"].([]any); ok {
		for _, p := range pl {
			if pm, ok := p.(map[string]any); ok {
				proxyNames[str(pm["name"])] = true
			}
		}
	}
	builtin := func(p string) bool {
		u := strings.ToUpper(p)
		return u == "DIRECT" || u == "PASS" || u == "COMPATIBLE" || strings.HasPrefix(u, "REJECT")
	}
	// ensureGroup puts back a policy group of the original (members limited to what the profile has).
	var ensureGroup func(name string, depth int) bool
	ensureGroup = func(name string, depth int) bool {
		if builtin(name) || curG[name] != nil || proxyNames[name] {
			return true
		}
		g := impG[name]
		if g == nil || depth > 4 {
			return false
		}
		ng := map[string]any{}
		for k, v := range g {
			ng[k] = v
		}
		var mem []any
		if list, ok := g["proxies"].([]any); ok {
			for _, x := range list {
				s := fmt.Sprint(x)
				if s != name && ensureGroup(s, depth+1) {
					mem = append(mem, s)
				}
			}
		}
		if use, ok := g["use"].([]any); ok {
			pp, _ := raw["proxy-providers"].(map[string]any)
			var keep []any
			for _, u := range use {
				if _, ok := pp[fmt.Sprint(u)]; ok {
					keep = append(keep, u)
				}
			}
			if len(keep) > 0 {
				ng["use"] = keep
			} else {
				delete(ng, "use")
			}
		}
		if len(mem) == 0 && ng["use"] == nil && ng["include-all"] == nil && ng["include-all-proxies"] == nil && ng["include-all-providers"] == nil {
			mem = []any{"DIRECT"}
		}
		if len(mem) > 0 {
			ng["proxies"] = mem
		} else {
			delete(ng, "proxies")
		}
		curGL = append(curGL, ng)
		curG[name] = ng
		out.Groups = append(out.Groups, name)
		changed = true
		return true
	}

	curRules := asList(raw["rules"])
	key := func(r string) string {
		f := strings.Split(r, ",")
		for i := range f {
			f[i] = strings.TrimSpace(f[i])
		}
		if len(f) >= 2 && strings.EqualFold(f[0], "RULE-SET") {
			if u := srcOf(curRP[f[1]]); u != "" {
				f[1] = "<" + u + ">"
			}
		}
		return strings.ToUpper(f[0]) + "," + strings.Join(f[1:], ",")
	}
	have := map[string]int{}
	for i, r := range curRules {
		if s, ok := r.(string); ok {
			have[key(s)] = i
		}
	}
	matchIdx := -1
	for i, r := range curRules {
		if s, ok := r.(string); ok && strings.HasPrefix(strings.ToUpper(strings.TrimSpace(s)), "MATCH,") {
			matchIdx = i
		}
	}
	pos := -1 // insert after the last rule of the original that the profile has
	for _, r := range asList(imp["rules"]) {
		s, ok := r.(string)
		if !ok {
			continue
		}
		f := strings.Split(s, ",")
		if strings.EqualFold(strings.TrimSpace(f[0]), "RULE-SET") && len(f) >= 3 {
			if nn, ok := rename[strings.TrimSpace(f[1])]; ok {
				f[1] = nn
			}
			s = strings.Join(f, ",")
		}
		if strings.HasPrefix(strings.ToUpper(s), "MATCH,") {
			continue // the profile keeps its own final rule
		}
		if i, ok := have[key(s)]; ok {
			pos = i
			continue
		}
		pf := strings.Split(s, ",")
		pol := ""
		if len(pf) >= 3 {
			pol = strings.TrimSpace(pf[2])
		}
		if logical := strings.ToUpper(strings.TrimSpace(pf[0])); logical == "AND" || logical == "OR" || logical == "NOT" {
			continue // logical rules (udp_drop_list …) are settings, not lost rules
		}
		if pol == "" || !ensureGroup(pol, 0) {
			out.Skipped = append(out.Skipped, s+" — 策略「"+pol+"」在配置中不存在")
			continue
		}
		at := pos + 1
		if at <= 0 {
			at = 0
		}
		if matchIdx >= 0 && at > matchIdx {
			at = matchIdx
		}
		curRules = append(curRules[:at], append([]any{s}, curRules[at:]...)...)
		if matchIdx >= at {
			matchIdx++
		}
		for k, v := range have {
			if v >= at {
				have[k] = v + 1
			}
		}
		have[key(s)] = at
		pos = at
		out.Rules = append(out.Rules, s)
		changed = true
	}
	if changed {
		raw["rules"] = curRules
		raw["proxy-groups"] = curGL
	}
	return changed
}
