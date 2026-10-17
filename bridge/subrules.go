package libmihomo

// Subscription management (Loon / Sub-Store style node processing).
//
// Rules live in our override store (<home>/subscriptions.json, keyed by profile id) and are applied
// while the runtime config is built — the downloaded profile file itself is never modified, so a
// subscription refresh keeps the user's rules. Order: filter → strip → rename → flag → dedupe → sort.
// Inline `proxies` get the full pipeline; proxy-providers get the parts mihomo supports natively
// (filter / exclude-filter / override.proxy-name / override.additional-prefix).

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/dlclark/regexp2"
	"go.yaml.in/yaml/v3"
)

// RenameRule is one regex replacement applied to node names ($1 / ${name} in Replace).
type RenameRule struct {
	Pattern string `json:"pattern"`
	Replace string `json:"replace"`
	Enabled *bool  `json:"enabled,omitempty"`
}

// SubRules is the per-subscription processing the app edits on the 配置 tab.
type SubRules struct {
	Enabled       bool         `json:"enabled"`
	Include       string       `json:"include,omitempty"` // keep only matching nodes ("" = all)
	Exclude       string       `json:"exclude,omitempty"` // drop matching nodes
	Regex         bool         `json:"regex,omitempty"`   // include/exclude are JS regexes; else keywords split by | or newline
	StripPrefixes []string     `json:"stripPrefixes,omitempty"`
	StripFlags    bool         `json:"stripFlags,omitempty"` // remove existing flag emojis
	Renames       []RenameRule `json:"renames,omitempty"`
	AddFlag       bool         `json:"addFlag,omitempty"` // prefix a flag emoji detected from the name
	Prefix        string       `json:"prefix,omitempty"`  // literal prefix added last
	Dedupe        bool         `json:"dedupe,omitempty"`  // drop nodes with the same type/server/port/credential
	Sort          string       `json:"sort,omitempty"`    // "" keep | name | region
}

func subRulesPath(home string) string { return filepath.Join(home, "subscriptions.json") }

func readAllSubRules(home string) map[string]SubRules {
	m := map[string]SubRules{}
	if home == "" {
		return m
	}
	if b, err := os.ReadFile(subRulesPath(home)); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

// profileIDFromPath: <container>/profiles/<id>.yaml → id.
func profileIDFromPath(path string) string {
	b := filepath.Base(path)
	return strings.TrimSuffix(b, filepath.Ext(b))
}

// overridesFor reads overrides and attaches the subscription rules of the profile at path.
func overridesFor(home, path string) Overrides {
	o := readOverrides(home)
	o.profileID = profileIDFromPath(path)
	if r, ok := readAllSubRules(home)[profileIDFromPath(path)]; ok && r.Enabled {
		rr := r
		o.sub = &rr
	}
	if c := readGroupChains(home, path); len(c) > 0 {
		o.chains = map[string]string{}
		for k, v := range c {
			o.chains[k] = v
		}
	}
	return o
}

// ---------------- regions ----------------

type region struct {
	code string
	re   *regexp2.Regexp
}

func flagOf(code string) string {
	if len(code) != 2 {
		return ""
	}
	r := []rune{}
	for _, c := range strings.ToUpper(code) {
		r = append(r, 0x1F1E6+(c-'A'))
	}
	return string(r)
}

// Order = sort order for Sort=="region". Two-letter codes only match as standalone tokens.
var regionDefs = []struct{ code, pat string }{
	{"HK", `香港|深港|沪港|呼港|广港|京港|🇭🇰|Hong\s?Kong|(?<![A-Za-z])HKG?(?![A-Za-z])`},
	{"MO", `澳门|澳門|🇲🇴|Macau|Macao|(?<![A-Za-z])MO(?![A-Za-z])`},
	{"TW", `台湾|台灣|臺灣|台北|新北|彰化|🇹🇼|Taiwan|(?<![A-Za-z])TWN?(?![A-Za-z])`},
	{"JP", `日本|东京|東京|大阪|埼玉|名古屋|🇯🇵|Japan|Tokyo|Osaka|(?<![A-Za-z])JPN?(?![A-Za-z])`},
	{"SG", `新加坡|狮城|獅城|🇸🇬|Singapore|(?<![A-Za-z])SGP?(?![A-Za-z])`},
	{"KR", `韩国|韓國|首尔|首爾|春川|🇰🇷|Korea|Seoul|(?<![A-Za-z])KO?R(?![A-Za-z])`},
	{"US", `美国|美國|洛杉矶|洛杉磯|圣何塞|聖何塞|硅谷|矽谷|西雅图|芝加哥|纽约|紐約|达拉斯|凤凰城|波特兰|🇺🇸|United\s?States|America|Los\s?Angeles|San\s?Jose|Silicon|Seattle|Chicago|New\s?York|(?<![A-Za-z])USA?(?![A-Za-z])`},
	{"CA", `加拿大|多伦多|温哥华|蒙特利尔|🇨🇦|Canada|Toronto|Vancouver|(?<![A-Za-z])CAN?(?![A-Za-z])`},
	{"GB", `英国|英國|伦敦|倫敦|🇬🇧|United\s?Kingdom|Britain|London|(?<![A-Za-z])(UK|GB)(?![A-Za-z])`},
	{"DE", `德国|德國|法兰克福|🇩🇪|Germany|Frankfurt|(?<![A-Za-z])DEU?(?![A-Za-z])`},
	{"FR", `法国|法國|巴黎|🇫🇷|France|Paris|(?<![A-Za-z])FRA?(?![A-Za-z])`},
	{"NL", `荷兰|荷蘭|阿姆斯特丹|🇳🇱|Netherlands|Amsterdam|(?<![A-Za-z])NLD?(?![A-Za-z])`},
	{"RU", `俄罗斯|俄羅斯|莫斯科|🇷🇺|Russia|Moscow|(?<![A-Za-z])RUS?(?![A-Za-z])`},
	{"IN", `印度(?!尼)|孟买|🇮🇳|India|Mumbai|(?<![A-Za-z])IND(?![A-Za-z])`},
	{"AU", `澳大利亚|澳洲|悉尼|墨尔本|🇦🇺|Australia|Sydney|(?<![A-Za-z])AUS?(?![A-Za-z])`},
	{"TR", `土耳其|伊斯坦布尔|🇹🇷|Turkey|Türkiye|Istanbul|(?<![A-Za-z])TUR?(?![A-Za-z])`},
	{"MY", `马来西亚|馬來西亞|吉隆坡|🇲🇾|Malaysia|(?<![A-Za-z])MYS?(?![A-Za-z])`},
	{"TH", `泰国|泰國|曼谷|🇹🇭|Thailand|Bangkok|(?<![A-Za-z])THA?(?![A-Za-z])`},
	{"VN", `越南|胡志明|河内|🇻🇳|Vietnam|(?<![A-Za-z])VNM?(?![A-Za-z])`},
	{"PH", `菲律宾|菲律賓|马尼拉|🇵🇭|Philippines|Manila|(?<![A-Za-z])PHL?(?![A-Za-z])`},
	{"ID", `印尼|印度尼西亚|雅加达|🇮🇩|Indonesia|Jakarta|(?<![A-Za-z])IDN(?![A-Za-z])`},
	{"AR", `阿根廷|🇦🇷|Argentina|(?<![A-Za-z])ARG(?![A-Za-z])`},
	{"BR", `巴西|圣保罗|🇧🇷|Brazil|(?<![A-Za-z])BRA(?![A-Za-z])`},
	{"IT", `意大利|義大利|米兰|🇮🇹|Italy|Milan|(?<![A-Za-z])ITA(?![A-Za-z])`},
	{"ES", `西班牙|马德里|🇪🇸|Spain|Madrid|(?<![A-Za-z])ESP(?![A-Za-z])`},
	{"CH", `瑞士|苏黎世|🇨🇭|Switzerland|Zurich|(?<![A-Za-z])CHE(?![A-Za-z])`},
	{"SE", `瑞典|🇸🇪|Sweden|(?<![A-Za-z])SWE(?![A-Za-z])`},
	{"PL", `波兰|波蘭|🇵🇱|Poland|(?<![A-Za-z])POL(?![A-Za-z])`},
	{"UA", `乌克兰|烏克蘭|🇺🇦|Ukraine|(?<![A-Za-z])UKR(?![A-Za-z])`},
	{"IE", `爱尔兰|愛爾蘭|🇮🇪|Ireland|(?<![A-Za-z])IRL(?![A-Za-z])`},
	{"IL", `以色列|🇮🇱|Israel|(?<![A-Za-z])ISR(?![A-Za-z])`},
	{"AE", `阿联酋|迪拜|🇦🇪|Dubai|Emirates|(?<![A-Za-z])UAE(?![A-Za-z])`},
	{"ZA", `南非|🇿🇦|South\s?Africa`},
	{"NG", `尼日利亚|🇳🇬|Nigeria`},
	{"EG", `埃及|🇪🇬|Egypt`},
	{"MX", `墨西哥|🇲🇽|Mexico`},
	{"CL", `智利|🇨🇱|Chile`},
	{"NZ", `新西兰|紐西蘭|🇳🇿|New\s?Zealand`},
	{"KZ", `哈萨克|🇰🇿|Kazakhstan`},
	{"PK", `巴基斯坦|🇵🇰|Pakistan`},
	{"BD", `孟加拉|🇧🇩|Bangladesh`},
	{"KH", `柬埔寨|🇰🇭|Cambodia`},
	{"MN", `蒙古|🇲🇳|Mongolia`},
	{"CN", `中国|中國|回国|回國|国内|國內|🇨🇳|China|(?<![A-Za-z])CHN(?![A-Za-z])`},
}

var regions = func() []region {
	out := make([]region, 0, len(regionDefs))
	for _, d := range regionDefs {
		out = append(out, region{d.code, regexp2.MustCompile(d.pat, regexp2.IgnoreCase)})
	}
	return out
}()

// detectRegion returns the ISO code for a node name and its sort index (len(regions) = unknown).
func detectRegion(name string) (string, int) {
	// An existing flag emoji is the strongest signal.
	if f := firstFlag(name); f != "" {
		for i, r := range regions {
			if flagOf(r.code) == f {
				return r.code, i
			}
		}
	}
	for i, r := range regions {
		if ok, _ := r.re.MatchString(name); ok {
			return r.code, i
		}
	}
	return "", len(regions)
}

func isRegionalIndicator(r rune) bool { return r >= 0x1F1E6 && r <= 0x1F1FF }

func firstFlag(s string) string {
	rs := []rune(s)
	for i := 0; i+1 < len(rs); i++ {
		if isRegionalIndicator(rs[i]) && isRegionalIndicator(rs[i+1]) {
			return string(rs[i : i+2])
		}
	}
	return ""
}

// stripFlagEmojis removes regional-indicator pairs (and the 🏳/🏴 families' trailing modifiers).
func stripFlagEmojis(s string) string {
	var b strings.Builder
	for _, r := range s {
		if isRegionalIndicator(r) || r == 0xFE0F || r == 0x1F3F3 || r == 0x1F3F4 || (r >= 0xE0020 && r <= 0xE007F) {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// ---------------- matching ----------------

type nameMatcher struct {
	re       *regexp2.Regexp
	keywords []string
}

func (m *nameMatcher) empty() bool { return m == nil || (m.re == nil && len(m.keywords) == 0) }

func (m *nameMatcher) match(name string) bool {
	if m.re != nil {
		ok, _ := m.re.MatchString(name)
		return ok
	}
	ln := strings.ToLower(name)
	for _, k := range m.keywords {
		if strings.Contains(ln, k) {
			return true
		}
	}
	return false
}

func splitKeywords(s string) []string {
	var out []string
	for _, k := range strings.FieldsFunc(s, func(r rune) bool { return r == '|' || r == '\n' || r == '\r' }) {
		if k = strings.TrimSpace(k); k != "" {
			out = append(out, strings.ToLower(k))
		}
	}
	return out
}

func newMatcher(expr string, regex bool) (*nameMatcher, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, nil
	}
	if regex {
		re, err := regexp2.Compile(expr, regexp2.IgnoreCase)
		if err != nil {
			return nil, fmt.Errorf("正则无效：%s", err.Error())
		}
		re.MatchTimeout = 0
		return &nameMatcher{re: re}, nil
	}
	return &nameMatcher{keywords: splitKeywords(expr)}, nil
}

// providerFilter turns include/exclude into a mihomo (regexp2) filter pattern.
func providerFilter(expr string, regex bool) string {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return ""
	}
	if regex {
		return "(?i)" + expr
	}
	ks := splitKeywords(expr)
	for i := range ks {
		ks[i] = regexp2.Escape(ks[i])
	}
	return "(?i)(" + strings.Join(ks, "|") + ")"
}

// ---------------- pipeline ----------------

type compiledSub struct {
	r        SubRules
	inc, exc *nameMatcher
	renames  []*regexp2.Regexp
	repl     []string
	errs     []string
}

func compileSub(r SubRules) *compiledSub {
	c := &compiledSub{r: r}
	var err error
	if c.inc, err = newMatcher(r.Include, r.Regex); err != nil {
		c.errs = append(c.errs, "保留："+err.Error())
	}
	if c.exc, err = newMatcher(r.Exclude, r.Regex); err != nil {
		c.errs = append(c.errs, "排除："+err.Error())
	}
	for _, rn := range r.Renames {
		if rn.Enabled != nil && !*rn.Enabled || strings.TrimSpace(rn.Pattern) == "" {
			continue
		}
		re, err := regexp2.Compile(rn.Pattern, 0)
		if err != nil {
			c.errs = append(c.errs, fmt.Sprintf("重命名「%s」：正则无效：%s", rn.Pattern, err.Error()))
			continue
		}
		c.renames = append(c.renames, re)
		c.repl = append(c.repl, rn.Replace)
	}
	return c
}

// rename runs strip → renames → flag → prefix on one name.
func (c *compiledSub) rename(name string) string {
	n := name
	if c.r.StripFlags || c.r.AddFlag {
		n = stripFlagEmojis(n)
	}
	for _, p := range c.r.StripPrefixes {
		if p != "" && strings.HasPrefix(n, p) {
			n = strings.TrimLeftFunc(strings.TrimPrefix(n, p), unicode.IsSpace)
		}
	}
	for i, re := range c.renames {
		if out, err := re.Replace(n, c.repl[i], -1, -1); err == nil {
			n = out
		}
	}
	n = strings.TrimSpace(n)
	if c.r.AddFlag {
		code, _ := detectRegion(name + " " + n)
		if f := flagOf(code); f != "" {
			n = f + " " + n
		}
	}
	if c.r.Prefix != "" {
		n = c.r.Prefix + n
	}
	if n == "" {
		n = name
	}
	return n
}

// PreviewNode is one row of the live preview.
type PreviewNode struct {
	Original string `json:"original"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Region   string `json:"region,omitempty"`
	Kept     bool   `json:"kept"`
	Reason   string `json:"reason,omitempty"` // 未匹配保留规则 / 匹配排除规则 / 重复节点
	Source   string `json:"source,omitempty"` // provider name for cached provider nodes
}

func dedupeKey(p map[string]any) string {
	cred := ""
	for _, k := range []string{"uuid", "password", "auth-str", "auth", "private-key", "psk", "username"} {
		if v := str(p[k]); v != "" {
			cred += k + "=" + v + ";"
		}
	}
	return strings.ToLower(str(p["type"])) + "|" + strings.ToLower(str(p["server"])) + "|" + fmt.Sprint(p["port"]) + "|" + cred
}

// processNodes runs the full pipeline. Returns the kept nodes (renamed in place), the rename map
// old → new for kept nodes, the removed names, and preview rows in original order.
func (c *compiledSub) processNodes(nodes []map[string]any) (kept []map[string]any, renamed map[string]string, removed map[string]bool, rows []PreviewNode) {
	renamed, removed = map[string]string{}, map[string]bool{}
	seenKey := map[string]bool{}
	type item struct {
		node   map[string]any
		row    int
		region int
	}
	var items []item
	for _, p := range nodes {
		orig := str(p["name"])
		row := PreviewNode{Original: orig, Name: orig, Type: strings.ToLower(str(p["type"]))}
		switch {
		case !c.inc.empty() && !c.inc.match(orig):
			row.Reason = "未匹配保留规则"
		case !c.exc.empty() && c.exc.match(orig):
			row.Reason = "匹配排除规则"
		}
		if row.Reason == "" && c.r.Dedupe {
			k := dedupeKey(p)
			if seenKey[k] {
				row.Reason = "重复节点"
			}
			seenKey[k] = true
		}
		if row.Reason != "" {
			removed[orig] = true
			rows = append(rows, row)
			continue
		}
		row.Kept = true
		row.Name = c.rename(orig)
		code, idx := detectRegion(orig + " " + row.Name)
		row.Region = code
		rows = append(rows, row)
		items = append(items, item{p, len(rows) - 1, idx})
	}
	switch c.r.Sort {
	case "name":
		sort.SliceStable(items, func(i, j int) bool { return naturalLess(rows[items[i].row].Name, rows[items[j].row].Name) })
	case "region":
		sort.SliceStable(items, func(i, j int) bool {
			if items[i].region != items[j].region {
				return items[i].region < items[j].region
			}
			return naturalLess(rows[items[i].row].Name, rows[items[j].row].Name)
		})
	}
	// Unique names (mihomo rejects duplicates): append 2, 3, … in final order.
	used := map[string]int{}
	for _, it := range items {
		base := rows[it.row].Name
		n := base
		for k := 1; used[n] > 0; k++ {
			n = fmt.Sprintf("%s %d", base, k+1)
		}
		used[n]++
		rows[it.row].Name = n
		orig := str(it.node["name"])
		if n != orig {
			renamed[orig] = n
		}
		it.node["name"] = n
		kept = append(kept, it.node)
	}
	return
}

// naturalLess compares names so "节点 2" < "节点 10".
func naturalLess(a, b string) bool {
	ra, rb := []rune(a), []rune(b)
	i, j := 0, 0
	for i < len(ra) && j < len(rb) {
		ca, cb := ra[i], rb[j]
		if unicode.IsDigit(ca) && unicode.IsDigit(cb) {
			si := i
			for i < len(ra) && unicode.IsDigit(ra[i]) {
				i++
			}
			sj := j
			for j < len(rb) && unicode.IsDigit(rb[j]) {
				j++
			}
			na := strings.TrimLeft(string(ra[si:i]), "0")
			nb := strings.TrimLeft(string(rb[sj:j]), "0")
			if len(na) != len(nb) {
				return len(na) < len(nb)
			}
			if na != nb {
				return na < nb
			}
			continue
		}
		if ca != cb {
			return ca < cb
		}
		i++
		j++
	}
	return len(ra)-i < len(rb)-j
}

// applySubRules rewrites raw (proxies, groups, rules, providers) in place.
func applySubRules(raw map[string]any, r *SubRules) []string {
	if r == nil || !r.Enabled {
		return nil
	}
	c := compileSub(*r)
	if pl, ok := raw["proxies"].([]any); ok && len(pl) > 0 {
		nodes := proxiesOf(raw)
		kept, renamed, removed, _ := c.processNodes(nodes)
		out := make([]any, 0, len(kept))
		for _, k := range kept {
			out = append(out, k)
		}
		raw["proxies"] = out
		fixReferences(raw, renamed, removed)
	}
	if pp, ok := raw["proxy-providers"].(map[string]any); ok {
		for name, v := range pp {
			m, ok := v.(map[string]any)
			if !ok {
				continue
			}
			if f := providerFilter(r.Include, r.Regex); f != "" && c.inc != nil {
				if old := str(m["filter"]); old != "" {
					f = "(?=.*(" + old + "))" + f
				}
				m["filter"] = f
			}
			if f := providerFilter(r.Exclude, r.Regex); f != "" && c.exc != nil {
				if old := str(m["exclude-filter"]); old != "" {
					f = old + "|" + f
				}
				m["exclude-filter"] = f
			}
			ov := asMap(m["override"])
			var pn []any
			if c.r.StripFlags || c.r.AddFlag {
				pn = append(pn, map[string]any{"pattern": "[\U0001F1E6-\U0001F1FF]{2}\\s*", "target": ""})
			}
			for _, p := range c.r.StripPrefixes {
				if p != "" {
					pn = append(pn, map[string]any{"pattern": "^" + regexp2.Escape(p) + `\s*`, "target": ""})
				}
			}
			for i, re := range c.renames {
				pn = append(pn, map[string]any{"pattern": re.String(), "target": c.repl[i]})
			}
			if len(pn) > 0 {
				ov["proxy-name"] = append(asList(ov["proxy-name"]), pn...)
			}
			if c.r.Prefix != "" {
				ov["additional-prefix"] = c.r.Prefix + str(ov["additional-prefix"])
			}
			if len(ov) > 0 {
				m["override"] = ov
			}
			pp[name] = m
		}
	}
	return c.errs
}

// fixReferences maps renamed nodes and drops removed ones from groups, dialer-proxy and rules.
func fixReferences(raw map[string]any, renamed map[string]string, removed map[string]bool) {
	if len(renamed) == 0 && len(removed) == 0 {
		return
	}
	mapName := func(s string) (string, bool) {
		if removed[s] {
			return "", false
		}
		if n, ok := renamed[s]; ok {
			return n, true
		}
		return s, true
	}
	groupNames := map[string]bool{}
	if gl, ok := raw["proxy-groups"].([]any); ok {
		for _, x := range gl {
			if m, ok := x.(map[string]any); ok {
				groupNames[str(m["name"])] = true
			}
		}
		for _, x := range gl {
			m, ok := x.(map[string]any)
			if !ok {
				continue
			}
			list, has := m["proxies"].([]any)
			if !has {
				continue
			}
			out := make([]any, 0, len(list))
			for _, p := range list {
				s := fmt.Sprint(p)
				if groupNames[s] {
					out = append(out, p)
					continue
				}
				if n, ok := mapName(s); ok {
					out = append(out, n)
				}
			}
			empty := len(out) == 0 && len(strList(m["use"])) == 0 && !boolOf(m["include-all"]) && !boolOf(m["include-all-proxies"]) && !boolOf(m["include-all-providers"])
			if empty {
				out = append(out, "DIRECT") // keep the group valid when the filter removed every member
			}
			m["proxies"] = out
		}
	}
	for _, p := range proxiesOf(raw) {
		if d := str(p["dialer-proxy"]); d != "" && !groupNames[d] {
			if n, ok := mapName(d); ok {
				p["dialer-proxy"] = n
			} else {
				delete(p, "dialer-proxy")
			}
		}
	}
	if rl, ok := raw["rules"].([]any); ok {
		for i, x := range rl {
			line, ok := x.(string)
			if !ok {
				continue
			}
			parts := strings.Split(line, ",")
			// policy is the last field, or the one before trailing options like no-resolve
			idx := len(parts) - 1
			if idx > 0 && strings.EqualFold(strings.TrimSpace(parts[idx]), "no-resolve") {
				idx--
			}
			if idx <= 0 {
				continue
			}
			pol := strings.TrimSpace(parts[idx])
			if groupNames[pol] {
				continue
			}
			if n, ok := renamed[pol]; ok {
				parts[idx] = n
				rl[i] = strings.Join(parts, ",")
			} else if removed[pol] {
				parts[idx] = "DIRECT"
				rl[i] = strings.Join(parts, ",")
			}
		}
	}
}

// ---------------- exported for the app ----------------

type previewResult struct {
	Nodes     []PreviewNode `json:"nodes"`
	Total     int           `json:"total"`
	Kept      int           `json:"kept"`
	Providers []string      `json:"providers"` // proxy-providers the rules are forwarded to (filter + rename only)
	Errors    []string      `json:"errors"`
}

// SubPreview runs rulesJSON (a SubRules object) against the profile at profilePath without saving.
// Inline nodes plus cached provider nodes are shown; returns JSON previewResult.
func SubPreview(homeDir, profilePath, rulesJSON string) string {
	res := previewResult{Nodes: []PreviewNode{}, Providers: []string{}, Errors: []string{}}
	var r SubRules
	if err := json.Unmarshal([]byte(rulesJSON), &r); err != nil {
		res.Errors = append(res.Errors, err.Error())
		b, _ := json.Marshal(res)
		return string(b)
	}
	r.Enabled = true
	raw := map[string]any{}
	if b, err := os.ReadFile(profilePath); err == nil {
		o := readOverrides(homeDir)
		o.home, o.MergeManual = "", false
		if rt, err := buildRuntime(b, o, 0); err == nil {
			_ = yaml.Unmarshal(rt, &raw)
		} else {
			res.Errors = append(res.Errors, err.Error())
		}
	} else {
		res.Errors = append(res.Errors, err.Error())
	}
	c := compileSub(r)
	res.Errors = append(res.Errors, c.errs...)
	nodes := proxiesOf(raw)
	_, _, _, rows := c.processNodes(nodes)
	res.Nodes = append(res.Nodes, rows...)
	for _, pv := range inspectProviders("proxy", raw["proxy-providers"]) {
		res.Providers = append(res.Providers, pv.Name)
		var pn []map[string]any
		for _, p := range pv.Proxies {
			pn = append(pn, map[string]any{"name": p.Name, "type": p.Type, "server": p.Server, "port": p.Port})
		}
		// Providers get filter + rename only (no dedupe / sort / unique suffix) — mirror that here.
		cc := compileSub(SubRules{Enabled: true, Include: r.Include, Exclude: r.Exclude, Regex: r.Regex, StripPrefixes: r.StripPrefixes,
			StripFlags: r.StripFlags || r.AddFlag, Renames: r.Renames, Prefix: r.Prefix})
		_, _, _, prow := cc.processNodes(pn)
		for i := range prow {
			prow[i].Source = pv.Name
		}
		res.Nodes = append(res.Nodes, prow...)
	}
	res.Total = len(res.Nodes)
	for _, n := range res.Nodes {
		if n.Kept {
			res.Kept++
		}
	}
	b, _ := json.Marshal(res)
	return string(b)
}

// DetectRegion returns the ISO region code (or "") for a node name.
func DetectRegion(name string) string { c, _ := detectRegion(name); return c }
