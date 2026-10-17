package libmihomo

// v0.8.1 provider handling for the app: readable provider names, offline downloads by the app
// (ProviderPlan + ProviderStore) and migration of profiles imported by v0.8.0 and earlier
// ("convert+<kind>:<url>" URLs, custom-<hash> names).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	"go.yaml.in/yaml/v3"
)

// prettyProviderName: the QX tag, else the list's file name without extension, else the host.
func prettyProviderName(u, tag string) string {
	n := strings.TrimSpace(tag)
	if n == "" {
		if pu, err := url.Parse(u); err == nil {
			b := path.Base(pu.Path)
			if i := strings.LastIndex(b, "."); i > 0 {
				b = b[:i]
			}
			if b != "/" && b != "." && b != "" {
				n = b
			}
			if n == "" {
				n = pu.Hostname()
			}
		}
	}
	n = strings.Map(func(r rune) rune {
		switch r {
		case ',', '\n', '\r', '\t', '/', '(', ')':
			return '-'
		}
		return r
	}, n)
	n = strings.Trim(strings.TrimSpace(n), "-")
	if n == "" {
		n = "ruleset"
	}
	return n
}

func uniqueProviderName(base string, taken func(string) bool) string {
	if !taken(base) {
		return base
	}
	for i := 2; ; i++ {
		if c := fmt.Sprintf("%s-%d", base, i); !taken(c) {
			return c
		}
	}
}

// providerTask is one provider the app can download itself.
type providerTask struct {
	Kind     string  `json:"kind"` // rule | proxy
	Name     string  `json:"name"`
	URL      string  `json:"url"`     // what to download (source, mirrored if the mirror is on)
	Source   string  `json:"source"`  // the URL shown to the user
	Convert  string  `json:"convert"` // list | domainset | nodes | ""
	Format   string  `json:"format,omitempty"`
	Path     string  `json:"path"` // absolute cache path the core reads
	Interval int     `json:"interval"`
	Updated  float64 `json:"updated"`
}

// ProviderPlan lists the HTTP providers of the profile (as the core would see them with the current
// overrides, custom rules included) with the URL to download and the file to write.
func ProviderPlan(homeDir, profilePath string) string {
	out := []providerTask{}
	defer func() { _ = recover() }()
	C.SetHomeDir(homeDir)
	b, err := os.ReadFile(profilePath)
	if err != nil {
		return "[]"
	}
	rt, err := buildRuntime(b, overridesFor(homeDir, profilePath), 0)
	if err != nil {
		return "[]"
	}
	raw := map[string]any{}
	_ = yaml.Unmarshal(rt, &raw)
	for _, kk := range [][2]string{{"rule", "rule-providers"}, {"proxy", "proxy-providers"}} {
		pv, _ := raw[kk[1]].(map[string]any)
		for name, v := range pv {
			m, ok := v.(map[string]any)
			if !ok || !strings.EqualFold(str(m["type"]), "http") {
				continue
			}
			t := providerTask{Kind: kk[0], Name: name, Format: str(m["format"]), Interval: intOf(m["interval"]), Path: providerCache(kk[0], m)}
			u := str(m["url"])
			if pu, err := url.Parse(u); err == nil && (pu.Hostname() == "127.0.0.1") && (strings.HasSuffix(pu.Path, "/rules/convert") || strings.HasSuffix(pu.Path, "/nodes/convert")) {
				t.URL = pu.Query().Get("url")
				t.Convert = pu.Query().Get("kind")
				if strings.HasSuffix(pu.Path, "/nodes/convert") {
					t.Convert = "nodes"
				}
			} else {
				t.URL = u
			}
			if truthyAny(m["x-own-policy"]) && t.Convert == "list" {
				t.Convert = "list-split" // v0.12: QX list without force-policy (ownpolicy.go)
			}
			t.Source = firstNonEmpty(str(m["x-source"]), t.URL)
			if t.URL == "" || t.Path == "" {
				continue
			}
			t.Updated = mtime(t.Path)
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind > out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	j, _ := json.Marshal(out)
	return string(j)
}

// ProviderStore converts downloaded bytes like the core's converter would and writes them to path
// (which must be inside homeDir). Returns JSON {"count": n, "error": "…"}.
func ProviderStore(homeDir, kind, cachePath, convert string, data []byte) string {
	res := func(n int, e string) string {
		b, _ := json.Marshal(map[string]any{"count": n, "error": e})
		return string(b)
	}
	rel, err := filepath.Rel(homeDir, cachePath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return res(0, "路径不在内核目录内")
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return res(0, "下载内容为空")
	}
	out, n := data, -1
	switch {
	case convert == "nodes":
		b, c, err := convertNodesText(data)
		if err != nil {
			return res(0, "没有识别到节点")
		}
		out, n = b, c
		if n < 0 {
			n = len(parseProviderNodes(b, ""))
		}
	case convert == "list-split":
		text, ok, _ := convertListText(bytes.NewReader(data), "list")
		if ok == 0 {
			return res(0, "列表里没有可用的规则")
		}
		out, n = []byte(text), ok
		if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
			return res(0, err.Error())
		}
		if _, err := splitOwnPolicyList(cachePath, data); err != nil {
			return res(0, err.Error())
		}
	case convert != "":
		text, ok, _ := convertListText(bytes.NewReader(data), convert)
		if ok == 0 {
			return res(0, "列表里没有可用的规则")
		}
		out, n = []byte(text), ok
	case kind == "proxy":
		n = len(parseProviderNodes(data, ""))
		if n == 0 {
			return res(0, "没有识别到节点")
		}
	default:
		_, n = parseRuleCache(data, "")
	}
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		return res(0, err.Error())
	}
	tmp := cachePath + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return res(0, err.Error())
	}
	if err := os.Rename(tmp, cachePath); err != nil {
		return res(0, err.Error())
	}
	return res(n, "")
}

var ruleSetRefRE = regexp.MustCompile(`RULE-SET\s*,\s*([^,()]+)`)

// MigrateProfileProviders rewrites a profile imported by v0.8.0 or earlier: "convert+<kind>:<url>"
// providers keep the source URL (+ x-convert) and custom-<hash> rule providers get readable names;
// RULE-SET references (also inside logical rules and sub-rules) follow. Returns the number of changed
// providers, or -1 on error. Cache paths are unchanged.
func MigrateProfileProviders(profilePath string) int {
	b, err := os.ReadFile(profilePath)
	if err != nil || !bytes.Contains(b, []byte(convertScheme)) {
		return 0
	}
	raw := map[string]any{}
	if yaml.Unmarshal(b, &raw) != nil {
		return -1
	}
	changed := 0
	renames := map[string]string{}
	if pp, ok := raw["proxy-providers"].(map[string]any); ok {
		for _, v := range pp {
			if m, ok := v.(map[string]any); ok {
				if k, src := providerConvert(m); k != "" && strings.HasPrefix(str(m["url"]), convertScheme) {
					m["url"], m["x-convert"] = src, k
					changed++
				}
			}
		}
	}
	if rp, ok := raw["rule-providers"].(map[string]any); ok {
		names := make([]string, 0, len(rp))
		for n := range rp {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			m, ok := rp[n].(map[string]any)
			if !ok || !strings.HasPrefix(str(m["url"]), convertScheme) {
				continue
			}
			k, src := providerConvert(m)
			m["url"], m["x-convert"] = src, k
			changed++
			if strings.HasPrefix(n, "custom-") {
				nn := uniqueProviderName(prettyProviderName(src, ""), func(s string) bool { _, ok := rp[s]; return ok })
				rp[nn] = m
				delete(rp, n)
				renames[n] = nn
			}
		}
	}
	if changed == 0 {
		return 0
	}
	fix := func(r string) string {
		return ruleSetRefRE.ReplaceAllStringFunc(r, func(s string) string {
			sub := ruleSetRefRE.FindStringSubmatch(s)
			if nn, ok := renames[strings.TrimSpace(sub[1])]; ok {
				return strings.Replace(s, sub[1], nn, 1)
			}
			return s
		})
	}
	if rl, ok := raw["rules"].([]any); ok {
		for i, r := range rl {
			if s, ok := r.(string); ok {
				rl[i] = fix(s)
			}
		}
	}
	if sr, ok := raw["sub-rules"].(map[string]any); ok {
		for _, v := range sr {
			if rl, ok := v.([]any); ok {
				for i, r := range rl {
					if s, ok := r.(string); ok {
						rl[i] = fix(s)
					}
				}
			}
		}
	}
	out, err := yaml.Marshal(raw)
	if err != nil {
		return -1
	}
	tmp := profilePath + ".tmp"
	if os.WriteFile(tmp, out, 0o644) != nil || os.Rename(tmp, profilePath) != nil {
		return -1
	}
	return changed
}
