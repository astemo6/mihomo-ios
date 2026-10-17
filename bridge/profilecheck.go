package libmihomo

// Profile editor validation: parse the edited text the same way Start would (YAML, our overrides,
// then mihomo's executor) and point at the line / column of the problem in the user's text.

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"go.yaml.in/yaml/v3"
)

type profileCheck struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Line   int    `json:"line,omitempty"`   // 1-based, 0 = unknown
	Column int    `json:"column,omitempty"` // 1-based, 0 = unknown
	// Counts when valid.
	Nodes     int `json:"nodes"`
	Groups    int `json:"groups"`
	Rules     int `json:"rules"`
	Providers int `json:"providers"`
}

var (
	yamlLineRe       = regexp.MustCompile(`line (\d+)(?:, column (\d+))?`)
	proxyIdxRe       = regexp.MustCompile(`^proxy (\d+):`)
	groupIdxRe       = regexp.MustCompile(`^proxy group(?:\[| )(\d+)\]?:`)
	groupNameRe      = regexp.MustCompile(`^proxy group\[\d+\]: ([^:]+):`)
	proxyDupRe       = regexp.MustCompile(`^proxy (.+) is the duplicate name`)
	groupDupRe       = regexp.MustCompile(`^proxy group (.+): the duplicate name`)
	providerRe       = regexp.MustCompile(`^parse proxy provider (\S+) error`)
	ruleLineRe       = regexp.MustCompile(`^(?:rules|sub-rule)\[\d+\] \[(.*?)\] error`)
	groupInsideUseRe = regexp.MustCompile(`proxy group (\S+) can't contains`)
)

// topValue returns the value node of a top-level key.
func topValue(root *yaml.Node, key string) *yaml.Node {
	doc := root
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		doc = doc.Content[0]
	}
	if doc.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value == key {
			return doc.Content[i+1]
		}
	}
	return nil
}

func mapValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// itemNamed finds the item of a sequence whose `name` is name.
func itemNamed(seq *yaml.Node, name string) *yaml.Node {
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return nil
	}
	for _, it := range seq.Content {
		if v := mapValue(it, "name"); v != nil && v.Value == name {
			return it
		}
	}
	return nil
}

func nthName(raw map[string]any, key string, idx int) string {
	l := asList(raw[key])
	if idx < 0 || idx >= len(l) {
		return ""
	}
	return str(asMap(l[idx])["name"])
}

func locate(root *yaml.Node, rt map[string]any, msg string) *yaml.Node {
	if m := proxyIdxRe.FindStringSubmatch(msg); m != nil {
		i, _ := strconv.Atoi(m[1])
		return itemNamed(topValue(root, "proxies"), nthName(rt, "proxies", i))
	}
	if m := groupNameRe.FindStringSubmatch(msg); m != nil {
		if n := itemNamed(topValue(root, "proxy-groups"), m[1]); n != nil {
			return n
		}
	}
	if m := groupIdxRe.FindStringSubmatch(msg); m != nil {
		i, _ := strconv.Atoi(m[1])
		return itemNamed(topValue(root, "proxy-groups"), nthName(rt, "proxy-groups", i))
	}
	if m := proxyDupRe.FindStringSubmatch(msg); m != nil {
		return itemNamed(topValue(root, "proxies"), m[1])
	}
	if m := groupDupRe.FindStringSubmatch(msg); m != nil {
		return itemNamed(topValue(root, "proxy-groups"), m[1])
	}
	if m := groupInsideUseRe.FindStringSubmatch(msg); m != nil {
		return itemNamed(topValue(root, "proxy-groups"), m[1])
	}
	if m := providerRe.FindStringSubmatch(msg); m != nil {
		pp := topValue(root, "proxy-providers")
		if pp != nil && pp.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(pp.Content); i += 2 {
				if pp.Content[i].Value == m[1] {
					return pp.Content[i]
				}
			}
		}
	}
	if m := ruleLineRe.FindStringSubmatch(msg); m != nil {
		want := strings.ReplaceAll(m[1], " ", "")
		var walk func(n *yaml.Node) *yaml.Node
		walk = func(n *yaml.Node) *yaml.Node {
			if n == nil {
				return nil
			}
			if n.Kind == yaml.ScalarNode && strings.ReplaceAll(n.Value, " ", "") == want {
				return n
			}
			for _, c := range n.Content {
				if r := walk(c); r != nil {
					return r
				}
			}
			return nil
		}
		for _, k := range []string{"rules", "sub-rules"} {
			if r := walk(topValue(root, k)); r != nil {
				return r
			}
		}
	}
	return nil
}

func checkProfileText(homeDir, profilePath, text string) profileCheck {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(text), &root); err != nil {
		r := profileCheck{Error: "YAML 格式错误：" + strings.TrimPrefix(err.Error(), "yaml: ")}
		if m := yamlLineRe.FindStringSubmatch(err.Error()); m != nil {
			r.Line, _ = strconv.Atoi(m[1])
			if m[2] != "" {
				r.Column, _ = strconv.Atoi(m[2])
			}
		}
		// yaml.v3 often reports where the enclosing block starts. The first line whose prefix no longer
		// parses is closer to what the user broke (binary search: ~log2(lines) parses).
		if l := firstBadLine(text); l > r.Line {
			r.Line, r.Column = l, 0
		}
		return r
	}
	if homeDir != "" {
		C.SetHomeDir(homeDir)
	}
	o := overridesFor(homeDir, profilePath)
	rt, err := buildRuntime([]byte(text), o, 0)
	if err != nil {
		return profileCheck{Error: FriendlyError(err.Error())}
	}
	cfg, err := executor.ParseWithBytes(rt)
	if err != nil {
		msg := err.Error()
		r := profileCheck{Error: FriendlyError(msg)}
		rtRaw := map[string]any{}
		_ = yaml.Unmarshal(rt, &rtRaw)
		if n := locate(&root, rtRaw, msg); n != nil {
			r.Line, r.Column = n.Line, n.Column
		}
		return r
	}
	rtRaw := map[string]any{}
	_ = yaml.Unmarshal(rt, &rtRaw)
	return profileCheck{OK: true, Nodes: len(asList(rtRaw["proxies"])), Groups: len(asList(rtRaw["proxy-groups"])),
		Rules: len(cfg.Rules), Providers: len(cfg.Providers)}
}

func firstBadLine(text string) int {
	lines := strings.SplitAfter(text, "\n")
	bad := func(n int) bool {
		var v yaml.Node
		return yaml.Unmarshal([]byte(strings.Join(lines[:n], "")), &v) != nil
	}
	lo, hi := 1, len(lines)
	if !bad(hi) {
		return 0
	}
	for lo < hi {
		mid := (lo + hi) / 2
		if bad(mid) {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return lo
}

// ProfileCheck validates edited profile text for the profile at profilePath (its subscription
// processing and our overrides apply). JSON {ok, error, line, column, stats}.
func ProfileCheck(homeDir, profilePath, text string) string {
	b, _ := json.Marshal(checkProfileText(homeDir, profilePath, text))
	return string(b)
}
