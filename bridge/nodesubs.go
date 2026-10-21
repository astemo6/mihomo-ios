package libmihomo

// 订阅管理 (v0.9): node-only subscriptions the user adds in the app. The app keeps the list in
// <home>/node-subscriptions.json, downloads each one itself (ProviderStore, convert "nodes") into
// <home>/nodesubs/<id>.yaml and buildRuntime merges every enabled one into the profile as a mihomo
// file proxy-provider, added with `use:` to the chosen groups. No new format: it is a proxy-provider.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

type NodeSub struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	URL     string   `json:"url"`
	Enabled bool     `json:"enabled"`
	Groups  []string `json:"groups,omitempty"` // nil / empty = default (select groups with nodes + url-test groups)
}

func nodeSubsPath(home string) string { return filepath.Join(home, "node-subscriptions.json") }

// NodeSubPath is the cache file of a node subscription (written by the app through ProviderStore).
func NodeSubPath(home, id string) string { return filepath.Join(home, "nodesubs", id+".yaml") }

func readNodeSubs(home string) []NodeSub {
	var l []NodeSub
	if home == "" {
		return nil
	}
	if b, err := os.ReadFile(nodeSubsPath(home)); err == nil {
		_ = json.Unmarshal(b, &l)
	}
	return l
}

var builtinMembers = map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "COMPATIBLE": true}

// defaultSubGroup: select groups that offer real nodes (not only DIRECT / REJECT) and url-test groups.
func defaultSubGroup(g map[string]any) bool {
	if boolOf(g["hidden"]) || str(g["name"]) == ProbeGroup {
		return false
	}
	switch strings.ToLower(str(g["type"])) {
	case "url-test":
		return true
	case "select":
		// Review 7 P1-1: a group whose 节点集 was 停用 / 删除 offered nodes before; it still takes subscriptions.
		if _, lost := g[providerLostKey]; lost {
			return true
		}
		if len(asList(g["use"])) > 0 || boolOf(g["include-all"]) || boolOf(g["include-all-proxies"]) || boolOf(g["include-all-providers"]) {
			return true
		}
		for _, m := range strList(g["proxies"]) {
			if !builtinMembers[strings.ToUpper(m)] {
				return true
			}
		}
	}
	return false
}

// mergeNodeSubs adds the enabled node subscriptions as file providers. sub returns the 节点处理 rules
// of a subscription ("nodesub-<id>").
func mergeNodeSubs(raw map[string]any, home string, sub func(key string) *SubRules) {
	subs := readNodeSubs(home)
	if len(subs) == 0 {
		return
	}
	pp, _ := raw["proxy-providers"].(map[string]any)
	if pp == nil {
		pp = map[string]any{}
	}
	groups, _ := raw["proxy-groups"].([]any)
	added := false
	for _, s := range subs {
		if !s.Enabled || s.ID == "" {
			continue
		}
		if fi, err := os.Stat(NodeSubPath(home, s.ID)); err != nil || fi.Size() == 0 {
			continue // not downloaded yet: a file provider without its file would fail the whole config
		}
		name := uniqueProviderName(firstNonEmpty(strings.TrimSpace(s.Name), "订阅"), func(n string) bool { _, ok := pp[n]; return ok })
		p := map[string]any{
			"type": "file", "path": "./nodesubs/" + s.ID + ".yaml",
			"health-check": map[string]any{"enable": true, "url": "https://www.gstatic.com/generate_204", "interval": 600, "lazy": true},
		}
		if r := sub("nodesub-" + s.ID); r != nil && r.Enabled {
			tmp := map[string]any{"proxy-providers": map[string]any{name: p}}
			_ = applySubRules(tmp, r)
		}
		pp[name] = p
		added = true
		want := map[string]bool{}
		for _, g := range s.Groups {
			want[g] = true
		}
		hit := false
		for _, gv := range groups {
			g, ok := gv.(map[string]any)
			if !ok {
				continue
			}
			if (len(want) > 0 && want[str(g["name"])]) || (len(want) == 0 && defaultSubGroup(g)) {
				g["use"] = append(asList(g["use"]), name)
				hit = true
			}
		}
		if !hit {
			// None of the chosen groups exist in this profile: fall back to the default groups.
			for _, gv := range groups {
				if g, ok := gv.(map[string]any); ok && defaultSubGroup(g) {
					g["use"] = append(asList(g["use"]), name)
				}
			}
		}
	}
	if added {
		raw["proxy-providers"] = pp
	}
}

// pruneDanglingUse (v0.19.8) drops `use:` entries that name no proxy-provider of the runtime: a node subscription
// that is 停用 (or not downloaded yet) is not merged, but a 筛选节点 / 策略组编辑 group may still list it in
// `use:` (only some subscriptions chosen as its source), and mihomo refuses the whole config over one unknown
// provider. A group left with no members at all gets DIRECT, like the delete paths do. Returns the groups changed.
func pruneDanglingUse(raw map[string]any) []string {
	pp, _ := raw["proxy-providers"].(map[string]any)
	var changed []string
	for _, gv := range asList(raw["proxy-groups"]) {
		g, ok := gv.(map[string]any)
		if !ok {
			continue
		}
		use := strList(g["use"])
		if len(use) == 0 {
			continue
		}
		var kept []any
		for _, u := range use {
			if _, ok := pp[u]; ok {
				kept = append(kept, u)
			}
		}
		if len(kept) == len(use) {
			continue
		}
		changed = append(changed, str(g["name"]))
		if len(kept) == 0 {
			delete(g, "use")
		} else {
			g["use"] = kept
		}
		if len(kept) == 0 && len(asList(g["proxies"])) == 0 && !boolOf(g["include-all"]) && !boolOf(g["include-all-proxies"]) && !boolOf(g["include-all-providers"]) {
			g["proxies"] = []any{"DIRECT"}
		}
	}
	return changed
}
