package libmihomo

// 节点订阅 (feat/subs-split, user 2026-10-21 「节点订阅里…没有禁用、删除选项」): the user's changes to the
// proxy-providers (节点集) of a profile, kept per profile in <home>/provider-overrides.json and applied in
// buildRuntime — the profile file is never rewritten. Keyed by the provider's name in the profile, so a
// re-download of the profile keeps them (a provider the subscription renames is a new provider).
//
//   disabled  停用: left out of the runtime (and out of every group's `use:`); 启用 brings it back.
//   deleted   删除: the same at runtime, and the app no longer lists it; 恢复已删除的节点集 clears the flag.
//   url / interval / filter / excludeFilter  编辑 (http providers; filters are mihomo provider filters).
//   name / icon  display only (the app's row title and icon); the runtime keeps the profile's name so
//                groups, rules and 策略组编辑 that name the provider keep working.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dlclark/regexp2"
)

type ProviderOverride struct {
	Disabled      bool   `json:"disabled,omitempty"`
	Deleted       bool   `json:"deleted,omitempty"`
	Name          string `json:"name,omitempty"`
	Icon          string `json:"icon,omitempty"`
	URL           string `json:"url,omitempty"`
	Interval      int    `json:"interval,omitempty"`
	Filter        string `json:"filter,omitempty"`
	ExcludeFilter string `json:"excludeFilter,omitempty"`
	// Policy: rule-provider overrides only (key "rule:<name>") — the policy of the profile's RULE-SET rules.
	Policy string `json:"policy,omitempty"`
	// Order: only on the entry keyed ruleOrderKey — the profile's rule sets in the order the user arranged them
	// on 规则 → 订阅 (matching priority, top first). See applyRuleSetOrder.
	Order []string `json:"order,omitempty"`
}

func providerOverridesPath(home string) string { return filepath.Join(home, "provider-overrides.json") }

func readProviderOverrides(home, profileID string) map[string]ProviderOverride {
	if home == "" || profileID == "" {
		return nil
	}
	m := map[string]map[string]ProviderOverride{}
	if b, err := os.ReadFile(providerOverridesPath(home)); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m[profileID]
}

// providerSourceURL is the address a provider downloads: the `url` query of our loopback converter
// (QX / Surge imports), otherwise `url`.
func providerSourceURL(m map[string]any) string {
	u := str(m["url"])
	if pu, err := url.Parse(u); err == nil && pu.Hostname() == "127.0.0.1" && strings.HasSuffix(pu.Path, "/convert") {
		if q := pu.Query().Get("url"); q != "" {
			return q
		}
	}
	return firstNonEmpty(str(m["x-source"]), u)
}

func setProviderURL(m map[string]any, nu string) {
	u := str(m["url"])
	if pu, err := url.Parse(u); err == nil && pu.Hostname() == "127.0.0.1" && strings.HasSuffix(pu.Path, "/convert") && pu.Query().Get("url") != "" {
		q := pu.Query()
		q.Set("url", nu)
		pu.RawQuery = q.Encode()
		m["url"] = pu.String()
	} else {
		m["url"] = nu
	}
	if _, ok := m["x-source"]; ok {
		m["x-source"] = nu
	}
}

// pathForURL gives a provider cache path its own name per link: ./proxies/a.yaml → ./proxies/a-<hash8>.yaml.
func pathForURL(p, u string) string {
	sum := sha256.Sum256([]byte(u))
	h := hex.EncodeToString(sum[:4])
	ext := filepath.Ext(p)
	return strings.TrimSuffix(p, ext) + "-" + h + ext
}

func validProviderFilter(f string) bool {
	_, err := regexp2.Compile(f, regexp2.None)
	return err == nil
}

// applyProviderOverrides applies ov and immediately gives a group left with no member DIRECT (used where
// no node subscription is merged afterwards, e.g. tests and previews). buildRuntime uses
// applyProviderOverridesDeferred and fillEmptyProviderGroups after node subscriptions and group edits.
func applyProviderOverrides(raw map[string]any, ov map[string]ProviderOverride) (removed []string, warns []string) {
	removed, warns = applyProviderOverridesDeferred(raw, ov)
	fillEmptyProviderGroups(raw)
	return removed, warns
}

// providerLostKey marks (inside buildRuntime only) a group that lost a 停用 / 删除 provider from `use:` or
// that only had include-all-providers. Review 7 P1-1: the DIRECT fallback must run after node subscriptions
// are merged — otherwise a select group whose only provider was disabled became `proxies: [DIRECT]`, the node
// subscription skipped it (defaultSubGroup saw a DIRECT-only group) and MATCH traffic went direct.
const providerLostKey = "x-tern-lost-provider"

// fillEmptyProviderGroups removes the providerLostKey markers; a marked group with no member left at all gets
// DIRECT so the config stays valid (安全模式 / no node subscription).
func fillEmptyProviderGroups(raw map[string]any) {
	pp, _ := raw["proxy-providers"].(map[string]any)
	for _, gv := range asList(raw["proxy-groups"]) {
		g, ok := gv.(map[string]any)
		if !ok {
			continue
		}
		if _, ok := g[providerLostKey]; !ok {
			continue
		}
		delete(g, providerLostKey)
		onlyProviders := boolOf(g["include-all-providers"]) && !boolOf(g["include-all"]) && !boolOf(g["include-all-proxies"])
		if len(asList(g["proxies"])) == 0 && len(asList(g["use"])) == 0 &&
			!boolOf(g["include-all"]) && !boolOf(g["include-all-proxies"]) && (!onlyProviders || len(pp) == 0) {
			g["proxies"] = []any{"DIRECT"}
		}
	}
}

// applyProviderOverridesDeferred applies ov to the profile's own proxy-providers (call it before node
// subscriptions are merged). Removed providers leave every `use:`; affected groups are marked with
// providerLostKey for fillEmptyProviderGroups. Returns the removed provider names and warnings.
func applyProviderOverridesDeferred(raw map[string]any, ov map[string]ProviderOverride) (removed []string, warns []string) {
	if len(ov) == 0 {
		return nil, nil
	}
	pp, _ := raw["proxy-providers"].(map[string]any)
	if len(pp) == 0 {
		return nil, nil
	}
	names := make([]string, 0, len(ov))
	for n := range ov {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		o := ov[name]
		v, ok := pp[name]
		if !ok {
			continue
		}
		if o.Disabled || o.Deleted {
			delete(pp, name)
			removed = append(removed, name)
			continue
		}
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if u := strings.TrimSpace(o.URL); u != "" && strings.EqualFold(str(m["type"]), "http") {
			if pu, err := url.Parse(u); err == nil && (pu.Scheme == "http" || pu.Scheme == "https") && pu.Host != "" {
				changed := u != providerSourceURL(m)
				setProviderURL(m, u)
				// Review 7 P2-3: with an explicit `path:` mihomo keeps using the old link's cached file until
				// the interval expires; a path per link makes the new link's nodes load on the next reload.
				if p := str(m["path"]); changed && p != "" {
					m["path"] = pathForURL(p, u)
				}
			} else {
				warns = append(warns, "节点集「"+name+"」的自定义链接无效，已使用配置里的链接")
			}
		}
		if o.Interval > 0 {
			m["interval"] = o.Interval
		}
		for _, kv := range [][2]string{{"filter", o.Filter}, {"exclude-filter", o.ExcludeFilter}} {
			f := strings.TrimSpace(kv[1])
			if f == "" {
				continue
			}
			if validProviderFilter(f) {
				m[kv[0]] = f
			} else {
				warns = append(warns, "节点集「"+name+"」的筛选表达式无效，已忽略")
			}
		}
	}
	if len(removed) == 0 {
		return nil, warns
	}
	gone := map[string]bool{}
	for _, n := range removed {
		gone[n] = true
	}
	for _, gv := range asList(raw["proxy-groups"]) {
		g, ok := gv.(map[string]any)
		if !ok {
			continue
		}
		had := false
		if use := strList(g["use"]); len(use) > 0 {
			var kept []any
			for _, u := range use {
				if gone[u] {
					had = true
				} else {
					kept = append(kept, u)
				}
			}
			if had {
				if len(kept) == 0 {
					delete(g, "use")
				} else {
					g["use"] = kept
				}
			}
		}
		onlyProviders := boolOf(g["include-all-providers"]) && !boolOf(g["include-all"]) && !boolOf(g["include-all-proxies"])
		if had || onlyProviders {
			g[providerLostKey] = true
		}
	}
	return removed, warns
}

// providerInfo is one proxy-provider of a profile as the profile declares it (before the user's overrides).
type providerInfo struct {
	Name          string `json:"name"`
	Vehicle       string `json:"vehicle"`
	URL           string `json:"url,omitempty"`
	Interval      int    `json:"interval,omitempty"`
	Filter        string `json:"filter,omitempty"`
	ExcludeFilter string `json:"excludeFilter,omitempty"`
}

// ProfileProviders lists the proxy-providers the profile itself declares (覆写脚本 output when current), before
// the user's provider overrides, so the app can show 停用 providers (not in the runtime) and the editor's
// defaults. JSON [providerInfo], sorted by name.
// ppCache (r7): ProfileProviders parses the whole profile; the node detail / 节点订阅 pages call it with
// other per-node calls. Reuse the answer for rtCacheTTL while the runtime inputs are unchanged.
var ppCache struct {
	sync.Mutex
	key, val string
	at       time.Time
}

func ProfileProviders(homeDir, profilePath string) string {
	key := runtimeCacheKey(homeDir, profilePath)
	ppCache.Lock()
	if ppCache.val != "" && ppCache.key == key && time.Since(ppCache.at) < rtCacheTTL {
		v := ppCache.val
		ppCache.Unlock()
		return v
	}
	ppCache.Unlock()
	v := profileProviders(homeDir, profilePath)
	ppCache.Lock()
	ppCache.key, ppCache.val, ppCache.at = key, v, time.Now()
	ppCache.Unlock()
	return v
}

func profileProviders(homeDir, profilePath string) string {
	out := []providerInfo{}
	defer func() { _ = recover() }()
	b, err := readRuntimeProfile(homeDir, profilePath, false)
	if err != nil {
		return "[]"
	}
	raw, err := profileAsMap(b)
	if err != nil {
		return "[]"
	}
	for name, v := range asMap(raw["proxy-providers"]) {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		p := providerInfo{Name: name, Vehicle: strings.ToLower(str(m["type"])), Interval: intOf(m["interval"]),
			Filter: str(m["filter"]), ExcludeFilter: str(m["exclude-filter"])}
		if p.Vehicle == "http" {
			p.URL = providerSourceURL(m)
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	j, _ := json.Marshal(out)
	return string(j)
}
