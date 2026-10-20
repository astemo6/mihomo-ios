package libmihomo

// Remote resources (QX-style), shown in the app's single module & resource manager: modules /
// rewrite sets (engine.json), remote rule sets (rules.json, plus RULE-SETs inside enabled modules)
// and the remote scripts those reference. There is no second store: settings stay where they live
// (EngineModule.enabled / interval, CustomRule.enabled / interval, engine.json scriptResources);
// this file only lists them with their cache files and records the last download error.
//
// The app downloads (URLSession, so it works offline from the tunnel and through it when connected)
// and hands the bytes to ResourceStore, which validates, converts (rule sets → mihomo classical text,
// the same /rules/convert output the core's provider would write) and writes the cache file the core
// / engine reads. Last-update time = cache file mtime, so updates by the core itself (rule-provider
// interval, engine script refresh) show up too.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
)

// ResourceItem is one row of the resource manager.
type ResourceItem struct {
	Key       string  `json:"key"`  // module:<id> | ruleset:<kind>|<url> | script:<url>
	Kind      string  `json:"kind"` // module | ruleset | script
	Name      string  `json:"name"`
	URL       string  `json:"url"`
	Format    string  `json:"format,omitempty"` // badge
	Enabled   bool    `json:"enabled"`
	ReadOnly  bool    `json:"readOnly,omitempty"` // toggled through its module
	Interval  int     `json:"interval"`           // seconds
	UpdatedAt float64 `json:"updatedAt"`          // cache mtime (unix), 0 = never downloaded
	CheckedAt float64 `json:"checkedAt,omitempty"`
	Error     string  `json:"error,omitempty"`
	Owner     string  `json:"owner,omitempty"`  // modules using this rule set / script
	Detail    string  `json:"detail,omitempty"` // policy, entry count …
	RefID     string  `json:"refId,omitempty"`  // module id / custom rule id
	ListKind  string  `json:"listKind,omitempty"`
}

type resourceState struct {
	CheckedAt float64 `json:"checkedAt"`
	Error     string  `json:"error,omitempty"`
}

var resStateMu sync.Mutex

func resStatePath(home string) string { return filepath.Join(home, "resources-state.json") }

func readResState(home string) map[string]resourceState {
	m := map[string]resourceState{}
	if b, err := os.ReadFile(resStatePath(home)); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func setResState(home, key, errMsg string) {
	resStateMu.Lock()
	defer resStateMu.Unlock()
	m := readResState(home)
	m[key] = resourceState{CheckedAt: float64(time.Now().Unix()), Error: errMsg}
	b, _ := json.MarshalIndent(m, "", "  ")
	_ = writeFileAtomic(resStatePath(home), b) // v0.19.11 (review 6 P2-2): the extension writes it too

}

func mtime(p string) float64 {
	if fi, err := os.Stat(p); err == nil {
		return float64(fi.ModTime().Unix())
	}
	return 0
}

func ruleSetPath(home, u, kind string) string {
	return filepath.Join(home, "ruleset", providerNameFor(u, kind)+".txt")
}

func countLines(p string) int {
	b, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	return strings.Count(string(b), "\n")
}

// remoteOfLine returns the remote list of a custom-rule line (QX filter_remote or Surge RULE-SET /
// DOMAIN-SET with a URL).
func remoteOfLine(line string) (u, kind, policy string, interval int, ok bool) {
	line = strings.TrimSpace(line)
	if sp, good := parseQXRemote(line); good {
		return sp.URL, "list", sp.Policy, sp.Interval, true
	}
	c, err := mitm.ConvertRuleLine(line)
	if err == nil && c.RemoteURL != "" {
		return c.RemoteURL, c.RemoteKind, c.Policy, 0, true
	}
	return "", "", "", 0, false
}

func listResources(home string) []ResourceItem {
	cfg := mitm.LoadConfig(home)
	st := readResState(home)
	var out []ResourceItem
	add := func(it ResourceItem) {
		if s, ok := st[it.Key]; ok {
			it.CheckedAt, it.Error = s.CheckedAt, s.Error
		}
		if it.Interval <= 0 {
			it.Interval = 86400
		}
		out = append(out, it)
	}

	// Modules / rewrite sets. Parse enabled ones for their rule sets and scripts.
	type ref struct {
		owners   []string
		interval int
		listKind string
		policy   string
	}
	moduleSets := map[string]*ref{} // ruleset key → owners
	scripts := map[string]*ref{}    // url → owners
	scriptOrder := []string{}
	note := func(m map[string]*ref, key, owner string, interval int) *ref {
		r, ok := m[key]
		if !ok {
			r = &ref{interval: interval}
			m[key] = r
		}
		for _, o := range r.owners {
			if o == owner {
				return r
			}
		}
		r.owners = append(r.owners, owner)
		return r
	}
	for _, m := range cfg.Modules {
		path := mitm.ModulePath(home, m.ID)
		it := ResourceItem{Key: "module:" + m.ID, Kind: "module", Name: m.Name, URL: m.URL, Enabled: m.Enabled,
			Interval: m.Interval, UpdatedAt: mtime(path), RefID: m.ID}
		b, err := os.ReadFile(path)
		if err == nil {
			sub := &mitm.Ruleset{}
			sub.ParseText(string(b), m.Name, m.Args)
			it.Format = sub.Format
			it.Detail = fmt.Sprintf("%d 条规则/脚本 · %d 个主机", len(sub.Rules)+len(sub.Tasks), len(sub.Hostnames))
			if m.Enabled {
				for _, r := range mitm.RemoteCoreRules(sub.CoreRules) {
					if u, kind, pol, _, ok := remoteOfLine(r); ok {
						rf := note(moduleSets, "ruleset:"+kind+"|"+u, m.Name, 0)
						rf.listKind, rf.policy = kind, pol
					}
				}
				for _, r := range sub.Rules {
					if r.Kind == mitm.KindScript && isRemoteURL(r.Script.Path) {
						if _, seen := scripts[r.Script.Path]; !seen {
							scriptOrder = append(scriptOrder, r.Script.Path)
						}
						note(scripts, r.Script.Path, m.Name, r.Script.UpdateInterval)
					}
				}
				for _, t := range sub.Tasks {
					if isRemoteURL(t.Script.Path) {
						if _, seen := scripts[t.Script.Path]; !seen {
							scriptOrder = append(scriptOrder, t.Script.Path)
						}
						note(scripts, t.Script.Path, m.Name, t.Script.UpdateInterval)
					}
				}
			}
		} else if m.URL != "" {
			it.Detail = "未下载"
		}
		if m.URL == "" {
			it.Detail = strings.TrimSpace("本地 · " + it.Detail)
		}
		add(it)
	}

	// User rule sets (rules.json).
	seenSet := map[string]bool{}
	for _, r := range readCustomRules(home) {
		u, kind, pol, iv, ok := remoteOfLine(r.Line)
		if !ok {
			continue
		}
		key := "ruleset:" + kind + "|" + u
		seenSet[key] = true
		if r.Interval > 0 {
			iv = r.Interval
		}
		p := ruleSetPath(home, u, kind)
		it := ResourceItem{Key: key, Kind: "ruleset", Name: listName(u), URL: u, Format: kind, Enabled: r.Enabled,
			Interval: iv, UpdatedAt: mtime(p), RefID: r.ID, ListKind: kind, Detail: "→ " + pol}
		if n := countLines(p); n > 0 {
			it.Detail += fmt.Sprintf(" · %d 条", n)
		}
		if o := moduleSets[key]; o != nil {
			it.Owner = strings.Join(o.owners, "、")
		}
		add(it)
	}
	// Rule sets that only come from modules.
	keys := make([]string, 0, len(moduleSets))
	for k := range moduleSets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if seenSet[key] {
			continue
		}
		o := moduleSets[key]
		kind, u, _ := strings.Cut(strings.TrimPrefix(key, "ruleset:"), "|")
		p := ruleSetPath(home, u, kind)
		it := ResourceItem{Key: key, Kind: "ruleset", Name: listName(u), URL: u, Format: kind, Enabled: true, ReadOnly: true,
			UpdatedAt: mtime(p), Owner: strings.Join(o.owners, "、"), ListKind: kind, Detail: "→ " + o.policy}
		if n := countLines(p); n > 0 {
			it.Detail += fmt.Sprintf(" · %d 条", n)
		}
		add(it)
	}

	// User script lines.
	for _, s := range cfg.Scripts {
		if !s.Enabled {
			continue
		}
		sub := &mitm.Ruleset{}
		sub.ParseLine(s.Line, "script", "用户")
		for _, r := range sub.Rules {
			if r.Kind == mitm.KindScript && isRemoteURL(r.Script.Path) {
				if _, seen := scripts[r.Script.Path]; !seen {
					scriptOrder = append(scriptOrder, r.Script.Path)
				}
				note(scripts, r.Script.Path, "脚本", r.Script.UpdateInterval)
			}
		}
		for _, t := range sub.Tasks {
			if isRemoteURL(t.Script.Path) {
				if _, seen := scripts[t.Script.Path]; !seen {
					scriptOrder = append(scriptOrder, t.Script.Path)
				}
				note(scripts, t.Script.Path, "脚本", t.Script.UpdateInterval)
			}
		}
	}
	// Scripts the user disabled stay listed (so they can be turned back on).
	for u := range cfg.ScriptResources {
		if _, seen := scripts[u]; !seen && isRemoteURL(u) {
			scripts[u] = &ref{}
			scriptOrder = append(scriptOrder, u)
		}
	}
	for _, u := range scriptOrder {
		o := scripts[u]
		it := ResourceItem{Key: "script:" + u, Kind: "script", Name: listName(u), URL: u, Format: "js", Enabled: true,
			Interval: o.interval, UpdatedAt: mtime(mitm.CachePath(home, u)), Owner: strings.Join(o.owners, "、")}
		if r, ok := cfg.ScriptResources[u]; ok {
			it.Enabled = !r.Disabled
			if r.Interval > 0 {
				it.Interval = r.Interval
			}
		}
		add(it)
	}
	if out == nil {
		out = []ResourceItem{}
	}
	return out
}

func isRemoteURL(p string) bool {
	return strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://")
}

// listName is a readable name for a URL: its last path component.
func listName(u string) string {
	s := u
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, "/")
	if i := strings.LastIndex(s, "/"); i >= 0 && i+1 < len(s) {
		s = s[i+1:]
	}
	return s
}

// ResourceList returns the resource manager rows as JSON.
func ResourceList(homeDir string) string {
	b, _ := json.Marshal(listResources(homeDir))
	return string(b)
}

func looksLikeHTML(b []byte) bool {
	t := strings.ToLower(strings.TrimSpace(string(b[:min(len(b), 256)])))
	return strings.HasPrefix(t, "<!doctype html") || strings.HasPrefix(t, "<html")
}

// storeResource validates and writes downloaded bytes for key; returns a short summary.
func storeResource(home, key string, data []byte) (string, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return "", errors.New("内容为空")
	}
	if looksLikeHTML(data) {
		return "", errors.New("下载到的是网页而不是资源文件（链接可能失效或需要登录）")
	}
	kind, rest, _ := strings.Cut(key, ":")
	switch kind {
	case "module":
		cfg := mitm.LoadConfig(home)
		var mod *mitm.Module
		for i := range cfg.Modules {
			if cfg.Modules[i].ID == rest {
				mod = &cfg.Modules[i]
			}
		}
		if mod == nil {
			return "", errors.New("模块不存在")
		}
		sub := &mitm.Ruleset{}
		sub.ParseText(string(data), mod.Name, mod.Args)
		if len(sub.Rules)+len(sub.Hostnames)+len(sub.CoreRules)+len(sub.Tasks)+len(sub.Panels) == 0 {
			return "", errors.New("未识别到可用的重写、脚本、规则或 MitM 内容")
		}
		p := mitm.ModulePath(home, rest)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := writeFileAtomic(p, data); err != nil {
			return "", err
		}
		return fmt.Sprintf("%d 条规则/脚本，%d 个主机", len(sub.Rules)+len(sub.Tasks), len(sub.Hostnames)), nil
	case "ruleset":
		lk, u, ok := strings.Cut(rest, "|")
		if !ok {
			return "", errors.New("无效的规则集")
		}
		text, n, skipped := convertListText(strings.NewReader(string(data)), lk)
		if n == 0 {
			return "", errors.New("没有可用的规则（格式无法识别）")
		}
		p := ruleSetPath(home, u, lk)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := writeFileAtomic(p, []byte(text)); err != nil {
			return "", err
		}
		msg := fmt.Sprintf("%d 条规则", n)
		if skipped > 0 {
			msg += fmt.Sprintf("，%d 条不支持已跳过", skipped)
		}
		return msg, nil
	case "script":
		p := mitm.CachePath(home, rest)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := writeFileAtomic(p, data); err != nil {
			return "", err
		}
		return fmt.Sprintf("%d KB", (len(data)+1023)/1024), nil
	}
	return "", errors.New("未知资源类型")
}

// writeFileAtomic: v0.19.10 (review 5 go-core P2-5) unique temp name + fsync + rename (writeAtomic). The
// fixed "<file>.tmp" let two writers (app reset + extension flush, two 更新 at once) interleave.
func writeFileAtomic(p string, b []byte) error {
	if err := writeAtomic(p, b); err != nil {
		return err
	}
	_ = os.Chmod(p, 0o644)
	return nil
}

// ResourceStore saves downloaded bytes for a resource key and records the result. Returns JSON
// {"ok":bool,"message":"…","error":"…"}.
func ResourceStore(homeDir, key string, data []byte) string {
	msg, err := storeResource(homeDir, key, data)
	res := map[string]any{"ok": err == nil, "message": msg}
	if err != nil {
		res["error"] = err.Error()
		setResState(homeDir, key, err.Error())
	} else {
		setResState(homeDir, key, "")
	}
	b, _ := json.Marshal(res)
	return string(b)
}

// ResourceSetError records a failed download (network error, HTTP status) for key.
func ResourceSetError(homeDir, key, message string) {
	setResState(homeDir, key, message)
}
