package libmihomo

// v0.15.4: editing the nodes that live in a profile file itself (节点管理 → 本地节点 → 配置 · <profile>).
// Edits are made on the YAML node tree (go.yaml.in/yaml/v3), so the order of keys and entries, comments and
// every other section stay as they were; only the touched proxy entry and the references to a renamed /
// deleted node change. Before writing, the edited profile is validated the same way ValidateConfigIn does,
// and the previous file is kept as <file>.bak (one-level undo, ProfileNodeUndo).

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	"go.yaml.in/yaml/v3"
)

type yamlDoc struct {
	doc  yaml.Node
	root *yaml.Node
}

func loadDoc(path string) (*yamlDoc, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	d := &yamlDoc{}
	if err := yaml.Unmarshal(b, &d.doc); err != nil {
		return nil, nil, fmt.Errorf("YAML 解析失败: %w", err)
	}
	if d.doc.Kind != yaml.DocumentNode || len(d.doc.Content) == 0 || d.doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil, errors.New("配置文件不是 YAML 映射")
	}
	d.root = d.doc.Content[0]
	return d, b, nil
}

func (d *yamlDoc) bytes() ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&d.doc); err != nil {
		return nil, err
	}
	_ = enc.Close()
	return buf.Bytes(), nil
}

// mapValue returns the value node for key in a mapping node (nil when absent) and its index.
func ymapValue(m *yaml.Node, key string) (*yaml.Node, int) {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, -1
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1], i
		}
	}
	return nil, -1
}

func scalarValue(m *yaml.Node, key string) string {
	if v, _ := ymapValue(m, key); v != nil && v.Kind == yaml.ScalarNode {
		return v.Value
	}
	return ""
}

func (d *yamlDoc) proxies() *yaml.Node {
	v, _ := ymapValue(d.root, "proxies")
	if v != nil && v.Kind == yaml.SequenceNode {
		return v
	}
	return nil
}

func (d *yamlDoc) findProxy(name string) (int, *yaml.Node) {
	seq := d.proxies()
	if seq == nil {
		return -1, nil
	}
	for i, it := range seq.Content {
		if it.Kind == yaml.MappingNode && scalarValue(it, "name") == name {
			return i, it
		}
	}
	return -1, nil
}

// names of every proxy and group in the file (for the duplicate check).
func (d *yamlDoc) allNames() map[string]bool {
	out := map[string]bool{}
	if seq := d.proxies(); seq != nil {
		for _, it := range seq.Content {
			if n := scalarValue(it, "name"); n != "" {
				out[n] = true
			}
		}
	}
	if g, _ := ymapValue(d.root, "proxy-groups"); g != nil && g.Kind == yaml.SequenceNode {
		for _, it := range g.Content {
			if n := scalarValue(it, "name"); n != "" {
				out[n] = true
			}
		}
	}
	return out
}

var builtinTargets = map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "COMPATIBLE": true, "GLOBAL": true}

// normalizeJSON turns integral float64s from JSON into ints, recursively.
func normalizeJSON(v any) any {
	switch t := v.(type) {
	case float64:
		if t == float64(int64(t)) {
			return int64(t)
		}
		return t
	case map[string]any:
		for k, x := range t {
			t[k] = normalizeJSON(x)
		}
		return t
	case []any:
		for i, x := range t {
			t[i] = normalizeJSON(x)
		}
		return t
	}
	return v
}

func encodeValue(v any) (*yaml.Node, error) {
	var n yaml.Node
	if err := n.Encode(v); err != nil {
		return nil, err
	}
	return &n, nil
}

// sameScalar: the existing scalar already says v (keeps its quoting / style).
func sameScalar(old *yaml.Node, v any) bool {
	if old == nil || old.Kind != yaml.ScalarNode {
		return false
	}
	switch t := v.(type) {
	case string:
		return old.Value == t && (old.Tag == "!!str" || old.Tag == "" || old.Style != 0)
	case bool:
		b, err := strconv.ParseBool(old.Value)
		return err == nil && b == t && old.Tag == "!!bool"
	case int64:
		return old.Value == strconv.FormatInt(t, 10) && old.Tag == "!!int"
	case int:
		return old.Value == strconv.Itoa(t) && old.Tag == "!!int"
	}
	return false
}

var leadKeys = []string{"name", "type", "server", "port"}

// applyMap rewrites mapping node m to hold exactly the keys of want, in place: existing keys keep their
// position (and comments), removed keys go, new keys are appended (name / type / server / port first).
func applyMap(m *yaml.Node, want map[string]any) error {
	var content []*yaml.Node
	seen := map[string]bool{}
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, old := m.Content[i], m.Content[i+1]
		v, ok := want[k.Value]
		if !ok {
			continue
		}
		seen[k.Value] = true
		switch {
		case sameScalar(old, v):
		case old.Kind == yaml.MappingNode && isMap(v):
			if err := applyMap(old, v.(map[string]any)); err != nil {
				return err
			}
		default:
			nv, err := encodeValue(v)
			if err != nil {
				return err
			}
			nv.HeadComment, nv.LineComment, nv.FootComment = old.HeadComment, old.LineComment, old.FootComment
			if m.Style&yaml.FlowStyle != 0 {
				nv.Style |= yaml.FlowStyle
			}
			old = nv
		}
		content = append(content, k, old)
	}
	var rest []string
	for k := range want {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.SliceStable(rest, func(i, j int) bool {
		ri, rj := leadRank(rest[i]), leadRank(rest[j])
		if ri != rj {
			return ri < rj
		}
		return rest[i] < rest[j]
	})
	for _, k := range rest {
		nv, err := encodeValue(want[k])
		if err != nil {
			return err
		}
		if m.Style&yaml.FlowStyle != 0 {
			nv.Style |= yaml.FlowStyle
		}
		content = append(content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}, nv)
	}
	m.Content = content
	return nil
}

func isMap(v any) bool { _, ok := v.(map[string]any); return ok }

func leadRank(k string) int {
	for i, l := range leadKeys {
		if l == k {
			return i
		}
	}
	return len(leadKeys)
}

// ruleTarget returns the index of a rule line's policy field (last one, skipping no-resolve / src).
func ruleTarget(parts []string) int {
	i := len(parts) - 1
	for i > 1 {
		p := strings.TrimSpace(parts[i])
		if p == "no-resolve" || p == "src" {
			i--
			continue
		}
		break
	}
	return i
}

// splitRule splits on commas outside parentheses (logic rules: AND,((DOMAIN,a),(NETWORK,UDP)),Target).
func ysplitRule(s string) []string {
	var out []string
	depth, start := 0, 0
	for i, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

// ruleSeqs: rules plus every sub-rules list.
func (d *yamlDoc) ruleSeqs() []*yaml.Node {
	var out []*yaml.Node
	if r, _ := ymapValue(d.root, "rules"); r != nil && r.Kind == yaml.SequenceNode {
		out = append(out, r)
	}
	if sr, _ := ymapValue(d.root, "sub-rules"); sr != nil && sr.Kind == yaml.MappingNode {
		for i := 1; i < len(sr.Content); i += 2 {
			if sr.Content[i].Kind == yaml.SequenceNode {
				out = append(out, sr.Content[i])
			}
		}
	}
	return out
}

func (d *yamlDoc) groups() []*yaml.Node {
	g, _ := ymapValue(d.root, "proxy-groups")
	if g == nil || g.Kind != yaml.SequenceNode {
		return nil
	}
	return g.Content
}

// renameStats counts what a rename / delete touched.
type renameStats struct {
	Groups  []string `json:"groups,omitempty"`
	Rules   int      `json:"rules"`
	Dialers []string `json:"dialers,omitempty"`
}

// renameRefs renames every reference to old (group members, dialer-proxy, rule targets); new == "" deletes them.
func (d *yamlDoc) renameRefs(old, new string) renameStats {
	var st renameStats
	for _, g := range d.groups() {
		gname := scalarValue(g, "name")
		if m, _ := ymapValue(g, "proxies"); m != nil && m.Kind == yaml.SequenceNode {
			var keep []*yaml.Node
			hit := false
			for _, x := range m.Content {
				if x.Kind == yaml.ScalarNode && x.Value == old {
					hit = true
					if new == "" {
						continue
					}
					x.Value = new
				}
				keep = append(keep, x)
			}
			m.Content = keep
			if hit {
				st.Groups = append(st.Groups, gname)
			}
		}
		if v, _ := ymapValue(g, "dialer-proxy"); v != nil && v.Value == old {
			st.Dialers = append(st.Dialers, gname)
			if new == "" {
				removeKey(g, "dialer-proxy")
			} else {
				v.Value = new
			}
		}
	}
	if seq := d.proxies(); seq != nil {
		for _, p := range seq.Content {
			if v, _ := ymapValue(p, "dialer-proxy"); v != nil && v.Value == old {
				st.Dialers = append(st.Dialers, scalarValue(p, "name"))
				if new == "" {
					removeKey(p, "dialer-proxy")
				} else {
					v.Value = new
				}
			}
		}
	}
	for _, seq := range d.ruleSeqs() {
		var keep []*yaml.Node
		for _, r := range seq.Content {
			if r.Kind == yaml.ScalarNode {
				parts := ysplitRule(r.Value)
				if len(parts) >= 2 {
					ti := ruleTarget(parts)
					if strings.TrimSpace(parts[ti]) == old {
						st.Rules++
						if new == "" {
							continue
						}
						parts[ti] = new
						r.Value = strings.Join(parts, ",")
					}
				}
			}
			keep = append(keep, r)
		}
		seq.Content = keep
	}
	return st
}

func removeKey(m *yaml.Node, key string) {
	if _, i := ymapValue(m, key); i >= 0 {
		m.Content = append(m.Content[:i], m.Content[i+2:]...)
	}
}

// groupKeepsMembers: a group that also takes nodes from providers / include-all is not empty without its list.
func groupKeepsMembers(g *yaml.Node) bool {
	if u, _ := ymapValue(g, "use"); u != nil && len(u.Content) > 0 {
		return true
	}
	for _, k := range []string{"include-all", "include-all-proxies", "include-all-providers"} {
		if scalarValue(g, k) == "true" {
			return true
		}
	}
	return false
}

func validateProfileBytes(home, path string, b []byte) string {
	C.SetHomeDir(home)
	rt, err := buildRuntime(b, overridesFor(home, path), 0)
	if err != nil {
		return err.Error()
	}
	return parseRuntimeCached(home, rt) // B32
}

// commit validates the edited document and writes it, keeping the previous file as <path>.bak. An error the
// unedited file already has (e.g. geo data that cannot be downloaded right now) does not block the edit.
func commit(home, path string, orig []byte, d *yamlDoc) string {
	nb, err := d.bytes()
	if err != nil {
		return err.Error()
	}
	if e := validateProfileBytes(home, path, nb); e != "" {
		if pre := validateProfileBytes(home, path, orig); pre == "" || pre != e {
			return e
		}
	}
	if err := writeAtomic(path+".bak", orig); err != nil {
		return err.Error()
	}
	// v0.19.2: atomic (temp file + rename) like the group-order writer. os.WriteFile truncated the profile
	// first, so a reload running at the same moment (the extension reads it) could see an empty / partial
	// file, and a crash mid-write lost the profile.
	if err := writeAtomic(path, nb); err != nil {
		return err.Error()
	}
	return ""
}

// ProfileNodeGet returns the full proxy entry (JSON) named name in the profile file, or "" (LastError).
func ProfileNodeGet(path, name string) string {
	d, _, err := loadDoc(path)
	if err != nil {
		setLastError(err.Error())
		return ""
	}
	_, n := d.findProxy(name)
	if n == nil {
		setLastError("配置文件里没有这个节点")
		return ""
	}
	var m map[string]any
	if err := n.Decode(&m); err != nil {
		setLastError(err.Error())
		return ""
	}
	b, err := json.Marshal(m)
	if err != nil {
		setLastError(err.Error())
		return ""
	}
	return string(b)
}

// ProfileNodeUpsert replaces the entry named oldName (or appends a new one when oldName is "") with nodeJSON.
// A rename is applied to every reference in the file. Returns "" or an error message.
func ProfileNodeUpsert(homeDir, path, nodeJSON, oldName string) string {
	defer lockPath(path)() // v0.19.6: one read-modify-write of the file at a time
	var node map[string]any
	if err := json.Unmarshal([]byte(nodeJSON), &node); err != nil {
		return err.Error()
	}
	node = normalizeJSON(node).(map[string]any)
	name := strings.TrimSpace(strOf(node["name"]))
	if name == "" || strOf(node["type"]) == "" || (strOf(node["server"]) == "" && !serverlessType(strOf(node["type"]))) {
		return "名称、类型、服务器不能为空"
	}
	node["name"] = name
	if b, err := yaml.Marshal(map[string]any{"proxies": []any{node}, "rules": []any{"MATCH,DIRECT"}}); err == nil {
		if e := validateBytes(b); e != "" {
			return e
		}
	}
	d, orig, err := loadDoc(path)
	if err != nil {
		return err.Error()
	}
	if name != oldName && (d.allNames()[name] || builtinTargets[name]) {
		return "已有同名的节点或策略组"
	}
	seq := d.proxies()
	if oldName == "" {
		if seq == nil {
			seq = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			d.root.Content = append(d.root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "proxies"}, seq)
		}
		item := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		if err := applyMap(item, node); err != nil {
			return err.Error()
		}
		seq.Content = append(seq.Content, item)
	} else {
		_, item := d.findProxy(oldName)
		if item == nil {
			return "配置文件里没有这个节点"
		}
		if err := applyMap(item, node); err != nil {
			return err.Error()
		}
		if name != oldName {
			d.renameRefs(oldName, name)
		}
	}
	return commit(homeDir, path, orig, d)
}

// ProfileNodeDuplicate inserts a copy of name right after it (not added to any group). Returns the new name,
// or "" (LastError).
func ProfileNodeDuplicate(homeDir, path, name, suffix string) string {
	defer lockPath(path)() // v0.19.6: one read-modify-write of the file at a time
	d, orig, err := loadDoc(path)
	if err != nil {
		setLastError(err.Error())
		return ""
	}
	i, item := d.findProxy(name)
	if item == nil {
		setLastError("配置文件里没有这个节点")
		return ""
	}
	if suffix == "" {
		suffix = "copy"
	}
	names := d.allNames()
	nn := name + " " + suffix
	for k := 2; names[nn]; k++ {
		nn = fmt.Sprintf("%s %s %d", name, suffix, k)
	}
	var m map[string]any
	if err := item.Decode(&m); err != nil {
		setLastError(err.Error())
		return ""
	}
	m["name"] = nn
	cp := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Style: item.Style}
	if err := applyMap(cp, m); err != nil {
		setLastError(err.Error())
		return ""
	}
	// keep the original key order
	order := map[string]int{}
	for j := 0; j+1 < len(item.Content); j += 2 {
		order[item.Content[j].Value] = j
	}
	type kv struct{ k, v *yaml.Node }
	var pairs []kv
	for j := 0; j+1 < len(cp.Content); j += 2 {
		pairs = append(pairs, kv{cp.Content[j], cp.Content[j+1]})
	}
	sort.SliceStable(pairs, func(a, b int) bool { return order[pairs[a].k.Value] < order[pairs[b].k.Value] })
	cp.Content = cp.Content[:0]
	for _, p := range pairs {
		cp.Content = append(cp.Content, p.k, p.v)
	}
	seq := d.proxies()
	seq.Content = append(seq.Content[:i+1], append([]*yaml.Node{cp}, seq.Content[i+1:]...)...)
	if e := commit(homeDir, path, orig, d); e != "" {
		setLastError(e)
		return ""
	}
	return nn
}

// deleteCheck is what deleting a node would change (shown before confirming).
type deleteCheck struct {
	Groups      []string `json:"groups,omitempty"`
	EmptyGroups []string `json:"emptyGroups,omitempty"`
	Rules       int      `json:"rules"`
	Dialers     []string `json:"dialers,omitempty"`
	Error       string   `json:"error,omitempty"`
}

func (d *yamlDoc) emptyAfterDelete(name string) []string {
	var out []string
	for _, g := range d.groups() {
		m, _ := ymapValue(g, "proxies")
		if m == nil || groupKeepsMembers(g) {
			continue
		}
		left, had := 0, false
		for _, x := range m.Content {
			if x.Value == name {
				had = true
			} else {
				left++
			}
		}
		if had && left == 0 {
			out = append(out, scalarValue(g, "name"))
		}
	}
	return out
}

// ProfileNodeDeleteCheck returns deleteCheck JSON for deleting name from the profile file.
func ProfileNodeDeleteCheck(path, name string) string {
	var c deleteCheck
	d, _, err := loadDoc(path)
	if err != nil {
		c.Error = err.Error()
	} else if _, n := d.findProxy(name); n == nil {
		c.Error = "配置文件里没有这个节点"
	} else {
		c.EmptyGroups = d.emptyAfterDelete(name)
		st := d.renameRefs(name, "")
		c.Groups, c.Rules, c.Dialers = st.Groups, st.Rules, st.Dialers
	}
	b, _ := json.Marshal(c)
	return string(b)
}

// ProfileNodeDelete removes name from the profile: the entry, group members (a group left with no member
// gets DIRECT), rules that target it and dialer-proxy references. Returns "" or an error message.
func ProfileNodeDelete(homeDir, path, name string) string {
	defer lockPath(path)() // v0.19.6: one read-modify-write of the file at a time
	d, orig, err := loadDoc(path)
	if err != nil {
		return err.Error()
	}
	i, n := d.findProxy(name)
	if n == nil {
		return "配置文件里没有这个节点"
	}
	empty := map[string]bool{}
	for _, g := range d.emptyAfterDelete(name) {
		empty[g] = true
	}
	seq := d.proxies()
	seq.Content = append(seq.Content[:i], seq.Content[i+1:]...)
	d.renameRefs(name, "")
	for _, g := range d.groups() {
		if empty[scalarValue(g, "name")] {
			if m, _ := ymapValue(g, "proxies"); m != nil {
				m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "DIRECT"})
			}
		}
	}
	return commit(homeDir, path, orig, d)
}

// ProfileRenameRefs renames references to a group or node (members, dialer-proxy, rules) without touching
// the entry itself — used when a group that lives outside the file (策略组编辑 added groups) is renamed.
func ProfileRenameRefs(homeDir, path, oldName, newName string) string {
	defer lockPath(path)() // v0.19.6: one read-modify-write of the file at a time
	if oldName == "" || newName == "" || oldName == newName {
		return ""
	}
	d, orig, err := loadDoc(path)
	if err != nil {
		return err.Error()
	}
	st := d.renameRefs(oldName, newName)
	if len(st.Groups) == 0 && st.Rules == 0 && len(st.Dialers) == 0 {
		return ""
	}
	return commit(homeDir, path, orig, d)
}

// ProfileNodeUndo restores <path>.bak (the file before the last node edit). Returns "" or an error message.
func ProfileNodeUndo(path string) string {
	defer lockPath(path)() // v0.19.6: one read-modify-write of the file at a time
	b, err := os.ReadFile(path + ".bak")
	if err != nil {
		return "没有可以撤销的修改"
	}
	cur, _ := os.ReadFile(path)
	if err := writeAtomic(path, b); err != nil {
		return err.Error()
	}
	_ = writeAtomic(path+".bak", cur)
	return ""
}

// ProfileHasNode reports whether the profile file itself defines name (editable in 节点管理).
func ProfileHasNode(path, name string) bool {
	d, _, err := loadDoc(path)
	if err != nil {
		return false
	}
	_, n := d.findProxy(name)
	return n != nil
}
