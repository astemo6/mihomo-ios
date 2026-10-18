package libmihomo

// feat/group-order: the user's order of 策略组, written back into the profile file.
//
// ReorderGroups rewrites only the order of the `proxy-groups:` sequence. Each group entry moves as a block of
// text (its lines plus the comment lines directly above it), so comments, quoting, flow / block style, blank
// lines, section-header comments and every other key stay exactly as they were. When the sequence cannot be
// moved as text (flow-style `proxy-groups: [...]`, odd layouts) the yaml.v3 node tree is permuted and
// re-encoded instead (comments survive, indentation may change). Either way the result must decode to the same
// document as before except for the group order, and must pass the same validation as a node edit, before it
// atomically replaces the file; the previous file is kept as <file>.bak.
//
// Only groups that exist in the file move. Names in the order that are not in the file (groups injected at
// runtime: __MITM__, 手动节点 / node-subscription merges, groups added in 策略组编辑) are ignored, and file groups
// missing from the order (hidden groups, groups new in a subscription update) keep their slot — the listed
// groups are permuted among the slots they already occupy.
//
// Subscription profiles are re-downloaded over the file, so the app also keeps the order in group-edits.json
// ("order", per profile id) and calls GroupOrderReapply after each download.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Fixed messages (App/Core/GoText.swift maps them to the UI language).
const (
	errUnsafeReorder = "无法安全地重排策略组（配置使用了 YAML 锚点或特殊格式）"
	errNoGroups      = "配置文件中没有可排序的策略组"
)

type reorderResult struct {
	Changed bool     `json:"changed"`
	Order   []string `json:"order,omitempty"`  // the file's group order afterwards
	Method  string   `json:"method,omitempty"` // text | node
	Error   string   `json:"error,omitempty"`
}

func (r reorderResult) json() string {
	b, _ := json.Marshal(r)
	return string(b)
}

// groupSlots computes the new order of the file's groups: names listed in want are placed, in want's order,
// into the slots that listed groups occupy; everything else keeps its slot. Returns perm (new index → old index).
func groupSlots(fileNames []string, want []string) []int {
	inFile := map[string]int{}
	for i, n := range fileNames {
		inFile[n] = i
	}
	seen := map[string]bool{}
	var ranked []int
	for _, n := range want {
		if i, ok := inFile[n]; ok && !seen[n] {
			seen[n] = true
			ranked = append(ranked, i)
		}
	}
	perm := make([]int, len(fileNames))
	k := 0
	for i, n := range fileNames {
		if seen[n] {
			perm[i] = ranked[k]
			k++
		} else {
			perm[i] = i
		}
	}
	return perm
}

func isIdentity(p []int) bool {
	for i, v := range p {
		if i != v {
			return false
		}
	}
	return true
}

// splitLines splits keeping the line terminators.
func splitLines(b []byte) []string {
	var out []string
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			out = append(out, string(b))
			break
		}
		out = append(out, string(b[:i+1]))
		b = b[i+1:]
	}
	return out
}

func indentOf(l string) int {
	n := 0
	for _, c := range l {
		if c == ' ' {
			n++
		} else if c == '\t' {
			n += 4
		} else {
			break
		}
	}
	return n
}

func isBlank(l string) bool   { return strings.TrimSpace(l) == "" }
func isComment(l string) bool { return strings.HasPrefix(strings.TrimSpace(l), "#") }

// reorderText moves the group entries as text blocks. Returns an error when the layout is not one it can
// handle safely (the caller falls back to the node tree).
func reorderText(b []byte, root, seq *yaml.Node, keyIdx int, perm []int) ([]byte, error) {
	if seq.Style&yaml.FlowStyle != 0 || len(seq.Content) == 0 {
		return nil, errors.New("flow sequence")
	}
	lines := splitLines(b)
	n := len(seq.Content)
	dash := make([]int, n) // 0-based line index of each item's "-"
	dashCol := -1
	for i, it := range seq.Content {
		l := it.Line - 1
		if l < 0 || l >= len(lines) {
			return nil, errors.New("line out of range")
		}
		ln := strings.TrimRight(lines[l], "\r\n")
		col := it.Column - 1
		if col > len(ln) {
			return nil, errors.New("column out of range")
		}
		pre := strings.TrimSpace(ln[:col])
		switch {
		case pre == "-":
		case pre == "":
			// "-" alone on an earlier line
			j := l - 1
			for j >= 0 && (isBlank(lines[j]) || isComment(lines[j])) {
				j--
			}
			if j < 0 || strings.TrimSpace(lines[j]) != "-" {
				return nil, errors.New("item without dash")
			}
			l = j
		default:
			return nil, errors.New("unexpected text before item")
		}
		c := indentOf(lines[l])
		if dashCol >= 0 && c != dashCol {
			return nil, errors.New("mixed indentation")
		}
		dashCol = c
		dash[i] = l
		if i > 0 && dash[i] <= dash[i-1] {
			return nil, errors.New("items share a line")
		}
	}
	keyLine := root.Content[keyIdx].Line - 1
	if dash[0] <= keyLine {
		return nil, errors.New("item on the key line")
	}
	// End of the sequence: the next top-level key (or EOF), minus that key's own head comments / blank lines.
	end := len(lines)
	if keyIdx+2 < len(root.Content) {
		end = root.Content[keyIdx+2].Line - 1
		if end <= dash[n-1] {
			return nil, errors.New("next key overlaps")
		}
	}
	// start[i]: comment lines directly above the dash (no blank line between, not indented deeper) move with it.
	start := make([]int, n)
	for i := range dash {
		lo := keyLine + 1
		if i > 0 {
			lo = dash[i-1] + 1
		}
		s := dash[i]
		for s-1 >= lo && isComment(lines[s-1]) && indentOf(lines[s-1]) <= dashCol {
			s--
		}
		start[i] = s
	}
	// Body of each item: start[i] .. before its trailing separator (blank lines / outdented comments), which stays
	// in its slot. The last item's region ends at `end`.
	bodyEnd := make([]int, n)
	sepEnd := make([]int, n)
	for i := range dash {
		hi := end
		if i+1 < n {
			hi = start[i+1]
		}
		e := hi
		for e-1 > dash[i] && (isBlank(lines[e-1]) || (isComment(lines[e-1]) && indentOf(lines[e-1]) <= dashCol)) {
			e--
		}
		bodyEnd[i] = e
		sepEnd[i] = hi
	}
	var out strings.Builder
	for _, l := range lines[:start[0]] {
		out.WriteString(l)
	}
	for k := 0; k < n; k++ {
		src := perm[k]
		body := strings.Join(lines[start[src]:bodyEnd[src]], "")
		if !strings.HasSuffix(body, "\n") {
			body += "\n"
		}
		out.WriteString(body)
		for _, l := range lines[bodyEnd[k]:sepEnd[k]] {
			out.WriteString(l)
		}
	}
	for _, l := range lines[sepEnd[n-1]:] {
		out.WriteString(l)
	}
	return []byte(out.String()), nil
}

func groupsSeq(doc *yaml.Node) (root, seq *yaml.Node, keyIdx int, err error) {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil, -1, errors.New("配置文件不是 YAML 映射")
	}
	root = doc.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "proxy-groups" {
			seq = root.Content[i+1]
			keyIdx = i
		}
	}
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return nil, nil, -1, errors.New(errNoGroups)
	}
	return root, seq, keyIdx, nil
}

func seqNames(seq *yaml.Node) ([]string, error) {
	var names []string
	seen := map[string]bool{}
	for _, it := range seq.Content {
		if it.Kind != yaml.MappingNode {
			return nil, errors.New("策略组条目格式无法识别（锚点或非映射条目）")
		}
		nm := scalarValue(it, "name")
		if nm == "" {
			return nil, errors.New("有策略组缺少名称")
		}
		if seen[nm] {
			return nil, fmt.Errorf("策略组「%s」重名", nm)
		}
		seen[nm] = true
		names = append(names, nm)
	}
	return names, nil
}

// sameExceptOrder: candidate decodes to orig with proxy-groups permuted by perm, and keeps every comment line.
func sameExceptOrder(orig, cand []byte, perm []int, textMode bool) error {
	var a, c map[string]any
	if err := yaml.Unmarshal(orig, &a); err != nil {
		return err
	}
	if err := yaml.Unmarshal(cand, &c); err != nil {
		return fmt.Errorf("重排后 YAML 无法解析: %w", err)
	}
	gs, _ := a["proxy-groups"].([]any)
	if len(gs) != len(perm) {
		return errors.New("策略组数量不一致")
	}
	np := make([]any, len(perm))
	for k, src := range perm {
		np[k] = gs[src]
	}
	a["proxy-groups"] = np
	if !reflect.DeepEqual(a, c) {
		return errors.New("重排后内容与原配置不一致")
	}
	if textMode {
		x, y := splitLines(orig), splitLines(cand)
		norm := func(ls []string) []string {
			var o []string
			for _, l := range ls {
				o = append(o, strings.TrimRight(l, "\r\n"))
			}
			sort.Strings(o)
			return o
		}
		if !reflect.DeepEqual(norm(x), norm(y)) {
			return errors.New("重排后行内容不一致")
		}
	}
	return nil
}

// reorderGroupsBytes returns the reordered profile, whether anything changed, and the method used.
func reorderGroupsBytes(b []byte, want []string) ([]byte, bool, string, []string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, false, "", nil, fmt.Errorf("YAML 解析失败: %w", err)
	}
	root, seq, keyIdx, err := groupsSeq(&doc)
	if err != nil {
		return nil, false, "", nil, err
	}
	names, err := seqNames(seq)
	if err != nil {
		return nil, false, "", nil, err
	}
	perm := groupSlots(names, want)
	after := make([]string, len(perm))
	for k, src := range perm {
		after[k] = names[src]
	}
	if isIdentity(perm) {
		return b, false, "", after, nil
	}
	if nb, err := reorderText(b, root, seq, keyIdx, perm); err == nil {
		if sameExceptOrder(b, nb, perm, true) == nil {
			return nb, true, "text", after, nil
		}
	}
	// Fallback: permute the node tree and re-encode.
	items := append([]*yaml.Node(nil), seq.Content...)
	for k, src := range perm {
		seq.Content[k] = items[src]
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, false, "", nil, err
	}
	_ = enc.Close()
	nb := buf.Bytes()
	if err := sameExceptOrder(b, nb, perm, false); err != nil {
		// e.g. a group that uses a YAML alias would end up before its anchor.
		return nil, false, "", nil, errors.New(errUnsafeReorder)
	}
	return nb, true, "node", after, nil
}

// writeAtomic writes b next to path and renames it over path (same directory = same volume).
func writeAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	_ = os.Chmod(tmp, 0o644)
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// reorderFile is ReorderGroups with an injectable validator (tests run without geo data).
func reorderFile(path string, want []string, validate func(b []byte) string) reorderResult {
	orig, err := os.ReadFile(path)
	if err != nil {
		return reorderResult{Error: err.Error()}
	}
	nb, changed, method, after, err := reorderGroupsBytes(orig, want)
	if err != nil {
		return reorderResult{Error: err.Error()}
	}
	if !changed {
		return reorderResult{Order: after}
	}
	if validate != nil {
		if e := validate(nb); e != "" {
			// An error the unchanged file already has (e.g. geo data not downloadable right now) does not block.
			if pre := validate(orig); pre == "" || pre != e {
				return reorderResult{Error: e}
			}
		}
	}
	if err := writeAtomic(path+".bak", orig); err != nil {
		return reorderResult{Error: err.Error()}
	}
	if err := writeAtomic(path, nb); err != nil {
		return reorderResult{Error: err.Error()}
	}
	return reorderResult{Changed: true, Order: after, Method: method}
}

// ReorderGroups puts the profile's proxy-groups in the order of orderJSON (a JSON array of group names), see
// the file comment. Returns JSON {changed, order, method, error}.
func ReorderGroups(homeDir, profilePath, orderJSON string) (out string) {
	defer func() {
		if r := recover(); r != nil {
			out = reorderResult{Error: fmt.Sprint(r)}.json()
		}
	}()
	var want []string
	if err := json.Unmarshal([]byte(orderJSON), &want); err != nil {
		return reorderResult{Error: err.Error()}.json()
	}
	return reorderFile(profilePath, want, func(b []byte) string { return validateProfileBytes(homeDir, profilePath, b) }).json()
}

// storedGroupOrder is the order kept in group-edits.json for the profile (subscriptions).
func storedGroupOrder(home, profileID string) []string {
	if e := readGroupEdits(home, profileID); e != nil {
		return e.Order
	}
	return nil
}

// GroupOrderReapply re-applies the stored order (group-edits.json "order") to the profile file, e.g. right
// after a subscription download replaced it. Returns the same JSON as ReorderGroups; {"changed":false} when no
// order is stored.
func GroupOrderReapply(homeDir, profilePath string) string {
	want := storedGroupOrder(homeDir, profileIDFromPath(profilePath))
	if len(want) == 0 {
		return reorderResult{}.json()
	}
	b, _ := json.Marshal(want)
	return ReorderGroups(homeDir, profilePath, string(b))
}

// ProfileGroupNames returns the names of the groups written in the profile file (JSON array, [] when the file has
// none or cannot be read), so the UI can tell file groups (movable) from groups added at runtime.
func ProfileGroupNames(profilePath string) string {
	out := []string{}
	if b, err := os.ReadFile(profilePath); err == nil {
		var doc yaml.Node
		if yaml.Unmarshal(b, &doc) == nil {
			if _, seq, _, err := groupsSeq(&doc); err == nil {
				for _, it := range seq.Content {
					if it.Kind == yaml.MappingNode {
						if n := scalarValue(it, "name"); n != "" {
							out = append(out, n)
						}
					}
				}
			}
		}
	}
	j, _ := json.Marshal(out)
	return string(j)
}
