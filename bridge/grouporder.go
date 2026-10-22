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
// The original profile is never rewritten (user 2026-10-18 16:51): the first reorder writes the new order into
// an 自定义 copy (GroupOrderCopy) that the app switches to; later reorders change only the copy
// (ReorderGroups on the copy's path). The copy's order is also kept in group-edits.json ("order", per copy id):
// when its source subscription updates, GroupOrderRegenerate rebuilds the copy from the fresh source content and
// re-applies that order, so the source stays a pristine mirror of the subscription.

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
	errCopyModified  = "副本已手动修改"
	errUnsafeReorder = "无法安全地重排策略组（配置使用了 YAML 锚点或特殊格式）"
	errNoGroups      = "配置文件中没有可排序的策略组"
)

type reorderResult struct {
	Changed bool `json:"changed"`
	// Modified: the copy was edited by the user since it was last generated: GroupOrderRegenerate left it,
	// GroupOrderCopy reordered it in place (v0.19.1).
	Modified bool     `json:"modified,omitempty"`
	Order    []string `json:"order,omitempty"`  // the file's group order afterwards
	Method   string   `json:"method,omitempty"` // text | node
	Error    string   `json:"error,omitempty"`
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

// reorderFile is ReorderGroups with an injectable validator (tests run without geo data): reorders the file in
// place.
func reorderFile(path string, want []string, validate func(b []byte) string) reorderResult {
	orig, err := os.ReadFile(path)
	if err != nil {
		return reorderResult{Error: err.Error()}
	}
	return reorderInto(orig, path, want, validate, false)
}

// reorderInto writes `src` with its groups in `want` order to `dest` (dest may be the file src came from, or a
// copy of another profile). The previous content of dest, when it exists, is kept as <dest>.bak.
// always=false: nothing is written when the order does not change. always=true (regenerating a copy from fresh
// source content): src is written even when the order is unchanged, and when the reorder or its validation fails
// src is written unchanged and the error is still reported, so the copy never keeps stale content.
func reorderInto(src []byte, dest string, want []string, validate func(b []byte) string, always bool) reorderResult {
	plain := func(e string) reorderResult {
		if !always {
			return reorderResult{Error: e}
		}
		if err := replaceKeepingBak(dest, src); err != nil {
			return reorderResult{Error: err.Error()}
		}
		return reorderResult{Changed: true, Error: e}
	}
	nb, changed, method, after, err := reorderGroupsBytes(src, want)
	if err != nil {
		return plain(err.Error())
	}
	if !changed {
		if !always {
			return reorderResult{Order: after}
		}
		if cur, err := os.ReadFile(dest); err == nil && bytes.Equal(cur, src) {
			return reorderResult{Order: after}
		}
		if err := replaceKeepingBak(dest, src); err != nil {
			return reorderResult{Error: err.Error()}
		}
		return reorderResult{Changed: true, Order: after}
	}
	if validate != nil {
		if e := validate(nb); e != "" {
			// An error the unchanged profile already has (e.g. geo data not downloadable right now) does not block.
			if pre := validate(src); pre == "" || pre != e {
				return plain(e)
			}
		}
	}
	if always {
		// Regenerated content identical to the copy as it is: nothing to write.
		if cur, err := os.ReadFile(dest); err == nil && bytes.Equal(cur, nb) {
			return reorderResult{Order: after, Method: method}
		}
	}
	if err := replaceKeepingBak(dest, nb); err != nil {
		return reorderResult{Error: err.Error()}
	}
	return reorderResult{Changed: true, Order: after, Method: method}
}

// replaceKeepingBak atomically writes b to path, keeping the previous content (if any) as <path>.bak.
func replaceKeepingBak(path string, b []byte) error {
	if cur, err := os.ReadFile(path); err == nil {
		if err := writeAtomic(path+".bak", cur); err != nil {
			return err
		}
	}
	return writeAtomic(path, b)
}

// ReorderGroups puts the profile's proxy-groups in the order of orderJSON (a JSON array of group names), see
// the file comment. The app only calls it on an 自定义 copy (GroupOrderCopy made it), never on an original
// profile. Returns JSON {changed, order, method, error}.
func ReorderGroups(homeDir, profilePath, orderJSON string) (out string) {
	defer lockPath(profilePath)() // v0.19.6: one read-modify-write of the file at a time
	defer func() {
		if r := recover(); r != nil {
			out = reorderResult{Error: fmt.Sprint(r)}.json()
		}
	}()
	var want []string
	if err := json.Unmarshal([]byte(orderJSON), &want); err != nil {
		return reorderResult{Error: err.Error()}.json()
	}
	generated := copyGenerated(profilePath)
	r := reorderFile(profilePath, want, func(b []byte) string { return validateProfileBytes(homeDir, profilePath, b) })
	if r.Error == "" && r.Changed && generated {
		// Only an unedited copy stays "generated"; a reorder must not bless the user's manual edits.
		markGenerated(profilePath)
	}
	return r.json()
}

// GroupOrderCopy writes the source profile with its groups in orderJSON order to copyPath, leaving the source
// file untouched (user 2026-10-18: 「自动复制一个配置文件出来，在复制的配置文件上更新」). Nothing is written
// when the order equals the source's (changed=false: the app then creates no copy). An existing copy (the
// source was reordered again while it was active) is overwritten, its previous content kept as .bak, unless
// the user edited it since it was generated: then only its group order changes (modified=true).
// Validation runs with the source's settings (the copy gets the same settings right after).
func GroupOrderCopy(homeDir, sourcePath, copyPath, orderJSON string) (out string) {
	defer lockPath(copyPath)() // v0.19.6: one read-modify-write of the file at a time
	defer func() {
		if r := recover(); r != nil {
			out = reorderResult{Error: fmt.Sprint(r)}.json()
		}
	}()
	var want []string
	if err := json.Unmarshal([]byte(orderJSON), &want); err != nil {
		return reorderResult{Error: err.Error()}.json()
	}
	// v0.19.1: an existing copy the user edited by hand (node edits, the YAML editor) is reordered in place
	// instead of being rebuilt from the source, so the edits survive (the same rule as GroupOrderRegenerate).
	// Modified=true tells the app to switch to the copy even when its order was already the wanted one.
	if _, err := os.Stat(copyPath); err == nil && !copyGenerated(copyPath) {
		r := reorderFile(copyPath, want, func(b []byte) string { return validateProfileBytes(homeDir, copyPath, b) })
		if r.Error == "" {
			r.Modified = true
		}
		return r.json()
	}
	src, err := os.ReadFile(sourcePath)
	if err != nil {
		return reorderResult{Error: err.Error()}.json()
	}
	r := reorderInto(src, copyPath, want, func(b []byte) string { return validateProfileBytes(homeDir, sourcePath, b) }, false)
	if r.Error == "" && r.Changed {
		markGenerated(copyPath)
	}
	return r.json()
}

// copyGenPath keeps the sha256 of the copy content this package last generated (GroupOrderCopy, regenerate,
// a reorder of an unedited copy), so a later regeneration can tell whether the user edited the copy since.
func copyGenPath(copyPath string) string { return copyPath + ".gen" }

func markGenerated(copyPath string) {
	if b, err := os.ReadFile(copyPath); err == nil {
		_ = writeAtomic(copyGenPath(copyPath), []byte(sha256Hex(b)))
	}
}

// copyGenerated reports whether the copy is still exactly what was last generated. Copies made before the
// .gen marker existed (no marker) count as generated.
func copyGenerated(copyPath string) bool {
	want, err := os.ReadFile(copyGenPath(copyPath))
	if err != nil {
		return true
	}
	b, err := os.ReadFile(copyPath)
	if err != nil {
		return true // nothing to lose
	}
	return strings.TrimSpace(string(want)) == sha256Hex(b)
}

// storedGroupOrder is the order kept in group-edits.json for a profile (the 自定义 copies).
func storedGroupOrder(home, profileID string) []string {
	if e := readGroupEdits(home, profileID); e != nil {
		return e.Order
	}
	return nil
}

// GroupOrderRegenerate rebuilds a copy from its source after the source subscription was updated: the fresh
// source content with the copy's stored order (group-edits.json "order" of the copy's id) applied — groups new
// in the subscription keep the provider's slot. The source file is only read. When no order is stored, or the
// order cannot be applied, the copy becomes the source content as is (error reported when it failed).
func GroupOrderRegenerate(homeDir, sourcePath, copyPath string) (out string) {
	return groupOrderRegenerate(homeDir, sourcePath, copyPath, false)
}

// GroupOrderRegenerateForced is GroupOrderRegenerate even when the user edited the copy (「从订阅重新生成」):
// the edits are replaced (previous content kept as .bak).
func GroupOrderRegenerateForced(homeDir, sourcePath, copyPath string) (out string) {
	return groupOrderRegenerate(homeDir, sourcePath, copyPath, true)
}

// groupOrderRegenerate: without force, a copy edited since it was last generated is left as it is
// ({modified: true, error: 副本已手动修改}).
func groupOrderRegenerate(homeDir, sourcePath, copyPath string, force bool) (out string) {
	defer lockPath(copyPath)() // v0.19.6: one read-modify-write of the file at a time
	defer func() {
		if r := recover(); r != nil {
			out = reorderResult{Error: fmt.Sprint(r)}.json()
		}
	}()
	src, err := os.ReadFile(sourcePath)
	if err != nil {
		return reorderResult{Error: err.Error()}.json()
	}
	if !force && !copyGenerated(copyPath) {
		return reorderResult{Modified: true, Error: errCopyModified}.json()
	}
	want := storedGroupOrder(homeDir, profileIDFromPath(copyPath))
	if len(want) == 0 {
		if cur, err := os.ReadFile(copyPath); err == nil && bytes.Equal(cur, src) {
			markGenerated(copyPath)
			return reorderResult{}.json()
		}
		if err := replaceKeepingBak(copyPath, src); err != nil {
			return reorderResult{Error: err.Error()}.json()
		}
		markGenerated(copyPath)
		return reorderResult{Changed: true}.json()
	}
	r := reorderInto(src, copyPath, want, func(b []byte) string { return validateProfileBytes(homeDir, copyPath, b) }, true)
	if r.Changed || r.Error == "" {
		markGenerated(copyPath) // the file is generated content now (reordered, or the source as is after a failure)
	}
	return r.json()
}

// profileSettingFiles are the home files that keep per-profile settings in a JSON object keyed by profile id
// (策略组编辑, 前置代理 / smart groups, 订阅规则, 网络策略).
var profileSettingFiles = []string{"group-edits.json", "groups.json", "subscriptions.json", "netpolicy.json"}

// CopyProfileSettings gives a new 自定义 copy the per-profile settings of its source, so switching to the copy
// changes nothing but the group order. Entries the copy already has are kept; the source's stored group order
// is not copied. Returns "" or an error.
func CopyProfileSettings(homeDir, fromID, toID string) string {
	if homeDir == "" || fromID == "" || toID == "" || fromID == toID {
		return ""
	}
	for _, f := range profileSettingFiles {
		if e := copyProfileSetting(filepath.Join(homeDir, f), f, fromID, toID); e != "" {
			return e
		}
	}
	return ""
}

// copyProfileSetting copies fromID's entry of one settings file to toID (v0.19.6: under the file's lock).
func copyProfileSetting(p, f, fromID, toID string) string {
	defer lockPath(p)()
	{
		b, err := os.ReadFile(p)
		if err != nil {
			return ""
		}
		m := map[string]json.RawMessage{}
		if json.Unmarshal(b, &m) != nil {
			return ""
		}
		v, ok := m[fromID]
		if !ok {
			return ""
		}
		if _, has := m[toID]; has {
			return ""
		}
		if f == "group-edits.json" {
			var e map[string]json.RawMessage
			if json.Unmarshal(v, &e) == nil {
				delete(e, "order")
				if len(e) == 0 {
					return ""
				}
				v, _ = json.Marshal(e)
			}
		}
		m[toID] = v
		nb, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return err.Error()
		}
		if err := writeAtomic(p, nb); err != nil {
			return err.Error()
		}
	}
	return ""
}

// ForgetProfile removes a deleted profile's per-profile settings (the profileSettingFiles entries keyed by its id)
// and its side files: <file>.bak, <file>.gen, <profile>.selected.json. Returns "" or an error.
func ForgetProfile(homeDir, profileID, profilePath string) string {
	var firstErr string
	if homeDir != "" && profileID != "" {
		for _, f := range profileSettingFiles {
			p := filepath.Join(homeDir, f)
			func() {
				defer lockPath(p)() // v0.19.6
				b, err := os.ReadFile(p)
				if err != nil {
					return
				}
				m := map[string]json.RawMessage{}
				if json.Unmarshal(b, &m) != nil {
					return
				}
				if _, ok := m[profileID]; !ok {
					return
				}
				delete(m, profileID)
				nb, err := json.MarshalIndent(m, "", "  ")
				if err == nil {
					err = writeAtomic(p, nb)
				}
				if err != nil && firstErr == "" {
					firstErr = err.Error()
				}
			}()
		}
	}
	if profilePath != "" {
		for _, side := range []string{profilePath + ".bak", copyGenPath(profilePath), selectionsPath(profilePath), confSourcePath(profilePath)} {
			_ = os.Remove(side)
		}
	}
	return firstErr
}

// CopyProfileSelections gives a new 自定义 copy the source's offline selections (<profile>.selected.json), so the
// copy starts on the same nodes. An existing file of the copy is kept.
func CopyProfileSelections(fromPath, toPath string) string {
	defer lockPath(selectionsPath(toPath))() // v0.19.6: one read-modify-write of the file at a time
	b, err := os.ReadFile(selectionsPath(fromPath))
	if err != nil {
		return ""
	}
	dst := selectionsPath(toPath)
	if _, err := os.Stat(dst); err == nil {
		return ""
	}
	if err := writeAtomic(dst, b); err != nil {
		return err.Error()
	}
	return ""
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
