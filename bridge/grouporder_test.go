package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const goProfile = `# 我的配置 — header comment
mixed-port: 7890
proxies:
  - {name: n1, type: ss, server: 192.0.2.1, port: 8388, cipher: aes-128-gcm, password: x}
  - {name: n2, type: ss, server: 192.0.2.2, port: 8388, cipher: aes-128-gcm, password: x}

proxy-groups:
  # 节点选择 — 主策略
  - name: 节点选择
    type: select
    proxies:
      - n1
      - n2
      # - n3 (disabled member, stays inside this group)
      - DIRECT

  # ---- 自动 ----

  - name: 自动
    type: url-test   # inline comment
    proxies: [n1, n2]
    url: "http://www.gstatic.com/generate_204"
    interval: 300
  - name: 隐藏
    type: select
    hidden: true
    proxies: [n1]
  # 流媒体
  - {name: 流媒体, type: select, proxies: [节点选择, DIRECT]}

# 规则 — belongs to rules
rules:
  - DOMAIN-SUFFIX,example.com,流媒体
  - MATCH,节点选择
`

func writeTmp(t *testing.T, name, s string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func groupNamesOf(t *testing.T, b []byte) []string {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal(b, &m); err != nil {
		t.Fatalf("decode: %v\n%s", err, b)
	}
	var out []string
	for _, g := range m["proxy-groups"].([]any) {
		out = append(out, g.(map[string]any)["name"].(string))
	}
	return out
}

func TestGroupOrderSlots(t *testing.T) {
	names := []string{"A", "B", "H", "C"}
	got := groupSlots(names, []string{"__MITM__", "C", "Merged", "A", "B", "C"})
	// A,B,C occupy slots 0,1,3 → C,A,_,B ; H keeps slot 2.
	want := []int{3, 0, 2, 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("perm %v want %v", got, want)
	}
	if !isIdentity(groupSlots(names, nil)) {
		t.Fatal("empty order must not move anything")
	}
}

func TestGroupOrderKeepsComments(t *testing.T) {
	p := writeTmp(t, "prof.yaml", goProfile)
	r := reorderFile(p, []string{"流媒体", "自动", "节点选择"}, nil)
	if r.Error != "" || !r.Changed || r.Method != "text" {
		t.Fatalf("result %+v", r)
	}
	b, _ := os.ReadFile(p)
	s := string(b)
	if got := groupNamesOf(t, b); !reflect.DeepEqual(got, []string{"流媒体", "自动", "隐藏", "节点选择"}) {
		t.Fatalf("order %v\n%s", got, s)
	}
	if !reflect.DeepEqual(r.Order, []string{"流媒体", "自动", "隐藏", "节点选择"}) {
		t.Fatalf("reported order %v", r.Order)
	}
	// Every original line is still there, and the comments travel with their groups.
	for _, l := range strings.Split(goProfile, "\n") {
		if !strings.Contains(s, l) {
			t.Fatalf("line lost: %q\n%s", l, s)
		}
	}
	idx := func(sub string) int { return strings.Index(s, sub) }
	if !(idx("# 流媒体") < idx("{name: 流媒体") && idx("{name: 流媒体") < idx("name: 自动")) {
		t.Fatalf("head comment did not move with its group:\n%s", s)
	}
	if !(idx("# 节点选择 — 主策略") < idx("- name: 节点选择") && idx("# - n3") > idx("- name: 节点选择") && idx("# - n3") < idx("# 规则")) {
		t.Fatalf("节点选择 block broken:\n%s", s)
	}
	if !strings.HasPrefix(s, "# 我的配置 — header comment\nmixed-port: 7890\n") {
		t.Fatalf("header changed:\n%s", s)
	}
	if !strings.Contains(s, "      - DIRECT\n\n# 规则 — belongs to rules\nrules:") {
		t.Fatalf("rules header comment moved:\n%s", s)
	}
	// Section-header comment stays in its slot (after the first group).
	if !(idx("# ---- 自动 ----") > idx("{name: 流媒体") && idx("# ---- 自动 ----") < idx("name: 自动")) {
		t.Fatalf("section comment slot:\n%s", s)
	}
	// .bak holds the previous file.
	if bak, _ := os.ReadFile(p + ".bak"); string(bak) != goProfile {
		t.Fatal(".bak is not the original")
	}
	// Same order again: nothing written.
	st, _ := os.Stat(p)
	r2 := reorderFile(p, r.Order, nil)
	if r2.Changed || r2.Error != "" {
		t.Fatalf("second run %+v", r2)
	}
	st2, _ := os.Stat(p)
	if !st2.ModTime().Equal(st.ModTime()) {
		t.Fatal("identical order rewrote the file")
	}
	// No temp files left behind.
	ents, _ := os.ReadDir(filepath.Dir(p))
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("temp file left: %s", e.Name())
		}
	}
}

func TestGroupOrderUnknownAndInjectedIgnored(t *testing.T) {
	p := writeTmp(t, "prof.yaml", goProfile)
	// Order as the app sees it at runtime: injected __MITM__ / merged 手动节点 groups, hidden group not listed.
	r := reorderFile(p, []string{"__MITM__", "手动节点", "自动", "不存在", "流媒体", "节点选择", "GLOBAL"}, nil)
	if r.Error != "" || !r.Changed {
		t.Fatalf("%+v", r)
	}
	b, _ := os.ReadFile(p)
	// 隐藏 keeps slot 2; listed ones fill slots 0,1,3.
	if got := groupNamesOf(t, b); !reflect.DeepEqual(got, []string{"自动", "流媒体", "隐藏", "节点选择"}) {
		t.Fatalf("order %v", got)
	}
	// Only unknown names: no change at all.
	r = reorderFile(p, []string{"__MITM__", "x"}, nil)
	if r.Changed || r.Error != "" {
		t.Fatalf("unknown-only %+v", r)
	}
}

func TestGroupOrderFlowStyleFallsBackToNodes(t *testing.T) {
	src := "# top\nproxies: []\nproxy-groups: [{name: A, type: select, proxies: [DIRECT]}, {name: B, type: select, proxies: [DIRECT]}] # groups\nrules: [MATCH,A]\n"
	p := writeTmp(t, "flow.yaml", src)
	r := reorderFile(p, []string{"B", "A"}, nil)
	if r.Error != "" || !r.Changed || r.Method != "node" {
		t.Fatalf("%+v", r)
	}
	b, _ := os.ReadFile(p)
	if got := groupNamesOf(t, b); !reflect.DeepEqual(got, []string{"B", "A"}) {
		t.Fatalf("order %v", got)
	}
	if !strings.Contains(string(b), "# top") || !strings.Contains(string(b), "# groups") {
		t.Fatalf("comments lost:\n%s", b)
	}
}

func TestGroupOrderCRLFAndNoTrailingNewline(t *testing.T) {
	src := "proxy-groups:\r\n  - name: A\r\n    type: select\r\n    proxies: [DIRECT]\r\n  - name: B\r\n    type: select\r\n    proxies: [DIRECT]"
	p := writeTmp(t, "crlf.yaml", src)
	r := reorderFile(p, []string{"B", "A"}, nil)
	if r.Error != "" || !r.Changed {
		t.Fatalf("%+v", r)
	}
	b, _ := os.ReadFile(p)
	if got := groupNamesOf(t, b); !reflect.DeepEqual(got, []string{"B", "A"}) {
		t.Fatalf("order %v\n%q", got, b)
	}
}

func TestGroupOrderValidation(t *testing.T) {
	p := writeTmp(t, "prof.yaml", goProfile)
	// The validator rejects the reordered profile (not the original): file untouched, no .bak.
	r := reorderFile(p, []string{"自动", "节点选择"}, func(b []byte) string {
		if strings.Index(string(b), "name: 自动") < strings.Index(string(b), "name: 节点选择") {
			return "rejected"
		}
		return ""
	})
	if r.Error != "rejected" || r.Changed {
		t.Fatalf("%+v", r)
	}
	if b, _ := os.ReadFile(p); string(b) != goProfile {
		t.Fatal("file changed after a failed validation")
	}
	if _, err := os.Stat(p + ".bak"); err == nil {
		t.Fatal(".bak written after a failed validation")
	}
	// An error the original already has does not block the reorder.
	r = reorderFile(p, []string{"自动", "节点选择"}, func([]byte) string { return "geo data missing" })
	if r.Error != "" || !r.Changed {
		t.Fatalf("pre-existing error blocked: %+v", r)
	}
}

func TestGroupOrderAnchorsRefused(t *testing.T) {
	src := "proxy-groups:\n  - &base\n    name: A\n    type: select\n    proxies: [DIRECT]\n  - name: B\n    type: select\n    proxies: *x\n"
	src = strings.Replace(src, "proxies: [DIRECT]\n  - name: B", "proxies: &x [DIRECT]\n  - name: B", 1)
	p := writeTmp(t, "anchor.yaml", src)
	r := reorderFile(p, []string{"B", "A"}, nil)
	if r.Error == "" || r.Changed {
		t.Fatalf("alias before anchor must be refused: %+v", r)
	}
	if b, _ := os.ReadFile(p); string(b) != src {
		t.Fatal("file changed")
	}
}

func TestGroupOrderBadInput(t *testing.T) {
	p := writeTmp(t, "nogroups.yaml", "proxies: []\nrules: [MATCH,DIRECT]\n")
	if r := reorderFile(p, []string{"A"}, nil); r.Error == "" {
		t.Fatal("profile without proxy-groups must error")
	}
	p = writeTmp(t, "dup.yaml", "proxy-groups:\n  - {name: A, type: select, proxies: [DIRECT]}\n  - {name: A, type: select, proxies: [DIRECT]}\n")
	if r := reorderFile(p, []string{"A"}, nil); r.Error == "" {
		t.Fatal("duplicate names must error")
	}
	var res reorderResult
	_ = json.Unmarshal([]byte(ReorderGroups(t.TempDir(), p, "not json")), &res)
	if res.Error == "" {
		t.Fatal("bad JSON must error")
	}
}

// End to end through the exported functions with the real validator (no geo rules, so no download): the first
// reorder goes into a copy (source untouched), later reorders change the copy, and a subscription update
// regenerates the copy from the fresh source with the copy's stored order (group-edits.json of the copy's id).
func TestGroupOrderCopyAndRegenerate(t *testing.T) {
	home := t.TempDir()
	prof := filepath.Join(home, "profiles")
	_ = os.MkdirAll(prof, 0o755)
	src := filepath.Join(prof, "SUB-1.yaml")
	cp := filepath.Join(prof, "COPY-1.yaml")
	if err := os.WriteFile(src, []byte(goProfile), 0o644); err != nil {
		t.Fatal(err)
	}
	var r reorderResult
	// Same order as the source: no copy is written.
	_ = json.Unmarshal([]byte(GroupOrderCopy(home, src, cp, `["节点选择","自动","流媒体"]`)), &r)
	if r.Error != "" || r.Changed {
		t.Fatalf("identity copy %+v", r)
	}
	if _, err := os.Stat(cp); err == nil {
		t.Fatal("copy written for an unchanged order")
	}
	_ = json.Unmarshal([]byte(GroupOrderCopy(home, src, cp, `["流媒体","节点选择","自动"]`)), &r)
	if r.Error != "" || !r.Changed || r.Method != "text" {
		t.Fatalf("GroupOrderCopy %+v", r)
	}
	if b, _ := os.ReadFile(src); string(b) != goProfile {
		t.Fatal("source file changed")
	}
	if _, err := os.Stat(src + ".bak"); err == nil {
		t.Fatal("source got a .bak")
	}
	if _, err := os.Stat(cp + ".bak"); err == nil {
		t.Fatal("new copy got a .bak")
	}
	cb, _ := os.ReadFile(cp)
	if got := groupNamesOf(t, cb); !reflect.DeepEqual(got, []string{"流媒体", "节点选择", "隐藏", "自动"}) {
		t.Fatalf("copy order %v", got)
	}
	if !strings.Contains(string(cb), "# 我的配置 — header comment") || !strings.Contains(string(cb), "# ---- 自动 ----") {
		t.Fatal("copy lost comments")
	}
	// A later reorder changes only the copy (previous copy → .bak).
	_ = json.Unmarshal([]byte(ReorderGroups(home, cp, `["自动","流媒体","节点选择"]`)), &r)
	if r.Error != "" || !r.Changed {
		t.Fatalf("reorder copy %+v", r)
	}
	if b, _ := os.ReadFile(cp + ".bak"); string(b) != string(cb) {
		t.Fatal("copy .bak is not the previous copy")
	}
	if b, _ := os.ReadFile(src); string(b) != goProfile {
		t.Fatal("source file changed by a copy reorder")
	}
	edits := map[string]GroupEdits{"COPY-1": {Order: []string{"自动", "流媒体", "节点选择"}}}
	b, _ := json.Marshal(edits)
	_ = os.WriteFile(groupEditsPath(home), b, 0o644)

	// The subscription is downloaded again in the provider's order, with a new group 新组 and a new node.
	fresh := strings.Replace(goProfile, "# 规则 — belongs to rules", "  - {name: 新组, type: select, proxies: [DIRECT]}\n\n# 规则 — belongs to rules", 1)
	fresh = strings.Replace(fresh, "  - {name: n2,", "  - {name: n3, type: ss, server: 192.0.2.3, port: 8388, cipher: aes-128-gcm, password: x}\n  - {name: n2,", 1)
	_ = os.WriteFile(src, []byte(fresh), 0o644)
	_ = json.Unmarshal([]byte(GroupOrderRegenerate(home, src, cp)), &r)
	if r.Error != "" || !r.Changed {
		t.Fatalf("regenerate %+v", r)
	}
	nb, _ := os.ReadFile(cp)
	if got := groupNamesOf(t, nb); !reflect.DeepEqual(got, []string{"自动", "流媒体", "隐藏", "节点选择", "新组"}) {
		t.Fatalf("order after regenerate %v", got)
	}
	if !strings.Contains(string(nb), "name: n3") {
		t.Fatal("copy did not get the fresh source content")
	}
	if b, _ := os.ReadFile(src); string(b) != fresh {
		t.Fatal("source changed by regenerate")
	}
	// Regenerating again with nothing new writes nothing.
	_ = json.Unmarshal([]byte(GroupOrderRegenerate(home, src, cp)), &r)
	if r.Changed || r.Error != "" {
		t.Fatalf("second regenerate %+v", r)
	}

	// 不再保持此顺序 (order cleared): the copy becomes the source content as is.
	_ = os.WriteFile(groupEditsPath(home), []byte("{}"), 0o644)
	_ = json.Unmarshal([]byte(GroupOrderRegenerate(home, src, cp)), &r)
	if r.Error != "" || !r.Changed {
		t.Fatalf("regenerate without order %+v", r)
	}
	if b, _ := os.ReadFile(cp); string(b) != fresh {
		t.Fatal("copy without order must equal the source")
	}
}

// When the stored order cannot be applied to the fresh source, the copy still gets the fresh content.
func TestGroupOrderRegenerateFallsBackToSource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "s.yaml")
	cp := filepath.Join(dir, "c.yaml")
	_ = os.WriteFile(cp, []byte("old copy\n"), 0o644)
	fresh := "proxy-groups:\n  - &base\n    name: A\n    type: select\n    proxies: &x [DIRECT]\n  - name: B\n    type: select\n    proxies: *x\n"
	r := reorderInto([]byte(fresh), cp, []string{"B", "A"}, nil, true)
	if r.Error == "" || !r.Changed {
		t.Fatalf("want error + written: %+v", r)
	}
	if b, _ := os.ReadFile(cp); string(b) != fresh {
		t.Fatal("copy must be the fresh source")
	}
	if b, _ := os.ReadFile(cp + ".bak"); string(b) != "old copy\n" {
		t.Fatal("previous copy not kept as .bak")
	}
	_ = src
}

func TestCopyProfileSettings(t *testing.T) {
	home := t.TempDir()
	w := func(f, s string) { _ = os.WriteFile(filepath.Join(home, f), []byte(s), 0o644) }
	w("group-edits.json", `{"SRC":{"edits":{"A":{"deleted":true}},"order":["B","A"]},"OTHER":{"order":["X"]}}`)
	w("groups.json", `{"SRC":{"dialer":{"A":"n1"}}}`)
	w("subscriptions.json", `{"SRC":{"enabled":true},"DST":{"enabled":false}}`)
	if e := CopyProfileSettings(home, "SRC", "DST"); e != "" {
		t.Fatal(e)
	}
	read := func(f string) map[string]any {
		var m map[string]any
		b, _ := os.ReadFile(filepath.Join(home, f))
		_ = json.Unmarshal(b, &m)
		return m
	}
	ge := read("group-edits.json")["DST"].(map[string]any)
	if _, has := ge["order"]; has || ge["edits"] == nil {
		t.Fatalf("group edits copied wrong: %v", ge)
	}
	if read("group-edits.json")["SRC"].(map[string]any)["order"] == nil {
		t.Fatal("source entry changed")
	}
	if read("groups.json")["DST"] == nil {
		t.Fatal("groups.json not copied")
	}
	if read("subscriptions.json")["DST"].(map[string]any)["enabled"] != false {
		t.Fatal("existing DST entry overwritten")
	}
	if _, err := os.Stat(filepath.Join(home, "netpolicy.json")); err == nil {
		t.Fatal("missing file created")
	}
}

func TestGroupOrderProfileGroupNames(t *testing.T) {
	p := writeTmp(t, "prof.yaml", goProfile)
	var got []string
	_ = json.Unmarshal([]byte(ProfileGroupNames(p)), &got)
	if !reflect.DeepEqual(got, []string{"节点选择", "自动", "隐藏", "流媒体"}) {
		t.Fatalf("names %v", got)
	}
	if ProfileGroupNames(filepath.Join(t.TempDir(), "missing.yaml")) != "[]" {
		t.Fatal("missing file must give []")
	}
}
