package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const v09Profile = `proxies:
  - {name: hk1, type: ss, server: 1.1.1.1, port: 443, cipher: aes-128-gcm, password: x}
proxy-groups:
  - {name: PROXY, type: select, proxies: [AUTO, hk1, DIRECT]}
  - {name: AUTO, type: url-test, proxies: [hk1], url: "https://www.gstatic.com/generate_204", interval: 300}
  - {name: AdBlock, type: select, proxies: [REJECT, DIRECT]}
rules:
  - DOMAIN-SUFFIX,google.com,PROXY
  - AND,((NETWORK,UDP),(DST-PORT,443)),AUTO
  - MATCH,PROXY
`

func TestNodeSubsMerge(t *testing.T) {
	home := t.TempDir()
	_ = os.MkdirAll(filepath.Join(home, "nodesubs"), 0o755)
	_ = os.WriteFile(NodeSubPath(home, "a"), []byte("proxies:\n  - {name: jp1, type: ss, server: 2.2.2.2, port: 443, cipher: aes-128-gcm, password: x}\n"), 0o644)
	subs := []NodeSub{{ID: "a", Name: "机场B", Enabled: true}, {ID: "b", Name: "未下载", Enabled: true}, {ID: "c", Name: "停用", Enabled: false}}
	b, _ := json.Marshal(subs)
	_ = os.WriteFile(nodeSubsPath(home), b, 0o644)
	raw := map[string]any{}
	_ = yaml.Unmarshal([]byte(v09Profile), &raw)
	mergeNodeSubs(raw, home, func(string) *SubRules { return nil })
	pp := raw["proxy-providers"].(map[string]any)
	if len(pp) != 1 || pp["机场B"] == nil {
		t.Fatalf("providers %v", pp)
	}
	for _, g := range asList(raw["proxy-groups"]) {
		m := g.(map[string]any)
		has := strings.Contains(strings.Join(strList(m["use"]), ","), "机场B")
		if want := str(m["name"]) != "AdBlock"; has != want {
			t.Fatalf("group %s use=%v", m["name"], m["use"])
		}
	}
	// Chosen groups only.
	subs[0].Groups = []string{"AUTO"}
	b, _ = json.Marshal(subs)
	_ = os.WriteFile(nodeSubsPath(home), b, 0o644)
	raw = map[string]any{}
	_ = yaml.Unmarshal([]byte(v09Profile), &raw)
	mergeNodeSubs(raw, home, func(string) *SubRules { return nil })
	for _, g := range asList(raw["proxy-groups"]) {
		m := g.(map[string]any)
		has := len(asList(m["use"])) > 0
		if has != (str(m["name"]) == "AUTO") {
			t.Fatalf("chosen: group %s use=%v", m["name"], m["use"])
		}
	}
	// The whole runtime parses.
	prof := filepath.Join(home, "p.yaml")
	_ = os.WriteFile(prof, []byte(v09Profile), 0o644)
	if _, err := buildRuntime([]byte(v09Profile), overridesFor(home, prof), 0); err != nil {
		t.Fatal(err)
	}
}

func TestGroupEdits(t *testing.T) {
	raw := map[string]any{}
	_ = yaml.Unmarshal([]byte(v09Profile), &raw)
	e := &GroupEdits{
		Edits: map[string]GroupEdit{
			"AUTO":    {Spec: &GroupSpec{Name: "自动", Type: "fallback", Proxies: []string{"hk1"}, Interval: 600}},
			"AdBlock": {Deleted: true},
		},
		Added: []GroupSpec{{Name: "新组", Type: "select", Proxies: []string{"自动", "DIRECT"}}},
	}
	w := applyGroupEdits(raw, e)
	if len(w) != 0 {
		t.Fatalf("warnings %v", w)
	}
	names := []string{}
	for _, g := range asList(raw["proxy-groups"]) {
		names = append(names, str(g.(map[string]any)["name"]))
	}
	if strings.Join(names, ",") != "PROXY,自动,新组" {
		t.Fatalf("groups %v", names)
	}
	px := strList(asList(raw["proxy-groups"])[0].(map[string]any)["proxies"])
	if strings.Join(px, ",") != "自动,hk1,DIRECT" {
		t.Fatalf("rename not followed in members: %v", px)
	}
	rules := strings.Join(strList(raw["rules"]), "\n")
	if !strings.Contains(rules, "AND,((NETWORK,UDP),(DST-PORT,443)),自动") {
		t.Fatalf("rename not followed in rules:\n%s", rules)
	}
	g := asList(raw["proxy-groups"])[1].(map[string]any)
	if g["type"] != "fallback" || intOf(g["interval"]) != 600 || g["tolerance"] != nil {
		t.Fatalf("spec %v", g)
	}

	home := t.TempDir()
	prof := filepath.Join(home, "p.yaml")
	_ = os.WriteFile(prof, []byte(v09Profile), 0o644)
	ok, _ := json.Marshal(e)
	if s := GroupEditCheck(home, prof, string(ok)); s != "" {
		t.Fatalf("valid edits rejected: %s", s)
	}
	cyc, _ := json.Marshal(GroupEdits{Edits: map[string]GroupEdit{"AUTO": {Spec: &GroupSpec{Name: "AUTO", Type: "url-test", Proxies: []string{"PROXY"}}}}})
	if s := GroupEditCheck(home, prof, string(cyc)); !strings.Contains(s, "循环") {
		t.Fatalf("cycle not detected: %q", s)
	}
	empty, _ := json.Marshal(GroupEdits{Edits: map[string]GroupEdit{"AUTO": {Spec: &GroupSpec{Name: "AUTO", Type: "url-test"}}}})
	if s := GroupEditCheck(home, prof, string(empty)); !strings.Contains(s, "没有任何成员") {
		t.Fatalf("empty group not detected: %q", s)
	}
	var gs struct {
		Groups []GroupSpec `json:"groups"`
	}
	_ = json.Unmarshal([]byte(GroupSpecs(home, prof)), &gs)
	if len(gs.Groups) != 3 || gs.Groups[1].Type != "url-test" {
		t.Fatalf("specs %+v", gs.Groups)
	}
}
