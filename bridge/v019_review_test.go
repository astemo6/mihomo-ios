package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Review fix 2: a copy the user edited after it was generated is not overwritten by a subscription update;
// 「从订阅重新生成」 (forced) still rebuilds it, and a reorder of an edited copy does not mark it as generated.
func TestV019RegenerateKeepsEditedCopy(t *testing.T) {
	home := t.TempDir()
	prof := filepath.Join(home, "profiles")
	_ = os.MkdirAll(prof, 0o755)
	src := filepath.Join(prof, "SUB-2.yaml")
	cp := filepath.Join(prof, "COPY-2.yaml")
	_ = os.WriteFile(src, []byte(goProfile), 0o644)
	var r reorderResult
	r = reorderResult{}
	_ = json.Unmarshal([]byte(GroupOrderCopy(home, src, cp, `["流媒体","节点选择","自动"]`)), &r)
	if r.Error != "" || !r.Changed {
		t.Fatalf("copy %+v", r)
	}
	if _, err := os.Stat(cp + ".gen"); err != nil {
		t.Fatal("no .gen marker after GroupOrderCopy")
	}
	edits, _ := json.Marshal(map[string]GroupEdits{"COPY-2": {Order: []string{"流媒体", "节点选择", "自动"}}})
	_ = os.WriteFile(groupEditsPath(home), edits, 0o644)

	// Unedited copy: regenerates normally.
	fresh := strings.Replace(goProfile, "  - {name: n2,", "  - {name: n3, type: ss, server: 192.0.2.3, port: 8388, cipher: aes-128-gcm, password: x}\n  - {name: n2,", 1)
	_ = os.WriteFile(src, []byte(fresh), 0o644)
	r = reorderResult{}
	_ = json.Unmarshal([]byte(GroupOrderRegenerate(home, src, cp)), &r)
	if r.Error != "" || !r.Changed || r.Modified {
		t.Fatalf("regenerate unedited %+v", r)
	}

	// The user edits the copy (text editor / node edit).
	cb, _ := os.ReadFile(cp)
	edited := strings.Replace(string(cb), "mixed-port: 7890", "mixed-port: 7891 # mine", 1)
	_ = os.WriteFile(cp, []byte(edited), 0o644)
	// A reorder of the edited copy keeps the edit but must not bless it as generated.
	r = reorderResult{}
	_ = json.Unmarshal([]byte(ReorderGroups(home, cp, `["节点选择","流媒体","自动"]`)), &r)
	if r.Error != "" || !r.Changed {
		t.Fatalf("reorder edited copy %+v", r)
	}
	after, _ := os.ReadFile(cp)
	if !strings.Contains(string(after), "7891 # mine") {
		t.Fatal("reorder lost the edit")
	}
	// Next subscription update: left alone, reported.
	fresh2 := strings.Replace(fresh, "  - {name: n3,", "  - {name: n4, type: ss, server: 192.0.2.4, port: 8388, cipher: aes-128-gcm, password: x}\n  - {name: n3,", 1)
	_ = os.WriteFile(src, []byte(fresh2), 0o644)
	r = reorderResult{}
	_ = json.Unmarshal([]byte(GroupOrderRegenerate(home, src, cp)), &r)
	if !r.Modified || r.Changed || r.Error != errCopyModified {
		t.Fatalf("edited copy must be reported, not overwritten: %+v", r)
	}
	if b, _ := os.ReadFile(cp); string(b) != string(after) {
		t.Fatal("edited copy overwritten")
	}
	// Forced: rebuilt from the subscription, edit gone (kept in .bak), marked generated again.
	r = reorderResult{}
	_ = json.Unmarshal([]byte(GroupOrderRegenerateForced(home, src, cp)), &r)
	if r.Error != "" || !r.Changed || r.Modified {
		t.Fatalf("forced %+v", r)
	}
	b, _ := os.ReadFile(cp)
	if strings.Contains(string(b), "7891") || !strings.Contains(string(b), "name: n4") {
		t.Fatal("forced regenerate did not take the subscription content")
	}
	if bak, _ := os.ReadFile(cp + ".bak"); !strings.Contains(string(bak), "7891 # mine") {
		t.Fatal("edited copy not kept as .bak")
	}
	if !copyGenerated(cp) {
		t.Fatal("not generated after forced regenerate")
	}
}

// Copies made before the .gen marker existed keep regenerating.
func TestV019RegenerateWithoutMarker(t *testing.T) {
	home := t.TempDir()
	src := filepath.Join(home, "S.yaml")
	cp := filepath.Join(home, "C.yaml")
	_ = os.WriteFile(src, []byte(goProfile), 0o644)
	_ = os.WriteFile(cp, []byte("old\n"), 0o644)
	var r reorderResult
	r = reorderResult{}
	_ = json.Unmarshal([]byte(GroupOrderRegenerate(home, src, cp)), &r)
	if r.Error != "" || !r.Changed {
		t.Fatalf("%+v", r)
	}
	if !copyGenerated(cp) {
		t.Fatal("marker not written")
	}
}

// Review fix 5: delete clears per-profile settings and side files; a new copy gets the source's selections.
func TestV019ForgetProfileAndSelections(t *testing.T) {
	home := t.TempDir()
	w := func(f, s string) { _ = os.WriteFile(filepath.Join(home, f), []byte(s), 0o644) }
	w("group-edits.json", `{"C":{"order":["B","A"]},"KEEP":{"order":["X"]}}`)
	w("groups.json", `{"C":{"dialer":{}}}`)
	prof := filepath.Join(home, "C.yaml")
	src := filepath.Join(home, "S.yaml")
	w("C.yaml", "x: 1\n")
	w("C.yaml.bak", "x: 0\n")
	w("C.yaml.gen", "abc")
	w("S.selected.json", `{"节点选择":"n2"}`)
	if e := CopyProfileSelections(src, prof); e != "" {
		t.Fatal(e)
	}
	if b, _ := os.ReadFile(filepath.Join(home, "C.selected.json")); string(b) != `{"节点选择":"n2"}` {
		t.Fatalf("selections not copied: %q", b)
	}
	if e := ForgetProfile(home, "C", prof); e != "" {
		t.Fatal(e)
	}
	for _, f := range []string{"C.yaml.bak", "C.yaml.gen", "C.selected.json"} {
		if _, err := os.Stat(filepath.Join(home, f)); err == nil {
			t.Fatalf("%s left behind", f)
		}
	}
	b, _ := os.ReadFile(filepath.Join(home, "group-edits.json"))
	if strings.Contains(string(b), `"C"`) || !strings.Contains(string(b), "KEEP") {
		t.Fatalf("group-edits after forget: %s", b)
	}
	b, _ = os.ReadFile(filepath.Join(home, "groups.json"))
	if strings.Contains(string(b), `"C"`) {
		t.Fatalf("groups.json after forget: %s", b)
	}
}

// Review fix 10: output computed from content that changed during the chain is refused.
func TestV019ScriptOutputRefusedWhenSourceChanged(t *testing.T) {
	home, prof := v019Home(t)
	snap, err := ScriptInputSnapshot(prof)
	if err != nil {
		t.Fatal(err)
	}
	i := strings.IndexByte(snap, '\n')
	if i != 64 {
		t.Fatalf("snapshot must start with a sha256 line: %q", snap[:min(80, len(snap))])
	}
	sha, js := snap[:i], snap[i+1:]
	if msg := ScriptOutputApplyFor(home, prof, js, `["a.js"]`, sha); msg != "" {
		t.Fatalf("unchanged source refused: %s", msg)
	}
	st := ScriptOutputStatus(home, prof)
	if !strings.Contains(st, `"fresh":true`) {
		t.Fatalf("status %s", st)
	}
	b, _ := os.ReadFile(prof)
	_ = os.WriteFile(prof, append(b, []byte("\n# changed by a download\n")...), 0o644)
	if msg := ScriptOutputApplyFor(home, prof, js, `["a.js"]`, sha); msg != errScriptSourceChanged {
		t.Fatalf("changed source: %q", msg)
	}
	if strings.Contains(ScriptOutputStatus(home, prof), `"exists":true`) {
		t.Fatal("old output kept after a refused apply")
	}
}
