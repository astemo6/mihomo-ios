package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// v0.19.1 B1: reordering the original again must not rebuild a copy the user edited by hand (the edits would be
// lost, kept only in .bak); the copy is reordered in place and reported as modified. An unedited copy is still
// rebuilt from the source as before.
func TestV0191GroupOrderCopyKeepsEditedCopy(t *testing.T) {
	home := t.TempDir()
	prof := filepath.Join(home, "profiles")
	_ = os.MkdirAll(prof, 0o755)
	src := filepath.Join(prof, "ORIG-1.yaml")
	cp := filepath.Join(prof, "COPY-1.yaml")
	_ = os.WriteFile(src, []byte(goProfile), 0o644)

	var r reorderResult
	_ = json.Unmarshal([]byte(GroupOrderCopy(home, src, cp, `["流媒体","节点选择","自动"]`)), &r)
	if r.Error != "" || !r.Changed || r.Modified {
		t.Fatalf("first copy %+v", r)
	}
	// Unedited copy, original reordered again: rebuilt from the source (generated, not modified).
	r = reorderResult{}
	_ = json.Unmarshal([]byte(GroupOrderCopy(home, src, cp, `["自动","流媒体","节点选择"]`)), &r)
	if r.Error != "" || !r.Changed || r.Modified {
		t.Fatalf("rebuild unedited copy %+v", r)
	}
	if !copyGenerated(cp) {
		t.Fatal("unedited copy should stay generated")
	}

	// The user edits the copy.
	cb, _ := os.ReadFile(cp)
	edited := strings.Replace(string(cb), "mixed-port: 7890", "mixed-port: 7891 # mine", 1)
	if edited == string(cb) {
		t.Fatal("fixture: mixed-port line not found")
	}
	_ = os.WriteFile(cp, []byte(edited), 0o644)

	// Original reordered again: in place, the edit survives, the order is applied.
	r = reorderResult{}
	_ = json.Unmarshal([]byte(GroupOrderCopy(home, src, cp, `["节点选择","自动","流媒体"]`)), &r)
	if r.Error != "" || !r.Modified || !r.Changed {
		t.Fatalf("reorder edited copy %+v", r)
	}
	after, _ := os.ReadFile(cp)
	if !strings.Contains(string(after), "7891 # mine") {
		t.Fatal("edited copy rebuilt from the source (edit lost)")
	}
	names := []string{}
	_ = json.Unmarshal([]byte(ProfileGroupNames(cp)), &names)
	var vis []string
	for _, n := range names {
		if n != "隐藏" { // hidden group not in the order: keeps its slot
			vis = append(vis, n)
		}
	}
	if len(vis) != 3 || vis[0] != "节点选择" || vis[1] != "自动" || vis[2] != "流媒体" {
		t.Fatalf("order not applied in place: %v", names)
	}
	if copyGenerated(cp) {
		t.Fatal("an in-place reorder must not bless the edit as generated")
	}
	// Same order again: nothing written, still reported as modified (the app switches to the copy).
	r = reorderResult{}
	_ = json.Unmarshal([]byte(GroupOrderCopy(home, src, cp, `["节点选择","自动","流媒体"]`)), &r)
	if r.Error != "" || !r.Modified || r.Changed {
		t.Fatalf("same order on edited copy %+v", r)
	}
	if b, _ := os.ReadFile(src); string(b) != goProfile {
		t.Fatal("source changed")
	}
}

// v0.19.1 B2: the main LAN user is passed exactly as before v0.19 (a ':' or spaces in the name no longer turn
// authentication off); extra users are still filtered, and an extra user cannot shadow the main user.
func TestV0191LanMainUserNeverDropped(t *testing.T) {
	o := defaultOverrides()
	o.AllowLan = true
	o.LanAuth = LanAuth{Username: "a:b", Password: "p0"}
	raw := map[string]any{}
	applyInbound(raw, o)
	got, _ := raw["authentication"].([]any)
	if len(got) != 1 || got[0] != "a:b:p0" {
		t.Fatalf("main user with ':' must keep authentication on (pre-v0.19 entry): %v", got)
	}

	o.LanAuth = LanAuth{Username: " main ", Password: "p0"}
	o.LanUsers = []LanAuth{{Username: "main", Password: "x"}, {Username: " main ", Password: "y"}, {Username: "tv", Password: "p1"}}
	raw = map[string]any{}
	applyInbound(raw, o)
	got, _ = raw["authentication"].([]any)
	want := []string{" main :p0", "tv:p1"}
	if len(got) != len(want) {
		t.Fatalf("authentication = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("authentication[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	// Main user incomplete: not passed; extra users still protect the port.
	o.LanAuth = LanAuth{Username: "main"}
	raw = map[string]any{}
	applyInbound(raw, o)
	got, _ = raw["authentication"].([]any)
	if len(got) != 2 || got[0] != "main:x" {
		t.Fatalf("incomplete main user: %v", got)
	}
}
