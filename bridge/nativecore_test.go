package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeConfigJSON(t *testing.T) {
	home := t.TempDir()
	rt := "mixed-port: 7890\nmode: rule\nproxies:\n  - name: A\n    type: ss\n    server: 1.2.3.4\n    port: 8388\nrules:\n  - MATCH,A\n"
	if err := os.WriteFile(filepath.Join(home, "runtime.yaml"), []byte(rt), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := NativeConfigJSON(home)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if m["mode"] != "rule" || m["mixed-port"] != float64(7890) {
		t.Fatalf("bad top level: %s", out)
	}
	rules, _ := m["rules"].([]any)
	if len(rules) != 1 || rules[0] != "MATCH,A" {
		t.Fatalf("bad rules: %s", out)
	}
	if _, err := NativeConfigJSON(filepath.Join(home, "missing")); err == nil {
		t.Fatal("expected error for missing runtime.yaml")
	}
	if !strings.Contains(out, "\"proxies\"") {
		t.Fatalf("missing proxies: %s", out)
	}
}
