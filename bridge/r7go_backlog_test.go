package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// B04: an empty controller secret is replaced by a random one and written back, never run as "".
func TestR7B04EmptySecretNeverReachesRuntime(t *testing.T) {
	home := t.TempDir()
	_ = os.WriteFile(filepath.Join(home, "overrides.json"), []byte(`{"secret":"","controllerPort":9191,"mode":"rule"}`), 0o644)
	o := readOverrides(home)
	if len(o.Secret) < 16 {
		t.Fatalf("want a random secret, got %q", o.Secret)
	}
	b, _ := os.ReadFile(filepath.Join(home, "overrides.json"))
	raw := map[string]any{}
	_ = json.Unmarshal(b, &raw)
	if raw["secret"] != o.Secret || raw["mode"] != "rule" || raw["controllerPort"] != float64(9191) {
		t.Fatalf("secret must be written back, other keys kept: %s", b)
	}
	if again := readOverrides(home); again.Secret != o.Secret {
		t.Fatalf("second read must reuse the stored secret: %q vs %q", again.Secret, o.Secret)
	}
	rt, err := buildRuntime([]byte("proxies: []\nrules: [MATCH,DIRECT]\n"), o, 0)
	if err != nil || !strings.Contains(string(rt), "secret: "+o.Secret) {
		t.Fatalf("runtime secret: %v\n%s", err, rt)
	}
	// No overrides.json at all: a per-process random secret, nothing created.
	empty := t.TempDir()
	o2 := readOverrides(empty)
	if o2.Secret == "" || o2.Secret != readOverrides(empty).Secret {
		t.Fatalf("missing file: want a stable process secret, got %q", o2.Secret)
	}
	if _, err := os.Stat(filepath.Join(empty, "overrides.json")); err == nil {
		t.Fatal("must not create overrides.json")
	}
}
