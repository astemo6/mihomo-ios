package libmihomo

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// v0.19.7: every file that changes the runtime must change the rtCache key.
func TestV0197RuntimeCacheKeyCoversInputs(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(root, "p.yaml")
	if err := os.WriteFile(profile, []byte("proxies: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"overrides.json", "subscriptions.json", "groups.json", "group-edits.json", "node-subscriptions.json"} {
		before := runtimeCacheKey(home, profile)
		if err := os.WriteFile(filepath.Join(home, f), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		after := runtimeCacheKey(home, profile)
		if before == after {
			t.Errorf("creating %s did not change the runtime cache key", f)
		}
		time.Sleep(2 * time.Millisecond)
		if err := os.WriteFile(filepath.Join(home, f), []byte(`{"x":1}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if runtimeCacheKey(home, profile) == after {
			t.Errorf("editing %s did not change the runtime cache key", f)
		}
	}
}
