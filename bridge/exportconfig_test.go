package libmihomo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFinalConfigStripsAppInternals(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "profile.yaml")
	if err := os.WriteFile(p, []byte(sample), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := FinalConfig(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"secret:", "external-controller:", ProbeGroup, probeListener} {
		if strings.Contains(out, gone) {
			t.Fatalf("final config still has %q:\n%s", gone, out)
		}
	}
	for _, kept := range []string{"password: x", "name: PROXY", "MATCH,PROXY"} {
		if !strings.Contains(out, kept) {
			t.Fatalf("final config lost %q:\n%s", kept, out)
		}
	}
}
