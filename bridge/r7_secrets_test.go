package libmihomo

import (
	"os"
	"path/filepath"
	"testing"
)

// r7 B01: secrets.json is overlaid on overrides.json; a value still in overrides.json wins; passwords of 其他用户
// are matched by username.
func TestR7SecretsOverlay(t *testing.T) {
	home := t.TempDir()
	mustWrite(t, filepath.Join(home, "overrides.json"), `{"controllerPort":9091,"allowLan":true,"lanAuth":{"username":"main"},"lanUsers":[{"username":"tv"},{"username":"pad"},{"username":"x","password":"legacy"}]}`)
	mustWrite(t, secretsPath(home), `{"secret":"ctrl-123","lanPassword":"mainpw","lanUsers":{"tv":"p1","x":"other"}}`)
	o := readOverrides(home)
	if o.Secret != "ctrl-123" || o.LanAuth.Password != "mainpw" {
		t.Fatalf("secret %q lan %q", o.Secret, o.LanAuth.Password)
	}
	want := map[string]string{"tv": "p1", "pad": "", "x": "legacy"}
	for _, u := range o.LanUsers {
		if want[u.Username] != u.Password {
			t.Errorf("user %s password %q, want %q", u.Username, u.Password, want[u.Username])
		}
	}
	creds := lanCredentials(o)
	if len(creds) != 3 { // main + tv + x (pad has no password)
		t.Errorf("credentials %v", creds)
	}
	// legacy overrides.json secret wins
	mustWrite(t, filepath.Join(home, "overrides.json"), `{"secret":"old-json"}`)
	if o := readOverrides(home); o.Secret != "old-json" {
		t.Errorf("legacy secret %q", o.Secret)
	}
	// missing / broken secrets.json: nothing overlaid, no panic
	_ = os.Remove(secretsPath(home))
	mustWrite(t, filepath.Join(home, "overrides.json"), `{}`)
	if o := readOverrides(home); o.Secret != "" {
		t.Errorf("no secrets file: %q", o.Secret)
	}
	mustWrite(t, secretsPath(home), `not json`)
	if o := readOverrides(home); o.Secret != "" {
		t.Errorf("broken secrets file: %q", o.Secret)
	}
}

// r7 B01: the runtime cache key changes when only secrets.json changes.
func TestR7SecretsInRuntimeInputs(t *testing.T) {
	home := t.TempDir()
	found := false
	for _, p := range runtimeInputFiles(home, filepath.Join(home, "p.yaml")) {
		if p == secretsPath(home) {
			found = true
		}
	}
	if !found {
		t.Fatal("secrets.json missing from runtimeInputFiles")
	}
}
