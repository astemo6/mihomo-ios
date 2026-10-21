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
	// missing / broken secrets.json: nothing overlaid, no panic — and (B04) never an empty controller secret:
	// a missing file gets a random secret written into secrets.json, a broken one is left alone.
	_ = os.Remove(secretsPath(home))
	mustWrite(t, filepath.Join(home, "overrides.json"), `{}`)
	o1 := readOverrides(home)
	if len(o1.Secret) < 16 {
		t.Errorf("no secrets file: %q", o1.Secret)
	}
	if s := readSecrets(home); s == nil || s.Secret != o1.Secret {
		t.Errorf("no secrets file: random secret not stored in secrets.json: %+v", s)
	}
	mustWrite(t, secretsPath(home), `not json`)
	if o := readOverrides(home); len(o.Secret) < 16 {
		t.Errorf("broken secrets file: %q", o.Secret)
	}
	if b, _ := os.ReadFile(secretsPath(home)); string(b) != "not json" {
		t.Errorf("broken secrets.json must not be overwritten: %q", b)
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
