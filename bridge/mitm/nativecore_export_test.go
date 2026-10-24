package mitm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// preludeBundlePath: the prelude the Go-free tunnel bundles (PacketTunnel target resource), PreludeSource() as is.
const preludeBundlePath = "../../PacketTunnel/NativeMitM/Script/TernPrelude.js"

// TestNativePreludeBundleCurrent keeps the tunnel's bundled prelude identical to the one Go hands every engine.
// TERN_UPDATE_PRELUDE=1 rewrites it.
func TestNativePreludeBundleCurrent(t *testing.T) {
	want := PreludeSource()
	if os.Getenv("TERN_UPDATE_PRELUDE") == "1" {
		if err := os.WriteFile(preludeBundlePath, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(preludeBundlePath)
	if err != nil {
		t.Fatalf("%v (run with TERN_UPDATE_PRELUDE=1)", err)
	}
	if string(got) != want {
		t.Fatalf("TernPrelude.js is stale: run TERN_UPDATE_PRELUDE=1 go test ./mitm -run TestNativePreludeBundleCurrent")
	}
}

func TestExportScriptManifest(t *testing.T) {
	home := t.TempDir()
	cfg := &Config{}
	rs := &Ruleset{Rules: []*Rule{
		{Kind: KindHeader, Pattern: "^https://a/"},
		{Kind: KindScript, Pattern: "^https://b/", Script: &Script{Name: "inline", Type: "http-response", Source: []byte("\ufeff$done({})"), Timeout: 5, Argument: "x=1", HasArgument: true}},
		{Kind: KindScript, Pattern: "^https://c/", Script: &Script{Name: "missing", Type: "http-request", Path: filepath.Join(home, "nope.js")}},
	}}
	// a stale code file from an earlier profile is removed
	_ = os.MkdirAll(filepath.Join(home, ScriptManifestDir), 0o755)
	_ = os.WriteFile(filepath.Join(home, ScriptManifestDir, "nc-old.js"), []byte("x"), 0o644)
	n, bad, err := ExportScriptManifest(home, cfg, rs)
	if err != nil || n != 2 || bad != 1 {
		t.Fatalf("n %d bad %d err %v", n, bad, err)
	}
	b, _ := os.ReadFile(filepath.Join(home, ScriptManifestFile))
	var m scriptManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	ok := m.Scripts[0]
	if ok.I != 1 || ok.Err != "" || !strings.HasPrefix(ok.Key, "nc-") || ok.TimeoutMs != 5000 {
		t.Fatalf("entry %+v", ok)
	}
	code, _ := os.ReadFile(filepath.Join(home, ok.File))
	if string(code) != "$done({})" {
		t.Fatalf("code %q (BOM must be stripped)", code)
	}
	var setup map[string]any
	if err := json.Unmarshal(ok.Setup, &setup); err != nil || setup["name"] != "inline" {
		t.Fatalf("setup %s", ok.Setup)
	}
	if m.Scripts[1].I != 2 || m.Scripts[1].Err == "" || m.Scripts[1].Key != "" {
		t.Fatalf("missing script entry %+v", m.Scripts[1])
	}
	if _, err := os.Stat(filepath.Join(home, ScriptManifestDir, "nc-old.js")); err == nil {
		t.Fatal("stale code file kept")
	}
}
