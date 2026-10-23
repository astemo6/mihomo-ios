package mitm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const switchModule = `#!name=Switch Test
#!author=tester
#!category=去广告
[URL Rewrite]
^https?://ad\.example\.com/ - reject
[Script]
s1 = type=http-response,pattern=^https?://api\.example\.com/,script-path=https://e.com/a.js
c1 = type=cron,cronexp="0 8 * * *",script-path=https://e.com/c.js
[Rule]
DOMAIN,tracker.example.com,REJECT
[MITM]
hostname = %APPEND% api.example.com
`

func switchHome(t *testing.T) string {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(EngineDir(home), "modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ModulePath(home, "m1"), []byte(switchModule), 0o644); err != nil {
		t.Fatal(err)
	}
	return home
}

func kinds(rs *Ruleset) (rew, scr int) {
	for _, r := range rs.Rules {
		if r.Kind == KindScript {
			scr++
		} else {
			rew++
		}
	}
	return
}

func TestSeparateRewriteAndScriptSwitches(t *testing.T) {
	home := switchHome(t)
	bp := func(b bool) *bool { return &b }
	mod := []Module{{ID: "m1", Name: "M", Enabled: true}}
	cases := []struct {
		name               string
		cfg                Config
		rew, scr, tasks    int
		anyOn, rewOn, scOn bool
	}{
		{"legacy on (no scriptsEnabled) keeps both", Config{Enabled: true, Modules: mod}, 1, 1, 1, true, true, true},
		{"legacy off keeps both off", Config{Enabled: false, Modules: mod}, 0, 0, 0, false, false, false},
		{"rewrite only", Config{Enabled: true, ScriptsEnabled: bp(false), Modules: mod}, 1, 0, 0, true, true, false},
		{"scripts only", Config{Enabled: false, ScriptsEnabled: bp(true), Modules: mod}, 0, 1, 1, true, false, true},
		{"both off", Config{Enabled: false, ScriptsEnabled: bp(false), Modules: mod}, 0, 0, 0, false, false, false},
	}
	for _, c := range cases {
		cfg := c.cfg
		rs := Build(home, &cfg)
		rew, scr := kinds(rs)
		if rew != c.rew || scr != c.scr || len(rs.Tasks) != c.tasks {
			t.Errorf("%s: rewrites %d scripts %d tasks %d, want %d %d %d", c.name, rew, scr, len(rs.Tasks), c.rew, c.scr, c.tasks)
		}
		if cfg.AnyOn() != c.anyOn || cfg.RewriteOn() != c.rewOn || cfg.ScriptsOn() != c.scOn {
			t.Errorf("%s: switches any=%v rew=%v scr=%v", c.name, cfg.AnyOn(), cfg.RewriteOn(), cfg.ScriptsOn())
		}
		// Module [Rule] lines and hostnames belong to the module, not to either switch.
		if c.anyOn && (len(rs.CoreRules) != 1 || len(rs.Hostnames) != 1) {
			t.Errorf("%s: core rules %v hostnames %v", c.name, rs.CoreRules, rs.Hostnames)
		}
		if !c.anyOn && len(rs.CoreRules) != 0 {
			t.Errorf("%s: core rules applied with both switches off", c.name)
		}
	}
}

func TestScriptsSwitchJSONMigration(t *testing.T) {
	var old Config
	if err := json.Unmarshal([]byte(`{"enabled":true}`), &old); err != nil {
		t.Fatal(err)
	}
	if !old.ScriptsOn() || !old.RewriteOn() {
		t.Fatal("old engine.json with enabled=true must keep scripts on")
	}
	var split Config
	if err := json.Unmarshal([]byte(`{"enabled":true,"scriptsEnabled":false}`), &split); err != nil {
		t.Fatal(err)
	}
	if split.ScriptsOn() || !split.RewriteOn() {
		t.Fatal("scriptsEnabled=false must turn scripts off only")
	}
}

func TestModuleMetaAuthorCategory(t *testing.T) {
	rs := &Ruleset{}
	rs.ParseText(switchModule, "m", nil)
	if rs.Author != "tester" || rs.Category != "去广告" {
		t.Fatalf("author %q category %q", rs.Author, rs.Category)
	}
	loon := &Ruleset{}
	loon.ParseText("#!name=L\n#!author=a1\n#!tag=工具\n[Rewrite]\n^https?://x\\.com/ reject\n", "m", nil)
	if loon.Author != "a1" || loon.Category != "工具" {
		t.Fatalf("loon author %q category %q", loon.Author, loon.Category)
	}
}
