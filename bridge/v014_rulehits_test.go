package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	RC "github.com/metacubex/mihomo/rules/common"
	RW "github.com/metacubex/mihomo/rules/wrapper"
)

func hit(w C.RuleWrapper, n int) {
	type hitter interface{ Hit() }
	for i := 0; i < n; i++ {
		w.(hitter).Hit()
	}
}

func TestRuleHitsFoldAcrossSessions(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.Local)
	a := RW.NewRuleWrapper(RC.NewDomain("example.com", "Proxy"))
	b := RW.NewRuleWrapper(RC.NewDomain("example.org", "DIRECT"))
	d := RuleHitsData{Rules: map[string]*RuleHitEntry{}}
	base := map[C.RuleWrapper]uint64{}

	hit(a, 3)
	if !foldRuleHits(&d, []C.Rule{a, b}, base, now) {
		t.Fatal("expected change")
	}
	if foldRuleHits(&d, []C.Rule{a, b}, base, now) {
		t.Fatal("no new hits must not change")
	}
	hit(a, 2)
	hit(b, 1)
	foldRuleHits(&d, []C.Rule{a, b}, base, now)
	ka := ruleHitKey("Domain", "example.com", "Proxy")
	if d.Rules[ka] == nil || d.Rules[ka].Total != 5 || d.Rules[ka].Today != 5 {
		t.Fatalf("a = %+v", d.Rules[ka])
	}
	// reload: new wrappers start at 0, the old ones are pruned from base.
	a2 := RW.NewRuleWrapper(RC.NewDomain("example.com", "Proxy"))
	hit(a2, 4)
	foldRuleHits(&d, []C.Rule{a2}, base, now.Add(24*time.Hour))
	if d.Rules[ka].Total != 9 || d.Rules[ka].Today != 4 || d.Rules[ka].Day != "2026-10-18" {
		t.Fatalf("after reload a = %+v", d.Rules[ka])
	}
	if len(base) != 1 {
		t.Fatalf("base not pruned: %d", len(base))
	}
	if d.Since == 0 {
		t.Fatal("since not set")
	}
}

func TestResetRuleHits(t *testing.T) {
	home := t.TempDir()
	d := RuleHitsData{Since: 1, Rules: map[string]*RuleHitEntry{"A": {Total: 1}, "B": {Total: 2}}}
	b, _ := json.Marshal(d)
	os.WriteFile(filepath.Join(home, ruleHitsFile), b, 0o644)
	if e := ResetRuleHits(home, "A"); e != "" {
		t.Fatal(e)
	}
	if r := readRuleHits(home); len(r.Rules) != 1 || r.Rules["B"] == nil {
		t.Fatalf("got %+v", r.Rules)
	}
	if e := ResetRuleHits(home, ""); e != "" {
		t.Fatal(e)
	}
	if _, err := os.Stat(filepath.Join(home, ruleHitsFile)); !os.IsNotExist(err) {
		t.Fatal("file should be gone")
	}
	if e := ResetRuleHits(home, ""); e != "" {
		t.Fatal("reset of a missing file must succeed")
	}
}
