package libmihomo

import (
	"net"
	"strconv"
	"testing"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
)

// R7 P2-2: the engine is stopped / reloaded only when the new core config is live (plan.commit);
// a failed build or parse (plan.rollback) leaves the old engine as it was.
func TestR7EnginePlanDeferredUntilCommit(t *testing.T) {
	home := t.TempDir()
	on := &mitm.Config{Enabled: true, Rules: []mitm.Item{{ID: "1", Enabled: true, Line: `^https://a\.test/ad - reject`}}}
	if _, err := prepareEngineWith(home, on); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stopEngine)
	first := eng
	if first == nil || first.Port() == 0 {
		t.Fatal("engine not started")
	}
	port := first.Port()
	listening := func() bool {
		c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			return false
		}
		c.Close()
		return true
	}

	// Reload with two rules: the engine keeps the old rules until commit; rollback keeps them for good.
	two := &mitm.Config{Enabled: true, Rules: append(on.Rules, mitm.Item{ID: "2", Enabled: true, Line: `^https://b\.test/ad - reject`})}
	_, plan, err := planEngineWith(home, two)
	if err != nil {
		t.Fatal(err)
	}
	if n := eng.Status().Rules; n != 1 {
		t.Fatalf("rules swapped before commit: %d", n)
	}
	plan.rollback()
	if eng != first || eng.Status().Rules != 1 {
		t.Fatalf("rollback changed the engine")
	}
	_, plan, _ = planEngineWith(home, two)
	plan.commit()
	if eng != first || eng.Status().Rules != 2 {
		t.Fatalf("commit did not reload: rules=%d", eng.Status().Rules)
	}

	// Turning everything off: the listener stays up until commit; rollback keeps it.
	off := &mitm.Config{}
	_, plan, _ = planEngineWith(home, off)
	if eng != first || !listening() {
		t.Fatal("engine stopped before the new core config was live")
	}
	plan.rollback()
	if eng != first || !listening() {
		t.Fatal("rollback stopped the engine")
	}
	_, plan, _ = planEngineWith(home, off)
	plan.commit()
	if eng != nil || listening() {
		t.Fatal("commit did not stop the engine")
	}

	// Safe mode: same, via stopEnginePlan.
	if _, err := prepareEngineWith(home, on); err != nil {
		t.Fatal(err)
	}
	p := stopEnginePlan()
	if eng == nil {
		t.Fatal("safe-mode plan stopped the engine early")
	}
	p.rollback()
	if eng == nil {
		t.Fatal("safe-mode rollback stopped the engine")
	}
	p.commit()
	if eng != nil {
		t.Fatal("safe-mode commit did not stop the engine")
	}

	// A fresh engine created for a failed apply is torn down again (the old core never pointed at it).
	_, plan, _ = planEngineWith(home, on)
	if eng == nil {
		t.Fatal("no engine")
	}
	plan.rollback()
	if eng != nil {
		t.Fatal("rollback kept an engine the old core config never used")
	}
}
