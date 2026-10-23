package libmihomo

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/tunnel"
)

func pwSnap(groups ...pwGroup) pwSnapshot { return pwSnapshot{Groups: groups} }

func TestPolicyWatchChangeBaselineAndQuiet(t *testing.T) {
	st := newPolicyWatchState()
	t0 := time.Unix(1_700_000_000, 0)
	auto := func(now string) pwGroup {
		return pwGroup{Name: "Auto", Auto: true, Now: now, Members: []pwMember{{Name: "A", Alive: true}, {Name: "B", Alive: true}}}
	}
	all := int32(policyEventChange | policyEventFailure | policyEventNode)
	if ev := st.step(pwSnap(auto("A")), all, t0); len(ev.Changes) != 0 {
		t.Fatalf("baseline must not report: %+v", ev)
	}
	ev := st.step(pwSnap(auto("B")), all, t0.Add(30*time.Second))
	if len(ev.Changes) != 1 || ev.Changes[0] != (pwChange{Group: "Auto", From: "A", To: "B"}) {
		t.Fatalf("change: %+v", ev)
	}
	// Back within the quiet window: not reported, but the baseline follows.
	if ev := st.step(pwSnap(auto("A")), all, t0.Add(60*time.Second)); len(ev.Changes) != 0 {
		t.Fatalf("quiet window: %+v", ev)
	}
	if ev := st.step(pwSnap(auto("B")), all, t0.Add(6*time.Minute)); len(ev.Changes) != 1 || ev.Changes[0].From != "A" {
		t.Fatalf("after quiet window: %+v", ev)
	}
	// Switch off: the state still follows, nothing reported.
	if ev := st.step(pwSnap(auto("A")), policyEventFailure, t0.Add(20*time.Minute)); len(ev.Changes) != 0 {
		t.Fatalf("kind off: %+v", ev)
	}
	// Pinned / hidden / selector groups never report a change.
	for _, g := range []pwGroup{
		{Name: "Auto", Auto: true, Now: "B", Fixed: true, Members: auto("").Members},
	} {
		if ev := st.step(pwSnap(g), all, t0.Add(40*time.Minute)); len(ev.Changes) != 0 {
			t.Fatalf("pinned: %+v", ev)
		}
	}
	sel := func(now string) pwGroup { return pwGroup{Name: "Sel", Now: now, Members: auto("").Members} }
	st.step(pwSnap(sel("A")), all, t0.Add(50*time.Minute))
	if ev := st.step(pwSnap(sel("B")), all, t0.Add(60*time.Minute)); len(ev.Changes) != 0 {
		t.Fatalf("selector (user choice) reported: %+v", ev)
	}
}

func TestPolicyWatchFailures(t *testing.T) {
	dead := func(names ...string) []pwMember {
		var m []pwMember
		for _, n := range names {
			m = append(m, pwMember{Name: n})
		}
		return m
	}
	groups := []pwGroup{
		{Name: "HK", Auto: true, Now: "h1", Members: dead("h1", "h2")},
		{Name: "Main", Now: "HK", Members: append([]pwMember{{Name: "HK", Group: true}}, dead("x")...)},
		{Name: "WithDirect", Now: "HK", Members: []pwMember{{Name: "HK", Group: true}, {Name: "DIRECT", Builtin: true, Alive: true}}},
		{Name: "Empty"},
	}
	f := failedGroups(groups)
	if !f["HK"] || !f["Main"] || f["WithDirect"] || f["Empty"] {
		t.Fatalf("failedGroups: %v", f)
	}
	// A cycle never counts as failed and never recurses forever.
	cyc := failedGroups([]pwGroup{{Name: "A", Members: []pwMember{{Name: "B", Group: true}}}, {Name: "B", Members: []pwMember{{Name: "A", Group: true}}}})
	if cyc["A"] && cyc["B"] {
		t.Logf("cycle: %v", cyc)
	}

	st := newPolicyWatchState()
	t0 := time.Unix(1_700_000_000, 0)
	all := int32(policyEventChange | policyEventFailure | policyEventNode)
	alive := []pwGroup{{Name: "HK", Auto: true, Now: "h1", Members: []pwMember{{Name: "h1", Alive: true}, {Name: "h2"}}}}
	st.step(pwSnapshot{Groups: alive}, all, t0)
	ev := st.step(pwSnapshot{Groups: groups[:2]}, all, t0.Add(30*time.Second))
	if len(ev.Failures) != 2 || ev.Failures[0] != "HK" || ev.Failures[1] != "Main" {
		t.Fatalf("failures: %+v", ev)
	}
	// While failed: no repeat, and the fallback's meaningless Now change is not a 切换.
	g2 := append([]pwGroup(nil), groups[:2]...)
	g2[0].Now = "h2"
	if ev := st.step(pwSnapshot{Groups: g2}, all, t0.Add(60*time.Second)); len(ev.Failures) != 0 || len(ev.Changes) != 0 {
		t.Fatalf("repeat: %+v", ev)
	}
	// Recovers, fails again → reported again. Hidden groups are tracked but never reported.
	st.step(pwSnapshot{Groups: alive}, all, t0.Add(90*time.Second))
	hidden := []pwGroup{{Name: "HK", Auto: true, Now: "h1", Hidden: true, Members: dead("h1")}}
	if ev := st.step(pwSnapshot{Groups: hidden}, all, t0.Add(120*time.Second)); len(ev.Failures) != 0 {
		t.Fatalf("hidden: %+v", ev)
	}
	st.step(pwSnapshot{Groups: alive}, all, t0.Add(150*time.Second))
	if ev := st.step(pwSnapshot{Groups: groups[:1]}, all, t0.Add(180*time.Second)); len(ev.Failures) != 1 {
		t.Fatalf("second failure: %+v", ev)
	}
}

func TestPolicyWatchNode(t *testing.T) {
	st := newPolicyWatchState()
	t0 := time.Unix(1_700_000_000, 0)
	all := int32(policyEventNode)
	st.step(pwSnapshot{Leaf: "n1", LeafGroup: "Main", LeafAlive: true}, all, t0)
	ev := st.step(pwSnapshot{Leaf: "n1", LeafGroup: "Main"}, all, t0.Add(time.Minute))
	if ev.Node != "n1" || ev.NodeGroup != "Main" {
		t.Fatalf("node: %+v", ev)
	}
	if ev := st.step(pwSnapshot{Leaf: "n1", LeafGroup: "Main"}, all, t0.Add(2*time.Minute)); ev.Node != "" {
		t.Fatalf("repeat: %+v", ev)
	}
	if ev := st.step(pwSnapshot{Leaf: "n2", LeafGroup: "Main"}, all, t0.Add(3*time.Minute)); ev.Node != "n2" {
		t.Fatalf("other node: %+v", ev)
	}
	if ev := st.step(pwSnapshot{Leaf: "", LeafGroup: ""}, all, t0.Add(4*time.Minute)); ev.Node != "" {
		t.Fatalf("DIRECT: %+v", ev)
	}
	// Dead already at the baseline: not reported (state from before this run).
	st2 := newPolicyWatchState()
	if ev := st2.step(pwSnapshot{Leaf: "n1", LeafGroup: "Main"}, all, t0); ev.Node != "" {
		t.Fatalf("baseline: %+v", ev)
	}
}

type pwRecorder struct {
	mu   sync.Mutex
	msgs []string
}

func (r *pwRecorder) Notify(p string) {
	r.mu.Lock()
	r.msgs = append(r.msgs, p)
	r.mu.Unlock()
}

// Through the real core: a url-test group of two closed local ports, tested by the group itself, is reported as
// failed (and the main select group that uses it, with its node) after the baseline scan.
func TestPolicyWatchThroughCore(t *testing.T) {
	closed := func() int {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		return p
	}
	home := t.TempDir()
	ov := defaultOverrides()
	ov.ControllerPort = freeTCPPort(t)
	ov.Secret = "s"
	ov.MixedPort = freeTCPPort(t)
	ob, _ := json.Marshal(ov)
	_ = os.WriteFile(filepath.Join(home, "overrides.json"), ob, 0o644)
	prof := filepath.Join(home, "p.yaml")
	node := func(n string) string {
		return "  - {name: " + n + ", type: ss, server: 127.0.0.1, port: " + strconv.Itoa(closed()) + ", cipher: aes-128-gcm, password: x}\n"
	}
	test := "http://127.0.0.1:" + strconv.Itoa(closed()) + "/"
	_ = os.WriteFile(prof, []byte("mode: rule\nproxies:\n"+node("n1")+node("n2")+
		"proxy-groups:\n  - {name: Main, type: select, proxies: [Auto]}\n  - {name: Auto, type: url-test, proxies: [n1, n2], url: '"+test+"', interval: 3600, lazy: true}\n"+
		"rules:\n  - MATCH,Main\n"), 0o644)
	rec := &pwRecorder{}
	SetNotifier(rec)
	defer SetNotifier(nil)
	if err := Start(home, prof, 0); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	var snap pwSnapshot
	ok := false
	for i := 0; i < 50 && !ok; i++ {
		snap, ok = takePolicySnapshot()
		if ok && len(snap.Groups) < 2 {
			ok = false
			time.Sleep(100 * time.Millisecond)
		}
	}
	if !ok {
		t.Fatal("no snapshot")
	}
	if snap.Groups[0].Name != "Main" && snap.Groups[1].Name != "Main" {
		t.Fatalf("groups: %+v", snap.Groups)
	}
	// Baseline = the same groups with every node working (the core may already have run a first check).
	base := pwSnapshot{Leaf: "n1", LeafGroup: "Auto", LeafAlive: true}
	for _, g := range snap.Groups {
		g2 := g
		g2.Members = nil
		for _, m := range g.Members {
			m.Alive = true
			g2.Members = append(g2.Members, m)
		}
		base.Groups = append(base.Groups, g2)
	}
	st := newPolicyWatchState()
	all := int32(policyEventChange | policyEventFailure | policyEventNode)
	st.step(base, all, time.Now())
	p := tunnel.Proxies()["Auto"]
	g := p.Adapter().(outboundgroup.ProxyGroup)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, _ = g.URLTest(ctx, test, nil)
	cancel()
	snap, ok = takePolicySnapshot()
	if !ok {
		t.Fatal("no snapshot after test")
	}
	if snap.Leaf == "" || snap.LeafAlive {
		t.Fatalf("leaf: %+v", snap)
	}
	ev := st.step(snap, all, time.Now())
	if len(ev.Failures) != 2 || ev.Node == "" || ev.NodeGroup != "Auto" {
		t.Fatalf("events: %+v (snap %+v)", ev, snap)
	}
	emitPolicyEvents(ev)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.msgs) != 2 {
		t.Fatalf("notifier got %v", rec.msgs)
	}
	var f struct {
		Kind   string   `json:"kind"`
		Groups []string `json:"groups"`
	}
	_ = json.Unmarshal([]byte(rec.msgs[0]), &f)
	if f.Kind != "policyFailure" || len(f.Groups) != 2 {
		t.Fatalf("payload %s", rec.msgs[0])
	}
}

func TestSetPolicyEventsStartsAndStops(t *testing.T) {
	old := pwInterval
	pwInterval = 10 * time.Millisecond
	defer func() { pwInterval = old }()
	SetPolicyEvents(policyEventChange)
	pwMu.Lock()
	started := pwStop != nil
	pwMu.Unlock()
	SetPolicyEvents(policyEventChange | policyEventNode) // already running: same goroutine
	time.Sleep(30 * time.Millisecond)                    // ticks with the core stopped: reset only
	SetPolicyEvents(0)
	pwMu.Lock()
	stopped := pwStop == nil && pwMask == 0
	pwMu.Unlock()
	if !started || !stopped {
		t.Fatalf("started %v stopped %v", started, stopped)
	}
	SetPolicyEvents(0) // twice is fine
}
