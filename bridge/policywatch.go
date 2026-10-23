package libmihomo

// feat/loon-menu-notify (user 2026-10-23, Loon's 通知 page: 策略匹配异常 / 策略匹配变更 / 节点异常): the policy watcher.
// While the tunnel runs and one of its kinds is switched on (更多 → 通知, passed in by SetPolicyEvents), it looks at
// the policy groups every 30 s and reports, through the script notifier with a `kind` field:
//
//   policyChange   an automatic group (url-test / fallback, not pinned) now uses another node
//   policyFailure  every member of a visible group failed its latency test (no DIRECT / REJECT member, nested groups
//                  count as failed only when they failed themselves)
//   nodeFailure    the node the main policy resolves to (the same walk as the Live Activity) failed its test
//
// Only real state is read: Now() and each proxy's alive flag for the group's test URL, which the groups' own health
// checks and the app's 测速 update. Nothing is dialled here. The first scan after a start / reload is a baseline (no
// events), a group that keeps switching reports at most once per 5 minutes, and a failure is reported once until
// it recovers.

import (
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/outboundgroup"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
)

const (
	policyEventChange  = 1
	policyEventFailure = 2
	policyEventNode    = 4

	policyWatchInterval = 30 * time.Second
	policyChangeQuiet   = 5 * time.Minute
)

var (
	pwMu    sync.Mutex
	pwMask  int32
	pwStop  chan struct{}
	pwState = newPolicyWatchState()
	// pwInterval is a variable for tests.
	pwInterval = policyWatchInterval
)

// SetPolicyEvents switches the watcher's kinds (bit 1 policyChange, 2 policyFailure, 4 nodeFailure). 0 stops the
// watcher goroutine; any other value starts it (baseline on its first scan).
func SetPolicyEvents(mask int32) {
	mask &= policyEventChange | policyEventFailure | policyEventNode
	pwMu.Lock()
	defer pwMu.Unlock()
	pwMask = mask
	if mask == 0 {
		if pwStop != nil {
			close(pwStop)
			pwStop = nil
		}
		pwState = newPolicyWatchState()
		return
	}
	if pwStop == nil {
		stop := make(chan struct{})
		pwStop = stop
		go policyWatchLoop(stop, pwInterval)
	}
}

// policyWatchReset drops the baseline (Reload: the groups may have changed; Stop: the next start begins fresh).
func policyWatchReset() {
	pwMu.Lock()
	pwState = newPolicyWatchState()
	pwMu.Unlock()
}

func policyWatchLoop(stop chan struct{}, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			policyWatchTick()
		}
	}
}

func policyWatchTick() {
	if !running.Load() {
		policyWatchReset()
		return
	}
	snap, ok := takePolicySnapshot()
	if !ok {
		return
	}
	pwMu.Lock()
	mask := pwMask
	ev := pwState.step(snap, mask, time.Now())
	pwMu.Unlock()
	emitPolicyEvents(ev)
}

// ---------------- snapshot ----------------

type pwMember struct {
	Name    string
	Group   bool
	Builtin bool
	Alive   bool
}

type pwGroup struct {
	Name    string
	Auto    bool // url-test / fallback
	Now     string
	Fixed   bool // url-test / fallback pinned by the user
	Hidden  bool
	Members []pwMember
}

type pwSnapshot struct {
	Groups    []pwGroup // runtime order, then name
	Leaf      string    // node the main policy resolves to ("" = none / built-in)
	LeafGroup string    // the group that picked it
	LeafAlive bool
}

func isBuiltinType(t C.AdapterType) bool {
	switch t {
	case C.Direct, C.Reject, C.RejectDrop, C.Pass, C.PassRule, C.Rematch, C.Compatible, C.Dns:
		return true
	}
	return false
}

func takePolicySnapshot() (s pwSnapshot, ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	proxies := tunnel.Proxies()
	if len(proxies) == 0 {
		return s, false
	}
	testURLs := map[string]string{}
	for name, p := range proxies {
		if name == "GLOBAL" {
			continue
		}
		g, isGroup := p.Adapter().(outboundgroup.ProxyGroup)
		if !isGroup {
			continue
		}
		var meta struct {
			TestURL string `json:"testUrl"`
			Fixed   string `json:"fixed"`
		}
		if b, err := p.Adapter().MarshalJSON(); err == nil {
			_ = json.Unmarshal(b, &meta)
		}
		testURLs[name] = meta.TestURL
		kind := p.Type()
		pg := pwGroup{Name: name, Auto: kind == C.URLTest || kind == C.Fallback, Now: g.Now(), Fixed: meta.Fixed != "", Hidden: g.Hidden()}
		for _, m := range g.Proxies() {
			_, mg := m.Adapter().(outboundgroup.ProxyGroup)
			pg.Members = append(pg.Members, pwMember{Name: m.Name(), Group: mg, Builtin: !mg && isBuiltinType(m.Type()), Alive: m.AliveForTestUrl(meta.TestURL)})
		}
		s.Groups = append(s.Groups, pg)
	}
	order, _ := liveGroupOrder.Load().([]string)
	rank := map[string]int{}
	for i, n := range order {
		rank[n] = i + 1
	}
	sort.Slice(s.Groups, func(i, j int) bool {
		ri, rj := rank[s.Groups[i].Name], rank[s.Groups[j].Name]
		if ri == 0 {
			ri = 1 << 30
		}
		if rj == 0 {
			rj = 1 << 30
		}
		if ri != rj {
			return ri < rj
		}
		return s.Groups[i].Name < s.Groups[j].Name
	})
	// The main policy's node: same walk as liveNode, remembering the group that picked the leaf.
	start := "GLOBAL"
	if tunnel.Mode() != tunnel.Global {
		if n := mainRuleGroup(proxies); n != "" {
			start = n
		}
	}
	name, parent := start, ""
	for hops := 0; hops < 8; hops++ {
		p, ok := proxies[name]
		if !ok {
			break
		}
		g, isGroup := p.Adapter().(outboundgroup.ProxyGroup)
		if !isGroup {
			break
		}
		now := g.Now()
		if now == "" || now == name {
			break
		}
		parent, name = name, now
	}
	if p, ok := proxies[name]; ok && parent != "" {
		if _, isGroup := p.Adapter().(outboundgroup.ProxyGroup); !isGroup && !isBuiltinType(p.Type()) {
			s.Leaf, s.LeafGroup = name, parent
			s.LeafAlive = p.AliveForTestUrl(testURLs[parent])
		}
	}
	return s, true
}

// ---------------- diff (pure, tested) ----------------

type pwChange struct {
	Group string `json:"group"`
	From  string `json:"from"`
	To    string `json:"to"`
}

type pwEvents struct {
	Changes   []pwChange
	Failures  []string
	Node      string
	NodeGroup string
}

type policyWatchState struct {
	baseline bool
	now      map[string]string
	notified map[string]time.Time
	failed   map[string]bool
	deadLeaf string
}

func newPolicyWatchState() *policyWatchState {
	return &policyWatchState{now: map[string]string{}, notified: map[string]time.Time{}, failed: map[string]bool{}}
}

// failedGroups: groups (visible or not) whose every member failed; nested groups resolved recursively.
func failedGroups(groups []pwGroup) map[string]bool {
	byName := map[string]*pwGroup{}
	for i := range groups {
		byName[groups[i].Name] = &groups[i]
	}
	memo := map[string]bool{}
	visiting := map[string]bool{}
	var failed func(name string, depth int) bool
	failed = func(name string, depth int) bool {
		if v, ok := memo[name]; ok {
			return v
		}
		g := byName[name]
		if g == nil || depth > 8 || visiting[name] || len(g.Members) == 0 {
			return false
		}
		visiting[name] = true
		res := true
		for _, m := range g.Members {
			switch {
			case m.Builtin:
				res = false
			case m.Group:
				if !failed(m.Name, depth+1) {
					res = false
				}
			case m.Alive:
				res = false
			}
			if !res {
				break
			}
		}
		visiting[name] = false
		memo[name] = res
		return res
	}
	out := map[string]bool{}
	for _, g := range groups {
		if failed(g.Name, 0) {
			out[g.Name] = true
		}
	}
	return out
}

func (st *policyWatchState) step(s pwSnapshot, mask int32, t time.Time) pwEvents {
	var ev pwEvents
	failedNow := failedGroups(s.Groups)
	first := !st.baseline
	st.baseline = true
	seen := map[string]bool{}
	for _, g := range s.Groups {
		seen[g.Name] = true
		// 策略组异常: report the transition into "all failed", once.
		if failedNow[g.Name] {
			if !st.failed[g.Name] && !first && !g.Hidden && mask&policyEventFailure != 0 {
				ev.Failures = append(ev.Failures, g.Name)
			}
			st.failed[g.Name] = true
		} else {
			delete(st.failed, g.Name)
		}
		// 自动策略切换: an unpinned url-test / fallback group with a working node now uses another one.
		if !g.Auto || g.Now == "" {
			continue
		}
		prev, had := st.now[g.Name]
		st.now[g.Name] = g.Now
		if first || !had || prev == g.Now || g.Fixed || g.Hidden || failedNow[g.Name] || mask&policyEventChange == 0 {
			continue
		}
		if last, ok := st.notified[g.Name]; ok && t.Sub(last) < policyChangeQuiet {
			continue
		}
		st.notified[g.Name] = t
		ev.Changes = append(ev.Changes, pwChange{Group: g.Name, From: prev, To: g.Now})
	}
	for n := range st.now {
		if !seen[n] {
			delete(st.now, n)
			delete(st.notified, n)
		}
	}
	for n := range st.failed {
		if !seen[n] {
			delete(st.failed, n)
		}
	}
	// 节点异常: the main policy's node failed its test; once per node until it recovers or another node is used.
	switch {
	case s.Leaf == "" || s.LeafAlive:
		st.deadLeaf = ""
	case st.deadLeaf != s.Leaf:
		st.deadLeaf = s.Leaf
		if !first && mask&policyEventNode != 0 {
			ev.Node, ev.NodeGroup = s.Leaf, s.LeafGroup
		}
	}
	return ev
}

// ---------------- delivery ----------------

func emitPolicyEvents(ev pwEvents) {
	engMu.Lock()
	n := notifier
	engMu.Unlock()
	if n == nil {
		return
	}
	send := func(v any) {
		if b, err := json.Marshal(v); err == nil {
			n.Notify(string(b))
		}
	}
	if len(ev.Changes) > 0 {
		send(map[string]any{"kind": "policyChange", "changes": ev.Changes})
	}
	if len(ev.Failures) > 0 {
		send(map[string]any{"kind": "policyFailure", "groups": ev.Failures})
	}
	if ev.Node != "" {
		send(map[string]any{"kind": "nodeFailure", "node": ev.Node, "group": ev.NodeGroup})
	}
}
