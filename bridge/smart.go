package libmihomo

// 智能选择 (smart selection) for url-test / fallback groups. It is an option on the group, not a new
// group type, so the profile stays a normal mihomo profile. The group keeps running mihomo's own
// health checks (url / interval / lazy from the profile); every 30 s we score each member from that
// check history — recency-weighted latency of the last successes, multiplied up for recent failures
// and for a failed last check — and pin the best node through the group's own Set (url-test / fallback
// "fixed"). mihomo still drops a pinned node the moment its health check fails, and we only switch
// when the new node is clearly better (score < 85 % of the current), so the choice doesn't flap.
//
// Settings: <home>/groups.json {"<profile id>": {"smart": ["GroupName", …]}} (our override store).
// Status: GET /smart on the local controller.

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/metacubex/chi"
	mhttp "github.com/metacubex/http"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/route"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
)

type groupSettings struct {
	Smart []string `json:"smart,omitempty"`
}

func groupSettingsPath(home string) string { return filepath.Join(home, "groups.json") }

func readSmartGroups(home, profilePath string) []string {
	b, err := os.ReadFile(groupSettingsPath(home))
	if err != nil {
		return nil
	}
	m := map[string]groupSettings{}
	_ = json.Unmarshal(b, &m)
	return m[profileIDFromPath(profilePath)].Smart
}

type smartMember struct {
	Name  string  `json:"name"`
	Score float64 `json:"score"` // lower is better; -1 = no data
	Avg   int     `json:"avg"`   // weighted latency of recent successes (ms)
	Fails int     `json:"fails"` // failures in the recent window
	Count int     `json:"count"` // checks in the recent window
	Alive bool    `json:"alive"`
}

type smartGroupStatus struct {
	Name       string        `json:"name"`
	Type       string        `json:"type"`
	Now        string        `json:"now"`
	Pinned     string        `json:"pinned,omitempty"`
	Reason     string        `json:"reason,omitempty"`
	SwitchedAt float64       `json:"switchedAt,omitempty"`
	CheckedAt  float64       `json:"checkedAt,omitempty"`
	Members    []smartMember `json:"members"`
}

var (
	smartMu     sync.Mutex
	smartStop   chan struct{}
	smartStatus = map[string]*smartGroupStatus{}
)

const smartWindow = 10

// smartScore scores one node from its health-check history (oldest first). Lower is better.
func smartScore(hist []C.DelayHistory, alive bool) (score float64, avg, fails, count int) {
	if len(hist) > smartWindow {
		hist = hist[len(hist)-smartWindow:]
	}
	count = len(hist)
	if count == 0 {
		return math.Inf(1), 0, 0, 0
	}
	var wsum, dsum float64
	succ := 0
	for i := len(hist) - 1; i >= 0; i-- {
		d := hist[i].Delay
		if d == 0 {
			fails++
			continue
		}
		if succ < 5 { // recency-weighted mean of the last 5 successes
			w := float64(5 - succ)
			dsum += w * float64(d)
			wsum += w
			succ++
		}
	}
	if wsum == 0 {
		return math.Inf(1), 0, fails, count
	}
	a := dsum / wsum
	score = a * (1 + 2*float64(fails)/float64(count))
	if hist[len(hist)-1].Delay == 0 {
		score *= 2
	}
	if !alive {
		score *= 4
	}
	return score, int(a + 0.5), fails, count
}

// smartPick returns the index of the member to use, or -1 to keep cur.
func smartPick(scores []float64, cur int) int {
	best := -1
	for i, s := range scores {
		if math.IsInf(s, 1) {
			continue
		}
		if best < 0 || s < scores[best] {
			best = i
		}
	}
	if best < 0 || best == cur {
		return -1
	}
	if cur >= 0 && !math.IsInf(scores[cur], 1) && scores[best] >= 0.85*scores[cur] {
		return -1
	}
	return best
}

func groupTestURL(p C.Proxy) string {
	b, err := json.Marshal(p)
	if err != nil {
		return ""
	}
	var m struct {
		TestURL string `json:"testUrl"`
	}
	_ = json.Unmarshal(b, &m)
	return m.TestURL
}

func memberHistory(p C.Proxy, testURL string) []C.DelayHistory {
	if testURL != "" {
		if st, ok := p.ExtraDelayHistories()[testURL]; ok && len(st.History) > 0 {
			return st.History
		}
	}
	return p.DelayHistory()
}

func smartTick(names []string) {
	proxies := tunnel.Proxies()
	now := float64(time.Now().Unix())
	for _, name := range names {
		p, ok := proxies[name]
		if !ok || (p.Type() != C.URLTest && p.Type() != C.Fallback) {
			continue
		}
		g, ok := p.Adapter().(outboundgroup.ProxyGroup)
		if !ok {
			continue
		}
		sel, _ := p.Adapter().(outboundgroup.SelectAble)
		testURL := groupTestURL(p)
		members := g.Proxies()
		scores := make([]float64, len(members))
		smartMu.Lock()
		st := smartStatus[name]
		if st == nil {
			st = &smartGroupStatus{Name: name}
			smartStatus[name] = st
		}
		st.Type, st.CheckedAt, st.Members = p.Type().String(), now, nil
		cur := -1
		for i, m := range members {
			alive := m.AliveForTestUrl(testURL)
			s, avg, fails, count := smartScore(memberHistory(m, testURL), alive)
			scores[i] = s
			sm := smartMember{Name: m.Name(), Score: -1, Avg: avg, Fails: fails, Count: count, Alive: alive}
			if !math.IsInf(s, 1) {
				sm.Score = math.Round(s)
			}
			st.Members = append(st.Members, sm)
			if m.Name() == st.Pinned {
				cur = i
			}
		}
		if cur < 0 {
			for i, m := range members {
				if m.Name() == g.Now() {
					cur = i
				}
			}
		}
		if pick := smartPick(scores, cur); pick >= 0 && sel != nil {
			target := members[pick].Name()
			if err := sel.Set(target); err == nil {
				st.Pinned, st.SwitchedAt = target, now
				st.Reason = "延迟与失败率综合最优"
				log.Infoln("[Smart] %s → %s (score %.0f)", name, target, scores[pick])
			}
		}
		st.Now = g.Now()
		smartMu.Unlock()
	}
}

// startSmart (re)starts the scorer for the profile's smart groups; called after every apply.
func startSmart(home, profilePath string) {
	smartMu.Lock()
	if smartStop != nil {
		close(smartStop)
		smartStop = nil
	}
	smartStatus = map[string]*smartGroupStatus{}
	names := readSmartGroups(home, profilePath)
	if len(names) == 0 {
		smartMu.Unlock()
		return
	}
	for _, n := range names {
		smartStatus[n] = &smartGroupStatus{Name: n, Members: []smartMember{}}
	}
	stop := make(chan struct{})
	smartStop = stop
	smartMu.Unlock()
	log.Infoln("[Smart] 智能选择：%v", names)
	go func() {
		first := time.NewTimer(20 * time.Second)
		defer first.Stop()
		select {
		case <-first.C:
		case <-stop:
			return
		}
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			smartTick(names)
			select {
			case <-t.C:
			case <-stop:
				return
			}
		}
	}()
}

func stopSmart() {
	smartMu.Lock()
	if smartStop != nil {
		close(smartStop)
		smartStop = nil
	}
	smartMu.Unlock()
}

func smartRoutes(r chi.Router) {
	r.Get("/smart", func(w mhttp.ResponseWriter, req *mhttp.Request) {
		smartMu.Lock()
		list := make([]*smartGroupStatus, 0, len(smartStatus))
		for _, s := range smartStatus {
			list = append(list, s)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
		b, _ := json.Marshal(map[string]any{"groups": list})
		smartMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	})
}

func init() { route.Register(smartRoutes) }
