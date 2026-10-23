package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
)

// v0.14 rule hit counters kept across sessions.
//
// mihomo counts hits per top-level rule (RuleWrapper.HitCount), but the counters start at 0 on every
// apply. The extension folds the per-session deltas into <home>/rule-hits.json every 30 s, before a
// reload and on stop. The file is read-modify-written on every flush, so the app can reset it (delete
// the file, or drop single keys) while the tunnel runs: the next flush only adds what is new since the
// previous one.

const ruleHitsFile = "rule-hits.json"
const ruleHitsInterval = 30 * time.Second

// RuleHitEntry is one rule identity (type, payload, policy).
type RuleHitEntry struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Proxy   string `json:"proxy"`
	Total   uint64 `json:"total"`
	Day     string `json:"day"`   // yyyy-mm-dd (local) of Today
	Today   uint64 `json:"today"` // hits on Day
	LastHit int64  `json:"lastHit"`
}

// RuleHitsData is the file layout.
type RuleHitsData struct {
	Since int64                    `json:"since"` // first count after the last full reset (unix seconds)
	Rules map[string]*RuleHitEntry `json:"rules"`
}

var (
	ruleHitsMu   sync.Mutex
	ruleHitsBase = map[C.RuleWrapper]uint64{}
	ruleHitsStop chan struct{}
)

func ruleHitKey(t, payload, proxy string) string { return t + "," + payload + "," + proxy }

func readRuleHits(home string) RuleHitsData {
	d := RuleHitsData{Rules: map[string]*RuleHitEntry{}}
	if b, err := os.ReadFile(filepath.Join(home, ruleHitsFile)); err == nil {
		_ = json.Unmarshal(b, &d)
	}
	if d.Rules == nil {
		d.Rules = map[string]*RuleHitEntry{}
	}
	return d
}

// foldRuleHits adds the deltas of the given rules into d. Returns true when anything changed.
func foldRuleHits(d *RuleHitsData, rules []C.Rule, base map[C.RuleWrapper]uint64, now time.Time) bool {
	seen := make(map[C.RuleWrapper]bool, len(rules))
	changed := false
	day := now.Format("2006-01-02")
	for _, r := range rules {
		w, ok := r.(C.RuleWrapper)
		if !ok {
			continue
		}
		seen[w] = true
		n := w.HitCount()
		prev := base[w]
		if n < prev { // never happens for one wrapper, but stay safe
			prev = 0
		}
		base[w] = n
		delta := n - prev
		if delta == 0 {
			continue
		}
		inner := w.Unwrap()
		t, p, px := inner.RuleType().String(), inner.Payload(), inner.Adapter()
		k := ruleHitKey(t, p, px)
		e := d.Rules[k]
		if e == nil {
			e = &RuleHitEntry{Type: t, Payload: p, Proxy: px}
			d.Rules[k] = e
		}
		e.Total += delta
		if e.Day != day {
			e.Day, e.Today = day, 0
		}
		e.Today += delta
		if at := w.HitAt(); !at.IsZero() {
			e.LastHit = at.Unix()
		} else {
			e.LastHit = now.Unix()
		}
		changed = true
	}
	for w := range base {
		if !seen[w] {
			delete(base, w)
		}
	}
	if changed && d.Since == 0 {
		d.Since = now.Unix()
	}
	return changed
}

// flushRuleHits folds the running core's counters into the file.
func flushRuleHits(home string) {
	if home == "" {
		return
	}
	ruleHitsMu.Lock()
	defer ruleHitsMu.Unlock()
	// v0.19.10 (review 5 go-core P2-4): keep the decoded data while running; re-read only when the file
	// changed under us (ResetRuleHits from the app process) instead of read + decode every 30 s.
	p := filepath.Join(home, ruleHitsFile)
	var d RuleHitsData
	if ruleHitsCache != nil && ruleHitsCacheHome == home && statSig(p) == ruleHitsCacheSig {
		d = *ruleHitsCache
	} else {
		d = readRuleHits(home)
	}
	now := time.Now()
	if !foldRuleHits(&d, tunnel.Rules(), ruleHitsBase, now) {
		ruleHitsCache, ruleHitsCacheHome, ruleHitsCacheSig = &d, home, statSig(p)
		return
	}
	pruneRuleHits(&d, now)
	if b, err := json.Marshal(d); err == nil {
		_ = writeFileAtomic(p, b)
	}
	ruleHitsCache, ruleHitsCacheHome, ruleHitsCacheSig = &d, home, statSig(p)
}

// Rule-hit entries are keyed type,payload,policy and never expired before v0.19.10, so profile switches,
// subscription updates and renames grew the file forever.
const (
	ruleHitsMaxAge     = 30 * 24 * time.Hour
	ruleHitsMaxEntries = 5000
)

var (
	ruleHitsCache     *RuleHitsData
	ruleHitsCacheHome string
	ruleHitsCacheSig  string
)

// pruneRuleHits drops entries not hit for 30 days and keeps at most ruleHitsMaxEntries (newest LastHit).
func pruneRuleHits(d *RuleHitsData, now time.Time) {
	cut := now.Add(-ruleHitsMaxAge).Unix()
	for k, e := range d.Rules {
		if e == nil || e.LastHit > 0 && e.LastHit < cut {
			delete(d.Rules, k)
		}
	}
	if len(d.Rules) <= ruleHitsMaxEntries {
		return
	}
	keys := make([]string, 0, len(d.Rules))
	for k := range d.Rules {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := d.Rules[keys[i]], d.Rules[keys[j]]
		if a.LastHit != b.LastHit {
			return a.LastHit > b.LastHit
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys[ruleHitsMaxEntries:] {
		delete(d.Rules, k)
	}
}

func startRuleHits(home string) {
	stopRuleHits("")
	stop := make(chan struct{})
	ruleHitsMu.Lock()
	ruleHitsStop = stop
	ruleHitsMu.Unlock()
	go func() {
		t := time.NewTicker(ruleHitsInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				flushRuleHits(home)
			case <-stop:
				return
			}
		}
	}()
}

// stopRuleHits flushes (when home is set) and stops the ticker.
func stopRuleHits(home string) {
	flushRuleHits(home)
	ruleHitsMu.Lock()
	if ruleHitsStop != nil {
		close(ruleHitsStop)
		ruleHitsStop = nil
	}
	ruleHitsBase = map[C.RuleWrapper]uint64{}
	ruleHitsMu.Unlock()
}

// FlushRuleHits saves the running core's counters now (the extension calls it for the app's flushStats
// message and on sleep). No-op when the core is not running.
func FlushRuleHits() {
	if running.Load() {
		flushRuleHits(curHomeStr())
		statsRec.save(false) // P0-2: the extension calls this on sleep / flushStats; keep the session stats too
	}
}

// ResetRuleHits clears saved counters: all of them when key is "", else the one rule identity
// ("TYPE,payload,policy" as stored). Returns the error text or "".
func ResetRuleHits(homeDir, key string) string {
	ruleHitsMu.Lock()
	defer ruleHitsMu.Unlock()
	ruleHitsCache = nil
	p := filepath.Join(homeDir, ruleHitsFile)
	if key == "" {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err.Error()
		}
		return ""
	}
	d := readRuleHits(homeDir)
	delete(d.Rules, key)
	b, err := json.Marshal(d)
	if err != nil {
		return err.Error()
	}
	if err := writeFileAtomic(p, b); err != nil {
		return err.Error()
	}
	return ""
}
