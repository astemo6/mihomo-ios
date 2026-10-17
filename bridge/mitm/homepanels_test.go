package mitm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const qxGenericJS = `$done({title: "流媒体", htmlMessage: "<p>Netflix: <b>解锁</b></p><br>YouTube &amp; Premium: 香港"});`
const qxInterJS = `console.log("node=" + $environment.params); $done({title: "节点", message: "节点：" + $environment.params});`
const surgePanelJS = `$done({title: "Surge", content: "c" + Date.now()});`

func TestHomePanels(t *testing.T) {
	cfg := &Config{Enabled: true}
	h := newHarness(t, cfg, map[string]string{"gen.js": qxGenericJS, "inter.js": qxInterJS, "sp.js": surgePanelJS})
	build := func() *Ruleset {
		rs := Build(h.home, cfg)
		rs.ParseText("[task_local]\nevent-interaction inter.js, tag=节点信息\n", "QX", nil)
		rs.ParseText("[Script]\n流媒体 = type=generic,script-path=gen.js\nsp = type=generic,script-path=sp.js\n[Panel]\n面板 = script-name=sp,update-interval=600\n", "Surge", nil)
		return rs
	}
	h.e.Reload(cfg, build())
	var gen, inter, surge string
	for _, s := range h.e.tasks.list() {
		switch s.Script.Name {
		case "流媒体":
			gen = s.ID
		case "节点信息":
			inter = s.ID
		}
	}
	pl := h.e.tasks.panelList()
	if gen == "" || inter == "" || len(pl) != 1 {
		t.Fatalf("setup: gen=%q inter=%q panels=%d", gen, inter, len(pl))
	}
	surge = pl[0].ID

	node := "🇭🇰 香港 02"
	list := h.e.tasks.setHome(HomePanels{Visible: []string{TaskPanelPrefix + gen, surge, TaskPanelPrefix + inter},
		Tasks: []HomePanelPin{{ID: gen, Interval: 1800}, {ID: inter, Params: &node}, {ID: "missing"}}})
	if len(list) != 3 {
		t.Fatalf("task panels not added: %+v", list)
	}
	b, _ := os.ReadFile(filepath.Join(h.home, homePanelsFile))
	var saved HomePanels
	if json.Unmarshal(b, &saved) != nil || len(saved.Tasks) != 3 {
		t.Fatalf("home-panels.json: %s", b)
	}

	// the scheduler fills Home panels without a result right away; refresh may meet such a run
	refresh := func(id string) (*PanelState, error) {
		st, err := h.e.tasks.refreshPanel(id)
		for i := 0; err == nil && st.Running && i < 100; i++ {
			time.Sleep(50 * time.Millisecond)
			for _, p := range h.e.tasks.panelList() {
				if p.ID == id {
					cp := p
					st = &cp
				}
			}
		}
		return st, err
	}
	st, err := refresh(TaskPanelPrefix + gen)
	if err != nil || st.Error != "" || st.Title != "流媒体" || st.Content != "Netflix: 解锁\nYouTube & Premium: 香港" {
		t.Fatalf("generic panel: %+v %v", st, err)
	}
	st, err = refresh(TaskPanelPrefix + inter)
	if err != nil || st.Error != "" || st.Content != "节点："+node || st.Icon != "hand.tap" {
		t.Fatalf("interaction panel: %+v %v", st, err)
	}
	if hist := h.e.tasks.historyFor(inter); len(hist) != 0 {
		t.Fatalf("panel runs must not enter the task log: %+v", hist)
	}

	// cache file holds all three (the Surge panel was filled by the scheduler), and a fresh engine start seeds them (last result while reconnecting)
	if _, err := refresh(surge); err != nil { // settles the scheduler's first fill of the Surge panel
		t.Fatal(err)
	}
	var cache []PanelState
	b, _ = os.ReadFile(filepath.Join(h.home, panelCacheFile))
	if json.Unmarshal(b, &cache) != nil || len(cache) != 3 {
		t.Fatalf("panel-cache.json: %s", b)
	}
	nt := newTasker(h.e)
	nt.mu.Lock()
	nt.tasks = append([]*Task(nil), build().Tasks...)
	nt.loadHomeLocked()
	nt.base = build().Panels
	nt.panels = nt.withTaskPanelsLocked(nt.base)
	nt.syncPanelStatesLocked()
	got := nt.pstates[TaskPanelPrefix+inter]
	nt.mu.Unlock()
	if got == nil || got.Content != "节点："+node || got.Updated == 0 {
		t.Fatalf("seed from cache: %+v", got)
	}

	// scheduling: Home panels refresh in the background (floor), others only while viewed
	now := time.Now()
	h.e.tasks.mu.Lock()
	h.e.tasks.viewed = time.Time{}
	h.e.tasks.pstates[surge].Updated = 0
	due := h.e.tasks.duePanelsLocked(now, nil)
	h.e.tasks.mu.Unlock()
	if !has(due, surge) {
		t.Fatalf("home panel without a result should fill right away: %v", due)
	}
	h.e.tasks.mu.Lock()
	h.e.tasks.pstates[surge].Updated = float64(now.Add(-11 * time.Minute).Unix())
	h.e.tasks.pstates[TaskPanelPrefix+gen].Updated = float64(now.Add(-10 * time.Minute).Unix())
	due = h.e.tasks.duePanelsLocked(now, nil)
	h.e.tasks.mu.Unlock()
	if !has(due, surge) || has(due, TaskPanelPrefix+gen) {
		t.Fatalf("background due: %v", due)
	}
	// hidden from Home → background refresh stops
	h.e.tasks.setHome(HomePanels{Visible: []string{TaskPanelPrefix + gen}, Tasks: []HomePanelPin{{ID: gen, Interval: 1800}}})
	h.e.tasks.mu.Lock()
	h.e.tasks.viewed = time.Time{}
	if len(h.e.tasks.panels) != 2 {
		t.Errorf("unpinned task panel should be removed: %d", len(h.e.tasks.panels))
	}
	h.e.tasks.pstates[surge].Updated = float64(now.Add(-time.Hour).Unix())
	due = h.e.tasks.duePanelsLocked(now, nil)
	h.e.tasks.mu.Unlock()
	if has(due, surge) {
		t.Fatalf("panel not on Home refreshed in background: %v", due)
	}
	// reload keeps pinned task panels and their output
	h.e.Reload(cfg, build())
	for _, p := range h.e.tasks.panelList() {
		if p.ID == TaskPanelPrefix+gen && p.Content == "" {
			t.Fatalf("reload lost output: %+v", p)
		}
	}
}

func TestNormalizePanelResult(t *testing.T) {
	if m := normalizePanelResult(map[string]any{"title": "a", "content": "x", "message": "y"}); m["content"] != "x" {
		t.Error(m)
	}
	if m := normalizePanelResult(map[string]any{"message": "y"}); m["content"] != "y" {
		t.Error(m)
	}
	if m := normalizePanelResult(map[string]any{"htmlMessage": "<div>a</div><div>b &lt;c&gt;</div>"}); m["content"] != "a\nb <c>" {
		t.Errorf("%q", m["content"])
	}
	if normalizePanelResult(nil) != nil {
		t.Error("nil")
	}
}

func has(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
