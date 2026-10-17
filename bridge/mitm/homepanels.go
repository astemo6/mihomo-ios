package mitm

// feat/panels: script panels on Home.
//
//   - home-panels.json (written by the app, App Group): which panels are on Home and visible, and which
//     QX / Surge generic or interaction scripts are pinned as panels (with their own refresh interval and,
//     for interaction scripts, the node passed as $environment.params). Pinned scripts become extra panels
//     with the id "task-<task id>", so they share one model (list / refresh / cache) with [Panel] entries.
//   - panel-cache.json (written by the engine): the last result of every panel that ran, so Home can show
//     the last result and its time while disconnected, and a reconnect starts from it.
//   - Panels visible on Home refresh on their update-interval while connected even when the app is not in
//     the foreground (at most every homeBackgroundFloor then); other panels only while the app shows them.

import (
	"fmt"
	"html"
	"io"
	"regexp"
	"strings"
	"time"

	"encoding/json"

	http "github.com/metacubex/http"

	"github.com/metacubex/chi"
)

const (
	homePanelsFile  = "home-panels.json"
	panelCacheFile  = "panel-cache.json"
	TaskPanelPrefix = "task-"

	// homeBackgroundFloor: the shortest refresh interval for a Home panel while the app is not showing it.
	homeBackgroundFloor = 5 * time.Minute
)

// HomePanelPin pins a generic / interaction script as a panel.
type HomePanelPin struct {
	ID       string  `json:"id"`                 // task id
	Interval int     `json:"interval,omitempty"` // seconds; 0 = on open / manual only
	Params   *string `json:"params,omitempty"`   // interaction scripts: $environment.params
}

// HomePanels is the app's Home panel configuration.
type HomePanels struct {
	Visible []string       `json:"visible"` // panel ids shown on Home (pinned and not hidden), in order
	Tasks   []HomePanelPin `json:"tasks"`
}

func (t *tasker) loadHomeLocked() {
	h := HomePanels{}
	readJSONFile(t.path(homePanelsFile), &h)
	t.home = h
}

// homeVisibleLocked reports whether the panel is shown on Home. t.mu held.
func (t *tasker) homeVisibleLocked(id string) bool {
	for _, v := range t.home.Visible {
		if v == id {
			return true
		}
	}
	return false
}

// withTaskPanelsLocked returns base plus one panel per pinned generic / interaction script. t.mu held.
func (t *tasker) withTaskPanelsLocked(base []*Panel) []*Panel {
	out := append([]*Panel(nil), base...)
	seen := map[string]bool{}
	for _, pin := range t.home.Tasks {
		if seen[pin.ID] {
			continue
		}
		seen[pin.ID] = true
		for _, tk := range t.tasks {
			if tk.ID != pin.ID || (tk.Kind != TaskGeneric && tk.Kind != TaskInteraction) {
				continue
			}
			icon := "play.rectangle"
			if tk.Kind == TaskInteraction {
				icon = "hand.tap"
			}
			format := tk.Format
			if format == "" {
				format = "surge"
			}
			out = append(out, &Panel{ID: TaskPanelPrefix + tk.ID, Name: tk.Script.Name, Title: tk.Script.Name, Icon: icon,
				Script: tk.Script.Name, Interval: max(pin.Interval, 0), Source: tk.Source, Format: format, TaskID: tk.ID})
			break
		}
	}
	return out
}

// syncPanelStatesLocked rebuilds pstates for t.panels: keeps script output across reloads, and seeds
// panels seen for the first time from panel-cache.json. t.mu held.
func (t *tasker) syncPanelStatesLocked() {
	if t.cache == nil {
		t.cache = map[string]PanelState{}
		var l []PanelState
		readJSONFile(t.path(panelCacheFile), &l)
		for _, c := range l {
			if c.Panel != nil && c.ID != "" {
				t.cache[c.ID] = c
			}
		}
	}
	ps := map[string]*PanelState{}
	for _, p := range t.panels {
		st := t.pstates[p.ID]
		cp := *p
		if st == nil {
			st = &PanelState{}
			if c, ok := t.cache[p.ID]; ok && p.Script != "" {
				cp.Title, cp.Content, cp.Icon, cp.IconColor, cp.Style = c.Title, c.Content, c.Icon, c.IconColor, c.Style
				st.Updated, st.Error, st.BGColor = c.Updated, c.Error, c.BGColor
			}
		} else if old := st.Panel; old != nil && p.Script != "" {
			// keep script output, refresh the static definition
			cp.Title, cp.Content, cp.Icon, cp.IconColor, cp.Style = old.Title, old.Content, old.Icon, old.IconColor, old.Style
		}
		st.Panel = &cp
		ps[p.ID] = st
	}
	t.pstates = ps
}

// saveCacheLocked writes the last result of every current panel that ran. t.mu held.
func (t *tasker) saveCacheLocked() {
	l := make([]PanelState, 0, len(t.panels))
	for _, p := range t.panels {
		st := t.pstates[p.ID]
		if st == nil || st.Updated == 0 || st.Panel == nil {
			continue
		}
		cp := *st
		pp := *st.Panel
		cp.Panel, cp.Running = &pp, false
		l = append(l, cp)
		if t.cache != nil {
			t.cache[p.ID] = cp
		}
	}
	writeJSONFile(t.path(panelCacheFile), l)
}

// panelTaskLocked finds the script that fills p: the pinned task itself, else by script name (same
// module first). t.mu held.
func (t *tasker) panelTaskLocked(p *Panel) *Task {
	var tk *Task
	for _, x := range t.tasks {
		if p.TaskID != "" {
			if x.ID == p.TaskID {
				return x
			}
			continue
		}
		if x.Script.Name == p.Script && (x.Source == p.Source || tk == nil) {
			tk = x
		}
	}
	return tk
}

// panelParamsLocked returns $environment.params for a pinned interaction script. t.mu held.
func (t *tasker) panelParamsLocked(p *Panel) *string {
	if p.TaskID == "" {
		return nil
	}
	for _, pin := range t.home.Tasks {
		if pin.ID == p.TaskID {
			return pin.Params
		}
	}
	return nil
}

var htmlTagRe = regexp.MustCompile(`(?is)<br\s*/?>|</p>|</div>|<[^>]+>`)

// normalizePanelResult maps QX UI-script results onto panel keys: message / htmlMessage → content
// (tags stripped, <br> → line break) when content is missing.
func normalizePanelResult(out map[string]any) map[string]any {
	if out == nil {
		return nil
	}
	if v, ok := out["content"]; ok && v != nil {
		return out
	}
	m := map[string]any{}
	for k, v := range out {
		m[k] = v
	}
	if v, ok := out["message"]; ok && v != nil {
		m["content"] = fmt.Sprint(v)
	} else if v, ok := out["htmlMessage"]; ok && v != nil {
		s := htmlTagRe.ReplaceAllStringFunc(fmt.Sprint(v), func(tag string) string {
			l := strings.ToLower(tag)
			if strings.HasPrefix(l, "<br") || l == "</p>" || l == "</div>" {
				return "\n"
			}
			return ""
		})
		lines := strings.Split(html.UnescapeString(s), "\n")
		keep := lines[:0]
		for _, ln := range lines {
			if ln = strings.TrimSpace(ln); ln != "" {
				keep = append(keep, ln)
			}
		}
		m["content"] = strings.Join(keep, "\n")
	}
	return m
}

// setHome applies the app's Home configuration (and saves it) without reparsing modules.
func (t *tasker) setHome(h HomePanels) []PanelState {
	t.mu.Lock()
	t.home = h
	t.panels = t.withTaskPanelsLocked(t.base)
	t.syncPanelStatesLocked()
	start := t.stop == nil && len(t.panels) > 0
	if start {
		t.stop = make(chan struct{})
	}
	stop := t.stop
	t.mu.Unlock()
	writeJSONFile(t.path(homePanelsFile), h)
	if start {
		go t.loop(stop)
	}
	select {
	case t.wake <- struct{}{}:
	default:
	}
	return t.panelList()
}

func (t *tasker) getHome() HomePanels {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := t.home
	if h.Visible == nil {
		h.Visible = []string{}
	}
	if h.Tasks == nil {
		h.Tasks = []HomePanelPin{}
	}
	return h
}

// homePanelRoutes: GET / PUT /mitm/panels-home.
func homePanelRoutes(r chi.Router, get func() *Engine) {
	r.Get("/panels-home", func(w http.ResponseWriter, req *http.Request) {
		e := get()
		if e == nil {
			writeJSON(w, HomePanels{Visible: []string{}, Tasks: []HomePanelPin{}})
			return
		}
		writeJSON(w, e.tasks.getHome())
	})
	r.Put("/panels-home", func(w http.ResponseWriter, req *http.Request) {
		e := get()
		if e == nil {
			http.Error(w, "engine not running", http.StatusServiceUnavailable)
			return
		}
		var h HomePanels
		if err := json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&h); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, e.tasks.setHome(h))
	})
}
