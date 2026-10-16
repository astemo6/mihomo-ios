package mitm

// Non-HTTP scripts: cron (scheduled while the tunnel runs), event (network-changed) and generic
// (run on demand / panels). One model for every source syntax:
//
//	Surge   [Script]  name = type=cron,cronexp="0 8 * * *",script-path=…   type=event,event-name=network-changed   type=generic
//	        [Panel]   name = script-name=…,update-interval=60   |   title=…,content=…,style=info,icon=…
//	Loon    [Script]  cron "0 8 * * *" script-path=…,tag=…   network-changed script-path=…   generic script-path=…
//	QX      [task_local]  0 8 * * * https://…/a.js, tag=…, enabled=true   event-network …   event-interaction …
//	Stash   cron.script[] (name/cron/timeout/argument) + script-providers;  tiles[] (name/interval/title/content/icon/backgroundColor)

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
)

// Task kinds.
const (
	TaskCron    = "cron"
	TaskEvent   = "event"
	TaskGeneric = "generic"
)

// Task is a cron / event / generic script.
type Task struct {
	ID     string  `json:"id"`
	Kind   string  `json:"kind"`
	Cron   string  `json:"cron,omitempty"`
	Event  string  `json:"event,omitempty"` // network-changed
	Script *Script `json:"script"`
	Source string  `json:"source"`
	Line   string  `json:"line"`
	Format string  `json:"format,omitempty"` // surge / loon / qx / stash
	cron   *Cron
}

// Panel is a Surge [Panel] entry or a Stash tile.
type Panel struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Title     string `json:"title,omitempty"`
	Content   string `json:"content,omitempty"`
	Style     string `json:"style,omitempty"` // info / good / alert / error (Surge)
	Icon      string `json:"icon,omitempty"`  // SF Symbol name
	IconColor string `json:"iconColor,omitempty"`
	Script    string `json:"script,omitempty"`   // generic task name that fills it
	Interval  int    `json:"interval,omitempty"` // seconds
	Source    string `json:"source"`
	Format    string `json:"format"` // surge / stash
}

func stableID(parts ...string) string {
	h := sha1.Sum([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:6])
}

var (
	loonCronRe    = regexp.MustCompile(`(?i)^cron\s+"([^"]+)"\s+(script-path\s*=.*)$`)
	loonEventRe   = regexp.MustCompile(`(?i)^(network-changed|generic)\s+(script-path\s*=.*)$`)
	qxEventRe     = regexp.MustCompile(`(?i)^event-(network|interaction)\s+(\S+?)\s*(,.*)?$`)
	qxCronRe      = regexp.MustCompile(`^((?:[0-9*?/,\-A-Za-z]+\s+){4,5}[0-9*?/,\-A-Za-z]+)\s+(\S+?)\s*(,.*)?$`)
	cronFieldOnly = regexp.MustCompile(`^[0-9*?/,\-]+$`)
)

func (rs *Ruleset) addTask(kind, cron, event string, sc *Script, source, line, format string) {
	if sc == nil || sc.Path == "" {
		rs.Errors = append(rs.Errors, "脚本缺少 script-path："+clip(line, 120))
		return
	}
	t := &Task{Kind: kind, Cron: cron, Event: event, Script: sc, Source: source, Line: line, Format: format}
	switch kind {
	case TaskCron:
		c, err := ParseCron(cron)
		if err != nil {
			rs.Errors = append(rs.Errors, err.Error()+"："+clip(line, 120))
			return
		}
		t.cron, t.Cron = c, c.String()
		sc.Type = "cron"
		if sc.Cron == "" {
			sc.Cron = cron
		}
	case TaskEvent:
		if event == "" {
			event = "network-changed"
		}
		if event != "network-changed" {
			rs.Unsupported = append(rs.Unsupported, line)
			return
		}
		t.Event = event
		sc.Type = "event"
	default:
		sc.Type = "generic"
	}
	if sc.Timeout <= 0 {
		sc.Timeout = 30
	}
	t.ID = stableID(source, kind, sc.Name, sc.Path, t.Cron)
	for _, o := range rs.Tasks {
		if o.ID == t.ID {
			return
		}
	}
	rs.Tasks = append(rs.Tasks, t)
}

func scriptFromParams(name string, p map[string]string) *Script {
	sc := &Script{Name: strings.TrimSpace(name), Path: p["script-path"], Timeout: atoiDef(p["timeout"], 0),
		UpdateInterval: atoiDef(p["script-update-interval"], 86400)}
	if a, ok := p["argument"]; ok {
		sc.Argument, sc.HasArgument = a, true
	}
	if sc.Name == "" {
		sc.Name = p["tag"]
	}
	if sc.Name == "" {
		sc.Name = scriptNameFromPath(sc.Path)
	}
	return sc
}

func disabledByParam(p map[string]string) bool {
	for _, k := range []string{"enable", "enabled"} {
		if v, ok := p[k]; ok && !truthy(v) {
			return true
		}
	}
	return false
}

// parseTaskLine handles the non-HTTP script syntaxes. Returns true when the line was consumed.
func (rs *Ruleset) parseTaskLine(line, section, source string) bool {
	low := strings.ToLower(line)
	// Surge: name = type=cron|event|generic,…
	if m := surgeScriptRe.FindStringSubmatch(line); m != nil {
		p := splitParams(m[2], scriptKeys)
		typ := strings.ToLower(strings.TrimSpace(p["type"]))
		switch typ {
		case "cron", "event", "generic":
		case "dns", "rule":
			rs.Unsupported = append(rs.Unsupported, line)
			return true
		default:
			return false
		}
		if disabledByParam(p) {
			return true
		}
		sc := scriptFromParams(m[1], p)
		cron := p["cronexp"]
		if cron == "" {
			cron = p["cron"]
		}
		rs.addTask(typ, cron, p["event-name"], sc, source, line, "surge")
		return true
	}
	// Loon
	if m := loonCronRe.FindStringSubmatch(line); m != nil {
		p := splitParams(m[2], scriptKeys)
		if !disabledByParam(p) {
			rs.addTask(TaskCron, m[1], "", scriptFromParams(p["tag"], p), source, line, "loon")
		}
		return true
	}
	if m := loonEventRe.FindStringSubmatch(line); m != nil {
		p := splitParams(m[2], scriptKeys)
		if !disabledByParam(p) {
			kind := TaskGeneric
			if strings.EqualFold(m[1], "network-changed") {
				kind = TaskEvent
			}
			rs.addTask(kind, "", "network-changed", scriptFromParams(p["tag"], p), source, line, "loon")
		}
		return true
	}
	// Quantumult X task_local
	if m := qxEventRe.FindStringSubmatch(line); m != nil {
		p := splitParams(strings.TrimPrefix(m[3], ","), scriptKeys)
		p["script-path"] = m[2]
		if !disabledByParam(p) {
			kind := TaskGeneric
			if strings.EqualFold(m[1], "network") {
				kind = TaskEvent
			}
			rs.addTask(kind, "", "network-changed", scriptFromParams(p["tag"], p), source, line, "qx")
		}
		return true
	}
	if section == "task_local" || strings.HasPrefix(low, "0") || strings.HasPrefix(low, "*") || (len(low) > 0 && low[0] >= '0' && low[0] <= '9') {
		if m := qxCronRe.FindStringSubmatch(line); m != nil && cronLooksValid(m[1]) && (strings.Contains(m[2], ".js") || strings.Contains(m[2], "://") || section == "task_local") {
			p := splitParams(strings.TrimPrefix(m[3], ","), scriptKeys)
			p["script-path"] = m[2]
			if !disabledByParam(p) {
				rs.addTask(TaskCron, m[1], "", scriptFromParams(p["tag"], p), source, line, "qx")
			}
			return true
		}
	}
	return false
}

func cronLooksValid(expr string) bool {
	f := strings.Fields(expr)
	if len(f) < 5 || len(f) > 6 {
		return false
	}
	// at least the first field must be numeric-ish (avoid swallowing ordinary text)
	if !cronFieldOnly.MatchString(f[0]) {
		return false
	}
	_, err := ParseCron(expr)
	return err == nil
}

// parsePanelLine handles a Surge [Panel] line.
func (rs *Ruleset) parsePanelLine(line, source string) {
	name, rest, ok := strings.Cut(line, "=")
	if !ok {
		return
	}
	p := splitParams(rest, []string{"script-name", "update-interval", "title", "content", "style", "icon", "icon-color"})
	pn := &Panel{Name: strings.TrimSpace(name), Title: p["title"], Content: unescapeNL(p["content"]), Style: p["style"], Icon: p["icon"],
		IconColor: p["icon-color"], Script: p["script-name"], Interval: atoiDef(p["update-interval"], 0), Source: source, Format: "surge"}
	if pn.Title == "" {
		pn.Title = pn.Name
	}
	pn.ID = stableID(source, "panel", pn.Name)
	rs.Panels = append(rs.Panels, pn)
}

func unescapeNL(s string) string { return strings.ReplaceAll(s, `\n`, "\n") }

// ---------------- scheduler / runner ----------------

// TaskState is what GET /mitm/tasks returns per task.
type TaskState struct {
	*Task
	NextRun    float64 `json:"nextRun,omitempty"` // unix seconds
	LastRun    float64 `json:"lastRun,omitempty"`
	LastOK     bool    `json:"lastOK"`
	LastResult string  `json:"lastResult,omitempty"`
	Duration   int64   `json:"duration,omitempty"` // ms
	Running    bool    `json:"running"`
}

// PanelState is a panel with its latest content.
type PanelState struct {
	*Panel
	Updated float64 `json:"updated,omitempty"`
	Error   string  `json:"error,omitempty"`
	Running bool    `json:"running"`
	BGColor string  `json:"backgroundColor,omitempty"`
}

type tasker struct {
	e       *Engine
	mu      sync.Mutex
	tasks   []*Task
	panels  []*Panel
	states  map[string]*TaskState
	pstates map[string]*PanelState
	stop    chan struct{}
	wake    chan struct{}
	network map[string]any
	lastNet string
	now     func() time.Time
	viewed  time.Time // last time the app showed panels (GET /mitm/panels)
}

// panelVisibleWindow: auto-refresh keeps running this long after the app last showed the panels
// (at least two intervals). The panels page polls while open; in the background nothing runs.
func panelVisibleWindow(interval int) time.Duration {
	return max(3*time.Minute, 2*time.Duration(interval)*time.Second)
}

// markViewed records that the app is showing panels and wakes the scheduler if refreshes had paused.
func (t *tasker) markViewed() {
	t.mu.Lock()
	paused := t.now().Sub(t.viewed) > 3*time.Minute
	t.viewed = t.now()
	t.mu.Unlock()
	if paused {
		select {
		case t.wake <- struct{}{}:
		default:
		}
	}
}

func newTasker(e *Engine) *tasker {
	return &tasker{e: e, states: map[string]*TaskState{}, pstates: map[string]*PanelState{}, wake: make(chan struct{}, 1), now: time.Now}
}

func (t *tasker) reload(rs *Ruleset) {
	t.mu.Lock()
	t.tasks = append([]*Task(nil), rs.Tasks...)
	t.panels = append([]*Panel(nil), rs.Panels...)
	ns := map[string]*TaskState{}
	for _, tk := range t.tasks {
		st := t.states[tk.ID]
		if st == nil {
			st = &TaskState{}
		}
		st.Task = tk
		st.NextRun = 0
		if tk.cron != nil {
			if n := tk.cron.Next(t.now()); !n.IsZero() {
				st.NextRun = float64(n.Unix())
			}
		}
		ns[tk.ID] = st
	}
	t.states = ns
	ps := map[string]*PanelState{}
	for _, p := range t.panels {
		st := t.pstates[p.ID]
		if st == nil {
			st = &PanelState{}
			cp := *p
			st.Panel = &cp
		} else {
			// keep script output, refresh the static definition
			old := st.Panel
			cp := *p
			if old != nil && p.Script != "" {
				cp.Title, cp.Content, cp.Icon, cp.IconColor, cp.Style = old.Title, old.Content, old.Icon, old.IconColor, old.Style
			}
			st.Panel = &cp
		}
		ps[p.ID] = st
	}
	t.pstates = ps
	start := t.stop == nil && (len(t.tasks) > 0 || len(t.panels) > 0)
	if start {
		t.stop = make(chan struct{})
	}
	stop := t.stop
	t.mu.Unlock()
	if start {
		go t.loop(stop)
	}
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

func (t *tasker) shutdown() {
	t.mu.Lock()
	if t.stop != nil {
		close(t.stop)
		t.stop = nil
	}
	t.mu.Unlock()
}

func (t *tasker) loop(stop chan struct{}) {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		now := t.now()
		next := now.Add(time.Hour)
		var due []*Task
		t.mu.Lock()
		for _, tk := range t.tasks {
			st := t.states[tk.ID]
			if tk.cron == nil || st == nil || st.NextRun == 0 {
				continue
			}
			at := time.Unix(int64(st.NextRun), 0)
			if !at.After(now) {
				due = append(due, tk)
				if n := tk.cron.Next(now); !n.IsZero() {
					st.NextRun = float64(n.Unix())
					at = n
				} else {
					st.NextRun = 0
					continue
				}
			}
			if at.Before(next) {
				next = at
			}
		}
		duePanels := t.duePanelsLocked(now, &next)
		t.mu.Unlock()
		for _, tk := range due {
			go t.run(tk, nil)
		}
		for _, id := range duePanels {
			go t.refreshPanel(id)
		}
		d := next.Sub(t.now())
		if d < time.Second {
			d = time.Second
		}
		timer.Reset(d)
		select {
		case <-stop:
			return
		case <-t.wake:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
		}
	}
}

// duePanelsLocked returns auto-refreshing panels (update-interval / Stash interval) that are due now,
// and pulls next forward to the earliest future one. Only while the app is showing panels. t.mu held.
func (t *tasker) duePanelsLocked(now time.Time, next *time.Time) []string {
	var due []string
	for _, p := range t.panels {
		if p.Script == "" || p.Interval <= 0 {
			continue
		}
		st := t.pstates[p.ID]
		if st == nil || st.Running || st.Updated == 0 {
			continue // first fill happens when the app opens the panels page
		}
		if now.Sub(t.viewed) > panelVisibleWindow(p.Interval) {
			continue // nobody is looking: no script runs (battery, memory); markViewed wakes us
		}
		at := time.Unix(int64(st.Updated), 0).Add(time.Duration(max(p.Interval, 60)) * time.Second)
		if !at.After(now) {
			due = append(due, p.ID)
		} else if next != nil && at.Before(*next) {
			*next = at
		}
	}
	return due
}

func (t *tasker) find(id string) *Task {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, tk := range t.tasks {
		if tk.ID == id || tk.Script.Name == id {
			return tk
		}
	}
	return nil
}

// run executes a task now. extra installs additional globals ($event / $network).
func (t *tasker) run(tk *Task, extra map[string]any) (map[string]any, error) {
	t.mu.Lock()
	st := t.states[tk.ID]
	if st == nil {
		st = &TaskState{Task: tk}
		t.states[tk.ID] = st
	}
	if st.Running {
		t.mu.Unlock()
		return nil, fmt.Errorf("%s 正在运行", tk.Script.Name)
	}
	st.Running = true
	net := t.network
	t.mu.Unlock()
	start := time.Now()
	t.e.Logs.Add(tk.Script.Name, "info", fmt.Sprintf("开始运行（%s）", kindLabel(tk.Kind)))
	out, err := t.e.scripts.RunTask(tk, net, extra)
	t.mu.Lock()
	st.Running = false
	st.LastRun = float64(start.Unix())
	st.Duration = time.Since(start).Milliseconds()
	st.LastOK = err == nil
	if err != nil {
		st.LastResult = err.Error()
	} else if out != nil {
		b, _ := json.Marshal(out)
		st.LastResult = clip(string(b), 300)
	} else {
		st.LastResult = ""
	}
	t.mu.Unlock()
	if err != nil {
		t.e.Logs.Add(tk.Script.Name, "error", err.Error())
	} else {
		t.e.Logs.Add(tk.Script.Name, "info", fmt.Sprintf("运行结束，用时 %d ms", st.Duration))
	}
	return out, err
}

func kindLabel(k string) string {
	switch k {
	case TaskCron:
		return "定时"
	case TaskEvent:
		return "事件"
	}
	return "通用"
}

// networkChanged runs every event task (debounced: same network signature within 3 s is ignored).
func (t *tasker) networkChanged(info map[string]any) int {
	b, _ := json.Marshal(info)
	t.mu.Lock()
	t.network = info
	sig := string(b)
	same := sig == t.lastNet
	t.lastNet = sig
	var list []*Task
	for _, tk := range t.tasks {
		if tk.Kind == TaskEvent {
			list = append(list, tk)
		}
	}
	t.mu.Unlock()
	if same {
		return 0
	}
	for _, tk := range list {
		go t.run(tk, map[string]any{"$event": map[string]any{"name": "network-changed", "data": info}})
	}
	return len(list)
}

func (t *tasker) list() []TaskState {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]TaskState, 0, len(t.tasks))
	for _, tk := range t.tasks {
		if st := t.states[tk.ID]; st != nil {
			out = append(out, *st)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out
}

func (t *tasker) panelList() []PanelState {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]PanelState, 0, len(t.panels))
	for _, p := range t.panels {
		if st := t.pstates[p.ID]; st != nil {
			cp := *st
			pp := *st.Panel
			cp.Panel = &pp
			out = append(out, cp)
		}
	}
	return out
}

// refreshPanel runs the panel's generic script and stores what $done returned.
func (t *tasker) refreshPanel(id string) (*PanelState, error) {
	t.mu.Lock()
	st := t.pstates[id]
	if st == nil {
		t.mu.Unlock()
		return nil, fmt.Errorf("面板不存在")
	}
	p := st.Panel
	if p.Script == "" {
		st.Updated = float64(t.now().Unix())
		cp := *st
		t.mu.Unlock()
		return &cp, nil
	}
	if st.Running {
		cp := *st
		t.mu.Unlock()
		return &cp, nil
	}
	st.Running = true
	var tk *Task
	for _, x := range t.tasks {
		if x.Script.Name == p.Script && (x.Source == p.Source || tk == nil) {
			tk = x
		}
	}
	t.mu.Unlock()
	var out map[string]any
	var err error
	if tk == nil {
		err = fmt.Errorf("找不到脚本 %s", p.Script)
	} else {
		pin := map[string]any{"title": p.Title, "content": p.Content, "icon": p.Icon, "icon-color": p.IconColor, "style": p.Style}
		out, err = t.run(tk, map[string]any{"$input": map[string]any{"purpose": "panel", "position": "policy-selection"}, "$panel": pin})
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	st.Running = false
	st.Updated = float64(t.now().Unix())
	if err != nil {
		st.Error = err.Error()
	} else {
		st.Error = ""
		np := *st.Panel
		get := func(k ...string) (string, bool) {
			for _, kk := range k {
				if v, ok := out[kk]; ok && v != nil {
					return fmt.Sprint(v), true
				}
			}
			return "", false
		}
		if v, ok := get("title"); ok {
			np.Title = v
		}
		if v, ok := get("content"); ok {
			np.Content = v
		}
		if v, ok := get("icon"); ok {
			np.Icon = v
		}
		if v, ok := get("icon-color", "iconColor"); ok {
			np.IconColor = v
		}
		if v, ok := get("style"); ok {
			np.Style = v
		}
		if v, ok := get("backgroundColor", "background-color"); ok {
			st.BGColor = v
		}
		st.Panel = &np
	}
	cp := *st
	return &cp, nil
}

// ---- RunTask on the script runner ----

// RunTask executes a cron / event / generic script (no $request / $response). Returns the object
// passed to $done (if any).
func (s *ScriptRunner) RunTask(tk *Task, network map[string]any, extra map[string]any) (map[string]any, error) {
	rc, err := s.execute(tk.Script, nil, nil, s.taskSem, 300*time.Second, 30*time.Second, func(rc *runCtx) {
		rt := rc.rt
		if network != nil {
			_ = rt.Set("$network", network)
		} else {
			_ = rt.Set("$network", map[string]any{})
		}
		for k, v := range extra {
			_ = rt.Set(k, v)
		}
	})
	if err != nil {
		return nil, err
	}
	if rc == nil || !rc.done || rc.result == nil || goja.IsUndefined(rc.result) || goja.IsNull(rc.result) {
		return nil, nil
	}
	if m, ok := rc.result.Export().(map[string]any); ok {
		return m, nil
	}
	return map[string]any{"value": rc.result.Export()}, nil
}
