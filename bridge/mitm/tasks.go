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
	// TaskInteraction: QX event-interaction (v0.11) — a UI script run on a chosen policy / node with
	// $environment.params = its name.
	TaskInteraction = "interaction"
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
	// v0.11: QX img-url, and lines written with enabled=false (kept in the list, switched off; the app's
	// task-prefs.json can turn them on).
	Icon           string `json:"icon,omitempty"`
	DisabledByLine bool   `json:"disabledByLine,omitempty"`
	cron           *Cron
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
	Format    string `json:"format"`           // surge / stash
	TaskID    string `json:"taskId,omitempty"` // feat/panels: a generic / interaction script pinned as a panel
	// v0.17: set when the app's interval override replaced the module's (DefaultInterval = module value).
	DefaultInterval    int  `json:"defaultInterval,omitempty"`
	IntervalOverridden bool `json:"intervalOverridden,omitempty"`
}

func stableID(parts ...string) string {
	h := sha1.Sum([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:6])
}

var (
	loonCronRe = regexp.MustCompile(`(?i)^cron\s+"([^"]+)"\s+(script-path\s*=.*)$`)
	// v0.19.9: `cron {cron} script-path=…` with an [Argument] input leaves the expression unquoted after
	// substitution (Sub-Store's official Loon plugin).
	loonCronBareRe = regexp.MustCompile(`(?i)^cron\s+((?:\S+\s+){4,5}\S+?)\s+(script-path\s*=.*)$`)
	loonEventRe    = regexp.MustCompile(`(?i)^(network-changed|generic)\s+(script-path\s*=.*)$`)
	qxEventRe      = regexp.MustCompile(`(?i)^event-(network|interaction)\s+(\S+?)\s*(,.*)?$`)
	qxCronRe       = regexp.MustCompile(`^((?:[0-9*?/,\-A-Za-z]+\s+){4,5}[0-9*?/,\-A-Za-z]+)\s+(\S+?)\s*(,.*)?$`)
	cronFieldOnly  = regexp.MustCompile(`^[0-9*?/,\-]+$`)
)

func (rs *Ruleset) addTask(kind, cron, event string, sc *Script, source, line, format string) *Task {
	if sc == nil || sc.Path == "" {
		rs.Errors = append(rs.Errors, "脚本缺少 script-path："+clip(line, 120))
		return nil
	}
	t := &Task{Kind: kind, Cron: cron, Event: event, Script: sc, Source: source, Line: line, Format: format}
	switch kind {
	case TaskCron:
		c, err := ParseCron(cron)
		if err != nil {
			rs.Errors = append(rs.Errors, err.Error()+"："+clip(line, 120))
			return nil
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
			return nil
		}
		t.Event = event
		sc.Type = "event"
	case TaskInteraction:
		t.Event = "interaction"
		sc.Type = "generic"
	default:
		sc.Type = "generic"
	}
	if sc.Timeout <= 0 {
		sc.Timeout = 30
	}
	t.ID = stableID(source, kind, sc.Name, sc.Path, t.Cron)
	for _, o := range rs.Tasks {
		if o.ID == t.ID {
			return o
		}
	}
	rs.Tasks = append(rs.Tasks, t)
	return t
}

// withLineOpts records img-url and enabled=false on a parsed task.
func withLineOpts(t *Task, p map[string]string) {
	if t == nil {
		return
	}
	if ic := p["img-url"]; strings.HasPrefix(ic, "http://") || strings.HasPrefix(ic, "https://") {
		t.Icon = ic
	}
	t.DisabledByLine = disabledByParam(p)
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
		sc := scriptFromParams(m[1], p)
		cron := p["cronexp"]
		if cron == "" {
			cron = p["cron"]
		}
		withLineOpts(rs.addTask(typ, cron, p["event-name"], sc, source, line, "surge"), p)
		return true
	}
	// Loon
	m := loonCronRe.FindStringSubmatch(line)
	if m == nil {
		if b := loonCronBareRe.FindStringSubmatch(line); b != nil && cronLooksValid(b[1]) {
			m = b
		}
	}
	if m != nil {
		p := splitParams(m[2], scriptKeys)
		withLineOpts(rs.addTask(TaskCron, m[1], "", scriptFromParams(p["tag"], p), source, line, "loon"), p)
		return true
	}
	if m := loonEventRe.FindStringSubmatch(line); m != nil {
		p := splitParams(m[2], scriptKeys)
		kind := TaskGeneric
		if strings.EqualFold(m[1], "network-changed") {
			kind = TaskEvent
		}
		withLineOpts(rs.addTask(kind, "", "network-changed", scriptFromParams(p["tag"], p), source, line, "loon"), p)
		return true
	}
	// Quantumult X task_local
	if m := qxEventRe.FindStringSubmatch(line); m != nil {
		p := splitParams(strings.TrimPrefix(m[3], ","), scriptKeys)
		p["script-path"] = m[2]
		kind := TaskInteraction
		if strings.EqualFold(m[1], "network") {
			kind = TaskEvent
		}
		withLineOpts(rs.addTask(kind, "", "network-changed", scriptFromParams(p["tag"], p), source, line, "qx"), p)
		return true
	}
	if section == "task_local" || strings.HasPrefix(low, "0") || strings.HasPrefix(low, "*") || (len(low) > 0 && low[0] >= '0' && low[0] <= '9') {
		if m := qxCronRe.FindStringSubmatch(line); m != nil && cronLooksValid(m[1]) && (strings.Contains(m[2], ".js") || strings.Contains(m[2], "://") || section == "task_local") {
			p := splitParams(strings.TrimPrefix(m[3], ","), scriptKeys)
			p["script-path"] = m[2]
			withLineOpts(rs.addTask(TaskCron, m[1], "", scriptFromParams(p["tag"], p), source, line, "qx"), p)
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
	Enabled    bool    `json:"enabled"` // v0.11: scheduled / event runs allowed (prefs + enabled=)
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
	prefs   TaskPrefs
	history map[string][]RunRecord
	// feat/panels (homepanels.go)
	base  []*Panel              // panels from modules; t.panels = base + pinned scripts
	home  HomePanels            // home-panels.json
	cache map[string]PanelState // panel-cache.json
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
	t.loadPersistedLocked()
	t.tasks = append([]*Task(nil), rs.Tasks...)
	t.saveListLocked()
	t.loadHomeLocked()
	t.base = append([]*Panel(nil), rs.Panels...)
	t.panels = t.withTaskPanelsLocked(t.base)
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
	t.syncPanelStatesLocked()
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
			if !t.enabledLocked(tk) {
				// switched off: keep the next time moving so turning it back on doesn't fire a backlog
				if at := time.Unix(int64(st.NextRun), 0); !at.After(now) {
					if n := tk.cron.Next(now); !n.IsZero() {
						st.NextRun = float64(n.Unix())
					}
				}
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
			go t.runAs(tk, nil, "schedule")
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
		st := t.pstates[p.ID]
		if p.Script == "" || st == nil || st.Running {
			continue
		}
		// feat/panels: panels shown on Home refresh while connected (first fill right after connect,
		// then on their interval, at least homeBackgroundFloor apart while the app is not showing panels).
		home := t.homeVisibleLocked(p.ID)
		if p.Interval <= 0 {
			if home && st.Updated == 0 {
				due = append(due, p.ID)
			}
			continue
		}
		if st.Updated == 0 && !home {
			continue // first fill happens when the app opens the panels page
		}
		viewed := now.Sub(t.viewed) <= panelVisibleWindow(p.Interval)
		if !viewed && !home {
			continue // nobody is looking: no script runs (battery, memory); markViewed wakes us
		}
		every := time.Duration(max(p.Interval, 60)) * time.Second
		if !viewed {
			every = max(every, homeBackgroundFloor)
		}
		at := time.Unix(int64(st.Updated), 0).Add(every)
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

// run executes a task now (manual). extra installs additional globals ($event / $network).
func (t *tasker) run(tk *Task, extra map[string]any) (map[string]any, error) {
	return t.runAs(tk, extra, "manual")
}

// runAs executes a task and records the run in its log under trigger.
func (t *tasker) runAs(tk *Task, extra map[string]any, trigger string) (map[string]any, error) {
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
	seq := t.e.Logs.Seq()
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
	rec := RunRecord{Time: float64(start.Unix()), OK: st.LastOK, Duration: st.Duration, Trigger: trigger, Result: st.LastResult}
	if err != nil {
		t.e.Logs.Add(tk.Script.Name, "error", err.Error())
	} else {
		t.e.Logs.Add(tk.Script.Name, "info", fmt.Sprintf("运行结束，用时 %d ms", st.Duration))
	}
	rec.Logs = t.runLogs(tk.Script.Name, seq)
	t.record(tk, rec)
	return out, err
}

func kindLabel(k string) string {
	switch k {
	case TaskCron:
		return "定时"
	case TaskEvent:
		return "事件"
	case TaskInteraction:
		return "交互"
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
		if tk.Kind == TaskEvent && t.enabledLocked(tk) {
			list = append(list, tk)
		}
	}
	t.mu.Unlock()
	if same {
		return 0
	}
	for _, tk := range list {
		go t.runAs(tk, map[string]any{"$event": map[string]any{"name": "network-changed", "data": info}}, "event")
	}
	return len(list)
}

func (t *tasker) list() []TaskState {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]TaskState, 0, len(t.tasks))
	for _, tk := range t.tasks {
		if st := t.states[tk.ID]; st != nil {
			cp := *st
			cp.Enabled = t.enabledLocked(tk)
			out = append(out, cp)
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
	tk := t.panelTaskLocked(p)
	params := t.panelParamsLocked(p)
	t.mu.Unlock()
	var out map[string]any
	var err error
	if tk == nil {
		err = fmt.Errorf("找不到脚本 %s", p.Script)
	} else {
		pin := map[string]any{"title": p.Title, "content": p.Content, "icon": p.Icon, "icon-color": p.IconColor, "style": p.Style}
		extra := map[string]any{"$input": map[string]any{"purpose": "panel", "position": "policy-selection"}, "$panel": pin}
		if params != nil {
			extra["$params"] = *params
		}
		out, err = t.runAs(tk, extra, "panel")
		out = normalizePanelResult(out)
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
	t.saveCacheLocked()
	cp := *st
	return &cp, nil
}

// ---- RunTask on the script runner ----

// RunTask executes a cron / event / generic script (no $request / $response). Returns the object
// passed to $done (if any).
func (s *ScriptRunner) RunTask(tk *Task, network map[string]any, extra map[string]any) (map[string]any, error) {
	rc, err := s.execute(nil, tk.Script, nil, nil, s.taskSem, false, 300*time.Second, 30*time.Second, func(rc *runCtx) {
		rt := rc.rt
		if network != nil {
			_ = rt.Set("$network", network)
		} else {
			_ = rt.Set("$network", map[string]any{})
		}
		for k, v := range extra {
			if k == "$params" {
				// QX event-interaction: $environment.params = the chosen policy / node.
				if env, ok := rt.Get("$environment").(*goja.Object); ok && env != nil {
					_ = env.Set("params", v)
				}
				continue
			}
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
