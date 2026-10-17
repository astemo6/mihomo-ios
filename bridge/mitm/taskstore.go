package mitm

// v0.11 task list (QX 「HTTP 请求」 style): per-task on/off and a master switch the app owns
// (task-prefs.json), a run log per task the engine owns (task-history.json), and a snapshot of the
// parsed task list (task-list.json) so the app can show the list and its history while disconnected.
// All three are small files in the engine home (the App Group).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	taskPrefsFile   = "task-prefs.json"
	taskHistoryFile = "task-history.json"
	taskListFile    = "task-list.json"

	historyPerTask = 10
	historyLogs    = 30
)

// TaskPrefs is written by the app: Paused stops every scheduled / event run (manual runs still work);
// Enabled overrides a task's own enabled= flag.
type TaskPrefs struct {
	Paused  bool            `json:"paused"`
	Enabled map[string]bool `json:"enabled,omitempty"`
}

// RunRecord is one entry of a task's run log.
type RunRecord struct {
	Time     float64  `json:"time"`
	OK       bool     `json:"ok"`
	Duration int64    `json:"duration"` // ms
	Trigger  string   `json:"trigger"`  // schedule / event / manual / interaction / panel
	Result   string   `json:"result,omitempty"`
	Logs     []string `json:"logs,omitempty"`
}

// enabled reports whether scheduled / event runs are allowed for tk. t.mu held.
func (t *tasker) enabledLocked(tk *Task) bool {
	if t.prefs.Paused {
		return false
	}
	if v, ok := t.prefs.Enabled[tk.ID]; ok {
		return v
	}
	return !tk.DisabledByLine
}

func (t *tasker) path(name string) string {
	if t.e == nil || t.e.home == "" {
		return ""
	}
	return filepath.Join(t.e.home, name)
}

func readJSONFile(path string, v any) {
	if path == "" {
		return
	}
	if b, err := os.ReadFile(path); err == nil && len(b) < 4<<20 {
		_ = json.Unmarshal(b, v)
	}
}

func writeJSONFile(path string, v any) {
	if path == "" {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, path)
	}
}

// loadPersistedLocked reads prefs (every reload) and history (first time). t.mu held.
func (t *tasker) loadPersistedLocked() {
	p := TaskPrefs{}
	readJSONFile(t.path(taskPrefsFile), &p)
	t.prefs = p
	if t.history == nil {
		t.history = map[string][]RunRecord{}
		readJSONFile(t.path(taskHistoryFile), &t.history)
	}
}

// SetPrefs applies prefs from the app (and saves them) without reparsing modules.
func (t *tasker) setPrefs(p TaskPrefs) {
	t.mu.Lock()
	t.prefs = p
	t.mu.Unlock()
	writeJSONFile(t.path(taskPrefsFile), p)
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

func (t *tasker) getPrefs() TaskPrefs {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.prefs
}

// record appends a run to the task's log and saves the log. Panel refreshes are not recorded.
//
// selftest fix: the log map was JSON-encoded after t.mu was released while another run (an event task
// fired by networkChanged next to a scheduled one) appended to the same map and slices — a data race,
// and in Go a concurrent map read / write is a fatal error that kills the extension. The snapshot is now
// encoded and written while the lock is held (the file is small: ≤ 10 runs per task), and each task's
// slice is a fresh copy.
func (t *tasker) record(tk *Task, rec RunRecord) {
	if rec.Trigger == "panel" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.history == nil {
		t.history = map[string][]RunRecord{}
	}
	old := t.history[tk.ID]
	l := make([]RunRecord, 0, len(old)+1)
	l = append(append(l, old...), rec)
	if len(l) > historyPerTask {
		l = l[len(l)-historyPerTask:]
	}
	t.history[tk.ID] = l
	// drop logs of tasks that no longer exist
	live := map[string]bool{}
	for _, x := range t.tasks {
		live[x.ID] = true
	}
	snap := map[string][]RunRecord{}
	for id, v := range t.history {
		if live[id] {
			snap[id] = v
		}
	}
	t.history = snap
	writeJSONFile(t.path(taskHistoryFile), snap)
}

func (t *tasker) historyFor(id string) []RunRecord {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := append([]RunRecord(nil), t.history[id]...)
	if out == nil {
		out = []RunRecord{}
	}
	return out
}

// saveListLocked writes the parsed task list for the app's offline view. t.mu held.
func (t *tasker) saveListLocked() {
	list := make([]*Task, 0, len(t.tasks))
	list = append(list, t.tasks...)
	writeJSONFile(t.path(taskListFile), list)
}

// runLogs collects the script's log lines written since seq (console output of this run).
func (t *tasker) runLogs(name string, seq int64) []string {
	var out []string
	for _, ln := range t.e.Logs.List(seq, name) {
		msg := ln.Msg
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		out = append(out, time.UnixMilli(int64(ln.Time*1000)).Format("15:04:05")+" "+levelMark(ln.Level)+" "+msg)
	}
	if len(out) > historyLogs {
		out = append([]string{"…"}, out[len(out)-historyLogs+1:]...)
	}
	return out
}

func levelMark(l string) string {
	if l == "" {
		return "I"
	}
	return strings.ToUpper(l[:1])
}
