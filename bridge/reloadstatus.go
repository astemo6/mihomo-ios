package libmihomo

// fix/xmly-memory-2 (device 2026-10-24 22:14): 「重载失败：重新加载超时：内核可能仍在使用旧配置」 — the app's
// reload request (resources updated when the app became active) got no answer within 45 s while the
// extension was memory-critical (喜马拉雅 open, 3 MB available). The app could not tell a reload still being
// applied from one that was lost. ReloadStatus lets it ask: the app polls it after the reply timed out and
// reports the real outcome, and the startup log records how long each reload took (waiting for the core lock
// vs applying).

import (
	"encoding/json"
	"sync"
	"time"
)

var reloadSt struct {
	sync.Mutex
	seq      int64     // reloads requested so far
	done     int64     // reloads finished so far
	running  int       // in progress (waiting for mu or applying)
	kind     string    // of the newest one
	started  time.Time // of the newest one
	lastErr  string    // of the newest finished one ("" = ok)
	lastMs   int64     // duration of the newest finished one
	lastDone time.Time
}

// reloadBegin records a reload request; the returned func records its end.
func reloadBegin(kind string) func(error) {
	reloadSt.Lock()
	reloadSt.seq++
	reloadSt.running++
	reloadSt.kind = kind
	start := time.Now()
	reloadSt.started = start
	reloadSt.Unlock()
	return func(err error) {
		d := time.Since(start)
		reloadSt.Lock()
		reloadSt.done++
		reloadSt.running--
		reloadSt.lastMs = d.Milliseconds()
		reloadSt.lastDone = time.Now()
		reloadSt.lastErr = ""
		if err != nil {
			reloadSt.lastErr = err.Error()
		}
		reloadSt.Unlock()
		if d >= 5*time.Second {
			stage("reload (%s) took %s, %s", kind, d.Round(time.Millisecond), memText())
		}
	}
}

// ReloadStatus reports the reload state (JSON): {"running":bool,"seq":N,"done":N,"kind":"hot|full",
// "runningMs":ms of the one in progress,"lastError":"","lastMs":ms,"lastDoneAgoMs":ms (-1 never)}.
func ReloadStatus() string {
	reloadSt.Lock()
	out := map[string]any{
		"running":       reloadSt.running > 0,
		"seq":           reloadSt.seq,
		"done":          reloadSt.done,
		"kind":          reloadSt.kind,
		"lastError":     reloadSt.lastErr,
		"lastMs":        reloadSt.lastMs,
		"lastDoneAgoMs": int64(-1),
		"runningMs":     int64(0),
	}
	if reloadSt.running > 0 {
		out["runningMs"] = time.Since(reloadSt.started).Milliseconds()
	}
	if !reloadSt.lastDone.IsZero() {
		out["lastDoneAgoMs"] = time.Since(reloadSt.lastDone).Milliseconds()
	}
	reloadSt.Unlock()
	b, _ := json.Marshal(out)
	return string(b)
}
