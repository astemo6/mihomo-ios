package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// v0.18.1 review fixes: Start's timeout vs a finishing apply is decided by one CAS,
// and Reload refuses to re-apply a core once it is not running.

func v0181Home(t *testing.T, port int) (home, prof, logPath string) {
	t.Helper()
	home = t.TempDir()
	ov := defaultOverrides()
	ov.ControllerPort = port
	ov.Secret = "s"
	ob, _ := json.Marshal(ov)
	if err := os.WriteFile(filepath.Join(home, "overrides.json"), ob, 0o644); err != nil {
		t.Fatal(err)
	}
	logPath = filepath.Join(home, "startup.log")
	SetStageLog(logPath, 8*3600)
	t.Cleanup(func() { SetStageLog("", 0) })
	prof = filepath.Join(home, "p.yaml")
	_ = os.WriteFile(prof, []byte(`proxies:
  - {name: demo, type: ss, server: 127.0.0.1, port: 1, cipher: aes-128-gcm, password: x}
rules:
  - MATCH,DIRECT
`), 0o644)
	return
}

func stageLogHas(path, s string) bool {
	b, _ := os.ReadFile(path)
	return strings.Contains(string(b), s)
}

func waitStage(t *testing.T, path, s string, d time.Duration) {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if stageLogHas(path, s) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	b, _ := os.ReadFile(path)
	t.Fatalf("stage %q not logged within %s:\n%s", s, d, b)
}

// Start's apply goroutine reads testHookApplyDone (and Start testHookAtDeadline) and can outlive the test that
// started it (Start returns on tun up while providers still load). Assigning those package vars from a test or
// its cleanup then raced with that read under -race (bridge.Start.func1 vs withStartTimeout). They are now set
// once, before any test runs, to dispatchers that load the current hook atomically; tests change hooks only
// through setApplyDoneHook / setAtDeadlineHook.
var curApplyDoneHook, curAtDeadlineHook atomic.Pointer[func()]

func init() {
	testHookApplyDone = func() {
		if f := curApplyDoneHook.Load(); f != nil {
			(*f)()
		}
	}
	testHookAtDeadline = func() {
		if f := curAtDeadlineHook.Load(); f != nil {
			(*f)()
		}
	}
}

func storeHook(p *atomic.Pointer[func()], f func()) {
	if f == nil {
		p.Store(nil)
		return
	}
	p.Store(&f)
}

func setApplyDoneHook(f func())  { storeHook(&curApplyDoneHook, f) }
func setAtDeadlineHook(f func()) { storeHook(&curAtDeadlineHook, f) }

func withStartTimeout(t *testing.T, d time.Duration) {
	old := startTimeout
	startTimeout = d
	t.Cleanup(func() {
		startTimeout = old
		setApplyDoneHook(nil)
		setAtDeadlineHook(nil)
	})
}

// Deadline wins the CAS: Start reports the timeout (running=false), the late apply sees it lost,
// skips the post-apply steps and tears its core down. A Reload in between is refused and must not
// take ownership (otherwise the teardown would be skipped and the core left running).
func TestV0181StartTimeoutWinsTearsDownLateApply(t *testing.T) {
	home, prof, logPath := v0181Home(t, 19381)
	withStartTimeout(t, time.Millisecond)
	release := make(chan struct{})
	setApplyDoneHook(func() { <-release })

	err := Start(home, prof, 0)
	if err == nil || !strings.Contains(err.Error(), "超时") {
		t.Fatalf("Start should time out, got %v", err)
	}
	if IsRunning() {
		t.Fatal("running after a timed-out Start")
	}
	if err := Reload(prof); err == nil || !strings.Contains(err.Error(), "not running") {
		t.Fatalf("Reload after a timed-out Start should be refused, got %v", err)
	}
	close(release)
	waitStage(t, logPath, "apply finished after Start timeout; tearing down stale core", 20*time.Second)
	if stageLogHas(logPath, "core apply finished") {
		t.Fatal("post-apply steps ran for a timed-out Start")
	}
	if IsRunning() {
		t.Fatal("running after the stale teardown")
	}

	// The bridge is usable again afterwards.
	setApplyDoneHook(nil)
	startTimeout = 20 * time.Second
	if err := Start(home, prof, 0); err != nil {
		t.Fatalf("Start after teardown: %v", err)
	}
	if !IsRunning() {
		t.Fatal("not running after a good Start")
	}
	Stop()
	if IsRunning() {
		t.Fatal("still running after Stop")
	}
}

// The apply goroutine wins the CAS just before the deadline branch tries its own (the interleaving
// that used to leave a live core while Start reported a timeout with running=false): Start must take
// the real result, report success and mark the core running so Stop can tear it down.
func TestV0181ApplyWinsBeforeDeadlineCAS(t *testing.T) {
	home, prof, logPath := v0181Home(t, 19382)
	withStartTimeout(t, time.Millisecond)
	applied := make(chan struct{})
	setApplyDoneHook(func() { close(applied) })
	setAtDeadlineHook(func() {
		<-applied
		// "core apply finished" is logged after the goroutine's winning CAS and its send on done.
		waitStage(t, logPath, "core apply finished", 20*time.Second)
	})

	if err := Start(home, prof, 0); err != nil {
		t.Fatalf("Start must return the finished apply's result, got %v", err)
	}
	if !IsRunning() {
		t.Fatal("core applied but running=false (Stop could not tear it down)")
	}
	if stageLogHas(logPath, "tearing down stale core") || stageLogHas(logPath, "TIMEOUT") {
		b, _ := os.ReadFile(logPath)
		t.Fatalf("apply that won the CAS was treated as timed out:\n%s", b)
	}
	Stop()
	if IsRunning() {
		t.Fatal("still running after Stop")
	}
}

// A reload queued on the extension's background queue before stopTunnel can run after Stop.
// It must be refused instead of re-applying a core nobody will stop.
func TestV0181ReloadAfterStopRefused(t *testing.T) {
	home, prof, logPath := v0181Home(t, 19383)
	if err := Start(home, prof, 0); err != nil {
		t.Fatal(err)
	}
	if err := Reload(prof); err != nil {
		t.Fatalf("Reload while running: %v", err)
	}
	Stop()
	before, _ := os.ReadFile(logPath)
	err := Reload(prof)
	if err == nil || !strings.Contains(err.Error(), "core not running") {
		t.Fatalf("Reload after Stop should fail with core not running, got %v", err)
	}
	if IsRunning() {
		t.Fatal("Reload after Stop brought the core back")
	}
	after, _ := os.ReadFile(logPath)
	if strings.Contains(string(after[len(before):]), "runtime.yaml written") {
		t.Fatal("Reload after Stop re-applied the config")
	}
}
