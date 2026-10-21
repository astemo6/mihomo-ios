package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/hub/executor"
)

// Review 7 P3-1: overlapping startup pacing (Start apply still loading, Reload enters) restores the original
// GOMAXPROCS whatever the order of the restores.
func TestR7P31OverlappingPacingRestoresProcs(t *testing.T) {
	if disablePacing {
		t.Skip("pacing disabled")
	}
	orig := runtime.GOMAXPROCS(0)
	if orig <= startupProcs {
		runtime.GOMAXPROCS(startupProcs + 2)
		defer runtime.GOMAXPROCS(orig)
	}
	want := runtime.GOMAXPROCS(0)
	startRestore := startupPacing()
	reloadRestore := startupPacing() // Reload while Start's apply still runs
	if got := runtime.GOMAXPROCS(0); got != startupProcs {
		t.Fatalf("pacing: want %d procs, got %d", startupProcs, got)
	}
	startRestore()
	if got := runtime.GOMAXPROCS(0); got != startupProcs {
		t.Fatalf("still pacing while Reload loads: want %d, got %d", startupProcs, got)
	}
	reloadRestore()
	reloadRestore() // idempotent
	if got := runtime.GOMAXPROCS(0); got != want {
		t.Fatalf("after both restores: want %d procs, got %d", want, got)
	}
}

func proxyTrafficSampling() bool {
	proxyTrafficStats.mu.Lock()
	defer proxyTrafficStats.mu.Unlock()
	return proxyTrafficStats.stop != nil
}

// Review 7 P3-2: a timed-out Start stops the proxy-only sampler (also the late stale teardown).
func TestR7P32StartTimeoutStopsTrafficSampler(t *testing.T) {
	home, prof, logPath := v0181Home(t, 19391)
	withStartTimeout(t, time.Millisecond)
	release := make(chan struct{})
	testHookApplyDone = func() { <-release }
	if err := Start(home, prof, 0); err == nil || !strings.Contains(err.Error(), "超时") {
		t.Fatalf("Start should time out, got %v", err)
	}
	if proxyTrafficSampling() {
		t.Fatal("proxy-only sampler still running after a timed-out Start")
	}
	close(release)
	waitStage(t, logPath, "tearing down stale core", 20*time.Second)
	if proxyTrafficSampling() {
		t.Fatal("proxy-only sampler running after the stale teardown")
	}
}

// B33: apply hands its Overrides back, so Reload decides 安全模式 without reading the override files again.
func TestR7B33ApplyReturnsOverrides(t *testing.T) {
	home, prof, _ := v0181Home(t, 19392)
	ov := defaultOverrides()
	ov.ControllerPort, ov.Secret, ov.SafeMode = 19392, "s", true
	ob, _ := json.Marshal(ov)
	_ = os.WriteFile(filepath.Join(home, "overrides.json"), ob, 0o644)
	var used Overrides
	if err := safeApplyInto(home, prof, 0, &used); err != nil {
		t.Fatal(err)
	}
	defer executor.Shutdown()
	if !used.SafeMode || used.ControllerPort != 19392 {
		t.Fatalf("applyInto must return the Overrides it used: %+v", used)
	}
}
