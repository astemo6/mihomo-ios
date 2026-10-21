package libmihomo

import (
	"encoding/json"
	"io"
	"net/http"
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

// Review 7 P3-3: the region fast path treats tab / NBSP / full-width space like the regex's \s.
func TestR7P33RegionUnicodeSpace(t *testing.T) {
	for name, want := range map[string]string{
		"Hong\u00a0Kong 01": "HK", "New\tYork 02": "US", "Los\u3000Angeles": "US", "United\u2009States": "US",
		"Hong Kong 03": "HK", "HongKong": "HK", "Nowhere 1": "",
	} {
		if got, _ := detectRegion(name); got != want {
			t.Errorf("%q: want %q, got %q", name, want, got)
		}
	}
}

// Review 7 P3-4: PUT /configs, POST /configs/geo, /restart and /upgrade are refused; PATCH /configs still works.
func TestR7P34ControllerLockdown(t *testing.T) {
	home, prof, _ := v0181Home(t, 19393)
	if err := Start(home, prof, 0); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	do := func(method, path, body string) int {
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, "http://127.0.0.1:19393"+path, rd)
		req.Header.Set("Authorization", "Bearer s")
		var resp *http.Response
		var err error
		for i := 0; i < 50; i++ {
			if resp, err = http.DefaultClient.Do(req); err == nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
			if body != "" {
				req.Body = io.NopCloser(strings.NewReader(body))
			}
		}
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for _, c := range []struct{ m, p string }{
		{"PUT", "/configs"}, {"PUT", "/configs/"}, {"POST", "/configs/geo"}, {"POST", "/restart"},
		{"POST", "/upgrade"}, {"POST", "/upgrade/"}, {"POST", "/upgrade/geo"}, {"POST", "/upgrade/ui"},
	} {
		if got := do(c.m, c.p, `{"path":""}`); got != http.StatusForbidden {
			t.Errorf("%s %s: want 403, got %d", c.m, c.p, got)
		}
	}
	if got := do("PATCH", "/configs", `{"mode":"global"}`); got != http.StatusNoContent && got != http.StatusOK {
		t.Errorf("PATCH /configs must keep working, got %d", got)
	}
	if got := do("GET", "/configs", ""); got != http.StatusOK {
		t.Errorf("GET /configs: %d", got)
	}
	// Unauthenticated callers still get 401 before the lock answers.
	req, _ := http.NewRequest("PUT", "http://127.0.0.1:19393/configs", strings.NewReader("{}"))
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("unauthenticated PUT: want 401, got %d", resp.StatusCode)
		}
	}
}
