package libmihomo

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// v0.19.6 (review 7): Start returns as soon as the tun listener is up while the apply goroutine is
// still loading providers. A Stop (or Reload) in that window must win: the late goroutine must not
// start the rule-hit ticker / smart groups / network policy on a core that was stopped.

func ruleHitsRunning() bool {
	ruleHitsMu.Lock()
	defer ruleHitsMu.Unlock()
	return ruleHitsStop != nil
}

func TestV0196StopWhileApplyPendingSkipsPostApply(t *testing.T) {
	home, prof, logPath := v0181Home(t, 19396)
	withStartTimeout(t, 10*time.Second)
	release := make(chan struct{})
	finished := make(chan struct{})
	testHookApplyDone = func() { <-release; defer close(finished) }

	if err := Start(home, prof, 0); err != nil {
		t.Fatal(err)
	}
	if !stageLogHas(logPath, "tun up") {
		t.Fatalf("Start should have returned on tun up while the apply was pending")
	}
	Stop()
	if IsRunning() {
		t.Fatal("running after Stop")
	}
	close(release)
	<-finished
	time.Sleep(300 * time.Millisecond) // post-apply steps run right after the hook
	if ruleHitsRunning() {
		stopRuleHits("")
		t.Fatal("rule-hit ticker started by a late apply after Stop")
	}
	if !stageLogHas(logPath, "post-apply steps skipped") {
		t.Fatalf("late apply did not skip its post-apply steps after Stop")
	}
}

// Reload during the pending window: the late Start goroutine must not re-apply the old profile's
// selections / smart groups after the Reload's own steps.
func TestV0196ReloadWhileApplyPendingKeepsNewest(t *testing.T) {
	home, prof, logPath := v0181Home(t, 19397)
	withStartTimeout(t, 10*time.Second)
	release := make(chan struct{})
	finished := make(chan struct{})
	testHookApplyDone = func() { <-release; defer close(finished) }
	if err := Start(home, prof, 0); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	if err := Reload(prof); err != nil {
		t.Fatal(err)
	}
	close(release)
	<-finished
	time.Sleep(300 * time.Millisecond)
	if !ruleHitsRunning() {
		t.Fatal("rule-hit ticker not running after Start + Reload")
	}
	if !IsRunning() {
		t.Fatal("not running")
	}
	if !stageLogHas(logPath, "after a Reload") {
		t.Fatal("late Start apply did not notice the Reload")
	}
}

// Concurrent read-modify-write of one file (the app runs node edits on detached tasks; selections are
// saved per tap): every write must survive.
func TestV0196ConcurrentProfileNodeWrites(t *testing.T) {
	home := v0194Home(t)
	path := writeScaleProfile(t, home, genYAMLProfile(50, 50, 2, 0))
	const n = 12
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			j := fmt.Sprintf(`{"name":"NEW %02d","type":"ss","server":"192.0.2.%d","port":443,"cipher":"aes-128-gcm","password":"x"}`, i, i+1)
			if e := ProfileNodeUpsert(home, path, j, ""); e != "" {
				errs <- e
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Errorf("upsert: %s", e)
	}
	missing := 0
	for i := 0; i < n; i++ {
		if !ProfileHasNode(path, fmt.Sprintf("NEW %02d", i)) {
			missing++
		}
	}
	if missing > 0 {
		t.Fatalf("%d of %d concurrent node additions lost", missing, n)
	}
}

func TestV0196ConcurrentManualAdds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manual.yaml")
	_ = ManualDelete(path, "")
	const n = 16
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ui := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw"))
			ManualAddText(path, fmt.Sprintf("ss://%s@192.0.2.%d:443#M%02d", ui, i+1, i))
		}(i)
	}
	wg.Wait()
	var list []map[string]any
	_ = json.Unmarshal([]byte(ManualList(path)), &list)
	if len(list) != n {
		t.Fatalf("manual nodes after %d concurrent adds: %d", n, len(list))
	}
}

func TestV0196ConcurrentSaveSelection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.yaml")
	_ = os.WriteFile(path, []byte("proxies: []\n"), 0o644)
	const n = 32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			SaveSelection(path, fmt.Sprintf("G%02d", i), "DIRECT")
		}(i)
	}
	wg.Wait()
	if got := len(readSelections(path)); got != n {
		t.Fatalf("selections after %d concurrent saves: %d", n, got)
	}
}
