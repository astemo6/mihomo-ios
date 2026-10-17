package libmihomo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/astemo6/mihomo-android/core/mitm"
)

// Cron / event scripts alone start the engine (scheduler) but steer no traffic to it.
func TestTasksOnlyEngineInjectsNothing(t *testing.T) {
	home := t.TempDir()
	cfg := mitm.Config{Enabled: true, Scripts: []mitm.Item{{ID: "1", Enabled: true, Line: `签到 = type=cron,cronexp="0 8 * * *",script-path=a.js`}}}
	b, _ := json.Marshal(cfg)
	_ = os.MkdirAll(mitm.EngineDir(home), 0o755)
	_ = os.WriteFile(filepath.Join(mitm.EngineDir(home), "engine.json"), b, 0o644)
	inject, err := prepareEngine(home)
	if err != nil {
		t.Fatal(err)
	}
	defer stopEngine()
	if inject != nil {
		raw := map[string]any{}
		inject(raw)
		if _, ok := raw["proxies"]; ok {
			t.Fatalf("tasks-only engine must not inject the MitM outbound: %v", raw)
		}
	}
	engMu.Lock()
	running := eng != nil
	engMu.Unlock()
	if !running {
		t.Fatal("engine (scheduler) not started for cron scripts")
	}
	if n := NotifyNetworkChanged(`{"wifi":{"ssid":"x"}}`); n != 0 {
		t.Fatalf("no event scripts, got %d", n)
	}
	if c, a, o := geoLookup("not-an-ip"); c != "" || a != "" || o != "" {
		t.Fatal("bad ip lookup")
	}
}
