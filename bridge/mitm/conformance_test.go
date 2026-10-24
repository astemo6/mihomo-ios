package mitm

import (
	"encoding/json"
	"os"
	"testing"
)

// TestEngineConformance: the shared corpus (UnitTests/ScriptEngineConformance.json, also run on JavaScriptCore
// by the iOS unit tests) gives the expected output on goja, and the same output through the native-engine
// adapter (fakeNative: context per script reused across runs, stop by polling).
func TestEngineConformance(t *testing.T) {
	raw, err := os.ReadFile("../../UnitTests/ScriptEngineConformance.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []ConformanceCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	old, _ := nativeJS.Load().(nativeBox)
	fake := newFakeNative()
	if msg := SetNativeEngine(fake); msg != "" {
		t.Fatal(msg)
	}
	defer func() {
		if old.n != nil {
			nativeJS.Store(old)
		} else {
			SetNativeEngine(nil)
		}
	}()
	// corpus cases with "lane": true run the native side through a fake native body store (conformancelane.go)
	lane := newFakeLane()
	SetNativeBodies(lane)
	activeFakeLane.Store(lane)
	defer func() {
		activeFakeLane.Store(nil)
		SetNativeBodies(nil)
		ResetLaneBreaker()
	}()
	home := t.TempDir()
	repeats := 0
	for _, c := range cases {
		r := RunConformance(home, c, true)
		if !r.OK {
			t.Errorf("%s: missing %q\n%s\ngoja: %s", c.Name, r.Missing, r.Diff, r.Goja)
		}
		if c.Lane && (r.LaneLive != 0 || lane.live() != 0) {
			t.Errorf("%s: lane handles left: go %d, store %d", c.Name, r.LaneLive, lane.live())
		}
		if c.Repeat > 1 {
			repeats += c.Repeat - 1
		}
	}
	// the repeated runs ran on the context their first run loaded (prelude reset in between)
	if fake.reused < repeats {
		t.Errorf("context reuse: %d runs on an existing context, want ≥ %d", fake.reused, repeats)
	}
}
