package libmihomo

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/log"
)

// B04: an empty controller secret is replaced by a random one and written back, never run as "".
func TestR7B04EmptySecretNeverReachesRuntime(t *testing.T) {
	home := t.TempDir()
	_ = os.WriteFile(filepath.Join(home, "overrides.json"), []byte(`{"secret":"","controllerPort":9191,"mode":"rule"}`), 0o644)
	o := readOverrides(home)
	if len(o.Secret) < 16 {
		t.Fatalf("want a random secret, got %q", o.Secret)
	}
	b, _ := os.ReadFile(filepath.Join(home, "overrides.json"))
	raw := map[string]any{}
	_ = json.Unmarshal(b, &raw)
	if raw["secret"] != o.Secret || raw["mode"] != "rule" || raw["controllerPort"] != float64(9191) {
		t.Fatalf("secret must be written back, other keys kept: %s", b)
	}
	if again := readOverrides(home); again.Secret != o.Secret {
		t.Fatalf("second read must reuse the stored secret: %q vs %q", again.Secret, o.Secret)
	}
	rt, err := buildRuntime([]byte("proxies: []\nrules: [MATCH,DIRECT]\n"), o, 0)
	if err != nil || !strings.Contains(string(rt), "secret: "+o.Secret) {
		t.Fatalf("runtime secret: %v\n%s", err, rt)
	}
	// No overrides.json at all: a per-process random secret, nothing created.
	empty := t.TempDir()
	o2 := readOverrides(empty)
	if o2.Secret == "" || o2.Secret != readOverrides(empty).Secret {
		t.Fatalf("missing file: want a stable process secret, got %q", o2.Secret)
	}
	if _, err := os.Stat(filepath.Join(empty, "overrides.json")); err == nil {
		t.Fatal("must not create overrides.json")
	}
}

// B11: concurrent recorders keep a ring in seq order, and a reader following the cursor never skips a line.
func TestR7B11LogRingConcurrentOrder(t *testing.T) {
	gen, dns := &logRing{cap: logRingCap}, &logRing{cap: logRingCap}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	seen := map[string]bool{}
	var cursor uint64
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			r := logHistoryFrom(gen, cursor, "")
			for _, e := range r.Logs {
				seen[e.Payload] = true
			}
			cursor = r.Seq
			select {
			case <-stop:
				r := logHistoryFrom(gen, cursor, "")
				for _, e := range r.Logs {
					seen[e.Payload] = true
				}
				return
			default:
			}
		}
	}()
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				recordLogEventTo(gen, dns, log.Event{LogLevel: log.INFO, Payload: fmt.Sprintf("w%d-%d", w, i)}, time.Now())
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	<-readerDone
	all, _ := gen.since(0)
	for i := 1; i < len(all); i++ {
		if all[i].Seq <= all[i-1].Seq {
			t.Fatalf("ring out of seq order at %d: %d after %d", i, all[i].Seq, all[i-1].Seq)
		}
	}
	if len(seen) != 1600 {
		t.Fatalf("cursor reader missed lines: saw %d of 1600", len(seen))
	}
}
