package mitm

import (
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dop251/goja"
)

func objHeap() uint64 {
	s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(s)
	return s[0].Value.Uint64()
}

// heapPeakDuring samples the heap every 50 µs while f runs and returns the peak above the starting heap.
// With a low GOGC the collector runs often, so the peak follows what f keeps alive (the compile's live
// set) rather than its garbage — that is what the extension's GOMEMLIMIT-driven GC sees.
func heapPeakDuring(f func()) uint64 {
	runtime.GC()
	base := objHeap()
	var stop atomic.Bool
	var peak atomic.Uint64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for !stop.Load() {
			if h := objHeap(); h > peak.Load() {
				peak.Store(h)
			}
			time.Sleep(50 * time.Microsecond)
		}
	}()
	f()
	stop.Store(true)
	<-done
	if p := peak.Load(); p > base {
		return p - base
	}
	return 0
}

// E 线 #5: compiling the Sub-Store bundle with goja. CompileReleasing (what the goja engine uses) drops
// each function's syntax tree once it is compiled, so the live peak is well below goja.Compile's while
// the program is the same (third_party/goja mihomo_release_test.go compares them instruction by
// instruction). Measured on linux/amd64: ~37 MB → ~24 MB for sub-store-1.min.js (1.3 MB).
func TestSubStoreCompilePeakReleasing(t *testing.T) {
	if raceEnabled {
		t.Skip("heap measurements are meaningless under -race")
	}
	src := string(fixture(t, substoreRel+"sub-store-1.min.js"))
	code := "(function(){\n" + src + "\n}).call(this);"
	old := debug.SetGCPercent(10)
	defer debug.SetGCPercent(old)
	measure := func(c func(string, string, bool) (*goja.Program, error)) uint64 {
		var best uint64
		for i := 0; i < 3; i++ { // the minimum of three: sampling noise only ever adds
			var p *goja.Program
			var err error
			pk := heapPeakDuring(func() { p, err = c("sub-store.js", code, false) })
			if err != nil {
				t.Fatal(err)
			}
			runtime.KeepAlive(p)
			if best == 0 || pk < best {
				best = pk
			}
		}
		return best
	}
	plain := measure(goja.Compile)
	rel := measure(goja.CompileReleasing)
	t.Logf("sub-store-1.min.js (%d KB): live compile peak goja.Compile +%.1f MB, CompileReleasing +%.1f MB (%.0f%%)",
		len(src)>>10, float64(plain)/(1<<20), float64(rel)/(1<<20), 100*float64(rel)/float64(plain))
	if rel > plain*85/100 {
		t.Fatalf("CompileReleasing peak %d KB is not clearly below goja.Compile's %d KB", rel>>10, plain>>10)
	}
	// The engine path the tunnel / tests use compiles with the releasing variant too.
	var pk uint64
	for i := 0; i < 3; i++ {
		e := New(t.TempDir(), nil, nil)
		sc := &Script{Name: "ss", Type: "http-request", Path: "ss.js", Source: []byte(src)}
		var c *compiled
		p := heapPeakDuring(func() {
			var err error
			c, _, err = e.scripts.programFor(sc, gojaEngine{})
			if err != nil {
				t.Fatal(err)
			}
		})
		runtime.KeepAlive(c)
		if pk == 0 || p < pk {
			pk = p
		}
	}
	t.Logf("ScriptRunner compile (goja): +%.1f MB", float64(pk)/(1<<20))
	if pk > plain*90/100 {
		t.Fatalf("ScriptRunner's goja compile peaked at %d KB, goja.Compile alone %d KB", pk>>10, plain>>10)
	}
}
