package libmihomo

import (
	"runtime"
	"testing"
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
