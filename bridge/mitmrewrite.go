package libmihomo

// Native rewrite snapshot (native MitM stage 3a; bridge/mitm/rewritesnap.go). The Swift rewrite engine
// (PacketTunnel/NativeMitM/Rewrite/) evaluates the Ruleset Go compiled instead of parsing module text itself:
// it polls MitmRewriteGeneration per request (cheap: an int) and fetches MitmRewriteSnapshot only when the
// generation changed (every reload). 0 / "": the MitM engine is not running (Swift then defers to Go).

// MitmRewriteGeneration is the current snapshot's generation (changes on every engine reload).
func MitmRewriteGeneration() int64 {
	engMu.Lock()
	e := eng
	engMu.Unlock()
	if e == nil {
		return 0
	}
	return e.RewriteSnapshotGen()
}

// MitmRewriteSnapshot is the current snapshot as JSON (version, gen, on, capture, inc/exc host patterns,
// rules in order with portability flags, required literals and inline Map Local answers).
func MitmRewriteSnapshot() string {
	engMu.Lock()
	e := eng
	engMu.Unlock()
	if e == nil {
		return ""
	}
	return e.RewriteSnapshotJSON()
}
