package libmihomo

// JavaScriptCore script engine for MitM / rewrite / task scripts (feat/jsc-engine). The tunnel registers
// PacketTunnel/JSCScriptEngine.swift with SetScriptEngine before Start; from then on scripts run in
// JavaScriptCore instead of goja (bridge/mitm/jsengine.go, jsnative.go). Without a registered engine
// (Android, Go tests, an older app) goja runs them as before.

import (
	"encoding/json"
	"runtime"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
)

// ScriptEngine is implemented in Swift (JavaScriptCore). Every method is synchronous and may be called from
// any thread; results are "" on success.
type ScriptEngine interface {
	// Prepare receives the shared prelude once (before any Load). "" or an error message.
	Prepare(prelude string) string
	// Load evaluates source as the script for key: "" or the syntax error message.
	Load(key string, name string, source string) string
	// Drop forgets key's context (one in use goes when its run ends).
	Drop(key string)
	// Collect runs the garbage collector after drops.
	Collect()
	// Begin runs __tern_begin(setup) and the script's top level for run on key's context: "", "missing"
	// (key not loaded) or an error JSON {"kind":"exception|terminated|syntax|internal","message":…}.
	Begin(run *ScriptRun, key string, setup string) string
	// Call invokes a prelude entry point (__tern_fire / __tern_deliver) in the run's context ("" or error JSON).
	Call(runID int64, fn string, arg string) string
	// End releases the run's context.
	End(runID int64)
	// Stats describes the engine's state for the memory line (free text).
	Stats() string
}

// ScriptRun is one script run as the Swift engine sees it: the JavaScript primitives __tern.host / put /
// take call these.
type ScriptRun struct{ r mitm.NativeRun }

// ID identifies the run (Call / End).
func (s *ScriptRun) ID() int64 { return s.r.ID() }

// Host is __tern.host(op, arg).
func (s *ScriptRun) Host(op string, arg string) string { return s.r.Host(op, arg) }

// Put is __tern.put: the bytes of an ArrayBuffer range; returns the blob id.
func (s *ScriptRun) Put(b []byte) int64 { return s.r.Put(b) }

// Take is __tern.take(id): the blob's bytes (copied into a fresh Uint8Array by the engine).
func (s *ScriptRun) Take(id int64) []byte { return s.r.Take(id) }

// ShouldStop tells the engine's execution-time-limit callback to terminate the script (timeout, client
// gone, memory).
func (s *ScriptRun) ShouldStop() bool { return s.r.ShouldStop() }

type nativeAdapter struct{ e ScriptEngine }

func (a nativeAdapter) Prepare(p string) string             { return a.e.Prepare(p) }
func (a nativeAdapter) Load(k, n, src string) string        { return a.e.Load(k, n, src) }
func (a nativeAdapter) Drop(k string)                       { a.e.Drop(k) }
func (a nativeAdapter) Collect()                            { a.e.Collect() }
func (a nativeAdapter) Call(id int64, f, arg string) string { return a.e.Call(id, f, arg) }
func (a nativeAdapter) End(id int64)                        { a.e.End(id) }
func (a nativeAdapter) Begin(r mitm.NativeRun, key, setup string) string {
	return a.e.Begin(&ScriptRun{r: r}, key, setup)
}

var scriptEngine ScriptEngine

// SetScriptEngine registers the JavaScriptCore engine (nil: back to goja). Returns "" or why it was not
// taken (the prelude failed to evaluate: scripts keep running in goja).
func SetScriptEngine(e ScriptEngine) string {
	engMu.Lock()
	scriptEngine = e
	engMu.Unlock()
	if e == nil {
		return mitm.SetNativeEngine(nil)
	}
	return mitm.SetNativeEngine(nativeAdapter{e})
}

// ScriptEngineStatus is the script engine in use, for diagnostics: {"engine":"native|goja","wedged":…,"stats":…}.
func ScriptEngineStatus() string {
	engMu.Lock()
	e := scriptEngine
	engMu.Unlock()
	st := map[string]any{"engine": mitm.ScriptEngineName(), "wedged": mitm.NativeWedged()}
	if e != nil {
		st["stats"] = e.Stats()
	}
	b, _ := json.Marshal(st)
	return string(b)
}

// ScriptConformance runs one engine-conformance case (UnitTests/ScriptEngineConformance.json) on goja and on the
// registered JavaScriptCore engine and returns mitm.ConformanceResult as JSON ({"ok":…,"diff":…,"gojaMs":…,
// "nativeMs":…}). Used by the iOS unit tests; ok=false when no native engine is registered.
func ScriptConformance(homeDir, caseJSON string) string {
	var c mitm.ConformanceCase
	if err := json.Unmarshal([]byte(caseJSON), &c); err != nil {
		b, _ := json.Marshal(map[string]any{"ok": false, "diff": "bad case: " + err.Error()})
		return string(b)
	}
	b, _ := json.Marshal(mitm.RunConformance(homeDir, c, true))
	return string(b)
}

// GoroutineDump is every goroutine's stack (diagnostics: the iOS conformance test logs it when a case hangs).
func GoroutineDump() string {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return string(buf[:n])
}
