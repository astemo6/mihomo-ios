package mitm

// Native script engine (feat/jsc-engine): JavaScriptCore in the iOS tunnel, registered by the bridge
// (libmihomo.SetScriptEngine ← PacketTunnel/JSCScriptEngine.swift). Go keeps the cache index (progs: which
// script keys are loaded, their estimated size, idle release of large bundles, ShedMemory), the event loop,
// timers and every host API; the Swift side only holds one JSVirtualMachine with one JSContext per loaded
// script and evaluates JavaScript.
//
// Calls are synchronous: Begin runs __tern_begin + the script's top level, Call runs __tern_fire /
// __tern_deliver; while JavaScript runs, the Swift side calls back into the run (NativeRun.Host / Put / Take)
// on the same thread. A run that must stop (timeout, client gone, memory) is ended by JavaScriptCore's
// execution time limit, whose callback asks NativeRun.ShouldStop. If the engine does not come back within
// nativeWedgeGrace of the stop (no time-limit API on this iOS), it is marked wedged and every later run uses
// goja.

import (
	"errors"
	"sync/atomic"
	"time"
)

// NativeJS is the engine as the bridge registers it (all methods synchronous, safe from any goroutine).
type NativeJS interface {
	// Prepare is called once with the prelude; "" or an error message.
	Prepare(prelude string) string
	// Load evaluates source as the script for key ("" or the syntax error).
	Load(key, name, source string) string
	// Drop forgets key (a context in use is dropped when its run ends).
	Drop(key string)
	// Collect asks the engine to collect garbage (after drops).
	Collect()
	// Begin starts run on key's context: "" ok, "missing" (key not loaded), else error JSON {kind, message}.
	Begin(run NativeRun, key, setup string) string
	// Call invokes a prelude entry point in the run's context: "" or error JSON.
	Call(runID int64, fn, arg string) string
	// End releases the run's context.
	End(runID int64)
}

// NativeRun is what the engine calls back into during a run (implemented by *runCtx).
type NativeRun interface {
	ID() int64
	Host(op, arg string) string
	Put(b []byte) int64
	Take(id int64) []byte
	ShouldStop() bool
}

type nativeBox struct{ n NativeJS }

var (
	nativeJS     atomic.Value // nativeBox
	nativeWedged atomic.Bool
)

// nativeWedgeGrace: how long after a stop request a native call may still take before the engine counts as
// wedged (the time-limit callback fires every 100 ms).
var nativeWedgeGrace = 3 * time.Second

// SetNativeEngine registers (nil: removes) the native engine. Returns the error of Prepare ("" = ok).
func SetNativeEngine(n NativeJS) string {
	if n == nil {
		nativeJS.Store(nativeBox{})
		return ""
	}
	if msg := n.Prepare(PreludeSource()); msg != "" {
		nativeJS.Store(nativeBox{})
		return msg
	}
	nativeWedged.Store(false)
	nativeJS.Store(nativeBox{n})
	return ""
}

func nativeUsable() bool {
	b, _ := nativeJS.Load().(nativeBox)
	return b.n != nil && !nativeWedged.Load()
}

func nativeEngineNow() jsEngine {
	b, _ := nativeJS.Load().(nativeBox)
	if b.n == nil || nativeWedged.Load() {
		return nil
	}
	return nativeEngine{b.n}
}

// NativeWedged reports that the native engine stopped answering and goja took over (diagnostics).
func NativeWedged() bool { return nativeWedged.Load() }

type nativeEngine struct{ n NativeJS }

// usesGoHeap: a native engine whose JavaScript lives in the Go heap after all (the goja-backed stand-in of
// the tests) still gets the GOMEMLIMIT loan.
func usesGoHeap(e jsEngine) bool {
	n, ok := e.(nativeEngine)
	if !ok {
		return true
	}
	g, ok := n.n.(interface{ UsesGoHeap() bool })
	return ok && g.UsesGoHeap()
}

func (nativeEngine) kind() string { return EngineNative }

// borrows: never — the native engine copies a body into its own heap, so a script's in-place edits can't
// reach the host's bytes (nothing to restore after an error).
func (nativeEngine) borrows() bool { return false }

func (e nativeEngine) compile(c *compiled, name, code string) error {
	c.native = true
	if msg := e.n.Load(c.key, name, code); msg != "" {
		return errors.New("脚本语法错误：" + msg)
	}
	return nil
}

func (e nativeEngine) begin(rc *runCtx, c *compiled, setup string) error {
	rc.native = e.n
	res := e.guard(rc, func() string { return e.n.Begin(rc, c.key, setup) })
	if res == "missing" {
		// the engine dropped the context on its own (restart): load again once
		if err := e.compile(c, rc.name, rc.code()); err != nil {
			return err
		}
		res = e.guard(rc, func() string { return e.n.Begin(rc, c.key, setup) })
	}
	if res != "" {
		return parseNativeErr(res)
	}
	return nil
}

func (e nativeEngine) call(rc *runCtx, fn, arg string) error {
	if res := e.guard(rc, func() string { return e.n.Call(rc.id, fn, arg) }); res != "" {
		return parseNativeErr(res)
	}
	return nil
}

func (nativeEngine) interrupt(rc *runCtx) {} // the engine polls ShouldStop

func (e nativeEngine) end(rc *runCtx) {
	if !rc.abandoned.Load() {
		e.n.End(rc.id)
	}
}

// guard runs one engine call. Normally it just returns its result; after a stop request it gives the call
// nativeWedgeGrace to end, then abandons it (the engine is marked wedged).
func (e nativeEngine) guard(rc *runCtx, f func() string) string {
	done := make(chan string, 1)
	go func() { done <- f() }()
	select {
	case r := <-done:
		return r
	case <-rc.stopCh:
	}
	t := time.NewTimer(nativeWedgeGrace)
	defer t.Stop()
	select {
	case r := <-done:
		return r
	case <-t.C:
	}
	rc.abandoned.Store(true)
	nativeWedged.Store(true)
	rc.e.logf("warning", "[MitM] JavaScriptCore 脚本引擎停止响应（"+rc.name+"），之后的脚本改用 goja 运行")
	return `{"kind":"terminated","message":"wedged"}`
}
