package mitm

// Script engines (feat/jsc-engine). A script run is driven by the Go host (script.go: event loop, timers,
// $httpClient downloads through the core, $persistentStore, notifications, $done → rewrite) while the
// JavaScript itself runs in one of two engines:
//
//   - goja (this file): pure Go, a fresh runtime per run. Tests, Android, the app's 脚本调试 when nothing
//     else is registered, and the fallback in the tunnel;
//   - native (jsnative.go): JavaScriptCore in the iOS tunnel (PacketTunnel/JSCScriptEngine.swift),
//     registered through the gomobile bridge (SetScriptEngine). Its heap is not the Go heap, it parses and
//     runs scripts several times faster than goja and keeps compiled scripts outside GOMEMLIMIT.
//
// Both evaluate the same prelude (prelude.js) on the same three primitives (__tern.host / put / take), so
// the script API is defined once.

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/dop251/goja"
)

//go:embed prelude.js
var preludeJS string

var (
	preludeOnce sync.Once
	preludeSrc  string
)

// PreludeSource is the complete prelude handed to every engine (URL polyfill spliced in).
func PreludeSource() string {
	preludeOnce.Do(func() {
		preludeSrc = strings.Replace(preludeJS, "/*URL_POLYFILL*/", urlPolyfillJS, 1)
	})
	return preludeSrc
}

// jsEngine runs one script invocation: begin installs the run's globals and runs the script's top level,
// call invokes a prelude entry (__tern_fire / __tern_deliver), end releases the run.
type jsEngine interface {
	kind() string
	compile(c *compiled, name, code string) error
	begin(rc *runCtx, c *compiled, setup string) error
	call(rc *runCtx, fn, arg string) error
	interrupt(rc *runCtx)
	end(rc *runCtx)
}

// compiled is a cache entry of ScriptRunner.progs: a goja program, or a script loaded into the native engine
// under key.
type compiled struct {
	key    string
	p      *goja.Program
	native bool
}

// jsError is a failed engine call, classified for jsErr.
type jsError struct {
	kind string // exception | interrupted | stack | internal
	msg  string
	err  error // goja's original error (tests unwrap it)
}

func (e *jsError) Error() string { return e.msg }
func (e *jsError) Unwrap() error { return e.err }

// stop reasons (runCtx.stop)
const (
	stopNone = iota
	stopTimeout
	stopMemory
	stopCancelled
)

// ---------------- goja ----------------

type gojaEngine struct{}

var gojaJS jsEngine = gojaEngine{}

var (
	preludeProgOnce sync.Once
	preludeProg     *goja.Program
	preludeProgErr  error
)

func gojaPrelude() (*goja.Program, error) {
	preludeProgOnce.Do(func() { preludeProg, preludeProgErr = goja.Compile("tern-prelude.js", PreludeSource(), false) })
	return preludeProg, preludeProgErr
}

func (gojaEngine) kind() string { return "goja" }

func (gojaEngine) compile(c *compiled, name, code string) error {
	// Wrap so a top-level `return` (allowed by Surge/JSC scripts) does not break compilation.
	p, err := goja.Compile(name+".js", "(function(){\n"+code+"\n}).call(this);", false)
	if err != nil {
		p2, err2 := goja.Compile(name+".js", code, false)
		if err2 != nil {
			return fmt.Errorf("脚本语法错误：%v", err)
		}
		p = p2
	}
	c.p = p
	return nil
}

func (g gojaEngine) begin(rc *runCtx, c *compiled, setup string) error {
	pp, err := gojaPrelude()
	if err != nil {
		return &jsError{kind: "internal", msg: "脚本运行环境错误：" + err.Error()}
	}
	rt := goja.New()
	// v0.19.3: goja's default call-stack limit is MaxInt32, so `function f(){f()} f()` grew the heap by
	// ~25 MB/s until jetsam killed the extension long before the timeout. JSC (Surge) throws RangeError.
	rt.SetMaxCallStackSize(scriptMaxCallStack)
	rc.rt.Store(rt)
	if r := rc.stop.Load(); r != stopNone { // a stop that came before the runtime existed
		rt.Interrupt(stopName(r))
	}
	t := rt.NewObject()
	_ = t.Set("host", func(call goja.FunctionCall) goja.Value {
		return rt.ToValue(rc.Host(call.Argument(0).String(), call.Argument(1).String()))
	})
	_ = t.Set("put", func(call goja.FunctionCall) goja.Value {
		ab, ok := call.Argument(0).Export().(goja.ArrayBuffer)
		if !ok {
			return rt.ToValue(-1)
		}
		b := ab.Bytes()
		off, n := int(call.Argument(1).ToInteger()), int(call.Argument(2).ToInteger())
		if off < 0 || n < 0 || off+n > len(b) {
			return rt.ToValue(-1)
		}
		return rt.ToValue(rc.Put(b[off : off+n]))
	})
	_ = t.Set("take", func(call goja.FunctionCall) goja.Value {
		b := rc.Take(call.Argument(0).ToInteger())
		ab := rt.NewArrayBuffer(append([]byte(nil), b...))
		o, err := rt.New(rt.Get("Uint8Array"), rt.ToValue(ab))
		if err != nil {
			panic(err)
		}
		return o
	})
	_ = rt.GlobalObject().DefineDataProperty("__tern", t, goja.FLAG_FALSE, goja.FLAG_FALSE, goja.FLAG_FALSE)
	if _, err := rt.RunProgram(pp); err != nil {
		return gojaErr(err)
	}
	if err := g.call(rc, "__tern_begin", setup); err != nil {
		return err
	}
	if _, err := rt.RunProgram(c.p); err != nil {
		return gojaErr(err)
	}
	return nil
}

func (gojaEngine) call(rc *runCtx, fn, arg string) error {
	rt := rc.rt.Load()
	if rt == nil {
		return &jsError{kind: "internal", msg: "脚本运行环境错误：运行时已释放"}
	}
	f, ok := goja.AssertFunction(rt.Get(fn))
	if !ok {
		return &jsError{kind: "internal", msg: "脚本运行环境错误：缺少 " + fn}
	}
	if _, err := f(goja.Undefined(), rt.ToValue(arg)); err != nil {
		return gojaErr(err)
	}
	return nil
}

func (gojaEngine) interrupt(rc *runCtx) {
	if rt := rc.rt.Load(); rt != nil {
		rt.Interrupt(stopName(rc.stop.Load()))
	}
}

func (gojaEngine) end(rc *runCtx) {}

func stopName(r int32) string {
	switch r {
	case stopMemory:
		return memInterrupt
	case stopCancelled:
		return cancelInterrupt
	}
	return "timeout"
}

// gojaErr classifies a goja error.
func gojaErr(err error) error {
	if err == nil {
		return nil
	}
	var ie *goja.InterruptedError
	if errors.As(err, &ie) {
		return &jsError{kind: "interrupted", msg: err.Error(), err: err}
	}
	var so *goja.StackOverflowError
	if errors.As(err, &so) {
		return &jsError{kind: "stack", msg: err.Error(), err: err}
	}
	var ex *goja.Exception
	if errors.As(err, &ex) {
		return &jsError{kind: "exception", msg: ex.Error(), err: err}
	}
	return err
}

// ---------------- engine choice ----------------

// EngineGoja / EngineNative name the engines (DebugInput.Engine, diagnostics).
const (
	EngineGoja   = "goja"
	EngineNative = "native"
)

// ScriptEngineName reports the engine new runs use ("native" when JavaScriptCore is registered and healthy).
func ScriptEngineName() string {
	if nativeUsable() {
		return EngineNative
	}
	return EngineGoja
}

// engineFor picks the engine for a run: a forced one (debug / conformance), else native when registered.
func engineFor(force string) (jsEngine, error) {
	switch force {
	case EngineGoja:
		return gojaJS, nil
	case EngineNative:
		if n := nativeEngineNow(); n != nil {
			return n, nil
		}
		return nil, errors.New("JavaScriptCore 脚本引擎未注册")
	}
	if n := nativeEngineNow(); n != nil {
		return n, nil
	}
	return gojaJS, nil
}

// ---------------- the run's host side ----------------

var runSeq atomic.Int64

// errDesc is the error JSON a native engine returns.
type errDesc struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

func parseNativeErr(s string) error {
	var d errDesc
	if json.Unmarshal([]byte(s), &d) != nil || d.Message == "" && d.Kind == "" {
		return &jsError{kind: "internal", msg: "脚本引擎错误：" + clip(s, 300)}
	}
	switch d.Kind {
	case "terminated":
		return &jsError{kind: "interrupted", msg: d.Message}
	case "exception":
		if strings.Contains(d.Message, "Maximum call stack size exceeded") {
			return &jsError{kind: "stack", msg: d.Message}
		}
		return &jsError{kind: "exception", msg: d.Message}
	case "syntax":
		return &jsError{kind: "syntax", msg: d.Message}
	}
	return &jsError{kind: "internal", msg: "脚本引擎错误：" + d.Message}
}
