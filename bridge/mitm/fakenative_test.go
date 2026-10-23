package mitm

// fakeNative is a NativeJS built on goja that behaves like PacketTunnel/JSCScriptEngine.swift: one context per
// loaded script, REUSED for every run (the prelude's reset between runs), a temporary context for a concurrent
// run, the script wrapped as a function created once at Load, stop through polling ShouldStop (JavaScriptCore's
// execution time limit), errors as {kind, message} JSON. It lets the Go tests drive the native adapter
// (jsnative.go) and the context-reuse semantics without a device:
//
//	TERN_TEST_NATIVE=1 go test ./mitm      # the whole suite through the native path
//
// TestEngineConformance always compares goja with it on the shared corpus.

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/dop251/goja"
)

type fakeCtx struct {
	rt      *goja.Runtime
	main    goja.Callable
	run     NativeRun
	busy    bool
	poison  bool
	stopped bool
}

type fakeEntry struct {
	key, name, src string
	wrapped        bool
	primary        *fakeCtx
	dropped        bool
}

type fakeSlot struct {
	c    *fakeCtx
	e    *fakeEntry
	temp bool
}

type fakeNative struct {
	mu       sync.Mutex
	prelude  *goja.Program
	entries  map[string]*fakeEntry
	runs     map[int64]*fakeSlot
	contexts int // made (tests)
	reused   int // runs on an existing context (tests)
}

func newFakeNative() *fakeNative {
	return &fakeNative{entries: map[string]*fakeEntry{}, runs: map[int64]*fakeSlot{}}
}

func init() {
	if os.Getenv("TERN_TEST_NATIVE") == "1" {
		if msg := SetNativeEngine(newFakeNative()); msg != "" {
			panic(msg)
		}
	}
}

func fakeErr(kind, msg string) string {
	b, _ := json.Marshal(map[string]string{"kind": kind, "message": msg})
	return string(b)
}

func (f *fakeNative) Prepare(p string) string {
	prog, err := goja.Compile("prelude.js", p, false)
	if err != nil {
		return err.Error()
	}
	f.prelude = prog
	return ""
}

func (f *fakeNative) newCtx() (*fakeCtx, error) {
	rt := goja.New()
	rt.SetMaxCallStackSize(scriptMaxCallStack)
	c := &fakeCtx{rt: rt}
	t := rt.NewObject()
	_ = t.Set("host", func(call goja.FunctionCall) goja.Value {
		if c.run == nil {
			return rt.ToValue("")
		}
		return rt.ToValue(c.run.Host(call.Argument(0).String(), call.Argument(1).String()))
	})
	_ = t.Set("put", func(call goja.FunctionCall) goja.Value {
		ab, ok := call.Argument(0).Export().(goja.ArrayBuffer)
		if !ok || c.run == nil {
			return rt.ToValue(-1)
		}
		b := ab.Bytes()
		off, n := int(call.Argument(1).ToInteger()), int(call.Argument(2).ToInteger())
		if off < 0 || n < 0 || off+n > len(b) {
			return rt.ToValue(-1)
		}
		return rt.ToValue(c.run.Put(b[off : off+n]))
	})
	_ = t.Set("take", func(call goja.FunctionCall) goja.Value {
		var b []byte
		if c.run != nil {
			b = c.run.Take(call.Argument(0).ToInteger())
		}
		o, _ := rt.New(rt.Get("Uint8Array"), rt.ToValue(rt.NewArrayBuffer(append([]byte(nil), b...))))
		return o
	})
	_ = rt.GlobalObject().DefineDataProperty("__tern", t, goja.FLAG_FALSE, goja.FLAG_FALSE, goja.FLAG_FALSE)
	if _, err := rt.RunProgram(f.prelude); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.contexts++
	f.mu.Unlock()
	return c, nil
}

func (f *fakeNative) loadMain(c *fakeCtx, e *fakeEntry) error {
	if !e.wrapped {
		return nil
	}
	p, err := goja.Compile(e.name+".js", "(function(){ return function(){\n"+e.src+"\n}; })()", false)
	if err != nil {
		return err
	}
	v, err := c.rt.RunProgram(p)
	if err != nil {
		return err
	}
	fn, ok := goja.AssertFunction(v)
	if !ok {
		return errors.New("not a function")
	}
	c.main = fn
	return nil
}

func (f *fakeNative) Load(key, name, src string) string {
	e := &fakeEntry{key: key, name: name, src: src, wrapped: true}
	if _, err := goja.Compile(name+".js", "(function(){ return function(){\n"+src+"\n}; })()", false); err != nil {
		if _, err2 := goja.Compile(name+".js", src, false); err2 != nil {
			return err.Error()
		}
		e.wrapped = false
	}
	c, err := f.newCtx()
	if err != nil {
		return "prelude: " + err.Error()
	}
	if err := f.loadMain(c, e); err != nil {
		return err.Error()
	}
	e.primary = c
	f.mu.Lock()
	if old := f.entries[e.key]; old != nil {
		old.dropped = true
	}
	f.entries[key] = e
	f.mu.Unlock()
	return ""
}

func (f *fakeNative) Drop(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e := f.entries[key]; e != nil {
		delete(f.entries, key)
		e.dropped = true
		if e.primary != nil && !e.primary.busy {
			e.primary = nil
		}
	}
}

func (f *fakeNative) Collect() {}

func (f *fakeNative) UsesGoHeap() bool { return true }

// exec runs fn on c, turning goja errors into the engine's error JSON; a watcher polls ShouldStop like
// JavaScriptCore's time-limit callback.
func (f *fakeNative) exec(c *fakeCtx, fn func() error) string {
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(10 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if c.run != nil && c.run.ShouldStop() {
					c.stopped = true
					c.rt.Interrupt("stop")
					return
				}
			}
		}
	}()
	err := fn()
	close(done)
	wg.Wait()
	if err == nil {
		return ""
	}
	var ie *goja.InterruptedError
	if errors.As(err, &ie) {
		c.poison = true
		c.rt.ClearInterrupt()
		return fakeErr("terminated", "terminated")
	}
	var so *goja.StackOverflowError
	if errors.As(err, &so) {
		return fakeErr("exception", "RangeError: Maximum call stack size exceeded.")
	}
	return fakeErr("exception", err.Error())
}

func (f *fakeNative) Begin(run NativeRun, key, setup string) string {
	f.mu.Lock()
	e := f.entries[key]
	if e == nil {
		f.mu.Unlock()
		return "missing"
	}
	var c *fakeCtx
	temp := false
	if p := e.primary; p != nil && !p.busy && !p.poison {
		c = p
		p.busy = true
		f.reused++
	}
	f.mu.Unlock()
	if c == nil {
		var err error
		c, err = f.newCtx()
		if err != nil {
			return fakeErr("internal", err.Error())
		}
		if err := f.loadMain(c, e); err != nil {
			return fakeErr("exception", err.Error())
		}
		c.busy = true
		f.mu.Lock()
		if e.primary == nil && !e.dropped {
			e.primary = c
		} else {
			temp = true
		}
		f.mu.Unlock()
	}
	c.run = run
	c.stopped = false
	f.mu.Lock()
	f.runs[run.ID()] = &fakeSlot{c: c, e: e, temp: temp}
	f.mu.Unlock()
	if r := f.call(c, "__tern_begin", setup); r != "" {
		return r
	}
	return f.exec(c, func() error {
		if c.main != nil {
			_, err := c.main(goja.Undefined())
			return err
		}
		_, err := c.rt.RunString(e.src)
		return err
	})
}

func (f *fakeNative) call(c *fakeCtx, fn, arg string) string {
	g, ok := goja.AssertFunction(c.rt.Get(fn))
	if !ok {
		return fakeErr("internal", "missing "+fn)
	}
	return f.exec(c, func() error {
		_, err := g(goja.Undefined(), c.rt.ToValue(arg))
		return err
	})
}

func (f *fakeNative) Call(runID int64, fn, arg string) string {
	f.mu.Lock()
	s := f.runs[runID]
	f.mu.Unlock()
	if s == nil {
		return fakeErr("internal", "unknown run")
	}
	return f.call(s.c, fn, arg)
}

func (f *fakeNative) End(runID int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.runs[runID]
	if s == nil {
		return
	}
	delete(f.runs, runID)
	s.c.run = nil
	s.c.busy = false
	if s.temp || s.c.poison || s.c.stopped || s.e.dropped {
		if s.e.primary == s.c {
			s.e.primary = nil
		}
	}
}
