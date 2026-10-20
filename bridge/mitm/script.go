package mitm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime/debug"
	"runtime/metrics"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/dop251/goja"
)

// ScriptHTTP is the request or response handed to a script.
type ScriptHTTP struct {
	URL     string
	Method  string
	Status  int
	Header  http.Header
	Body    []byte
	HasBody bool
	// Host is the request's Host (Go keeps it out of Header); exposed as $request.headers.Host.
	Host string
}

// ScriptResult is what $done() asked for.
type ScriptResult struct {
	URL      string
	Method   string
	Status   int
	Header   http.Header
	Body     []byte
	BodySet  bool
	Response *ScriptHTTP // request phase: answer locally
	Abort    bool        // Egern ctx.abort(): drop the request / fail the response
}

// ScriptRunner executes scripts with goja. A fresh Runtime per run (isolation like Surge), compiled
// programs cached (LRU), and a small concurrency cap so the extension's memory stays bounded.
type ScriptRunner struct {
	e       *Engine
	progs   *lru[*goja.Program]
	sem     chan struct{} // HTTP scripts
	taskSem chan struct{} // cron / event / generic scripts (long running, kept apart from HTTP traffic)
	mu      sync.Mutex
	byURL   map[string]string // script path -> program cache key
	// v0.19.6: compiles in flight by cache key (one compile per script for a burst of cold requests).
	compiling map[string]*compileCall
}

type compileCall struct {
	done chan struct{}
	p    *goja.Program
	err  error
}

// compileCount counts goja compiles (tests).
var compileCount atomic.Int64

func NewScriptRunner(e *Engine) *ScriptRunner {
	progs := newLRU[*goja.Program](16)
	progs.maxW = progCacheBudget
	return &ScriptRunner{e: e, progs: progs, sem: make(chan struct{}, 2), taskSem: make(chan struct{}, 1), byURL: map[string]string{}}
}

// Reset drops compiled programs (memory).
func (s *ScriptRunner) Reset() { s.progs.Reset() }

// Invalidate forgets a program after its source was re-downloaded.
func (s *ScriptRunner) Invalidate(path string) {
	s.mu.Lock()
	delete(s.byURL, path)
	s.mu.Unlock()
}

func (s *ScriptRunner) program(sc *Script) (prog *goja.Program, err error) {
	src := sc.Source
	if src == nil {
		var err error
		src, err = s.e.res.Get(sc.Path, sc.UpdateInterval)
		if err != nil {
			return nil, fmt.Errorf("加载脚本失败：%w", err)
		}
	}
	sum := sha256.Sum256(src)
	key := hex.EncodeToString(sum[:])
	if p, ok := s.progs.Get(key); ok {
		return p, nil
	}
	// v0.19.6 (review 7): compile runs before the run semaphore, so a burst of requests on a script whose
	// program was not cached (first use after a start, or right after FreeMemory dropped the cache under
	// memory pressure) compiled it once per request in parallel, ~14× the source in heap each (24 requests
	// on a 330 KB script: 24 compiles). Concurrent callers for one key now wait for a single compile.
	s.mu.Lock()
	if c, ok := s.compiling[key]; ok {
		s.mu.Unlock()
		<-c.done
		return c.p, c.err
	}
	if p, ok := s.progs.Get(key); ok { // finished between the check above and the lock
		s.mu.Unlock()
		return p, nil
	}
	if s.compiling == nil {
		s.compiling = map[string]*compileCall{}
	}
	c := &compileCall{done: make(chan struct{})}
	s.compiling[key] = c
	s.mu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			c.p, c.err = nil, fmt.Errorf("脚本编译内部错误：%v", r)
			prog, err = nil, c.err
		}
		s.mu.Lock()
		delete(s.compiling, key)
		s.mu.Unlock()
		close(c.done)
	}()
	c.p, c.err = s.compile(sc, src, key)
	return c.p, c.err
}

func (s *ScriptRunner) compile(sc *Script, src []byte, key string) (*goja.Program, error) {
	compileCount.Add(1)
	code := strings.TrimPrefix(string(src), "\ufeff")
	if egernNativeRe.MatchString(code) {
		adapted, err := adaptEgern(code)
		if err != nil {
			return nil, err
		}
		code = adapted
	}
	// Wrap so a top-level `return` (allowed by Surge/JSC scripts) does not break compilation.
	p, err := goja.Compile(sc.Name+".js", "(function(){\n"+code+"\n}).call(this);", false)
	if err != nil {
		p2, err2 := goja.Compile(sc.Name+".js", code, false)
		if err2 != nil {
			return nil, fmt.Errorf("脚本语法错误：%v", err)
		}
		p = p2
	}
	s.progs.PutW(key, p, int64(len(code))*progBytesPerSourceByte)
	return p, nil
}

// A compiled goja Program takes ~14× its source in heap (measured: 300 KB of JS → ~4.1 MB). 16 cached
// programs of large module scripts (100–500 KB is common) used to sit at tens of MB inside the 50 MB
// extension. The cache now has a budget on the estimated compiled size; evicted scripts are compiled
// again on their next run.
const (
	progBytesPerSourceByte = 14
	progCacheBudget        = 8 << 20
)

type loopJob func()

// liveRuntimes counts goja runtimes that exist right now. Every run creates one and drops it when the
// run returns (nothing keeps a reference: timers are stopped, late callbacks see a cancelled context),
// so this is at most the semaphore sizes (2 HTTP + 1 task) at any moment.
var liveRuntimes atomic.Int64

// LiveRuntimes reports how many script runtimes are alive (diagnostics, memory samples, tests).
func LiveRuntimes() int64 { return liveRuntimes.Load() }

type runCtx struct {
	rt      *goja.Runtime
	jobs    chan loopJob
	pending int
	done    bool
	result  goja.Value
	script  *Script
	name    string
	e       *Engine
	ctx     context.Context
	timers  map[int64]*time.Timer
	// origSetCookie holds the response's Set-Cookie lines when there were several (review5 P2-3).
	origSetCookie []string
	timerID       int64
	// Debug runs (脚本调试): console output and notifications are captured instead of going to the
	// engine's rings / the user's notification history.
	onLog    func(level, msg string)
	onNotify func(title, sub, body, url string)
}

func (rc *runCtx) post(j loopJob) {
	select {
	case rc.jobs <- j:
	case <-rc.ctx.Done():
	}
}

// Run executes a script rule. resp == nil means request phase.
func (s *ScriptRunner) Run(parent context.Context, rule *Rule, req, resp *ScriptHTTP) (*ScriptResult, error) {
	return s.run(rule, req, resp, s.sem)
}

// Reserve takes an HTTP-script slot ahead of RunReserved (review5 P0-1: the slot is taken before the
// body is loaded, so queued scripts don't each hold a body). The returned release is idempotent.
func (s *ScriptRunner) Reserve(rule *Rule) (func(), error) {
	select {
	case s.sem <- struct{}{}:
	case <-time.After(scriptTimeout(rule.Script, 120*time.Second, 10*time.Second)):
		return nil, errors.New("脚本排队超时")
	}
	var once sync.Once
	return func() { once.Do(func() { <-s.sem }) }, nil
}

// RunReserved is Run for a caller already holding a slot from Reserve.
func (s *ScriptRunner) RunReserved(parent context.Context, rule *Rule, req, resp *ScriptHTTP) (*ScriptResult, error) {
	return s.run(rule, req, resp, nil)
}

func scriptTimeout(sc *Script, maxTimeout, defTimeout time.Duration) time.Duration {
	timeout := time.Duration(sc.Timeout) * time.Second
	if timeout <= 0 {
		timeout = defTimeout
	}
	if timeout > maxTimeout {
		timeout = maxTimeout
	}
	return timeout
}

// bodyLimit is the largest body the script is handed (its max-size, at most MaxBody).
func (sc *Script) bodyLimit() int {
	if sc.MaxSize > 0 && sc.MaxSize < MaxBody {
		return sc.MaxSize
	}
	return MaxBody
}

func (s *ScriptRunner) run(rule *Rule, req, resp *ScriptHTTP, sem chan struct{}) (*ScriptResult, error) {
	rc, err := s.execute(rule.Script, req, resp, sem, 120*time.Second, 10*time.Second, nil)
	if err != nil {
		return nil, err
	}
	if !rc.done {
		return &ScriptResult{}, nil
	}
	return rc.parseDone(resp == nil)
}

// execute compiles + runs one script in a fresh runtime and drives its event loop until $done or until
// nothing is pending. req == nil => task script (no $request / $response).
func (s *ScriptRunner) execute(sc *Script, req, resp *ScriptHTTP, sem chan struct{}, maxTimeout, defTimeout time.Duration, setup func(*runCtx)) (rcOut *runCtx, errOut error) {
	// v0.19.3: a Go panic inside a native helper must not take the tunnel down (task scripts run on the
	// scheduler goroutine, which has no net/http recover around it).
	defer func() {
		if p := recover(); p != nil {
			rcOut, errOut = nil, fmt.Errorf("脚本运行时内部错误：%v", p)
		}
	}()
	prog, err := s.program(sc)
	if err != nil {
		return nil, err
	}
	timeout := scriptTimeout(sc, maxTimeout, defTimeout)
	if sem != nil { // nil: the caller holds a slot (Reserve)
		select {
		case sem <- struct{}{}:
		case <-time.After(timeout):
			return nil, errors.New("脚本排队超时")
		}
		defer func() { <-sem }()
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	rt := goja.New()
	// v0.19.3: goja's default call-stack limit is MaxInt32, so `function f(){f()} f()` grew the heap by
	// ~25 MB/s until jetsam killed the extension long before the timeout. JSC (Surge) throws RangeError.
	rt.SetMaxCallStackSize(scriptMaxCallStack)
	liveRuntimes.Add(1)
	defer liveRuntimes.Add(-1)
	rc := &runCtx{rt: rt, jobs: make(chan loopJob, 8), script: sc, name: sc.Name, e: s.e, ctx: ctx, timers: map[int64]*time.Timer{}}
	defer func() {
		for _, t := range rc.timers {
			t.Stop()
		}
	}()
	start := time.Now()
	if err := rc.install(req, resp); err != nil {
		return nil, err
	}
	if setup != nil {
		setup(rc)
	}
	stop := context.AfterFunc(ctx, func() { rt.Interrupt("timeout") })
	defer stop()
	stopGuard := startMemGuard(ctx, rt)
	defer stopGuard()

	_, err = rt.RunProgram(prog)
	if err != nil {
		return nil, s.jsErr(sc, err, timeout)
	}
	for !rc.done {
		if rc.pending <= 0 && len(rc.jobs) == 0 {
			break // nothing left to wait for and $done never called => unchanged
		}
		select {
		case j := <-rc.jobs:
			func() {
				defer func() {
					if p := recover(); p != nil {
						if pe, ok := p.(error); ok {
							err = pe // keeps *goja.Exception / StackOverflowError / InterruptedError for jsErr
						} else {
							err = fmt.Errorf("%v", p)
						}
					}
				}()
				j()
			}()
			if err != nil {
				return nil, s.jsErr(sc, err, timeout)
			}
		case <-ctx.Done():
			return nil, fmt.Errorf("脚本执行超时（%s）", timeout)
		}
	}
	if rc.onLog == nil {
		s.e.Logs.Add(sc.Name, "debug", fmt.Sprintf("执行完成，用时 %d ms", time.Since(start).Milliseconds()))
	}
	return rc, nil
}

func (s *ScriptRunner) jsErr(sc *Script, err error, timeout time.Duration) error {
	var ie *goja.InterruptedError
	if errors.As(err, &ie) {
		if v, _ := ie.Value().(string); v == memInterrupt {
			return errors.New("脚本内存占用过高，已终止（保护隧道内存）")
		}
		return fmt.Errorf("脚本执行超时（%s）", timeout)
	}
	var so *goja.StackOverflowError
	if errors.As(err, &so) {
		return errors.New("脚本调用栈溢出（递归过深）")
	}
	var ex *goja.Exception
	if errors.As(err, &ex) {
		return fmt.Errorf("脚本异常：%s", clip(ex.Error(), 400))
	}
	return err
}

// scriptMaxCallStack bounds JS recursion (frames). JSC allows roughly this order of magnitude too.
const scriptMaxCallStack = 3000

const memInterrupt = "memory"

// memGuardHook lets tests force a limit; nil in production.
var memGuardLimit = func() int64 { return debug.SetMemoryLimit(-1) }

// startMemGuard interrupts the runtime when the Go heap nears the soft memory limit (GOMEMLIMIT is set
// in the extension from the jetsam budget). A script that builds huge strings / arrays would otherwise
// push the extension over its ~50 MB budget and the system kills the tunnel. No limit set (app, tests)
// => no guard.
func startMemGuard(ctx context.Context, rt *goja.Runtime) func() {
	limit := memGuardLimit()
	if limit <= 0 || limit >= 1<<40 {
		return func() {}
	}
	threshold := uint64(limit) / 10 * 9
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(50 * time.Millisecond)
		defer t.Stop()
		sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				metrics.Read(sample)
				if sample[0].Value.Kind() == metrics.KindUint64 && sample[0].Value.Uint64() > threshold {
					rt.Interrupt(memInterrupt)
					return
				}
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}

// ---- headers as a case-insensitive JS object ----

type ciHeaders struct {
	rt   *goja.Runtime
	keys []string
	vals map[string]goja.Value // by lower-case key
	orig map[string]string     // lower -> original key
}

func newCIHeaders(rt *goja.Runtime, h http.Header) *ciHeaders {
	c := &ciHeaders{rt: rt, vals: map[string]goja.Value{}, orig: map[string]string{}}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := h[k]
		var jv goja.Value
		// Set-Cookie is joined like Surge does; parseDone splits it back (review5 P2-3).
		jv = rt.ToValue(strings.Join(v, ", "))
		c.set(k, jv)
	}
	return c
}

func (c *ciHeaders) set(k string, v goja.Value) {
	lk := strings.ToLower(k)
	if _, ok := c.orig[lk]; !ok {
		c.keys = append(c.keys, k)
		c.orig[lk] = k
	}
	c.vals[lk] = v
}
func (c *ciHeaders) Get(k string) goja.Value { return c.vals[strings.ToLower(k)] }
func (c *ciHeaders) Set(k string, v goja.Value) bool {
	if goja.IsUndefined(v) {
		c.Delete(k)
		return true
	}
	c.set(k, v)
	return true
}
func (c *ciHeaders) Has(k string) bool { _, ok := c.vals[strings.ToLower(k)]; return ok }
func (c *ciHeaders) Delete(k string) bool {
	lk := strings.ToLower(k)
	if o, ok := c.orig[lk]; ok {
		delete(c.vals, lk)
		delete(c.orig, lk)
		for i, kk := range c.keys {
			if kk == o {
				c.keys = append(c.keys[:i], c.keys[i+1:]...)
				break
			}
		}
	}
	return true
}
func (c *ciHeaders) Keys() []string { return append([]string(nil), c.keys...) }

// fixSetCookie undoes the ", " join scripts see (review5 P2-3): an unchanged value gets the original
// lines back, a changed one is split before each "name=" that starts a new cookie.
func fixSetCookie(h http.Header, orig []string) {
	vs := h.Values("Set-Cookie")
	if len(vs) != 1 {
		return
	}
	if len(orig) > 1 && vs[0] == strings.Join(orig, ", ") {
		h["Set-Cookie"] = append([]string(nil), orig...)
		return
	}
	if parts := splitSetCookie(vs[0]); len(parts) > 1 {
		h["Set-Cookie"] = parts
	}
}

// splitSetCookie splits a comma-joined Set-Cookie value at commas followed by `token=` (the comma in
// "Expires=Wed, 21 Oct 2027 ..." is followed by a date, not a cookie name).
func splitSetCookie(v string) []string {
	var out []string
	start := 0
	for i := 0; i < len(v); i++ {
		if v[i] != ',' {
			continue
		}
		j := i + 1
		for j < len(v) && (v[j] == ' ' || v[j] == '\t') {
			j++
		}
		k := j
		for k < len(v) && v[k] != '=' && v[k] != ';' && v[k] != ',' && v[k] != ' ' && v[k] != '\t' {
			k++
		}
		if k > j && k < len(v) && v[k] == '=' {
			out = append(out, strings.TrimSpace(v[start:i]))
			start = j
		}
	}
	return append(out, strings.TrimSpace(v[start:]))
}

func toHeader(rt *goja.Runtime, v goja.Value) http.Header {
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return nil
	}
	obj := v.ToObject(rt)
	h := http.Header{}
	for _, k := range obj.Keys() {
		val := obj.Get(k)
		if val == nil || goja.IsUndefined(val) || goja.IsNull(val) {
			continue
		}
		if arr, ok := val.Export().([]any); ok {
			for _, a := range arr {
				h.Add(k, fmt.Sprint(a))
			}
			continue
		}
		h.Add(k, val.String())
	}
	return h
}

// ---- bodies ----

func (rc *runCtx) uint8Array(b []byte) goja.Value {
	ab := rc.rt.NewArrayBuffer(append([]byte(nil), b...))
	ctor := rc.rt.Get("Uint8Array")
	o, err := rc.rt.New(ctor, rc.rt.ToValue(ab))
	if err != nil {
		return rc.rt.ToValue(ab)
	}
	return o
}

// bodyBytes converts a JS value (string / ArrayBuffer / TypedArray / object) into bytes.
func (rc *runCtx) bodyBytes(v goja.Value) ([]byte, bool) {
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return nil, false
	}
	switch x := v.Export().(type) {
	case string:
		return []byte(x), true
	case goja.ArrayBuffer:
		return append([]byte(nil), x.Bytes()...), true
	case []byte:
		return append([]byte(nil), x...), true
	}
	obj := v.ToObject(rc.rt)
	if buf := obj.Get("buffer"); buf != nil {
		if ab, ok := buf.Export().(goja.ArrayBuffer); ok {
			off := int(obj.Get("byteOffset").ToInteger())
			n := int(obj.Get("byteLength").ToInteger())
			b := ab.Bytes()
			if off >= 0 && off+n <= len(b) {
				return append([]byte(nil), b[off:off+n]...), true
			}
		}
	}
	// plain object => JSON
	if b, err := json.Marshal(v.Export()); err == nil {
		return b, true
	}
	return []byte(v.String()), true
}

func bodyString(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	return strings.ToValidUTF8(string(b), "\uFFFD")
}

// ---- API installation ----

func (rc *runCtx) install(req, resp *ScriptHTTP) error {
	rt := rc.rt
	set := func(name string, v any) { _ = rt.Set(name, v) }
	if req != nil {
		rc.installHTTP(req, resp)
	}
	rc.installCommon(set)
	return nil
}

func (rc *runCtx) installHTTP(req, resp *ScriptHTTP) {
	rt := rc.rt
	sc := rc.script
	set := func(name string, v any) { _ = rt.Set(name, v) }
	// $request
	ro := rt.NewObject()
	_ = ro.Set("url", req.URL)
	_ = ro.Set("method", req.Method)
	rh := req.Header
	if req.Host != "" && rh.Get("Host") == "" {
		// review5 P2-4: Go moves Host out of the header map; scripts expect to see it.
		rh = rh.Clone()
		if rh == nil {
			rh = http.Header{}
		}
		rh.Set("Host", req.Host)
	}
	_ = ro.Set("headers", rt.NewDynamicObject(newCIHeaders(rt, rh)))
	_ = ro.Set("id", strconv.FormatInt(time.Now().UnixNano(), 36))
	if resp == nil && req.HasBody {
		if sc.BinaryBody {
			_ = ro.Set("body", rc.uint8Array(req.Body))
			_ = ro.Set("bodyBytes", rt.NewArrayBuffer(append([]byte(nil), req.Body...)))
		} else {
			_ = ro.Set("body", bodyString(req.Body))
		}
	}
	set("$request", ro)
	if resp != nil {
		so := rt.NewObject()
		_ = so.Set("status", resp.Status)
		_ = so.Set("statusCode", resp.Status)
		if sc := resp.Header.Values("Set-Cookie"); len(sc) > 1 {
			rc.origSetCookie = append([]string(nil), sc...)
		}
		_ = so.Set("headers", rt.NewDynamicObject(newCIHeaders(rt, resp.Header)))
		if resp.HasBody {
			if sc.BinaryBody {
				_ = so.Set("body", rc.uint8Array(resp.Body))
				_ = so.Set("bodyBytes", rt.NewArrayBuffer(append([]byte(nil), resp.Body...)))
			} else {
				_ = so.Set("body", bodyString(resp.Body))
			}
		}
		set("$response", so)
	}
}

func (rc *runCtx) installCommon(set func(string, any)) {
	rt := rc.rt
	sc := rc.script
	// $done
	set("$done", func(call goja.FunctionCall) goja.Value {
		if rc.done {
			return goja.Undefined()
		}
		rc.done = true
		rc.result = call.Argument(0)
		return goja.Undefined()
	})

	if sc.HasArgument {
		set("$argument", sc.Argument)
	} else {
		set("$argument", goja.Undefined()) // declared, so `if ($argument)` does not throw
	}
	scr := rt.NewObject()
	_ = scr.Set("name", sc.Name)
	_ = scr.Set("type", sc.Type)
	_ = scr.Set("startTime", rt.ToValue(time.Now()))
	_ = scr.Set("path", sc.Path)
	set("$script", scr)
	env := rt.NewObject()
	_ = env.Set("surge-version", "5.20.0")
	_ = env.Set("surge-build", "3000")
	_ = env.Set("language", "zh-Hans")
	_ = env.Set("system", "iOS")
	_ = env.Set("mihomo-ios", true)
	set("$environment", env)

	// console
	con := rt.NewObject()
	for _, lv := range []string{"log", "info", "warn", "error", "debug"} {
		level := lv
		_ = con.Set(lv, func(call goja.FunctionCall) goja.Value {
			parts := make([]string, 0, len(call.Arguments))
			for _, a := range call.Arguments {
				parts = append(parts, jsString(rt, a))
			}
			msg := strings.Join(parts, " ")
			if rc.onLog != nil {
				rc.onLog(level, msg)
				return goja.Undefined()
			}
			rc.e.Logs.Add(rc.name, level, msg)
			return goja.Undefined()
		})
	}
	set("console", con)

	// timers
	set("setTimeout", func(call goja.FunctionCall) goja.Value { return rc.addTimer(call, false) })
	set("setInterval", func(call goja.FunctionCall) goja.Value { return rc.addTimer(call, true) })
	clear := func(call goja.FunctionCall) goja.Value {
		id := call.Argument(0).ToInteger()
		if t, ok := rc.timers[id]; ok {
			t.Stop()
			delete(rc.timers, id)
			rc.pending--
		}
		return goja.Undefined()
	}
	set("clearTimeout", clear)
	set("clearInterval", clear)

	// $persistentStore (Surge) / $prefs (QX)
	keyFor := func(v goja.Value) string {
		if v == nil || goja.IsUndefined(v) || goja.IsNull(v) || v.String() == "" {
			return "@script:" + sc.Name
		}
		return v.String()
	}
	ps := rt.NewObject()
	_ = ps.Set("read", func(call goja.FunctionCall) goja.Value {
		if v, ok := rc.e.Store.Read(keyFor(call.Argument(0))); ok {
			return rt.ToValue(v)
		}
		return goja.Null()
	})
	_ = ps.Set("write", func(call goja.FunctionCall) goja.Value {
		v := call.Argument(0)
		del := goja.IsUndefined(v) || goja.IsNull(v)
		return rt.ToValue(rc.e.Store.Write(keyFor(call.Argument(1)), jsString(rt, v), del))
	})
	set("$persistentStore", ps)
	prefs := rt.NewObject()
	_ = prefs.Set("valueForKey", func(call goja.FunctionCall) goja.Value {
		if v, ok := rc.e.Store.Read(call.Argument(0).String()); ok {
			return rt.ToValue(v)
		}
		return goja.Undefined()
	})
	_ = prefs.Set("setValueForKey", func(call goja.FunctionCall) goja.Value {
		return rt.ToValue(rc.e.Store.Write(call.Argument(1).String(), jsString(rt, call.Argument(0)), false))
	})
	_ = prefs.Set("removeValueForKey", func(call goja.FunctionCall) goja.Value {
		return rt.ToValue(rc.e.Store.Write(call.Argument(0).String(), "", true))
	})
	_ = prefs.Set("removeAllValues", func(call goja.FunctionCall) goja.Value { return rt.ToValue(rc.e.Store.Clear()) })
	set("$prefs", prefs)

	// notifications
	post := func(title, sub, body, url string) {
		// review5 P2-6: bounded fields (the history file is rewritten on every post) and a per-script
		// rate limit so a debug loop can't flood iOS notifications.
		title, sub = clipBytes(title, noticeShortMax), clipBytes(sub, noticeShortMax)
		body, url = clipBytes(body, noticeLongMax), clipBytes(url, noticeLongMax)
		if rc.onNotify != nil {
			rc.onNotify(title, sub, body, url)
			return
		}
		if !noticeRate.allow(rc.name) {
			rc.e.Logs.Add(rc.name, "warn", "通知过于频繁，已丢弃："+clip(title, 60))
			return
		}
		rc.e.Logs.Add(rc.name, "notify", strings.TrimSpace(title+" | "+sub+" | "+body))
		rc.e.Notices.Add(Notice{Script: rc.name, Title: title, Subtitle: sub, Body: body, URL: url})
		if n := rc.e.notify.Load(); n != nil && *n != nil {
			(*n)(title, sub, body, url)
		}
	}
	optURL := func(v goja.Value) string {
		if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
			return ""
		}
		if s, ok := v.Export().(string); ok {
			return s
		}
		o := v.ToObject(rt)
		for _, k := range []string{"url", "open-url", "openUrl", "action-url"} {
			if x := o.Get(k); x != nil && !goja.IsUndefined(x) {
				return x.String()
			}
		}
		return ""
	}
	argStr := func(call goja.FunctionCall, i int) string {
		v := call.Argument(i)
		if goja.IsUndefined(v) || goja.IsNull(v) {
			return ""
		}
		return v.String()
	}
	notif := rt.NewObject()
	_ = notif.Set("post", func(call goja.FunctionCall) goja.Value {
		post(argStr(call, 0), argStr(call, 1), argStr(call, 2), optURL(call.Argument(3)))
		return goja.Undefined()
	})
	set("$notification", notif)
	set("$notify", func(call goja.FunctionCall) goja.Value {
		post(argStr(call, 0), argStr(call, 1), argStr(call, 2), optURL(call.Argument(3)))
		return goja.Undefined()
	})

	// $httpClient (Surge)
	hc := rt.NewObject()
	for _, m := range []string{"get", "post", "put", "delete", "head", "options", "patch"} {
		method := strings.ToUpper(m)
		_ = hc.Set(m, func(call goja.FunctionCall) goja.Value {
			rc.httpClient(method, call.Argument(0), call.Argument(1))
			return goja.Undefined()
		})
	}
	set("$httpClient", hc)

	// $httpAPI (Surge): policy groups, outbound mode, profile reload — answered by the bridge.
	set("$httpAPI", func(call goja.FunctionCall) goja.Value {
		method := strings.ToUpper(argStr(call, 0))
		path := argStr(call, 1)
		var body any
		if b := call.Argument(2); !goja.IsUndefined(b) && !goja.IsNull(b) {
			body = b.Export()
			if s, ok := body.(string); ok {
				var m map[string]any
				if json.Unmarshal([]byte(s), &m) == nil {
					body = m
				}
			}
		}
		fn, _ := goja.AssertFunction(call.Argument(3))
		res, err := rc.e.callAPI(method, path, body)
		if err != nil {
			rc.e.Logs.Add(rc.name, "warning", "$httpAPI "+method+" "+path+"："+err.Error())
			res = map[string]any{"error": err.Error()}
		}
		if fn != nil {
			rc.pending++
			rc.post(func() {
				rc.pending--
				if _, e := fn(goja.Undefined(), rt.ToValue(res)); e != nil {
					panic(e)
				}
			})
		}
		return goja.Undefined()
	})

	// $task.fetch (QX)
	task := rt.NewObject()
	_ = task.Set("fetch", func(call goja.FunctionCall) goja.Value { return rc.taskFetch(call.Argument(0)) })
	set("$task", task)

	// small helpers JavaScriptCore / browsers have and bundled scripts expect
	te := func(call goja.ConstructorCall) *goja.Object {
		_ = call.This.Set("encoding", "utf-8")
		_ = call.This.Set("encode", func(c goja.FunctionCall) goja.Value {
			s := ""
			if !goja.IsUndefined(c.Argument(0)) {
				s = c.Argument(0).String()
			}
			return rc.uint8Array([]byte(s))
		})
		return nil
	}
	set("TextEncoder", te)
	td := func(call goja.ConstructorCall) *goja.Object {
		_ = call.This.Set("encoding", "utf-8")
		_ = call.This.Set("decode", func(c goja.FunctionCall) goja.Value {
			b, _ := rc.bodyBytes(c.Argument(0))
			return rt.ToValue(bodyString(b))
		})
		return nil
	}
	set("TextDecoder", td)
	set("btoa", func(call goja.FunctionCall) goja.Value {
		s := call.Argument(0).String()
		b := make([]byte, 0, len(s))
		for _, r := range s {
			b = append(b, byte(r))
		}
		return rt.ToValue(base64.StdEncoding.EncodeToString(b))
	})
	set("atob", func(call goja.FunctionCall) goja.Value {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(call.Argument(0).String()))
		if err != nil {
			b, _ = base64.RawStdEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(call.Argument(0).String()), "="))
		}
		rs := make([]rune, len(b))
		for i, c := range b {
			rs[i] = rune(c)
		}
		return rt.ToValue(string(rs))
	})
	rc.installUtils(set)
	rc.installEgern(set)
}

func jsString(rt *goja.Runtime, v goja.Value) string {
	if v == nil || goja.IsUndefined(v) {
		return "undefined"
	}
	if goja.IsNull(v) {
		return "null"
	}
	if _, ok := v.Export().(string); ok {
		return v.String()
	}
	if o, ok := v.(*goja.Object); ok {
		if o.ClassName() == "Error" {
			return o.String()
		}
		if b, err := json.Marshal(o.Export()); err == nil {
			return string(b)
		}
	}
	return v.String()
}

func (rc *runCtx) addTimer(call goja.FunctionCall, repeat bool) goja.Value {
	fn, ok := goja.AssertFunction(call.Argument(0))
	if !ok {
		return goja.Undefined()
	}
	ms := call.Argument(1).ToInteger()
	if ms < 0 {
		ms = 0
	}
	if repeat && ms < 10 {
		ms = 10
	}
	args := append([]goja.Value(nil), call.Arguments[min(2, len(call.Arguments)):]...)
	rc.timerID++
	id := rc.timerID
	rc.pending++
	var t *time.Timer
	var fire func()
	fire = func() {
		rc.post(func() {
			if _, ok := rc.timers[id]; !ok {
				return
			}
			if !repeat {
				delete(rc.timers, id)
				rc.pending--
			} else {
				rc.timers[id] = time.AfterFunc(time.Duration(ms)*time.Millisecond, fire)
			}
			if _, err := fn(goja.Undefined(), args...); err != nil {
				panic(err)
			}
		})
	}
	t = time.AfterFunc(time.Duration(ms)*time.Millisecond, fire)
	rc.timers[id] = t
	return rc.rt.ToValue(id)
}

type fetchReq struct {
	url, method, policy string
	headers             http.Header
	body                []byte
	timeout             time.Duration
	binary, insecure    bool
	noRedirect          bool
}

func (rc *runCtx) parseFetch(method string, v goja.Value) (*fetchReq, error) {
	fr := &fetchReq{method: method, headers: http.Header{}, timeout: 15 * time.Second}
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return nil, errors.New("缺少请求参数")
	}
	if s, ok := v.Export().(string); ok {
		fr.url = s
		return fr, nil
	}
	o := v.ToObject(rc.rt)
	get := func(k string) goja.Value {
		x := o.Get(k)
		if x == nil || goja.IsUndefined(x) || goja.IsNull(x) {
			return nil
		}
		return x
	}
	if x := get("url"); x != nil {
		fr.url = x.String()
	}
	if x := get("method"); x != nil && method == "" {
		fr.method = strings.ToUpper(x.String())
	}
	if fr.method == "" {
		fr.method = "GET"
	}
	if x := get("headers"); x != nil {
		fr.headers = toHeader(rc.rt, x)
	}
	if x := get("body"); x != nil {
		fr.body, _ = rc.bodyBytes(x)
	} else if x := get("bodyBytes"); x != nil {
		fr.body, _ = rc.bodyBytes(x)
	}
	if x := get("timeout"); x != nil {
		t := x.ToFloat()
		if t > 0 {
			// QX ($task.fetch, method "") documents milliseconds; Surge ($httpClient) seconds. Large Surge
			// values are milliseconds in practice too.
			if method == "" || t > 1000 {
				fr.timeout = time.Duration(t) * time.Millisecond
			} else {
				fr.timeout = time.Duration(t * float64(time.Second))
			}
		}
	}
	if x := get("binary-mode"); x != nil {
		fr.binary = x.ToBoolean()
	}
	if x := get("policy"); x != nil {
		fr.policy = x.String()
	}
	if x := get("insecure"); x != nil {
		fr.insecure = x.ToBoolean()
	}
	if x := get("auto-redirect"); x != nil && !x.ToBoolean() {
		fr.noRedirect = true
	}
	if x := get("opts"); x != nil {
		oo := x.ToObject(rc.rt)
		if p := oo.Get("policy"); p != nil && !goja.IsUndefined(p) {
			fr.policy = p.String()
		}
		if r := oo.Get("redirection"); r != nil && !goja.IsUndefined(r) && !r.ToBoolean() {
			fr.noRedirect = true
		}
	}
	if fr.url == "" {
		return nil, errors.New("缺少 url")
	}
	return fr, nil
}

type fetchResp struct {
	status int
	header http.Header
	body   []byte
	err    error
}

func (rc *runCtx) do(fr *fetchReq) *fetchResp {
	ctx, cancel := context.WithTimeout(rc.ctx, fr.timeout)
	defer cancel()
	var body io.Reader
	if len(fr.body) > 0 {
		body = bytes.NewReader(fr.body)
	}
	req, err := http.NewRequestWithContext(ctx, fr.method, fr.url, body)
	if err != nil {
		return &fetchResp{err: err}
	}
	req.Header = fr.headers
	if req.Header == nil {
		req.Header = http.Header{}
	}
	if h := req.Header.Get("Host"); h != "" {
		req.Host = h
		req.Header.Del("Host")
	}
	req.Header.Del("Content-Length")
	c := rc.e.client(fr.policy, fr.insecure)
	if fr.noRedirect {
		c2 := *c
		c2.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		c = &c2
	}
	resp, err := c.Do(req)
	if err != nil {
		return &fetchResp{err: err}
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
	if err != nil {
		return &fetchResp{err: err}
	}
	return &fetchResp{status: resp.StatusCode, header: resp.Header, body: b}
}

func (rc *runCtx) httpClient(method string, opts, cb goja.Value) {
	fn, _ := goja.AssertFunction(cb)
	fr, err := rc.parseFetch(method, opts)
	if err != nil {
		if fn != nil {
			_, _ = fn(goja.Undefined(), rc.rt.ToValue(err.Error()), goja.Null(), goja.Null())
		}
		return
	}
	rc.pending++
	go func() {
		res := rc.do(fr)
		rc.post(func() {
			rc.pending--
			if fn == nil {
				return
			}
			var e error
			if res.err != nil {
				_, e = fn(goja.Undefined(), rc.rt.ToValue(res.err.Error()), goja.Null(), goja.Null())
			} else {
				ro := rc.rt.NewObject()
				_ = ro.Set("status", res.status)
				_ = ro.Set("statusCode", res.status)
				_ = ro.Set("headers", rc.rt.NewDynamicObject(newCIHeaders(rc.rt, res.header)))
				var data goja.Value
				if fr.binary {
					data = rc.uint8Array(res.body)
				} else {
					data = rc.rt.ToValue(bodyString(res.body))
				}
				_ = ro.Set("body", data)
				_, e = fn(goja.Undefined(), goja.Null(), ro, data)
			}
			if e != nil {
				panic(e)
			}
		})
	}()
}

func (rc *runCtx) taskFetch(opts goja.Value) goja.Value {
	p, resolve, reject := rc.rt.NewPromise()
	fr, err := rc.parseFetch("", opts)
	if err != nil {
		eo := rc.rt.NewObject()
		_ = eo.Set("error", err.Error())
		_ = reject(eo)
		return rc.rt.ToValue(p)
	}
	rc.pending++
	go func() {
		res := rc.do(fr)
		rc.post(func() {
			rc.pending--
			var e error
			if res.err != nil {
				eo := rc.rt.NewObject()
				_ = eo.Set("error", res.err.Error())
				e = reject(eo)
			} else {
				ro := rc.rt.NewObject()
				_ = ro.Set("statusCode", res.status)
				_ = ro.Set("status", res.status)
				_ = ro.Set("headers", rc.rt.NewDynamicObject(newCIHeaders(rc.rt, res.header)))
				_ = ro.Set("body", bodyString(res.body))
				_ = ro.Set("bodyBytes", rc.rt.NewArrayBuffer(res.body))
				e = resolve(ro)
			}
			if e != nil {
				panic(e)
			}
		})
	}()
	return rc.rt.ToValue(p)
}

// parseStatus accepts 200, "200", "HTTP/1.1 200 OK".
func parseStatus(v goja.Value) int {
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return 0
	}
	if n, ok := v.Export().(int64); ok {
		return int(n)
	}
	if f, ok := v.Export().(float64); ok {
		return int(f)
	}
	s := strings.TrimSpace(v.String())
	if strings.HasPrefix(s, "HTTP/") {
		f := strings.Fields(s)
		if len(f) >= 2 {
			s = f[1]
		}
	}
	n, _ := strconv.Atoi(s)
	return n
}

func (rc *runCtx) parseDone(requestPhase bool) (*ScriptResult, error) {
	res := &ScriptResult{}
	v := rc.result
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return res, nil
	}
	o, ok := v.(*goja.Object)
	if !ok {
		return res, nil
	}
	get := func(obj *goja.Object, k string) goja.Value {
		x := obj.Get(k)
		if x == nil || goja.IsUndefined(x) || goja.IsNull(x) {
			return nil
		}
		return x
	}
	if a := get(o, "__egernAbort"); a != nil && a.ToBoolean() {
		res.Abort = true
		return res, nil
	}
	if requestPhase {
		mock := get(o, "response")
		if mock == nil && rc.script.Echo {
			if get(o, "status") != nil || get(o, "body") != nil || get(o, "bodyBytes") != nil {
				mock = o
			}
		}
		if mock != nil {
			mo := mock.ToObject(rc.rt)
			r := &ScriptHTTP{Status: parseStatus(get(mo, "status")), Header: toHeader(rc.rt, get(mo, "headers"))}
			if r.Status == 0 {
				r.Status = parseStatus(get(mo, "statusCode"))
			}
			if b := get(mo, "bodyBytes"); b != nil {
				r.Body, _ = rc.bodyBytes(b)
			} else if b := get(mo, "body"); b != nil {
				r.Body, _ = rc.bodyBytes(b)
			}
			res.Response = r
			return res, nil
		}
		if x := get(o, "url"); x != nil {
			res.URL = x.String()
		}
		if x := get(o, "method"); x != nil {
			res.Method = x.String()
		}
	} else {
		res.Status = parseStatus(get(o, "status"))
		if res.Status == 0 {
			res.Status = parseStatus(get(o, "statusCode"))
		}
	}
	if x := get(o, "headers"); x != nil {
		res.Header = toHeader(rc.rt, x)
		if !requestPhase {
			fixSetCookie(res.Header, rc.origSetCookie)
		}
	}
	if x := get(o, "bodyBytes"); x != nil {
		res.Body, res.BodySet = rc.bodyBytes(x)
	} else if x := get(o, "body"); x != nil {
		res.Body, res.BodySet = rc.bodyBytes(x)
	}
	return res, nil
}
