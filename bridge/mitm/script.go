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
	"os"
	"runtime"
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
	// v0.19.9: large programs (bundles like Sub-Store, ~1.3 MB of JS → ~14 MB compiled) stay cached only
	// while in use: lastUse by cache key, released after largeProgIdle without a run. bigSem runs them
	// one at a time so two such compiles / runtimes never coexist in the 50 MB extension.
	lastUse map[string]time.Time
	bigSem  chan struct{}
	// used: last use of every cached program key (DropIdle keeps the recent ones).
	used map[string]time.Time
}

// largeProgSource is the source size from which a script counts as a large bundle (compiled ≥ ~7 MB).
// v0.19.18: 256 KB (was 512 KB). The 喜马拉雅 unlock script is 363 KB of obfuscated JS; two of its runs
// at once took ~18 MB of heap on top of the core, and its player page fires several matching requests
// together — the extension was killed (user 2026-10-22 「把 app 干崩了」, Tern's VPN). Now one at a time.
const largeProgSource = 256 << 10

// largeQueueWaitNs bounds how long an HTTP request waits for the large-bundle lock (Reserve). Atomic so a
// test can shorten it.
var largeQueueWaitNs atomic.Int64

func init() { largeQueueWaitNs.Store(int64(45 * time.Second)) }

func largeQueueWait() time.Duration { return time.Duration(largeQueueWaitNs.Load()) }

// largeProgIdle is how long a large compiled program is kept after its last run (a burst of API calls
// from a web UI reuses it; then the memory goes back to the tunnel).
var largeProgIdleNs atomic.Int64 // atomic: a test shortens it while release timers from earlier runs read it (-race)

func init() { largeProgIdleNs.Store(int64(45 * time.Second)) }

func largeProgIdle() time.Duration { return time.Duration(largeProgIdleNs.Load()) }

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
	return &ScriptRunner{e: e, progs: progs, sem: make(chan struct{}, 2), taskSem: make(chan struct{}, 1), byURL: map[string]string{},
		lastUse: map[string]time.Time{}, bigSem: make(chan struct{}, 1)}
}

// Reset drops compiled programs (memory).
func (s *ScriptRunner) Reset() { s.progs.Reset() }

// dropKeepRecent: DropCaches (FreeMemory from the extension's MemoryGuard, every tick at ≥ 40 MB
// footprint) keeps programs used this recently. v0.19.21: it used to drop them all, so a script in use
// (喜马拉雅: 1.8 MB compiled, ~8 MB of heap to compile again; youtube.response.js 1.2 MB / ~6 MB) was
// compiled again on the next request — trading a small retained program for a much larger compile
// peak, at the moment memory was already high.
var dropKeepRecent = 60 * time.Second

// markUsed records that a program key was just used (DropIdle).
func (s *ScriptRunner) markUsed(key string) {
	s.mu.Lock()
	if s.used == nil {
		s.used = map[string]time.Time{}
	}
	s.used[key] = time.Now()
	s.mu.Unlock()
}

// DropIdle drops compiled programs not used within keep (0 = all).
func (s *ScriptRunner) DropIdle(keep time.Duration) {
	if keep <= 0 {
		s.progs.Reset()
		s.mu.Lock()
		s.used = nil
		s.mu.Unlock()
		return
	}
	for _, k := range s.progs.Keys() {
		s.mu.Lock()
		t, ok := s.used[k]
		recent := ok && time.Since(t) < keep
		if !recent {
			delete(s.used, k)
		}
		s.mu.Unlock()
		if !recent {
			s.progs.Remove(k)
		}
	}
}

// Invalidate forgets a program after its source was re-downloaded.
func (s *ScriptRunner) Invalidate(path string) {
	s.mu.Lock()
	delete(s.byURL, path)
	s.mu.Unlock()
}

func (s *ScriptRunner) program(sc *Script) (prog *goja.Program, err error) {
	src := sc.Source
	sig := ""
	if src == nil {
		// v0.19.9 (review 5 P2-7): a script file that has not changed (same size + mtime) maps straight to
		// its compiled program: no re-read + SHA-256 of a 1.3 MB bundle on every request.
		var size int64
		sig, size = s.statSig(sc.Path)
		if sig != "" {
			s.mu.Lock()
			v, ok := s.byURL[sc.Path]
			s.mu.Unlock()
			if ok && strings.HasPrefix(v, sig+"|") {
				if p, ok := s.progs.Get(strings.TrimPrefix(v, sig+"|")); ok {
					s.markUsed(strings.TrimPrefix(v, sig+"|"))
					if size >= largeProgSource {
						s.touchLarge(strings.TrimPrefix(v, sig+"|"))
					}
					s.e.res.RefreshIfStale(sc.Path, sc.UpdateInterval)
					return p, nil
				}
			}
		}
		var err error
		src, err = s.e.res.Get(sc.Path, sc.UpdateInterval)
		if err != nil {
			return nil, fmt.Errorf("加载脚本失败：%w", err)
		}
	}
	sum := sha256.Sum256(src)
	key := hex.EncodeToString(sum[:])
	if sig != "" {
		s.mu.Lock()
		s.byURL[sc.Path] = sig + "|" + key
		s.mu.Unlock()
	}
	s.markUsed(key)
	if p, ok := s.progs.Get(key); ok {
		if len(src) >= largeProgSource {
			s.touchLarge(key)
		}
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
	if len(src) >= largeProgSource {
		// One large bundle at a time: drop the others before compiling (a cached Sub-Store core plus a
		// compile of its sibling bundle measured 64 MB live).
		for k := range s.lastUse {
			delete(s.lastUse, k)
			s.progs.Remove(k)
		}
	}
	if err := compileFits(len(src)); err != nil {
		s.mu.Unlock()
		return nil, err
	}
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
	if len(code) >= largeProgSource {
		s.touchLarge(key)
	}
	return p, nil
}

// compileBytesPerSourceByte: goja's heap growth while compiling, per byte of source. Measured v0.19.9 on
// the 1.3 MB Sub-Store bundle (AST + program + compiler scopes, ~43 MB peak ≈ 32×) and v0.19.21 on arm64
// (zz test TestCompileMemoryMeasured): 喜马拉雅 363 KB → peak +8.3 MB with GC off (24×), +7.3 MB with GC
// (21×), 1.8 MB retained; youtube.response.js 133 KB → +5.8 MB (46×), 1.2 MB retained. 32× stays the
// estimate for large bundles (the only ones gated).
const compileBytesPerSourceByte = 32

// compileFits refuses to compile a large bundle when the estimated compile peak does not fit. The compile
// happens in Go, outside the script memory guard, so without this check the system would kill the
// tunnel. In the extension it is judged on the memory iOS still allows (os_proc_available_memory, see
// memory.go): the estimate plus availReserve must be available. Without a probe the old heuristic
// against the soft memory limit applies. No limit and no probe (app process: 脚本调试, tests) → allowed.
func compileFits(srcLen int) error {
	if srcLen < largeProgSource {
		return nil
	}
	need := int64(srcLen) * compileBytesPerSourceByte
	if ok, known, avail := availableAtLeast(need + availReserve); known {
		if !ok {
			return fmt.Errorf("脚本过大（%.1f MB），编译约需 %d MB 内存，隧道当前可用 %d MB（iOS 网络扩展上限约 50 MB），已跳过",
				float64(srcLen)/(1<<20), need>>20, avail>>20)
		}
		return nil
	}
	limit := memGuardLimit()
	if limit <= 0 || limit >= 1<<40 {
		return nil
	}
	runtime.GC()
	sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(sample)
	live := sample[0].Value.Uint64()
	if live+uint64(need) > uint64(limit) {
		return fmt.Errorf("脚本过大（%.1f MB），在隧道内编译约需 %d MB 内存，超出 iOS 网络扩展的内存上限（%d MB），已跳过",
			float64(srcLen)/(1<<20), (live+uint64(need))>>20, limit>>20)
	}
	return nil
}

// statSig is "size:mtime" of the file behind a script path (cache file for URLs), "" when missing.
func (s *ScriptRunner) statSig(path string) (string, int64) {
	p := path
	if isRemote(p) {
		p = CachePath(s.e.home, p)
	} else {
		p = s.e.res.LocalPath(p)
	}
	fi, err := os.Stat(p)
	if err != nil {
		return "", 0
	}
	return strconv.FormatInt(fi.Size(), 10) + ":" + strconv.FormatInt(fi.ModTime().UnixNano(), 10), fi.Size()
}

// scriptSize is the source size of sc without reading it (0 when unknown, e.g. not downloaded yet).
func (s *ScriptRunner) scriptSize(sc *Script) int64 {
	if sc.Source != nil {
		return int64(len(sc.Source))
	}
	p := sc.Path
	if isRemote(p) {
		p = CachePath(s.e.home, p)
	} else {
		p = s.e.res.LocalPath(p)
	}
	if fi, err := os.Stat(p); err == nil {
		return fi.Size()
	}
	return 0
}

// knownSize is the source size used for the large-bundle decision. r7 P3-6: a remote script that is
// not downloaded yet sized as 0, so its first run compiled a 1.3 MB bundle outside bigSem; it is
// downloaded (into the cache, deduplicated per URL) before deciding.
func (s *ScriptRunner) knownSize(sc *Script) int64 {
	if n := s.scriptSize(sc); n > 0 || sc.Source != nil || !isRemote(sc.Path) {
		return n
	}
	b, err := s.e.res.Get(sc.Path, sc.UpdateInterval)
	if err != nil {
		return 0 // program() reports the download error
	}
	return int64(len(b))
}

// touchLarge records a run of a large program and schedules its release after largeProgIdle.
func (s *ScriptRunner) touchLarge(key string) {
	s.mu.Lock()
	_, scheduled := s.lastUse[key]
	s.lastUse[key] = time.Now()
	s.mu.Unlock()
	if !scheduled {
		s.scheduleRelease(key, largeProgIdle())
	}
}

func (s *ScriptRunner) scheduleRelease(key string, after time.Duration) {
	time.AfterFunc(after, func() {
		s.mu.Lock()
		last, ok := s.lastUse[key]
		if !ok {
			s.mu.Unlock()
			return
		}
		if idle := time.Since(last); idle < largeProgIdle() {
			s.mu.Unlock()
			s.scheduleRelease(key, largeProgIdle()-idle)
			return
		}
		delete(s.lastUse, key)
		s.mu.Unlock()
		s.progs.Remove(key)
		largeReleases.Add(1)
	})
}

// largeReleases counts idle releases of large programs (tests / diagnostics).
var largeReleases atomic.Int64

// isLarge reports whether a cached program key belongs to a large bundle.
func (s *ScriptRunner) isLarge(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.lastUse[key]
	return ok
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
	// origBody / origBodyBytes are the phase object's own body values ($response's, or $request's in the
	// request phase): $done($response) after `$response.body = x` hands both back, and the untouched
	// original bodyBytes must not win over the body the script changed.
	origBody, origBodyBytes goja.Value
}

func (rc *runCtx) post(j loopJob) {
	select {
	case rc.jobs <- j:
	case <-rc.ctx.Done():
	}
}

// Run executes a script rule. resp == nil means request phase.
func (s *ScriptRunner) Run(parent context.Context, rule *Rule, req, resp *ScriptHTTP) (*ScriptResult, error) {
	return s.run(parent, rule, req, resp, s.sem, false)
}

// Slot is an HTTP-script slot taken by Reserve. big: the large-bundle lock (bigSem) is held too.
type Slot struct {
	once sync.Once
	s    *ScriptRunner
	big  bool
}

// Release gives the slot (and the large-bundle lock) back; idempotent.
func (sl *Slot) Release() {
	if sl == nil {
		return
	}
	sl.once.Do(func() {
		<-sl.s.sem
		if sl.big {
			<-sl.s.bigSem
		}
	})
}

// Reserve takes an HTTP-script slot ahead of RunReserved (review5 P0-1: the slot is taken before the
// body is loaded, so queued scripts don't each hold a body).
// r7 P2-1: a large bundle (≥ largeProgSource) takes the large-bundle lock FIRST and only then an HTTP
// slot — the same order as task scripts (bigSem → taskSem). Waiting for bigSem while holding one of the
// two HTTP slots let two large requests starve every other HTTP script for the length of a Sub-Store
// sync.
func (s *ScriptRunner) Reserve(parent context.Context, rule *Rule) (*Slot, error) {
	if parent == nil {
		parent = context.Background()
	}
	wait := scriptTimeout(rule.Script, 120*time.Second, 10*time.Second)
	sl := &Slot{s: s}
	if s.knownSize(rule.Script) >= largeProgSource {
		// v0.19.19 (喜马拉雅): large bundles run one at a time, and the 喜马拉雅 script costs ~1 s of goja
		// per run, so a player page firing 6–10 matching requests queued the last ones (track/v4/baseInfo,
		// the one that unlocks playback) past the 10 s script timeout: 「脚本排队超时」, the paid response
		// went through unchanged and the app asked for VIP. The queue no longer spends the run's timeout —
		// it waits up to largeQueueWait while the client is still there (parent ends the wait when the
		// app gives up); the run gets its full timeout once it starts.
		qwait := wait
		if q := largeQueueWait(); q > qwait {
			qwait = q
		}
		qt := time.NewTimer(qwait)
		start := time.Now()
		select {
		case s.bigSem <- struct{}{}:
			sl.big = true
			qt.Stop()
		case <-qt.C:
			return nil, fmt.Errorf("脚本排队超时（大脚本逐个运行，已等待 %d 秒）", int(qwait/time.Second))
		case <-parent.Done():
			qt.Stop()
			return nil, fmt.Errorf("客户端已断开，跳过脚本（排队 %d ms）", time.Since(start).Milliseconds())
		}
		if d := time.Since(start); d >= time.Second {
			s.e.Logs.Add(rule.Script.Name, "debug", fmt.Sprintf("排队 %d ms（大脚本逐个运行）", d.Milliseconds()))
		}
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	select {
	case s.sem <- struct{}{}:
	case <-deadline.C:
		if sl.big {
			<-s.bigSem
		}
		return nil, errors.New("脚本排队超时")
	case <-parent.Done():
		if sl.big {
			<-s.bigSem
		}
		return nil, errors.New("客户端已断开，跳过脚本")
	}
	return sl, nil
}

// RunReserved is Run for a caller already holding a slot from Reserve.
func (s *ScriptRunner) RunReserved(parent context.Context, sl *Slot, rule *Rule, req, resp *ScriptHTTP) (*ScriptResult, error) {
	return s.run(parent, rule, req, resp, nil, sl != nil && sl.big)
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

// bodyLimit is the largest body the script is handed (see scriptBodyLimit: its max-size within
// MaxBody, or up to MaxScriptBody for max-size=-1 / above MaxBody).
func (sc *Script) bodyLimit() int { return scriptBodyLimit(sc) }

func (s *ScriptRunner) run(parent context.Context, rule *Rule, req, resp *ScriptHTTP, sem chan struct{}, holdsBig bool) (*ScriptResult, error) {
	rc, err := s.execute(parent, rule.Script, req, resp, sem, holdsBig, 120*time.Second, 10*time.Second, nil)
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
// parent: the run stops when it ends (client gone, engine stopped); nil = no parent. holdsBig: the
// caller already holds bigSem (Reserve for a large bundle).
func (s *ScriptRunner) execute(parent context.Context, sc *Script, req, resp *ScriptHTTP, sem chan struct{}, holdsBig bool, maxTimeout, defTimeout time.Duration, setup func(*runCtx)) (rcOut *runCtx, errOut error) {
	// v0.19.3: a Go panic inside a native helper must not take the tunnel down (task scripts run on the
	// scheduler goroutine, which has no net/http recover around it).
	defer func() {
		if p := recover(); p != nil {
			rcOut, errOut = nil, fmt.Errorf("脚本运行时内部错误：%v", p)
		}
	}()
	timeout := scriptTimeout(sc, maxTimeout, defTimeout)
	if parent == nil {
		parent = context.Background()
	}
	// v0.19.9: large bundles compile and run one at a time (see bigSem). Lock order everywhere:
	// bigSem → sem / taskSem (r7 P2-1).
	if !holdsBig && s.knownSize(sc) >= largeProgSource {
		select {
		case s.bigSem <- struct{}{}:
		case <-time.After(timeout):
			return nil, errors.New("脚本排队超时")
		case <-parent.Done():
			return nil, errScriptCancelled
		}
		defer func() { <-s.bigSem }()
	}
	// Lend the run (compile included) what iOS still allows above GOMEMLIMIT (memory.go).
	defer borrowSoftLimit()()
	prog, err := s.program(sc)
	if err != nil {
		return nil, err
	}
	if sem != nil { // nil: the caller holds a slot (Reserve)
		select {
		case sem <- struct{}{}:
		case <-time.After(timeout):
			return nil, errors.New("脚本排队超时")
		case <-parent.Done():
			return nil, errScriptCancelled
		}
		defer func() { <-sem }()
	}
	if parent.Err() != nil {
		return nil, errScriptCancelled
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
	// r7 B29 / P3-7: the client went away (HTTP scripts) or the engine stopped (task scripts): stop the
	// run instead of letting it go on to its timeout (up to 300 s for a task, with network + store writes).
	stopParent := context.AfterFunc(parent, func() { rt.Interrupt(cancelInterrupt) })
	defer stopParent()
	stopGuard := startMemGuard(ctx, rt)
	defer stopGuard()

	jsFail := func(err error) error {
		var ie *goja.InterruptedError
		if parent.Err() != nil && errors.As(err, &ie) {
			return errScriptCancelled // interrupted because the parent ended (whatever value won)
		}
		return s.jsErr(sc, err, timeout)
	}
	// afterDone: Surge / Loon / QX / Egern hand the $done value over the moment $done is called; an
	// exception the script throws afterwards (trailing obfuscator code such as jsjiami's `}(window));`,
	// a callback that fails after answering) only shows up in the log. Tern discarded the answer instead.
	afterDone := func(err error) bool {
		if !rc.done || err == nil {
			return false
		}
		var ie *goja.InterruptedError
		if errors.As(err, &ie) {
			return false
		}
		msg := s.jsErr(sc, err, timeout).Error()
		if rc.onLog != nil {
			rc.onLog("warn", "$done 之后的异常已忽略："+msg)
		} else {
			s.e.Logs.Add(sc.Name, "warn", "$done 之后的异常已忽略："+msg)
		}
		return true
	}
	_, err = rt.RunProgram(prog)
	if err != nil && !afterDone(err) {
		return nil, jsFail(err)
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
			if err != nil && !afterDone(err) {
				return nil, jsFail(err)
			}
		case <-parent.Done():
			return nil, errScriptCancelled
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
		} else if v == cancelInterrupt {
			return errScriptCancelled
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

// cancelInterrupt: the run's parent context ended (client disconnected, engine stopped).
const cancelInterrupt = "cancelled"

var errScriptCancelled = errors.New("脚本已停止（客户端已断开或引擎已停止）")

// memGuardHook lets tests force a limit; nil in production.
var memGuardLimit = func() int64 { return debug.SetMemoryLimit(-1) }

// startMemGuard interrupts the runtime when the Go heap nears the soft memory limit (GOMEMLIMIT is set
// in the extension from the jetsam budget). A script that builds huge strings / arrays would otherwise
// push the extension over its ~50 MB budget and the system kills the tunnel. No limit set (app, tests)
// => no guard.
func startMemGuard(ctx context.Context, rt *goja.Runtime) func() {
	if _, known := availableMemory(); known {
		return startAvailGuard(ctx, rt)
	}
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
		var lastGC time.Time
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				metrics.Read(sample)
				if sample[0].Value.Kind() == metrics.KindUint64 && sample[0].Value.Uint64() > threshold {
					// v0.19.9: heap objects include garbage the GC has not swept yet. Under GOMEMLIMIT the
					// heap legitimately runs close to the limit (a large bundle that was just replaced in
					// the program cache), so collect once and judge the live heap; at most every 500 ms.
					if time.Since(lastGC) > 500*time.Millisecond {
						lastGC = time.Now()
						runtime.GC()
						metrics.Read(sample)
						if sample[0].Value.Uint64() <= threshold {
							continue
						}
					}
					rt.Interrupt(memInterrupt)
					return
				}
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}

// startAvailGuard is the memory guard in the extension (v0.19.21): it watches what iOS still allows
// (os_proc_available_memory) instead of the Go heap against GOMEMLIMIT, which is only the GC's soft
// target (26 MB) and interrupted large scripts such as 喜马拉雅 with half the real budget unused. Below
// scriptAvailFloor it returns memory to the OS once (garbage counts in the footprint until scavenged)
// and interrupts the script if that did not help.
func startAvailGuard(ctx context.Context, rt *goja.Runtime) func() {
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(50 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				if ok, known, _ := availableAtLeast(scriptAvailFloor); known && !ok {
					if a, _ := availableMemoryNow(); a < scriptAvailFloor {
						rt.Interrupt(memInterrupt)
						return
					}
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

// binaryBody exposes a binary-mode body as a Uint8Array plus the ArrayBuffer under it (review6 OPT-1:
// one copy of the body instead of two; Surge's body / bodyBytes describe the same bytes).
func (rc *runCtx) binaryBody(b []byte) (goja.Value, goja.Value) {
	ab := rc.rt.NewArrayBuffer(append([]byte(nil), b...))
	abv := rc.rt.ToValue(ab)
	o, err := rc.rt.New(rc.rt.Get("Uint8Array"), abv)
	if err != nil {
		return abv, abv
	}
	return o, abv
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
		rc.setBody(ro, req.Body, sc.BinaryBody)
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
			rc.setBody(so, resp.Body, sc.BinaryBody)
		}
		set("$response", so)
	}
}

// setBody puts a request / response body on its script object.
//   - binary-body-mode (Surge binary-body-mode=1, Loon binary-body-mode=true): body is a Uint8Array and
//     bodyBytes the ArrayBuffer under it;
//   - text mode: body is the string, and bodyBytes is the raw bytes as an ArrayBuffer, the way Quantumult X
//     gives every script-request-body / script-response-body script (QX syntax has no binary flag, so
//     protobuf scripts such as Maasea's youtube.response.js read $response.bodyBytes there; before, Tern
//     left it undefined and the script exited without touching the response). It is a lazy, non-enumerable
//     accessor: the copy is made only when a script reads it, and `{...$response}` does not copy it.
func (rc *runCtx) setBody(obj *goja.Object, b []byte, binary bool) {
	if binary {
		u8, ab := rc.binaryBody(b)
		_ = obj.Set("body", u8)
		_ = obj.Set("bodyBytes", ab)
		rc.origBody, rc.origBodyBytes = u8, ab
		return
	}
	str := rc.rt.ToValue(bodyString(b))
	_ = obj.Set("body", str)
	rc.origBody = str
	var cur goja.Value
	getter := rc.rt.ToValue(func(goja.FunctionCall) goja.Value {
		if cur == nil {
			cur = rc.rt.ToValue(rc.rt.NewArrayBuffer(append([]byte(nil), b...)))
			rc.origBodyBytes = cur
		}
		return cur
	})
	setter := rc.rt.ToValue(func(call goja.FunctionCall) goja.Value {
		cur = call.Argument(0)
		return goja.Undefined()
	})
	_ = obj.DefineAccessorProperty("bodyBytes", getter, setter, goja.FLAG_TRUE, goja.FLAG_FALSE)
}

// doneBody picks the body a $done object carries: bodyBytes, unless it is the phase object's untouched
// original and the script changed body ($response.body = x; $done($response)).
func (rc *runCtx) doneBody(o *goja.Object, get func(*goja.Object, string) goja.Value) ([]byte, bool) {
	bb, body := get(o, "bodyBytes"), get(o, "body")
	if bb != nil && body != nil && rc.origBodyBytes != nil && bb.StrictEquals(rc.origBodyBytes) &&
		(rc.origBody == nil || !body.StrictEquals(rc.origBody)) {
		bb = nil
	}
	if bb != nil {
		return rc.bodyBytes(bb)
	}
	if body != nil {
		return rc.bodyBytes(body)
	}
	return nil, false
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

	if sc.HasArgument && sc.ArgObject {
		// JSON.parse in the runtime keeps the plugin's key order (a Go map made Object.keys($argument)
		// come out in a different order on every run).
		var obj goja.Value
		if parse, ok := goja.AssertFunction(rt.Get("JSON").ToObject(rt).Get("parse")); ok {
			if v, err := parse(goja.Undefined(), rt.ToValue(sc.Argument)); err == nil {
				if o, isObj := v.(*goja.Object); isObj && o.ClassName() == "Object" {
					obj = v
				}
			}
		}
		if obj != nil {
			set("$argument", obj)
		} else {
			set("$argument", sc.Argument)
		}
	} else if sc.HasArgument {
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
	lang := "zh-Hans"
	if st := rc.e.st.Load(); st != nil {
		lang = st.cfg.scriptLanguage()
	}
	_ = env.Set("language", lang)
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
			if r > 0xFF {
				// r7 B27: browsers / JSC throw InvalidCharacterError; byte(r) silently produced wrong output.
				ex := rt.NewTypeError("Failed to execute 'btoa': The string to be encoded contains characters outside of the Latin1 range.")
				_ = ex.Set("name", "InvalidCharacterError")
				panic(ex)
			}
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
	installURLGlobals(rt)
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
	status  int
	header  http.Header
	body    []byte
	err     error
	release func() // body budget share (nil on error); returned by deliverFetch
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
	// v0.19.9 (review 5 P1-4): a script passing its own Accept-Encoding (often $request.headers) turned
	// off Go's transparent gzip and got compressed bytes. Surge / QX / Loon hand scripts decoded bodies:
	// let the transport negotiate gzip, and decode anything a server sends regardless (below).
	req.Header.Del("Accept-Encoding")
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
	// review6 P1-2 / r7: script downloads share the global body budget with rewrite / script bodies,
	// charged as they are read and held until the callback has run (see deliverFetch, fetchbudget.go).
	if heapHigh() {
		return &fetchResp{err: errors.New("内存紧张，已跳过下载（保护隧道内存）")}
	}
	charge := &fetchCharge{ctx: ctx}
	release := charge.release
	fail := func(err error) *fetchResp { release(); return &fetchResp{err: err} }
	cl := resp.ContentLength
	if resp.Header.Get("Content-Encoding") != "" {
		cl = -1 // compressed: the announced length is not what we end up holding
	}
	// v0.19.9 (review 5 P2-5): read one byte past the cap and fail loudly instead of handing the script a
	// silently truncated body (it then failed later in JSON.parse).
	b, err := charge.read(resp.Body, cl, MaxScriptBody)
	if err != nil {
		return fail(err)
	}
	if len(b) > MaxScriptBody {
		return fail(fmt.Errorf("响应体超过 %d MB", MaxScriptBody>>20))
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
		d, derr := decodeBody(ce, b, MaxScriptBody)
		if errors.Is(derr, errBodyTooBig) {
			return fail(fmt.Errorf("响应体超过 %d MB", MaxScriptBody>>20))
		}
		if derr == nil {
			// compressed and decoded bodies are both alive here: charge them
			if err := charge.ensure(int64(len(b) + len(d))); err != nil {
				return fail(err)
			}
			b = d
			resp.Header.Del("Content-Encoding")
			resp.Header.Del("Content-Length")
		}
	}
	return &fetchResp{status: resp.StatusCode, header: resp.Header, body: b, release: release}
}

// fetchBudgetWait is how long a script download waits for body budget before trying the single
// unbudgeted slot (fetchbudget.go).
var fetchBudgetWait = 2 * time.Second

// deliverFetch posts a fetch result to the event loop and returns its body budget once the callback
// ran, or once the script ended without running it.
func (rc *runCtx) deliverFetch(res *fetchResp, job func()) {
	done := make(chan struct{})
	rc.post(func() {
		defer close(done)
		job()
	})
	if res.release != nil {
		select {
		case <-done:
		case <-rc.ctx.Done():
		}
		res.release()
	}
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
		rc.deliverFetch(res, func() {
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
		rc.deliverFetch(res, func() {
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
		// v0.19.9: a request script that sees $task (we expose the QX API to every script) answers the
		// QX way, $done({status: "HTTP/1.1 200 OK", headers, body}), even when the rule came from a Surge
		// module or Loon plugin. Surge's request $done has no status key, so a status here can only mean
		// a local answer (Sub-Store's backend did this and every API call fell through to the network).
		if mock == nil && (get(o, "status") != nil || get(o, "statusCode") != nil) && get(o, "url") == nil && get(o, "method") == nil {
			mock = o
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
	res.Body, res.BodySet = rc.doneBody(o, get)
	return res, nil
}
