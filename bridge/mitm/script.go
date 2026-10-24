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
	// BodyShared: the script's ArrayBuffer may use Body itself instead of a copy (v0.19.22, large
	// bodies). The caller checks Body afterwards and restores it if the script changed it in place
	// without handing it back (modifyResponse).
	BodyShared bool
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

// ScriptRunner executes scripts in a JavaScript engine (jsengine.go: goja, or JavaScriptCore in the iOS
// tunnel), compiled programs cached (LRU), and a small concurrency cap so the extension's memory stays bounded.
type ScriptRunner struct {
	e       *Engine
	progs   *lru[*compiled]
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
	// queue admits HTTP requests to the bigSem wait (v0.19.22, admission.go).
	queue *scriptQueue
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
	p    *compiled
	err  error
}

// compileCount counts script compiles, any engine (tests).
var compileCount atomic.Int64

func NewScriptRunner(e *Engine) *ScriptRunner {
	progs := newLRU[*compiled](16)
	progs.maxW = progCacheBudget
	// A native (JavaScriptCore) program lives in the Swift engine: leaving the index drops it there too.
	progs.onEvict = func(k string, c *compiled) {
		// A wedged engine still runs the abandoned script and holds its VM lock: Drop would block forever.
		if c != nil && c.native && !nativeWedged.Load() {
			if b, _ := nativeJS.Load().(nativeBox); b.n != nil {
				b.n.Drop(k)
			}
		}
	}
	return &ScriptRunner{e: e, progs: progs, sem: make(chan struct{}, 2), taskSem: make(chan struct{}, 1), byURL: map[string]string{},
		lastUse: map[string]time.Time{}, bigSem: make(chan struct{}, 1), queue: newScriptQueue()}
}

// Reset drops compiled programs (memory).
func (s *ScriptRunner) Reset() {
	s.progs.Reset()
	nativeCollect()
}

// nativeCollect lets JavaScriptCore collect what dropped contexts left behind.
func nativeCollect() {
	if nativeWedged.Load() {
		return // see onEvict: the VM is held by the abandoned run
	}
	if b, _ := nativeJS.Load().(nativeBox); b.n != nil {
		b.n.Collect()
	}
}

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
	defer nativeCollect()
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

// program returns sc compiled for the engine new runs use (tests).
func (s *ScriptRunner) program(sc *Script) (*compiled, error) {
	eng, err := engineFor("")
	if err != nil {
		return nil, err
	}
	c, _, err := s.programFor(sc, eng)
	return c, err
}

// programFor returns sc compiled for eng (cache key: the source's SHA-256, prefixed for the native engine)
// and the source when it had to be read ("" for a cache hit by file signature).
func (s *ScriptRunner) programFor(sc *Script, eng jsEngine) (prog *compiled, code string, err error) {
	prefix := ""
	if eng.kind() == EngineNative {
		prefix = "jsc:"
	}
	src := sc.Source
	sig := ""
	if src == nil {
		// v0.19.9 (review 5 P2-7): a script file that has not changed (same size + mtime) maps straight to
		// its compiled program: no re-read + SHA-256 of a 1.3 MB bundle on every request.
		var size int64
		sig, size = s.statSig(sc.Path)
		if sig != "" {
			sig = prefix + sig
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
					return p, "", nil
				}
			}
		}
		var err error
		src, err = s.e.res.Get(sc.Path, sc.UpdateInterval)
		if err != nil {
			return nil, "", fmt.Errorf("加载脚本失败：%w", err)
		}
	}
	sum := sha256.Sum256(src)
	key := prefix + hex.EncodeToString(sum[:])
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
		return p, string(src), nil
	}
	// v0.19.6 (review 7): compile runs before the run semaphore, so a burst of requests on a script whose
	// program was not cached (first use after a start, or right after FreeMemory dropped the cache under
	// memory pressure) compiled it once per request in parallel, ~14× the source in heap each (24 requests
	// on a 330 KB script: 24 compiles). Concurrent callers for one key now wait for a single compile.
	s.mu.Lock()
	if c, ok := s.compiling[key]; ok {
		s.mu.Unlock()
		<-c.done
		return c.p, string(src), c.err
	}
	if p, ok := s.progs.Get(key); ok { // finished between the check above and the lock
		s.mu.Unlock()
		return p, string(src), nil
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
	if err := compileFits(len(src), eng); err != nil {
		s.mu.Unlock()
		return nil, "", err
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
	c.p, c.err = s.compile(sc, src, key, eng)
	return c.p, string(src), c.err
}

func (s *ScriptRunner) compile(sc *Script, src []byte, key string, eng jsEngine) (*compiled, error) {
	compileCount.Add(1)
	code, err := scriptCode(src)
	if err != nil {
		return nil, err
	}
	c := &compiled{key: key}
	if err := eng.compile(c, sc.Name, code); err != nil {
		return nil, err
	}
	per := int64(progBytesPerSourceByte)
	if c.native {
		per = nativeBytesPerSourceByte
	}
	s.progs.PutW(key, c, int64(len(code))*per)
	if len(code) >= largeProgSource {
		s.touchLarge(key)
	}
	return c, nil
}

// scriptCode is the source an engine evaluates: BOM removed, a native Egern module adapted.
func scriptCode(src []byte) (string, error) {
	code := strings.TrimPrefix(string(src), "\ufeff")
	if egernNativeRe.MatchString(code) {
		return adaptEgern(code)
	}
	return code, nil
}

// compileBytesPerSourceByte: goja's heap growth while compiling, per byte of source. Measured v0.19.9 on
// the 1.3 MB Sub-Store bundle (AST + program + compiler scopes, ~43 MB peak ≈ 32×) and v0.19.21 on arm64
// (zz test TestCompileMemoryMeasured): 喜马拉雅 363 KB → peak +8.3 MB with GC off (24×), +7.3 MB with GC
// (21×), 1.8 MB retained; youtube.response.js 133 KB → +5.8 MB (46×), 1.2 MB retained. 32× stays the
// estimate for large bundles (the only ones gated).
const compileBytesPerSourceByte = 32

// nativeCompileBytesPerSourceByte: the same estimate for JavaScriptCore (feat/jsc-engine). Its parser and
// bytecode generator allocate far less than goja's (no Go AST, compact unlinked code blocks); 12x is a
// deliberately cautious estimate until it is measured on a device (memory line of the startup log).
const nativeCompileBytesPerSourceByte = 12

// compileFits refuses to compile a large bundle when the estimated compile peak does not fit. The compile
// happens in Go, outside the script memory guard, so without this check the system would kill the
// tunnel. In the extension it is judged on the memory iOS still allows (os_proc_available_memory, see
// memory.go): the estimate plus availReserve must be available. Without a probe the old heuristic
// against the soft memory limit applies. No limit and no probe (app process: 脚本调试, tests) → allowed.
func compileFits(srcLen int, eng jsEngine) error {
	if srcLen < largeProgSource {
		return nil
	}
	per := int64(compileBytesPerSourceByte)
	if eng != nil && eng.kind() == EngineNative {
		per = nativeCompileBytesPerSourceByte
	}
	need := int64(srcLen) * per
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
	// nativeBytesPerSourceByte: retained size of a loaded JavaScriptCore script context (source + unlinked
	// bytecode + its global object), estimated; it only weighs the shared cache budget.
	nativeBytesPerSourceByte = 6
)

// loopJob is one event-loop turn (a timer, a download's callback); a JS error it returns ends the run.
type loopJob func() error

// liveRuntimes counts script runs that exist right now (any engine). Every run creates one and drops it
// when the run returns (nothing keeps a reference: timers are stopped, late callbacks see a cancelled
// context), so this is at most the semaphore sizes (2 HTTP + 1 task) at any moment.
var liveRuntimes atomic.Int64

// textConversions counts blob → text conversions (tests: a body the script never read as text stays bytes).
var textConversions atomic.Int64

// runtimesCreated counts script runtimes ever created (tests: how many runs a burst cost).
var runtimesCreated atomic.Int64

// LiveRuntimes reports how many script runtimes are alive (diagnostics, memory samples, tests).
func LiveRuntimes() int64 { return liveRuntimes.Load() }

// runCtx is one script run: the host side of the prelude (hostOp) plus the event loop state.
type runCtx struct {
	id      int64
	eng     jsEngine
	rt      atomic.Pointer[goja.Runtime] // goja engine (atomic: interrupts come from timer goroutines)
	native  NativeJS                     // native engine
	src     string                       // source, for a native reload ("" when it came from the cache)
	jobs    chan loopJob
	pending int
	done    bool
	desc    *doneDescJS // what $done handed over (nil: $done not called / nothing usable)
	doneRaw string
	script  *Script
	name    string
	e       *Engine
	ctx     context.Context
	timers  map[int64]*time.Timer
	// origSetCookie holds the response's Set-Cookie lines when there were several (review5 P2-3).
	origSetCookie []string
	// Debug runs (脚本调试): console output and notifications are captured instead of going to the
	// engine's rings / the user's notification history.
	onLog    func(level, msg string)
	onNotify func(title, sub, body, url string)
	// setup additions: globals ($network, task extras), $environment.params, the exported $done value.
	globals    map[string]any
	params     any
	hasParams  bool
	wantExport bool

	stop      atomic.Int32 // stop reason (jsengine.go)
	stopCh    chan struct{}
	stopOnce  sync.Once
	abandoned atomic.Bool // native call given up (wedged engine)

	hmu     sync.Mutex // host entry points (Host / Put / Take) vs. the end of the run
	dead    bool
	blobs   map[int64]*blob
	blobSeq int64
}

// blob is bytes shared with the engine by id. temp blobs (made for one conversion) go away when read.
type blob struct {
	b    []byte
	temp bool
	// shared: the bytes are the caller's (ScriptHTTP.BodyShared) and an engine that borrows (goja) maps them
	// without a copy; the handler restores them if the script changed them in place without handing them back.
	shared bool
}

func (rc *runCtx) post(j loopJob) {
	select {
	case rc.jobs <- j:
	case <-rc.ctx.Done():
	}
}

// requestStop ends the run's JavaScript as soon as the engine can (first reason wins).
func (rc *runCtx) requestStop(reason int32) {
	rc.stop.CompareAndSwap(stopNone, reason)
	rc.stopOnce.Do(func() { close(rc.stopCh) })
	if rc.eng != nil {
		rc.eng.interrupt(rc)
	}
}

// reloadCode is the code a native engine evaluates when it lost the script's context ("missing" from Begin,
// e.g. after JavaScriptCore was restarted): the same transformation as the first compile (scriptCode: BOM
// removed, a native Egern module adapted). rc.src is "" when the program came from the cache by file
// signature (programFor did not read the file), so the source is read again then — evaluating "" would load
// an empty script that never calls $done.
func (rc *runCtx) reloadCode() (string, error) {
	src := rc.src
	if src == "" && rc.script != nil {
		switch {
		case rc.script.Source != nil:
			src = string(rc.script.Source)
		case rc.script.Path != "" && rc.e != nil && rc.e.res != nil:
			b, err := rc.e.res.Get(rc.script.Path, rc.script.UpdateInterval)
			if err != nil {
				return "", fmt.Errorf("加载脚本失败：%w", err)
			}
			src = string(b)
		}
	}
	if src == "" {
		return "", errors.New("脚本源码为空，无法重新载入")
	}
	return scriptCode([]byte(src))
}

// ---- NativeRun (also used by the goja primitives) ----

func (rc *runCtx) ID() int64        { return rc.id }
func (rc *runCtx) ShouldStop() bool { return rc.stop.Load() != stopNone }

func (rc *runCtx) Put(b []byte) int64 {
	rc.hmu.Lock()
	defer rc.hmu.Unlock()
	if rc.dead {
		return -1
	}
	return rc.addBlob(append([]byte(nil), b...), true)
}

func (rc *runCtx) Take(id int64) []byte {
	rc.hmu.Lock()
	defer rc.hmu.Unlock()
	return rc.useBlob(id)
}

// takeOwned is Take for an engine that maps blob bytes into its own heap (goja): a copy, except for a
// shared body, which is borrowed (v0.19.22).
func (rc *runCtx) takeOwned(id int64) []byte {
	rc.hmu.Lock()
	defer rc.hmu.Unlock()
	shared := false
	if bl, ok := rc.blobs[id]; ok {
		shared = bl.shared
	}
	b := rc.useBlob(id)
	if shared {
		return b
	}
	return append([]byte(nil), b...)
}

// putOwned is Put without the copy, for bytes a finished run hands back from an engine whose buffers are
// Go memory (goja: the runtime is dropped when the run ends; nothing writes to them any more).
func (rc *runCtx) putOwned(b []byte) int64 {
	rc.hmu.Lock()
	defer rc.hmu.Unlock()
	if rc.dead {
		return -1
	}
	return rc.addBlob(b[:len(b):len(b)], true)
}

// addBlob / useBlob / keepBlob: callers hold hmu.
func (rc *runCtx) addBlob(b []byte, temp bool) int64 {
	if rc.blobs == nil {
		rc.blobs = map[int64]*blob{}
	}
	rc.blobSeq++
	rc.blobs[rc.blobSeq] = &blob{b: b, temp: temp}
	return rc.blobSeq
}

func (rc *runCtx) useBlob(id int64) []byte {
	bl, ok := rc.blobs[id]
	if !ok {
		return nil
	}
	if bl.temp {
		delete(rc.blobs, id)
	}
	return bl.b
}

// blobBytes reads a blob for the host (parseDone).
func (rc *runCtx) blobBytes(id int64) []byte {
	rc.hmu.Lock()
	defer rc.hmu.Unlock()
	if b := rc.blobs[id]; b != nil {
		return b.b
	}
	return nil
}

func (rc *runCtx) freeBlob(id int64) {
	rc.hmu.Lock()
	delete(rc.blobs, id)
	rc.hmu.Unlock()
}

// Host is the prelude's synchronous host call (__tern.host).
func (rc *runCtx) Host(op, arg string) string {
	rc.hmu.Lock()
	defer rc.hmu.Unlock()
	if rc.dead {
		return ""
	}
	return rc.hostOp(op, arg)
}

func (rc *runCtx) hostOp(op, arg string) string {
	switch op {
	case "log":
		level, msg, _ := strings.Cut(arg, "\n")
		if rc.onLog != nil {
			rc.onLog(level, msg)
		} else {
			rc.e.Logs.Add(rc.name, level, msg)
		}
	case "done":
		if !rc.done {
			rc.done = true
			rc.doneRaw = arg
		}
	case "timer":
		f := strings.Split(arg, ",")
		if len(f) == 3 {
			id, _ := strconv.ParseInt(f[0], 10, 64)
			ms, _ := strconv.ParseInt(f[1], 10, 64)
			rc.addTimer(id, ms, f[2] == "1")
		}
	case "clear":
		id, _ := strconv.ParseInt(arg, 10, 64)
		if t, ok := rc.timers[id]; ok {
			t.Stop()
			delete(rc.timers, id)
			rc.pending--
		}
	case "sread":
		if v, ok := rc.e.Store.Read(arg); ok {
			return "1" + v
		}
		return "0"
	case "swrite":
		// "w|d" + len(key) + ":" + key + value
		if len(arg) < 3 {
			return "false"
		}
		del := arg[0] == 'd'
		n, rest, ok := strings.Cut(arg[1:], ":")
		kl, err := strconv.Atoi(n)
		if !ok || err != nil || kl < 0 || kl > len(rest) {
			return "false"
		}
		return strconv.FormatBool(rc.e.Store.Write(rest[:kl], rest[kl:], del))
	case "sclear":
		return strconv.FormatBool(rc.e.Store.Clear())
	case "notify":
		var a [4]string
		if json.Unmarshal([]byte(arg), &a) == nil {
			rc.notify(a[0], a[1], a[2], a[3])
		}
	case "http":
		rc.startFetch(arg)
	case "api":
		rc.httpAPI(arg)
	case "utf8":
		return strconv.FormatInt(rc.addBlob([]byte(arg), true), 10)
	case "text":
		id, _ := strconv.ParseInt(arg, 10, 64)
		textConversions.Add(1)
		return bodyString(rc.useBlob(id))
	case "btoa":
		b := make([]byte, 0, len(arg))
		for _, r := range arg {
			if r > 0xFF {
				return "!" // r7 B27: InvalidCharacterError (thrown by the prelude), like browsers / JSC
			}
			b = append(b, byte(r))
		}
		return base64.StdEncoding.EncodeToString(b)
	case "atob":
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(arg))
		if err != nil {
			b, _ = base64.RawStdEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(arg), "="))
		}
		rs := make([]rune, len(b))
		for i, c := range b {
			rs[i] = rune(c)
		}
		return string(rs)
	case "geo":
		if arg == "" {
			return ""
		}
		c, a, o := rc.e.lookup(arg[1:])
		switch arg[0] {
		case 'c':
			return c
		case 'a':
			return a
		case 'o':
			return o
		}
	case "ungzip":
		id, _ := strconv.ParseInt(arg, 10, 64)
		in := rc.useBlob(id)
		if in == nil {
			return "-1"
		}
		out, err := inflateAny(in)
		if err != nil {
			return "-1"
		}
		return strconv.FormatInt(rc.addBlob(out, true), 10)
	case "compress":
		op, ids, _ := strings.Cut(arg, ",")
		id, _ := strconv.ParseInt(ids, 10, 64)
		in := rc.useBlob(id)
		if in == nil {
			return "-1"
		}
		out, err := egernCompress(op, in)
		if err != nil {
			return "-1"
		}
		return strconv.FormatInt(rc.addBlob(out, true), 10)
	}
	return ""
}

// notify posts a $notification.post / $notify.
func (rc *runCtx) notify(title, sub, body, url string) {
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

func (rc *runCtx) addTimer(id, ms int64, repeat bool) {
	if ms < 0 {
		ms = 0
	}
	rc.pending++
	var fire func()
	fire = func() {
		rc.post(func() error {
			if _, ok := rc.timers[id]; !ok {
				return nil
			}
			if !repeat {
				delete(rc.timers, id)
				rc.pending--
			} else {
				rc.timers[id] = time.AfterFunc(time.Duration(ms)*time.Millisecond, fire)
			}
			return rc.eng.call(rc, "__tern_fire", strconv.FormatInt(id, 10))
		})
	}
	rc.timers[id] = time.AfterFunc(time.Duration(ms)*time.Millisecond, fire)
}

// $httpAPI (Surge): policy groups, outbound mode, profile reload — answered by the bridge.
func (rc *runCtx) httpAPI(arg string) {
	var d struct {
		M    string          `json:"m"`
		P    string          `json:"p"`
		HasB bool            `json:"hasB"`
		BS   bool            `json:"bs"`
		B    json.RawMessage `json:"b"`
		CB   int64           `json:"cb"`
	}
	if json.Unmarshal([]byte(arg), &d) != nil {
		return
	}
	var body any
	if d.HasB {
		if d.BS {
			var s string
			_ = json.Unmarshal(d.B, &s)
			body = s
			var m map[string]any
			if json.Unmarshal([]byte(s), &m) == nil {
				body = m
			}
		} else {
			_ = json.Unmarshal(d.B, &body)
		}
	}
	res, err := rc.e.callAPI(d.M, d.P, body)
	if err != nil {
		rc.e.Logs.Add(rc.name, "warning", "$httpAPI "+d.M+" "+d.P+"："+err.Error())
		res = map[string]any{"error": err.Error()}
	}
	if d.CB < 0 {
		return
	}
	out, _ := json.Marshal(map[string]any{"id": d.CB, "v": res})
	rc.pending++
	rc.post(func() error {
		rc.pending--
		return rc.eng.call(rc, "__tern_deliver", string(out))
	})
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
	// v0.19.22: when the large-bundle lock was taken and for which script (scriptQueue.observe), and
	// whether the script really ran in it (a skipped body must not pull the measured run time down).
	bigAt  time.Time
	bigKey string
	ran    bool
	// parked: the HTTP slot itself is given back while the caller waits for something that is not a
	// script (E 线 #1: bigBodyLock), so other HTTP scripts are not held up by that wait. The large-bundle
	// lock (big) is kept: it is the scriptQueue's turn, and giving it up would reorder the queue.
	parked bool
	wait   time.Duration // how long Reserve waited for the slot; unpark waits as long
}

// park gives the HTTP slot back for the duration of a non-script wait; unpark takes it again.
// Only the goroutine holding the slot calls park / unpark / Release (no locking needed).
func (sl *Slot) park() {
	if sl == nil || sl.parked {
		return
	}
	sl.parked = true
	<-sl.s.sem
}

// unpark takes the HTTP slot back after park, bounded like Reserve (the script's timeout, or until
// ctx ends). On error the slot stays parked and Release only gives back the large-bundle lock.
func (sl *Slot) unpark(ctx context.Context) error {
	if sl == nil || !sl.parked {
		return nil
	}
	select {
	case sl.s.sem <- struct{}{}:
		sl.parked = false
		return nil
	default:
	}
	w := sl.wait
	if w <= 0 {
		w = 10 * time.Second
	}
	t := time.NewTimer(w)
	defer t.Stop()
	select {
	case sl.s.sem <- struct{}{}:
		sl.parked = false
		return nil
	case <-t.C:
		return errors.New("脚本排队超时")
	case <-ctx.Done():
		return &errQueueSkip{"客户端已断开，跳过脚本"}
	}
}

// Release gives the slot (and the large-bundle lock) back; idempotent.
func (sl *Slot) Release() {
	if sl == nil {
		return
	}
	sl.once.Do(func() {
		if !sl.parked {
			<-sl.s.sem
		}
		if sl.big {
			if sl.ran {
				sl.s.queue.observe(sl.bigKey, time.Since(sl.bigAt))
			}
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
	sl := &Slot{s: s, wait: wait}
	if s.knownSize(rule.Script) >= largeProgSource {
		// v0.19.19 (喜马拉雅): large bundles run one at a time, and the 喜马拉雅 script costs ~1 s of goja
		// per run, so a player page firing 6–10 matching requests queued the last ones (track/v4/baseInfo,
		// the one that unlocks playback) past the 10 s script timeout: 「脚本排队超时」, the paid response
		// went through unchanged and the app asked for VIP. The queue no longer spends the run's timeout —
		// it waits up to largeQueueWait while the client is still there (parent ends the wait when the
		// app gives up); the run gets its full timeout once it starts.
		//
		// v0.19.22 (「打开喜马拉雅后有问题，自动断连」): the wait is admitted by scriptQueue — only when the
		// turn can come within queueBudget, with a bounded number waiting (fewer when memory is short),
		// and Shed at the critical level turns the waiters away. Otherwise the response passes through
		// unchanged at once instead of holding its connection and goroutines for up to 45 s.
		// The wait itself is capped a little above the budget: when runs take longer than measured
		// (GC under memory pressure), the request still passes through before the app gives up (~10 s).
		qwait := time.Duration(queueBudgetNs.Load()) + queueGrace
		if q := largeQueueWait(); q < qwait {
			qwait = q
		}
		leave, kick, err := s.queue.admit(rule.Script.Path, len(s.bigSem) > 0)
		if err != nil {
			return nil, err
		}
		qt := time.NewTimer(qwait)
		start := time.Now()
		select {
		case s.bigSem <- struct{}{}:
			sl.big, sl.bigAt, sl.bigKey = true, time.Now(), rule.Script.Path
			qt.Stop()
			leave()
		case <-qt.C:
			leave()
			return nil, &errQueueSkip{fmt.Sprintf("脚本排队过长，已跳过（大脚本逐个运行，已等待 %.1f 秒）", qwait.Seconds())}
		case <-kick:
			qt.Stop()
			leave()
			return nil, &errQueueSkip{fmt.Sprintf("内存紧张，已取消排队中的脚本（排队 %d ms）", time.Since(start).Milliseconds())}
		case <-parent.Done():
			qt.Stop()
			leave()
			return nil, &errQueueSkip{fmt.Sprintf("客户端已断开，跳过脚本（排队 %d ms）", time.Since(start).Milliseconds())}
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
		return nil, &errQueueSkip{"客户端已断开，跳过脚本"}
	}
	return sl, nil
}

// RunReserved is Run for a caller already holding a slot from Reserve.
func (s *ScriptRunner) RunReserved(parent context.Context, sl *Slot, rule *Rule, req, resp *ScriptHTTP) (*ScriptResult, error) {
	if sl != nil {
		sl.ran = true
	}
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

// execute compiles + runs one script and drives its event loop until $done or until nothing is pending.
// req == nil => task script (no $request / $response).
// parent: the run stops when it ends (client gone, engine stopped); nil = no parent. holdsBig: the
// caller already holds bigSem (Reserve for a large bundle).
func (s *ScriptRunner) execute(parent context.Context, sc *Script, req, resp *ScriptHTTP, sem chan struct{}, holdsBig bool, maxTimeout, defTimeout time.Duration, setup func(*runCtx)) (rcOut *runCtx, errOut error) {
	return s.executeOn("", parent, sc, req, resp, sem, holdsBig, maxTimeout, defTimeout, setup)
}

// executeOn is execute on a chosen engine ("" = the default: native when registered, else goja).
func (s *ScriptRunner) executeOn(engine string, parent context.Context, sc *Script, req, resp *ScriptHTTP, sem chan struct{}, holdsBig bool, maxTimeout, defTimeout time.Duration, setup func(*runCtx)) (rcOut *runCtx, errOut error) {
	// v0.19.3: a Go panic inside a native helper must not take the tunnel down (task scripts run on the
	// scheduler goroutine, which has no net/http recover around it).
	defer func() {
		if p := recover(); p != nil {
			rcOut, errOut = nil, fmt.Errorf("脚本运行时内部错误：%v", p)
		}
	}()
	eng, err := engineFor(engine)
	if err != nil {
		return nil, err
	}
	var ran *runCtx // set once the run exists: a failed run notes its engine in the script log
	defer func() {
		if errOut != nil && ran != nil && ran.onLog == nil && !errors.Is(errOut, errScriptCancelled) {
			s.e.Logs.Add(sc.Name, "debug", "运行引擎："+engineLabel(eng))
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
	// Lend the run (compile included) what iOS still allows above GOMEMLIMIT (memory.go). Only goja's
	// heap is the Go heap; JavaScriptCore allocates outside it.
	if eng.kind() != EngineNative || usesGoHeap(eng) {
		defer borrowSoftLimit()()
	}
	prog, src, err := s.programFor(sc, eng)
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
	liveRuntimes.Add(1)
	runtimesCreated.Add(1)
	defer liveRuntimes.Add(-1)
	rc := &runCtx{id: runSeq.Add(1), eng: eng, src: src, jobs: make(chan loopJob, 8), script: sc, name: sc.Name, e: s.e, ctx: ctx,
		timers: map[int64]*time.Timer{}, stopCh: make(chan struct{})}
	if rc.src == "" && sc.Source != nil {
		rc.src = string(sc.Source)
	}
	defer func() {
		rc.hmu.Lock()
		rc.dead = true
		rc.hmu.Unlock()
		for _, t := range rc.timers {
			t.Stop()
		}
		eng.end(rc)
		rc.rt.Store(nil)
	}()
	start := time.Now()
	if setup != nil {
		setup(rc)
	}
	ran = rc
	setupJSON, err := rc.setupJSON(req, resp)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { rc.requestStop(stopTimeout) })
	defer stop()
	// r7 B29 / P3-7: the client went away (HTTP scripts) or the engine stopped (task scripts): stop the
	// run instead of letting it go on to its timeout (up to 300 s for a task, with network + store writes).
	stopParent := context.AfterFunc(parent, func() { rc.requestStop(stopCancelled) })
	defer stopParent()
	stopGuard := startMemGuard(ctx, func() { rc.requestStop(stopMemory) })
	defer stopGuard()

	jsFail := func(err error) error {
		var je *jsError
		if parent.Err() != nil && errors.As(err, &je) && je.kind == "interrupted" {
			return errScriptCancelled // interrupted because the parent ended (whatever value won)
		}
		return s.jsErr(rc, err, timeout)
	}
	// afterDone: Surge / Loon / QX / Egern hand the $done value over the moment $done is called; an
	// exception the script throws afterwards (trailing obfuscator code such as jsjiami's `}(window));`,
	// a callback that fails after answering) only shows up in the log. Tern discarded the answer instead.
	afterDone := func(err error) bool {
		if !rc.done || err == nil {
			return false
		}
		var je *jsError
		if errors.As(err, &je) && je.kind == "interrupted" {
			return false
		}
		msg := s.jsErr(rc, err, timeout).Error()
		if rc.onLog != nil {
			rc.onLog("warn", "$done 之后的异常已忽略："+msg)
		} else {
			s.e.Logs.Add(sc.Name, "warn", "$done 之后的异常已忽略："+msg)
		}
		return true
	}
	err = eng.begin(rc, prog, setupJSON)
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
							err = gojaErr(pe) // keeps goja's Exception / StackOverflowError / InterruptedError for jsErr
						} else {
							err = fmt.Errorf("%v", p)
						}
					}
				}()
				err = j()
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
	if rc.done {
		if err := rc.readDone(); err != nil {
			return nil, err
		}
	}
	if rc.onLog == nil {
		s.e.Logs.Add(sc.Name, "debug", fmt.Sprintf("执行完成，用时 %d ms（%s）", time.Since(start).Milliseconds(), engineLabel(eng)))
	}
	return rc, nil
}

// engineLabel names the engine that ran a script, for the script log.
func engineLabel(e jsEngine) string {
	if e != nil && e.kind() == EngineNative {
		return "JavaScriptCore"
	}
	return "goja"
}

func (s *ScriptRunner) jsErr(rc *runCtx, err error, timeout time.Duration) error {
	var je *jsError
	if !errors.As(err, &je) {
		return err
	}
	switch je.kind {
	case "interrupted":
		switch rc.stop.Load() {
		case stopMemory:
			return errors.New("脚本内存占用过高，已终止（保护隧道内存）")
		case stopCancelled:
			return errScriptCancelled
		}
		return fmt.Errorf("脚本执行超时（%s）", timeout)
	case "stack":
		return errors.New("脚本调用栈溢出（递归过深）")
	case "exception":
		return fmt.Errorf("脚本异常：%s", clip(je.msg, 400))
	case "syntax":
		return fmt.Errorf("脚本语法错误：%s", clip(je.msg, 400))
	}
	return errors.New(je.msg)
}

// ---- setup handed to __tern_begin ----

type jsArg struct {
	Has bool   `json:"has"`
	Obj bool   `json:"obj"`
	S   string `json:"s"`
}

type jsEnv struct {
	SurgeVersion string `json:"surge-version"`
	SurgeBuild   string `json:"surge-build"`
	Language     string `json:"language"`
	System       string `json:"system"`
	MihomoIOS    bool   `json:"mihomo-ios"`
}

type jsHTTP struct {
	URL     string      `json:"url,omitempty"`
	Method  string      `json:"method,omitempty"`
	ID      string      `json:"id,omitempty"`
	Status  int         `json:"status,omitempty"`
	Headers [][2]string `json:"headers"`
	Body    int64       `json:"body"`
	// Borrow: Body is the caller's shared buffer mapped without a copy (prelude setBody).
	Borrow bool `json:"borrow,omitempty"`
}

type jsSetup struct {
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	Path      string            `json:"path"`
	Phase     string            `json:"phase"` // request | response | task
	Echo      bool              `json:"echo"`
	Binary    bool              `json:"binary"`
	Export    bool              `json:"export"`
	Arg       jsArg             `json:"arg"`
	Env       jsEnv             `json:"env"`
	EgernEnv  map[string]string `json:"egernEnv"`
	EgernCron string            `json:"egernCron"`
	Req       *jsHTTP           `json:"req,omitempty"`
	Resp      *jsHTTP           `json:"resp,omitempty"`
	Globals   map[string]any    `json:"globals,omitempty"`
	HasParams bool              `json:"hasParams"`
	Params    any               `json:"params,omitempty"`
}

// addBody makes the phase body's blob (hmu held). A shared body is borrowed by an engine that can (goja).
func (rc *runCtx) addBody(h *ScriptHTTP) (int64, bool) {
	id := rc.addBlob(h.Body, false)
	if h.BodyShared && rc.eng != nil && rc.eng.borrows() {
		rc.blobs[id].shared = true
		return id, true
	}
	return id, false
}

func (rc *runCtx) setupJSON(req, resp *ScriptHTTP) (string, error) {
	sc := rc.script
	st := jsSetup{Name: sc.Name, Type: sc.Type, Path: sc.Path, Phase: "task", Echo: sc.Echo, Binary: sc.BinaryBody,
		Export: rc.wantExport, Arg: jsArg{Has: sc.HasArgument, Obj: sc.ArgObject, S: sc.Argument},
		Env:      jsEnv{SurgeVersion: "5.20.0", SurgeBuild: "3000", Language: "zh-Hans", System: "iOS", MihomoIOS: true},
		EgernEnv: sc.Env, EgernCron: sc.Cron, Globals: rc.globals, HasParams: rc.hasParams, Params: rc.params}
	if st.EgernEnv == nil {
		st.EgernEnv = map[string]string{}
	}
	if s := rc.e.st.Load(); s != nil {
		st.Env.Language = s.cfg.scriptLanguage()
	}
	if req != nil {
		st.Phase = "request"
		rh := req.Header
		if req.Host != "" && rh.Get("Host") == "" {
			// review5 P2-4: Go moves Host out of the header map; scripts expect to see it.
			rh = rh.Clone()
			if rh == nil {
				rh = http.Header{}
			}
			rh.Set("Host", req.Host)
		}
		st.Req = &jsHTTP{URL: req.URL, Method: req.Method, Headers: headerPairs(rh), ID: strconv.FormatInt(time.Now().UnixNano(), 36), Body: -1}
		rc.hmu.Lock()
		if resp == nil && req.HasBody {
			st.Req.Body, st.Req.Borrow = rc.addBody(req)
		}
		if resp != nil {
			st.Phase = "response"
			if v := resp.Header.Values("Set-Cookie"); len(v) > 1 {
				rc.origSetCookie = append([]string(nil), v...)
			}
			st.Resp = &jsHTTP{Status: resp.Status, Headers: headerPairs(resp.Header), Body: -1}
			if resp.HasBody {
				st.Resp.Body, st.Resp.Borrow = rc.addBody(resp)
			}
		}
		rc.hmu.Unlock()
	}
	b, err := json.Marshal(st)
	if err != nil {
		return "", fmt.Errorf("脚本参数错误：%v", err)
	}
	return string(b), nil
}

// ---- $done ----

// doneMockJS / doneDescJS: the prelude's doneDesc (prelude.js).
type doneMockJS struct {
	Status     json.RawMessage `json:"status"`
	StatusCode json.RawMessage `json:"statusCode"`
	Headers    *[][2]string    `json:"headers"`
	Body       int64           `json:"body"`
}

type doneDescJS struct {
	Kind       string          `json:"kind"`
	Err        string          `json:"err"`
	Abort      bool            `json:"abort"`
	Mock       *doneMockJS     `json:"mock"`
	URL        *string         `json:"url"`
	Method     *string         `json:"method"`
	Status     json.RawMessage `json:"status"`
	StatusCode json.RawMessage `json:"statusCode"`
	Headers    *[][2]string    `json:"headers"`
	Body       *int64          `json:"body"`
	Undef      bool            `json:"undef"`
	IsNull     bool            `json:"isNull"`
	Value      json.RawMessage `json:"value"`
}

func (rc *runCtx) readDone() error {
	var d doneDescJS
	if err := json.Unmarshal([]byte(rc.doneRaw), &d); err != nil {
		return fmt.Errorf("脚本运行时内部错误：$done %v", err)
	}
	if d.Err != "" {
		msg := "$done 的参数无法读取：" + clip(d.Err, 300)
		if rc.onLog != nil {
			rc.onLog("warn", msg)
		} else {
			rc.e.Logs.Add(rc.name, "warn", msg)
		}
	}
	rc.desc = &d
	return nil
}

// exported is the $done value as plain Go data (task results, 脚本调试); ok=false: undefined / null / none.
func (rc *runCtx) exported() (any, bool) {
	d := rc.desc
	if d == nil || d.Undef || d.IsNull || len(d.Value) == 0 {
		return nil, false
	}
	var v any
	if json.Unmarshal(d.Value, &v) != nil {
		return nil, false
	}
	return v, true
}

// parseStatus accepts 200, "200", "HTTP/1.1 200 OK" (a number or a string from the prelude).
func parseStatus(raw json.RawMessage) int {
	if len(raw) == 0 || string(raw) == "null" {
		return 0
	}
	var f float64
	if json.Unmarshal(raw, &f) == nil {
		return int(f)
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return 0
	}
	s = strings.TrimSpace(s)
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
	d := rc.desc
	if d == nil || d.Kind != "obj" {
		return res, nil
	}
	if d.Abort {
		res.Abort = true
		return res, nil
	}
	if requestPhase {
		if m := d.Mock; m != nil {
			r := &ScriptHTTP{Status: parseStatus(m.Status)}
			if m.Headers != nil {
				r.Header = pairsHeader(*m.Headers)
			}
			if r.Status == 0 {
				r.Status = parseStatus(m.StatusCode)
			}
			if m.Body >= 0 {
				r.Body = rc.blobBytes(m.Body)
			}
			res.Response = r
			return res, nil
		}
		if d.URL != nil {
			res.URL = *d.URL
		}
		if d.Method != nil {
			res.Method = *d.Method
		}
	} else {
		res.Status = parseStatus(d.Status)
		if res.Status == 0 {
			res.Status = parseStatus(d.StatusCode)
		}
	}
	if d.Headers != nil {
		res.Header = pairsHeader(*d.Headers)
		if !requestPhase {
			fixSetCookie(res.Header, rc.origSetCookie)
		}
	}
	if d.Body != nil && *d.Body >= 0 {
		res.Body, res.BodySet = rc.blobBytes(*d.Body), true
		if res.Body == nil {
			res.Body = []byte{}
		}
	}
	return res, nil
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
func startMemGuard(ctx context.Context, stop func()) func() {
	if _, known := availableMemory(); known {
		return startAvailGuard(ctx, stop)
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
					stop()
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
func startAvailGuard(ctx context.Context, stop func()) func() {
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
						stop()
						return
					}
				}
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}

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

func bodyString(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	return strings.ToValidUTF8(string(b), "\uFFFD")
}

type fetchReq struct {
	url, method, policy string
	headers             http.Header
	body                []byte
	timeout             time.Duration
	binary, insecure    bool
	noRedirect          bool
}

// fetchJS is a request as the prelude's parseFetch normalized it.
type fetchJS struct {
	ID         int64       `json:"id"`
	URL        string      `json:"url"`
	Method     string      `json:"method"`
	Headers    [][2]string `json:"headers"`
	Body       int64       `json:"body"`
	Timeout    float64     `json:"timeout"` // ms, 0 = default
	Binary     bool        `json:"binary"`
	Policy     string      `json:"policy"`
	Insecure   bool        `json:"insecure"`
	NoRedirect bool        `json:"noRedirect"`
}

func pairsHeader(p [][2]string) http.Header {
	h := http.Header{}
	for _, kv := range p {
		h.Add(kv[0], kv[1])
	}
	return h
}

// startFetch runs a $httpClient / $task.fetch download (through the core, the script's policy) and delivers
// {id, err} or {id, status, headers, body (blob)} to __tern_deliver. Called with hmu held.
func (rc *runCtx) startFetch(arg string) {
	var j fetchJS
	if json.Unmarshal([]byte(arg), &j) != nil {
		return
	}
	fr := &fetchReq{url: j.URL, method: j.Method, headers: pairsHeader(j.Headers), timeout: 15 * time.Second,
		binary: j.Binary, policy: j.Policy, insecure: j.Insecure, noRedirect: j.NoRedirect}
	if j.Body >= 0 {
		if bl, ok := rc.blobs[j.Body]; ok {
			fr.body = bl.b
			delete(rc.blobs, j.Body)
		}
	}
	if j.Timeout > 0 {
		fr.timeout = time.Duration(j.Timeout * float64(time.Millisecond))
	}
	rc.pending++
	go func() {
		res := rc.do(fr)
		rc.deliverFetch(res, func() error {
			rc.pending--
			d := map[string]any{"id": j.ID}
			var id int64 = -1
			if res.err != nil {
				d["err"] = res.err.Error()
			} else {
				d["status"] = res.status
				d["headers"] = headerPairs(res.header)
				rc.hmu.Lock()
				id = rc.addBlob(res.body, false)
				rc.hmu.Unlock()
				d["body"] = id
			}
			b, _ := json.Marshal(d)
			err := rc.eng.call(rc, "__tern_deliver", string(b))
			if id >= 0 {
				rc.freeBlob(id)
			}
			return err
		})
	}()
}

// headerPairs is h as the scripts see it: names sorted, several values joined with ", " (Set-Cookie too,
// like Surge; parseDone splits it back, review5 P2-3).
func headerPairs(h http.Header) [][2]string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([][2]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, [2]string{k, strings.Join(h[k], ", ")})
	}
	return out
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
	cl0 := resp.ContentLength
	if resp.Header.Get("Content-Encoding") != "" && cl0 >= 0 {
		cl0 = min(cl0*4, smallWorkMax)
	}
	// fix/xmly-memory: a small answer (cookie, JSON) is judged on its own size; only large or unknown
	// downloads are refused by the general gate when memory is short.
	small := cl0 >= 0 && cl0 <= smallWorkMax
	if heapHigh() && !(small && smallWorkOK(cl0, smallFetchFloor)) {
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
func (rc *runCtx) deliverFetch(res *fetchResp, job func() error) {
	done := make(chan struct{})
	rc.post(func() error {
		defer close(done)
		return job()
	})
	if res.release != nil {
		select {
		case <-done:
		case <-rc.ctx.Done():
		}
		res.release()
	}
}
