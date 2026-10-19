package mitm

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// v0.19.6 (review 7): the script runtime under concurrent requests.

// A burst of requests hitting one large script while its compiled program is not cached (first use after
// a start, or right after FreeMemory dropped the cache under memory pressure) compiled it once per request
// in parallel: compile ran before the semaphore, ~14× the source each. It must compile once.
func TestV0196ConcurrentColdCompileOnce(t *testing.T) {
	e := New(t.TempDir(), nil, nil)
	big := strings.Repeat("var x = 1;\n", 30000) + "$done({});\n" // ~330 KB
	sc := &Script{Name: "big", Type: "http-request", Source: []byte(big), Timeout: 30}
	rule := &Rule{Script: sc}
	runtime.GC()
	debug.FreeOSMemory()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	base := ms.HeapAlloc
	var peak atomic.Uint64
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > peak.Load() {
				peak.Store(m.HeapAlloc)
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	before := compileCount.Load()
	const n = 24
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := &ScriptHTTP{URL: "https://a.test/x", Method: "GET", Header: http.Header{}}
			if _, err := e.scripts.Run(context.Background(), rule, req, nil); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(stop)
	close(errs)
	for err := range errs {
		t.Errorf("run: %v", err)
	}
	compiles := compileCount.Load() - before
	p := peak.Load()
	if p < base {
		p = base
	}
	t.Logf("%d concurrent cold runs of a %d KB script: %d compile(s), peak heap +%.1f MB", n, len(big)>>10, compiles, float64(p-base)/(1<<20))
	if compiles != 1 {
		t.Fatalf("compiled %d times for one script (want 1)", compiles)
	}
	if LiveRuntimes() != 0 {
		t.Fatalf("live runtimes after the burst: %d", LiveRuntimes())
	}
}

// Many concurrent requests with $persistentStore writes: no lost runtime, bounded live runtimes, every
// run answered.
func TestV0196ConcurrentScriptsPersistentStore(t *testing.T) {
	e := New(t.TempDir(), nil, nil)
	js := `var k = "k" + ($request.url.length % 7);
var v = $persistentStore.read(k) || "0";
$persistentStore.write(String(Number(v) + 1), k);
$done({headers: Object.assign({}, $request.headers, {"X-Run": "1"})});`
	sc := &Script{Name: "ps", Type: "http-request", Source: []byte(js), Timeout: 30}
	rule := &Rule{Script: sc}
	var maxLive atomic.Int64
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if l := LiveRuntimes(); l > maxLive.Load() {
				maxLive.Store(l)
			}
			time.Sleep(time.Millisecond)
		}
	}()
	const n = 200
	var wg sync.WaitGroup
	var ok atomic.Int64
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := &ScriptHTTP{URL: fmt.Sprintf("https://a.test/%d", i), Method: "GET", Header: http.Header{"A": {"b"}}}
			r, err := e.scripts.Run(context.Background(), rule, req, nil)
			if err != nil {
				t.Errorf("run %d: %v", i, err)
				return
			}
			if r != nil && r.Header.Get("X-Run") == "1" {
				ok.Add(1)
			}
		}(i)
	}
	wg.Wait()
	close(stop)
	if ok.Load() != n {
		t.Fatalf("%d of %d runs returned the script's headers", ok.Load(), n)
	}
	if m := maxLive.Load(); m > 3 {
		t.Fatalf("up to %d runtimes alive at once (cap 2 HTTP + 1 task)", m)
	}
}
