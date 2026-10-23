package mitm

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// v0.19.22 喜马拉雅 (user 2026-10-23 22:40, v0.19.21: 「打开喜马拉雅后有问题，自动断连」): large bundles run
// one at a time (bigSem) and the 363 KB unlock script costs ~1.1 s of goja per run. Opening the app
// fired a burst of matching requests; every one waited for its turn (up to largeQueueWait, 45 s), the
// app gave up after ~10 s (「客户端已断开，跳过脚本（排队 9881 ms）」) and retried, the runtime ran back to
// back the whole time, and the extension went from 18 MB to 40 MB and was killed by jetsam.
//
// scriptQueue admits a request to the large-bundle queue only when its turn can come in time:
//   - expected wait (runs ahead × the script's measured run time) within queueBudget;
//   - at most queueMaxWaiting waiting, fewer when memory is short (queueLimit), none when it is critical;
//   - Shed at the critical level turns every waiting request away (kick).
//
// A request that is turned away passes through unchanged — what Surge / Quantumult X do when a script
// cannot run — and the script log says 「脚本排队过长，已跳过」 at most once a minute per script.
//
// Coalescing identical in-flight runs (same script + URL) was considered and left out: the waiting
// request's response body is not loaded yet (review5 P0-1, the slot is taken first), two responses for
// the same URL routinely differ (track ids, timestamps, signatures), and scripts have side effects
// ($persistentStore, notifications) a shared result would hide.
type scriptQueue struct {
	mu      sync.Mutex
	waiting int
	avg     map[string]time.Duration // smoothed slot time per script path
	kick    chan struct{}            // closed (and replaced) by kickAll
	logged  map[string]time.Time     // last 「排队过长」 log line per script name
}

func newScriptQueue() *scriptQueue {
	return &scriptQueue{avg: map[string]time.Duration{}, kick: make(chan struct{}), logged: map[string]time.Time{}}
}

var (
	// queueBudgetNs: the longest expected wait a request is queued for (apps give up after ~10 s and
	// the run itself still takes its time once the turn comes).
	queueBudgetNs atomic.Int64
	// queueMaxWaitingN: requests waiting for the large-bundle lock at most, with memory to spare.
	queueMaxWaitingN atomic.Int64
)

func init() {
	queueBudgetNs.Store(int64(6 * time.Second))
	queueMaxWaitingN.Store(6)
}

// queueGrace: how much longer than queueBudget a waiter may wait before it passes through anyway.
const queueGrace = 2 * time.Second

// queueDefaultRun is the assumed slot time of a script that has not run yet.
const queueDefaultRun = time.Second

// queueTightAvail: below this much available memory only one request may wait.
const queueTightAvail = 12 << 20

// queueLimit is how many requests may wait now: queueMaxWaitingN, 1 when memory is tight, 0 when the
// body gates already refuse work (heapHigh).
func queueLimit() int {
	n := int(queueMaxWaitingN.Load())
	if a, known := availableMemory(); known && a < queueTightAvail {
		n = min(n, 1)
	}
	if heapHigh() {
		n = 0
	}
	return n
}

// errQueueSkip marks a request the queue turned away (handler: pass through, rate-limited log).
type errQueueSkip struct{ msg string }

func (e *errQueueSkip) Error() string { return e.msg }

func isQueueSkip(err error) bool {
	var q *errQueueSkip
	return errors.As(err, &q)
}

// admit registers a waiter for the large-bundle lock, or says why not. ahead: runs in front of this
// request (the one holding the lock plus the waiters). The returned leave must be called when the wait
// ends, whatever the outcome; kick ends the wait early (Shed).
func (q *scriptQueue) admit(key string, running bool) (leave func(), kick <-chan struct{}, err error) {
	limit := -1
	if running || q.Waiting() > 0 {
		limit = queueLimit() // outside q.mu: heapHigh may run a (rate-limited) GC
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	ahead := q.waiting
	if running {
		ahead++
	}
	if ahead > 0 {
		run := q.avg[key]
		if run <= 0 {
			run = queueDefaultRun
		}
		est := time.Duration(ahead) * run
		if limit < 0 {
			limit = int(queueMaxWaitingN.Load())
		}
		switch {
		case limit == 0:
			return nil, nil, &errQueueSkip{fmt.Sprintf("脚本排队过长，已跳过（%s，前面还有 %d 个）", heapHighReason(), ahead)}
		case q.waiting >= limit:
			return nil, nil, &errQueueSkip{fmt.Sprintf("脚本排队过长，已跳过（前面还有 %d 个，最多排 %d 个）", ahead, limit)}
		case est > time.Duration(queueBudgetNs.Load()):
			return nil, nil, &errQueueSkip{fmt.Sprintf("脚本排队过长，已跳过（前面还有 %d 个，预计等待 %.1f 秒）", ahead, est.Seconds())}
		}
	}
	q.waiting++
	var once sync.Once
	return func() {
		once.Do(func() {
			q.mu.Lock()
			q.waiting--
			q.mu.Unlock()
		})
	}, q.kick, nil
}

// observe records how long a run held the large-bundle lock (smoothed, 1/4 weight for the new sample).
func (q *scriptQueue) observe(key string, d time.Duration) {
	if key == "" || d <= 0 {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if old, ok := q.avg[key]; ok {
		d = (3*old + d) / 4
	}
	q.avg[key] = d
	if len(q.avg) > 64 { // scripts removed from the config: start over rather than grow
		q.avg = map[string]time.Duration{key: d}
	}
}

// kickAll turns away every request waiting right now (Shed at the critical level). Returns how many.
func (q *scriptQueue) kickAll() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := q.waiting
	close(q.kick)
	q.kick = make(chan struct{})
	return n
}

// Waiting reports how many requests wait for the large-bundle lock (diagnostics, tests).
func (q *scriptQueue) Waiting() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.waiting
}

// shouldLog rate-limits the queue's script-log line: once a minute per script.
func (q *scriptQueue) shouldLog(name string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := time.Now()
	if t, ok := q.logged[name]; ok && now.Sub(t) < queueLogEvery {
		return false
	}
	if len(q.logged) > 64 {
		q.logged = map[string]time.Time{}
	}
	q.logged[name] = now
	return true
}

var queueLogEvery = time.Minute
