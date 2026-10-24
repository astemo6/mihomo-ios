package mitm

// r7 (review: a script download that timed out waiting for body budget went ahead with NO accounting
// while the heap was < 70 %, and an unknown-length download pre-reserved 4 MB of the 6 MB pool):
//
//   - a download is charged incrementally as it is read (fetchChunk at a time, exact length up front when
//     the server announces it), and the whole charge is returned once the callback ran;
//   - when budget cannot be had within fetchBudgetWait the download may continue unbudgeted — that keeps a
//     script that itself holds a body share from deadlocking on its own fetch — but only ONE unbudgeted
//     download runs at a time and it is capped at fetchUnbudgetedMax.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

const fetchChunk = 256 << 10

// fetchUnbudgetedMax caps a download that runs outside the budget (anti-deadlock path).
var fetchUnbudgetedMax int64 = 2 << 20

// fetchSlotWait bounds how long a download waits for the unbudgeted slot (another unbudgeted download is
// running). Downloads queue for the slot rather than failing after fetchBudgetWait, so a script that fires
// several requests while the budget is held elsewhere gets them one after another (the script's own
// timeout / ctx still applies).
var fetchSlotWait = 10 * time.Second

// unbudgetedFetch is the single unbudgeted-download slot.
var unbudgetedFetch = make(chan struct{}, 1)

var errFetchNoBudget = errors.New("内存预算不足，已跳过下载（保护隧道内存）")

// fetchCharge is one download's share of bodyBudget, grown as bytes arrive.
type fetchCharge struct {
	ctx        context.Context
	held       int64 // bytes taken from bodyBudget
	rels       []func()
	unbudgeted bool // holds the unbudgeted slot instead
	once       sync.Once
}

// ensure makes sure total bytes are covered, growing the charge or switching to the unbudgeted slot.
func (c *fetchCharge) ensure(total int64) error {
	if c.unbudgeted {
		if total > fetchUnbudgetedMax {
			return fmt.Errorf("内存预算不足，响应体超过 %d MB 已跳过", fetchUnbudgetedMax>>20)
		}
		return nil
	}
	if total <= c.held {
		return nil
	}
	need := total - c.held
	if need < fetchChunk {
		need = fetchChunk
	}
	// fix/xmly-memory (device 2026-10-24: 「获取Cookie失败:内存预算不足，已跳过下载」): a small answer does not
	// wait for the global budget — under pressure it has shrunk to 256 KB and the response that started the
	// script holds it until the script ends, so the fetch waited fetchBudgetWait and was refused. Small
	// totals take the small pool when the global budget has no room right now.
	if total <= smallWorkMax {
		n := min(max(total-c.held, 64<<10), smallWorkMax-c.held)
		if smallWorkOK(total, smallFetchFloor) {
			if rel := acquireSmall(c.ctx, n, fetchBudgetWait); rel != nil {
				c.held += n
				c.rels = append(c.rels, rel)
				return nil
			}
		}
	}
	if c.held+need > int64(MaxScriptBody) {
		need = max(total-c.held, int64(MaxScriptBody)-c.held)
	}
	if rel := bodyBudget.acquire(c.ctx, need, fetchBudgetWait); rel != nil {
		c.held += need
		c.rels = append(c.rels, rel)
		return nil
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if heapHigh() {
		return errFetchNoBudget
	}
	// anti-deadlock path: one unbudgeted download at a time, hard-capped.
	if total > fetchUnbudgetedMax {
		return fmt.Errorf("内存预算不足，响应体超过 %d MB 已跳过", fetchUnbudgetedMax>>20)
	}
	t := time.NewTimer(fetchSlotWait)
	defer t.Stop()
	select {
	case unbudgetedFetch <- struct{}{}:
	case <-t.C:
		return errFetchNoBudget
	case <-c.ctx.Done():
		return c.ctx.Err()
	}
	c.unbudgeted = true
	c.releaseBudget() // the slot now covers the whole download
	return nil
}

func (c *fetchCharge) releaseBudget() {
	for _, r := range c.rels {
		r()
	}
	c.rels, c.held = nil, 0
}

// release returns everything (safe to call more than once).
func (c *fetchCharge) release() {
	c.once.Do(func() {
		c.releaseBudget()
		if c.unbudgeted {
			<-unbudgetedFetch
		}
	})
}

// read reads r up to limit (+1 to detect overflow), charging the budget as it goes.
func (c *fetchCharge) read(r io.Reader, contentLength int64, limit int) ([]byte, error) {
	if contentLength >= 0 && contentLength <= int64(limit) {
		if err := c.ensure(contentLength); err != nil {
			return nil, err
		}
	}
	var buf []byte
	if contentLength >= 0 && contentLength <= int64(limit) {
		buf = make([]byte, 0, contentLength+1)
	}
	tmp := make([]byte, 32<<10)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			if len(buf)+n > limit {
				return append(buf, tmp[:n]...), nil // caller reports "too big" (len > limit)
			}
			if e := c.ensure(int64(len(buf) + n)); e != nil {
				return nil, e
			}
			buf = append(buf, tmp[:n]...)
		}
		if err == io.EOF {
			return buf, nil
		}
		if err != nil {
			return nil, err
		}
	}
}
