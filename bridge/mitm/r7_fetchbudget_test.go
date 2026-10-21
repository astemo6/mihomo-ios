package mitm

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

// r7: unknown-length downloads are charged as read (no 4 MB pre-reservation).
func TestR7FetchChargeIncremental(t *testing.T) {
	rel := bodyBudget.acquire(t.Context(), bodyBudgetBytes-(1<<20), time.Second) // leave 1 MB free
	if rel == nil {
		t.Fatal("budget")
	}
	defer rel()
	c := &fetchCharge{ctx: t.Context()}
	body := bytes.Repeat([]byte("z"), 600<<10)
	b, err := c.read(io.MultiReader(bytes.NewReader(body)), -1, MaxScriptBody)
	if err != nil || len(b) != len(body) {
		t.Fatalf("read: %v %d", err, len(b))
	}
	if c.unbudgeted {
		t.Fatal("600 KB unknown-length download fell to the unbudgeted path with 1 MB free")
	}
	if c.held < int64(len(body)) || c.held > 1<<20 {
		t.Fatalf("charged %d for %d bytes", c.held, len(body))
	}
	c.release()
	if n := bodyBudget.inUse(); n != bodyBudgetBytes-(1<<20) {
		t.Fatalf("budget after release: %d", n)
	}
}

// r7: with the budget exhausted only one download runs unbudgeted at a time, and it is size-capped.
func TestR7FetchUnbudgetedCapped(t *testing.T) {
	oldWait := fetchBudgetWait
	fetchBudgetWait = 50 * time.Millisecond
	defer func() { fetchBudgetWait = oldWait }()
	rel := bodyBudget.acquire(t.Context(), bodyBudgetBytes, time.Second)
	if rel == nil {
		t.Fatal("budget")
	}
	defer rel()
	a := &fetchCharge{ctx: t.Context()}
	if _, err := a.read(strings.NewReader("hello"), -1, MaxScriptBody); err != nil || !a.unbudgeted {
		t.Fatalf("first download should run unbudgeted: %v %v", err, a.unbudgeted)
	}
	b := &fetchCharge{ctx: context.Background()}
	if _, err := b.read(strings.NewReader("hello"), -1, MaxScriptBody); err == nil {
		t.Fatal("second concurrent unbudgeted download was allowed")
	}
	b.release()
	a.release()
	big := &fetchCharge{ctx: t.Context()}
	if _, err := big.read(bytes.NewReader(make([]byte, fetchUnbudgetedMax+1)), -1, MaxScriptBody); err == nil {
		t.Fatal("unbudgeted download past fetchUnbudgetedMax was allowed")
	}
	big.release()
	if len(unbudgetedFetch) != 0 {
		t.Fatal("unbudgeted slot leaked")
	}
}
