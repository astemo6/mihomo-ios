package mitm

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
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

// r7: a replayed response longer than MaxBody is marked truncated (not silently cut).
func TestR7ReplayTruncatedMarked(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(`^https://api\.test\.com/nothing - reject`)}
	h := newHarness(t, cfg, nil)
	r, _ := h.client.Get("https://api.test.com/x")
	if r != nil {
		r.Body.Close()
	}
	var id int64
	for _, s := range h.e.Requests.List(0) {
		if strings.HasSuffix(s.URL, "/x") {
			id = s.ID
		}
	}
	if id == 0 {
		t.Fatal("not captured")
	}
	big := bytes.Repeat([]byte("q"), MaxBody+10)
	h.up.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(big) })
	res, err := h.e.Replay(id, nil)
	if err != nil || !res.Truncated || res.Length != MaxBody {
		t.Fatalf("replay: %v truncated=%v len=%d", err, res.Truncated, res.Length)
	}
}

// r7: a ClientHello bigger than the 8 KB reader with the SNI after a large extension is still parsed.
func TestR7PeekSNILargeClientHello(t *testing.T) {
	ext := func(typ int, data []byte) []byte {
		return append([]byte{byte(typ >> 8), byte(typ), byte(len(data) >> 8), byte(len(data))}, data...)
	}
	host := "big.example.com"
	sniData := append([]byte{0, byte(len(host) + 3), 0, 0, byte(len(host))}, host...)
	exts := append(ext(0x15, make([]byte, 10000)), ext(0, sniData)...)
	body := append(make([]byte, 34), 0)         // version+random, session id len 0
	body = append(body, 0, 2, 0x13, 0x01, 1, 0) // one cipher suite, one compression method
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)
	hs := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	br := bufio.NewReaderSize(bytes.NewReader(rec), 8192)
	if got := peekSNI(br); got == host {
		t.Log("(8 KB reader happened to fit)")
	}
	br = growForClientHello(br)
	if got := peekSNI(br); got != host {
		t.Fatalf("SNI %q, want %q", got, host)
	}
}

// r7: a store file that is unreadable on the first read but fine on the re-read is not quarantined.
func TestR7StoreQuarantineAfterReread(t *testing.T) {
	home := t.TempDir()
	s := NewStore(home)
	_ = os.MkdirAll(filepath.Dir(s.path), 0o755)
	_ = os.WriteFile(s.path, []byte(`{"a":`), 0o644)
	go func() {
		time.Sleep(10 * time.Millisecond)
		_ = os.WriteFile(s.path+".tmp", []byte(`{"a":"1"}`), 0o644)
		_ = os.Rename(s.path+".tmp", s.path)
	}()
	m, _, ok := s.readFile()
	if !ok || m["a"] != "1" {
		t.Fatalf("read %v %v", m, ok)
	}
	if _, err := os.Stat(s.path + ".bad"); err == nil {
		t.Fatal("quarantined a store that re-read fine")
	}
	_ = os.WriteFile(s.path, []byte(`{"a":`), 0o644)
	if _, _, ok := s.readFile(); ok {
		t.Fatal("broken store read as ok")
	}
	if _, err := os.Stat(s.path + ".bad"); err != nil {
		t.Fatal("persistently broken store not quarantined")
	}
}
