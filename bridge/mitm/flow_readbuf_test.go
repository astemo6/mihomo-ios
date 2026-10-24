package mitm

// fix/selective-largebody: FlowRead reuses one buffer per flow and direction. The v0.19.25 smoke bench
// (UnitTests/NativeMitmSelectiveTests, jq 960 KB ×16) had the selective mode's Go heap peak 14.9 MB above the
// all-Go path: the native front hands bodies over 256 KB back to Go (adopt), Go runs the jq rule, and the
// native session then pulls the result with MitmFlowRead in 16 KB pieces — each call allocated a fresh slice
// that gomobile copies into NSData and drops, i.e. ~1× the body of garbage per flow on top of what the Go path
// holds.

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type bigJSONRT struct{ body []byte }

func (rt bigJSONRT) RoundTrip(r *http.Request) (*http.Response, error) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Content-Length", strconv.Itoa(len(rt.body)))
	return &http.Response{StatusCode: 200, Status: "200 OK", Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: h, ContentLength: int64(len(rt.body)), Body: io.NopCloser(bytes.NewReader(rt.body)), Request: r}, nil
}

// bigJSON: {"data":{"items":[…]},"ads":[…]} of about n bytes.
func bigJSON(n int) []byte {
	var b strings.Builder
	b.WriteString(`{"data":{"items":[`)
	for i := 0; b.Len() < n-64; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"id":`)
		b.WriteString(strconv.Itoa(i))
		b.WriteString(`,"title":"item number `)
		b.WriteString(strconv.Itoa(i))
		b.WriteString(` lorem ipsum dolor sit amet"}`)
	}
	b.WriteString(`]},"ads":[1,2,3]}`)
	return []byte(b.String())
}

func jqLargeHarness(t *testing.T) *harness {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Rules: items(
		`http-response-jq ^https://api\.test\.com/big 'del(.ads)'`,
	)}
	return newHarness(t, cfg, nil)
}

// TestFlowReadNoGarbagePerChunk: pulling a ~960 KB jq result through FlowRead in the native session's 16 KB
// pieces allocates (almost) nothing per piece — before the fix it allocated the whole body again.
func TestFlowReadNoGarbagePerChunk(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation figures under -race are meaningless")
	}
	h := jqLargeHarness(t)
	body := bigJSON(960 << 10)
	sim := newFlowSim(t, h.e)
	sim.chunk = 16 << 10
	sim.rt = bigJSONRT{body: body}
	// warm (and check the rule applied)
	res := sim.do("GET", "https://api.test.com/big", http.Header{"User-Agent": {"T"}}, nil)
	if res.err != "" {
		t.Fatal(res.err)
	}
	if last := res.decisions[len(res.decisions)-1]; last.Body != "read" || bytes.Contains(res.body, []byte(`"ads"`)) || len(res.body) < 900<<10 {
		t.Fatalf("jq not applied through the flow: mode %q, %d bytes, ads kept %v", last.Body, len(res.body), bytes.Contains(res.body, []byte(`"ads"`)))
	}
	var alloc uint64
	sim.readAlloc = &alloc
	worst := uint64(0)
	for i := 0; i < 3; i++ {
		res = sim.do("GET", "https://api.test.com/big", http.Header{"User-Agent": {"T"}}, nil)
		if res.err != "" {
			t.Fatal(res.err)
		}
		if res.n < 900<<10 {
			t.Fatalf("pulled %d bytes", res.n)
		}
		worst = max(worst, alloc)
	}
	t.Logf("FlowRead of a %d KB jq result in 16 KB pieces: %d KB allocated (worst of 3)", res.n>>10, worst>>10)
	if worst > 128<<10 {
		t.Fatalf("FlowRead allocated %d KB for a %d KB body (want ≲ one buffer)", worst>>10, res.n>>10)
	}
	waitFlows(t)
}

// TestFlowReadSharedBufferSemantics: many flows at once, each pulled in different piece sizes, all get the
// whole rewritten body (each flow's reads reuse its own buffer; callers copy before the next read).
func TestFlowReadSharedBufferSemantics(t *testing.T) {
	h := jqLargeHarness(t)
	body := bigJSON(300 << 10)
	want := func() []byte {
		s := newFlowSim(t, h.e)
		s.rt = bigJSONRT{body: body}
		r := s.do("GET", "https://api.test.com/big", nil, nil)
		if r.err != "" || bytes.Contains(r.body, []byte(`"ads"`)) {
			t.Fatalf("reference: %s", r.err)
		}
		return r.body
	}()
	var mu sync.Mutex
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			s := newFlowSim(t, h.e)
			s.chunk = 1000 + g*3001
			s.rt = bigJSONRT{body: body}
			r := s.do("GET", "https://api.test.com/big", nil, nil)
			mu.Lock()
			defer mu.Unlock()
			if r.err != "" || !bytes.Equal(r.body, want) {
				t.Errorf("goroutine %d: err %q, %d bytes (want %d), equal %v", g, r.err, len(r.body), len(want), bytes.Equal(r.body, want))
			}
		}(g)
	}
	wg.Wait()
	waitFlows(t)

}
