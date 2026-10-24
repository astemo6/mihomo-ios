package mitm

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/andybalholm/brotli"
)

func brotliOf(t *testing.T, b []byte, quality int) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := brotli.NewWriterLevel(&buf, quality)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// semi-compressible payload: JSON-ish text with random runs, so the stream has several meta-blocks.
func brotliPayload(n int, seed int64) []byte {
	rnd := rand.New(rand.NewSource(seed))
	out := make([]byte, 0, n)
	words := []string{`{"id":`, `"name":"`, `","items":[`, `true,`, `null,`, `"url":"https://example.com/`, `]},`}
	for len(out) < n {
		out = append(out, words[rnd.Intn(len(words))]...)
		for i := rnd.Intn(12); i > 0; i-- {
			out = append(out, byte('a'+rnd.Intn(26)))
		}
	}
	return out[:n]
}

// The upstream bug: andybalholm/brotli returns a clean io.EOF for most truncated streams. This pins it (so the
// wrapper can be dropped once upstream fixes it) and shows the strict reader catching every cut.
func TestBrotliTruncatedIsDecodeError(t *testing.T) {
	for _, size := range []int{900, 20 << 10, 300 << 10} { // small path, one source chunk, exact-size path
		plain := brotliPayload(size, int64(size))
		enc := brotliOf(t, plain, 5)
		if got, err := decodeBody("br", enc, 8<<20); err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("size %d: complete stream: err %v, equal %v", size, err, bytes.Equal(got, plain))
		}
		lax := 0
		cuts := []int{1, 2, len(enc) / 3, len(enc) / 2, len(enc) - 2, len(enc) - 1}
		for c := 5; c < len(enc); c += max(1, len(enc)/40) {
			cuts = append(cuts, c)
		}
		for _, cut := range cuts {
			if cut <= 0 || cut >= len(enc) {
				continue
			}
			// upstream reader alone
			if _, err := io.ReadAll(brotli.NewReader(bytes.NewReader(enc[:cut]))); err == nil {
				lax++
			}
			got, err := decodeBody("br", enc[:cut], 8<<20)
			if err == nil {
				t.Fatalf("size %d: cut at %d/%d decoded to %d bytes without an error", size, cut, len(enc), len(got))
			}
			// script API (Egern compression.unbrotli)
			if _, err := egernCompress("unbrotli", enc[:cut]); err == nil {
				t.Fatalf("size %d: unbrotli of cut at %d/%d: no error", size, cut, len(enc))
			}
		}
		t.Logf("size %d (%d B br): upstream reader accepted %d of %d truncations", size, len(enc), lax, len(cuts))
	}
}

func TestBrotliStateFieldPinned(t *testing.T) {
	if brotliStateField < 0 {
		t.Fatal("brotli.Reader has no int field state: the truncation check is off (brotlistrict.go)")
	}
	plain := brotliPayload(4000, 7)
	br := brotli.NewReader(bytes.NewReader(brotliOf(t, plain, 5)))
	if _, err := io.ReadAll(br); err != nil || !brotliFinished(br) {
		t.Fatalf("complete stream not in stateDone (%d): %v", brotliStateDone, err)
	}
}

func TestBrotliStrictEdges(t *testing.T) {
	// empty body (no stream at all) stays empty, as before
	if got, err := decodeBody("br", nil, 1<<20); err != nil || len(got) != 0 {
		t.Fatalf("empty: %q %v", got, err)
	}
	// an empty stream that is complete
	enc := brotliOf(t, nil, 5)
	if got, err := decodeBody("br", enc, 1<<20); err != nil || len(got) != 0 {
		t.Fatalf("empty stream: %q %v", got, err)
	}
	// trailing garbage is still rejected (upstream's excessive input)
	plain := brotliPayload(5000, 1)
	enc = brotliOf(t, plain, 5)
	if _, err := decodeBody("br", append(append([]byte{}, enc...), 'x', 'y'), 1<<20); err == nil {
		t.Fatal("trailing garbage accepted")
	}
	// Reset reuse: truncated, then complete on the same reader
	s := newStrictBrotli(bytes.NewReader(enc[:len(enc)/2]))
	if _, err := io.ReadAll(s); !errors.Is(err, errBrotliTruncated) {
		t.Fatalf("first: %v", err)
	}
	if err := s.Reset(bytes.NewReader(enc)); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(s); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("after reset: %v equal %v", err, bytes.Equal(got, plain))
	}
	// sticky: reading again after the end keeps saying EOF
	if n, err := s.Read(make([]byte, 10)); n != 0 || err != io.EOF {
		t.Fatalf("after EOF: %d %v", n, err)
	}
	// a source that trickles one byte at a time
	got, err := io.ReadAll(newStrictBrotli(&oneByteReader{r: bytes.NewReader(enc)}))
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("trickle: %v", err)
	}
	if _, err := io.ReadAll(newStrictBrotli(&oneByteReader{r: bytes.NewReader(enc[:len(enc)-1])})); err == nil {
		t.Fatal("trickle truncated: no error")
	}
	// the capture prefix decoder stays lenient (it decodes cut captures on purpose)
	if got, err := decodePrefix("br", enc[:len(enc)/2], 1<<20); err != nil || len(got) == 0 {
		t.Fatalf("decodePrefix: %d %v", len(got), err)
	}
}

type oneByteReader struct{ r io.Reader }

func (o *oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return o.r.Read(p)
}

// brxBody is what the test upstream's /brx answers (Content-Encoding: br, as is).
var brxBody atomic.Value

// TestBrotliTruncatedResponseSkipsScript: end to end, a cut br answer no longer reaches a body script as a
// shorter body; it passes through as received with a decode note. The complete answer still runs the script.
func TestBrotliTruncatedResponseSkipsScript(t *testing.T) {
	cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
		`n = type=http-response,pattern=^https://api\.test\.com/brx,requires-body=1,script-path=n.js`)}
	h := newHarness(t, cfg, map[string]string{"n.js": `$done({body: "len=" + $response.body.length})`})
	plain := brotliPayload(40<<10, 3)
	enc := brotliOf(t, plain, 5)
	brxBody.Store(enc)
	if _, body := h.get("https://api.test.com/brx"); body != "len="+strconv.Itoa(len(plain)) {
		t.Fatalf("complete: %q", clip(body, 60))
	}
	cut := enc[:len(enc)*2/3]
	brxBody.Store(cut)
	resp, body := h.get("https://api.test.com/brx")
	if strings.HasPrefix(body, "len=") {
		t.Fatalf("truncated br reached the script: %q", body)
	}
	if body != string(cut) || resp.Header.Get("Content-Encoding") != "br" {
		t.Fatalf("not passed through as received: %d bytes (cut %d), encoding %q", len(body), len(cut), resp.Header.Get("Content-Encoding"))
	}
	if notes := entryNotes(h.e); !strings.Contains(notes, "truncated") {
		t.Fatalf("notes %q", notes)
	}
}
