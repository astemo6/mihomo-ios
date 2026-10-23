package mitm

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// TestGenLaneFixtures writes UnitTests/NativeBodyFixtures.json, the decode corpus NativeBodyStore.swift must agree
// with (UnitTests/NativeBodyStoreTests.swift feeds each case in several chunk sizes). Every "ok" case is checked
// against the Go path's decoder here, so the two decoders share one truth. Regenerate with
//
//	LANE_FIXTURES_OUT=$PWD/../UnitTests/NativeBodyFixtures.json go test ./mitm -run TestGenLaneFixtures
func TestGenLaneFixtures(t *testing.T) {
	out := os.Getenv("LANE_FIXTURES_OUT")
	// highly compressible past several 64 KB decoder scratch buffers, small encoded
	doc := append(laneDoc(4000), bytes.Repeat([]byte(`,{"id":12345,"title":"video","ad":false}`), 6000)...)
	small := []byte(`{"ok":true}`)
	type fx struct {
		Name   string `json:"name"`
		Enc    string `json:"enc"`
		Data   string `json:"data"`
		Limit  int    `json:"limit"`
		Expect string `json:"expect"` // ok | decode | too-big
		Len    int    `json:"len,omitempty"`
		SHA256 string `json:"sha256,omitempty"`
	}
	var list []fx
	add := func(name, enc string, data []byte, limit int, expect string, plain []byte) {
		f := fx{Name: name, Enc: enc, Data: base64.StdEncoding.EncodeToString(data), Limit: limit, Expect: expect}
		d, err := decodeBody(enc, data, limit)
		switch expect {
		case "ok":
			if err != nil || !bytes.Equal(d, plain) {
				t.Fatalf("%s: Go decode %v", name, err)
			}
			s := sha256.Sum256(plain)
			f.Len, f.SHA256 = len(plain), hex.EncodeToString(s[:])
		default:
			// br-truncated: the Go path's brotli reader (andybalholm) returns the partial output without an
			// error — a known laxness of the Go path; the lane must report it as a decode error.
			if err == nil && len(data) <= limit && name != "br-truncated" {
				t.Fatalf("%s: Go path decodes it (want %s)", name, expect)
			}
		}
		list = append(list, f)
	}
	gz := func(p []byte, name, comment string, extra []byte) []byte {
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		w.Name, w.Comment, w.Extra = name, comment, extra
		_, _ = w.Write(p)
		_ = w.Close()
		return b.Bytes()
	}
	zl := func(p []byte) []byte {
		var b bytes.Buffer
		w := zlib.NewWriter(&b)
		_, _ = w.Write(p)
		_ = w.Close()
		return b.Bytes()
	}
	raw := func(p []byte) []byte {
		var b bytes.Buffer
		w, _ := flate.NewWriter(&b, 6)
		_, _ = w.Write(p)
		_ = w.Close()
		return b.Bytes()
	}
	add("identity", "", small, 1<<20, "ok", small)
	add("identity-too-big", "identity", bytes.Repeat(small, 200), 1000, "too-big", nil)
	add("gzip-plain", "gzip", gz(doc, "", "", nil), 1<<20, "ok", doc)
	add("gzip-header-fields", "x-gzip", gz(small, "body.json", "comment here", []byte("XYextra")), 1<<20, "ok", small)
	add("gzip-multi-member", "gzip", append(gz(small, "", "", nil), gz(doc, "", "", nil)...), 1<<20, "ok", append(append([]byte{}, small...), doc...))
	add("gzip-too-big", "gzip", gz(doc, "", "", nil), 4096, "too-big", nil)
	g := gz(doc, "", "", nil)
	add("gzip-truncated", "gzip", g[:len(g)/2], 1<<20, "decode", nil)
	c := append([]byte{}, g...)
	for i := 20; i < 60 && i < len(c); i++ {
		c[i] ^= 0x5a
	}
	add("gzip-corrupt", "gzip", c, 1<<20, "decode", nil)
	add("deflate-zlib", "deflate", zl(doc), 1<<20, "ok", doc)
	add("deflate-raw", "deflate", raw(doc), 1<<20, "ok", doc)
	add("br", "br", brEncode(doc), 1<<20, "ok", doc)
	add("br-small", "br", brEncode(small), 1<<20, "ok", small)
	b := brEncode(doc)
	add("br-truncated", "br", b[:len(b)/2], 1<<20, "decode", nil)
	add("br-too-big", "br", b, 10000, "too-big", nil)
	if out == "" {
		t.Skip("set LANE_FIXTURES_OUT to write the corpus (the cases were checked against the Go decoder)")
	}
	j, _ := json.MarshalIndent(list, "", " ")
	if err := os.WriteFile(out, append(j, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
