package libmihomo

// Native MitM stage 3 lane s3-h2: fixtures for the Swift HTTP/2 codec tests (UnitTests/NativeMitmH2Tests.swift),
// written by Go's own golang.org/x/net/http2 Framer and hpack Encoder, plus a check that the Swift Huffman
// table (PacketTunnel/NativeMitM/H2/HPACKHuffmanTable.swift) encodes every symbol exactly like Go's.
//
//	TERN_GEN_H2=1 go test . -run TestH2Fixtures   # regenerate UnitTests/NativeMitmH2Fixtures.json
//	go test . -run TestH2Fixtures                 # CI: the committed file must match what Go writes now

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type h2FixHPACKBlock struct {
	Hex    string      `json:"hex"`
	Fields [][2]string `json:"fields"`
}

type h2FixHPACKSeq struct {
	Name      string            `json:"name"`
	TableSize uint32            `json:"tableSize"` // decoder table size (SETTINGS_HEADER_TABLE_SIZE)
	Blocks    []h2FixHPACKBlock `json:"blocks"`
}

type h2FixFrame struct {
	Name   string         `json:"name"`
	Hex    string         `json:"hex"`
	Expect map[string]any `json:"expect"`
}

type h2Fixtures struct {
	HPACK  []h2FixHPACKSeq `json:"hpack"`
	Frames []h2FixFrame    `json:"frames"`
}

func h2Fields(kv ...string) []hpack.HeaderField {
	var out []hpack.HeaderField
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, hpack.HeaderField{Name: kv[i], Value: kv[i+1]})
	}
	return out
}

func genH2Fixtures(t *testing.T) []byte {
	var fx h2Fixtures
	// HPACK: sequences encoded by one Go encoder each (dynamic table carried across blocks).
	seqs := []struct {
		name      string
		tableSize uint32
		blocks    [][]hpack.HeaderField
	}{
		{"requests", 4096, [][]hpack.HeaderField{
			h2Fields(":method", "GET", ":scheme", "https", ":authority", "api.example.com", ":path", "/v1/feed?page=1",
				"user-agent", "Tern/1.0 (iPhone; iOS 17.4)", "accept", "application/json", "accept-encoding", "gzip, deflate, br",
				"cookie", "a=1; b=2", "authorization", "Bearer abc.def.ghi"),
			h2Fields(":method", "GET", ":scheme", "https", ":authority", "api.example.com", ":path", "/v1/feed?page=2",
				"user-agent", "Tern/1.0 (iPhone; iOS 17.4)", "accept", "application/json", "accept-encoding", "gzip, deflate, br",
				"cookie", "a=1; b=3"),
			h2Fields(":method", "POST", ":scheme", "https", ":authority", "api.example.com", ":path", "/v1/upload",
				"content-type", "application/x-www-form-urlencoded", "content-length", "1234", "x-custom", strings.Repeat("v", 300)),
		}},
		{"responses-small-table", 256, [][]hpack.HeaderField{
			h2Fields(":status", "200", "content-type", "application/json; charset=utf-8", "date", "Sat, 24 Oct 2026 07:00:00 GMT",
				"set-cookie", "sid=xyz; Path=/; HttpOnly", "cache-control", "private, max-age=0"),
			h2Fields(":status", "304", "date", "Sat, 24 Oct 2026 07:00:01 GMT", "etag", `"abc"`, "cache-control", "private, max-age=0"),
			h2Fields(":status", "404", "content-length", "0", "x-binary", "caf\xe9 \xff"),
		}},
	}
	for _, s := range seqs {
		var buf bytes.Buffer
		enc := hpack.NewEncoder(&buf)
		enc.SetMaxDynamicTableSizeLimit(s.tableSize)
		enc.SetMaxDynamicTableSize(s.tableSize)
		seq := h2FixHPACKSeq{Name: s.name, TableSize: s.tableSize}
		for _, b := range s.blocks {
			buf.Reset()
			var fs [][2]string
			for _, f := range b {
				if err := enc.WriteField(f); err != nil {
					t.Fatal(err)
				}
				fs = append(fs, [2]string{latin1(f.Name), latin1(f.Value)})
			}
			seq.Blocks = append(seq.Blocks, h2FixHPACKBlock{Hex: hex.EncodeToString(buf.Bytes()), Fields: fs})
		}
		fx.HPACK = append(fx.HPACK, seq)
	}

	// Frames written by Go's Framer.
	frame := func(name string, expect map[string]any, write func(f *http2.Framer) error) {
		var buf bytes.Buffer
		f := http2.NewFramer(&buf, nil)
		f.AllowIllegalWrites = true
		if err := write(f); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		fx.Frames = append(fx.Frames, h2FixFrame{Name: name, Hex: hex.EncodeToString(buf.Bytes()), Expect: expect})
	}
	frame("data", map[string]any{"type": "data", "stream": 1, "payload": hex.EncodeToString([]byte("hello")), "endStream": true, "flowSize": 5},
		func(f *http2.Framer) error { return f.WriteData(1, true, []byte("hello")) })
	frame("data padded", map[string]any{"type": "data", "stream": 3, "payload": hex.EncodeToString([]byte("abc")), "endStream": false, "flowSize": 3 + 1 + 7},
		func(f *http2.Framer) error { return f.WriteDataPadded(3, false, []byte("abc"), make([]byte, 7)) })
	block := []byte{0x82, 0x87, 0x84}
	frame("headers priority padded", map[string]any{"type": "headers", "stream": 5, "block": hex.EncodeToString(block), "endStream": true, "endHeaders": false},
		func(f *http2.Framer) error {
			return f.WriteHeaders(http2.HeadersFrameParam{StreamID: 5, BlockFragment: block, EndStream: true, EndHeaders: false,
				PadLength: 4, Priority: http2.PriorityParam{StreamDep: 1, Weight: 15, Exclusive: true}})
		})
	frame("continuation", map[string]any{"type": "continuation", "stream": 5, "block": "41", "endHeaders": true},
		func(f *http2.Framer) error { return f.WriteContinuation(5, true, []byte{0x41}) })
	frame("settings", map[string]any{"type": "settings", "ack": false, "values": [][2]uint32{{3, 100}, {4, 1 << 20}, {5, 32768}, {0x99, 7}}},
		func(f *http2.Framer) error {
			return f.WriteSettings(http2.Setting{ID: 3, Val: 100}, http2.Setting{ID: 4, Val: 1 << 20}, http2.Setting{ID: 5, Val: 32768}, http2.Setting{ID: 0x99, Val: 7})
		})
	frame("settings ack", map[string]any{"type": "settings", "ack": true, "values": [][2]uint32{}},
		func(f *http2.Framer) error { return f.WriteSettingsAck() })
	frame("ping", map[string]any{"type": "ping", "ack": false, "payload": "0102030405060708"},
		func(f *http2.Framer) error { return f.WritePing(false, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}) })
	frame("ping ack", map[string]any{"type": "ping", "ack": true, "payload": "0102030405060708"},
		func(f *http2.Framer) error { return f.WritePing(true, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}) })
	frame("goaway", map[string]any{"type": "goaway", "lastStream": 7, "code": 11, "debug": hex.EncodeToString([]byte("calm down"))},
		func(f *http2.Framer) error {
			return f.WriteGoAway(7, http2.ErrCodeEnhanceYourCalm, []byte("calm down"))
		})
	frame("window update conn", map[string]any{"type": "windowUpdate", "stream": 0, "increment": 1 << 20},
		func(f *http2.Framer) error { return f.WriteWindowUpdate(0, 1<<20) })
	frame("window update stream", map[string]any{"type": "windowUpdate", "stream": 9, "increment": 1},
		func(f *http2.Framer) error { return f.WriteWindowUpdate(9, 1) })
	frame("rst", map[string]any{"type": "rstStream", "stream": 9, "code": 8},
		func(f *http2.Framer) error { return f.WriteRSTStream(9, http2.ErrCodeCancel) })
	frame("priority", map[string]any{"type": "priority", "stream": 11},
		func(f *http2.Framer) error {
			return f.WritePriority(11, http2.PriorityParam{StreamDep: 3, Weight: 200})
		})
	frame("push promise", map[string]any{"type": "pushPromise", "stream": 1, "promised": 2, "block": "8287", "endHeaders": true},
		func(f *http2.Framer) error {
			return f.WritePushPromise(http2.PushPromiseParam{StreamID: 1, PromiseID: 2, BlockFragment: []byte{0x82, 0x87}, EndHeaders: true})
		})
	frame("unknown type", map[string]any{"type": "unknown", "rawType": 0xfa, "stream": 13},
		func(f *http2.Framer) error { return f.WriteRawFrame(0xfa, 0x1, 13, []byte("x")) })
	// Invalid frames (Swift must reject with these codes; connection errors unless "stream" is set).
	frame("err data on stream 0", map[string]any{"error": 1},
		func(f *http2.Framer) error { return f.WriteRawFrame(0, 0, 0, []byte("x")) })
	frame("err padding too long", map[string]any{"error": 1},
		func(f *http2.Framer) error { return f.WriteRawFrame(0, 0x8, 1, []byte{5, 'a', 'b'}) })
	frame("err settings length", map[string]any{"error": 6},
		func(f *http2.Framer) error { return f.WriteRawFrame(4, 0, 0, []byte{0, 3, 0, 0, 0}) })
	frame("err settings ack payload", map[string]any{"error": 6},
		func(f *http2.Framer) error { return f.WriteRawFrame(4, 1, 0, []byte{0, 3, 0, 0, 0, 1}) })
	frame("err ping length", map[string]any{"error": 6},
		func(f *http2.Framer) error { return f.WriteRawFrame(6, 0, 0, []byte{1, 2, 3}) })
	frame("err ping on stream", map[string]any{"error": 1},
		func(f *http2.Framer) error { return f.WriteRawFrame(6, 0, 1, make([]byte, 8)) })
	frame("err window update length", map[string]any{"error": 6},
		func(f *http2.Framer) error { return f.WriteRawFrame(8, 0, 0, []byte{0, 0, 1}) })
	frame("err rst on stream 0", map[string]any{"error": 1},
		func(f *http2.Framer) error { return f.WriteRawFrame(3, 0, 0, []byte{0, 0, 0, 8}) })
	frame("err priority length", map[string]any{"error": 6, "stream": 3},
		func(f *http2.Framer) error { return f.WriteRawFrame(2, 0, 3, []byte{0, 0, 0, 1}) })
	frame("err headers depends on itself", map[string]any{"error": 1, "stream": 3},
		func(f *http2.Framer) error { return f.WriteRawFrame(1, 0x20|0x4, 3, []byte{0, 0, 0, 3, 16, 0x82}) })
	frame("err goaway on stream", map[string]any{"error": 1},
		func(f *http2.Framer) error { return f.WriteRawFrame(7, 0, 1, make([]byte, 8)) })
	b, err := json.MarshalIndent(fx, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

// latin1 maps every byte to one scalar (how the Swift side reads header bytes).
func latin1(s string) string {
	r := make([]rune, 0, len(s))
	for i := 0; i < len(s); i++ {
		r = append(r, rune(s[i]))
	}
	return string(r)
}

const h2FixturePath = "../UnitTests/NativeMitmH2Fixtures.json"

func TestH2Fixtures(t *testing.T) {
	got := genH2Fixtures(t)
	if os.Getenv("TERN_GEN_H2") == "1" {
		if err := os.WriteFile(h2FixturePath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(h2FixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fatal("UnitTests/NativeMitmH2Fixtures.json is stale: TERN_GEN_H2=1 go test . -run TestH2Fixtures")
	}
}

// The Swift Huffman table must encode each symbol like Go's hpack (codes and lengths, via 3-symbol strings so
// the padding position differs).
func TestH2SwiftHuffmanTable(t *testing.T) {
	src, err := os.ReadFile("../PacketTunnel/NativeMitM/H2/HPACKHuffmanTable.swift")
	if err != nil {
		t.Fatal(err)
	}
	sect := func(name string) []uint64 {
		i := strings.Index(string(src), name)
		if i < 0 {
			t.Fatalf("%s missing", name)
		}
		body := string(src[i:])
		body = body[strings.Index(body, "[")+1:]
		body = body[strings.Index(body, "[")+1:]
		body = body[:strings.Index(body, "]")]
		var out []uint64
		for _, m := range regexp.MustCompile(`0x[0-9a-f]+|\d+`).FindAllString(body, -1) {
			v, err := strconv.ParseUint(m, 0, 64)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, v)
		}
		return out
	}
	codes, lens := sect("static let codes"), sect("static let lengths")
	if len(codes) != 257 || len(lens) != 257 || codes[256] != 0x3fffffff || lens[256] != 30 {
		t.Fatalf("table shape: %d codes, %d lengths", len(codes), len(lens))
	}
	enc := func(s []byte) []byte {
		var out []byte
		var acc uint64
		n := 0
		for _, b := range s {
			acc = acc<<lens[b] | codes[b]
			n += int(lens[b])
			for n >= 8 {
				n -= 8
				out = append(out, byte(acc>>uint(n)))
			}
			acc &= 1<<uint(n) - 1
		}
		if n > 0 {
			out = append(out, byte(acc<<uint(8-n)|(1<<uint(8-n)-1)))
		}
		return out
	}
	for b := 0; b < 256; b++ {
		s := []byte{byte(b), 'a', byte(b)}
		if got, want := enc(s), hpack.AppendHuffmanString(nil, string(s)); !bytes.Equal(got, want) {
			t.Fatalf("symbol %d: swift table %x, go %x", b, got, want)
		}
	}
}
