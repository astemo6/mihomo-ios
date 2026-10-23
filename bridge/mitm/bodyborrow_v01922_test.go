package mitm

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"testing"
)

// v0.19.22 integration of the JSC engine (feat/jsc-engine) with the body budget work (fix/code-review): the
// shared prelude keeps a text-mode body lazy, hands an untouched body back as "unchanged" (no copy), and a
// large decoded body (ScriptHTTP.BodyShared) is borrowed only by an engine whose heap is Go memory (goja);
// the native engine (JavaScriptCore; here its goja-backed stand-in) always gets a copy, so a script's in-place
// edits never reach the host's bytes, and with goja the handler restores them after an error.

// withEngine runs f with the native stand-in registered (native=true) or with goja only.
func withEngine(t *testing.T, native bool, f func()) {
	t.Helper()
	old, _ := nativeJS.Load().(nativeBox)
	if native {
		if msg := SetNativeEngine(newFakeNative()); msg != "" {
			t.Fatal(msg)
		}
	} else {
		SetNativeEngine(nil)
	}
	defer func() {
		if old.n != nil {
			nativeJS.Store(old)
		} else {
			SetNativeEngine(nil)
		}
	}()
	f()
}

func engineName(native bool) string {
	if native {
		return "native"
	}
	return "goja"
}

func runPhaseScript(t *testing.T, js string, binary bool, body []byte, shared bool) (*ScriptResult, error) {
	t.Helper()
	e := New(t.TempDir(), nil, nil)
	sc := &Script{Name: "t", Type: "http-response", Path: "t.js", RequiresBody: true, BinaryBody: binary, Source: []byte(js)}
	rule := &Rule{Kind: KindScript, Phase: "response", Script: sc}
	return e.scripts.Run(context.Background(), rule, &ScriptHTTP{URL: "https://x/", Method: "GET", Header: http.Header{}},
		&ScriptHTTP{Status: 200, Header: http.Header{}, Body: body, HasBody: true, BodyShared: shared})
}

func TestPhaseBodyLazyBothEngines(t *testing.T) {
	bin := []byte{0xff, 0xfe, 0x00, 'a', 0x80}
	for _, native := range []bool{false, true} {
		withEngine(t, native, func() {
			name := engineName(native)
			// Quantumult X protobuf style: only bodyBytes is read; the text is never built.
			n0 := textConversions.Load()
			res, err := runPhaseScript(t, `var u = new Uint8Array($response.bodyBytes); u[0] = 1; $done({bodyBytes: u.buffer})`, false, bin, false)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if !res.BodySet || !bytes.Equal(res.Body, append([]byte{1}, bin[1:]...)) {
				t.Fatalf("%s bytes-only: got %q set=%v", name, res.Body, res.BodySet)
			}
			if d := textConversions.Load() - n0; d != 0 {
				t.Fatalf("%s bytes-only: body converted to text %d times", name, d)
			}
			// Untouched body handed back: unchanged (the handler keeps its bytes, nothing copied back).
			n0 = textConversions.Load()
			res, err = runPhaseScript(t, `$response.headers["X-A"] = "1"; $done($response)`, false, bin, false)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if res.BodySet {
				t.Fatalf("%s untouched: body handed back (%q)", name, res.Body)
			}
			if res.Header.Get("X-A") != "1" {
				t.Fatalf("%s untouched: header lost", name)
			}
			if d := textConversions.Load() - n0; d != 0 {
				t.Fatalf("%s untouched: body converted to text %d times", name, d)
			}
			// Body read as text and handed back unchanged via a copy of the object: the original bytes
			// (not the U+FFFD text).
			res, err = runPhaseScript(t, `$done({...$response})`, false, bin, false)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if res.BodySet && !bytes.Equal(res.Body, bin) {
				t.Fatalf("%s spread: got %q", name, res.Body)
			}
		})
	}
}

func TestSharedBodyBorrowedOnlyByGoHeapEngine(t *testing.T) {
	for _, native := range []bool{false, true} {
		withEngine(t, native, func() {
			name := engineName(native)
			for _, binary := range []bool{true, false} {
				get := `new Uint8Array($response.bodyBytes)`
				if binary {
					get = `$response.body`
				}
				// In-place edit, then an error.
				body := bytes.Repeat([]byte("abcd"), 1024)
				orig := append([]byte(nil), body...)
				_, err := runPhaseScript(t, `var u = `+get+`; for (var i = 0; i < 8; i++) u[i] = 88; throw new Error("boom")`, binary, body, true)
				if err == nil {
					t.Fatalf("%s binary=%v: no error", name, binary)
				}
				changed := !bytes.Equal(body, orig)
				if native && changed {
					t.Fatalf("native binary=%v: in-place edit reached the host's bytes", binary)
				}
				if !native && !changed {
					t.Fatalf("goja binary=%v: shared body was copied, not borrowed", binary)
				}
				// In-place edit handed back: the edit wins; goja hands back the borrowed bytes themselves.
				body = append([]byte(nil), orig...)
				res, err := runPhaseScript(t, `var u = `+get+`; u[0] = 89; $done($response)`, binary, body, true)
				if err != nil {
					t.Fatalf("%s binary=%v: %v", name, binary, err)
				}
				if !res.BodySet || len(res.Body) != len(orig) || res.Body[0] != 89 || !bytes.Equal(res.Body[1:], orig[1:]) {
					t.Fatalf("%s binary=%v: handed-back edit lost (set=%v, len %d)", name, binary, res.BodySet, len(res.Body))
				}
				if !native && &res.Body[0] != &body[0] {
					t.Fatalf("goja binary=%v: borrowed body copied on the way back", binary)
				}
				if native && body[0] != orig[0] {
					t.Fatalf("native binary=%v: host bytes changed", binary)
				}
			}
		})
	}
}

// TestSharedBodyRestoredBothEngines: the handler-level guarantee (TestSharedBodyRestoredAfterInPlaceChange)
// for both engines and for text mode (bodyBytes edited in place).
func TestSharedBodyRestoredBothEngines(t *testing.T) {
	raw := bytes.Repeat([]byte("0123456789abcdef"), (1<<20)/16+4096) // > bigBodyThreshold
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	for _, native := range []bool{false, true} {
		withEngine(t, native, func() {
			for _, c := range []struct{ mode, js string }{
				{"binary-body-mode=1,", `var u = $response.body; for (var i = 0; i < 16; i++) u[i] = 88; throw new Error("boom")`},
				{"", `var u = new Uint8Array($response.bodyBytes); for (var i = 0; i < 16; i++) u[i] = 88; throw new Error("boom")`},
				{"", `var u = new Uint8Array($response.bodyBytes); for (var i = 0; i < 16; i++) u[i] = 88; $done({})`},
			} {
				cfg := &Config{Enabled: true, MitM: true, Hostnames: []string{"api.test.com"}, Scripts: items(
					`b = type=http-response,pattern=^https://api\.test\.com/big,requires-body=1,` + c.mode + `max-size=-1,script-path=b.js`)}
				h := newHarness(t, cfg, map[string]string{"b.js": c.js})
				h.up.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Encoding", "gzip")
					_, _ = w.Write(gz.Bytes())
				})
				resp, body := h.get("https://api.test.com/big")
				got := []byte(body)
				if resp.Header.Get("Content-Encoding") == "gzip" {
					zr, err := gzip.NewReader(bytes.NewReader(got))
					if err != nil {
						t.Fatal(err)
					}
					got, _ = io.ReadAll(zr)
				}
				if !bytes.Equal(got, raw) {
					t.Fatalf("%s %s: body changed (%d vs %d bytes, head %q)", engineName(native), c.js, len(got), len(raw), clip(string(got), 20))
				}
			}
		})
	}
}
