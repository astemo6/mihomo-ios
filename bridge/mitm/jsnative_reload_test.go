package mitm

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// A native engine that lost a script's context (JavaScriptCore restarted: Begin answers "missing") gets the
// script loaded again. That reload must evaluate the same code as the first compile: the BOM removed and a
// native Egern module adapted — and for a file script whose program came from the cache by file signature
// (programFor returns no source), the file is read again instead of loading an empty script.
func TestNativeReloadAfterMissingContext(t *testing.T) {
	// BOM + Egern native module: raw, it is a syntax error (export) on the engine; adapted, it rewrites the body.
	const js = "\ufeffexport default async function(ctx) { const d = await ctx.response.json(); d.ad = false; return {body: d}; }\n"
	for _, inline := range []bool{false, true} {
		name := map[bool]string{false: "file", true: "inline"}[inline]
		t.Run(name, func(t *testing.T) {
			f := newFakeNative()
			old, _ := nativeJS.Load().(nativeBox)
			if msg := SetNativeEngine(f); msg != "" {
				t.Fatal(msg)
			}
			defer func() {
				if old.n != nil {
					nativeJS.Store(old)
				} else {
					SetNativeEngine(nil)
				}
			}()
			e := New(t.TempDir(), nil, nil)
			sc := &Script{Name: "reload", Type: "http-response", Path: "reload.js", RequiresBody: true}
			if inline {
				sc.Source = []byte(js)
			} else {
				p := e.res.LocalPath(sc.Path)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(js), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			rule := &Rule{Kind: KindScript, Phase: "response", Script: sc}
			run := func() *ScriptResult {
				t.Helper()
				res, err := e.scripts.Run(context.Background(), rule, &ScriptHTTP{URL: "https://x/", Method: "GET", Header: http.Header{}},
					&ScriptHTTP{Status: 200, Header: http.Header{}, Body: []byte(`{"ad":true}`), HasBody: true})
				if err != nil {
					t.Fatalf("run: %v", err)
				}
				return res
			}
			if res := run(); !res.BodySet || string(res.Body) != `{"ad":false}` {
				t.Fatalf("first run: body %q set=%v", res.Body, res.BodySet)
			}
			if !inline {
				// the second lookup must be the signature cache hit that returns no source
				if _, src, err := e.scripts.programFor(sc, nativeEngineNow()); err != nil || src != "" {
					t.Fatalf("expected a cache hit by file signature without source, got src %d bytes err %v", len(src), err)
				}
			}
			// the engine restarts: every context is gone, Begin answers "missing"
			f.mu.Lock()
			f.entries = map[string]*fakeEntry{}
			f.mu.Unlock()
			if res := run(); !res.BodySet || string(res.Body) != `{"ad":false}` {
				t.Fatalf("after reload: body %q set=%v", res.Body, res.BodySet)
			}
			f.mu.Lock()
			n := len(f.entries)
			var src string
			for _, en := range f.entries {
				src = en.src
			}
			f.mu.Unlock()
			if n != 1 || src == "" || src[0] == '\xef' || IsEgernNative(src) {
				t.Fatalf("reloaded entry: n=%d, source %.40q (want the adapted code, no BOM)", n, src)
			}
		})
	}
}
