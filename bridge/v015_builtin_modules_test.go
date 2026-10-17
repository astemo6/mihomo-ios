package libmihomo

import (
	"encoding/json"
	"net/url"
	"os"
	"path"
	"strings"
	"testing"
)

// feat/module-browser: shape of the built-in curated module index shipped in the app
// (App/Resources/BuiltinModules.json). Offline: links are not fetched here.
func TestBuiltinModuleIndexShape(t *testing.T) {
	b, err := os.ReadFile("../App/Resources/BuiltinModules.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Version    int
		Categories []struct{ ID string }
		Modules    []struct {
			ID, Category, Author, Homepage, URL string
			Name, Desc                          map[string]string
			Alternates                          []string
		}
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if f.Version != 1 || len(f.Modules) == 0 {
		t.Fatalf("version %d, %d modules", f.Version, len(f.Modules))
	}
	cats := map[string]bool{}
	for _, c := range f.Categories {
		cats[c.ID] = true
	}
	// Category ids the app maps to localized names (BuiltinModuleIndex.categoryName).
	for _, c := range []string{"adblock", "subtitles", "enhance", "tools"} {
		if !cats[c] {
			t.Errorf("category %s missing", c)
		}
	}
	exts := map[string]bool{".sgmodule": true, ".plugin": true, ".lpx": true, ".stoverride": true, ".snippet": true, ".conf": true}
	langs := []string{"zh-Hans", "zh-Hant", "en", "ja", "ko", "ru"}
	ids, urls := map[string]bool{}, map[string]bool{}
	formats := map[string]bool{}
	for _, m := range f.Modules {
		if m.ID == "" || ids[m.ID] {
			t.Errorf("empty or duplicate id %q", m.ID)
		}
		ids[m.ID] = true
		if !cats[m.Category] {
			t.Errorf("%s: unknown category %q", m.ID, m.Category)
		}
		for _, l := range langs {
			if strings.TrimSpace(m.Name[l]) == "" || strings.TrimSpace(m.Desc[l]) == "" {
				t.Errorf("%s: name/desc missing for %s", m.ID, l)
			}
		}
		if m.Homepage != "" {
			if u, err := url.Parse(m.Homepage); err != nil || u.Scheme != "https" {
				t.Errorf("%s: bad homepage %q", m.ID, m.Homepage)
			}
		}
		for _, raw := range append([]string{m.URL}, m.Alternates...) {
			u, err := url.Parse(raw)
			if err != nil || u.Scheme != "https" || u.Host == "" {
				t.Errorf("%s: bad url %q", m.ID, raw)
				continue
			}
			ext := strings.ToLower(path.Ext(u.Path))
			if !exts[ext] {
				t.Errorf("%s: %q is not a module file", m.ID, raw)
			}
			formats[ext] = true
			if urls[raw] {
				t.Errorf("%s: duplicate url %q", m.ID, raw)
			}
			urls[raw] = true
		}
	}
	// The index should show every importer: Surge, Loon, Stash and QX.
	for _, e := range []string{".sgmodule", ".plugin", ".stoverride", ".snippet"} {
		if !formats[e] {
			t.Errorf("no module in %s format", e)
		}
	}
}
