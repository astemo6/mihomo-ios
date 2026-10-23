package mitm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestQXAuditParse (opt-in, TERN_QX_AUDIT_DIR=<dir with res/>): parses every downloaded rewrite_remote
// resource exactly as the module store does (ParseText of the downloaded text) and writes parse.json.
func TestQXAuditParse(t *testing.T) {
	dir := os.Getenv("TERN_QX_AUDIT_DIR")
	if dir == "" {
		t.Skip("audit only")
	}
	resdir := os.Getenv("TERN_AUDIT_RESDIR")
	if resdir == "" {
		resdir = "res"
	}
	files, _ := filepath.Glob(filepath.Join(dir, resdir, "*"))
	sort.Strings(files)
	type out struct {
		File      string         `json:"file"`
		Format    string         `json:"format"`
		Kinds     map[string]int `json:"kinds"`
		Tasks     int            `json:"tasks"`
		Hosts     []string       `json:"hosts"`
		Core      []string       `json:"core"`
		Errors    []string       `json:"errors"`
		Unsupp    []string       `json:"unsupported"`
		Scripts   []string       `json:"scripts"`
		ScriptRul []*Rule        `json:"scriptRules"`
	}
	var all []out
	for _, f := range files {
		b, _ := os.ReadFile(f)
		rs := &Ruleset{}
		rs.ParseText(string(b), filepath.Base(f), nil)
		o := out{File: filepath.Base(f), Format: rs.Format, Kinds: map[string]int{}, Tasks: len(rs.Tasks), Hosts: rs.Hostnames, Core: rs.CoreRules, Errors: rs.Errors, Unsupp: rs.Unsupported}
		seen := map[string]bool{}
		for _, r := range rs.Rules {
			k := r.Kind
			if r.Kind == KindURL {
				k += ":" + r.Action
			}
			if r.Script != nil {
				k += ":" + r.Script.Type
				if r.Script.Echo {
					k += "(echo)"
				}
				if r.Script.RequiresBody {
					k += "+body"
				}
				if !seen[r.Script.Path] {
					seen[r.Script.Path] = true
					o.Scripts = append(o.Scripts, r.Script.Path)
				}
				o.ScriptRul = append(o.ScriptRul, r)
			}
			o.Kinds[k]++
		}
		for _, tk := range rs.Tasks {
			if tk.Script != nil && !seen[tk.Script.Path] {
				seen[tk.Script.Path] = true
				o.Scripts = append(o.Scripts, tk.Script.Path)
			}
		}
		all = append(all, o)
		t.Logf("%s: %s kinds=%v tasks=%d hosts=%d core=%d err=%v unsupp=%v args=%d scripts=%d", o.File, o.Format, o.Kinds, o.Tasks, len(o.Hosts), len(o.Core), o.Errors, len(o.Unsupp), len(rs.Arguments), len(o.Scripts))
		for i, u := range o.Unsupp {
			if i >= 4 {
				break
			}
			t.Logf("   unsupported: %s", clip(u, 200))
		}
	}
	j, _ := json.MarshalIndent(all, "", " ")
	_ = os.WriteFile(filepath.Join(dir, strings.ReplaceAll(resdir, "/", "_")+"-parse.json"), j, 0o644)
	_ = strings.TrimSpace
}
