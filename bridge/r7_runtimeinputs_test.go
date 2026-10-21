package libmihomo

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// r7: every os.ReadFile / os.Stat / os.Open reachable from the runtime build must be a runtimeInputFiles
// member. The call graph is name-based over the package's own (non-test) functions, so it over-approximates;
// a new read in the build path fails here until it is classified below AND covered by runtimeInputFiles.
func TestRuntimeInputFilesCoverBuildReads(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	profile := filepath.Join(root, "profiles", "abc.yaml")
	for _, d := range []string{home, filepath.Join(home, "ruleset"), filepath.Join(home, "nodesubs"), filepath.Join(root, "profiles")} {
		_ = os.MkdirAll(d, 0o755)
	}
	mustWrite(t, nodeSubsPath(home), `[{"id":"s1","name":"S1","enabled":true}]`)
	mustWrite(t, filepath.Join(home, "ruleset", "x.txt.policies.json"), `[]`)
	in := map[string]bool{}
	for _, p := range runtimeInputFiles(home, profile) {
		in[p] = true
	}
	yp, mp := scriptedPaths(home, profile)
	// "<func>: <first argument>" → the file(s) that read touches.
	known := map[string][]string{
		"readRuntimeProfile: path":                           {profile},
		"scriptedFor: mp":                                    {mp},
		"scriptedFor: yp":                                    {yp},
		"readOverrides: overridesPath(home)":                 {overridesPath(home)},
		"readDNSOverride: dnsOverridePath(home)":             {dnsOverridePath(home)},
		"readLocalDNS: localDNSPath(home)":                   {localDNSPath(home)},
		"readAllSubRules: subRulesPath(home)":                {subRulesPath(home)},
		"readProviderOverrides: providerOverridesPath(home)": {providerOverridesPath(home)},
		"mergeNodeSubs: NodeSubPath(home, s.ID)":             {NodeSubPath(home, "s1")},
		"readGroupEdits: groupEditsPath(home)":               {groupEditsPath(home)},
		"readAllGroupSettings: groupSettingsPath(home)":      {groupSettingsPath(home)},
		"readNodeSubs: nodeSubsPath(home)":                   {nodeSubsPath(home)},
		"readCustomRules: customRulesPath(home)":             {customRulesPath(home)},
		"loadYAML: path":                                     {manualNodesPath(home)}, // mergeManualNodes
		"readOwnPolicyParts: ownPolicySidecar(cachePath)":    {filepath.Join(home, "ruleset", "x.txt.policies.json")},
	}
	// writes / logs the walker sees, not inputs of the build
	notInputs := map[string]bool{"stage: stagePath": true} // startup log, append-only
	reads := buildReads(t, "runtimeRawWithHome")
	if len(reads) < 10 {
		t.Fatalf("call-graph walk found only %d reads — the walker is broken: %v", len(reads), reads)
	}
	for _, r := range reads {
		if notInputs[r] {
			continue
		}
		files, ok := known[r]
		if !ok {
			t.Errorf("the runtime build reads %q, which runtimeInputFiles does not list — add the file to runtimeInputFiles and classify it here", r)
			continue
		}
		for _, f := range files {
			if !in[f] {
				t.Errorf("%q reads %s but runtimeInputFiles does not include it", r, f)
			}
		}
	}
	// node-subscription / provider bodies (content files) are signed too
	if !in[NodeSubPath(home, "s1")] {
		t.Error("node subscription body missing from runtimeInputFiles")
	}
}

func mustWrite(t *testing.T, p, s string) {
	t.Helper()
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func buildReads(t *testing.T, start string) []string {
	t.Helper()
	fs := token.NewFileSet()
	funcs := map[string]*ast.FuncDecl{}
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fs, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range af.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				n := fd.Name.Name
				if fd.Recv != nil {
					n = "." + n
				}
				funcs[n] = fd
			}
		}
	}
	seen := map[string]bool{}
	out := map[string]bool{}
	q := []string{start}
	for len(q) > 0 {
		n := q[0]
		q = q[1:]
		if seen[n] || funcs[n] == nil {
			continue
		}
		seen[n] = true
		ast.Inspect(funcs[n].Body, func(x ast.Node) bool {
			c, ok := x.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fn := c.Fun.(type) {
			case *ast.Ident:
				q = append(q, fn.Name)
			case *ast.SelectorExpr:
				if id, ok := fn.X.(*ast.Ident); ok && id.Name == "os" {
					switch fn.Sel.Name {
					case "ReadFile", "Stat", "Lstat", "Open", "OpenFile", "ReadDir":
						var b bytes.Buffer
						_ = printer.Fprint(&b, fs, c.Args[0])
						out[n+": "+b.String()] = true
					}
				}
				q = append(q, "."+fn.Sel.Name)
			}
			return true
		})
	}
	l := make([]string, 0, len(out))
	for k := range out {
		l = append(l, k)
	}
	return l
}

// Editing any input (provider-overrides.json included) changes the key, and the cached runtime follows.
func TestRuntimeCacheKeyFollowsEveryInput(t *testing.T) {
	resetRuntimeCache()
	defer resetRuntimeCache()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	profile := filepath.Join(root, "profiles", "abc.yaml")
	mustWrite(t, profile, subsSplitProfile)
	mustWrite(t, nodeSubsPath(home), `[{"id":"s1","name":"S1","enabled":true}]`)
	mustWrite(t, NodeSubPath(home, "s1"), "proxies: []\n")
	mustWrite(t, filepath.Join(home, "ruleset", "x.txt.policies.json"), `[]`)
	mustWrite(t, filepath.Join(home, "proxies", "a.yaml"), "proxies: []\n")
	for _, p := range runtimeInputFiles(home, profile) {
		if _, err := os.Stat(p); err != nil {
			mustWrite(t, p, "{}")
		}
	}
	for _, p := range runtimeInputFiles(home, profile) {
		before := runtimeCacheKey(home, profile)
		time.Sleep(2 * time.Millisecond)
		b, _ := os.ReadFile(p)
		mustWrite(t, p, string(b)+"\n")
		if runtimeCacheKey(home, profile) == before {
			t.Errorf("editing %s did not change the runtime cache key", p)
		}
	}
	// end to end: disabling provider A through provider-overrides.json must reach the cached runtime
	writeProviderOverrides(t, home, "", nil)
	resetRuntimeCache()
	id := profileIDFromPath(profile)
	raw := cachedRuntimeRaw(home, profile)
	if _, ok := asMap(raw["proxy-providers"])["A"]; !ok {
		t.Fatalf("provider A missing before the override: %v", raw["proxy-providers"])
	}
	time.Sleep(2 * time.Millisecond)
	writeProviderOverrides(t, home, id, map[string]ProviderOverride{"A": {Disabled: true}})
	raw = cachedRuntimeRaw(home, profile)
	if _, ok := asMap(raw["proxy-providers"])["A"]; ok {
		t.Error("cached runtime still serves provider A after provider-overrides.json disabled it")
	}
}

// r7: purely alphabetic random tokens are masked; words and CamelCase names are not.
func TestR7LooksLikeTokenAlphabetic(t *testing.T) {
	for seg, want := range map[string]bool{
		"aBcDeFgHiJkLmNoPqRsT":   true,
		"QxTrVbNmKlPoIuYtReWq":   false, // upper-heavy, few flips? computed below
		"GeoSiteDatabaseUpdater": false,
		"release":                false,
		"subscription":           false,
		"geoip":                  false,
		"v1.19.32":               false,
		"kHtPqWzRmXbVnLsDfGjA":   true,
	} {
		if seg == "QxTrVbNmKlPoIuYtReWq" {
			want = true // alternating case: a token
		}
		if got := looksLikeToken(seg); got != want {
			t.Errorf("looksLikeToken(%q) = %v, want %v", seg, got, want)
		}
	}
}

// r7: a tuic-server that is not a map (was a dead branch) is dropped.
func TestR7TuicServerNonMapDropped(t *testing.T) {
	raw := map[string]any{"tuic-server": "0.0.0.0:443"}
	sanitizeProfileInbounds(raw, defaultOverrides())
	if _, ok := raw["tuic-server"]; ok {
		t.Fatal("non-map tuic-server kept")
	}
}
