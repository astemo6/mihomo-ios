package mitm

// Engine conformance (feat/jsc-engine): one corpus (UnitTests/ScriptEngineConformance.json) run on goja and on
// the native engine must give the same result. Go's TestEngineConformance runs it against a goja-backed stand-in
// of the native engine; the iOS unit test (MihomoUnitTests/ScriptEngineConformanceTests) against JavaScriptCore.

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// ConformanceCase is one corpus entry: a 脚本调试 input, substrings the normalized output must contain, how
// many times to run it on one engine (repeat > 1: the native engine reuses the script's context).
type ConformanceCase struct {
	Name   string     `json:"name"`
	Input  DebugInput `json:"input"`
	Expect []string   `json:"expect"`
	Repeat int        `json:"repeat,omitempty"`
}

// ConformanceResult compares the engines on one case.
type ConformanceResult struct {
	Name     string   `json:"name"`
	OK       bool     `json:"ok"`
	Goja     string   `json:"goja"`
	Native   string   `json:"native,omitempty"`
	Missing  []string `json:"missing,omitempty"` // expectations not met (goja's output)
	Diff     string   `json:"diff,omitempty"`
	GojaMs   int64    `json:"gojaMs"`
	NativeMs int64    `json:"nativeMs"`
}

var (
	excRe    = regexp.MustCompile(`脚本异常：([A-Za-z]*Error|[A-Za-z]+)[^"\\]*`)
	syntaxRe = regexp.MustCompile(`脚本语法错误：.*`)
)

// normalizeDebug drops what legitimately differs between engines: timings and the wording of the engine's own
// exception messages (the error name stays).
func normalizeDebug(out DebugOutput) string {
	out.DurationMs = 0
	logs := make([]DebugLog, len(out.Logs))
	for i, l := range out.Logs {
		l.T = 0
		l.Msg = excRe.ReplaceAllString(l.Msg, "脚本异常：$1")
		logs[i] = l
	}
	out.Logs = logs
	out.Error = excRe.ReplaceAllString(out.Error, "脚本异常：$1")
	out.Error = syntaxRe.ReplaceAllString(out.Error, "脚本语法错误")
	b, _ := json.Marshal(out)
	return string(b)
}

// RunConformance runs c on goja and, when one is registered (or required), on the native engine.
func RunConformance(home string, c ConformanceCase, requireNative bool) ConformanceResult {
	r := ConformanceResult{Name: c.Name}
	n := c.Repeat
	if n < 1 {
		n = 1
	}
	run := func(engine string) (string, int64, string) {
		var first string
		var ms int64
		e := newDebugEngine(home, nil)
		defer e.scripts.Reset()
		for i := 0; i < n; i++ {
			in := c.Input
			in.Engine = engine
			out := debugRunOn(e, in)
			_ = e.Store.Flush()
			ms += out.DurationMs
			s := normalizeDebug(out)
			if i == 0 {
				first = s
			} else if s != first {
				return first, ms, fmt.Sprintf("run %d on %s differs from run 1:\n%s\n%s", i+1, engine, first, s)
			}
		}
		return first, ms, ""
	}
	var d string
	r.Goja, r.GojaMs, d = run(EngineGoja)
	if d != "" {
		r.Diff = d
	}
	for _, e := range c.Expect {
		if !strings.Contains(r.Goja, e) {
			r.Missing = append(r.Missing, e)
		}
	}
	if nativeUsable() {
		r.Native, r.NativeMs, d = run(EngineNative)
		if d != "" && r.Diff == "" {
			r.Diff = d
		}
		if r.Native != r.Goja && r.Diff == "" {
			r.Diff = "goja:   " + r.Goja + "\nnative: " + r.Native
		}
	} else if requireNative {
		r.Diff = "native engine not registered"
	}
	r.OK = len(r.Missing) == 0 && r.Diff == ""
	return r
}
