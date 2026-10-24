package goja

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/dop251/goja/ast"
)

// mihomo-ios patch 6: CompileReleasing produces the same program as Compile (instruction by instruction,
// nested functions and class bodies included) for every script under bridge/mitm/testdata, the
// constructs below, and — when present — the Sub-Store bundles in $TERN_JS_CORPUS (directory of .js).
func dumpNorm(p *Program) string {
	var b strings.Builder
	p.dumpCode(func(format string, args ...interface{}) { fmt.Fprintf(&b, format+"\n", args...) })
	return regexp.MustCompile(`0x[0-9a-f]+`).ReplaceAllString(b.String(), "0x")
}

func TestCompileReleasingSameProgram(t *testing.T) {
	srcs := map[string]string{
		"constructs": `
			function hoisted(a, b = () => a) { return b() }
			var arrow = x => x * 2, block = (x) => { return x + 1 };
			class A { constructor(n = "x") { this.n = n } m() { return () => this.n } static s() { return 1 } #p = () => 1; get g() { return this.#p() } }
			class B extends A { constructor() { super(); eval("1") } }
			for (let i = 0; i < 2; i++) { setTimeout(() => i) }
			if (false) { (function dead() { return 1 })() }
			for (; false;) { (() => 2)() }
			label: { function inBlock() { return 3 } break label; (function after() {})() }
			function dup() { return 1 } function dup() { return 2 }
			var o = { m() { return function () { return arguments } }, [k]: async () => await 1, *g() { yield 1 } };
			try { throw 1 } catch ({ e = () => 1 }) { } finally { (() => 0)() }
			(function () { "use strict"; return (a, ...r) => r })();
		`,
	}
	files, _ := filepath.Glob("../../mitm/testdata/*.js")
	if dir := os.Getenv("TERN_JS_CORPUS"); dir != "" {
		more, _ := filepath.Glob(filepath.Join(dir, "*.js"))
		files = append(files, more...)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		srcs[filepath.Base(f)] = string(b)
	}
	for name, src := range srcs {
		for _, wrap := range []bool{false, true} {
			code := src
			if wrap {
				code = "(function(){\n" + src + "\n}).call(this);"
			}
			p1, err1 := Compile(name, code, false)
			p2, err2 := CompileReleasing(name, code, false)
			if (err1 == nil) != (err2 == nil) {
				t.Fatalf("%s: errors differ: %v / %v", name, err1, err2)
			}
			if err1 != nil {
				if err1.Error() != err2.Error() {
					t.Fatalf("%s: errors differ: %v / %v", name, err1, err2)
				}
				continue
			}
			if d1, d2 := dumpNorm(p1), dumpNorm(p2); d1 != d2 {
				l1, l2 := strings.Split(d1, "\n"), strings.Split(d2, "\n")
				for i := range l1 {
					if i >= len(l2) || l1[i] != l2[i] {
						t.Fatalf("%s (wrap %v): programs differ at line %d:\n%s\n%s", name, wrap, i, l1[i], l2[min(i, len(l2)-1)])
					}
				}
				t.Fatalf("%s: programs differ in length", name)
			}
			if fmt.Sprint(p1.srcMap) != fmt.Sprint(p2.srcMap) {
				t.Fatalf("%s: source maps differ", name)
			}
		}
	}
	t.Logf("%d sources compared", len(srcs))
}

// A literal whose body was dropped and is compiled again falls back to a normal compile.
func TestCompileReleasingFallback(t *testing.T) {
	c := newCompiler()
	c.releaseBodies = true
	prg, err := Parse("x", "var f = function () { return 1 }")
	if err != nil {
		t.Fatal(err)
	}
	c.compile(prg, false, true, nil)
	lit := prg.Body[0].(*ast_VariableStatement).List[0].Initializer.(*ast_FunctionLiteral)
	func() {
		defer func() {
			if _, ok := recover().(errBodyReleased); !ok {
				t.Fatal("second compile of a released literal did not raise errBodyReleased")
			}
		}()
		c.compileFunctionLiteral(lit, true)
	}()
	r := New()
	p, err := CompileReleasing("x", "var f = function () { return 41 + 1 }; f()", false)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := r.RunProgram(p); err != nil || v.ToInteger() != 42 {
		t.Fatalf("%v %v", v, err)
	}
}

type (
	ast_VariableStatement = ast.VariableStatement
	ast_FunctionLiteral   = ast.FunctionLiteral
)
