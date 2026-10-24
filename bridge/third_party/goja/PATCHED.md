# goja (patched copy)

Upstream: github.com/dop251/goja @ v0.0.0-20261016120441-313b6b662e53 (MIT, see LICENSE).
Copied without tests / testdata / the `goja` CLI. Used through `replace` in bridge/go.mod.

## Patch (mihomo-ios v0.19.9)

A direct `eval()` inside a class method / constructor, or inside the body of a strict function with
non-simple parameters (defaults, patterns, rest), panicked the VM ("index out of range" in
`stash.getByIdx`, or a nil dereference) on the first access to an outer `let`/`const`/`class` binding.

Cause: `scope.finaliseVarAlloc` counts every scope with `isDynamic()` (dynLookup set by a direct eval in
an inner scope) as one stash level when it encodes `level<<24 | idx`, but `enterBlock` /
`enterFuncBody` only created a stash when the scope had bindings to put in it. The class scope of an
anonymous class and the empty body scope of such a function have none, so lookups went one level too
far.

Fix: `updateEnterBlock` sets `enterBlock.forceStash` for a dynamic-lookup scope with no bindings;
`enterBlock.exec`, `enterFuncBody.exec` and `leaveScopeBlock` (popStash) honour it.
Files: compiler.go, compiler_stmt.go, vm.go (search "mihomo-ios patch").

This broke every Sub-Store bundle (sub-store-0/1.min.js, cron-sync-artifacts.min.js):
`class{constructor(name="untitled",debug=!1){… eval('require("dotenv")') …}}`.
Upstream's own test suite passes with the patch. Drop this copy once upstream fixes it.

## Patch 2: source map memory (mihomo-ios v0.19.9)

`srcMapItem`'s `pc` and `srcPos` fields were narrowed from `int` to `int32`, and at the end of
compilation the source map is compacted to its exact length (it grows by append and otherwise
keeps up to 2x spare capacity). Files: compiler.go, compiler_expr.go (search "mihomo-ios patch").

Why: the source map holds one item per source position change and is the second largest part of
a compiled program after the code itself; halving the item size measurably cuts the memory a
compiled script bundle holds in the extension.

Safe because both fields are bounded far below 2^31 for any script this app runs: `pc` by the
instruction count of the compiled program, `srcPos` by the source length in bytes. Drop /
re-apply this patch together with the copy, like the eval patch above.

## Patch 3: TypedArray.from with a primitive source (mihomo-ios v0.19.18)

`typedArray_from` converted its source with `r.toObject`, which throws "Value is not an object"
for any primitive. The spec (23.2.2.1) only requires `GetMethod(source, @@iterator)`, so V8 and
JavaScriptCore iterate a string: `Uint8Array.from(binaryString, c => c.charCodeAt(0))`. The source
is now converted with `ToObject` (null / undefined still throw). File: builtin_typedarrays.go
(search "mihomo-ios patch"); test: bridge/mitm/goja_typedarray_test.go.

This broke the 喜马拉雅 VIP script (ximalaya.js): its paid-track `ep` decrypt failed, so the app kept
showing the VIP / 喜点 prompt. Drop / re-apply together with the copy.

## Patch 4: `break` / `continue` in dead code (mihomo-ios v0.19.22)

`enterDummyMode` (used to compile constant-false branches such as `if(!1){…}` for early errors only)
copied just the innermost block. A `break` / `continue` in that dead code which resolved to an outer
block (e.g. `case 5: e: if(!1){ …; break }` — the labelled statement is the copied block, the switch
is its real `outer`) appended a pc of the throw-away dummy program to the real block's `breaks`, and
the later patch overwrote a live instruction at that pc with a jump: "Compiler bug: Unsupported
instruction for binding: goja.jump", or silently wrong code. The whole block chain is now copied (with
`breaking` links remapped). File: compiler.go (search "Patch 4"); test:
bridge/mitm/goja_deadbreak_test.go. Hit by obfuscated scripts (a Loon 喜马拉雅 plugin's xmly.js).

## Patch 5: compile-time memory (mihomo-ios v0.19.23, E 线 #5)

- `binding.accessPoints` was `map[*scope]*[]int`: one map plus one boxed slice per binding (~250
  bytes), and a Sub-Store bundle keeps tens of thousands of bindings alive until its outer function is
  finalised. Now a small slice of `{scope, []int32}` (the last entry is checked first; a map index is
  built only past 8 scopes). The finalisation loops iterate the slice instead of the map (each writes
  its own instructions, so the order does not matter). File: compiler.go.
- `parser.ParseFile` with a string source used it as `[]byte` and back as `string` (two transient
  copies of the whole source); a string is now used as is. File: parser/parser.go.

Checked: the compiled programs (instruction dump + source map) are byte-identical to unpatched goja's
for 184 real-world scripts (work/qx-audit corpus, Sub-Store 0/1/cron bundles).

## Patch 6: `CompileReleasing` (mihomo-ios v0.19.23, E 线 #5)

`goja.Compile` keeps the whole syntax tree until the end of compilation; for a bundle (one outer
function holding every module) that is ~16 MB of AST for a 1.3 MB Sub-Store bundle on top of the
program being built. `CompileReleasing` (runtime.go) compiles with `compiler.releaseBodies`: once a
function / arrow literal is compiled, its AST body and declaration list are replaced by an empty block
(compiler_expr.go, `compiledFunctionLiteral.release`). The literal is recorded; should the compiler
ever compile the same literal again (none known — every path compiles a literal once, dead code
included), it raises `errBodyReleased` and `CompileReleasing` compiles the source again with plain
`Compile`, so the result is never a function with a missing body. `eval` / `new Function` and the
prelude keep using the normal path.

Measured (sub-store-1.min.js, GOGC=10 live peak): goja.Compile ~35 MB → CompileReleasing ~22 MB;
the ScriptRunner compile path ~42 MB → ~30 MB (bridge/mitm TestSubStoreCompilePeakReleasing).
Equivalence: third_party/goja/mihomo_release_test.go compares Compile and CompileReleasing instruction
by instruction (`TERN_JS_CORPUS=<dir of .js> go test -run CompileReleasing` inside third_party/goja;
189 sources identical). Drop / re-apply together with the copy.
