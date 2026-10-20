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
