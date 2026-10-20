#!/usr/bin/env bash
# goja_diff_check.sh — verify that bridge/third_party/goja is a faithful copy of
# upstream github.com/dop251/goja at the pinned version, except for the local
# patches documented in bridge/third_party/goja/PATCHED.md.
#
# Files that exist only upstream (tests, testdata, the goja CLI) were never
# copied and are ignored. Any vendored file that is new or differs from
# upstream without being one of the documented patches fails the check.
set -euo pipefail

VERSION="v0.0.0-20261016120441-313b6b662e53"
MODULE="github.com/dop251/goja"
VENDORED="bridge/third_party/goja"

# Files PATCHED.md documents as locally patched (plus PATCHED.md itself).
ALLOWED=" compiler.go compiler_expr.go compiler_stmt.go vm.go "

cd "$(dirname "$0")/.."

upstream=""
tmp=""
cleanup() {
	if [ -n "$tmp" ]; then
		rm -rf "$tmp"
	fi
	return 0
}
trap cleanup EXIT

if command -v go >/dev/null 2>&1; then
	upstream="$(go env GOMODCACHE)/$MODULE@$VERSION"
	if [ ! -d "$upstream" ]; then
		tmp="$(mktemp -d)"
		(cd "$tmp" && go mod init tmpcheck >/dev/null && go mod download "$MODULE@$VERSION")
	fi
fi

if [ ! -d "$upstream" ]; then
	# Fallback: fetch the module zip straight from the Go module proxy.
	tmp="$(mktemp -d)"
	curl -fsSL "https://proxy.golang.org/$MODULE/@v/$VERSION.zip" -o "$tmp/goja.zip"
	(cd "$tmp" && unzip -q goja.zip)
	upstream="$tmp/$MODULE@$VERSION"
fi

fail=0
while IFS= read -r -d '' f; do
	rel="${f#"$VENDORED"/}"
	[ "$rel" = "PATCHED.md" ] && continue
	case "$ALLOWED" in
	*" $rel "*) continue ;;
	esac
	if [ ! -f "$upstream/$rel" ]; then
		echo "FAIL: $rel exists in the vendored copy but not upstream"
		fail=1
	elif ! cmp -s "$f" "$upstream/$rel"; then
		echo "FAIL: $rel differs from upstream but is not a documented patch (see PATCHED.md)"
		fail=1
	fi
done < <(find "$VENDORED" -type f -print0)

if [ "$fail" -ne 0 ]; then
	exit 1
fi
echo "OK: vendored goja matches upstream $MODULE@$VERSION except the documented patches"
