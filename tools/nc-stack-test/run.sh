#!/usr/bin/env bash
# fix/nc-tcp0: builds nc_stack.c + the vendored lwIP core on the host and runs nc_stack_test.c (Checks → nc-stack-c).
# CC defaults to cc; any C11 compiler works (clang on macOS, gcc on Linux).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
L="$here/../../PacketTunnel/NativeCore/lwip"
out="${TMPDIR:-/tmp}/nc_stack_test.$$"
shim=""
# lwIP's port uses arc4random (Darwin); older glibc lacks it.
if ! printf '#include <stdlib.h>\nint main(void){return (int)arc4random()&0;}\n' | ${CC:-cc} -x c - -o "$out.probe" 2>/dev/null; then
  shim="$here/arc4random_shim.c"
fi
rm -f "$out.probe"
${CC:-cc} -std=gnu11 -O1 -w -I"$L" -I"$L/include" -I"$L/port" -o "$out" \
  "$here/nc_stack_test.c" "$L/nc_stack.c" "$L"/core/*.c $shim
"$out"
rc=$?
rm -f "$out"
exit $rc
