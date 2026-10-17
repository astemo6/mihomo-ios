#!/usr/bin/env bash
# Re-sync core/ from the iOS bridge (astemo6/mihomo-ios, bridge/) and re-apply the Android hooks.
# Usage: scripts/sync-core.sh <path-to-mihomo-ios-checkout>
# Android-only code lives in core/platform_*.go and core/android*.go (never overwritten by this script).
set -euo pipefail
SRC=${1:?path to a mihomo-ios checkout}
DST=$(cd "$(dirname "$0")/.." && pwd)/core
keep=$(mktemp -d)
cp "$DST"/platform*.go "$keep"/ 2>/dev/null || true
rm -rf "$DST"; mkdir -p "$DST"; cp -r "$SRC/bridge/." "$DST/"
cp "$keep"/*.go "$DST"/ 2>/dev/null || true
cd "$DST"
grep -rl "github.com/astemo6/mihomo-ios/bridge" . | xargs sed -i 's#github.com/astemo6/mihomo-ios/bridge#github.com/astemo6/mihomo-android/core#g'
# Hook 1: platform memory limit (iOS clamps to the NE jetsam budget; Android has far more headroom).
sed -i 's/^\tstartGC(o.MemoryLimitMB)$/\tstartGC(platformMemoryLimit(o.MemoryLimitMB))/' bridge.go
# Hook 2: platform tun options (Android VpnService fd instead of the iOS socketpair).
perl -0pi -e 's/(\t\tif o\.IPv6 \{\n\t\t\traw\["tun"\]\.\(map\[string\]any\)\["inet6-address"\] = \[\]any\{"fdfe:dcba:9876::1\/126"\}\n\t\t\})/$1\n\t\tplatformTun(raw, o)/' bridge.go
grep -q 'platformMemoryLimit(o.MemoryLimitMB)' bridge.go && grep -q 'platformTun(raw, o)' bridge.go || { echo "hook patch failed: update scripts/sync-core.sh"; exit 1; }
echo "core synced from $(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo "$SRC")"
