#!/usr/bin/env bash
# ci/speedup: pick the iOS simulator every test job uses (iOS 18 runtime first; iPhone 16 Pro → 17 Pro → 15 Pro → 16)
# and start booting it without waiting (the wait — `xcrun simctl bootstatus "$DEV" -b`, 1.8–3.5 min measured —
# happens right before the tests, so it overlaps whatever the job does in between).
# Prints the UDID on stdout; diagnostics on stderr. Same selection the workflows used inline before.
set -euo pipefail
DEV=$(xcrun simctl list devices available -j | python3 -c "
import json,sys
d=json.load(sys.stdin)['devices']
devs=[(r,x) for r,l in d.items() if 'iOS' in r for x in l]
devs.sort(key=lambda rx: (0 if 'iOS-18' in rx[0] else 1, rx[0]))
for want in ['iPhone 16 Pro','iPhone 17 Pro','iPhone 15 Pro','iPhone 16']:
    m=[(r,x) for r,x in devs if x['name']==want]
    if m: print(m[0][1]['udid']); sys.stderr.write('using %s on %s\\n' % (want, m[0][0])); break
")
test -n "$DEV"
xcrun simctl boot "$DEV" >&2 || true
echo "$DEV"
