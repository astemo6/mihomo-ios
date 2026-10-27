#!/usr/bin/env python3
"""ci/speedup: remove the Thread Performance Checker (libRPAC) from .xctestrun files (argv; default: every
*.xctestrun below the current directory).

fix/nc-mem-4: its priority-inversion report (JSCThread, timing-dependent) made XCTest symbolicate the ~100 MB Debug
test bundle on the main thread with CoreSymbolication: +55 MB for ~2 s, the whole kernel peak of the E2E memory gate
(runs 40419441795 / 40422441193 / 40431543693). The TernE2E scheme flag alone did not keep it out of every run, so the
jobs that run the TernE2E xctestrun (E2E replay, OpenConnect / CONNECT-IP / WARP loopback) strip it from the file
test-without-building reads. Moved here unchanged from e2e-replay.yml. A device / Release build never loads the checker.
"""
import glob, plistlib, sys

files = sys.argv[1:] or glob.glob("**/*.xctestrun", recursive=True)
for f in files:
    with open(f, "rb") as fh:
        d = plistlib.load(fh)
    n = 0

    def fix(env):
        global n
        if not isinstance(env, dict):
            return
        for k in list(env):
            if k.startswith("PERFC_"):
                del env[k]
                n += 1
        v = env.get("DYLD_INSERT_LIBRARIES")
        if isinstance(v, str) and "RPAC" in v:
            env["DYLD_INSERT_LIBRARIES"] = ":".join(x for x in v.split(":") if "RPAC" not in x)
            n += 1

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in ("EnvironmentVariables", "TestingEnvironmentVariables"):
                    fix(v)
                else:
                    walk(v)
        elif isinstance(o, list):
            for x in o:
                walk(x)

    walk(d)
    with open(f, "wb") as fh:
        plistlib.dump(d, fh)
    print(f"{f}: {n} Thread Performance Checker setting(s) removed")
