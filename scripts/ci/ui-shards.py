#!/usr/bin/env python3
"""ci/speedup: split the full-matrix UI tests of one language into N jobs of about equal duration.

  ui-shards.py N            summary of all shards (plan job)
  ui-shards.py N K          selection for shard K (1-based): lines "light <xcodebuild arg>" / "dark <xcodebuild arg>"

Work items: every light-appearance UI test, read from the sources (UITests/*.swift: `func test…` inside `class X` /
`extension X` at top level, so a new test is scheduled without editing anything), plus the dark-appearance checks
(DARK below — the tests the old dark:0 job ran). Durations: scripts/ci/ui-test-times.tsv (unknown = the median).
Greedy longest-first into the currently lightest shard — deterministic for a given source tree. A shard job runs its
light tests, then switches the simulator to dark and runs its dark tests (if any).
Light: shards 1…N-1 are explicit -only-testing lists; shard N is `-only-testing:TernUITests` minus everything in shards
1…N-1, so even a test this parser missed still runs (in shard N).
"""
import glob, os, re, statistics, sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
TARGET = "TernUITests"
DARK = ["TernUITests/test01_TabsAndHome", "TernUITests/test03_MoreEveryPage", "TernUITests/test04_NodeManager",
        "TernUITests/test05_AddNodeAndEditor"]


def tests():
    out = []
    for p in sorted(glob.glob(os.path.join(ROOT, "UITests", "*.swift"))):
        cls = None
        for line in open(p, encoding="utf-8"):
            m = re.match(r"(?:final\s+|open\s+|public\s+)*(?:class|extension)\s+(\w+)", line)
            if m:
                cls = m.group(1)
                continue
            m = re.match(r"\s+(?:@\w+\s+)*func\s+(test\w*)\s*\(", line)
            if m and cls:
                out.append(f"{cls}/{m.group(1)}")
    return sorted(set(out))


def times():
    t = {}
    for line in open(os.path.join(ROOT, "scripts", "ci", "ui-test-times.tsv"), encoding="utf-8"):
        if line.startswith("#") or not line.strip():
            continue
        k, v = line.rstrip("\n").split("\t")
        t[k] = float(v)
    return t


def shards(n):
    items = tests() + ["dark:" + t for t in DARK]
    dur = times()
    med = statistics.median(dur.values()) if dur else 60.0
    bins = [[0.0, []] for _ in range(n)]
    for k in sorted(items, key=lambda k: (-dur.get(k, med), k)):
        b = min(bins, key=lambda b: b[0])
        b[0] += dur.get(k, med)
        b[1].append(k)
    return bins, [k for k in items if k not in dur]


def main():
    n = int(sys.argv[1])
    bins, unknown = shards(n)
    if len(sys.argv) == 2:
        light = sum(1 for b in bins for k in b[1] if not k.startswith("dark:"))
        print(f"{light} light + {len(DARK)} dark UI test runs in {n} jobs (estimated minutes of tests):")
        for i, (t, ks) in enumerate(bins, 1):
            d = sum(1 for k in ks if k.startswith("dark:"))
            print(f"- {i}/{n}: {len(ks) - d} light + {d} dark, ~{t / 60:.1f} min")
        if unknown:
            print(f"- no measured duration (counted as the median): {' '.join(unknown)}")
        return
    k = int(sys.argv[2])
    mine = bins[k - 1][1]
    if k < n:
        for t in sorted(x for x in mine if not x.startswith("dark:")):
            print(f"light -only-testing:{TARGET}/{t}")
    else:
        print(f"light -only-testing:{TARGET}")
        for b in bins[:-1]:
            for t in sorted(x for x in b[1] if not x.startswith("dark:")):
                print(f"light -skip-testing:{TARGET}/{t}")
    for t in sorted(x[5:] for x in mine if x.startswith("dark:")):
        print(f"dark -only-testing:{TARGET}/{t}")


if __name__ == "__main__":
    main()
