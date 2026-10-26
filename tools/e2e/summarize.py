#!/usr/bin/env python3
"""Tern E2E replay — turn the E2E-RESULT lines of both stages into the job summary + report.

  summarize.py OUT_MD [--known tools/e2e/known-gaps.txt] [--title T] [--expect-stages app,tunnel] INPUT...

--expect-stages: every listed stage must end with its `stage-done` INFO line; a stage that never reported it (hung,
crashed, timed out, never started) gets a synthetic `<stage>/stage-done` FAIL so a partial run cannot pass.

INPUT: results.jsonl files and/or xcodebuild logs (lines `E2E-RESULT|stage|name|STATUS|detail`, `E2E-NOTE|stage|text`).
JSONL wins when both carry a scenario (same stage+name: last one).

known-gaps.txt: `<scenario fnmatch pattern> <TAB> <why / which lane fixes it>`. A FAIL matching a known gap is shown as
KNOWN and does not fail the job; a PASS matching one is shown as FIXED? (remove the line). Exit 1 when any FAIL is not
a known gap, or when no result at all was found.
"""

import fnmatch
import json
import sys


def load_known(path):
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for raw in f:
                line = raw.rstrip("\n")
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                pat, _, why = line.partition("\t")
                out.append((pat.strip(), why.strip()))
    except OSError:
        pass
    return out


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__, file=sys.stderr)
        return 2
    out_md = args.pop(0)
    known_path, title = "tools/e2e/known-gaps.txt", "E2E replay"
    expect = []
    inputs = []
    while args:
        a = args.pop(0)
        if a == "--known":
            known_path = args.pop(0)
        elif a == "--title":
            title = args.pop(0)
        elif a == "--expect-stages":
            expect = [x for x in args.pop(0).split(",") if x]
        else:
            inputs.append(a)
    results, notes, order = {}, [], []
    for path in inputs:
        try:
            f = open(path, encoding="utf-8", errors="replace")
        except OSError:
            continue
        with f:
            for raw in f:
                line = raw.strip()
                rec = None
                if line.startswith("{") and '"status"' in line:
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        rec = None
                else:
                    i = line.find("E2E-RESULT|")
                    if i >= 0:
                        parts = line[i:].split("|", 4)
                        if len(parts) == 5:
                            rec = {"stage": parts[1], "name": parts[2], "status": parts[3], "detail": parts[4]}
                    j = line.find("E2E-NOTE|")
                    if j >= 0:
                        p = line[j:].split("|", 2)
                        if len(p) == 3 and p[2] not in notes:
                            notes.append("[%s] %s" % (p[1], p[2]))
                if rec:
                    key = (rec["stage"], rec["name"])
                    if key not in results:
                        order.append(key)
                    results[key] = rec
    for st in expect:
        if (st, "stage-done") not in results:
            last = [k[1] for k in order if k[0] == st]
            results[(st, "stage-done")] = {"stage": st, "name": "stage-done", "status": "FAIL",
                                           "detail": "stage did not finish (hung / crashed / timed out / never ran); last scenario: %s"
                                           % (last[-1] if last else "none")}
            order.append((st, "stage-done"))
    known = load_known(known_path)
    rows, unexpected, fixed = [], 0, []
    counts = {}
    for key in order:
        rec = results[key]
        st = rec["status"]
        why = next((w for p, w in known if fnmatch.fnmatch(rec["name"], p)), None)
        shown = st
        if st == "FAIL" and why:
            shown = "KNOWN"
        elif st == "FAIL":
            unexpected += 1
        elif st == "PASS" and why:
            shown = "FIXED?"
            fixed.append(rec["name"])
        counts[shown] = counts.get(shown, 0) + 1
        icon = {"PASS": "✅", "FAIL": "❌", "SKIP": "⏭️", "INFO": "ℹ️", "KNOWN": "🟧", "FIXED?": "🟩"}.get(shown, "")
        detail = rec.get("detail", "").replace("\n", " ")
        if why and shown in ("KNOWN", "FIXED?"):
            detail = "%s — known gap: %s" % (detail, why)
        rows.append("| %s %s | %s | `%s` | %s |" % (icon, shown, rec["stage"], rec["name"], detail.replace("|", "¦")))
    lines = ["### %s" % title, ""]
    if not rows:
        lines.append("❌ **no E2E-RESULT line found** — the replay did not run (build / test host failure; see the logs).")
    else:
        summary = ", ".join("%s %d" % (k, v) for k, v in sorted(counts.items()))
        lines.append("**%s** — unexpected failures: **%d**" % (summary, unexpected))
        lines += ["", "| result | stage | scenario | detail |", "|---|---|---|---|"] + rows
    if fixed:
        lines += ["", "🟩 Passing now but still listed in known-gaps.txt: " + ", ".join("`%s`" % f for f in fixed)]
    if notes:
        lines += ["", "<details><summary>notes (%d)</summary>" % len(notes), "", "```"] + notes[:400] + ["```", "</details>"]
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("results %d, unexpected failures %d" % (len(rows), unexpected))
    return 1 if (unexpected or not rows) else 0


if __name__ == "__main__":
    sys.exit(main())
