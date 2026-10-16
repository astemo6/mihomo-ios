#!/usr/bin/env python3
"""Sync App/Localizable.xcstrings with compiler-extracted keys.

Usage: scripts/i18n_sync.py <dir with *.stringsdata from the CI artifact "stringsdata">

- adds new keys (zh-Hant generated with OpenCC s2twp: `pip install opencc-python-reimplemented`)
- lists keys that still need an English translation (state "new")
- keeps manual keys (extractionState "manual") and existing translations
"""
import glob, json, os, sys

CAT = os.path.join(os.path.dirname(__file__), "..", "App", "Localizable.xcstrings")

def main(d):
    import opencc
    cc = opencc.OpenCC("s2twp")
    cat = json.load(open(CAT, encoding="utf-8"))
    keys = set()
    for f in glob.glob(os.path.join(d, "*.stringsdata")):
        for table in json.load(open(f)).get("tables", {}).values():
            keys.update(e["key"] for e in table)
    keys.discard("")
    strings = cat["strings"]
    added = 0
    for k in sorted(keys):
        if k in strings:
            continue
        strings[k] = {"localizations": {"zh-Hant": {"stringUnit": {"state": "translated", "value": cc.convert(k)}},
                                         "en": {"stringUnit": {"state": "new", "value": k}}}}
        added += 1
    cat["strings"] = dict(sorted(strings.items()))
    json.dump(cat, open(CAT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    todo = [k for k, v in strings.items() if v.get("localizations", {}).get("en", {}).get("stringUnit", {}).get("state") != "translated"]
    print(f"added {added} keys; {len(todo)} need English:")
    for k in todo:
        print("  " + k.replace("\n", "\\n"))

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "stringsdata")
