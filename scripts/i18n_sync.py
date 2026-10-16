#!/usr/bin/env python3
"""Sync App/Localizable.xcstrings with compiler-extracted keys and manage translations.

Usage:
  scripts/i18n_sync.py <dir with *.stringsdata from the CI artifact "stringsdata">
      adds new keys (zh-Hant generated with OpenCC s2twp: `pip install opencc-python-reimplemented`),
      marks en / ja / ko / ru as "new", lists what still needs translating per language
  scripts/i18n_sync.py --export <lang> <out.tsv>
      writes "key<TAB>English" for every key not yet translated into <lang> (newlines as \\n)
  scripts/i18n_sync.py --import <lang> <in.tsv>
      reads "key<TAB>translation" lines and stores them as translated

Keeps manual keys (extractionState "manual") and existing translations. Source language: zh-Hans.
"""
import glob, json, os, sys

CAT = os.path.join(os.path.dirname(__file__), "..", "App", "Localizable.xcstrings")
LANGS = ["en", "ja", "ko", "ru"]  # hand-translated; zh-Hant is generated


def load():
    return json.load(open(CAT, encoding="utf-8"))


def save(cat):
    cat["strings"] = dict(sorted(cat["strings"].items()))
    json.dump(cat, open(CAT, "w", encoding="utf-8"), ensure_ascii=False, indent=2)


def state(v, lang):
    return v.get("localizations", {}).get(lang, {}).get("stringUnit", {}).get("state")


def value(v, lang, key):
    return v.get("localizations", {}).get(lang, {}).get("stringUnit", {}).get("value", key)


def todo(strings, lang):
    return [k for k, v in strings.items() if state(v, lang) != "translated"]


# OpenCC s2twp picks some terms Taiwanese proxy users don't use; one name per thing (v0.6 audit).
ZH_HANT_TERMS = [("指令碼", "腳本"), ("擴充套件", "延伸功能"), ("全域性", "全域"), ("全侷", "全域"), ("麵板", "面板"), ("後臺", "背景")]


def hant(cc, k):
    v = cc.convert(k)
    for a, b in ZH_HANT_TERMS:
        v = v.replace(a, b)
    return v


def sync(d):
    import opencc
    cc = opencc.OpenCC("s2twp")
    cat = load()
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
        loc = {"zh-Hant": {"stringUnit": {"state": "translated", "value": hant(cc, k)}}}
        for lang in LANGS:
            loc[lang] = {"stringUnit": {"state": "new", "value": k}}
        strings[k] = {"localizations": loc}
        added += 1
    save(cat)
    print(f"added {added} keys")
    for lang in LANGS:
        t = todo(strings, lang)
        print(f"{lang}: {len(t)} need translation")
        if lang == "en":
            for k in t:
                print("  " + k.replace("\n", "\\n"))


def export(lang, out):
    cat = load()
    with open(out, "w", encoding="utf-8") as f:
        for k in todo(cat["strings"], lang):
            en = value(cat["strings"][k], "en", k)
            f.write(k.replace("\n", "\\n") + "\t" + en.replace("\n", "\\n") + "\n")


def imp(lang, path):
    cat = load()
    strings = cat["strings"]
    n = 0
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line or "\t" not in line:
            continue
        k, v = line.split("\t", 1)
        k, v = k.replace("\\n", "\n"), v.replace("\\n", "\n")
        if k not in strings:
            print("unknown key:", k[:60])
            continue
        strings[k].setdefault("localizations", {})[lang] = {"stringUnit": {"state": "translated", "value": v}}
        n += 1
    save(cat)
    print(f"{lang}: imported {n}")


if __name__ == "__main__":
    a = sys.argv[1:]
    if a and a[0] == "--export":
        export(a[1], a[2])
    elif a and a[0] == "--import":
        imp(a[1], a[2])
    else:
        sync(a[0] if a else "stringsdata")
