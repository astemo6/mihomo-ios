#!/usr/bin/env python3
"""Terminology audit for App/Localizable.xcstrings: one name per thing in every language.

For each core term (配置 → Profile, 节点 → Node, 订阅 → Subscription …) it lists translations that use a
competing word instead of the canonical one. Keys about the iOS "VPN 配置" or foreign Surge / QX configs
are a different concept and are skipped. Exit code 1 when anything is inconsistent.

r7 brand check: the app is Tern. A user-visible "Mihomo" (capital M: the old app name) in the string catalog
(keys and every translation), in an Info.plist display name / usage description, or in a UI string literal of the
Swift sources fails the audit. Lowercase "mihomo" names the core / config format and is allowed, as are legal and
core attributions (GPL notices, "mihomo core", MetaCubeX).

Usage: scripts/term_audit.py [-q]
"""
import glob, json, os, plistlib, re, sys

CAT = os.path.join(os.path.dirname(__file__), "..", "App", "Localizable.xcstrings")
CANON = {
    "en": {"配置": (r"profile", r"\bconfig"), "策略组": (r"policy group", r"proxy group"), "规则集": (r"rule set", r"ruleset"),
           "节点": (r"node", r"\bserver"), "订阅": (r"subscription", r"\bsub\b"), "重写": (r"rewrite", r"override")},
    "ja": {"配置": (r"プロファイル", r"構成|設定ファイル|プロフィール"), "节点": (r"ノード", r"サーバー"), "订阅": (r"購読", r"サブスクリプション"),
           "重写": (r"書き換え", r"リライト"), "规则集": (r"ルールセット", r"ルール集")},
    "ko": {"配置": (r"프로파일", r"프로필|구성"), "节点": (r"노드", r"서버"), "订阅": (r"구독", r"서브스크립션"), "重写": (r"재작성", r"리라이트|다시 쓰기")},
    "ru": {"配置": (r"профил", r"конфиг"), "节点": (r"узл|узел", r"сервер"), "订阅": (r"подписк", r"subscription"), "重写": (r"перезапис", r"переписыв")},
    "zh-Hant": {"脚本": (r"腳本", r"指令碼"), "全局": (r"全域", r"全域性|全侷"), "面板": (r"面板", r"麵板"), "扩展": (r"延伸功能|擴展", r"擴充套件")},
}
# Different concepts that share a Chinese word: the iOS VPN configuration, foreign client configs,
# the generated runtime config, proxy-server name resolution.
SKIP = re.compile(r"VPN 配置|Surge|Quantumult|QX|运行配置|未配置|proxy-server-nameserver|规则集 / 节点集缓存|一个 zip|MitM 即可重写")


ROOT = os.path.join(os.path.dirname(__file__), "..")
# Swift sources under these top-level directories are not brand-audited: the test bundles, and bridge/ —
# the gomobile Go package deleted in the Go-zero migration. The bridge skip stays explicit so a stale
# checkout (or the org mirror) never audits sources that no longer ship.
SKIP_PATH_PREFIXES = ("UITests", "UnitTests", "bridge")
BRAND = re.compile(r"\bMihomo\b")
# Attribution and legal text that may keep the upstream name.
BRAND_OK = re.compile(r"Mihomo[ -]?(core|内核|核心|kernel|カーネル|커널|ядр)|MetaCubeX|General Public License|GPL", re.I)
# Swift UI string literals: Text("…"), String(localized: "…"), Label / Button / Section / TextField titles,
# navigationTitle, prompt: / placeholder: arguments.
UI_LITERAL = re.compile(r'(?:\bText|\bLabel|\bButton|\bSection|\bTextField|\bSecureField|\bToggle|navigationTitle|'
                        r'String\(localized:|LocalizedStringKey\(|prompt:|placeholder:|title:|message:)\s*\(?\s*"((?:[^"\\]|\\.)*)"')
PLIST_KEYS = ("CFBundleDisplayName", "CFBundleName")


def brand_hits():
    """User-visible "Mihomo" outside the allowed attributions, as (where, text)."""
    hits = []

    def check(where, text):
        if BRAND.search(text) and not BRAND_OK.search(text):
            hits.append((where, text))

    s = json.load(open(CAT, encoding="utf-8"))["strings"]
    for k, v in s.items():
        check("catalog key", k)
        for lang, loc in v.get("localizations", {}).items():
            u = loc.get("stringUnit", {}).get("value")
            if u:
                check(f"catalog {lang} of {k[:30]!r}", u)
    for p in sorted(glob.glob(os.path.join(ROOT, "*", "Info.plist"))):
        try:
            info = plistlib.load(open(p, "rb"))
        except Exception:
            continue
        for key, val in info.items():
            if isinstance(val, str) and (key in PLIST_KEYS or key.endswith("UsageDescription")):
                check(f"{os.path.relpath(p, ROOT)} {key}", val)
    for p in sorted(glob.glob(os.path.join(ROOT, "**", "*.swift"), recursive=True)):
        rel = os.path.relpath(p, ROOT)
        if rel.startswith(SKIP_PATH_PREFIXES):
            continue
        for n, line in enumerate(open(p, encoding="utf-8"), 1):
            if line.lstrip().startswith("//"):
                continue
            for m in UI_LITERAL.finditer(line):
                check(f"{rel}:{n}", m.group(1))
    return hits


def main():
    s = json.load(open(CAT, encoding="utf-8"))["strings"]
    bad = 0
    for lang, terms in CANON.items():
        for term, (good, alt) in terms.items():
            for k, v in s.items():
                if term not in k or SKIP.search(k):
                    continue
                u = v.get("localizations", {}).get(lang, {}).get("stringUnit", {}).get("value")
                if u and re.search(alt, u, re.I) and not re.search(good, u, re.I):
                    bad += 1
                    if "-q" not in sys.argv:
                        print(f"{lang}\t{term}\t{k[:40]!r} => {u[:80]!r}")
    print("inconsistent:", bad)
    brand = brand_hits()
    for where, text in brand:
        if "-q" not in sys.argv:
            print(f"brand\t{where}\t{text[:80]!r}")
    print("brand leftovers (\"Mihomo\"):", len(brand))
    sys.exit(1 if bad or brand else 0)


if __name__ == "__main__":
    main()
