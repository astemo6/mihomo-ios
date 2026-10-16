#!/usr/bin/env python3
"""Terminology audit for App/Localizable.xcstrings: one name per thing in every language.

For each core term (配置 → Profile, 节点 → Node, 订阅 → Subscription …) it lists translations that use a
competing word instead of the canonical one. Keys about the iOS "VPN 配置" or foreign Surge / QX configs
are a different concept and are skipped. Exit code 1 when anything is inconsistent.

Usage: scripts/term_audit.py [-q]
"""
import json, os, re, sys

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
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
