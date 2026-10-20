#!/usr/bin/env python3
"""v0.19.8 clipboard rule (user: 「其他的时候不读取。只在粘贴的时候读」).

The app reads the clipboard ONLY inside an explicit 粘贴 / 从剪贴板… action the user taps (prefer SwiftUI
PasteButton, which needs no marker and shows no prompt). No reads on launch / activate / onAppear / sheet or menu
open, no pre-fill, and no hasStrings / hasURLs / changeCount / detectPatterns polling. Writes (copy) are fine.
Every UIPasteboard read line must carry the marker `// clipboard-read: explicit 粘贴 tap only`.
Mirrored by UnitTests ClipboardRuleTests. Exit 1 on a violation.
"""
import os, re, sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
DIRS = ["App", "Widget", "PacketTunnel", "Shared"]
MARK = "clipboard-read: explicit 粘贴 tap only"
POLL = re.compile(r"UIPasteboard[\w.]*\.(hasStrings|hasURLs|hasImages|hasColors|changeCount|detectPatterns|detectValues)|UIPasteboard\.changedNotification|pasteboardChanged")
READ = re.compile(r"UIPasteboard\.general\.(string|strings|url|urls|image|images|items|data|value|itemProviders)\b(?!\s*=[^=])")


def violations(root=ROOT):
    out = []
    for d in DIRS:
        for dp, _, fs in os.walk(os.path.join(root, d)):
            for f in fs:
                if not f.endswith(".swift"):
                    continue
                p = os.path.join(dp, f)
                for i, line in enumerate(open(p, encoding="utf-8"), 1):
                    if POLL.search(line):
                        out.append(f"{os.path.relpath(p, root)}:{i}: clipboard polling is not allowed")
                    elif READ.search(line) and MARK not in line:
                        out.append(f"{os.path.relpath(p, root)}:{i}: clipboard read without the explicit-粘贴 marker")
    return out


if __name__ == "__main__":
    v = violations()
    print("\n".join(v) if v else "clipboard rule: OK")
    sys.exit(1 if v else 0)
