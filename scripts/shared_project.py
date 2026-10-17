#!/usr/bin/env python3
"""v0.15 shared-core variant: rewrite project.yml -> project-shared.yml.

- Mihomo (app): links FrameworksShared/Libmihomo.xcframework (dynamic) and EMBEDS it once (Frameworks/).
- PacketTunnel: links the same framework without embedding; rpath @executable_path/../../Frameworks
  (= Mihomo.app/Frameworks seen from Mihomo.app/PlugIns/PacketTunnel.appex/PacketTunnel).
- MihomoWidget does not link the core, nothing changes there.
The normal project.yml (static linking) is left untouched; CI builds both.
"""
import re
import sys

src = sys.argv[1] if len(sys.argv) > 1 else "project.yml"
dst = sys.argv[2] if len(sys.argv) > 2 else "project-shared.yml"
text = open(src, encoding="utf-8").read()

STATIC_DEP = "      - framework: Frameworks/Libmihomo.xcframework\n        embed: false\n"
assert text.count(STATIC_DEP) == 2, "expected the static core dependency in exactly two targets"

app_start = text.index("  Mihomo:\n    type: application")
tun_start = text.index("  PacketTunnel:\n    type: app-extension")
wid_start = text.index("  MihomoWidget:\n    type: app-extension")
app, tun, rest = text[app_start:tun_start], text[tun_start:wid_start], text[wid_start:]
head = text[:app_start]

app = app.replace(STATIC_DEP,
                  "      - framework: FrameworksShared/Libmihomo.xcframework\n"
                  "        embed: true\n"
                  "        codeSign: true\n")
app = app.replace("        PRODUCT_NAME: Mihomo\n",
                  "        PRODUCT_NAME: Mihomo\n"
                  "        LD_RUNPATH_SEARCH_PATHS: [\"$(inherited)\", \"@executable_path/Frameworks\"]\n")
tun = tun.replace(STATIC_DEP,
                  "      - framework: FrameworksShared/Libmihomo.xcframework\n"
                  "        embed: false\n")
tun = tun.replace("        PRODUCT_NAME: PacketTunnel\n",
                  "        PRODUCT_NAME: PacketTunnel\n"
                  "        LD_RUNPATH_SEARCH_PATHS: [\"$(inherited)\", \"@executable_path/Frameworks\", \"@executable_path/../../Frameworks\"]\n")
head = head.replace('"$(PROJECT_DIR)/Frameworks"', '"$(PROJECT_DIR)/FrameworksShared"')

out = head + app + tun + rest
assert "Frameworks/Libmihomo.xcframework\n        embed: false" not in out.replace("FrameworksShared", "X")
assert out.count("@executable_path/../../Frameworks") == 1
open(dst, "w", encoding="utf-8").write(out)
print(f"wrote {dst}")
