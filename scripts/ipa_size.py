#!/usr/bin/env python3
"""IPA size report: top 15 files + per component. Fails when build junk ships.
usage: ipa_size.py <ipa> [--shared-core]   (--shared-core allows exactly one Frameworks/Libmihomo.framework)"""
import sys, zipfile, collections

path = sys.argv[1]
shared = "--shared-core" in sys.argv
z = zipfile.ZipFile(path)
rows = sorted(((i.compress_size, i.file_size, i.filename) for i in z.infolist()), reverse=True)
print("compressed   unpacked  file (top 15)")
for c, u, n in rows[:15]:
    print(f"{c:>10} {u:>10}  {n}")
groups = collections.defaultdict(lambda: [0, 0])
for c, u, n in rows:
    base = n.rsplit("/", 1)[-1]
    if n.endswith("Mihomo.app/Mihomo"): k = "app binary"
    elif n.endswith("PacketTunnel.appex/PacketTunnel"): k = "tunnel binary"
    elif n.endswith("MihomoWidget.appex/MihomoWidget"): k = "widget binary"
    elif n.endswith("Libmihomo.framework/Libmihomo"): k = "shared core"
    elif base.endswith((".dat", ".metadb", ".mmdb")): k = "geo databases"
    elif base.endswith(".car") or base.endswith(".png"): k = "assets / icons"
    elif ".lproj/" in n: k = "localizations"
    else: k = "other"
    groups[k][0] += c; groups[k][1] += u
print("--- per component (compressed / unpacked) ---")
for k, (c, u) in sorted(groups.items(), key=lambda x: -x[1][0]):
    print(f"{k:16} {c:>10} {u:>10}")

def allowed(n):
    return shared and n.startswith("Payload/Mihomo.app/Frameworks/Libmihomo.framework/") and \
        "/Headers/" not in n and "/Modules/" not in n

bad = [n for _, _, n in rows
       if (".dSYM" in n or n.endswith((".swiftmodule", ".h", ".a")) or "/Headers/" in n or "/Modules/" in n
           or ".framework/" in n or "Libmihomo" in n) and not allowed(n)]
if shared:
    cores = [n for _, _, n in rows if n.endswith("/Libmihomo")]
    if cores != ["Payload/Mihomo.app/Frameworks/Libmihomo.framework/Libmihomo"]:
        bad += ["expected exactly one shared core, found: " + ", ".join(cores)]
if bad:
    print("SHOULD NOT SHIP:", *bad[:20], sep="\n  "); sys.exit(1)
print("ok:", "one shared Libmihomo.framework, no dSYM / headers" if shared else "no dSYM / swiftmodule / headers / embedded frameworks")
