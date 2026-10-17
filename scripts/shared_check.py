#!/usr/bin/env python3
"""Shared-core variant checks + size report for BOTH variants (pure Python, no Xcode needed).

usage: shared_check.py <shared-core.ipa> <static.ipa> [<static-widget.ipa>] [--summary FILE]

Launch-crash guards (fail the build):
  shared IPA
    - exactly one Payload/Mihomo.app/Frameworks/Libmihomo.framework/Libmihomo, an MH_DYLIB whose install name is
      @rpath/Libmihomo.framework/Libmihomo and which contains the Go runtime (Go buildinfo marker)
    - the dylib depends only on system libraries (/usr/lib, /System/Library) -> nothing else to find at launch
    - dylib platform iOS and minos <= app minos (dyld refuses a newer-minos dylib)
    - framework Info.plist: CFBundleExecutable Libmihomo, CFBundlePackageType FMWK, MinimumOSVersion,
      CFBundleIdentifier (installd / re-signers need these)
    - app + tunnel: MH_EXECUTE, a NON-weak load of @rpath/Libmihomo.framework/Libmihomo, the right LC_RPATH
      (app @executable_path/Frameworks, tunnel @executable_path/../../Frameworks) and NO Go runtime of their own
      (a second copy would mean two Go runtimes / duplicate ObjC classes in one process)
    - no Frameworks/ inside the appex, no widget (or a widget that does not load the core), every Mach-O signed
  static IPAs (must stay as before)
    - app + tunnel each carry the Go runtime, nothing loads @rpath/Libmihomo, no Frameworks/ in the bundle
Report (step summary): IPA sizes, per-component compressed sizes, and the segment sizes the tunnel maps
(static tunnel vs shared tunnel + dylib) -> input for the 50 MB extension memory question.
"""
import plistlib
import struct
import sys
import zipfile

GO_MARKER = b"\xff Go buildinf:"
CORE = "Payload/Mihomo.app/Frameworks/Libmihomo.framework/Libmihomo"
APP = "Payload/Mihomo.app/Mihomo"
TUN = "Payload/Mihomo.app/PlugIns/PacketTunnel.appex/PacketTunnel"
WID = "Payload/Mihomo.app/PlugIns/MihomoWidget.appex/MihomoWidget"
INSTALL_NAME = "@rpath/Libmihomo.framework/Libmihomo"

LC_REQ_DYLD = 0x80000000
LC_SEGMENT_64, LC_LOAD_DYLIB, LC_ID_DYLIB, LC_CODE_SIGNATURE = 0x19, 0xC, 0xD, 0x1D
LC_LOAD_WEAK_DYLIB, LC_RPATH, LC_REEXPORT_DYLIB = 0x18 | LC_REQ_DYLD, 0x1C | LC_REQ_DYLD, 0x1F | LC_REQ_DYLD
LC_BUILD_VERSION, LC_VERSION_MIN_IPHONEOS = 0x32, 0x25
MH_EXECUTE, MH_DYLIB = 2, 6

errors = []


def fail(msg):
    errors.append(msg)
    print("FAIL:", msg)


def thin(data):
    """Return the arm64 slice of a (possibly fat) Mach-O."""
    magic = struct.unpack(">I", data[:4])[0]
    if magic in (0xCAFEBABE, 0xCAFEBABF):
        n = struct.unpack(">I", data[4:8])[0]
        is64 = magic == 0xCAFEBABF
        off = 8
        for _ in range(n):
            if is64:
                cpu, _, o, s = struct.unpack(">iiQQ", data[off:off + 24]); off += 32
            else:
                cpu, _, o, s = struct.unpack(">iiII", data[off:off + 16]); off += 20
            if cpu == 0x0100000C:
                return data[o:o + s]
        raise ValueError("no arm64 slice")
    return data


def cstr(b, off):
    return b[off:b.index(b"\0", off)].decode()


def ver(v):
    return f"{v >> 16}.{(v >> 8) & 0xFF}" + (f".{v & 0xFF}" if v & 0xFF else "")


def macho(data):
    d = thin(data)
    magic, cpu, _, ftype, ncmds, _, _, _ = struct.unpack("<IiiIIIII", d[:32])
    if magic != 0xFEEDFACF:
        raise ValueError("not a 64-bit Mach-O")
    info = dict(cpu=cpu, type=ftype, loads=[], weak=[], rpaths=[], id=None, minos=None, platform=None,
                signed=False, segs={}, go=GO_MARKER in d)
    off = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack("<II", d[off:off + 8])
        body = d[off:off + size]
        if cmd in (LC_LOAD_DYLIB, LC_REEXPORT_DYLIB):
            info["loads"].append(cstr(body, struct.unpack("<I", body[8:12])[0]))
        elif cmd == LC_LOAD_WEAK_DYLIB:
            info["weak"].append(cstr(body, struct.unpack("<I", body[8:12])[0]))
        elif cmd == LC_ID_DYLIB:
            info["id"] = cstr(body, struct.unpack("<I", body[8:12])[0])
        elif cmd == LC_RPATH:
            info["rpaths"].append(cstr(body, struct.unpack("<I", body[8:12])[0]))
        elif cmd == LC_BUILD_VERSION:
            info["platform"], info["minos"] = struct.unpack("<II", body[8:16])
        elif cmd == LC_VERSION_MIN_IPHONEOS:
            info["platform"], info["minos"] = 2, struct.unpack("<I", body[8:12])[0]
        elif cmd == LC_CODE_SIGNATURE:
            info["signed"] = True
        elif cmd == LC_SEGMENT_64:
            name = body[8:24].rstrip(b"\0").decode()
            vmsize, _, filesize = struct.unpack("<QQQ", body[32:56])
            info["segs"][name] = (vmsize, filesize)
        off += size
    return info


def mb(n):
    return f"{n / 1048576:.2f} MB"


def components(z):
    g = {}
    for i in z.infolist():
        n = i.filename
        base = n.rsplit("/", 1)[-1]
        if n == APP: k = "app binary"
        elif n == TUN: k = "tunnel binary"
        elif n == WID: k = "widget binary"
        elif n == CORE: k = "shared core (Libmihomo.framework)"
        elif base.endswith((".dat", ".metadb", ".mmdb")): k = "geo databases"
        elif ".lproj/" in n: k = "localizations"
        elif base.endswith((".car", ".png")): k = "assets / icons"
        else: k = "other"
        g[k] = g.get(k, 0) + i.compress_size
    return g


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    summary = None
    if "--summary" in sys.argv:
        summary = sys.argv[sys.argv.index("--summary") + 1]
        args = [a for a in args if a != summary]
    shared_ipa, static_ipa = args[0], args[1]
    widget_ipa = args[2] if len(args) > 2 else None

    zs = zipfile.ZipFile(shared_ipa)
    names = zs.namelist()
    cores = [n for n in names if n.endswith("/Libmihomo") and not n.endswith("/Headers/Libmihomo")]
    if cores != [CORE]:
        fail(f"expected exactly one shared core at {CORE}, found {cores}")
        return report(summary)
    core = macho(zs.read(CORE))
    app = macho(zs.read(APP))
    tun = macho(zs.read(TUN))

    if core["type"] != MH_DYLIB: fail(f"Libmihomo is not an MH_DYLIB (filetype {core['type']})")
    if core["id"] != INSTALL_NAME: fail(f"Libmihomo install name {core['id']!r} != {INSTALL_NAME}")
    if not core["go"]: fail("Libmihomo carries no Go runtime (buildinfo marker missing)")
    nonsys = [l for l in core["loads"] + core["weak"] if not l.startswith(("/usr/lib/", "/System/Library/"))]
    if nonsys: fail(f"Libmihomo depends on non-system libraries: {nonsys}")
    if core["platform"] != 2: fail(f"Libmihomo platform {core['platform']} is not iOS (2)")
    if core["minos"] is None or app["minos"] is None or core["minos"] > app["minos"]:
        fail(f"Libmihomo minos {core['minos'] and ver(core['minos'])} > app minos {app['minos'] and ver(app['minos'])}")

    plist_name = CORE.rsplit("/", 1)[0] + "/Info.plist"
    if plist_name not in names:
        fail("Libmihomo.framework/Info.plist missing")
    else:
        p = plistlib.loads(zs.read(plist_name))
        for k, want in (("CFBundleExecutable", "Libmihomo"), ("CFBundlePackageType", "FMWK")):
            if p.get(k) != want: fail(f"framework Info.plist {k}={p.get(k)!r}, want {want!r}")
        for k in ("CFBundleIdentifier", "MinimumOSVersion", "CFBundleShortVersionString"):
            if not p.get(k): fail(f"framework Info.plist lacks {k}")

    for label, m, rp in (("app", app, "@executable_path/Frameworks"), ("tunnel", tun, "@executable_path/../../Frameworks")):
        if m["type"] != MH_EXECUTE: fail(f"{label}: not MH_EXECUTE")
        if INSTALL_NAME not in m["loads"]:
            fail(f"{label}: no (non-weak) load of {INSTALL_NAME}; loads={m['loads']} weak={m['weak']}")
        if rp not in m["rpaths"]: fail(f"{label}: LC_RPATH {rp} missing (has {m['rpaths']})")
        if m["go"]: fail(f"{label}: still contains a Go runtime (static core linked in as well)")
        if m["minos"] != app["minos"]: fail(f"{label}: minos {ver(m['minos'])} differs from the app")
    for label, m in (("Libmihomo", core), ("app", app), ("tunnel", tun)):
        if not m["signed"]: fail(f"{label}: no LC_CODE_SIGNATURE")
    if f"{CORE.rsplit('/', 1)[0]}/_CodeSignature/CodeResources" not in names:
        fail("Libmihomo.framework/_CodeSignature/CodeResources missing (framework bundle not signed)")
    if any(n.startswith("Payload/Mihomo.app/PlugIns/PacketTunnel.appex/Frameworks/") for n in names):
        fail("PacketTunnel.appex carries its own Frameworks/")
    if WID in names and INSTALL_NAME in macho(zs.read(WID))["loads"]:
        fail("widget loads the core; it would need the same rpath")
    hdr = [n for n in names if "/Libmihomo.framework/Headers/" in n or "/Libmihomo.framework/Modules/" in n]
    if hdr: fail(f"framework headers / modules shipped: {hdr[:3]}")

    statics = [(static_ipa, zipfile.ZipFile(static_ipa))]
    if widget_ipa:
        statics.append((widget_ipa, zipfile.ZipFile(widget_ipa)))
    for path, z in statics:
        zn = z.namelist()
        if any("/Frameworks/" in n for n in zn): fail(f"{path}: static IPA ships a Frameworks/ folder")
        for label, n in (("app", APP), ("tunnel", TUN)):
            m = macho(z.read(n))
            if not m["go"]: fail(f"{path}: {label} has no Go runtime (static linking changed)")
            if any("Libmihomo" in l for l in m["loads"] + m["weak"]): fail(f"{path}: {label} loads a Libmihomo dylib")

    st_tun = macho(statics[0][1].read(TUN))
    return report(summary, shared_ipa, zs, statics, core, app, tun, st_tun)


def report(summary, shared_ipa=None, zs=None, statics=None, core=None, app=None, tun=None, st_tun=None):
    lines = []
    if zs is not None:
        import os
        rows = [(p, os.path.getsize(p), z) for p, z in statics] + [(shared_ipa, os.path.getsize(shared_ipa), zs)]
        base = rows[0][1]
        lines += ["### IPA size: static vs shared core", "",
                  "| IPA | size | vs static |", "|---|---:|---:|"]
        for p, s, _ in rows:
            d = s - base
            lines.append(f"| `{p.rsplit('/', 1)[-1]}` | {s:,} B ({mb(s)}) | "
                         f"{'—' if p == rows[0][0] else f'{d:+,} B ({d / base * 100:+.1f} %)'} |")
        comps = [components(z) for _, _, z in rows]
        keys = sorted({k for c in comps for k in c}, key=lambda k: -max(c.get(k, 0) for c in comps))
        heads = ["static" if i == 0 else "static + widget" if i < len(rows) - 1 else "shared core"
                 for i in range(len(rows))]
        lines += ["", "| component (compressed) | " + " | ".join(heads) + " |",
                  "|---|" + "---:|" * len(rows)]
        for k in keys:
            lines.append(f"| {k} | " + " | ".join(mb(c.get(k, 0)) if c.get(k) else "—" for c in comps) + " |")
        seg = ("__TEXT", "__DATA_CONST", "__DATA", "__LINKEDIT")
        lines += ["", "#### Tunnel process: mapped segments (vmsize)", "",
                  "| segment | static tunnel | shared: tunnel + Libmihomo |", "|---|---:|---:|"]
        for s in seg:
            a = st_tun["segs"].get(s, (0, 0))[0]
            b = tun["segs"].get(s, (0, 0))[0] + core["segs"].get(s, (0, 0))[0]
            lines.append(f"| {s} | {mb(a)} | {mb(b)} |")
        lines += ["", f"- Libmihomo: install name `{core['id']}`, minos {ver(core['minos'])} (app {ver(app['minos'])}), "
                      f"deps: {', '.join(l.rsplit('/', 1)[-1] for l in core['loads'])}",
                  f"- app rpaths {app['rpaths']}, tunnel rpaths {tun['rpaths']}; Go runtime only in Libmihomo",
                  "- __DATA / __DATA_CONST pages get rebased at load in both layouts (file-backed __TEXT / __LINKEDIT "
                  "are clean and do not count toward the extension's 50 MB footprint)."]
    lines.append("")
    lines.append("- shared-core checks: " + ("**FAILED** — " + "; ".join(errors) if errors else "all passed"))
    text = "\n".join(lines)
    print(text)
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(text + "\n")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
