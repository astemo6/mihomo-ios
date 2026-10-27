#!/usr/bin/env python3
"""Alternate app icon guard for every shipped IPA (pure Python).

usage: icon_check.py <ipa> [<ipa> ...]

For each IPA, Payload/Tern.app must have:
  - Info.plist CFBundleIcons and CFBundleIcons~ipad with CFBundlePrimaryIcon AppIcon and CFBundleAlternateIcons
    containing every name in ALTERNATES (each entry's CFBundleIconName = its key), which is what
    UIApplication.setAlternateIconName looks up;
  - Assets.car containing the compiled renditions for AppIcon and every alternate (name strings present).
Added for v0.19.14 after a device report that switching to 夜航 / 晴空 did not work in the -sharedcore IPA.
"""
import plistlib
import re
import sys
import zipfile

ALTERNATES = ["AppIcon-Night", "AppIcon-Sky"]
APP = "Payload/Tern.app/"


def fail(path, msg):
    print(f"{path}: FAIL")
    print("  ERROR " + msg)
    return False


def check(path):
    # r7: a missing file / entry or a broken archive prints a FAIL line (exit 1) instead of a traceback.
    errs = []
    try:
        with zipfile.ZipFile(path) as z:
            names_in_zip = set(z.namelist())
            for entry in ("Info.plist", "Assets.car"):
                if APP + entry not in names_in_zip:
                    return fail(path, f"IPA has no {APP}{entry}")
            info = plistlib.loads(z.read(APP + "Info.plist"))
            car = z.read(APP + "Assets.car")
    except FileNotFoundError:
        return fail(path, "file not found")
    except zipfile.BadZipFile as e:
        return fail(path, f"not a valid IPA (zip): {e}")
    except (plistlib.InvalidFileException, ValueError) as e:
        return fail(path, f"{APP}Info.plist is not a valid plist: {e}")
    except OSError as e:
        return fail(path, f"cannot read: {e}")
    if not isinstance(info, dict):
        return fail(path, f"{APP}Info.plist is not a dictionary")
    for key in ("CFBundleIcons", "CFBundleIcons~ipad"):
        icons = info.get(key) or {}
        if (icons.get("CFBundlePrimaryIcon") or {}).get("CFBundleIconName") != "AppIcon":
            errs.append(f"{key}: primary icon is not AppIcon")
        alt = icons.get("CFBundleAlternateIcons") or {}
        for name in ALTERNATES:
            if (alt.get(name) or {}).get("CFBundleIconName") != name:
                errs.append(f"{key}.CFBundleAlternateIcons missing {name}")
    names = set(m.decode() for m in re.findall(rb"AppIcon[-A-Za-z0-9]*", car))
    for name in ["AppIcon"] + ALTERNATES:
        if name not in names:
            errs.append(f"Assets.car has no {name} rendition")
    print(f"{path}: alternates {sorted((info.get('CFBundleIcons') or {}).get('CFBundleAlternateIcons', {}))}, "
          f"Assets.car icon sets {sorted(names)} -> {'OK' if not errs else 'FAIL'}")
    for e in errs:
        print("  ERROR " + e)
    return not errs


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    ok = all([check(p) for p in sys.argv[1:]])
    sys.exit(0 if ok else 1)
