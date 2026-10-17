#!/bin/bash
# v0.15 "shared core" test variant (macOS / CI only).
#
# gomobile can only produce a STATIC Libmihomo.framework, which ends up linked into both the app and the
# PacketTunnel extension (~26 MB compressed twice). This script links that static archive into ONE dynamic,
# shallow iOS framework (install name @rpath/Libmihomo.framework/Libmihomo) and wraps it in
# FrameworksShared/Libmihomo.xcframework. scripts/shared_project.py then rewrites project.yml so the app
# embeds it once (Mihomo.app/Frameworks) and the tunnel loads it via @executable_path/../../Frameworks.
#
# usage: scripts/shared_core.sh [static xcframework] [out dir] [bundle id prefix] [version]
set -euo pipefail
SRC=${1:-Frameworks/Libmihomo.xcframework}
OUT=${2:-FrameworksShared}
PREFIX=${3:-com.astemo6.mihomo}
VER=${4:-1.0}
MINOS=15.0

SLICE=$(find "$SRC" -maxdepth 1 -type d -name 'ios-arm64*' ! -name '*simulator*' | head -n1)
FW="$SLICE/Libmihomo.framework"
test -e "$FW/Libmihomo" || { echo "no static Libmihomo in $SRC"; exit 1; }

WORK=$(mktemp -d)
cp -L "$FW/Libmihomo" "$WORK/libmihomo.a"
file "$WORK/libmihomo.a"

DST="$WORK/Libmihomo.framework"
mkdir -p "$DST/Headers" "$DST/Modules"
cp -L "$FW"/Headers/* "$DST/Headers/"
cp -L "$FW"/Modules/* "$DST/Modules/"

SDK=$(xcrun --sdk iphoneos --show-sdk-path)
# -all_load keeps every object (Go's go.o + the gomobile Objective-C glue); exported = global symbols only.
# Frameworks: what Go's runtime / crypto/x509 / net and the objc glue reference on iOS.
xcrun --sdk iphoneos clang -target arm64-apple-ios${MINOS} -isysroot "$SDK" \
  -dynamiclib -o "$DST/Libmihomo" \
  -install_name @rpath/Libmihomo.framework/Libmihomo \
  -compatibility_version 1 -current_version 1 \
  -Wl,-all_load "$WORK/libmihomo.a" \
  -framework Foundation -framework CoreFoundation -framework Security -framework SystemConfiguration \
  -lresolv -lobjc \
  -Wl,-dead_strip_dylibs -Wl,-x -Wl,-headerpad_max_install_names

cat > "$DST/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key><string>en</string>
  <key>CFBundleExecutable</key><string>Libmihomo</string>
  <key>CFBundleIdentifier</key><string>${PREFIX}.Libmihomo</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>Libmihomo</string>
  <key>CFBundlePackageType</key><string>FMWK</string>
  <key>CFBundleShortVersionString</key><string>${VER}</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>CFBundleSupportedPlatforms</key><array><string>iPhoneOS</string></array>
  <key>MinimumOSVersion</key><string>${MINOS}</string>
</dict>
</plist>
EOF
plutil -lint "$DST/Info.plist"

echo "--- dylib ---"
file "$DST/Libmihomo"
ls -la "$DST/Libmihomo"
otool -L "$DST/Libmihomo"
otool -l "$DST/Libmihomo" | grep -A4 -E "LC_BUILD_VERSION|LC_ID_DYLIB" | head -n 20
echo "exported Libmihomo* / Universe* ObjC classes: $(nm -gU "$DST/Libmihomo" | grep -c -E 'OBJC_CLASS_\$_(Libmihomo|Universe)' || true)"

rm -rf "$OUT/Libmihomo.xcframework"
mkdir -p "$OUT"
xcodebuild -create-xcframework -framework "$DST" -output "$OUT/Libmihomo.xcframework"
find "$OUT/Libmihomo.xcframework" -maxdepth 3 | sort
du -sh "$OUT/Libmihomo.xcframework"
rm -rf "$WORK"
