#!/usr/bin/env bash
# Runs inside reactivecircus/android-emulator-runner (test/android-emu only).
set -x
APK=$(ls app/build/outputs/apk/debug/*universal*.apk | head -1)
mkdir -p emu-out
adb wait-for-device
adb shell getprop ro.build.version.release
adb shell wm size
adb install -r -g "$APK" 2>&1 | tee emu-out/install.txt
timeout 2400 python3 scripts/emu/crawl.py || true
ls -R emu-out | head -50
exit 0
