#!/usr/bin/env python3
"""Emulator UI crawl for the Android review (CI only, test/android-emu).

Seeds a SYNTHETIC profile + module through the app's own share intent, then walks every
screen in zh/en x light/dark, saving a screenshot + uiautomator dump per screen and logcat.
Output: $OUT (default emu-out/). Nothing here is real config.
"""
import glob, html, os, re, subprocess, sys, time
import xml.etree.ElementTree as ET

PKG = os.environ.get("PKG", "io.github.astemo6.mihomo.debug")
ACT = f"{PKG}/io.github.astemo6.mihomo.ui.MainActivity"
OUT = os.environ.get("OUT", "emu-out")
RES = "app/src/main/res"
HERE = os.path.dirname(os.path.abspath(__file__))
LOG = None


def log(*a):
    s = time.strftime("%H:%M:%S ") + " ".join(str(x) for x in a)
    print(s, flush=True)
    if LOG: LOG.write(s + "\n")


def sh(cmd, timeout=60, check=False):
    r = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"{cmd}: {r.stderr.decode(errors='replace')}")
    return r.stdout.decode(errors="replace")


def adb(args, timeout=60):
    return sh(f"adb {args}", timeout)


# ---- strings ------------------------------------------------------------------------------------
def load_strings(d):
    out = {}
    for f in glob.glob(f"{RES}/{d}/strings*.xml"):
        for k, v in re.findall(r'<string name="([^"]+)"[^>]*>(.*?)</string>', open(f, encoding="utf-8").read(), re.S):
            v = html.unescape(v).replace("\\'", "'").replace('\\"', '"').replace("\\n", "\n")
            out[k] = v
    return out


ZH = load_strings("values")
EN = {**ZH, **load_strings("values-en")}
S = ZH


def L(k):
    return S.get(k, k)


# ---- ui -----------------------------------------------------------------------------------------
def _raw_dump():
    r = adb("shell uiautomator dump /sdcard/ui.xml", 40)
    if "dumped" in r:
        x = adb("exec-out cat /sdcard/ui.xml")
        try:
            return x, ET.fromstring(x)
        except ET.ParseError:
            pass
    return "", None


def dump():
    """Dump the UI; dismisses system 'isn't responding' dialogs (emulator launcher ANRs) first."""
    for _ in range(5):
        x, root = _raw_dump()
        if root is None:
            time.sleep(1.5); continue
        if "isn't responding" in x or "没有响应" in x or "無回應" in x:
            ours = PKG in x or "Mihomo" in x
            with open(os.path.join(OUT, "anomalies.txt"), "a") as f:
                titles = re.findall(r'text="([^"]*(?:responding|响应|回應)[^"]*)"', x)
                f.write(f"{PASS[0]}: system ANR dialog ours={ours} {titles}\n")
            for lab in ("Wait", "等待", "Close app", "关闭应用"):
                b = find(lab, root=root)
                if b:
                    tap_b(b); time.sleep(1.5); break
            continue
        return x, root
    return "", None


def bounds(n):
    m = re.findall(r"\d+", n.get("bounds", ""))
    if len(m) != 4: return None
    x1, y1, x2, y2 = map(int, m)
    return x1, y1, x2, y2


def find(label, exact=True, root=None, attr=("text", "content-desc")):
    if root is None:
        _, root = dump()
    if root is None: return None
    cands = []
    for n in root.iter("node"):
        for a in attr:
            v = (n.get(a) or "").strip()
            if not v: continue
            if (v == label) if exact else (label in v):
                b = bounds(n)
                if b and b[2] > b[0] and b[3] > b[1]:
                    cands.append(b)
    if not cands: return None
    # prefer the lowest on-screen candidate that is not in the status bar
    cands = [c for c in cands if c[1] > 80] or cands
    return cands[0]


def tap_b(b):
    x, y = (b[0] + b[2]) // 2, (b[1] + b[3]) // 2
    adb(f"shell input tap {x} {y}")


def tap(label, exact=True, wait=1.6, long=False):
    b = find(label, exact) or (find(label, False) if exact else None)
    if not b:
        log("  ! not found:", repr(label))
        return False
    x, y = (b[0] + b[2]) // 2, (b[1] + b[3]) // 2
    if long:
        adb(f"shell input swipe {x} {y} {x} {y} 900")
    else:
        adb(f"shell input tap {x} {y}")
    time.sleep(wait)
    return True


def back(wait=1.2):
    adb("shell input keyevent KEYCODE_BACK")
    time.sleep(wait)


W, H = 1080, 2400


def screen_size():
    global W, H
    m = re.search(r"(\d+)x(\d+)", adb("shell wm size"))
    if m: W, H = int(m.group(1)), int(m.group(2))


def scroll(down=True):
    if down:
        adb(f"shell input swipe {W//2} {int(H*0.72)} {W//2} {int(H*0.28)} 450")
    else:
        adb(f"shell input swipe {W//2} {int(H*0.3)} {W//2} {int(H*0.8)} 300")
    time.sleep(1.0)


def to_top():
    for _ in range(4): scroll(False)


SHOT_N = [0]
PASS = ["x"]


def foreground_ok():
    a = adb("shell dumpsys activity activities | grep -E 'mResumedActivity|topResumedActivity' | head -2")
    return PKG in a, a.strip()


def shot(name, also_dump=True):
    SHOT_N[0] += 1
    d = os.path.join(OUT, "shots", PASS[0])
    os.makedirs(d, exist_ok=True)
    base = os.path.join(d, f"{SHOT_N[0]:03d}_{name}")
    sh(f"adb exec-out screencap -p > '{base}.png'")
    if also_dump:
        x, _ = dump()
        if x: open(base + ".xml", "w", encoding="utf-8").write(x)
    ok, a = foreground_ok()
    if not ok:
        log(f"  !! not in app after {name}: {a}")
        with open(os.path.join(OUT, "anomalies.txt"), "a") as f:
            f.write(f"{PASS[0]}/{name}: foreground = {a}\n")
    log("  shot", base)


def launch(wait=4):
    adb(f"shell am start -W -n {ACT}", 60)
    time.sleep(wait)


def ensure_app():
    ok, _ = foreground_ok()
    if not ok:
        log("  relaunching app")
        launch()


def at_settings(root=None):
    if root is None: _, root = dump()
    return find(L("sec_data_tools"), root=root) is not None or find(L("panels_toolbar"), root=root) is not None


def at_home(root=None):
    if root is None: _, root = dump()
    return find(L("panel_nodes"), root=root) is not None and find(L("panel_logs"), root=root) is not None


def go_home():
    for _ in range(5):
        _, r = dump()
        if at_home(r): return True
        back()
    ensure_app()
    return at_home()


def go_settings():
    _, r = dump()
    if at_settings(r): to_top(); return True
    go_home()
    tap(L("settings"), wait=2)
    return at_settings()


def find_scrolling(label, tries=5):
    to_top()
    for i in range(tries):
        b = find(label)
        if b and b[3] < H - 150: return b
        scroll(True)
    return None


# ---- seeding ------------------------------------------------------------------------------------
def share_text(path):
    adb(f"push {path} /data/local/tmp/seed.txt")
    adb(f"shell 'am start -n {ACT} -a android.intent.action.SEND -t text/plain --es android.intent.extra.TEXT \"$(cat /data/local/tmp/seed.txt)\"'")
    time.sleep(3)


def seed():
    log("seed profile")
    share_text(os.path.join(HERE, "demo.yaml"))
    shot("import_confirm_profile")
    tap(L("import_"), wait=4)
    shot("after_import_profile")
    log("seed module")
    share_text(os.path.join(HERE, "demo.sgmodule"))
    shot("import_confirm_module")
    tap(L("import_"), wait=4)
    shot("after_import_module")


# ---- passes -------------------------------------------------------------------------------------
def set_locale(loc):
    """Switch through 设置 › 语言 (exercises the in-app picker); falls back to `cmd locale`."""
    global S
    target = ZH if loc == "zh" else EN
    if S is target and at_lang(target): return
    if go_settings():
        b = find_scrolling(L("language"))
        if b:
            tap_b(b); time.sleep(1.5)
            shot("language_dialog")
            tap("简体中文" if loc == "zh" else "English", wait=4)
    S = target
    if not at_lang(target):
        out = adb(f"shell cmd locale set-app-locales {PKG} --user 0 --locales {'zh-CN' if loc == 'zh' else 'en-US'}")
        log("  cmd locale:", out.strip()); time.sleep(4)
    log("  locale now", loc, "ok" if at_lang(target) else "NOT APPLIED")


def at_lang(t):
    _, r = dump()
    return r is not None and (find(t["settings"], root=r) is not None or find(t["panel_nodes"], root=r) is not None
                              or find(t["sec_data_tools"], root=r) is not None)


def set_dark(dark):
    adb(f"shell cmd uimode night {'yes' if dark else 'no'}")
    time.sleep(3)


def home_pass(prefix=""):
    go_home(); to_top()
    shot(prefix + "home_nodes")
    # expand the first custom group card + PROXY resource card
    for g in ("Streaming", "PROXY"):
        if tap(g, wait=1.5):
            shot(prefix + f"home_nodes_expand_{g}")
            scroll(True); shot(prefix + f"home_nodes_expand_{g}_scrolled")
            to_top()
    for k in ("panel_activity", "panel_rules", "panel_rewrite", "panel_logs"):
        to_top()
        if tap(L(k), wait=2):
            shot(prefix + "home_" + k)
            scroll(True); shot(prefix + "home_" + k + "_scrolled")
    to_top(); tap(L("panel_nodes"))


def toolbar_pass():
    go_home()
    if tap(L("tb_search"), wait=1.5):
        adb("shell input text HK"); time.sleep(1.5)
        shot("toolbar_search_HK")
        back(); back(0.8)
        tap(L("cancel"))
    go_home()
    if tap(L("tb_stats")): shot("toolbar_stats_dialog"); back()
    if tap(L("tb_add"), wait=2): shot("toolbar_add_sheet"); back()
    if tap(L("settings"), long=True, wait=2): shot("mode_sheet_longpress_windmill"); back()
    if tap(L("tb_search"), long=True, wait=1.5):
        shot("toolbar_edit_mode")
        tap(L("done"))
    if tap(L("tb_requests"), wait=1.5): shot("toolbar_requests"); to_top(); tap(L("panel_nodes"))


SETTINGS_ITEMS = [
    # key, extra taps inside (labels or string keys prefixed with @)
    ("sec_rewrite", ["Demo Module", "@add"]),
    ("sec_mitm", []),
    ("sec_profiles", ["@add_profile"]),
    ("dns", []),
    ("scripts", ["@e2_new_script", "@e2_workbench"]),
    ("f2_rulesets", ["@f2_add"]),
    ("f2_dnslog", []),
    ("f2_traffic", []),
    ("f2_nodesubs", ["@f2_add"]),
    ("f2_groups", ["Streaming", "@f2_add"]),
    ("f2_manualnodes", ["@f2_add"]),
    ("f2_diagnostics", []),
    ("panels_toolbar", []),
    ("connection", []),
    ("per_app", []),
    ("a3_net_title", []),
    ("a3_lan_title", []),
    ("a3_system", []),
    ("appearance", None),   # dialogs
    ("language", None),
    ("about", None),
]


def settings_pass(items=SETTINGS_ITEMS):
    if not go_settings():
        log("  ! could not reach settings"); return
    shot("settings_top"); scroll(True); shot("settings_mid"); scroll(True); shot("settings_bottom")
    for key, extras in items:
        if not go_settings(): continue
        label = L(key)
        b = find_scrolling(label)
        if not b:
            log("  ! settings item not found", key, repr(label)); continue
        tap_b(b); time.sleep(2.2)
        shot("set_" + key)
        if extras is None:
            back(); continue
        x1, _ = dump()
        scroll(True)
        x2, _ = dump()
        if x1 != x2: shot("set_" + key + "_scrolled")
        to_top()
        for e in extras:
            lab = L(e[1:]) if e.startswith("@") else e
            if tap(lab, wait=2):
                shot("set_" + key + "__" + re.sub(r"\W+", "_", e.strip("@")))
                back()
                _, r = dump()
                if at_settings(r): break
        back()


def connect():
    log("connect VPN")
    go_home(); to_top()
    _, r = dump()
    sw = None
    for n in r.iter("node") if r is not None else []:
        if n.get("checkable") == "true":
            sw = bounds(n); break
    if not sw:
        log("  ! switch not found"); return False
    tap_b(sw); time.sleep(3)
    shot("vpn_consent_dialog")
    b = find("android:id/button1", attr=("resource-id",)) or find("OK") or find("确定")
    if b:
        tap_b(b); time.sleep(8)
    else:
        log("  ! no consent dialog; trying appops")
    shot("after_connect")
    time.sleep(6)
    shot("after_connect_12s")
    st = adb("shell dumpsys connectivity | grep -i -E 'VPN|tun' | head -20")
    open(os.path.join(OUT, "vpn_state.txt"), "a").write(st + "\n")
    return True


def main():
    global LOG
    os.makedirs(OUT, exist_ok=True)
    LOG = open(os.path.join(OUT, "crawl.log"), "a", buffering=1)
    screen_size()
    adb("logcat -c")
    adb(f"shell pm grant {PKG} android.permission.POST_NOTIFICATIONS")
    adb("shell settings put global window_animation_scale 0")
    adb("shell settings put global transition_animation_scale 0")
    adb("shell settings put global animator_duration_scale 0")

    for l in ("com.google.android.apps.nexuslauncher", "com.android.launcher3"):
        log("disable", l, adb(f"shell pm disable-user --user 0 {l}").strip())
    time.sleep(2)

    global S
    PASS[0] = "0_firstrun_en_light"
    S = EN
    set_dark(False)
    launch(6)
    shot("first_launch_empty")
    seed()
    home_pass()
    set_locale("zh")

    PASS[0] = "1_zh_light_offline"
    toolbar_pass()
    settings_pass()

    PASS[0] = "2_zh_light_connected"
    connect()
    home_pass()
    tap(L("tb_search"))  # nothing
    go_home()
    tap(L("panel_nodes")); to_top()
    # latency test: tap first visible "测速"-like control is icon-only; tap Auto group header icon area skipped
    settings_pass([("f2_traffic", []), ("f2_dnslog", []), ("f2_diagnostics", []), ("sec_mitm", [])])

    for loc, dark, name in (("zh", True, "3_zh_dark"), ("en", False, "4_en_light"), ("en", True, "5_en_dark")):
        PASS[0] = name
        set_locale(loc); set_dark(dark)
        ensure_app(); go_home()
        home_pass()
        toolbar_pass()
        settings_pass()

    sh(f"adb logcat -d -b all -v threadtime > {OUT}/logcat_all.txt", 120)
    sh(f"adb logcat -d -b crash -v threadtime > {OUT}/logcat_crash.txt", 60)
    sh(f"adb shell dumpsys activity processes > {OUT}/dumpsys_processes.txt", 60)
    sh(f"adb shell ls -la /data/anr/ > {OUT}/anr_ls.txt 2>&1", 30)
    log("done")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log("FATAL", repr(e))
        sh(f"adb logcat -d -b all -v threadtime > {OUT}/logcat_all.txt", 120)
        sys.exit(0)  # keep artifacts
