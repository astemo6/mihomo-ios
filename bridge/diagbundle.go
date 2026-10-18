package libmihomo

// 诊断 → 导出诊断包: one zip the user shares from the device after a test. The extension keeps the
// recent core log and memory samples in small rings and dumps them to <home>/diag/; the app (which also
// links this package) collects those files plus its own state and writes the zip. Everything passes
// through the redactor (redact.go) first.

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"go.yaml.in/yaml/v3"
)

// ---------------- bounded line rings (extension) ----------------

type lineRing struct {
	mu    sync.Mutex
	max   int
	maxLn int // bytes per line
	lines []string
	seq   uint64 // lines ever added (dump only when it moved)
}

func newLineRing(max, maxLine int) *lineRing { return &lineRing{max: max, maxLn: maxLine} }

func (r *lineRing) add(s string) {
	if len(s) > r.maxLn {
		s = s[:r.maxLn] + "…"
	}
	r.mu.Lock()
	r.lines = append(r.lines, s)
	if len(r.lines) > r.max {
		// drop the oldest quarter at once so appends stay amortised O(1)
		drop := len(r.lines) - r.max + r.max/4
		r.lines = append(r.lines[:0], r.lines[drop:]...)
	}
	r.seq++
	r.mu.Unlock()
}

func (r *lineRing) snapshot() ([]string, uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...), r.seq
}

func (r *lineRing) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.lines)
}

const (
	coreLogLines   = 400 // ~400 × ≤600 B ≈ 240 KB worst case
	coreLogLineMax = 600
	memSamples     = 180 // 30 min at the 10 s MemoryGuard tick
)

var (
	coreLog    = newLineRing(coreLogLines, coreLogLineMax)
	memLog     = newLineRing(memSamples, 200)
	logOnce    sync.Once
	dumpMu     sync.Mutex
	dumpedSeq  [2]uint64
	dumpHome   string
	dumpTicker *time.Ticker
)

// diagLevel mirrors the core's log level for the capture filter (set by apply after each config).
var diagLevel atomic.Int32

func init() { diagLevel.Store(int32(log.INFO)) }

// startDiagCapture subscribes to mihomo's log once per process and flushes the rings to disk every
// 30 s when they changed, so a jetsam kill (no Stop callback) still leaves the last lines behind.
func startDiagCapture(home string) {
	dumpMu.Lock()
	dumpHome = home
	dumpMu.Unlock()
	logOnce.Do(func() {
		sub := log.Subscribe()
		go func() {
			for ev := range sub {
				if strings.HasPrefix(ev.Payload, "[Tailscale]") {
					tsObserveLog(ev.Payload)
				}
				if ev.LogLevel < log.LogLevel(diagLevel.Load()) {
					continue
				}
				coreLog.add(time.Now().Format("15:04:05.000") + " " + strings.ToUpper(ev.Type()) + " " + ev.Payload)
			}
		}()
		dumpTicker = time.NewTicker(30 * time.Second)
		go func() {
			for range dumpTicker.C {
				DumpDiagnostics()
			}
		}()
	})
}

// RecordMemorySample is called by the extension's MemoryGuard on every tick (bytes, -1 = unknown).
func RecordMemorySample(footprint, available int64) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	conns := 0
	statistic.DefaultManager.Range(func(statistic.Tracker) bool { conns++; return true })
	memLog.add(fmt.Sprintf("%s footprint %.1f MB, available %s, go heap %.1f MB, go sys %.1f MB, goroutines %d, connections %d, js runtimes %d",
		time.Now().Format("15:04:05"), float64(footprint)/(1<<20), mbOrDash(available), float64(ms.HeapAlloc)/(1<<20), float64(ms.Sys)/(1<<20),
		runtime.NumGoroutine(), conns, mitm.LiveRuntimes()))
}

func mbOrDash(v int64) string {
	if v < 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f MB", float64(v)/(1<<20))
}

func diagDir(home string) string { return filepath.Join(home, "diag") }

// DumpDiagnostics writes the core-log and memory rings to <home>/diag/ (only what changed). Called by
// the extension on the app's request, on stop / failed start, and every 30 s.
func DumpDiagnostics() {
	dumpMu.Lock()
	defer dumpMu.Unlock()
	if dumpHome == "" {
		return
	}
	dir := diagDir(dumpHome)
	_ = os.MkdirAll(dir, 0o755)
	for i, f := range []struct {
		r    *lineRing
		name string
	}{{coreLog, "core-log.txt"}, {memLog, "memory.txt"}} {
		lines, seq := f.r.snapshot()
		if seq == dumpedSeq[i] {
			continue
		}
		tmp := filepath.Join(dir, f.name+".tmp")
		if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err == nil {
			_ = os.Rename(tmp, filepath.Join(dir, f.name))
			dumpedSeq[i] = seq
		}
	}
}

// ---------------- bundle (app) ----------------

// WriteDiagnosticBundle writes a zip with everything a device test report needs, all redacted.
// homeDir = <container>/mihomo, profilePath = active profile ("" if none), appInfo = text from the app
// (versions, App Group status, VPN state, enabled settings), outPath = the zip to create.
func WriteDiagnosticBundle(homeDir, profilePath, appInfo, outPath string) error {
	files, err := diagnosticFiles(homeDir, profilePath, appInfo)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: "mihomo-diagnostics/" + n, Method: zip.Deflate, Modified: time.Now()})
		if err != nil {
			return err
		}
		if _, err := w.Write([]byte(files[n])); err != nil {
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	_ = os.MkdirAll(filepath.Dir(outPath), 0o755)
	return os.WriteFile(outPath, buf.Bytes(), 0o644)
}

// DiagnosticSummary returns the bundle as one plain text (for "复制为文本"), redacted the same way.
func DiagnosticSummary(homeDir, profilePath, appInfo string) string {
	files, err := diagnosticFiles(homeDir, profilePath, appInfo)
	if err != nil {
		return err.Error()
	}
	order := []string{"info.txt", "startup-log.txt", "last-error.txt", "modules.txt", "memory.txt", "core-log.txt"}
	var b strings.Builder
	for _, n := range order {
		if s, ok := files[n]; ok {
			fmt.Fprintf(&b, "===== %s =====\n%s\n", n, tailText(s, 12000))
		}
	}
	return b.String()
}

func tailText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…\n" + s[len(s)-n:]
}

// diagnosticFiles builds name → redacted content. The redactor first walks every config so the secrets
// it finds are scrubbed from the log files too.
func diagnosticFiles(home, profilePath, appInfo string) (map[string]string, error) {
	if home == "" {
		return nil, fmt.Errorf("没有工作目录")
	}
	container := filepath.Dir(home)
	r := newRedactor()
	out := map[string]string{}
	readS := func(p string) string { b, _ := os.ReadFile(p); return string(b) }

	// 1. configs (also teach the redactor every secret)
	effective := "（还没有成功启动过：runtime.yaml 不存在）\n"
	if b, err := os.ReadFile(filepath.Join(home, "runtime.yaml")); err == nil {
		fi, _ := os.Stat(filepath.Join(home, "runtime.yaml"))
		effective = fmt.Sprintf("# 上次启动时实际使用的配置（%s），已脱敏\n%s", fi.ModTime().Format(time.RFC3339), r.yamlText(b))
	}
	var nextRun string
	if profilePath != "" {
		if prof, err := os.ReadFile(profilePath); err != nil {
			nextRun = "读取配置失败：" + err.Error()
		} else if rt, err := buildRuntime(prof, overridesFor(home, profilePath), 0); err != nil {
			nextRun = "生成运行配置失败：" + err.Error()
		} else {
			nextRun = "# 当前配置 + 覆写在下次连接时生成的配置（不含 tun 与 MitM 注入），已脱敏\n" + r.yamlText(rt)
		}
	} else {
		nextRun = "（没有选中的配置）"
	}
	out["config-effective.yaml"] = effective
	out["config-next-start.yaml"] = nextRun
	for _, f := range []string{"overrides.json", "dns.json", "localdns.json", "group-icons.json", "rules.json", "subscriptions.json", "groups.json", "resources-state.json"} {
		if b, err := os.ReadFile(filepath.Join(home, f)); err == nil {
			out["settings/"+f] = r.jsonText(b, "")
		}
	}
	if b, err := os.ReadFile(filepath.Join(container, "profiles.json")); err == nil {
		out["settings/profiles.json"] = r.jsonText(b, "profiles")
	}
	out["modules.txt"] = r.text(modulesReport(home))
	out["geo.json"] = GeoInfo(home)
	out["resources.json"] = r.jsonText([]byte(ResourceList(home)), "")

	// 2. logs (after the configs so every secret is known)
	startup := readS(filepath.Join(container, "startup-log.txt"))
	if prev := readS(filepath.Join(container, "startup-log.prev.txt")); prev != "" {
		startup += "\n--- 上一次 ---\n" + prev
	}
	out["startup-log.txt"] = r.text(orNone(startup))
	out["last-error.txt"] = r.text(orNone(readS(filepath.Join(container, "tunnel-last-error.txt"))))
	out["core-log.txt"] = r.text(orNone(readS(filepath.Join(diagDir(home), "core-log.txt"))))
	out["memory.txt"] = r.text(orNone(readS(filepath.Join(diagDir(home), "memory.txt"))))

	// 3. app + bridge info
	info := strings.TrimSpace(appInfo) + "\n" +
		"core=" + Version() + "\n" +
		"bridge.goos=" + runtime.GOOS + "/" + runtime.GOARCH + "\n" +
		"generated=" + time.Now().Format(time.RFC3339) + "\n"
	out["info.txt"] = r.text(info)
	out["README.txt"] = "Mihomo iOS 诊断包\n\n" +
		"info.txt              App / 扩展 / 内核版本、App Group、VPN 状态\n" +
		"startup-log.txt       启动阶段日志（本次 + 上一次）\n" +
		"last-error.txt        扩展最近一次写下的错误\n" +
		"core-log.txt          内核最近日志（最多 400 行）\n" +
		"memory.txt            扩展内存采样（每 10 秒，最多 30 分钟）\n" +
		"modules.txt           模块、重写、脚本、MitM 开关与数量\n" +
		"config-effective.yaml 上次启动实际使用的配置\n" +
		"config-next-start.yaml 下次连接会使用的配置\n" +
		"settings/             覆写、DNS、自定义规则、订阅处理等设置\n\n" +
		"已脱敏：服务器地址、密码、UUID、密钥、订阅链接、令牌、公网 IP 后两段。\n"
	return out, nil
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "（暂无）\n"
	}
	return s
}

func (r *redactor) yamlText(b []byte) string {
	raw := map[string]any{}
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return "# YAML 解析失败，按文本脱敏\n" + r.text(string(b))
	}
	out, err := yaml.Marshal(r.config(raw))
	if err != nil {
		return "# 序列化失败\n"
	}
	return string(out)
}

func (r *redactor) jsonText(b []byte, section string) string {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return r.text(string(b))
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(r.value(v, "", section))
	return r.text(buf.String())
}

// modulesReport lists engine switches and every module (enabled first) with what it contributes.
func modulesReport(home string) string {
	cfg := mitm.LoadConfig(home)
	var b strings.Builder
	fmt.Fprintf(&b, "重写与脚本总开关: %v\nHTTPS 解密 (MitM): %v\nMitM 主机名(用户): %d\n用户重写: %d 条\n用户脚本: %d 条\nQUIC: %s\n",
		cfg.Enabled, cfg.MitM, len(cfg.Hostnames), len(cfg.Rules), len(cfg.Scripts), orDefault(cfg.QUIC, "mitm"))
	o := readOverrides(home)
	fmt.Fprintf(&b, "安全模式: %v\n\n", o.SafeMode)
	mods := append([]mitm.Module(nil), cfg.Modules...)
	sort.SliceStable(mods, func(i, j int) bool { return mods[i].Enabled && !mods[j].Enabled })
	fmt.Fprintf(&b, "模块 %d 个（启用 %d）\n", len(mods), countEnabled(mods))
	for _, m := range mods {
		state := "关"
		if m.Enabled {
			state = "开"
		}
		line := fmt.Sprintf("[%s] %s", state, m.Name)
		if txt, err := os.ReadFile(mitm.ModulePath(home, m.ID)); err == nil {
			sub := &mitm.Ruleset{}
			sub.ParseText(string(txt), m.Name, m.Args)
			line += fmt.Sprintf("  格式 %s · 重写/脚本 %d · 主机名 %d · 定时/事件 %d · 面板 %d · 内核规则 %d",
				orDefault(sub.Format, "?"), len(sub.Rules), len(sub.Hostnames), len(sub.Tasks), len(sub.Panels), len(sub.CoreRules))
			if len(sub.Errors) > 0 {
				line += fmt.Sprintf(" · 错误 %d：%s", len(sub.Errors), strings.Join(head(sub.Errors, 3), "；"))
			}
		} else {
			line += "  （未下载）"
		}
		b.WriteString(line + "\n")
	}
	if cfg.Enabled || cfg.MitM {
		rs := mitm.Build(home, cfg)
		fmt.Fprintf(&b, "\n合计（启用部分）: 重写/脚本 %d · 主机名 %d · 定时/事件 %d · 面板 %d · 内核规则 %d · 错误 %d\n",
			len(rs.Rules), len(rs.Hostnames), len(rs.Tasks), len(rs.Panels), len(rs.CoreRules), len(rs.Errors))
	}
	return b.String()
}

func countEnabled(ms []mitm.Module) int {
	n := 0
	for _, m := range ms {
		if m.Enabled {
			n++
		}
	}
	return n
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
