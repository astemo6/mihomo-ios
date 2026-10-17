// Package libmihomo is the thin gomobile bridge between the iOS app / PacketTunnel
// extension and the mihomo core (github.com/metacubex/mihomo, GPL-3.0).
//
// Exported API is intentionally tiny and uses only gomobile-friendly types.
package libmihomo

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"

	"go.yaml.in/yaml/v3"
)

// CoreVersion is overridden at build time via -ldflags -X.
var CoreVersion = "unknown"

var (
	mu        sync.Mutex
	running   bool
	curFd     int32
	curHome   string
	gcStop    chan struct{}
	lastError string
)

// Overrides mirrors the JSON the Swift side writes to <home>/overrides.json.
type Overrides struct {
	LogLevel       string `json:"logLevel"`       // silent/error/warning/info/debug
	IPv6           bool   `json:"ipv6"`           // enable IPv6 in core + DNS
	AllowLan       bool   `json:"allowLan"`       // default false
	DNSMode        string `json:"dnsMode"`        // fake-ip | redir-host
	Sniffer        bool   `json:"sniffer"`        // enable sniffer
	ControllerPort int    `json:"controllerPort"` // 127.0.0.1:<port>
	Secret         string `json:"secret"`         // controller secret
	Mode           string `json:"mode"`           // rule/global/direct ("" = keep profile)
	MemoryLimitMB  int    `json:"memoryLimitMB"`  // soft limit for Go runtime (GOMEMLIMIT)
	TunnelMode     string `json:"tunnelMode"`     // "tun" (default, NEPacketTunnelFlow) | "mix" (tun + system HTTP proxy) | "proxy" (NEProxySettings only)
	MixedPort      int    `json:"mixedPort"`      // local HTTP/SOCKS port for proxy-only mode / LAN sharing
	TunMTU         int    `json:"tunMTU"`         // MTU of the packet-flow bridge (default 4064, like Hako)
	GeoMirror      string `json:"geoMirror"`      // jsdelivr (default, testingcf CDN) / fastly / github — always replaces the profile's geox-url

	GeoURLs     map[string]string `json:"geoURLs"`     // custom per-database URLs (mmdb/geoip/geosite/asn), "" = mirror default
	MergeManual bool              `json:"mergeManual"` // add the 手动节点 profile's nodes (+ group) to every profile
	// SafeMode (set by the app for one connection after a failed start): the profile with our core
	// overrides only — no modules, rewrite, scripts, MitM, custom rules or smart groups.
	SafeMode bool `json:"safeMode"`

	// Latency test (v0.6.1): URL used for manual 测速 (app side) and, when OverrideHealthCheck is on,
	// for every group / provider health check of the profile.
	TestURL             string `json:"testURL"`
	TestTimeoutMs       int    `json:"testTimeoutMs"`
	OverrideHealthCheck bool   `json:"overrideHealthCheck"`

	// v0.7 连接方式: 阻止 QUIC — "off" | "nondirect" (default, the v0.6.1 UDP 443 fallback REJECT) | "always".
	BlockQUIC string `json:"blockQUIC"`
	// v0.7 局域网共享: optional username / password for the mixed port, and LAN-only source addresses.
	LanAuth      LanAuth `json:"lanAuth"`
	LanLocalOnly bool    `json:"lanLocalOnly"`

	DNS        *DNSOverride      `json:"-"` // loaded from <home>/dns.json
	Local      *LocalDNS         `json:"-"` // loaded from <home>/localdns.json (hosts + 真实 IP 域名)
	sub        *SubRules         // per-subscription node processing (subscriptions.json), set by overridesFor
	chains     map[string]string // group → 前置代理 (groups.json), set by overridesFor
	manualPath string            // <container>/profiles/manual-nodes.yaml
	home       string
}

const (
	// GOMEMLIMIT. v0.6.1: 26 MB (was 36). The first device test sat at 38–40 MB footprint with a 40 MB
	// limit: Go's heap plus runtime overhead, gVisor buffers and Swift leave too little headroom below the
	// ~50 MB jetsam line. Accepted range 20–30 MB; anything else falls back to the default.
	defaultMemoryLimitMB = 26
	maxMemoryLimitMB     = 30
	minMemoryLimitMB     = 20
	defaultTestURL       = "https://www.gstatic.com/generate_204"
	defaultTunMTU        = 4064
	defaultMixedPort     = 7890
)

// LanAuth protects the shared mixed port (mihomo `authentication`). Both fields empty = no auth.
type LanAuth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// lanPrivatePrefixes = 仅允许局域网: RFC 1918, link-local, CGNAT-free hotspot ranges, ULA and loopback
// (loopback so proxy-only / 混合 mode keeps working on the same port).
var lanPrivatePrefixes = []any{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128"}

var loopbackPrefixes = []any{"127.0.0.0/8", "::1/128"}

func defaultOverrides() Overrides {
	return Overrides{LogLevel: "info", DNSMode: "fake-ip", Sniffer: true, ControllerPort: 9090, MemoryLimitMB: defaultMemoryLimitMB,
		TunnelMode: "tun", MixedPort: defaultMixedPort, TunMTU: defaultTunMTU, BlockQUIC: "nondirect", LanLocalOnly: true}
}

func readOverrides(home string) Overrides {
	o := defaultOverrides()
	b, err := os.ReadFile(filepath.Join(home, "overrides.json"))
	if err == nil {
		_ = json.Unmarshal(b, &o)
	}
	if o.ControllerPort <= 0 || o.ControllerPort > 65535 {
		o.ControllerPort = 9090
	}
	if o.DNSMode != "redir-host" {
		o.DNSMode = "fake-ip"
	}
	if o.MemoryLimitMB < minMemoryLimitMB || o.MemoryLimitMB > maxMemoryLimitMB {
		o.MemoryLimitMB = defaultMemoryLimitMB
	}
	if !validTestURL(o.TestURL) {
		o.TestURL = defaultTestURL
	}
	if o.TestTimeoutMs < 1000 || o.TestTimeoutMs > 30000 {
		o.TestTimeoutMs = 5000
	}
	if o.TunnelMode != "proxy" && o.TunnelMode != "mix" {
		o.TunnelMode = "tun"
	}
	if o.BlockQUIC != "off" && o.BlockQUIC != "always" {
		o.BlockQUIC = "nondirect"
	}
	o.LanAuth.Username = strings.TrimSpace(o.LanAuth.Username)
	if o.MixedPort <= 0 || o.MixedPort > 65535 || o.MixedPort == o.ControllerPort {
		o.MixedPort = defaultMixedPort
	}
	if o.TunMTU < 1280 || o.TunMTU > 9000 {
		o.TunMTU = defaultTunMTU
	}
	o.DNS = readDNSOverride(home)
	o.Local = readLocalDNS(home)
	o.home = home
	if home != "" {
		o.manualPath = filepath.Join(filepath.Dir(home), "profiles", "manual-nodes.yaml")
	}
	return o
}

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

// BuildRuntimeConfig merges the user's profile with app overrides and the tun fd.
// Exposed for debugging / previews ("" fd => no tun section, useful for validation).
func buildRuntime(profile []byte, o Overrides, fd int32) ([]byte, error) {
	return buildRuntimeWith(profile, o, fd, nil)
}

func buildRuntimeWith(profile []byte, o Overrides, fd int32, inject func(raw map[string]any)) ([]byte, error) {
	raw := map[string]any{}
	if err := yaml.Unmarshal(profile, &raw); err != nil {
		return nil, fmt.Errorf("YAML 解析失败: %w", err)
	}
	if raw == nil {
		raw = map[string]any{}
	}
	// Plain share-link / base64 subscription => convert.
	if _, ok := raw["proxies"]; !ok {
		if _, ok2 := raw["proxy-providers"]; !ok2 {
			if conv, err := convertLinks(profile); err == nil {
				raw = map[string]any{}
				_ = yaml.Unmarshal(conv, &raw)
			}
		}
	}

	if o.sub != nil {
		for _, e := range applySubRules(raw, o.sub) {
			log.Warnln("[Subscription] %s", e)
		}
	}
	if o.MergeManual && o.manualPath != "" {
		mergeManualNodes(raw, o.manualPath)
	}
	if o.SafeMode {
		applyChains(raw, nil)
	} else {
		applyChains(raw, o.chains)
	}
	if o.LogLevel != "" {
		raw["log-level"] = o.LogLevel
	}
	if o.Mode != "" {
		raw["mode"] = o.Mode
	}
	raw["ipv6"] = o.IPv6
	raw["allow-lan"] = o.AllowLan
	raw["external-controller"] = fmt.Sprintf("127.0.0.1:%d", o.ControllerPort)
	raw["secret"] = o.Secret
	delete(raw, "external-controller-tls")
	delete(raw, "external-controller-unix")
	delete(raw, "external-ui")
	raw["find-process-mode"] = "off"
	raw["unified-delay"] = true
	raw["geo-auto-update"] = false
	raw["geodata-loader"] = "memconservative"
	// Bundled geoip.metadb / GeoSite.dat / ASN.mmdb are copied into home before start, so the core
	// never needs to download them at startup. mmdb mode (not GeoIP.dat) matches the bundled files.
	raw["geodata-mode"] = false
	raw["geox-url"] = geoxFor(o)
	rewriteProviderURLs(raw)
	// No inbound listeners on iOS except tun.
	for _, k := range []string{"port", "socks-port", "redir-port", "tproxy-port", "mixed-port"} {
		delete(raw, k)
	}
	applyInbound(raw, o)
	// Battery: fewer TCP keep-alive wake-ups unless the profile chose its own values.
	if _, ok := raw["keep-alive-interval"]; !ok {
		raw["keep-alive-interval"] = 30
	}
	if _, ok := raw["keep-alive-idle"]; !ok {
		raw["keep-alive-idle"] = 300
	}
	delete(raw, "iptables")
	delete(raw, "interface-name")
	delete(raw, "routing-mark")

	profileCfg := asMap(raw["profile"])
	profileCfg["store-selected"] = true
	profileCfg["store-fake-ip"] = false
	raw["profile"] = profileCfg

	// DNS
	dns := asMap(raw["dns"])
	dns["enable"] = true
	dns["ipv6"] = o.IPv6
	dns["listen"] = "" // the core hijacks DNS via tun dns-hijack
	dns["enhanced-mode"] = o.DNSMode
	if o.DNSMode == "fake-ip" {
		if _, ok := dns["fake-ip-range"]; !ok {
			dns["fake-ip-range"] = "198.18.0.1/16"
		}
		if _, ok := dns["fake-ip-filter"]; !ok {
			dns["fake-ip-filter"] = []any{"*.lan", "*.local", "localhost.ptlogin2.qq.com", "+.msftconnecttest.com", "+.msftncsi.com", "time.*.com", "+.ntp.org", "+.apple.com"}
		}
	}
	if _, ok := dns["nameserver"]; !ok {
		dns["nameserver"] = []any{"https://223.5.5.5/dns-query", "https://doh.pub/dns-query"}
	}
	if _, ok := dns["default-nameserver"]; !ok {
		dns["default-nameserver"] = []any{"223.5.5.5", "119.29.29.29"}
	}
	applyDNSOverride(dns, o.DNS, o.DNSMode)
	applyLocalDNS(raw, dns, o.Local, o.DNSMode)
	raw["dns"] = dns

	// Sniffer
	sn := asMap(raw["sniffer"])
	sn["enable"] = o.Sniffer
	if o.Sniffer {
		if _, ok := sn["sniff"]; !ok {
			sn["sniff"] = map[string]any{
				"HTTP": map[string]any{"ports": []any{80, "8080-8880"}, "override-destination": true},
				"TLS":  map[string]any{"ports": []any{443, 8443}},
				"QUIC": map[string]any{"ports": []any{443, 8443}},
			}
		}
	}
	raw["sniffer"] = sn

	// TUN — fd is the core end of the PacketFlow bridge socketpair (AF_UNIX/SOCK_DGRAM, utun framing:
	// 4-byte address family + IP packet). The Swift side moves packets with NEPacketTunnelFlow
	// readPackets / writePackets (public API), the same design as Hako-Adapter's PacketFlowBridge.
	// recvmsg_x / sendmsg_x and the utun-only socket options must stay off for a socketpair.
	if fd > 0 {
		raw["tun"] = map[string]any{
			"enable":                true,
			"stack":                 "gvisor",
			"file-descriptor":       int(fd),
			"auto-route":            false,
			"auto-detect-interface": false,
			"dns-hijack":            []any{"any:53"},
			"mtu":                   o.TunMTU,
			"recvmsgx":              false,
			"sendmsgx":              false,
			"udp-timeout":           120,
		}
		// IPv4 tun address is derived from fake-ip-range by mihomo; IPv6 must match NEIPv6Settings.
		if o.IPv6 {
			raw["tun"].(map[string]any)["inet6-address"] = []any{"fdfe:dcba:9876::1/126"}
		}
	} else {
		delete(raw, "tun")
	}
	rewriteConvertProviders(raw, o)
	if o.OverrideHealthCheck {
		overrideHealthCheckURL(raw, o.TestURL)
	}
	if !o.SafeMode {
		applyCustomRules(raw, o)
	}
	if inject != nil {
		inject(raw)
	}
	applyQUICBlock(raw, o.BlockQUIC)
	return yaml.Marshal(raw)
}

func convertLinks(buf []byte) ([]byte, error) {
	ps, errs := parseNodeText(string(buf))
	if len(ps) == 0 && len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return buildConfigFromProxies(ps)
}

func validateBytes(profile []byte) string {
	home := curHome
	if home == "" {
		home = C.Path.HomeDir()
	}
	rt, err := buildRuntime(profile, readOverrides(home), 0)
	if err != nil {
		return err.Error()
	}
	if _, err := executor.ParseWithBytes(rt); err != nil {
		return err.Error()
	}
	return ""
}

// ConvertShareLinks turns a list of ss/vmess/vless/trojan/hysteria2/tuic URIs (optionally
// base64 encoded, i.e. a v2rayN style subscription) into a minimal mihomo YAML config.
// Returns "" on failure; use LastError() for the reason.
func ConvertShareLinks(text string) string {
	b, err := convertLinks([]byte(text))
	if err != nil {
		lastError = err.Error()
		return ""
	}
	return string(b)
}

// LastError returns the last error message produced by a string-returning helper.
func LastError() string { return lastError }

// startGC applies Hako-style GC pacing for the NetworkExtension: GOMEMLIMIT at 3/4 of the jetsam budget
// with a normal GOGC, so the collector only works hard near the limit (less CPU = less battery than a
// permanently low GOGC). A slow ticker returns idle spans to the OS; the Swift MemoryGuard handles
// footprint spikes (FreeMemory / ShedConnections) using phys_footprint and memory-pressure events.
func startGC(limitMB int) {
	gogc := steadyGOGC
	if testOldPacing { // A/B measurement against v0.6.0 (tests only)
		limitMB, gogc = 40, 100
	}
	debug.SetMemoryLimit(int64(limitMB) << 20)
	debug.SetGCPercent(gogc)
	if gcStop != nil {
		return
	}
	gcStop = make(chan struct{})
	stop := gcStop
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				var ms runtime.MemStats
				runtime.ReadMemStats(&ms)
				// Lots of idle-but-retained heap: hand it back so the footprint jetsam sees stays low.
				if ms.HeapIdle-ms.HeapReleased > 4<<20 || ms.HeapAlloc > uint64(limitMB)<<20*8/10 {
					debug.FreeOSMemory()
				}
			}
		}
	}()
}

func apply(home, configPath string, fd int32) error {
	C.SetHomeDir(home)
	C.SetConfig(configPath)
	profile, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取配置失败: %w", err)
	}
	o := overridesFor(home, configPath)
	startGC(o.MemoryLimitMB)
	// Startup burst (rule / proxy providers parse concurrently): collect more eagerly and limit
	// parallelism until the config is applied, then return to steady pacing and hand memory back.
	restore := startupPacing()
	defer restore()
	stage("config read (%d bytes), building runtime", len(profile))
	var inject func(raw map[string]any)
	if o.SafeMode {
		stopEngine()
		stage("SAFE MODE: modules, rewrite, scripts, MitM, custom rules and smart groups are off")
		log.Warnln("[Bridge] 安全模式：模块、重写、脚本、MitM、自定义规则与智能选择已停用")
	} else {
		inject, err = prepareEngine(home)
		if err != nil {
			log.Warnln("[MitM] %s", err.Error())
		}
	}
	rt, err := buildRuntimeWith(profile, o, fd, inject)
	if err != nil {
		return err
	}
	_ = os.WriteFile(filepath.Join(home, "runtime.yaml"), rt, 0o644)
	stage("runtime.yaml written, parsing")
	if missing := missingGeo(home, rt); len(missing) > 0 {
		stage("geo data missing for this profile: %s (the core will try to download it)", strings.Join(missing, ", "))
	}
	if err := hub.Parse(rt); err != nil {
		return friendlyError(err)
	}
	debug.FreeOSMemory()
	return nil
}

// Start launches the core. homeDir is the App Group working dir (geo files, cache),
// configPath the selected profile YAML, tunFd the utun file descriptor (0 = no tun).
//
// It never blocks longer than startTimeout: the config is applied in a goroutine and Start returns as
// soon as the tun listener is up (tunnel status Inner/Running). Proxy / rule providers keep loading in
// the background (mihomo only forwards tun traffic once they finish; INNER traffic already flows).
func Start(homeDir, configPath string, tunFd int32) error {
	mu.Lock()
	defer mu.Unlock()
	if err := os.MkdirAll(homeDir, 0o755); err != nil {
		return err
	}
	curFd, curHome = tunFd, homeDir
	startDiagCapture(homeDir)
	stage("core start begin (fd=%d)", tunFd)
	tunnel.OnSuspend()
	safe := overridesFor(homeDir, configPath).SafeMode
	done := make(chan error, 1)
	go func() {
		err := safeApply(homeDir, configPath, tunFd)
		if err != nil {
			stage("core apply failed: %s", err.Error())
		} else {
			stage("core apply finished: providers loaded, tunnel %s, %s", tunnel.Status().String(), memText())
			if n := applySelections(configPath); n > 0 {
				stage("restored %d saved group selection(s)", n)
			}
			if !safe {
				startSmart(homeDir, configPath)
			}
		}
		done <- err
	}()
	deadline := time.NewTimer(startTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case err := <-done:
			if err != nil {
				lastError = err.Error()
				log.Errorln("[Bridge] start failed: %s", err.Error())
				DumpDiagnostics()
				return err
			}
			running = true
			stage("core start end (running), %s", memText())
			return nil
		case <-tick.C:
			if st := tunnel.Status(); st == tunnel.Inner || st == tunnel.Running {
				running = true
				stage("core start end (tun up, status %s; providers continue in background), %s", st.String(), memText())
				return nil
			}
		case <-deadline.C:
			msg := fmt.Sprintf("内核启动超时（%d 秒）：可能在下载 GeoIP/GeoSite 或规则集 / 节点集。请检查网络，或在 更多 → 诊断 查看启动日志", int(startTimeout/time.Second))
			stage("core start TIMEOUT after %s, %s", startTimeout, memText())
			DumpDiagnostics()
			lastError = msg
			return errors.New(msg)
		}
	}
}

// Reload re-reads the profile (and overrides.json) while keeping the same tun fd.
func Reload(configPath string) error {
	mu.Lock()
	defer mu.Unlock()
	if curHome == "" {
		return errors.New("core not started")
	}
	if err := safeApply(curHome, configPath, curFd); err != nil {
		lastError = err.Error()
		return err
	}
	if overridesFor(curHome, configPath).SafeMode {
		stopSmart()
	} else {
		startSmart(curHome, configPath)
	}
	return nil
}

// Stop tears the core down.
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if !running {
		return
	}
	stopEngine()
	stopSmart()
	executor.Shutdown()
	running = false
	DumpDiagnostics()
	if gcStop != nil {
		close(gcStop)
		gcStop = nil
	}
	debug.FreeOSMemory()
}

// IsRunning reports whether Start succeeded and Stop was not called.
func IsRunning() bool { return running }

// ValidateConfig parses the profile at path the same way Start would (without tun).
// Returns "" when valid, otherwise a human readable error.
func ValidateConfig(path string) string {
	profile, err := os.ReadFile(path)
	if err != nil {
		return err.Error()
	}
	home := filepath.Dir(path)
	if curHome != "" {
		home = curHome
	}
	C.SetHomeDir(home)
	rt, err := buildRuntime(profile, overridesFor(home, path), 0)
	if err != nil {
		return err.Error()
	}
	if _, err := executor.ParseWithBytes(rt); err != nil {
		return err.Error()
	}
	return ""
}

// ValidateConfigIn is ValidateConfig with an explicit home dir (geo data location).
func ValidateConfigIn(homeDir, path string) string {
	profile, err := os.ReadFile(path)
	if err != nil {
		return err.Error()
	}
	C.SetHomeDir(homeDir)
	rt, err := buildRuntime(profile, overridesFor(homeDir, path), 0)
	if err != nil {
		return err.Error()
	}
	if _, err := executor.ParseWithBytes(rt); err != nil {
		return err.Error()
	}
	return ""
}

// Version returns the mihomo core version string.
func Version() string {
	v := C.Version
	if v == "" || v == "1.10.0" {
		v = CoreVersion
	}
	return "mihomo " + strings.TrimPrefix(v, "mihomo ") + " (" + runtime.Version() + ")"
}

// FreeMemory forces a GC and returns memory to the OS (call on memory warnings / sleep).
func FreeMemory() { debug.FreeOSMemory() }

// SetMemoryLimit adjusts the Go soft memory limit in MB.
func SetMemoryLimit(mb int32) { debug.SetMemoryLimit(int64(mb) << 20) }
