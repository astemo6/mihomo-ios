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
	TunnelMode     string `json:"tunnelMode"`     // "tun" (default, NEPacketTunnelFlow) | "proxy" (NEProxySettings only)
	MixedPort      int    `json:"mixedPort"`      // local HTTP/SOCKS port for proxy-only mode / LAN sharing
	TunMTU         int    `json:"tunMTU"`         // MTU of the packet-flow bridge (default 4064, like Hako)
	GeoMirror      string `json:"geoMirror"`      // jsdelivr (default, testingcf CDN) / fastly / github — always replaces the profile's geox-url

	GeoURLs     map[string]string `json:"geoURLs"`     // custom per-database URLs (mmdb/geoip/geosite/asn), "" = mirror default
	MergeManual bool              `json:"mergeManual"` // add the 手动节点 profile's nodes (+ group) to every profile

	DNS        *DNSOverride `json:"-"` // loaded from <home>/dns.json
	sub        *SubRules    // per-subscription node processing (subscriptions.json), set by overridesFor
	manualPath string       // <container>/profiles/manual-nodes.yaml
	home       string
}

const (
	defaultMemoryLimitMB = 36 // 3/4 of the ~50 MB NetworkExtension jetsam budget (Hako GC pacing)
	defaultTunMTU        = 4064
	defaultMixedPort     = 7890
)

func defaultOverrides() Overrides {
	return Overrides{LogLevel: "info", DNSMode: "fake-ip", Sniffer: true, ControllerPort: 9090, MemoryLimitMB: defaultMemoryLimitMB,
		TunnelMode: "tun", MixedPort: defaultMixedPort, TunMTU: defaultTunMTU}
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
	if o.MemoryLimitMB <= 0 || o.MemoryLimitMB > 45 {
		o.MemoryLimitMB = defaultMemoryLimitMB
	}
	if o.TunnelMode != "proxy" {
		o.TunnelMode = "tun"
	}
	if o.MixedPort <= 0 || o.MixedPort > 65535 || o.MixedPort == o.ControllerPort {
		o.MixedPort = defaultMixedPort
	}
	if o.TunMTU < 1280 || o.TunMTU > 9000 {
		o.TunMTU = defaultTunMTU
	}
	o.DNS = readDNSOverride(home)
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
	if o.AllowLan {
		raw["mixed-port"] = o.MixedPort
		raw["bind-address"] = "*"
	} else if o.TunnelMode == "proxy" {
		// Proxy-only mode: iOS sends HTTP/HTTPS through NEProxySettings to this local port.
		raw["mixed-port"] = o.MixedPort
		raw["bind-address"] = "127.0.0.1"
	}
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
	applyCustomRules(raw, o)
	if inject != nil {
		inject(raw)
	}
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
	debug.SetMemoryLimit(int64(limitMB) << 20)
	debug.SetGCPercent(100)
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
	stage("config read (%d bytes), building runtime", len(profile))
	inject, err := prepareEngine(home)
	if err != nil {
		log.Warnln("[MitM] %s", err.Error())
	}
	rt, err := buildRuntimeWith(profile, o, fd, inject)
	if err != nil {
		return err
	}
	_ = os.WriteFile(filepath.Join(home, "runtime.yaml"), rt, 0o644)
	stage("runtime.yaml written, parsing")
	if err := hub.Parse(rt); err != nil {
		return err
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
	stage("core start begin (fd=%d)", tunFd)
	tunnel.OnSuspend()
	done := make(chan error, 1)
	go func() {
		err := apply(homeDir, configPath, tunFd)
		if err != nil {
			stage("core apply failed: %s", err.Error())
		} else {
			stage("core apply finished: providers loaded, tunnel %s, %s", tunnel.Status().String(), memText())
			if n := applySelections(configPath); n > 0 {
				stage("restored %d saved group selection(s)", n)
			}
			startSmart(homeDir, configPath)
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
	if err := apply(curHome, configPath, curFd); err != nil {
		lastError = err.Error()
		return err
	}
	startSmart(curHome, configPath)
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
