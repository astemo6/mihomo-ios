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
	MemoryLimitMB  int    `json:"memoryLimitMB"`  // soft limit for Go runtime
}

func defaultOverrides() Overrides {
	return Overrides{LogLevel: "info", DNSMode: "fake-ip", Sniffer: true, ControllerPort: 9090, MemoryLimitMB: 40}
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
	if o.MemoryLimitMB <= 0 {
		o.MemoryLimitMB = 40
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
	// No inbound listeners on iOS except tun.
	for _, k := range []string{"port", "socks-port", "redir-port", "tproxy-port", "mixed-port"} {
		delete(raw, k)
	}
	if o.AllowLan {
		raw["mixed-port"] = 7890
		raw["bind-address"] = "*"
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

	// TUN — the fd comes from NEPacketTunnelProvider's utun.
	if fd > 0 {
		raw["tun"] = map[string]any{
			"enable":                true,
			"stack":                 "gvisor",
			"file-descriptor":       int(fd),
			"auto-route":            false,
			"auto-detect-interface": false,
			"dns-hijack":            []any{"any:53"},
			"mtu":                   1500,
		}
	} else {
		delete(raw, "tun")
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

func startGC(limitMB int) {
	debug.SetMemoryLimit(int64(limitMB) << 20)
	debug.SetGCPercent(10)
	if gcStop != nil {
		return
	}
	gcStop = make(chan struct{})
	stop := gcStop
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				var ms runtime.MemStats
				runtime.ReadMemStats(&ms)
				if ms.HeapAlloc > uint64(limitMB)<<20*7/10 {
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
	o := readOverrides(home)
	startGC(o.MemoryLimitMB)
	rt, err := buildRuntime(profile, o, fd)
	if err != nil {
		return err
	}
	_ = os.WriteFile(filepath.Join(home, "runtime.yaml"), rt, 0o644)
	if err := hub.Parse(rt); err != nil {
		return err
	}
	debug.FreeOSMemory()
	return nil
}

// Start launches the core. homeDir is the App Group working dir (geo files, cache),
// configPath the selected profile YAML, tunFd the utun file descriptor (0 = no tun).
func Start(homeDir, configPath string, tunFd int32) error {
	mu.Lock()
	defer mu.Unlock()
	if err := os.MkdirAll(homeDir, 0o755); err != nil {
		return err
	}
	curFd, curHome = tunFd, homeDir
	if err := apply(homeDir, configPath, tunFd); err != nil {
		lastError = err.Error()
		log.Errorln("[Bridge] start failed: %s", err.Error())
		return err
	}
	running = true
	return nil
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
	return nil
}

// Stop tears the core down.
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if !running {
		return
	}
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
	rt, err := buildRuntime(profile, readOverrides(home), 0)
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
	rt, err := buildRuntime(profile, readOverrides(homeDir), 0)
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
