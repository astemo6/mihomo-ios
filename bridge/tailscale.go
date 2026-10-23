package libmihomo

// v0.18 experimental Tailscale node (parity-matrix §5 #12).
//
// mihomo v1.19.32 builds the Tailscale outbound in with the with_gvisor tag the app already uses
// (adapter/outbound/tailscale.go, tsnet + gVisor netstack), so nothing new is linked; this file only
// keeps it inside the ~50 MB Network Extension budget:
//   - normalizeTailscale: every Tailscale node gets its own state dir under the core home (App Group
//     container, <group>/mihomo/tailscale/<name>), a hostname, and never a path outside the container;
//   - tsGuard wraps the outbound in the extension's config (hub.Parse option). tsnet starts lazily on the
//     first dial; before that first start the guard asks the extension for its footprint / headroom
//     (MemoryProbe) and refuses with a Chinese error when less than tsMinAvailableToStart is left, instead
//     of letting jetsam kill the VPN. While it runs, a watchdog stops tsnet again when the headroom falls
//     under tsStopBelowAvailable (connections through it then fail with the same kind of message).
//   - TailscaleStatus / MemorySnapshot report what happened (footprint before / after the start, the peak
//     since, refusals, the interactive login URL from tsnet's log) for 更多 → 诊断 → 隧道内存.
//   - The app process never starts tsnet (offline 测速 refuses Tailscale nodes in TestDelay), so the
//     state dir is only ever used by the extension.

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"context"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

// MemoryProbe is implemented by the extension (Swift): phys_footprint and os_proc_available_memory in
// bytes, -1 when unknown.
type MemoryProbe interface {
	Footprint() int64
	Available() int64
}

type probeBox struct{ p MemoryProbe }

var memProbe atomic.Value // probeBox

// SetMemoryProbe registers the extension's memory probe (nil clears it).
// v0.19.21: the MitM engine's memory gates (compile, body, script guard) read os_proc_available_memory
// from it too instead of comparing the Go heap with GOMEMLIMIT.
func SetMemoryProbe(p MemoryProbe) {
	memProbe.Store(probeBox{p})
	if p == nil {
		mitm.SetAvailableMemoryProbe(nil)
		return
	}
	mitm.SetAvailableMemoryProbe(func() int64 { return p.Available() })
}

func probeNow() (fp, avail int64, ok bool) {
	b, _ := memProbe.Load().(probeBox)
	if b.p == nil {
		return -1, -1, false
	}
	return b.p.Footprint(), b.p.Available(), true
}

const (
	tsMinAvailableToStart = 14 << 20 // tsnet + netstack + control client need roughly this much to come up
	tsStopBelowAvailable  = 5 << 20  // stop tsnet before MemoryGuard has to shed connections (3 MB)
	tsWatchInterval       = 2 * time.Second
)

// serverlessTypes are node types without server / port (overlay networks joined through a control plane).
func serverlessType(t string) bool {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "tailscale", "zerotier", "easytier":
		return true
	}
	return false
}

var tsSafeChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// tailscaleStateDir is the default state dir of a node: relative to the core home (App Group container),
// unique per node name (ASCII part + hash, so Chinese names do not collide).
func tailscaleStateDir(name string) string {
	h := sha1.Sum([]byte(name))
	base := strings.Trim(tsSafeChars.ReplaceAllString(name, "_"), "_.")
	if len(base) > 24 {
		base = base[:24]
	}
	if base == "" {
		base = "node"
	}
	return "tailscale/" + base + "-" + hex.EncodeToString(h[:4])
}

// normalizeTailscale fixes state-dir / hostname of every Tailscale node in proxies (home = core home).
func normalizeTailscale(raw map[string]any, home string) int {
	n := 0
	for _, p := range asList(raw["proxies"]) {
		m, ok := p.(map[string]any)
		if !ok || !strings.EqualFold(str(m["type"]), "tailscale") {
			continue
		}
		n++
		name := str(m["name"])
		dir := strings.TrimSpace(str(m["state-dir"]))
		switch {
		case dir == "":
			dir = tailscaleStateDir(name)
		case filepath.IsAbs(dir):
			clean := filepath.Clean(dir)
			if home == "" || !strings.HasPrefix(clean+"/", filepath.Clean(home)+"/") {
				log.Warnln("[Tailscale] %s: state-dir %s 不在 App Group 内核目录里，改用默认目录", name, dir)
				dir = tailscaleStateDir(name)
			}
		default:
			if c := filepath.Clean(dir); c == ".." || strings.HasPrefix(c, "../") {
				dir = tailscaleStateDir(name)
			}
		}
		m["state-dir"] = dir
		if strings.TrimSpace(str(m["hostname"])) == "" {
			m["hostname"] = "mihomo-ios"
		}
	}
	return n
}

// MARK: guard

type tsStatus struct {
	Nodes            int    `json:"nodes"`
	State            string `json:"state"` // idle | starting | started | refused | stopped | failed
	Node             string `json:"node,omitempty"`
	StartedAt        int64  `json:"startedAt,omitempty"`
	FootprintBefore  int64  `json:"footprintBefore,omitempty"`
	AvailableBefore  int64  `json:"availableBefore,omitempty"`
	FootprintAfter   int64  `json:"footprintAfter,omitempty"`
	StartMillis      int64  `json:"startMillis,omitempty"`
	PeakSinceStart   int64  `json:"peakSinceStart,omitempty"`
	RefusedAvailable int64  `json:"refusedAvailable,omitempty"`
	RefusedAt        int64  `json:"refusedAt,omitempty"`
	StoppedAvailable int64  `json:"stoppedAvailable,omitempty"`
	StoppedAt        int64  `json:"stoppedAt,omitempty"`
	Error            string `json:"error,omitempty"`
	AuthURL          string `json:"authURL,omitempty"`
	MinAvailable     int64  `json:"minAvailableToStart"`
	StopBelow        int64  `json:"stopBelowAvailable"`
}

var tsMu sync.Mutex
var tsCur = tsStatus{State: "idle", MinAvailable: tsMinAvailableToStart, StopBelow: tsStopBelowAvailable}

func tsUpdate(f func(s *tsStatus)) {
	tsMu.Lock()
	f(&tsCur)
	tsMu.Unlock()
}

// TailscaleStatus returns the guard's status as JSON (see tsStatus).
func TailscaleStatus() string {
	tsMu.Lock()
	b, _ := json.Marshal(tsCur)
	tsMu.Unlock()
	return string(b)
}

var tsAuthURL = regexp.MustCompile(`go to: (https?://\S+)`)

// tsObserveLog is fed every core log line starting with "[Tailscale]" (diag capture subscription).
func tsObserveLog(payload string) {
	if m := tsAuthURL.FindStringSubmatch(payload); m != nil {
		tsUpdate(func(s *tsStatus) { s.AuthURL = m[1] })
	}
}

type tsGuard struct {
	C.ProxyAdapter
	mu       sync.Mutex
	starting bool // first start allowed (tsnet runs or is coming up)
	recorded bool // footprint after the first start recorded
	stopped  bool // stopped by the watchdog (memory)
	closed   bool
	stopFree int64
}

func mb(v int64) float64 { return float64(v) / (1 << 20) }

// TailscaleRefusedError is the message of a refused first start (also used by tests).
func tailscaleRefusedError(avail int64) error {
	return fmt.Errorf("Tailscale 未启动：隧道扩展只剩 %.1f MB 可用内存（启动至少需要 %d MB，iOS 对 VPN 扩展的上限约 50 MB），继续启动可能让系统直接终止 VPN。可减少规则集 / 模块后重新连接，或在 更多 → 诊断 查看隧道内存", mb(avail), tsMinAvailableToStart>>20)
}

func tailscaleStoppedError(avail int64) error {
	return fmt.Errorf("Tailscale 已停止：隧道扩展可用内存降到 %.1f MB，为避免 VPN 被系统终止已关闭 Tailscale。重新连接后可再次使用", mb(avail))
}

func (g *tsGuard) before() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return fmt.Errorf("Tailscale 节点已关闭")
	}
	if g.stopped {
		return tailscaleStoppedError(g.stopFree)
	}
	if g.starting {
		return nil
	}
	fp, avail, ok := probeNow()
	if ok && avail >= 0 && avail < tsMinAvailableToStart {
		tsUpdate(func(s *tsStatus) {
			if s.State != "started" && s.State != "starting" {
				s.State = "refused"
			}
			s.Node = g.Name()
			s.RefusedAvailable = avail
			s.RefusedAt = time.Now().Unix()
		})
		log.Warnln("[Tailscale] %s: 可用内存 %.1f MB 低于 %d MB，未启动", g.Name(), mb(avail), tsMinAvailableToStart>>20)
		return tailscaleRefusedError(avail)
	}
	g.starting = true
	now := time.Now()
	tsUpdate(func(s *tsStatus) {
		s.State = "starting"
		s.Node = g.Name()
		s.StartedAt = now.Unix()
		s.FootprintBefore = fp
		s.AvailableBefore = avail
		s.FootprintAfter = 0
		s.PeakSinceStart = fp
		s.Error = ""
	})
	stage("tailscale %s: first use, starting tsnet (footprint %.1f MB, available %.1f MB)", g.Name(), mb(fp), mb(avail))
	go g.watch(now)
	return nil
}

func (g *tsGuard) after(err error, began time.Time) {
	g.mu.Lock()
	if g.recorded || !g.starting {
		g.mu.Unlock()
		return
	}
	g.recorded = true
	g.mu.Unlock()
	fp, _, _ := probeNow()
	ms := time.Since(began).Milliseconds()
	tsUpdate(func(s *tsStatus) {
		s.FootprintAfter = fp
		s.StartMillis = ms
		if fp > s.PeakSinceStart {
			s.PeakSinceStart = fp
		}
		if err != nil {
			s.State = "failed"
			s.Error = err.Error()
		} else {
			s.State = "started"
		}
	})
	if err != nil {
		stage("tailscale %s: first dial failed after %d ms: %s (footprint %.1f MB)", g.Name(), ms, err.Error(), mb(fp))
	} else {
		stage("tailscale %s: up after %d ms (footprint %.1f MB)", g.Name(), ms, mb(fp))
	}
}

// watch samples the footprint while tsnet runs and stops it when the extension runs out of headroom.
func (g *tsGuard) watch(began time.Time) {
	t := time.NewTicker(tsWatchInterval)
	defer t.Stop()
	for range t.C {
		g.mu.Lock()
		done := g.closed || g.stopped
		g.mu.Unlock()
		if done {
			return
		}
		fp, avail, ok := probeNow()
		if !ok {
			continue
		}
		tsUpdate(func(s *tsStatus) {
			if fp > s.PeakSinceStart {
				s.PeakSinceStart = fp
			}
		})
		if avail >= 0 && avail < tsStopBelowAvailable && time.Since(began) > 3*time.Second {
			g.stop(avail)
			return
		}
	}
}

func (g *tsGuard) stop(avail int64) {
	g.mu.Lock()
	if g.stopped || g.closed {
		g.mu.Unlock()
		return
	}
	g.stopped = true
	g.stopFree = avail
	g.mu.Unlock()
	_ = g.ProxyAdapter.Close()
	debug.FreeOSMemory()
	tsUpdate(func(s *tsStatus) {
		s.State = "stopped"
		s.StoppedAvailable = avail
		s.StoppedAt = time.Now().Unix()
	})
	fp, avail2, _ := probeNow()
	stage("tailscale %s: stopped, available memory fell to %.1f MB → now footprint %.1f MB, available %.1f MB", g.Name(), mb(avail), mb(fp), mb(avail2))
	log.Warnln("[Tailscale] %s: 可用内存不足，已停止", g.Name())
}

func (g *tsGuard) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if err := g.before(); err != nil {
		return nil, err
	}
	began := time.Now()
	c, err := g.ProxyAdapter.DialContext(ctx, metadata)
	g.after(err, began)
	return c, err
}

func (g *tsGuard) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := g.before(); err != nil {
		return nil, err
	}
	began := time.Now()
	c, err := g.ProxyAdapter.ListenPacketContext(ctx, metadata)
	g.after(err, began)
	return c, err
}

func (g *tsGuard) Close() error {
	g.mu.Lock()
	already := g.closed || g.stopped
	g.closed = true
	g.mu.Unlock()
	if already {
		return nil
	}
	return g.ProxyAdapter.Close()
}

// guardTailscale is the hub.Parse option of the extension: wraps every Tailscale outbound of cfg.
func guardTailscale(cfg *config.Config) {
	n := 0
	for _, p := range cfg.Proxies {
		ap, ok := p.(*adapter.Proxy)
		if !ok || ap.ProxyAdapter == nil || ap.Type() != C.Tailscale {
			continue
		}
		if _, done := ap.ProxyAdapter.(*tsGuard); done {
			continue
		}
		ap.ProxyAdapter = &tsGuard{ProxyAdapter: ap.ProxyAdapter}
		n++
	}
	tsUpdate(func(s *tsStatus) {
		auth := s.AuthURL
		*s = tsStatus{Nodes: n, State: "idle", MinAvailable: tsMinAvailableToStart, StopBelow: tsStopBelowAvailable, AuthURL: auth}
	})
	if n > 0 {
		stage("tailscale: %d experimental node(s), tsnet starts on first use (needs ≥ %d MB available)", n, tsMinAvailableToStart>>20)
	}
}

// MemorySnapshot is the extension's memory readout for 更多 → 诊断 (JSON): the footprint / peak /
// available bytes the extension measured, Go runtime numbers and the Tailscale guard status.
func MemorySnapshot(footprint, peak, available int64) string {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	conns := 0
	statistic.DefaultManager.Range(func(statistic.Tracker) bool { conns++; return true })
	tsMu.Lock()
	ts := tsCur
	tsMu.Unlock()
	b, _ := json.Marshal(map[string]any{
		"footprint":   footprint,
		"peak":        peak,
		"available":   available,
		"goHeap":      ms.HeapAlloc,
		"goSys":       ms.Sys,
		"goroutines":  runtime.NumGoroutine(),
		"connections": conns,
		"at":          time.Now().Unix(),
		"tailscale":   ts,
	})
	return string(b)
}
