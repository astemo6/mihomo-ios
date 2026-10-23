package libmihomo

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/astemo6/mihomo-ios/bridge/mitm"
	"github.com/metacubex/mihomo/tunnel/statistic"
	"go.yaml.in/yaml/v3"
)

// v0.19.22 memory plateau (device log 2026-10-23): see memshed.go.

type memFakeProbe struct{ fp, avail atomic.Int64 }

func (f *memFakeProbe) Footprint() int64 { return f.fp.Load() }
func (f *memFakeProbe) Available() int64 { return f.avail.Load() }

func withMemProbe(t *testing.T, fp, avail int64) *memFakeProbe {
	t.Helper()
	p := &memFakeProbe{}
	p.fp.Store(fp)
	p.avail.Store(avail)
	SetMemoryProbe(p)
	t.Cleanup(func() { SetMemoryProbe(nil) })
	return p
}

func resetShedState() {
	shedState.Lock()
	shedState.last, shedState.backoff, shedState.lastFP = time.Time{}, 0, 0
	shedState.Unlock()
}

func runtimeDNS(t *testing.T, profile string) map[string]any {
	t.Helper()
	home := t.TempDir()
	rt, err := buildRuntime([]byte(profile), Overrides{home: home, ControllerPort: 19098, Secret: "x", DNSMode: "redir-host"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(rt, &raw); err != nil {
		if err := json.Unmarshal(rt, &raw); err != nil {
			t.Fatal(err)
		}
	}
	return asMap(raw["dns"])
}

// The DNS answer caches (4096 parsed messages per resolver by default, stale entries kept) are capped.
func TestV01922DNSCacheCapped(t *testing.T) {
	base := "proxies:\n  - {name: a, type: ss, server: 127.0.0.1, port: 1, cipher: aes-128-gcm, password: x}\nrules:\n  - MATCH,DIRECT\n"
	if got := intOf(runtimeDNS(t, base)["cache-max-size"]); got != iosDNSCacheMax {
		t.Fatalf("default cache-max-size %d, want %d", got, iosDNSCacheMax)
	}
	if got := intOf(runtimeDNS(t, base+"dns:\n  cache-max-size: 300\n")["cache-max-size"]); got != 300 {
		t.Fatalf("profile's smaller cache-max-size not kept: %d", got)
	}
	if got := intOf(runtimeDNS(t, base+"dns:\n  cache-max-size: 8192\n")["cache-max-size"]); got != iosDNSCacheMax {
		t.Fatalf("profile's 8192 not capped: %d", got)
	}
}

// ShedMemory backs off while a shed frees nothing (the guard called FreeMemory every 3 s for two hours),
// and sheds again at once when the footprint grew.
func TestV01922ShedBackoff(t *testing.T) {
	SetStageLog(filepath.Join(t.TempDir(), "s.log"), 0)
	defer SetStageLog("", 0)
	p := withMemProbe(t, 40<<20, 10<<20)
	resetShedState()
	defer resetShedState()
	if ShedMemory(1, "test") == "" {
		t.Fatal("first shed skipped")
	}
	if ShedMemory(1, "test") != "" {
		t.Fatal("second shed within 3 s ran")
	}
	shedState.Lock()
	b := shedState.backoff
	shedState.last = time.Now().Add(-shedMinGap - b - time.Millisecond)
	shedState.Unlock()
	if b == 0 {
		t.Fatal("a shed that freed nothing did not back off")
	}
	if ShedMemory(1, "test") == "" {
		t.Fatal("shed after the back-off skipped")
	}
	shedState.Lock()
	b2 := shedState.backoff
	shedState.Unlock()
	if b2 <= b {
		t.Fatalf("back-off did not grow: %v → %v", b, b2)
	}
	p.fp.Store(43 << 20) // grew by 3 MB: shed at once despite the back-off
	if ShedMemory(1, "test") == "" {
		t.Fatal("shed skipped although the footprint grew by 3 MB")
	}
}

// Critical level (or < 8 MB available) clears the DNS caches; the line says what was freed.
func TestV01922ShedCriticalClearsDNSAndLogs(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "s.log")
	SetStageLog(logPath, 0)
	defer SetStageLog("", 0)
	withMemProbe(t, 40<<20, 7<<20) // < memCriticalAvail: raised to critical
	resetShedState()
	defer resetShedState()
	var cleared atomic.Bool
	testHookShedDNS = func() { cleared.Store(true) }
	defer func() { testHookShedDNS = nil }()
	line := ShedMemory(1, "memory pressure warning")
	if !cleared.Load() || !strings.Contains(line, "memory shed L2") || !strings.Contains(line, "DNS caches cleared") {
		t.Fatalf("critical shed: cleared=%v line %q", cleared.Load(), line)
	}
	if !stageLogHas(logPath, "footprint 40.0 MB") {
		b, _ := os.ReadFile(logPath)
		t.Fatalf("shed line missing from the startup log:\n%s", b)
	}
	// a system-wide critical event while the extension still has 20 MB: light shed, DNS caches stay
	withMemProbe(t, 29<<20, 20<<20)
	resetShedState()
	cleared.Store(false)
	if line := ShedMemory(2, "memory pressure critical"); !strings.Contains(line, "memory shed L1") || cleared.Load() {
		t.Fatalf("calm critical: cleared=%v line %q", cleared.Load(), line)
	}
}

// The governor lowers GOMEMLIMIT above the footprint target, never below live heap + headroom, leaves it
// alone during a script loan, and restores the configured limit once the footprint is back down.
func TestV01922GovernLimit(t *testing.T) {
	old := debug.SetMemoryLimit(-1)
	defer func() { debug.SetMemoryLimit(old); setConfiguredLimit(old) }()
	debug.SetMemoryLimit(26 << 20)
	setConfiguredLimit(26 << 20)
	v := governLimit(40<<20, 8<<20)
	if v != 26<<20-(4<<20)-(1<<20) {
		t.Fatalf("first step %d MB, want 21", v>>20)
	}
	v2 := governLimit(40<<20, 8<<20)
	if v2 >= v || v2 < memGovernFloor {
		t.Fatalf("second step %d MB (first %d)", v2>>20, v>>20)
	}
	for i := 0; i < 10; i++ {
		governLimit(45<<20, 8<<20)
	}
	if cur := debug.SetMemoryLimit(-1); cur != memGovernFloor {
		t.Fatalf("floor: %d MB", cur>>20)
	}
	// live heap 14 MB: never below 20 MB
	debug.SetMemoryLimit(26 << 20)
	setConfiguredLimit(26 << 20)
	for i := 0; i < 10; i++ {
		governLimit(45<<20, 14<<20)
	}
	if cur := debug.SetMemoryLimit(-1); cur != 20<<20 {
		t.Fatalf("live-heap floor: %d MB, want 20", cur>>20)
	}
	if governLimit(30<<20, 14<<20) != 26<<20 || debug.SetMemoryLimit(-1) != 26<<20 {
		t.Fatalf("not restored at 30 MB: %d", debug.SetMemoryLimit(-1)>>20)
	}
	// someone else (内存上限) changed the limit: hands off
	governLimit(40<<20, 8<<20)
	debug.SetMemoryLimit(30 << 20)
	if governLimit(45<<20, 8<<20) != 0 || debug.SetMemoryLimit(-1) != 30<<20 {
		t.Fatal("governor overrode a limit it did not set")
	}
}

// Idle connections (no bytes for the given age) are found and closed; active ones stay.
func TestV01922IdleConnections(t *testing.T) {
	home := t.TempDir()
	ov := defaultOverrides()
	ov.ControllerPort = 19522
	ov.Secret = "s"
	ob, _ := json.Marshal(ov)
	_ = os.WriteFile(filepath.Join(home, "overrides.json"), ob, 0o644)
	SetStageLog(filepath.Join(home, "startup.log"), 0)
	defer SetStageLog("", 0)
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		for {
			c, err := up.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 64)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					c.Write(buf[:n])
				}
			}()
		}
	}()
	pl, _ := net.Listen("tcp", "127.0.0.1:0")
	port := pl.Addr().(*net.TCPAddr).Port
	pl.Close()
	prof := filepath.Join(home, "p.yaml")
	_ = os.WriteFile(prof, []byte(fmt.Sprintf(`listeners:
  - {name: m, type: mixed, port: %d, listen: 127.0.0.1}
proxies:
  - {name: demo, type: ss, server: 127.0.0.1, port: 1, cipher: aes-128-gcm, password: x}
rules:
  - MATCH,DIRECT
`, port)), 0o644)
	if err := Start(home, prof, 0); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	dial := func() net.Conn {
		var c net.Conn
		var err error
		for i := 0; i < 50; i++ {
			if c, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", up.Addr(), up.Addr())
		br := bufio.NewReader(c)
		line, _ := br.ReadString('\n')
		if !strings.Contains(line, "200") {
			t.Fatalf("CONNECT: %q", line)
		}
		for {
			l, _ := br.ReadString('\n')
			if l == "\r\n" || l == "" {
				break
			}
		}
		c.Write([]byte("hi"))
		buf := make([]byte, 2)
		_, _ = c.Read(buf)
		return c
	}
	idle, active := dial(), dial()
	defer idle.Close()
	defer active.Close()
	trackConnActivity(time.Now(), time.Hour) // first sample
	stop := make(chan struct{})
	go func() {
		buf := make([]byte, 2)
		for {
			select {
			case <-stop:
				return
			case <-time.After(30 * time.Millisecond):
				active.Write([]byte("hi"))
				_, _ = active.Read(buf)
			}
		}
	}()
	defer close(stop)
	upPort := uint16(up.Addr().(*net.TCPAddr).Port)
	ours := func(ts []statistic.Tracker) (n int) {
		for _, c := range ts {
			if c.Info().Metadata.DstPort == upPort {
				n++
			}
		}
		return
	}
	// other tests in this process may leave connections of their own behind: count only ours
	deadline := time.Now().Add(3 * time.Second)
	var n int
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		total, idles := trackConnActivity(time.Now(), 400*time.Millisecond)
		if total < 2 {
			t.Fatalf("connections tracked %d", total)
		}
		if n = ours(idles); n > 0 {
			break
		}
	}
	if n != 1 {
		t.Fatalf("idle connections of ours %d, want 1", n)
	}
	if closed := closeIdleConnections(400 * time.Millisecond); closed < 1 {
		t.Fatalf("closed %d, want ≥ 1", closed)
	}
	idle.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := idle.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle connection still open")
	}
	active.SetDeadline(time.Now().Add(time.Second))
	if _, err := active.Write([]byte("hi")); err != nil {
		t.Fatalf("active connection closed: %v", err)
	}
}

func settledMem() (uint64, int) {
	for i := 0; i < 3; i++ {
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc, runtime.NumGoroutine()
}

// Repeated reloads of a profile with file / http rule providers, a proxy provider and a missing file
// provider: no goroutine growth (the fswatch leak), the heap returns to its level, and every reload logs
// its footprint.
func TestV01922ReloadsDoNotRatchet(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	home := t.TempDir()
	ov := defaultOverrides()
	ov.ControllerPort = 19523
	ov.Secret = "s"
	ob, _ := json.Marshal(ov)
	_ = os.WriteFile(filepath.Join(home, "overrides.json"), ob, 0o644)
	logPath := filepath.Join(home, "startup.log")
	SetStageLog(logPath, 0)
	defer SetStageLog("", 0)
	_ = os.MkdirAll(filepath.Join(home, "rules"), 0o755)
	for p := 0; p < 10; p++ {
		var b strings.Builder
		b.WriteString("payload:\n")
		for i := 0; i < 2000; i++ {
			fmt.Fprintf(&b, "  - '+.r%d-%d.example.org'\n", p, i)
		}
		_ = os.WriteFile(filepath.Join(home, "rules", fmt.Sprintf("rp%04d.yaml", p)), []byte(b.String()), 0o644)
	}
	body := string(genYAMLProfile(200, 2000, 5, 10))
	body = strings.Replace(body, "rule-providers:\n", "rule-providers:\n  gone: {type: file, behavior: domain, path: ./missing-dir/gone.yaml}\n", 1)
	body = strings.Replace(body, "rules:\n", "rules:\n  - RULE-SET,gone,DIRECT\n", 1)
	// MATCH,DIRECT: the core keeps its last rules after Stop, and later tests download geo data through
	// them (MATCH,Proxy would send that to the profile's unreachable nodes).
	body = strings.Replace(body, "  - MATCH,Proxy\n", "  - MATCH,DIRECT\n", 1)
	prof := writeScaleProfile(t, home, []byte(body))
	if err := Start(home, prof, 0); err != nil {
		t.Fatal(err)
	}
	defer Stop()
	time.Sleep(time.Second)
	if err := Reload(prof); err != nil { // warm-up: first reload settles lazily created state
		t.Fatal(err)
	}
	h0, g0 := settledMem()
	for i := 0; i < 5; i++ {
		if err := Reload(prof); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(300 * time.Millisecond)
	h1, g1 := settledMem()
	t.Logf("after warm-up reload: heap %.1f MB, %d goroutines; after 5 more: heap %.1f MB, %d goroutines",
		float64(h0)/(1<<20), g0, float64(h1)/(1<<20), g1)
	if g1 > g0+3 {
		t.Fatalf("goroutines grew over 5 reloads: %d → %d", g0, g1)
	}
	if h1 > h0+2<<20 {
		t.Fatalf("heap grew over 5 reloads: %.1f → %.1f MB", float64(h0)/(1<<20), float64(h1)/(1<<20))
	}
	if !stageLogHas(logPath, "reload memory: footprint") || !stageLogHas(logPath, "memory shed L1 (before reload)") {
		b, _ := os.ReadFile(logPath)
		t.Fatalf("reload memory lines missing:\n%s", b)
	}
}

// The periodic memory line: every 5 min under pressure (and once at the first sample).
func TestV01922PeriodicMemoryLine(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "s.log")
	SetStageLog(logPath, 0)
	defer SetStageLog("", 0)
	memLogState.Lock()
	memLogState.last = time.Time{}
	memLogState.Unlock()
	now := time.Now()
	memTick(40<<20, 10<<20, now)
	memTick(40<<20, 10<<20, now.Add(time.Minute))
	b, _ := os.ReadFile(logPath)
	if c := strings.Count(string(b), "memory: footprint 40.0 MB"); c != 1 {
		t.Fatalf("%d lines within a minute, want 1:\n%s", c, b)
	}
	for _, want := range []string{"go heap", "idle", "released", "stacks", "goroutines", "connections", "mitm", "GOMEMLIMIT"} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("line lacks %q:\n%s", want, b)
		}
	}
	memTick(40<<20, 10<<20, now.Add(memLogPressureEvery+time.Second))
	b, _ = os.ReadFile(logPath)
	if c := strings.Count(string(b), "memory: footprint 40.0 MB"); c != 2 {
		t.Fatalf("%d lines after 5 min under pressure, want 2", c)
	}
	_ = mitm.ShedLight
}
