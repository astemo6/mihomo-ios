package mitm

// fix/xmly-memory (v0.19.22 device report 2026-10-24): how much memory does the JavaScriptCore path add
// that GOMEMLIMIT does not see? This rig runs the real 喜马拉雅 script in JavaScriptCore (Bun's JSC with
// BUN_JSC_useJIT=0, the LLInt interpreter an app extension gets) through the real Go host and reports the
// JSC heap and Bun's RSS next to the Go numbers.
// Manual: TERN_BUN=/path/to/bun go test ./mitm -run TestXimalayaJSCFootprint -v

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

type bunJS struct {
	mu   sync.Mutex
	in   io.Writer
	out  *bufio.Reader
	runs sync.Map // id -> NativeRun
}

func startBunJS(t *testing.T) *bunJS {
	t.Helper()
	bin := os.Getenv("TERN_BUN")
	if bin == "" {
		t.Skip("set TERN_BUN to a bun binary")
	}
	cmd := exec.Command(bin, "testdata/bun_jsc_host.js")
	cmd.Env = append(os.Environ(), "BUN_JSC_useJIT=0")
	cmd.Stderr = os.Stderr
	in, _ := cmd.StdinPipe()
	outp, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close(); _ = cmd.Wait() })
	return &bunJS{in: in, out: bufio.NewReaderSize(outp, 1<<20)}
}

type bunMsg struct {
	T   string `json:"t"`
	R   any    `json:"r"`
	Op  string `json:"op"`
	Arg string `json:"arg"`
	B64 string `json:"b64"`
	ID  int64  `json:"id"`
}

// rpc sends one command and answers host callbacks until the engine returns.
func (b *bunJS) rpc(cmd map[string]any, run NativeRun) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	j, _ := json.Marshal(cmd)
	_, _ = b.in.Write(append(j, '\n'))
	reply := func(v any) {
		r, _ := json.Marshal(v)
		_, _ = b.in.Write(append(r, '\n'))
	}
	for {
		line, err := b.out.ReadBytes('\n')
		if err != nil {
			return `{"kind":"internal","message":"bun gone"}`
		}
		var m bunMsg
		if json.Unmarshal(line, &m) != nil {
			continue
		}
		switch m.T {
		case "ret":
			s, _ := m.R.(string)
			return s
		case "host":
			reply(map[string]any{"r": run.Host(m.Op, m.Arg)})
		case "put":
			d, _ := base64.StdEncoding.DecodeString(m.B64)
			reply(map[string]any{"r": run.Put(d)})
		case "take":
			reply(map[string]any{"b64": base64.StdEncoding.EncodeToString(run.Take(m.ID))})
		}
	}
}

func (b *bunJS) Prepare(prelude string) string {
	return b.rpc(map[string]any{"op": "prepare", "src": prelude}, nil)
}
func (b *bunJS) Load(key, name, source string) string {
	return b.rpc(map[string]any{"op": "load", "key": key, "name": name, "src": source}, nil)
}
func (b *bunJS) Drop(key string) { b.rpc(map[string]any{"op": "drop", "key": key}, nil) }
func (b *bunJS) Collect()        { b.rpc(map[string]any{"op": "collect"}, nil) }
func (b *bunJS) Begin(run NativeRun, key, setup string) string {
	b.runs.Store(run.ID(), run)
	return b.rpc(map[string]any{"op": "begin", "run": run.ID(), "key": key, "setup": setup}, run)
}
func (b *bunJS) Call(runID int64, fn, arg string) string {
	r, _ := b.runs.Load(runID)
	run, _ := r.(NativeRun)
	return b.rpc(map[string]any{"op": "call", "run": runID, "fn": fn, "arg": arg}, run)
}
func (b *bunJS) End(runID int64) {
	b.runs.Delete(runID)
	b.rpc(map[string]any{"op": "end", "run": runID}, nil)
}

type bunStats struct {
	RSS, HeapSize, HeapCapacity, Extra, Objects, Globals, Contexts float64
}

func (b *bunJS) stats(gc bool) bunStats {
	var s bunStats
	_ = json.Unmarshal([]byte(b.rpc(map[string]any{"op": "stats", "gc": gc}, nil)), &s)
	return s
}

func (s bunStats) String() string {
	return fmt.Sprintf("jsc heap %.1f MB (capacity %.1f, extra %.1f, %d objects, %d globals, %d script contexts), bun rss %.1f MB",
		s.HeapSize/(1<<20), s.HeapCapacity/(1<<20), s.Extra/(1<<20), int(s.Objects), int(s.Globals), int(s.Contexts), s.RSS/(1<<20))
}

func TestXimalayaJSCFootprint(t *testing.T) {
	b := startBunJS(t)
	s0 := b.stats(true)
	if msg := SetNativeEngine(b); msg != "" {
		t.Fatal(msg)
	}
	t.Cleanup(func() { SetNativeEngine(nil) })
	t.Logf("bun idle:        %s", s0)
	t.Logf("prelude context: %s", b.stats(true))
	if msg := b.Load("probe", "xmly", string(ximalayaFile(t))); msg != "" {
		t.Fatal(msg)
	}
	t.Logf("xmly loaded:     %s", b.stats(true))
	b.Drop("probe")
	t.Logf("xmly dropped:    %s", b.stats(true))
	for _, n := range []int{1, 10, 30} {
		st := xmlyBurst(t, n, 80, 10*time.Second)
		live := b.stats(false)
		after := b.stats(true)
		t.Logf("burst %2d: go %s", n, st)
		t.Logf("   jsc live:     %s", live)
		t.Logf("   jsc after GC: %s", after)
	}
}
