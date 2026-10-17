package libmihomo

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// test/selftest: 节点管理 全部测速 runs NodeTestDelay 8 at a time from Swift task groups (one OS thread each
// through gomobile). Run with -race: before the fix lastError was a plain string written from every call.
func TestSelftestConcurrentNodeTestDelay(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	_ = os.MkdirAll(filepath.Join(home, "nodesubs"), 0o755)
	var sb strings.Builder
	sb.WriteString("proxies:\n")
	for i := 0; i < 24; i++ {
		// 127.0.0.1:1 refuses at once, so every test fails fast and writes LastError.
		fmt.Fprintf(&sb, "  - {name: n%02d, type: ss, server: 127.0.0.1, port: 1, cipher: aes-128-gcm, password: x}\n", i)
	}
	sb.WriteString("proxy-groups:\n  - {name: G, type: select, proxies: [n00, n01, DIRECT]}\nrules:\n  - MATCH,G\n")
	profile := filepath.Join(root, "p.yaml")
	if err := os.WriteFile(profile, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	resetRuntimeCache()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	results := make([]int, 24)
	stop := make(chan struct{})
	go func() { // concurrent reader, like the Swift side reading LastError after a failure
		for {
			select {
			case <-stop:
				return
			default:
				_ = LastError()
			}
		}
	}()
	start := time.Now()
	for i := 0; i < 24; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = NodeTestDelay(home, profile, fmt.Sprintf("n%02d", i), "http://127.0.0.1:1/generate_204", 800)
		}(i)
	}
	wg.Wait()
	close(stop)
	for i, r := range results {
		if r != -1 {
			t.Fatalf("n%02d: want -1 (refused), got %d", i, r)
		}
	}
	if strings.Contains(LastError(), "找不到") {
		t.Fatalf("a node was not found: %s", LastError())
	}
	t.Logf("24 offline tests, 8 at a time: %v", time.Since(start))

	// One shared runtime while the inputs are unchanged; a profile edit invalidates it.
	a := cachedRuntimeRaw(home, profile)
	b := cachedRuntimeRaw(home, profile)
	if fmt.Sprintf("%p", a) != fmt.Sprintf("%p", b) {
		t.Fatal("runtime not shared within the TTL")
	}
	time.Sleep(20 * time.Millisecond)
	_ = os.WriteFile(profile, []byte(strings.Replace(sb.String(), "n23,", "n23x,", 1)+"\n# edit\n"), 0o644)
	c := cachedRuntimeRaw(home, profile)
	if fmt.Sprintf("%p", a) == fmt.Sprintf("%p", c) {
		t.Fatal("profile edit did not invalidate the shared runtime")
	}
	// A new manual node file invalidates it too.
	_ = os.MkdirAll(filepath.Join(root, "profiles"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "profiles", "manual-nodes.yaml"), []byte("proxies: []\n"), 0o644)
	if fmt.Sprintf("%p", c) == fmt.Sprintf("%p", cachedRuntimeRaw(home, profile)) {
		t.Fatal("manual node change did not invalidate the shared runtime")
	}
}

// Concurrent TestDelay on node JSON (manual nodes not in the profile) plus the offline interface setter.
func TestSelftestConcurrentTestDelay(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%4 == 0 {
				SetOfflineTestInterface("")
			}
			b, _ := json.Marshal(map[string]any{"name": fmt.Sprintf("m%d", i), "type": "socks5", "server": "127.0.0.1", "port": 1})
			if d := TestDelay(string(b), "http://127.0.0.1:1/", 500); d != -1 {
				t.Errorf("m%d: %d", i, d)
			}
			_ = LastError()
		}(i)
	}
	wg.Wait()
}
