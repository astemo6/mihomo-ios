package mitm

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Resources downloads and caches remote scripts / map-local data / jq files.
// Downloads go through the core (so GitHub raw etc. follow the user's rules) and are cached in
// <home>/engine/cache. A stale copy is served while a refresh runs in the background.
type Resources struct {
	home string
	e    *Engine
	mu   sync.Mutex
	inf  map[string]*sync.WaitGroup
	mem  *lru[[]byte]
	// v0.19.9 (review 5 P2-7): last background refresh attempt per URL (stale refreshes at most every
	// staleRetry, so an offline device does not start a download on every run).
	tried map[string]time.Time
}

// memCacheMax / memCacheBudget: sources kept in memory (small files only, 2 MB in total).
const (
	memCacheMax    = 512 << 10
	memCacheBudget = 2 << 20
	staleRetry     = 10 * time.Minute
)

func NewResources(home string, e *Engine) *Resources {
	mem := newLRU[[]byte](12)
	mem.maxW = memCacheBudget
	return &Resources{home: home, e: e, inf: map[string]*sync.WaitGroup{}, mem: mem, tried: map[string]time.Time{}}
}

// RefreshIfStale starts a background download when the cached copy of a remote resource is older than
// maxAge seconds, at most once per staleRetry per URL.
func (r *Resources) RefreshIfStale(p string, maxAge int) {
	if !isRemote(p) || maxAge <= 0 {
		return
	}
	fi, err := os.Stat(r.cachePath(p))
	if err != nil || time.Since(fi.ModTime()) <= time.Duration(maxAge)*time.Second {
		return
	}
	r.mu.Lock()
	if t, ok := r.tried[p]; ok && time.Since(t) < staleRetry {
		r.mu.Unlock()
		return
	}
	r.tried[p] = time.Now()
	r.mu.Unlock()
	go func() { _, _ = r.fetch(p) }()
}

func isRemote(p string) bool {
	return strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://")
}

func (r *Resources) cachePath(u string) string { return CachePath(r.home, u) }

// CachePath is where a remote script / resource URL is cached (shared by the app's resource manager).
func CachePath(home, u string) string {
	h := sha1.Sum([]byte(u))
	return filepath.Join(EngineDir(home), "cache", hex.EncodeToString(h[:]))
}

// LocalPath resolves a non-URL path: absolute, file://, or relative to the scripts dir.
func (r *Resources) LocalPath(p string) string {
	p = strings.TrimPrefix(p, "file://")
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(ScriptsDir(r.home), filepath.Clean("/"+p))
}

// Get returns the content of p. maxAge (seconds) controls background refresh of remote files.
func (r *Resources) Get(p string, maxAge int) ([]byte, error) {
	if !isRemote(p) {
		return os.ReadFile(r.LocalPath(p))
	}
	if b, ok := r.mem.Get(p); ok {
		return b, nil
	}
	cp := r.cachePath(p)
	if fi, err := os.Stat(cp); err == nil {
		b, err := os.ReadFile(cp)
		if err == nil {
			if maxAge > 0 && time.Since(fi.ModTime()) > time.Duration(maxAge)*time.Second {
				r.RefreshIfStale(p, maxAge)
			}
			if len(b) < memCacheMax {
				r.mem.PutW(p, b, int64(len(b)))
			}
			return b, nil
		}
	}
	return r.fetch(p)
}

// Refresh forces a download.
func (r *Resources) Refresh(p string) ([]byte, error) {
	if !isRemote(p) {
		return os.ReadFile(r.LocalPath(p))
	}
	return r.fetch(p)
}

func (r *Resources) fetch(u string) ([]byte, error) {
	r.mu.Lock()
	if wg, ok := r.inf[u]; ok {
		r.mu.Unlock()
		wg.Wait()
		if b, err := os.ReadFile(r.cachePath(u)); err == nil {
			return b, nil
		}
		return nil, fmt.Errorf("下载失败：%s", u)
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	r.inf[u] = wg
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.inf, u)
		r.mu.Unlock()
		wg.Done()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Surge iOS/3000 Mihomo-iOS")
	resp, err := r.e.client("", false).Do(req)
	if err != nil {
		return nil, fmt.Errorf("下载 %s 失败：%w", clip(u, 80), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("下载 %s 失败：HTTP %d", clip(u, 80), resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	cp := r.cachePath(u)
	_ = os.MkdirAll(filepath.Dir(cp), 0o755)
	_ = writeAtomic(cp, b, 0o644)
	if len(b) < memCacheMax {
		r.mem.PutW(u, b, int64(len(b)))
	} else {
		r.mem.Remove(u)
	}
	r.e.scripts.Invalidate(u)
	return b, nil
}

// Prefetch downloads every remote resource referenced by rs (in background, sequentially).
func (r *Resources) Prefetch(rs *Ruleset) {
	time.Sleep(3 * time.Second)
	seen := map[string]bool{}
	for _, rule := range rs.Rules {
		var p string
		age := 86400
		switch {
		case rule.Kind == KindScript:
			p, age = rule.Script.Path, rule.Script.UpdateInterval
		case rule.Kind == KindMapLocal && rule.DataType == "file":
			p = rule.Data
		case rule.Kind == KindJQ && rule.Data != "":
			p = rule.Data
		}
		if p == "" || !isRemote(p) || seen[p] {
			continue
		}
		seen[p] = true
		if _, err := r.Get(p, age); err != nil {
			r.e.logf("warning", "[MitM] "+err.Error())
		}
	}
}
