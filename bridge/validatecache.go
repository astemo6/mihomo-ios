package libmihomo

// B32 (review 7 checklist): editing one node of a big profile (5k nodes / 20k rules) parsed the whole runtime
// with executor.ParseWithBytes on every commit, and a second time for the unedited file whenever the edit did
// not validate; the app's ValidateConfigIn right after re-parsed the same runtime again. Parse results are now
// remembered by the exact runtime bytes (plus the home that resolves its relative paths): the previous
// commit's edited file is the next commit's original, so its re-check is a lookup, and a validate of an
// unchanged file after a commit is free. Successes are kept 10 min, failures 30 s (a failure can depend on
// files that appear later, e.g. geo data finishing its download). Bounded to a few entries (hashes only).

import (
	"crypto/sha256"
	"sync"
	"time"

	"github.com/metacubex/mihomo/hub/executor"
)

const (
	validateCacheMax = 8
	validateOKTTL    = 10 * time.Minute
	validateErrTTL   = 30 * time.Second
)

type validateEntry struct {
	err string
	at  time.Time
}

var (
	validateMu    sync.Mutex
	validateCache = map[[32]byte]validateEntry{}
	validateParse = func(rt []byte) error { _, err := executor.ParseWithBytes(rt); return err } // tests count calls
)

// parseRuntimeCached returns "" when the core accepts rt, else its error text.
func parseRuntimeCached(home string, rt []byte) string {
	h := sha256.New()
	h.Write([]byte(home))
	h.Write([]byte{0})
	h.Write(rt)
	var key [32]byte
	copy(key[:], h.Sum(nil))
	now := time.Now()
	validateMu.Lock()
	if e, ok := validateCache[key]; ok {
		ttl := validateOKTTL
		if e.err != "" {
			ttl = validateErrTTL
		}
		if now.Sub(e.at) < ttl {
			validateMu.Unlock()
			return e.err
		}
		delete(validateCache, key)
	}
	validateMu.Unlock()
	msg := ""
	if err := validateParse(rt); err != nil {
		msg = err.Error()
	}
	validateMu.Lock()
	if len(validateCache) >= validateCacheMax {
		var oldest [32]byte
		var ot time.Time
		for k, e := range validateCache {
			if ot.IsZero() || e.at.Before(ot) {
				oldest, ot = k, e.at
			}
		}
		delete(validateCache, oldest)
	}
	validateCache[key] = validateEntry{err: msg, at: now}
	validateMu.Unlock()
	return msg
}
