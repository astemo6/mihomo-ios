package mitm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Store backs $persistentStore / $prefs: a JSON map in the App Group container
// (<home>/engine/store.json) that the app can view and edit too.
type Store struct {
	mu    sync.Mutex
	path  string
	data  map[string]string
	mtime time.Time
}

func NewStore(home string) *Store {
	return &Store{path: filepath.Join(EngineDir(home), "store.json")}
}

func (s *Store) loadLocked() {
	fi, err := os.Stat(s.path)
	if err != nil {
		if s.data == nil {
			s.data = map[string]string{}
		}
		return
	}
	if s.data != nil && fi.ModTime().Equal(s.mtime) {
		return
	}
	m := map[string]string{}
	if b, err := os.ReadFile(s.path); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	s.data, s.mtime = m, fi.ModTime()
}

func (s *Store) saveLocked() error {
	_ = os.MkdirAll(filepath.Dir(s.path), 0o755)
	b, _ := json.MarshalIndent(s.data, "", " ")
	if err := writeAtomic(s.path, b, 0o644); err != nil {
		return err
	}
	if fi, err := os.Stat(s.path); err == nil {
		s.mtime = fi.ModTime()
	}
	return nil
}

// storeMaxTotal caps $persistentStore / $prefs (keys + values).
const storeMaxTotal = 8 << 20

// storeMaxValue caps one $persistentStore / $prefs value.
const storeMaxValue = 4 << 20

// Read returns the value and whether it exists.
func (s *Store) Read(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadLocked()
	v, ok := s.data[key]
	return v, ok
}

// Write sets (or deletes when del) a key.
func (s *Store) Write(key, val string, del bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadLocked()
	if del {
		delete(s.data, key)
	} else {
		// v0.19.9: 4 MB per value (was 1 MB). Sub-Store keeps all its subscriptions, collections, files and
		// artifacts in one JSON key; BoxJS backups are one key each. The 8 MB total still bounds the store.
		if len(val) > storeMaxValue {
			return false
		}
		// v0.19.3: total cap. Every write re-serialises the whole map inside the 50 MB extension, so an
		// unbounded store (a script appending to a key on every request) ended in a jetsam kill.
		total := len(val) + len(key)
		for k, v := range s.data {
			if k != key {
				total += len(k) + len(v)
			}
		}
		if total > storeMaxTotal {
			return false
		}
		s.data[key] = val
	}
	return s.saveLocked() == nil
}

// Clear removes all keys.
func (s *Store) Clear() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = map[string]string{}
	return s.saveLocked() == nil
}

// All returns a copy of the store.
func (s *Store) All() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadLocked()
	out := make(map[string]string, len(s.data))
	for k, v := range s.data {
		out[k] = v
	}
	return out
}
