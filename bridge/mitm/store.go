package mitm

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
	"unicode/utf8"
)

// Store backs $persistentStore / $prefs: a JSON map in the App Group container
// (<home>/engine/store.json) that the app can view and edit too.
//
// v0.19.9 (review 5 P1-5): writes used to re-serialise the whole map with MarshalIndent on every call
// (a 5 MB store spiked the heap by ~70 MB for a one-byte write). Now:
//   - the file is written key by key through a buffered writer (peak ≈ the largest escaped value);
//   - writes are coalesced: the in-memory map changes at once, the file follows within storeFlushDelay
//     (Flush forces it, e.g. when the engine stops);
//   - when the app edited the file meanwhile (mtime changed), the flush reloads it and re-applies only
//     the keys this process changed, so neither side's edits are lost.
type Store struct {
	mu      sync.Mutex
	path    string
	data    map[string]string
	mtime   time.Time
	pending map[string]*string // keys changed since the last flush (nil = deleted)
	cleared bool               // removeAllValues since the last flush
	timer   *time.Timer
	size    int // bytes of keys + values in data
}

// storeFlushDelay coalesces bursts of writes (a script setting several keys, counters per request).
var storeFlushDelay = 250 * time.Millisecond

func NewStore(home string) *Store {
	return &Store{path: filepath.Join(EngineDir(home), "store.json")}
}

func (s *Store) readFile() (map[string]string, time.Time, bool) {
	fi, err := os.Stat(s.path)
	if err != nil {
		return nil, time.Time{}, false
	}
	m := map[string]string{}
	f, err := os.Open(s.path)
	if err != nil {
		return nil, time.Time{}, false
	}
	derr := json.NewDecoder(bufio.NewReader(f)).Decode(&m)
	f.Close()
	if derr != nil && fi.Size() > 0 {
		// review6 P2-2: an unreadable file used to read as an empty (or partial) store, and the next
		// write replaced the whole store with it — every BoxJS setting / Sub-Store subscription gone.
		// Keep a copy for recovery and keep what is in memory.
		_ = os.Rename(s.path, s.path+".bad")
		return nil, time.Time{}, false
	}
	return m, fi.ModTime(), true
}

// recomputeSizeLocked recounts the bytes of keys + values (review6 OPT-2: Write keeps a running total
// instead of summing every key on each call).
func (s *Store) recomputeSizeLocked() {
	n := 0
	for k, v := range s.data {
		n += len(k) + len(v)
	}
	s.size = n
}

func (s *Store) loadLocked() {
	if s.data != nil && (len(s.pending) > 0 || s.cleared) {
		return // our unflushed changes win until the flush merges
	}
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
	if m, mt, ok := s.readFile(); ok {
		s.data, s.mtime = m, mt
	} else if s.data == nil {
		s.data = map[string]string{}
	}
	s.recomputeSizeLocked()
}

// markLocked records a change and schedules the flush.
func (s *Store) markLocked(key string, val *string) {
	if s.pending == nil {
		s.pending = map[string]*string{}
	}
	s.pending[key] = val
	if s.timer == nil {
		s.timer = time.AfterFunc(storeFlushDelay, func() { _ = s.Flush() })
	}
}

// Flush writes pending changes to the file now.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flushLocked()
}

func (s *Store) flushLocked() error {
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	if len(s.pending) == 0 && !s.cleared {
		return nil
	}
	// The app may have written the file since we last read it: start from its content and replay ours.
	if fi, err := os.Stat(s.path); err == nil && !fi.ModTime().Equal(s.mtime) {
		if m, _, ok := s.readFile(); ok {
			if s.cleared {
				m = map[string]string{}
			}
			for k, v := range s.pending {
				if v == nil {
					delete(m, k)
				} else {
					m[k] = *v
				}
			}
			s.data = m
			s.recomputeSizeLocked()
		}
	}
	s.pending, s.cleared = nil, false
	if err := s.writeLocked(); err != nil {
		return err
	}
	if fi, err := os.Stat(s.path); err == nil {
		s.mtime = fi.ModTime()
	}
	return nil
}

// writeLocked streams the map as compact JSON, one key at a time (sorted for stable diffs).
func (s *Store) writeLocked() error {
	_ = os.MkdirAll(filepath.Dir(s.path), 0o755)
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(f, 32<<10)
	keys := make([]string, 0, len(s.data))
	for k := range s.data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	_ = w.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			_ = w.WriteByte(',')
		}
		writeJSONString(w, k)
		_ = w.WriteByte(':')
		writeJSONString(w, s.data[k])
	}
	_ = w.WriteByte('}')
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, s.path)
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
		if _, ok := s.data[key]; !ok {
			return true
		}
		s.size -= len(key) + len(s.data[key])
		delete(s.data, key)
		s.markLocked(key, nil)
		return true
	}
	// v0.19.9: 4 MB per value (was 1 MB). Sub-Store keeps all its subscriptions, collections, files and
	// artifacts in one JSON key; BoxJS backups are one key each. The 8 MB total still bounds the store
	// (v0.19.3: an unbounded store, e.g. a script appending to a key on every request, ended in jetsam).
	if len(val) > storeMaxValue {
		return false
	}
	old, had := s.data[key]
	if had && old == val {
		return true
	}
	total := s.size + len(val)
	if had {
		total -= len(old)
	} else {
		total += len(key)
	}
	if total > storeMaxTotal {
		return false
	}
	s.size = total
	s.data[key] = val
	v := val
	s.markLocked(key, &v)
	return true
}

// Clear removes all keys.
func (s *Store) Clear() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = map[string]string{}
	s.size = 0
	s.pending = nil
	s.cleared = true
	return s.flushLocked() == nil
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

// writeJSONString writes s as a JSON string without building it in memory (json.Marshal of a 1 MB
// value allocates ~2–3 MB). Invalid UTF-8 falls back to json.Marshal, which substitutes U+FFFD.
func writeJSONString(w *bufio.Writer, s string) {
	if !utf8.ValidString(s) {
		b, _ := json.Marshal(s)
		_, _ = w.Write(b)
		return
	}
	const hex = "0123456789abcdef"
	_ = w.WriteByte('"')
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c != '"' && c != '\\' {
			continue
		}
		_, _ = w.WriteString(s[start:i])
		switch c {
		case '"':
			_, _ = w.WriteString(`\"`)
		case '\\':
			_, _ = w.WriteString(`\\`)
		case '\n':
			_, _ = w.WriteString(`\n`)
		case '\r':
			_, _ = w.WriteString(`\r`)
		case '\t':
			_, _ = w.WriteString(`\t`)
		default:
			_, _ = w.WriteString(`\u00`)
			_ = w.WriteByte(hex[c>>4])
			_ = w.WriteByte(hex[c&0xf])
		}
		start = i + 1
	}
	_, _ = w.WriteString(s[start:])
	_ = w.WriteByte('"')
}
