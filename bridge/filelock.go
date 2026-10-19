package libmihomo

import (
	"path/filepath"
	"sync"
)

// v0.19.6 (review 7): the app runs file edits on detached tasks (node edits, manual nodes, offline group
// selections, 前置代理, group order, the launch-time provider migration), so two read-modify-write calls on
// one file could interleave and the later write dropped the earlier one (9 of 12 concurrent node additions
// were lost in TestV0196ConcurrentProfileNodeWrites). Every read-modify-write of a file now holds that
// file's lock for the whole read → edit → write. In-process only: the extension only reads these files.
var fileLocks sync.Map // cleaned path → *sync.Mutex

// lockPath locks path and returns the unlock func: `defer lockPath(p)()`.
func lockPath(path string) func() {
	m, _ := fileLocks.LoadOrStore(filepath.Clean(path), &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}
