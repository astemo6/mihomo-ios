package mitm

// Manual order (user 2026-10-23 「这个规则要能手动调顺序」「三个路径…也都要可以手动调顺序」): the app stores the
// order the user dragged a list into as a list of names / ids. ReorderSlots applies it without moving anything
// else: the items named in `order` are sorted among the positions they already occupy, everything else (items the
// order does not name — new ones keep their natural place — and items the key function skips) stays where it is.
// Items sharing one name keep their relative order. Applying the same order twice gives the same result.

import (
	"path/filepath"
	"sort"
)

// ReorderSlots returns a reordered copy of items. key returns an item's name and whether it takes part at all.
func ReorderSlots[T any](items []T, key func(T) (string, bool), order []string) []T {
	out := append([]T(nil), items...)
	if len(order) == 0 || len(items) < 2 {
		return out
	}
	rank := make(map[string]int, len(order))
	for i, n := range order {
		if _, dup := rank[n]; !dup {
			rank[n] = i
		}
	}
	var slots []int
	var picked []T
	var ranks []int
	for i, it := range items {
		n, ok := key(it)
		if !ok {
			continue
		}
		r, ok := rank[n]
		if !ok {
			continue
		}
		slots = append(slots, i)
		picked = append(picked, it)
		ranks = append(ranks, r)
	}
	if len(slots) < 2 {
		return out
	}
	idx := make([]int, len(picked))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return ranks[idx[a]] < ranks[idx[b]] })
	for k, s := range slots {
		out[s] = picked[idx[k]]
	}
	return out
}

// OrderTasks applies the task order of the app (task-prefs.json `order`, task ids) to a parsed task list.
func OrderTasks(tasks []*Task, order []string) []*Task {
	return ReorderSlots(tasks, func(t *Task) (string, bool) {
		if t == nil {
			return "", false
		}
		return t.ID, true
	}, order)
}

// ReadTaskPrefs reads the app's task-prefs.json in the engine home (zero value when missing).
func ReadTaskPrefs(home string) TaskPrefs {
	p := TaskPrefs{}
	if home != "" {
		readJSONFile(filepath.Join(home, taskPrefsFile), &p)
	}
	return p
}
