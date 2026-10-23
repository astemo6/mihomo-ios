package mitm

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReorderSlots(t *testing.T) {
	key := func(s string) (string, bool) {
		if len(s) > 0 && s[0] == '-' { // "-x" items never take part
			return "", false
		}
		return s, true
	}
	cases := []struct {
		in, order, want []string
	}{
		{[]string{"a", "b", "c"}, nil, []string{"a", "b", "c"}},
		{[]string{"a", "b", "c"}, []string{"c", "b", "a"}, []string{"c", "b", "a"}},
		// fixed items stay in their slots
		{[]string{"a", "-x", "b", "-y", "c"}, []string{"c", "a", "b"}, []string{"c", "-x", "a", "-y", "b"}},
		// a name not in the order (new) keeps its position; unknown order names are ignored
		{[]string{"a", "new", "b", "c"}, []string{"c", "gone", "b", "a"}, []string{"c", "new", "b", "a"}},
		// duplicates of one name keep their relative order
		{[]string{"a", "b", "a"}, []string{"b", "a"}, []string{"b", "a", "a"}},
		// a duplicated order entry counts once (first position)
		{[]string{"a", "b"}, []string{"b", "a", "b"}, []string{"b", "a"}},
	}
	for i, c := range cases {
		got := ReorderSlots(c.in, key, c.order)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("case %d: got %v want %v", i, got, c.want)
		}
		// idempotent, and the input is not modified
		if again := ReorderSlots(got, key, c.order); !reflect.DeepEqual(again, c.want) {
			t.Errorf("case %d: second pass %v", i, again)
		}
	}
	in := []string{"a", "b"}
	_ = ReorderSlots(in, key, []string{"b", "a"})
	if in[0] != "a" {
		t.Fatalf("input modified: %v", in)
	}
}

func TestTaskOrderPrefs(t *testing.T) {
	home := t.TempDir()
	e := &Engine{home: home}
	tk := newTasker(e)
	a := &Task{ID: "a", Kind: TaskCron}
	b := &Task{ID: "b", Kind: TaskCron}
	c := &Task{ID: "c", Kind: TaskEvent}
	tk.natural = []*Task{a, b, c}
	tk.tasks = tk.natural
	tk.states = map[string]*TaskState{"a": {Task: a}, "b": {Task: b}, "c": {Task: c}}
	tk.setPrefs(TaskPrefs{Order: []string{"c", "b", "a"}, Deleted: map[string]bool{"b": true}})
	var ids []string
	for _, x := range tk.tasks {
		ids = append(ids, x.ID)
	}
	if !reflect.DeepEqual(ids, []string{"c", "b", "a"}) {
		t.Fatalf("running order %v", ids)
	}
	// the list keeps the kind grouping, the user's order inside each kind
	var listed []string
	for _, s := range tk.list() {
		listed = append(listed, s.ID)
		if s.ID == "b" && s.Enabled {
			t.Fatalf("deleted task b still enabled")
		}
	}
	if !reflect.DeepEqual(listed, []string{"b", "a", "c"}) {
		t.Fatalf("list %v", listed)
	}
	// persisted for the offline list
	if _, err := os.Stat(filepath.Join(home, taskPrefsFile)); err != nil {
		t.Fatal(err)
	}
	if p := ReadTaskPrefs(home); !reflect.DeepEqual(p.Order, []string{"c", "b", "a"}) || !p.Deleted["b"] {
		t.Fatalf("prefs %+v", p)
	}
	if got := OrderTasks([]*Task{a, b, c}, ReadTaskPrefs(home).Order); got[0] != c || got[2] != a {
		t.Fatalf("OrderTasks %v", got)
	}
}
