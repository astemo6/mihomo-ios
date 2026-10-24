package mitm

// Native request-log records (nativerecord.go): an entry written from Swift's events must be the entry the Go
// flow API writes for the same request — the request list and detail view must not tell them apart.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func nrPairs(m map[string]string) [][2]string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([][2]string, 0, len(m))
	for _, k := range keys {
		out = append(out, [2]string{k, m[k]})
	}
	return out
}

func nrApply(t *testing.T, e *Engine, recs ...NativeRecord) {
	t.Helper()
	b, _ := json.Marshal(recs)
	if n := e.RecordNative(string(b)); n != len(recs) {
		t.Fatalf("applied %d of %d records: %s", n, len(recs), b)
	}
}

func nrNewest(e *Engine) *Entry {
	e.Requests.mu.Lock()
	defer e.Requests.mu.Unlock()
	var best *Entry
	for _, x := range e.Requests.list {
		if best == nil || x.ID > best.ID {
			best = x
		}
	}
	return best
}

func nrIndex(labels []string, l string) int {
	for i, x := range labels {
		if x == l {
			return i
		}
	}
	return -1
}

// TestNativeRecordReproducesFlowLog: for every native-answerable case of the CI suites, the records Swift sends
// (built here from what Swift knows: rule indices, URL, the r.Host it saw, request / response header pairs)
// give the entry the real flow API left.
func TestNativeRecordReproducesFlowLog(t *testing.T) {
	suites := rwCISuites(t)
	mods := map[string][]rwModule{
		"edge":   {{"edge", "edge", rwEdgeModule}, {"qx", "qx", rwQXEdge}},
		"compat": {{"sg", "Surge", surgeCompatModule}, {"lo", "Loon", loonCompatModule}, {"qx", "QX", qxCompatModule}, {"eg", "Egern", egernCompatModule}},
	}
	checked := 0
	for _, s := range suites {
		ms, ok := mods[s.Name]
		if !ok {
			continue
		}
		e, _ := rwEngine(t, t.TempDir(), ms)
		gen := e.RewriteSnapshotGen()
		labels := []string{}
		for _, r := range e.state().rs.Rules {
			labels = append(labels, r.label())
		}
		if !reflect.DeepEqual(labels, s.Labels) {
			t.Fatalf("suite %s: labels differ from the suite's", s.Name)
		}
		for k, c := range s.Cases {
			if c.Log == nil {
				continue
			}
			head := FlowHead{Method: c.Method, Target: c.Target, Host: c.Host, Headers: c.Headers, Length: c.Length, ConnHost: c.ConnHost, ConnPort: c.ConnPort, TLS: true}
			r, err := head.request()
			if err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			var rules []int
			for _, l := range c.Log.Matched {
				i := nrIndex(labels, l)
				if i < 0 {
					t.Fatalf("%s: label %q not in the ruleset", c.Name, l)
				}
				rules = append(rules, i)
			}
			base := NativeRecord{K: int64(k + 1), T: float64(time.Now().UnixMilli()) / 1000, Ms: 1.5, Gen: gen, Rules: rules, Method: r.Method, URL: c.Log.URL, Host: r.Host, TLS: true}
			switch c.Expect.Action {
			case "drop":
				d := base
				d.Ev = "drop"
				nrApply(t, e, d)
			case "local":
				d := base
				d.Ev, d.Status, d.Headers, d.Len = "local", c.Log.Status, nrPairs(c.Log.RespHdr), c.Log.Bytes
				nrApply(t, e, d)
			case "forward":
				f := base
				f.Ev, f.Headers = "forward", nrPairs(c.Log.ReqHdr)
				recs := []NativeRecord{f}
				if c.Resp != nil {
					recs = append(recs, NativeRecord{K: f.K, Ev: "response", Ms: 2, Status: c.Log.Status, Headers: nrPairs(c.Log.RespHdr)})
				}
				recs = append(recs, NativeRecord{K: f.K, Ev: "end", Ms: 3, Resp: c.Resp != nil})
				nrApply(t, e, recs...)
			default:
				t.Fatalf("%s: log on a %s case", c.Name, c.Expect.Action)
			}
			got := rwLogOf(nrNewest(e))
			if !reflect.DeepEqual(got, c.Log) {
				gj, _ := json.Marshal(got)
				wj, _ := json.Marshal(c.Log)
				t.Errorf("[%s] %s:\n native %s\n go     %s", s.Name, c.Name, gj, wj)
			}
			checked++
		}
		if e.NativePending() != 0 {
			t.Errorf("suite %s: %d native forwards left pending", s.Name, e.NativePending())
		}
		e.Stop()
	}
	if checked < 100 {
		t.Fatalf("only %d cases checked", checked)
	}
	t.Logf("%d native records reproduce the flow API's entries", checked)
	waitFlows(t)
}

// TestNativeRecordEndPaths: how a native forward ends (bytes, error after the response, client cancel before /
// after the response, upstream failure, upgrade) reads exactly like the flow API's entry for the same ending.
func TestNativeRecordEndPaths(t *testing.T) {
	e, rs := rwEngine(t, t.TempDir(), []rwModule{{"edge", "edge", rwEdgeModule}})
	defer e.Stop()
	gen := e.RewriteSnapshotGen()
	idx := func(pat string) int {
		for i, r := range rs.Rules {
			if r.Pattern == pat {
				return i
			}
		}
		t.Fatalf("no rule %s", pat)
		return -1
	}
	reqRule := idx(`^https://edge\.test\.com/h/add`)
	reqRule2 := -1
	for i, r := range rs.Rules {
		if i != reqRule && r.Pattern == `^https://edge\.test\.com/h/add` {
			reqRule2 = i
		}
	}
	respRule := idx(`^https://edge\.test\.com/(h|r)/`)
	hdrs := [][2]string{{"Host", "edge.test.com"}, {"User-Agent", "t"}}
	type step struct {
		name     string
		upgrade  bool
		response bool
		finish   func(id int64)
		native   func(k int64) []NativeRecord
	}
	steps := []step{
		{name: "complete with bytes", response: true,
			finish: func(id int64) { FlowEnd(id, 2, "") },
			native: func(k int64) []NativeRecord { return []NativeRecord{{K: k, Ev: "end", Sent: 2, Resp: true}} }},
		{name: "client cut after response", response: true,
			finish: func(id int64) { FlowEnd(id, 1, "write: broken pipe") },
			native: func(k int64) []NativeRecord {
				return []NativeRecord{{K: k, Ev: "end", Sent: 1, Why: "write: broken pipe", Resp: true}}
			}},
		{name: "cancel before response",
			finish: func(id int64) { FlowCancel(id, "") },
			native: func(k int64) []NativeRecord { return []NativeRecord{{K: k, Ev: "cancel"}} }},
		{name: "cancel after response", response: true,
			finish: func(id int64) { FlowCancel(id, "超时") },
			native: func(k int64) []NativeRecord { return []NativeRecord{{K: k, Ev: "cancel", Why: "超时", Resp: true}} }},
		{name: "upstream failed",
			finish: func(id int64) { FlowUpstreamFailed(id, "dial tcp: timeout") },
			native: func(k int64) []NativeRecord { return []NativeRecord{{K: k, Ev: "upstream", Why: "dial tcp: timeout"}} }},
		{name: "upgrade", response: true, upgrade: true,
			finish: func(id int64) { FlowEnd(id, 500, "") },
			native: func(k int64) []NativeRecord { return []NativeRecord{{K: k, Ev: "end", Sent: 500}} }}, // relayed bytes count; no note (no response body)
	}
	for i, s := range steps {
		hj, _ := json.Marshal(FlowHead{Method: "GET", Target: "/h/add", Headers: hdrs, ConnHost: "edge.test.com", ConnPort: 443, TLS: true})
		d := rwDecode(t, e.FlowBegin(string(hj)))
		if d.Action != "forward" {
			t.Fatalf("%s: %s", s.name, d.Action)
		}
		ent := lookupFlow(d.ID).ent
		status, rh := 200, rwCannedResp
		if s.upgrade {
			status, rh = 101, [][2]string{{"Connection", "Upgrade"}, {"Upgrade", "websocket"}}
		}
		if s.response {
			b, _ := json.Marshal(FlowRespHead{Status: status, Headers: rh, Length: 2})
			if rd := rwDecode(t, FlowResponse(d.ID, string(b))); rd.Action == "error" {
				t.Fatalf("%s: response %s", s.name, rd.Note)
			}
		}
		s.finish(d.ID)
		for j := 0; j < 1000 && !func() bool { ent.mu.Lock(); defer ent.mu.Unlock(); return ent.Done }(); j++ {
			time.Sleep(time.Millisecond)
		}
		want := rwLogOf(ent)

		k := int64(1000 + i)
		rules := []int{reqRule}
		if reqRule2 >= 0 {
			rules = append(rules, reqRule2)
		}
		recs := []NativeRecord{{K: k, Ev: "forward", T: float64(time.Now().UnixMilli()) / 1000, Ms: 0.4, Gen: gen, Rules: rules, Method: "GET",
			URL: "https://edge.test.com/h/add", Host: "edge.test.com", TLS: true, Headers: nrPairs(want.ReqHdr)}}
		if s.response {
			rr := NativeRecord{K: k, Ev: "response", Ms: 3, Gen: gen, Status: status, Headers: nrPairs(want.RespHdr)}
			rr.Rules = []int{respRule} // for 101 Go ignores them (modifyResponse returns before the rules)
			recs = append(recs, rr)
		}
		recs = append(recs, s.native(k)...)
		nrApply(t, e, recs...)
		got := rwLogOf(nrNewest(e))
		if !reflect.DeepEqual(got, want) {
			gj, _ := json.Marshal(got)
			wj, _ := json.Marshal(want)
			t.Errorf("%s:\n native %s\n go     %s", s.name, gj, wj)
		}
	}
	if e.NativePending() != 0 {
		t.Errorf("%d pending", e.NativePending())
	}
	waitFlows(t)
}

// TestNativeRecordMechanics: ordering by start time, capture of a local body, labels across a reload, unknown
// keys, bad input, the pending bound and the summary the list shows.
func TestNativeRecordMechanics(t *testing.T) {
	home := t.TempDir()
	e, rs := rwEngine(t, home, []rwModule{{"edge", "edge", rwEdgeModule}})
	defer e.Stop()
	gen := e.RewriteSnapshotGen()
	rej := -1
	for i, r := range rs.Rules {
		if r.Pattern == `^https://edge\.test\.com/dict` {
			rej = i
		}
	}
	if e.RecordNative("{") != -1 {
		t.Fatal("bad JSON accepted")
	}
	if n := e.RecordNative(`[{"k":77,"ev":"end"},{"k":1,"ev":"nonsense"}]`); n != 0 {
		t.Fatalf("unknown key / event applied: %d", n)
	}

	now := float64(time.Now().UnixMilli()) / 1000
	// a Go entry started now, then a native forward that started 2 s earlier: the native one sorts before it
	if err := writeGoEntry(e, "https://edge.test.com/plain/go"); err != nil {
		t.Fatal(err)
	}
	nrApply(t, e, NativeRecord{K: 5, Ev: "forward", T: now - 2, Ms: 1, Gen: gen, Method: "GET", URL: "https://edge.test.com/plain/n", Host: "edge.test.com:443", TLS: true})
	list := e.Requests.List(0)
	if len(list) != 2 || list[0].URL != "https://edge.test.com/plain/go" || list[1].URL != "https://edge.test.com/plain/n" || list[1].Host != "edge.test.com" || list[1].Done {
		b, _ := json.Marshal(list)
		t.Fatalf("order / host: %s", b)
	}
	nrApply(t, e, NativeRecord{K: 5, Ev: "end", Ms: 2004.1234567})
	if s := e.Requests.List(0)[1]; !s.Done || s.Duration != 2004.123 {
		t.Fatalf("finish: %+v", s)
	}

	// labels resolve for the current generation and one reload back; capture records a local body
	cfg := &Config{Enabled: true, MitM: true, Modules: e.state().cfg.Modules} // capture on (nil = on)
	e.Reload(cfg, Build(home, cfg))
	gen2 := e.RewriteSnapshotGen()
	if gen2 == gen {
		t.Fatal("reload kept the generation")
	}
	nrApply(t, e,
		NativeRecord{K: 6, Ev: "local", T: now, Ms: 0.2, Gen: gen, Rules: []int{rej}, Method: "GET", URL: "https://edge.test.com/dict", Host: "edge.test.com", TLS: true,
			Status: 200, Headers: [][2]string{{"Content-Length", "2"}, {"Content-Type", "application/json"}}, Len: 2, Body: []byte("{}")},
		NativeRecord{K: 7, Ev: "drop", T: now, Ms: 0.1, Gen: gen2, Rules: []int{rej}, Method: "GET", URL: "https://edge.test.com/drop", Host: "edge.test.com", TLS: true},
		NativeRecord{K: 8, Ev: "drop", T: now, Gen: 999999, Rules: []int{rej}, URL: "https://edge.test.com/x", Host: "edge.test.com"},
	)
	var local, drop, stale *Entry
	for _, x := range e.Requests.list {
		switch x.URL {
		case "https://edge.test.com/dict":
			local = x
		case "https://edge.test.com/drop":
			drop = x
		case "https://edge.test.com/x":
			stale = x
		}
	}
	want := rs.Rules[rej].label()
	if local == nil || fmt.Sprint(local.Matched) != "["+want+"]" || !local.IsLocal || local.RespBodyS != "{}" || local.Bytes != 2 || local.Status != 200 {
		t.Fatalf("local: %+v", local)
	}
	if drop == nil || fmt.Sprint(drop.Matched) != "["+want+"]" || drop.Status != 0 || fmt.Sprint(drop.Notes) != "[拒绝（断开）]" || !drop.Done {
		t.Fatalf("drop: %+v", drop)
	}
	if stale == nil || len(stale.Matched) != 0 || stale.Method != http.MethodGet {
		t.Fatalf("stale generation: %+v", stale)
	}

	// pending forwards are bounded
	var recs []NativeRecord
	for i := 0; i < nativeRecPendingMax+50; i++ {
		recs = append(recs, NativeRecord{K: int64(10000 + i), Ev: "forward", T: now, URL: "https://edge.test.com/p", Host: "edge.test.com"})
	}
	nrApply(t, e, recs...)
	if p := e.NativePending(); p != nativeRecPendingMax {
		t.Fatalf("pending %d", p)
	}
	if n := e.RecordNative(`[{"k":10000,"ev":"end"}]`); n != 0 {
		t.Fatal("the oldest pending forward should have been forgotten")
	}
	if len(e.Requests.List(0)) > 200 || !strings.Contains(e.Requests.List(0)[0].URL, "edge.test.com") {
		t.Fatal("ring bound")
	}
}

// writeGoEntry records a Go-path entry (Start + Finish) for ordering tests.
func writeGoEntry(e *Engine, u string) error {
	r, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return err
	}
	ent := e.Requests.Start(r, u, true)
	ent.Finish(200, "")
	return nil
}
