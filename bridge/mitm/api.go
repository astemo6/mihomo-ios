package mitm

import (
	"encoding/json"
	http "github.com/metacubex/http"
	"io"
	"strconv"

	"github.com/metacubex/chi"
)

// Status is GET /mitm/status.
type Status struct {
	Running     bool     `json:"running"`
	Port        int      `json:"port"`
	Enabled     bool     `json:"enabled"`
	MitM        bool     `json:"mitm"`
	CALoaded    bool     `json:"caLoaded"`
	Hostnames   []string `json:"hostnames"`
	Rules       int      `json:"rules"`
	Scripts     int      `json:"scripts"`
	CoreRules   int      `json:"coreRules"`
	Errors      []string `json:"errors"`
	Unsupported int      `json:"unsupported"`
	Pinned      []string `json:"pinned"`
}

func (e *Engine) Status() Status {
	st := e.state()
	s := Status{Running: e.ln != nil, Port: e.port, Enabled: st.cfg.Enabled, MitM: st.cfg.MitM, CALoaded: st.ca != nil,
		Hostnames: st.rs.Hostnames, CoreRules: len(st.rs.CoreRules), Errors: st.rs.Errors, Unsupported: len(st.rs.Unsupported), Pinned: []string{}}
	for _, r := range st.rs.Rules {
		if r.Kind == KindScript {
			s.Scripts++
		} else {
			s.Rules++
		}
	}
	e.pinned.Range(func(k, _ any) bool { s.Pinned = append(s.Pinned, k.(string)); return true })
	if s.Hostnames == nil {
		s.Hostnames = []string{}
	}
	if s.Errors == nil {
		s.Errors = []string{}
	}
	return s
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

// Routes mounts /mitm on the mihomo external controller (same Bearer secret).
func Routes(get func() *Engine) func(r chi.Router) {
	return func(r chi.Router) {
		r.Route("/mitm", func(r chi.Router) {
			r.Get("/status", func(w http.ResponseWriter, req *http.Request) {
				e := get()
				if e == nil {
					writeJSON(w, Status{Hostnames: []string{}, Errors: []string{}, Pinned: []string{}})
					return
				}
				writeJSON(w, e.Status())
			})
			r.Get("/requests", func(w http.ResponseWriter, req *http.Request) {
				e := get()
				if e == nil {
					writeJSON(w, []Summary{})
					return
				}
				since, _ := strconv.ParseInt(req.URL.Query().Get("since"), 10, 64)
				writeJSON(w, e.Requests.List(since))
			})
			r.Get("/requests/{id}", func(w http.ResponseWriter, req *http.Request) {
				e := get()
				id, _ := strconv.ParseInt(chi.URLParam(req, "id"), 10, 64)
				if e == nil {
					http.NotFound(w, req)
					return
				}
				ent := e.Requests.Get(id)
				if ent == nil {
					http.NotFound(w, req)
					return
				}
				ent.mu.Lock()
				b, _ := json.Marshal(ent)
				ent.mu.Unlock()
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				_, _ = w.Write(b)
			})
			r.Delete("/requests", func(w http.ResponseWriter, req *http.Request) {
				if e := get(); e != nil {
					e.Requests.Clear()
				}
				w.WriteHeader(http.StatusNoContent)
			})
			r.Get("/hosts", func(w http.ResponseWriter, req *http.Request) {
				e := get()
				if e == nil {
					writeJSON(w, map[string][]string{})
					return
				}
				writeJSON(w, e.Requests.Hosts())
			})
			r.Get("/logs", func(w http.ResponseWriter, req *http.Request) {
				e := get()
				if e == nil {
					writeJSON(w, []LogLine{})
					return
				}
				since, _ := strconv.ParseInt(req.URL.Query().Get("since"), 10, 64)
				writeJSON(w, e.Logs.List(since, req.URL.Query().Get("script")))
			})
			r.Delete("/logs", func(w http.ResponseWriter, req *http.Request) {
				if e := get(); e != nil {
					e.Logs.Clear()
				}
				w.WriteHeader(http.StatusNoContent)
			})
			r.Post("/requests/{id}/replay", func(w http.ResponseWriter, req *http.Request) {
				e := get()
				id, _ := strconv.ParseInt(chi.URLParam(req, "id"), 10, 64)
				if e == nil {
					http.Error(w, "engine not running", http.StatusServiceUnavailable)
					return
				}
				var edit *ReplayRequest
				if req.ContentLength != 0 {
					var x ReplayRequest
					if err := json.NewDecoder(req.Body).Decode(&x); err == nil {
						edit = &x
					}
				}
				res, err := e.Replay(id, edit)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				writeJSON(w, res)
			})
			r.Get("/tasks", func(w http.ResponseWriter, req *http.Request) {
				e := get()
				if e == nil {
					writeJSON(w, []TaskState{})
					return
				}
				writeJSON(w, e.tasks.list())
			})
			r.Post("/tasks/{id}/run", func(w http.ResponseWriter, req *http.Request) {
				e := get()
				if e == nil {
					http.Error(w, "engine not running", http.StatusServiceUnavailable)
					return
				}
				tk := e.tasks.find(chi.URLParam(req, "id"))
				if tk == nil {
					http.NotFound(w, req)
					return
				}
				// v0.11: {"params": "<policy>"} for QX interaction scripts.
				var body struct {
					Params *string `json:"params"`
				}
				_ = json.NewDecoder(io.LimitReader(req.Body, 64<<10)).Decode(&body)
				var extra map[string]any
				trigger := "manual"
				if body.Params != nil {
					extra = map[string]any{"$params": *body.Params}
					trigger = "interaction"
				}
				out, err := e.tasks.runAs(tk, extra, trigger)
				if err != nil {
					writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
					return
				}
				writeJSON(w, map[string]any{"ok": true, "result": out})
			})
			r.Get("/tasks/{id}/history", func(w http.ResponseWriter, req *http.Request) {
				e := get()
				if e == nil {
					writeJSON(w, []RunRecord{})
					return
				}
				writeJSON(w, e.tasks.historyFor(chi.URLParam(req, "id")))
			})
			r.Get("/http-backend", func(w http.ResponseWriter, req *http.Request) {
				e := get()
				if e == nil {
					writeJSON(w, map[string]any{"running": false})
					return
				}
				writeJSON(w, e.backend.status())
			})
			r.Get("/tasks-prefs", func(w http.ResponseWriter, req *http.Request) {
				e := get()
				if e == nil {
					writeJSON(w, TaskPrefs{})
					return
				}
				writeJSON(w, e.tasks.getPrefs())
			})
			r.Put("/tasks-prefs", func(w http.ResponseWriter, req *http.Request) {
				e := get()
				if e == nil {
					http.Error(w, "engine not running", http.StatusServiceUnavailable)
					return
				}
				var p TaskPrefs
				if err := json.NewDecoder(io.LimitReader(req.Body, 1<<20)).Decode(&p); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				e.tasks.setPrefs(p)
				writeJSON(w, map[string]any{"ok": true})
			})
			r.Get("/panels", func(w http.ResponseWriter, req *http.Request) {
				e := get()
				if e == nil {
					writeJSON(w, []PanelState{})
					return
				}
				e.tasks.markViewed()
				writeJSON(w, e.tasks.panelList())
			})
			homePanelRoutes(r, get) // feat/panels: GET / PUT /mitm/panels-home
			r.Post("/panels/{id}/refresh", func(w http.ResponseWriter, req *http.Request) {
				e := get()
				if e == nil {
					http.Error(w, "engine not running", http.StatusServiceUnavailable)
					return
				}
				st, err := e.tasks.refreshPanel(chi.URLParam(req, "id"))
				if err != nil {
					http.Error(w, err.Error(), http.StatusNotFound)
					return
				}
				writeJSON(w, st)
			})
			r.Get("/notifications", func(w http.ResponseWriter, req *http.Request) {
				e := get()
				if e == nil {
					writeJSON(w, []Notice{})
					return
				}
				writeJSON(w, e.Notices.List())
			})
			r.Post("/refresh", func(w http.ResponseWriter, req *http.Request) {
				// re-download a remote script / resource: {"url": "..."}
				e := get()
				var body struct {
					URL string `json:"url"`
				}
				_ = json.NewDecoder(req.Body).Decode(&body)
				if e == nil || body.URL == "" {
					http.Error(w, "engine not running", http.StatusBadRequest)
					return
				}
				if _, err := e.res.Refresh(body.URL); err != nil {
					http.Error(w, err.Error(), http.StatusBadGateway)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			})
		})
	}
}
