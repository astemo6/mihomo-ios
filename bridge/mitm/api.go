package mitm

import (
	"encoding/json"
	http "github.com/metacubex/http"
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
