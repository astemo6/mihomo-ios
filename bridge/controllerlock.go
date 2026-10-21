package libmihomo

// Review 7 P3-4 (hardening): mihomo's controller would let a caller holding the secret
//   PUT  /configs        reload from C.Path.Config() (the raw profile) — bypassing buildRuntime: no tun fd,
//                        the profile's own controller / listeners (inbound sanitising lost);
//   POST /configs/geo    download geo databases outside the app's mirror / memory budget;
//   POST /restart        syscall.Exec the extension (the process dies);
//   POST /upgrade[/…]    replace the core binary / UI / geo files.
// route.SetEmbedMode(true) would remove them but also PATCH /configs, which the app and widget use for 出站模式.
// Instead these exact method + path pairs are re-registered on the authenticated group (external routers are
// added after mihomo's own mounts, and a chi route on an existing pattern replaces that method's handler),
// answering 403. Everything else, PATCH /configs included, is unchanged.

import (
	"github.com/metacubex/chi"
	mhttp "github.com/metacubex/http"
	"github.com/metacubex/mihomo/hub/route"
)

func controllerDenied(w mhttp.ResponseWriter, _ *mhttp.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(mhttp.StatusForbidden)
	_, _ = w.Write([]byte(`{"message":"not available on iOS: use the app (Reload) instead"}`))
}

func controllerLockRoutes(r chi.Router) {
	for _, p := range []string{"/configs", "/configs/"} {
		r.Put(p, controllerDenied)
	}
	r.Post("/configs/*", controllerDenied) // /configs/geo
	for _, base := range []string{"/restart", "/upgrade"} {
		for _, p := range []string{base, base + "/", base + "/*"} {
			r.Post(p, controllerDenied)
		}
	}
}

func init() { route.Register(controllerLockRoutes) }
