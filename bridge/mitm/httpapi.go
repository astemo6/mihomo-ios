package mitm

import (
	"errors"
	"regexp"
)

// APIFunc answers Surge $httpAPI calls (method, path incl. query, decoded JSON body). The bridge
// installs it because policy groups, the outbound mode and profile reload live outside the engine.
type APIFunc func(method, path string, body any) (any, error)

// egernNativeRe detects Egern's native script shape (ES module + ctx); such scripts run through the
// ctx adapter in egernadapter.go.
// v0.19.4: any `export default` (also `export default async (ctx) => …` / `export default ctx => …`, which
// adaptEgern already handled but were never detected and failed with a syntax error).
var egernNativeRe = regexp.MustCompile(`(?m)^[ \t]*export[ \t]+default[ \t]+`)

// SetAPI installs the $httpAPI handler (nil removes it).
func (e *Engine) SetAPI(f APIFunc) {
	if f == nil {
		e.api.Store(nil)
		return
	}
	e.api.Store(&f)
}

func (e *Engine) callAPI(method, path string, body any) (any, error) {
	if p := e.api.Load(); p != nil && *p != nil {
		return (*p)(method, path, body)
	}
	return nil, errors.New("$httpAPI 不可用")
}
