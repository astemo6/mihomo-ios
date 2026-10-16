package mitm

import (
	"errors"
	"regexp"
)

// APIFunc answers Surge $httpAPI calls (method, path incl. query, decoded JSON body). The bridge
// installs it because policy groups, the outbound mode and profile reload live outside the engine.
type APIFunc func(method, path string, body any) (any, error)

// egernNativeRe detects Egern's native script shape (ES module + ctx), which the goja runtime and our
// Surge / QX compatible globals don't provide.
var egernNativeRe = regexp.MustCompile(`(?m)^\s*export\s+default\s+(async\s+)?function`)

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
