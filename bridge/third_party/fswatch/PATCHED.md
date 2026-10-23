# fswatch (patched copy)

Upstream: github.com/metacubex/fswatch @ v0.1.1 (MIT, see LICENSE). Copied without tests.
Used through `replace` in bridge/go.mod.

## Patch (mihomo-ios v0.19.22)

`Watcher.Start` returned on a failed `fsnotify.Watcher.Add` without closing the fsnotify watcher it had
just created, and `w.watcher` was not set yet, so `Close` could not reach it either. mihomo starts one
watcher per `type: file` provider (component/resource fetcher); a provider whose directory does not exist
leaked one inotify/kqueue descriptor and its read goroutine on every start and config reload (20 file
providers × 6 reloads = 120 goroutines in the reload probe). Fix: close it before returning the error
(watcher.go, search "mihomo-ios patch"). Drop this copy once upstream fixes it.
