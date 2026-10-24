package mitm

// Native MitM stage 3 lane s3-h2: whether the Swift TLS front may serve HTTP/2 (PacketTunnel/NativeMitM/H2/,
// switch nativeMitmH2, default OFF). Stage 2 served HTTP/1.1 only: a ClientHello offering only h2 (gRPC) stayed
// on the Go path and "h2,http/1.1" was downgraded to HTTP/1.1 on the native side. With the native h2 switch on
// (Swift calls SetNativeH2 when it installs the front) and the engine's own h2 option on (Config.H2, the same
// option the Go path obeys), the offer passed to Listen keeps "h2" and h2-only clients are handed over too.
// The Swift front then negotiates h2 itself; every request on the connection still goes through the flow API.

import "sync/atomic"

var termH2 atomic.Bool

// SetNativeH2 tells the engine whether the registered native front serves h2.
func SetNativeH2(on bool) { termH2.Store(on) }

// NativeH2 reports SetNativeH2's value.
func NativeH2() bool { return termH2.Load() }

// nativeOffer returns the ALPN protocols to pass to the native front for a ClientHello that offered alpn, and
// whether the native front can serve the connection at all. h2: the native side may speak HTTP/2. No ALPN
// means HTTP/1.1. Protocols the native side does not speak are not passed on; a client that offers none of
// http/1.1 (and h2 when allowed) stays on the Go path.
func nativeOffer(alpn []string, h2 bool) ([]string, bool) {
	if len(alpn) == 0 {
		return nil, true // no ALPN: HTTP/1.1
	}
	var out []string
	for _, p := range alpn {
		if p == "http/1.1" || (h2 && p == "h2") {
			out = append(out, p)
		}
	}
	return out, len(out) > 0
}
