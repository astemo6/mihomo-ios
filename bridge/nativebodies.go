package libmihomo

// Native body lane (feat/native-mitm stage 1; bridge/mitm/nativelane.go, work/native-mitm-design.md). The tunnel
// registers PacketTunnel/NativeBodyStore.swift after the JavaScriptCore engine; from then on response bodies that
// only scripts read are decoded and kept in native memory instead of the Go heap. Without a registered store
// (Android, Go tests, the app) nothing changes.

import "github.com/astemo6/mihomo-ios/bridge/mitm"

// NativeBodyStore is implemented in Swift. Every method is synchronous and may be called from any thread.
// Handles are > 0. (Names avoid NSObject's retain / release selectors: gomobile maps Free to `free:`.)
type NativeBodyStore interface {
	// Open starts a body: enc = Content-Encoding as received, limit = largest decoded size, hint = announced
	// length (-1 unknown). A handle, or 0 to refuse (unsupported encoding, low memory) before anything is read.
	Open(enc string, limit int64, hint int64) int64
	// Write feeds encoded bytes: "" ok, "too-big", "decode: <why>", or anything else for an internal failure.
	Write(h int64, b []byte) string
	// Finish ends the input: decoded length, -1 decode error, -2 too big, -3 internal (Err says why).
	Finish(h int64) int64
	// Err is the handle's last failure message.
	Err(h int64) string
	// Len is the decoded (raw=false) or encoded (raw=true) length; -1 for an unknown handle.
	Len(h int64, raw bool) int64
	// Read copies up to n bytes at off of the decoded / encoded bytes (empty at the end, nil unknown handle).
	Read(h int64, raw bool, off int64, n int64) []byte
	// Free forgets the handle.
	Free(h int64)
	// Stats is a short line for the memory log.
	Stats() string
}

type laneAdapter struct{ s NativeBodyStore }

func (a laneAdapter) Open(enc string, limit, hint int64) int64 { return a.s.Open(enc, limit, hint) }
func (a laneAdapter) Write(h int64, b []byte) string           { return a.s.Write(h, b) }
func (a laneAdapter) Finish(h int64) int64                     { return a.s.Finish(h) }
func (a laneAdapter) Err(h int64) string                       { return a.s.Err(h) }
func (a laneAdapter) Len(h int64, raw bool) int64              { return a.s.Len(h, raw) }
func (a laneAdapter) Read(h int64, raw bool, off, n int64) []byte {
	return a.s.Read(h, raw, off, n)
}
func (a laneAdapter) Free(h int64)  { a.s.Free(h) }
func (a laneAdapter) Stats() string { return a.s.Stats() }

// SetNativeBodyStore registers the native body lane (nil: off).
func SetNativeBodyStore(s NativeBodyStore) {
	if s == nil {
		mitm.SetNativeBodies(nil)
		return
	}
	mitm.SetNativeBodies(laneAdapter{s})
}

// NativeBlobBase is the first script blob id that names a native body (the Swift engine serves __tern.take for
// ids at or above it from NativeBodyStore). Exported so both sides share one constant.
func NativeBlobBase() int64 { return mitm.NativeBlobBase }

// NativeLaneStats is the lane's line for diagnostics ("" when none is registered).
func NativeLaneStats() string { return mitm.LaneStats() }

// ---- stage 2: native TLS front (bridge/mitm/nativeterm.go, relay.go) ----

// NativeTLSFront is implemented in Swift (PacketTunnel/NativeMitM, not built yet). Listen returns the loopback
// port of a TLS listener presenting a leaf for host (LeafIdentity), given the client's ALPN offer (comma
// separated); 0 declines and Go terminates TLS itself.
type NativeTLSFront interface {
	Listen(host string, alpn string) int64
}

// SetNativeTLSFront registers the native TLS front (nil: off). Registering also starts the upstream relay.
func SetNativeTLSFront(f NativeTLSFront) {
	if f == nil {
		mitm.SetNativeTerminator(nil)
		return
	}
	mitm.SetNativeTerminator(f)
	engMu.Lock()
	e := eng
	engMu.Unlock()
	if e != nil {
		_, _ = e.StartRelay()
	}
}

// MitmRelayPort is the upstream relay's loopback port for the native front (0: engine or relay not running).
func MitmRelayPort() int {
	engMu.Lock()
	e := eng
	engMu.Unlock()
	if e == nil {
		return 0
	}
	if p := e.RelayPort(); p != 0 {
		return p
	}
	if _, err := e.StartRelay(); err != nil {
		return 0
	}
	return e.RelayPort()
}

// MitmLeafIdentity is a PKCS#12 blob (password mitm.LeafIdentityPassword, "tern") with the leaf for host, the
// CA chain and the leaf key, for SecPKCS12Import in the native front. nil when no CA is installed.
func MitmLeafIdentity(host string) []byte {
	engMu.Lock()
	e := eng
	engMu.Unlock()
	if e == nil {
		return nil
	}
	b, err := e.LeafIdentity(host)
	if err != nil {
		return nil
	}
	return b
}

// MitmNativeHandshakeFailed reports a client handshake the native front saw fail ("cert", "closed", "timeout",
// "cancelled"), so pinning memory behaves like the Go path. Returns whether the host is now passed through.
func MitmNativeHandshakeFailed(host, kind string) bool {
	engMu.Lock()
	e := eng
	engMu.Unlock()
	if e == nil {
		return false
	}
	return e.NativeHandshakeFailed(host, kind)
}
