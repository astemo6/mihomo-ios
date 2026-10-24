package mitm

// fix/xmly-memory-2: 喜马拉雅 opens 70–100 connections within a second or two (HTTPDNS to IPs on the MitM
// list), and every one was TLS-terminated at once: certificate leaf (cached per name, but the IP leaf covers
// the whole MitM hostname list), handshake buffers and goroutines for all of them at the same moment — the
// footprint peak that left 3–5 MB available. While memory is tight the client handshakes now take turns
// (hsTightConcurrent at a time). A connection never fails because of it: after hsMaxWait it handshakes anyway.

import (
	"context"
	"sync/atomic"
	"time"
)

// hsTightAvail: below this much available memory client TLS handshakes take turns.
const hsTightAvail = 10 << 20

// hsTightConcurrent: handshakes in flight at most while memory is tight.
const hsTightConcurrent = 4

// hsMaxWait: the longest a handshake waits for its turn before going ahead anyway.
var hsMaxWait = 3 * time.Second

var hsSem = make(chan struct{}, hsTightConcurrent)

// hsWaited counts handshakes that had to wait (diagnostics, tests).
var hsWaited atomic.Int64

// handshakeTurn waits for a turn when memory is tight and returns the release (always call it).
func handshakeTurn(ctx context.Context) func() {
	if a, known := availableMemory(); !known || a >= hsTightAvail {
		return func() {}
	}
	select {
	case hsSem <- struct{}{}:
		return func() { <-hsSem }
	default:
	}
	hsWaited.Add(1)
	t := time.NewTimer(hsMaxWait)
	defer t.Stop()
	select {
	case hsSem <- struct{}{}:
		return func() { <-hsSem }
	case <-t.C:
	case <-ctx.Done():
	}
	return func() {}
}
