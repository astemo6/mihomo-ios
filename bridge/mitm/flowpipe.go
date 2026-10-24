package mitm

// Body pipes of the native flow API (flow.go; design: work/native-mitm-design.md §12).
//
// A flowPipe carries one body between the native HTTP/1.1 session (Swift) and the Go code that runs the rules.
// Bytes only ever sit here in small pieces: a pipe holds at most flowPipeCap bytes, and all pipes together at
// most flowPipeBudget (the native side gets "full" and must drain first). Two directions:
//
//   - in-pipes (client request body, upstream response body): the native side pushes (FlowWrite / FlowClose),
//     Go reads as an io.Reader. While the flow's phase goroutine runs, a Go read blocks for data (and the first
//     such wait tells the native side "need-body"); after the phase it never blocks: a read with nothing
//     buffered returns errFlowWouldBlock, which FlowRead turns into state "more" (push the next chunk).
//   - out-pipes (a local response body Go is still writing, e.g. a large Map Local file): Go writes, blocking
//     while the pipe is full; the native side pulls with FlowRead, never blocking.
//
// Every wait is also woken by the flow's cancellation (client gone, FlowEnd, reaper).

import (
	"errors"
	"io"
	"sync/atomic"
)

// flowPipeCap: bytes one pipe buffers (two lane chunks: one being consumed, one arriving).
const flowPipeCap = 2 * laneChunk

// flowPipeBudget: bytes all pipes together may buffer; past it pushes report "full".
var flowPipeBudget int64 = 4 << 20

var (
	flowPipeBytes atomic.Int64 // bytes buffered in all pipes now
	flowPipePeak  atomic.Int64
)

// errFlowWouldBlock: a non-blocking read found nothing buffered and the writer still open.
var errFlowWouldBlock = errors.New("flow: would block")

// errFlowStopped: the reader no longer wants the body (it was replaced, or the flow answered locally).
var errFlowStopped = errors.New("flow: body no longer wanted")

type flowPipe struct {
	nf      *NativeFlow // its mu / cond guard every field below
	which   int         // flowReq / flowResp
	out     bool        // Go writes, native reads
	buf     []byte      // buffered bytes: a window into store
	store   []byte      // allocated on the first push (flowPipeCap), reused for the pipe's life
	closedW bool        // writer finished
	errW    error       // io.EOF or the writer's failure
	closedR bool        // reader gone: pushes are refused
	touched bool        // Go read from it at least once (an in-pipe)
	asked   bool        // "need-body" published for it
	total   int64       // bytes that went through
}

func newFlowPipe(nf *NativeFlow, which int, out bool) *flowPipe {
	return &flowPipe{nf: nf, which: which, out: out}
}

func (p *flowPipe) account(d int) {
	n := flowPipeBytes.Add(int64(d))
	for {
		pk := flowPipePeak.Load()
		if n <= pk || flowPipePeak.CompareAndSwap(pk, n) {
			break
		}
	}
	p.nf.held.Add(int64(d))
}

// room reports whether k more bytes fit (an empty pipe always takes one chunk, so a flow never starves).
func (p *flowPipe) room(k int) bool {
	if len(p.buf) == 0 {
		return true
	}
	return len(p.buf)+k <= flowPipeCap && flowPipeBytes.Load()+int64(k) <= flowPipeBudget
}

// push appends b (copied). block: wait for room while wait() says so. Results: "" taken, "full" not taken
// (drain or await first), "stop" the reader is gone (drop the rest of this body), "gone" the flow ended.
// Called with nf.mu held.
func (p *flowPipe) push(b []byte, wait func() bool) string {
	nf := p.nf
	for {
		switch {
		case nf.ctx.Err() != nil:
			return "gone"
		case p.closedR:
			return "stop"
		case p.closedW:
			return "stop"
		case p.room(len(b)):
			if len(b) > 0 {
				p.appendBuf(b)
				p.total += int64(len(b))
				p.account(len(b))
				nf.cond.Broadcast()
			}
			return ""
		case wait != nil && wait():
			nf.cond.Wait()
		default:
			return "full"
		}
	}
}

// appendBuf copies b behind the buffered bytes, reusing store (compacting it first) so a steady stream
// allocates nothing per chunk.
func (p *flowPipe) appendBuf(b []byte) {
	if cap(p.buf)-len(p.buf) < len(b) {
		need := len(p.buf) + len(b)
		if cap(p.store) < need {
			p.store = make([]byte, max(need, flowPipeCap))
		}
		n := copy(p.store, p.buf)
		p.buf = p.store[:n]
	}
	p.buf = append(p.buf, b...)
}

// closeWrite ends the body (err nil: clean end). Called with nf.mu held.
func (p *flowPipe) closeWrite(err error) {
	if p.closedW {
		return
	}
	p.closedW = true
	if err == nil {
		err = io.EOF
	}
	p.errW = err
	p.nf.cond.Broadcast()
}

// closeRead drops what is buffered and refuses further pushes. Called with nf.mu held.
func (p *flowPipe) closeRead() {
	if p.closedR {
		return
	}
	p.closedR = true
	if len(p.buf) > 0 {
		p.account(-len(p.buf))
	}
	p.buf, p.store = nil, nil
	p.nf.cond.Broadcast()
}

// pull copies buffered bytes into dst. block: wait for data while wait() says so. Called with nf.mu held.
func (p *flowPipe) pull(dst []byte, wait func() bool) (int, error) {
	nf := p.nf
	for {
		if len(p.buf) > 0 {
			k := copy(dst, p.buf)
			p.buf = p.buf[k:]
			if len(p.buf) == 0 {
				p.buf = p.store[:0]
			}
			p.account(-k)
			nf.cond.Broadcast()
			return k, nil
		}
		if p.closedR {
			return 0, errFlowStopped
		}
		if p.closedW {
			return 0, p.errW
		}
		if err := nf.ctx.Err(); err != nil {
			return 0, err
		}
		if wait == nil || !wait() {
			return 0, errFlowWouldBlock
		}
		nf.cond.Wait()
	}
}

// Read is the Go side of an in-pipe: it blocks only while the flow's phase goroutine runs (the first wait
// publishes "need-body" so the native side starts pushing).
func (p *flowPipe) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	nf := p.nf
	nf.mu.Lock()
	defer nf.mu.Unlock()
	nf.touch()
	if p.out {
		// the native side pulling a body Go is still writing: wait for it (Go's writer never waits on us)
		return p.pull(dst, func() bool { return true })
	}
	p.touched = true
	return p.pull(dst, func() bool {
		if !nf.phaseActive || nf.final {
			return false
		}
		if !p.asked {
			p.asked = true
			nf.publishLocked(flowDecision{Action: "need-body", Which: p.which})
		}
		return true
	})
}

// Close is the Go side giving up an in-pipe (the body was replaced, or fully read and closed).
func (p *flowPipe) Close() error {
	nf := p.nf
	nf.mu.Lock()
	p.closeRead()
	nf.mu.Unlock()
	return nil
}

// Write is the Go side of an out-pipe (a local response body): blocks while full, until the flow ends.
func (p *flowPipe) Write(b []byte) (int, error) {
	nf := p.nf
	nf.mu.Lock()
	defer nf.mu.Unlock()
	written := 0
	for len(b) > 0 {
		k := min(len(b), laneChunk)
		switch p.push(b[:k], func() bool { return true }) {
		case "":
			written += k
			b = b[k:]
		case "gone":
			return written, nf.ctx.Err()
		default:
			return written, errFlowStopped
		}
	}
	return written, nil
}
