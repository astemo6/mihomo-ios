package mitm

// Shared readiness poller of the lean pipe (leanpipe.go): one epoll (Linux) / kqueue (Darwin, iOS) instance and
// one goroutine for the whole process, started on first use. A parked direction is registered one-shot for
// readability; the poller only calls fire(), which starts the copy on its own goroutine.

import "sync"

type leanPoller struct {
	mu   sync.Mutex
	dirs map[int]*leanDir // by fd
	reg  map[int]bool     // fd known to the kernel instance (epoll: ADD done)
	h    leanPollHandle
	ok   bool
}

var (
	leanPollOnce sync.Once
	leanPoll     leanPoller
)

func leanPollOK() bool {
	leanPollOnce.Do(func() {
		leanPoll.dirs = map[int]*leanDir{}
		leanPoll.reg = map[int]bool{}
		h, err := leanPollOpen()
		if err != nil {
			return
		}
		leanPoll.h, leanPoll.ok = h, true
		go leanPollLoop(h)
	})
	return leanPoll.ok
}

func leanPollArm(d *leanDir) error {
	if !leanPollOK() {
		return errLeanNoPoller
	}
	leanPoll.mu.Lock()
	defer leanPoll.mu.Unlock()
	leanPoll.dirs[d.fd] = d
	if err := leanPollCtlArm(leanPoll.h, d.fd, leanPoll.reg[d.fd]); err != nil {
		delete(leanPoll.dirs, d.fd)
		return err
	}
	leanPoll.reg[d.fd] = true
	return nil
}

// leanPollForget drops fd before it is closed.
func leanPollForget(fd int) {
	if !leanPollOK() {
		return
	}
	leanPoll.mu.Lock()
	defer leanPoll.mu.Unlock()
	if leanPoll.reg[fd] {
		leanPollCtlDel(leanPoll.h, fd)
	}
	delete(leanPoll.reg, fd)
	delete(leanPoll.dirs, fd)
}

func leanPollDispatch(fd int) {
	leanPoll.mu.Lock()
	d := leanPoll.dirs[fd]
	leanPoll.mu.Unlock()
	if d != nil {
		d.fire()
	}
}

type leanErr string

func (e leanErr) Error() string { return string(e) }

const errLeanNoPoller = leanErr("lean pipe: no poller")
