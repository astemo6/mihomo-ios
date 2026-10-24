//go:build darwin

package mitm

import "syscall"

type leanPollHandle = int

func leanPollOpen() (int, error) {
	kq, err := syscall.Kqueue()
	if err == nil {
		syscall.CloseOnExec(kq)
	}
	return kq, err
}

func leanPollCtlArm(kq, fd int, _ bool) error {
	var ch [1]syscall.Kevent_t
	syscall.SetKevent(&ch[0], fd, syscall.EVFILT_READ, syscall.EV_ADD|syscall.EV_ONESHOT)
	_, err := syscall.Kevent(kq, ch[:], nil, nil)
	return err
}

func leanPollCtlDel(kq, fd int) {
	var ch [1]syscall.Kevent_t
	syscall.SetKevent(&ch[0], fd, syscall.EVFILT_READ, syscall.EV_DELETE)
	_, _ = syscall.Kevent(kq, ch[:], nil, nil) // ENOENT once the one-shot fired: fine
}

func leanPollLoop(kq int) {
	evs := make([]syscall.Kevent_t, 64)
	for {
		n, err := syscall.Kevent(kq, nil, evs, nil)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return
		}
		for i := 0; i < n; i++ {
			if evs[i].Flags&syscall.EV_ERROR != 0 {
				continue
			}
			leanPollDispatch(int(evs[i].Ident))
		}
	}
}
