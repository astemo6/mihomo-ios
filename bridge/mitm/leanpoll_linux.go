//go:build linux

package mitm

import "syscall"

type leanPollHandle = int

func leanPollOpen() (int, error) { return syscall.EpollCreate1(syscall.EPOLL_CLOEXEC) }

const leanEpollIn = syscall.EPOLLIN | syscall.EPOLLRDHUP | syscall.EPOLLONESHOT

func leanPollCtlArm(ep, fd int, known bool) error {
	ev := syscall.EpollEvent{Events: leanEpollIn, Fd: int32(fd)}
	op := syscall.EPOLL_CTL_ADD
	if known {
		op = syscall.EPOLL_CTL_MOD
	}
	err := syscall.EpollCtl(ep, op, fd, &ev)
	if err == syscall.ENOENT && known {
		err = syscall.EpollCtl(ep, syscall.EPOLL_CTL_ADD, fd, &ev)
	} else if err == syscall.EEXIST && !known {
		err = syscall.EpollCtl(ep, syscall.EPOLL_CTL_MOD, fd, &ev)
	}
	return err
}

func leanPollCtlDel(ep, fd int) { _ = syscall.EpollCtl(ep, syscall.EPOLL_CTL_DEL, fd, nil) }

func leanPollLoop(ep int) {
	evs := make([]syscall.EpollEvent, 64)
	for {
		n, err := syscall.EpollWait(ep, evs, -1)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return
		}
		for i := 0; i < n; i++ {
			leanPollDispatch(int(evs[i].Fd))
		}
	}
}
