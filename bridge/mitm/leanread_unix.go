//go:build unix

package mitm

import "syscall"

const leanSockets = true

func leanSysRead(fd uintptr, b []byte) (int, error) { return syscall.Read(int(fd), b) }
