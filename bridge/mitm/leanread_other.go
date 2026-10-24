//go:build !unix

package mitm

const leanSockets = false // no raw socket reads: every direction runs on a goroutine with a pooled buffer

func leanSysRead(uintptr, []byte) (int, error) { return 0, errLeanNoPoller }
