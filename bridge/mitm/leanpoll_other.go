//go:build !linux && !darwin

package mitm

type leanPollHandle = int

func leanPollOpen() (int, error)          { return -1, errLeanNoPoller }
func leanPollCtlArm(int, int, bool) error { return errLeanNoPoller }
func leanPollCtlDel(int, int)             {}
func leanPollLoop(int)                    {}
