package libmihomo

import (
	"encoding/json"
	"errors"
	"testing"
)

type reloadStatusJS struct {
	Running   bool   `json:"running"`
	Seq       int64  `json:"seq"`
	Done      int64  `json:"done"`
	Kind      string `json:"kind"`
	LastError string `json:"lastError"`
	RunningMs int64  `json:"runningMs"`
}

func readReloadStatus(t *testing.T) reloadStatusJS {
	t.Helper()
	var s reloadStatusJS
	if err := json.Unmarshal([]byte(ReloadStatus()), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// fix/xmly-memory-2: the app asks for the reload state after a reply timed out (VPNManager.followUpReload).
func TestReloadStatusTracksRequests(t *testing.T) {
	s0 := readReloadStatus(t)
	end := reloadBegin("full")
	s1 := readReloadStatus(t)
	if !s1.Running || s1.Seq != s0.Seq+1 || s1.Done != s0.Done || s1.Kind != "full" {
		t.Fatalf("in progress: %+v (before %+v)", s1, s0)
	}
	end(errors.New("yaml: line 3"))
	s2 := readReloadStatus(t)
	if s2.Running || s2.Done != s0.Done+1 || s2.LastError != "yaml: line 3" {
		t.Fatalf("finished with error: %+v", s2)
	}
	reloadBegin("hot")(nil)
	s3 := readReloadStatus(t)
	if s3.Running || s3.Done != s0.Done+2 || s3.LastError != "" || s3.Kind != "hot" {
		t.Fatalf("finished ok: %+v", s3)
	}
}

// Reload / ReloadHot on a core that is not running still finish their record (and report the error).
func TestReloadStatusNotRunningCore(t *testing.T) {
	if IsRunning() {
		t.Skip("core running in this process")
	}
	s0 := readReloadStatus(t)
	if err := ReloadHot("/nonexistent/config.yaml"); err == nil {
		t.Fatal("ReloadHot without a core succeeded")
	}
	s1 := readReloadStatus(t)
	if s1.Running || s1.Done != s0.Done+1 || s1.LastError == "" {
		t.Fatalf("%+v", s1)
	}
}
