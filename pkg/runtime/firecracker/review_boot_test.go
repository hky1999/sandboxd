package firecracker

import (
	"os"
	"testing"
)

func TestReviewMalformedBootCannotAuthorizeExit(t *testing.T) {
	start, err := readFirecrackerProcessStartTime(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	for _, boot := range []string{"boot", " ", "00000000-0000-0000-0000-000000000000", "truncated"} {
		t.Run(boot, func(t *testing.T) {
			r := firecrackerUffdRecord{Version: firecrackerUffdRecordVersion, Phase: firecrackerUffdPhaseReady, PID: os.Getpid(), StartTime: start, BootID: boot, Socket: "/run/uffd.sock"}
			if err := confirmFirecrackerUffdExit(r); err == nil {
				t.Fatal("malformed boot authorized exit of the currently running test process")
			}
		})
	}
}
