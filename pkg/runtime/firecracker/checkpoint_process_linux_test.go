// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package firecracker

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func checkpointTestPidfd(t *testing.T, pid int) int {
	t.Helper()
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

func checkpointTestExitReady(t *testing.T, fd int) bool {
	t.Helper()
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	if _, err := unix.Poll(fds, 0); err != nil {
		t.Fatal(err)
	}
	return fds[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0
}

func TestCheckpointStopRejectsUnconfirmedIdentity(t *testing.T) {
	handler, instance := checkpointPersistenceFixture(t)
	startCheckpointPersistenceChild(t, handler, instance)
	fd := checkpointTestPidfd(t, instance.state.PID)
	// Model identity becoming unavailable while the captured process still
	// exists. The helper must not mistake it for a completed exit or signal it.
	instance.state.ID = "unrecognized-source"
	before := instance.snapshot()
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	if err := handler.finishCheckpointedSandbox(instance, before, before.ID); err == nil {
		t.Fatal("checkpoint accepted an unconfirmed source exit")
	}
	if checkpointTestExitReady(t, fd) {
		t.Fatal("unrecognized process was stopped")
	}
	if instance.snapshot().Exited {
		t.Fatal("unconfirmed source marked exited")
	}
	disk, err := readFirecrackerState(before.BundlePath)
	if err != nil || disk.Exited {
		t.Fatalf("unconfirmed exit persisted: %+v %v", disk, err)
	}
}

func TestCheckpointStopConfirmsKernelExit(t *testing.T) {
	handler, instance := checkpointPersistenceFixture(t)
	startCheckpointPersistenceChild(t, handler, instance)
	fd := checkpointTestPidfd(t, instance.state.PID)
	before := instance.snapshot()
	if err := handler.finishCheckpointedSandbox(instance, before, before.ID); err != nil {
		t.Fatal(err)
	}
	if !checkpointTestExitReady(t, fd) {
		t.Fatal("checkpoint returned before kernel exit notification")
	}
}

func TestCheckpointExitPoll(t *testing.T) {
	handler, instance := checkpointPersistenceFixture(t)
	child := startCheckpointPersistenceChild(t, handler, instance)
	fd := checkpointTestPidfd(t, instance.state.PID)
	if exited, err := waitCheckpointProcessExit(fd, 10*time.Millisecond); exited || err != nil {
		t.Fatalf("live process: exited=%v error=%v", exited, err)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if exited, err := waitCheckpointProcessExit(fd, time.Second); !exited || err != nil {
		t.Fatalf("killed process: exited=%v error=%v", exited, err)
	}
	invalid, err := unix.Dup(fd)
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(invalid)
	if exited, err := waitCheckpointProcessExit(invalid, 0); exited || err == nil {
		t.Fatalf("invalid handle: exited=%v error=%v", exited, err)
	}
}
