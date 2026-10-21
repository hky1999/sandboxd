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
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// These exit gates backport the pidfd retirement algorithm from the current
// sandboxd checkpoint_process_linux.go. A pinned kernel handle, rather than
// disappearance of argv/exe, is the exit witness. Generation/admission fencing
// remains a separate prerequisite before these gates can back a reader receipt.
func stopFirecrackerProcessConfirmed(state firecrackerPersistedState, binary string) error {
	return stopFirecrackerReaderConfirmed("VMM", state.PID, func() bool {
		return firecrackerProcessMatches(state.PID, binary, state.APIPath, state.ID)
	})
}

func stopFirecrackerVirtioFSConfirmed(state *firecrackerVirtioFSState, binary string) error {
	if state == nil {
		return nil
	}
	return stopFirecrackerReaderConfirmed("virtiofsd", state.PID, func() bool {
		return firecrackerVirtioFSProcessMatches(state, binary)
	})
}

func stopFirecrackerReaderConfirmed(kind string, pid int, matches func() bool) error {
	if pid <= 1 {
		return fmt.Errorf("Firecracker %s pid %d is invalid; exit unconfirmed", kind, pid)
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open Firecracker %s pidfd: %w", kind, err)
	}
	defer unix.Close(fd)
	if !matches() {
		// Never signal a process whose native identity is unavailable. It
		// may be in exit teardown; only the pinned exit notification proves it.
		exited, err := waitFirecrackerRetirementExit(fd, 1500*time.Millisecond)
		if err != nil {
			return err
		}
		if !exited {
			return fmt.Errorf("Firecracker %s pid %d identity unavailable; exit unconfirmed", kind, pid)
		}
		return nil
	}
	for _, step := range []struct {
		signal unix.Signal
		wait   time.Duration
	}{{unix.SIGTERM, 500 * time.Millisecond}, {unix.SIGKILL, time.Second}} {
		if err := unix.PidfdSendSignal(fd, step.signal, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("signal Firecracker %s: %w", kind, err)
		}
		exited, err := waitFirecrackerRetirementExit(fd, step.wait)
		if err != nil {
			return err
		}
		if exited {
			return nil
		}
	}
	return fmt.Errorf("Firecracker %s pid %d did not exit after SIGKILL", kind, pid)
}

func waitFirecrackerRetirementExit(fd int, timeout time.Duration) (bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		milliseconds := 0
		if remaining > 0 {
			milliseconds = int((remaining + time.Millisecond - 1) / time.Millisecond)
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, err := unix.Poll(fds, milliseconds)
		if errors.Is(err, unix.EINTR) {
			if time.Now().Before(deadline) {
				continue
			}
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("poll Firecracker reader exit: %w", err)
		}
		if fds[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return false, fmt.Errorf("poll Firecracker reader exit: events %#x", fds[0].Revents)
		}
		return fds[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0, nil
	}
}
