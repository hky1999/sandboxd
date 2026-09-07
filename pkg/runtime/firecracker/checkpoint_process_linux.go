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

// stopFirecrackerProcessConfirmed stops the Firecracker process recorded in
// state and returns nil only after its exit is confirmed. It waits for the
// kernel's exit notification, not the disappearance of argv/exe, which can
// precede completion of exit teardown.
func stopFirecrackerProcessConfirmed(state firecrackerPersistedState, binary string) error {
	if state.PID <= 1 {
		// A missing or sentinel PID — including init itself — is an invalid
		// record, not evidence of an exit. Never probe or signal PID 1; a
		// caller that can repair the state may retry.
		return fmt.Errorf("Firecracker process pid %d is not a valid recorded pid; exit unconfirmed", state.PID)
	}
	fd, err := unix.PidfdOpen(state.PID, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open Firecracker process pidfd: %w", err)
	}
	defer unix.Close(fd)
	if !firecrackerProcessMatches(state.PID, binary, state.APIPath, state.ID) {
		// The original process may already be tearing down, or this PID may
		// belong to somebody else. Never signal an unrecognized process.
		exited, err := waitProcessExitNotification(fd, 1500*time.Millisecond)
		if err != nil {
			return err
		}
		if !exited {
			return fmt.Errorf("Firecracker process pid %d identity unavailable and exit unconfirmed", state.PID)
		}
		return nil
	}
	for _, step := range []struct {
		signal unix.Signal
		wait   time.Duration
	}{{unix.SIGTERM, 500 * time.Millisecond}, {unix.SIGKILL, time.Second}} {
		// The handle continues to refer to the same process even if its
		// numerical PID is recycled between the identity check and signal.
		if err := unix.PidfdSendSignal(fd, step.signal, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("signal Firecracker process: %w", err)
		}
		exited, err := waitProcessExitNotification(fd, step.wait)
		if err != nil {
			return err
		}
		if exited {
			return nil
		}
	}
	return fmt.Errorf("Firecracker process pid %d did not exit after SIGKILL", state.PID)
}

func waitProcessExitNotification(fd int, timeout time.Duration) (bool, error) {
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
			return false, fmt.Errorf("poll Firecracker process exit: %w", err)
		}
		if fds[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return false, fmt.Errorf("poll Firecracker process exit: events %#x", fds[0].Revents)
		}
		return fds[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0, nil
	}
}
