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

// stopFirecrackerProcessConfirmedBirth stops the exact process whose birth
// identity (PID plus /proc starttime, captured while it was alive) a
// checkpoint operation witness recorded, and returns nil only after that
// process's exit is confirmed. Birth is revalidated through the recorded PID
// before the pidfd is used to signal and again before every signal, so a
// PID-reused or next-generation process is never signalled; a recycled PID is
// not treated as proof of the original's exit either — the recorded process's
// outcome stays unknown and the caller retains its evidence.
func stopFirecrackerProcessConfirmedBirth(
	state firecrackerPersistedState,
	binary string,
	pid int,
	startTime uint64,
) error {
	if pid <= 1 {
		return fmt.Errorf("Firecracker process pid %d is not a valid recorded pid; exit unconfirmed", pid)
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open Firecracker process pidfd: %w", err)
	}
	defer unix.Close(fd)
	if err := confirmFirecrackerProcessBirth(pid, startTime, fd); err != nil {
		return err
	}
	if !firecrackerProcessMatches(pid, binary, state.APIPath, state.ID) {
		// The birth matches but argv/exe identity does not resolve: the
		// original process may already be tearing down. Never signal an
		// unrecognized process; wait out its exit notification instead.
		exited, err := waitProcessExitNotification(fd, 1500*time.Millisecond)
		if err != nil {
			return err
		}
		if !exited {
			return fmt.Errorf("Firecracker process pid %d identity unavailable and exit unconfirmed", pid)
		}
		return nil
	}
	for _, step := range []struct {
		signal unix.Signal
		wait   time.Duration
	}{{unix.SIGTERM, 500 * time.Millisecond}, {unix.SIGKILL, time.Second}} {
		// The handle continues to refer to the same process even if its
		// numerical PID is recycled between the identity checks and the
		// signal, and the birth revalidation refuses to signal any process
		// the recorded identity no longer describes.
		if err := confirmFirecrackerProcessBirth(pid, startTime, fd); err != nil {
			return err
		}
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
	return fmt.Errorf("Firecracker process pid %d did not exit after SIGKILL", pid)
}

// pinAliveFirecrackerProcessBirth proves the recorded birth identity still
// names a LIVE process and returns its pinned pidfd for re-confirmation. A
// source that is gone, exited, or running under a recycled PID proves no
// resumption and is refused: the caller must not claim it resumed the source.
func pinAliveFirecrackerProcessBirth(pid int, startTime uint64) (int, error) {
	if pid <= 1 {
		return -1, fmt.Errorf("Firecracker process pid %d is not a valid recorded pid", pid)
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if errors.Is(err, unix.ESRCH) {
		return -1, fmt.Errorf(
			"Firecracker process pid %d is gone; the recorded source is not alive", pid,
		)
	}
	if err != nil {
		return -1, fmt.Errorf("open Firecracker process pidfd: %w", err)
	}
	if err := confirmPinnedFirecrackerProcessBirth(pid, startTime, fd); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// confirmPinnedFirecrackerProcessBirth re-proves, against a pinned pidfd, that
// the recorded birth identity still names the same live process.
func confirmPinnedFirecrackerProcessBirth(pid int, startTime uint64, fd int) error {
	if err := confirmFirecrackerProcessBirth(pid, startTime, fd); err != nil {
		return err
	}
	exited, err := waitProcessExitNotification(fd, 0)
	if err != nil {
		return err
	}
	if exited {
		return fmt.Errorf(
			"Firecracker process pid %d already exited; the recorded source is not alive", pid,
		)
	}
	return nil
}

// confirmFirecrackerProcessBirth proves the PID still carries the recorded
// start time, consulting the pinned pidfd when the /proc entry has vanished
// between the two reads.
func confirmFirecrackerProcessBirth(pid int, startTime uint64, fd int) error {
	current, err := readFirecrackerProcessStartTime(pid)
	if err != nil {
		// The identity vanished between the pidfd open and this read: the
		// pinned handle still knows the truth.
		exited, waitErr := waitProcessExitNotification(fd, 0)
		if waitErr == nil && exited {
			return nil
		}
		return fmt.Errorf(
			"Firecracker process pid %d birth identity unavailable; exit unconfirmed", pid,
		)
	}
	if current != startTime {
		// A live process under the recorded PID with a different birth is
		// not the recorded source. Never signal it, and never treat the
		// recycling as proof of the original's exit.
		return fmt.Errorf(
			"Firecracker process pid %d now carries start time %d, not the recorded %d; refusing to signal a reused pid, recorded process exit unconfirmed",
			pid, current, startTime,
		)
	}
	return nil
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
