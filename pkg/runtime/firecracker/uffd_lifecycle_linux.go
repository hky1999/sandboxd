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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// firecrackerUffdPermitToken is the fixed single line the gated shell must
// read on its stdin before it may exec the handler binary.
const firecrackerUffdPermitToken = "akernel-uffd-permit-v1"

// firecrackerUffdGateScript is the gated shell's entire program: read exactly
// one permit line, and only then exec "$@". EOF on stdin (the parent closed
// the gate, or died) or a wrong token exits without executing anything. The
// handler binary and its arguments travel as positional parameters, never
// interpolated into this script.
const firecrackerUffdGateScript = `IFS= read -r token || exit 111
[ "$token" = "` + firecrackerUffdPermitToken + `" ] || exit 112
exec "$@"`

// gatedUffdChild is a uffd handler spawned behind its permit gate. The child
// is /bin/sh reading the gate script from stdin; until releasePermit writes
// the token, nothing beyond that shell exists.
type gatedUffdChild struct {
	command *exec.Cmd
	permit  *os.File
	// closeOnce makes the permit end exactly-once: exactly one of releasePermit
	// or holdPermit runs, whatever failure paths are taken.
	closeOnce sync.Once
	// pid, startTime and bootID are the kernel identity of the child, captured
	// while it is still blocked reading the gate. exec preserves PID and
	// starttime, so this stays the identity of the executed handler.
	pid       int
	startTime uint64
	bootID    string
	// waitDone is closed exactly once by the single cmd.Wait reaper below; it
	// is the only publication of the child's completion, so no other reader
	// ever touches cmd.ProcessState.
	waitDone chan struct{}
}

// startGatedUffdChild spawns the uffd handler binary behind the permit gate.
// On success the child is blocked in the gate: it executes nothing until
// releasePermit, and it exits by itself (EOF) after holdPermit or if this
// process dies. The caller receives the child's kernel identity, captured
// before the gate can open.
func startGatedUffdChild(
	binary string,
	arguments []string,
	dir string,
	output *os.File,
) (*gatedUffdChild, error) {
	// Standard Go os.Pipe: both ends close-on-exec, so the only descriptor
	// that survives into the child — and across its exec — is the dup the
	// runtime installs as the child's stdin.
	permitRead, permitWrite, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create uffd permit pipe: %w", err)
	}
	command := exec.Command("/bin/sh", append([]string{
		"-c", firecrackerUffdGateScript, "uffd-gate", binary,
	}, arguments...)...)
	command.Dir = dir
	command.Stdin = permitRead
	command.Stdout = output
	command.Stderr = output
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		_ = permitRead.Close()
		_ = permitWrite.Close()
		return nil, fmt.Errorf("start gated uffd child: %w", err)
	}
	// Drop the parent's read end: with only the write end held here, closing
	// it — deliberately or by this process dying — is the shell's EOF.
	_ = permitRead.Close()
	child := &gatedUffdChild{
		command:  command,
		permit:   permitWrite,
		pid:      command.Process.Pid,
		waitDone: make(chan struct{}),
	}
	// The single reaper: one cmd.Wait per child, and its completion is
	// broadcast by closing waitDone. Nothing else reads the process state.
	go func() {
		_ = command.Wait() //nolint:errcheck // exit status surfaces in its log
		close(child.waitDone)
	}()
	startTime, err := readFirecrackerProcessStartTime(child.pid)
	if err != nil {
		return child, child.abandon(fmt.Errorf(
			"capture gated uffd child %d identity: %w", child.pid, err,
		))
	}
	bootID, err := readFirecrackerBootID()
	if err != nil {
		return child, child.abandon(fmt.Errorf(
			"capture gated uffd child %d boot id: %w", child.pid, err,
		))
	}
	child.startTime = startTime
	child.bootID = bootID
	return child, nil
}

// releasePermit writes the permit line and closes the gate. After it returns
// the shell has (or will immediately) exec the handler; the handler inherits
// the child's PID and starttime, so the already-captured identity stays valid.
func (child *gatedUffdChild) releasePermit() error {
	var err error
	child.closeOnce.Do(func() {
		_, err = child.permit.WriteString(firecrackerUffdPermitToken + "\n")
		if closeErr := child.permit.Close(); err == nil {
			err = closeErr
		}
	})
	return err
}

// holdPermit closes the gate without a permit. The shell reads EOF and exits
// without executing anything.
func (child *gatedUffdChild) holdPermit() {
	child.closeOnce.Do(func() { _ = child.permit.Close() })
}

// waitExit waits for the single reaper to report the child's exit.
func (child *gatedUffdChild) waitExit(timeout time.Duration) bool {
	select {
	case <-child.waitDone:
		return true
	case <-time.After(timeout):
		return false
	}
}

// abandon withholds the permit and proves the child left by itself, so a
// caller reporting a capture failure never leaves an ungated child behind.
func (child *gatedUffdChild) abandon(reason error) error {
	child.holdPermit()
	if !child.waitExit(firecrackerUffdExitGrace) {
		return errors.Join(reason, errors.New(
			"gated uffd child did not exit after the withheld permit",
		))
	}
	return reason
}

func (record firecrackerUffdRecord) isZero() bool {
	return record == firecrackerUffdRecord{}
}

// validateFirecrackerUffdRecord accepts only complete, self-consistent
// identities: a pending record may be intent-only (no process identity), a
// ready record must carry the full identity, and a partial identity is never
// interpretable.
func validateFirecrackerUffdRecord(record firecrackerUffdRecord) error {
	if record.Version != firecrackerUffdRecordVersion {
		return fmt.Errorf("unsupported uffd record version %d", record.Version)
	}
	switch record.Phase {
	case firecrackerUffdPhasePending, firecrackerUffdPhaseReady:
	default:
		return fmt.Errorf("invalid uffd record phase %q", record.Phase)
	}
	if record.BootID != "" {
		parsed, err := uuid.Parse(record.BootID)
		if err != nil || parsed == uuid.Nil || parsed.String() != record.BootID {
			return errors.New("uffd record boot id must be a canonical nonzero UUID")
		}
	}
	if record.Socket == "" {
		return errors.New("uffd record carries no socket")
	}
	switch {
	case record.PID > 1 && record.StartTime > 0 && record.BootID != "":
		return nil
	case record.PID == 0 && record.StartTime == 0 && record.BootID == "" &&
		record.Phase == firecrackerUffdPhasePending:
		return nil
	default:
		return fmt.Errorf(
			"uffd record phase %q carries a partial identity (pid=%d start_time=%d boot=%q)",
			record.Phase, record.PID, record.StartTime, record.BootID,
		)
	}
}

// confirmFirecrackerUffdExit proves the recorded uffd handler exited and
// returns nil only on that proof. It is bound to the persisted identity — the
// kernel pidfd plus the recorded birth (starttime) and boot — never to argv
// inspection or a process-local cmd handle, so it works for a restarted
// daemon that is not the child's reaper. Only a pidfd ESRCH or a recorded
// boot that no longer exists prove the handler gone; a live PID with a
// different birth is neither proof about the original nor permission to
// touch the process under it, and a malformed record can prove nothing. The
// gate waits first for natural exit, then requests SIGTERM on the verified
// pidfd. The paired handler treats SIGTERM as cancellation and joins active
// work. There is no SIGKILL escalation: an unconfirmed exit retains ownership.
func confirmFirecrackerUffdExit(record firecrackerUffdRecord) error {
	if record.isZero() {
		// No handler is tracked: a fresh Start, a file-backend restore, or a
		// legacy state written before UFFD ownership existed. This nil claims
		// nothing about any untracked process; the compatibility limitation is
		// documented in doc/checkpoint-restore.md.
		return nil
	}
	if err := validateFirecrackerUffdRecord(record); err != nil {
		// A malformed record names no process, so it can never prove an exit.
		return fmt.Errorf("uffd handler record is unusable: %w", err)
	}
	if record.PID == 0 {
		// Intent-only: the launch never reached a durable child identity. No
		// handler can have executed — the permit is sent only after that
		// identity is fsynced — but the gated shell's own exit cannot be
		// proven without a PID, so retirement must stay pending.
		return errors.New(
			"uffd handler record carries intent only, no process identity; exit unconfirmed",
		)
	}
	bootID, err := readFirecrackerBootID()
	if err != nil {
		return fmt.Errorf("read boot id to confirm uffd handler exit: %w", err)
	}
	if record.BootID != bootID {
		// The record's host boot is gone; no process from it can still exist.
		return nil
	}
	fd, err := unix.PidfdOpen(record.PID, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		if errors.Is(err, unix.EINVAL) {
			// No task holds the recorded pid anymore. A numeric pid can
			// outlive its task as a process-group id — an orphaned descendant
			// of the dead group leader keeps it — and pidfd_open refuses such
			// a pid with EINVAL. Cross-check that /proc carries no task entry
			// either; only two agreeing kernel views prove the recorded
			// process gone.
			if _, statErr := readFirecrackerProcessStartTime(record.PID); os.IsNotExist(statErr) {
				return nil
			}
		}
		return fmt.Errorf("open uffd handler pidfd for pid %d: %w", record.PID, err)
	}
	defer unix.Close(fd)
	startTime, err := readFirecrackerProcessStartTime(record.PID)
	if err != nil {
		// The identity vanished between the pidfd open and this read: the
		// pinned handle still knows the truth.
		exited, waitErr := waitProcessExitNotification(fd, 100*time.Millisecond)
		if waitErr != nil {
			return waitErr
		}
		if exited {
			return nil
		}
		return fmt.Errorf(
			"uffd handler pid %d identity unavailable; exit unconfirmed", record.PID,
		)
	}
	if startTime != record.StartTime {
		// A live process under the recorded PID with a different birth is not
		// the recorded handler. This gate does not signal it, and it does not
		// treat the recycling as proof of the original's exit: the original's
		// outcome stays unknown.
		return fmt.Errorf(
			"uffd handler pid %d start time %d does not match the recorded %d; recorded process exit unconfirmed",
			record.PID, startTime, record.StartTime,
		)
	}
	// The pinned handle is the exact recorded process — still the gated shell
	// or the executed handler. The caller confirms the VMM first, so a
	// connected handler has seen its handshake drop; wait out its natural
	// exit. A handler that cannot leave by itself (for example one that never
	// saw the VMM handshake) receives graceful cancellation below.
	exited, err := waitProcessExitNotification(fd, firecrackerUffdExitGrace)
	if err != nil {
		return err
	}
	if exited {
		return nil
	}
	// The natural EOF grace expired. Revalidate the recorded birth before
	// signalling through the original pidfd; never signal a recycled PID.
	current, identityErr := readFirecrackerProcessStartTime(record.PID)
	if identityErr != nil || current != record.StartTime {
		if exited, err := waitProcessExitNotification(fd, 0); err == nil && exited {
			return nil
		}
		return fmt.Errorf("uffd handler identity unavailable before graceful stop; exit unconfirmed")
	}
	if err := unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("request uffd graceful stop: %w", err)
	}
	exited, err = waitProcessExitNotification(fd, firecrackerUffdExitGrace)
	if err != nil {
		return err
	}
	if exited {
		return nil
	}
	return fmt.Errorf(
		"uffd handler pid %d did not exit within %s; exit unconfirmed",
		record.PID, firecrackerUffdExitGrace,
	)
}

// readFirecrackerProcessStartTime returns /proc/<pid>/stat field 22, the
// process start time in clock ticks since boot. It survives execve, which is
// what makes it the birth identity of the gated shell and the handler it
// execs; it also disambiguates a recycled PID.
func readFirecrackerProcessStartTime(pid int) (uint64, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	closeParen := strings.LastIndexByte(string(data), ')')
	if closeParen < 0 || closeParen+2 >= len(data) {
		return 0, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	fields := strings.Fields(string(data[closeParen+2:]))
	// fields[0] is the process state (field 3 overall); starttime is field 22.
	if len(fields) < 20 {
		return 0, fmt.Errorf("short /proc/%d/stat", pid)
	}
	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse /proc/%d/stat start time: %w", pid, err)
	}
	return startTime, nil
}

// readFirecrackerBootID returns the current boot id, the boundary that makes
// a recorded identity from an earlier boot provably gone.
func readFirecrackerBootID() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	bootID := strings.TrimSpace(string(data))
	if bootID == "" {
		return "", errors.New("empty boot id")
	}
	return bootID, nil
}
