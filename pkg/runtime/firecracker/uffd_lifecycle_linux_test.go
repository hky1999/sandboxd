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
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"golang.org/x/sys/unix"
)

// These tests drive the real gated spawn primitive and the real exit gate
// with owned shell-script children. No fake launch hook exists: every
// identity that reaches confirmFirecrackerUffdExit or the Delete/rollback/
// checkpoint paths was produced by the production launch flow.

// uffdSleepHandlerScript serves the socket path ($2 of the production
// argument vector) and stays alive until killed, standing in for a connected
// page-fault handler.
const uffdSleepHandlerScript = "#!/bin/sh\ntrap '' TERM\n: > \"$2\"\nexec sleep 300\n"

// uffdIdentityCheckHandlerScript additionally proves the ordering contract
// from inside the child: the permit is written only after the identity is
// fsynced, so an executed handler must already find its own PID and start
// time in the persisted state file ($4 via -remote, set by the fixture).
const uffdIdentityCheckHandlerScript = "#!/bin/sh\n" +
	"sock=$2\n" +
	"state=$4\n" +
	"fail=$6\n" +
	"pid=$$\n" +
	"start=$(cut -d' ' -f22 /proc/$pid/stat)\n" +
	"grep -q \"\\\"pid\\\": $pid,\" \"$state\" || { echo pid > \"$fail\"; exit 9; }\n" +
	"grep -q \"\\\"start_time\\\": $start,\" \"$state\" || { echo starttime > \"$fail\"; exit 9; }\n" +
	": > \"$sock\"\n" +
	"exec sleep 300\n"

// uffdMarkerHandlerScript touches a marker file ($1) so a test can observe
// whether the gated child ever executed.
const uffdMarkerHandlerScript = "#!/bin/sh\n: > \"$1\"\nexec sleep 300\n"

func uffdChildOutput(t *testing.T) *os.File {
	t.Helper()
	file, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func uffdKillRecordedChild(t *testing.T, record firecrackerUffdRecord) {
	t.Helper()
	pid := record.PID
	start, err := readFirecrackerProcessStartTime(pid)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if start != record.StartTime {
		return
	}
	if pid <= 1 {
		t.Fatalf("invalid recorded uffd pid %d", pid)
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if errors.Is(err, unix.ESRCH) {
		return
	}
	if err != nil {
		t.Fatalf("open pidfd for uffd child %d: %v", pid, err)
	}
	defer unix.Close(fd)
	if current, err := readFirecrackerProcessStartTime(pid); err != nil || current != record.StartTime {
		return
	}
	if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil &&
		!errors.Is(err, unix.ESRCH) {
		t.Fatalf("signal uffd child %d: %v", pid, err)
	}
	exited, err := waitProcessExitNotification(fd, 5*time.Second)
	if err != nil || !exited {
		t.Fatalf("uffd child %d did not exit: exited=%v err=%v", pid, exited, err)
	}
}

func uffdFileAppears(t *testing.T, path string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func TestGatedUffdChildCannotExecuteBeforePermit(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "handler")
	if err := os.WriteFile(bin, []byte(uffdMarkerHandlerScript), 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "ran")
	child, err := startGatedUffdChild(bin, []string{marker}, root, uffdChildOutput(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { uffdKillRecordedChild(t, firecrackerUffdRecord{PID: child.pid, StartTime: child.startTime}) })
	if child.pid <= 1 || child.startTime == 0 || child.bootID == "" {
		t.Fatalf("captured identity incomplete: %+v", child)
	}
	// The gate is held by this test: the child must not run while the permit
	// is outstanding, well past any plausible spawn latency.
	time.Sleep(300 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("gated child executed before the permit was written")
	}
	if err := child.releasePermit(); err != nil {
		t.Fatal(err)
	}
	if !uffdFileAppears(t, marker, 2*time.Second) {
		t.Fatal("child did not execute after the permit was written")
	}
}

func TestGatedUffdChildPermitEOFCannotRunBody(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "handler")
	if err := os.WriteFile(bin, []byte(uffdMarkerHandlerScript), 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "ran")
	child, err := startGatedUffdChild(bin, []string{marker}, root, uffdChildOutput(t))
	if err != nil {
		t.Fatal(err)
	}
	// Closing the gate without a permit models a daemon that dies (or fails)
	// before the identity is durable: the shell reads EOF and exits.
	child.holdPermit()
	if !child.waitExit(firecrackerUffdExitGrace) {
		t.Fatal("gated child did not exit after the permit was withheld")
	}
	// Safe to read after the reaper broadcast the completed Wait.
	if code := child.command.ProcessState.ExitCode(); code != 111 {
		t.Fatalf("withheld-permit exit code = %d, want 111", code)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("child executed although the permit was never sent")
	}
}

func TestGatedUffdChildWrongTokenCannotRunBody(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "handler")
	if err := os.WriteFile(bin, []byte(uffdMarkerHandlerScript), 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "ran")
	child, err := startGatedUffdChild(bin, []string{marker}, root, uffdChildOutput(t))
	if err != nil {
		t.Fatal(err)
	}
	// Write a wrong line through the real gate pipe: the shell program must
	// refuse it exactly like it refuses EOF.
	if _, err := child.permit.WriteString("not-the-permit\n"); err != nil {
		t.Fatal(err)
	}
	if err := child.permit.Close(); err != nil {
		t.Fatal(err)
	}
	if !child.waitExit(firecrackerUffdExitGrace) {
		t.Fatal("gated child did not exit after a wrong permit token")
	}
	if code := child.command.ProcessState.ExitCode(); code != 112 {
		t.Fatalf("wrong-token exit code = %d, want 112", code)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("child executed on a wrong permit token")
	}
}

// TestUffdLaunchPersistsIdentityBeforePermit proves the launch ordering from
// inside the executed handler: the permit is written only after the identity
// is fsynced, so the handler must already find its own PID and start time on
// disk. The -remote argument (normally the remote URL template) carries the
// state file path, and -cache carries the failure marker path.
func TestUffdLaunchPersistsIdentityBeforePermit(t *testing.T) {
	handler, instance, root := uffdLaunchFixture(t, "sbox-uffd-order", uffdIdentityCheckHandlerScript)
	statePath := filepath.Join(instance.state.BundlePath, firecrackerArtifactsDir, firecrackerStateFilename)
	failMarker := filepath.Join(root, "order-failed")
	handler.uffdRemoteURL = statePath
	handler.uffdCacheDir = root
	sockPath := filepath.Join(root, "order.sock")
	defer func() {
		if r := instance.snapshot().Uffd; r.PID > 1 {
			uffdKillRecordedChild(t, r)
		}
	}()
	if err := handler.launchUffdHandler(
		instance, "sbox-uffd-order", sockPath, filepath.Join(root, "memory"), root,
	); err != nil {
		if reason, readErr := os.ReadFile(failMarker); readErr == nil {
			t.Fatalf("handler did not find its identity on disk (%s): %v", reason, err)
		}
		t.Fatal(err)
	}
	if _, err := os.Stat(failMarker); err == nil {
		t.Fatal("handler reported a missing identity record")
	}
	record := instance.snapshot().Uffd
	if record.Phase != firecrackerUffdPhaseReady || record.PID <= 1 ||
		record.StartTime == 0 || record.BootID == "" || record.Socket != sockPath {
		t.Fatalf("ready record = %+v", record)
	}
	// The ready phase must be durable before the launch returned success.
	disk, err := readFirecrackerState(instance.state.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if disk.Uffd != record {
		t.Fatalf("durable record %+v does not match the ready record %+v", disk.Uffd, record)
	}
}

// uffdLaunchLiveHandler runs the production launch with a long-lived
// stand-in handler and returns the durable record identifying it.
func uffdLaunchLiveHandler(t *testing.T, handler *Handler, instance *firecrackerInstance, sockPath, stateDir string) firecrackerUffdRecord {
	t.Helper()
	if err := handler.launchUffdHandler(
		instance, instance.state.ID, sockPath, filepath.Join(stateDir, "memory"), stateDir,
	); err != nil {
		t.Fatal(err)
	}
	record := instance.snapshot().Uffd
	if record.Phase != firecrackerUffdPhaseReady || record.PID <= 1 ||
		record.StartTime == 0 || record.BootID == "" {
		t.Fatalf("live handler record = %+v", record)
	}
	t.Cleanup(func() { uffdKillRecordedChild(t, record) })
	return record
}

func TestUffdGateWaitsForChildExit(t *testing.T) {
	handler, instance, root := uffdLaunchFixture(t, "sbox-uffd-wait", uffdSleepHandlerScript)
	record := uffdLaunchLiveHandler(t, handler, instance, filepath.Join(root, "wait.sock"), root)
	fd := checkpointTestPidfd(t, record.PID)
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- confirmFirecrackerUffdExit(record) }()
	select {
	case err := <-done:
		t.Fatalf("gate returned %v while the handler was still running", err)
	case <-time.After(300 * time.Millisecond):
	}
	uffdKillRecordedChild(t, record)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("gate did not accept the handler exit: %v", err)
		}
	case <-time.After(firecrackerUffdExitGrace + 3*time.Second):
		t.Fatal("gate did not return after the handler exited")
	}
	if !checkpointTestExitReady(t, fd) {
		t.Fatal("gate returned before the kernel exit notification")
	}
	if elapsed := time.Since(start); elapsed < 300*time.Millisecond {
		t.Fatal("gate returned before the child exited")
	}
}

func TestUffdGateBirthMismatchDoesNotKillChild(t *testing.T) {
	handler, instance, root := uffdLaunchFixture(t, "sbox-uffd-birth", uffdSleepHandlerScript)
	record := uffdLaunchLiveHandler(t, handler, instance, filepath.Join(root, "birth.sock"), root)
	fd := checkpointTestPidfd(t, record.PID)
	mismatched := record
	mismatched.StartTime++
	start := time.Now()
	if err := confirmFirecrackerUffdExit(mismatched); err == nil {
		t.Fatal("gate accepted a mismatched birth identity as a confirmed exit")
	}
	if elapsed := time.Since(start); elapsed >= firecrackerUffdExitGrace {
		t.Fatalf("mismatch reported after the full grace window: %s", elapsed)
	}
	if checkpointTestExitReady(t, fd) {
		t.Fatal("a live process with a different birth was signalled or died")
	}
	if startTime, err := readFirecrackerProcessStartTime(record.PID); err != nil ||
		startTime != record.StartTime {
		t.Fatalf("recorded child changed identity: %d %v", startTime, err)
	}
}

func TestUffdGateDifferentBootProvesGoneWithoutSignal(t *testing.T) {
	handler, instance, root := uffdLaunchFixture(t, "sbox-uffd-boot", uffdSleepHandlerScript)
	record := uffdLaunchLiveHandler(t, handler, instance, filepath.Join(root, "boot.sock"), root)
	fd := checkpointTestPidfd(t, record.PID)
	otherBoot := record
	otherBoot.BootID = "11111111-1111-4111-8111-111111111111"
	if err := confirmFirecrackerUffdExit(otherBoot); err != nil {
		t.Fatalf("a record from a gone boot was not proven: %v", err)
	}
	if checkpointTestExitReady(t, fd) {
		t.Fatal("the boot check signalled a live process")
	}
}

func TestUffdGateGonePIDProvesExit(t *testing.T) {
	// A child that was spawned, waited for, and reaped: its PID is gone.
	command := exec.Command("/bin/true")
	if err := command.Run(); err != nil {
		t.Fatal(err)
	}
	bootID, err := readFirecrackerBootID()
	if err != nil {
		t.Fatal(err)
	}
	record := firecrackerUffdRecord{
		Version:   firecrackerUffdRecordVersion,
		Phase:     firecrackerUffdPhaseReady,
		PID:       command.Process.Pid,
		StartTime: 1,
		BootID:    bootID,
		Socket:    "/run/uffd.sock",
	}
	if err := confirmFirecrackerUffdExit(record); err != nil {
		t.Fatalf("a reaped handler pid was not proven gone: %v", err)
	}
}

func TestUffdGateRejectsUnprovableRecords(t *testing.T) {
	bootID, err := readFirecrackerBootID()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		record firecrackerUffdRecord
	}{
		{
			name: "unknown version",
			record: firecrackerUffdRecord{
				Version: 2, Phase: firecrackerUffdPhaseReady,
				PID: 42, StartTime: 1, BootID: bootID, Socket: "/run/uffd.sock",
			},
		},
		{
			name: "unknown phase",
			record: firecrackerUffdRecord{
				Version: 1, Phase: "running",
				PID: 42, StartTime: 1, BootID: bootID, Socket: "/run/uffd.sock",
			},
		},
		{
			name: "partial identity",
			record: firecrackerUffdRecord{
				Version: 1, Phase: firecrackerUffdPhaseReady,
				PID: 42, Socket: "/run/uffd.sock",
			},
		},
		{
			name: "intent only",
			record: firecrackerUffdRecord{
				Version: 1, Phase: firecrackerUffdPhasePending, Socket: "/run/uffd.sock",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := confirmFirecrackerUffdExit(test.record); err == nil {
				t.Fatal("an unprovable record was accepted as a confirmed exit")
			}
		})
	}
	// A zero record is the documented no-tracking case, not a malformed one.
	if err := confirmFirecrackerUffdExit(firecrackerUffdRecord{}); err != nil {
		t.Fatalf("zero record must not gate: %v", err)
	}
}

// TestUffdGateUsesPersistedStateOnly proves ownership does not depend on a
// process-local handle: the record is read back from the state file and gated
// without any cmd object.
func TestUffdGateUsesPersistedStateOnly(t *testing.T) {
	handler, instance, root := uffdLaunchFixture(t, "sbox-uffd-disk", uffdSleepHandlerScript)
	record := uffdLaunchLiveHandler(t, handler, instance, filepath.Join(root, "disk.sock"), root)
	disk, err := readFirecrackerState(instance.state.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if disk.Uffd != record {
		t.Fatalf("disk record %+v diverged from %+v", disk.Uffd, record)
	}
	fd := checkpointTestPidfd(t, record.PID)
	done := make(chan error, 1)
	go func() { done <- confirmFirecrackerUffdExit(disk.Uffd) }()
	select {
	case err := <-done:
		t.Fatalf("reconstructed gate returned %v while the handler ran", err)
	case <-time.After(300 * time.Millisecond):
	}
	uffdKillRecordedChild(t, record)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("reconstructed gate rejected a confirmed exit: %v", err)
		}
	case <-time.After(firecrackerUffdExitGrace + 3*time.Second):
		t.Fatal("reconstructed gate did not return after the handler exited")
	}
	if !checkpointTestExitReady(t, fd) {
		t.Fatal("gate returned before the kernel exit notification")
	}
}

func TestValidatePersistedStateUffdRecord(t *testing.T) {
	root := t.TempDir()
	handler := &Handler{
		sandboxRoot: filepath.Join(root, "containers"),
		storageRoot: filepath.Join(root, "filestore"),
		runtimeRoot: filepath.Join(root, "runtime"),
	}
	sandboxID := "sbox-uffd-state"
	bundlePath := filepath.Join(handler.sandboxRoot, sandboxID)
	storagePath := filepath.Join(handler.storageRoot, sandboxID)
	runtimePath := handler.runtimeDirectory(sandboxID)
	for _, path := range []string{bundlePath, storagePath, runtimePath} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	valid := firecrackerPersistedState{
		ID:          sandboxID,
		BundlePath:  bundlePath,
		APIPath:     filepath.Join(runtimePath, firecrackerAPISocket),
		VsockPath:   filepath.Join(runtimePath, firecrackerVsock),
		OverlayPath: filepath.Join(storagePath, "overlay.ext4"),
		Uffd: firecrackerUffdRecord{
			Version:   firecrackerUffdRecordVersion,
			Phase:     firecrackerUffdPhaseReady,
			PID:       4242,
			StartTime: 99,
			BootID:    "11111111-1111-4111-8111-111111111111",
			Socket:    handler.uffdSocketPath(sandboxID),
		},
	}
	if err := handler.validatePersistedState(sandboxID, bundlePath, valid); err != nil {
		t.Fatalf("valid state with a uffd record rejected: %v", err)
	}
	mutateSocket := func(state *firecrackerPersistedState) {
		state.Uffd.Socket = filepath.Join(t.TempDir(), "elsewhere.sock")
	}
	mutatePartial := func(state *firecrackerPersistedState) {
		state.Uffd.PID = 0
	}
	mutateVersion := func(state *firecrackerPersistedState) {
		state.Uffd.Version = 7
	}
	for name, mutate := range map[string]func(*firecrackerPersistedState){
		"socket":  mutateSocket,
		"partial": mutatePartial,
		"version": mutateVersion,
	} {
		t.Run(name, func(t *testing.T) {
			state := valid
			mutate(&state)
			if err := handler.validatePersistedState(sandboxID, bundlePath, state); err == nil {
				t.Fatalf("accepted an inconsistent uffd %s record: %+v", name, state.Uffd)
			}
		})
	}
	// The zero record (legacy state) stays loadable; it simply claims no
	// handler.
	legacy := valid
	legacy.Uffd = firecrackerUffdRecord{}
	if err := handler.validatePersistedState(sandboxID, bundlePath, legacy); err != nil {
		t.Fatalf("legacy state without a uffd record rejected: %v", err)
	}
}

// TestDeleteRetainsUntilUffdHandlerExits drives the full Delete flow: the
// VMM exit is confirmed, and the delete then blocks on the recorded uffd
// handler. Nothing may be retired — or signalled — while the handler lives;
// once it exits, the retry releases everything.
func TestDeleteRetainsUntilUffdHandlerExits(t *testing.T) {
	handler, instance := deleteExitFixture(t)
	startDeleteExitChild(t, handler, instance)
	bin := filepath.Join(t.TempDir(), "uffd-handler")
	if err := os.WriteFile(bin, []byte(uffdSleepHandlerScript), 0700); err != nil {
		t.Fatal(err)
	}
	handler.uffdHandlerBin = bin
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	record := uffdLaunchLiveHandler(
		t, handler, instance, handler.uffdSocketPath(instance.state.ID), filepath.Join(
			instance.state.BundlePath, firecrackerArtifactsDir,
		),
	)
	sandboxID := instance.state.ID
	bundlePath := instance.state.BundlePath
	start := time.Now()
	if err := handler.Delete(context.Background(), sandboxID); err == nil ||
		!containsAll(err.Error(), "uffd handler exit", "unconfirmed") {
		t.Fatalf("delete accepted an unconfirmed uffd handler exit: %v", err)
	}
	if elapsed := time.Since(start); elapsed < firecrackerUffdExitGrace {
		t.Fatalf("delete did not wait out the handler grace: %s", elapsed)
	}
	assertDeleteExitRetained(t, handler, sandboxID, bundlePath)
	if startTime, err := readFirecrackerProcessStartTime(record.PID); err != nil ||
		startTime != record.StartTime {
		t.Fatalf("delete signalled the live uffd handler: %d %v", startTime, err)
	}
	uffdKillRecordedChild(t, record)
	if err := handler.Delete(context.Background(), sandboxID); err != nil {
		t.Fatal(err)
	}
	assertDeleteExitReleased(t, handler, sandboxID, bundlePath)
}

// TestDeleteRecoveredStateGatesUffd reconstructs the instance from the
// persisted state alone — no in-memory mapping, no cmd handle — and requires
// the same uffd gate before retirement.
func TestDeleteRecoveredStateGatesUffd(t *testing.T) {
	handler, instance := deleteExitFixture(t)
	// Recovery looks up sandboxRoot/ID, unlike the mapped-only fixture.
	handler.sandboxRoot = filepath.Dir(instance.state.BundlePath)
	recoveredBundle := filepath.Join(handler.sandboxRoot, instance.state.ID)
	if err := os.Rename(instance.state.BundlePath, recoveredBundle); err != nil {
		t.Fatal(err)
	}
	instance.state.BundlePath = recoveredBundle
	startDeleteExitChild(t, handler, instance)
	bin := filepath.Join(t.TempDir(), "uffd-handler")
	if err := os.WriteFile(bin, []byte(uffdSleepHandlerScript), 0700); err != nil {
		t.Fatal(err)
	}
	handler.uffdHandlerBin = bin
	instance.state.Configured = true
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	record := uffdLaunchLiveHandler(
		t, handler, instance, handler.uffdSocketPath(instance.state.ID), filepath.Join(
			instance.state.BundlePath, firecrackerArtifactsDir,
		),
	)
	sandboxID := instance.state.ID
	bundlePath := instance.state.BundlePath
	// Model the daemon restart: only the durable record survives.
	handler.mu.Lock()
	delete(handler.instances, sandboxID)
	handler.mu.Unlock()
	if err := handler.Delete(context.Background(), sandboxID); err == nil ||
		!containsAll(err.Error(), "uffd handler exit", "unconfirmed") {
		t.Fatalf("recovered delete accepted an unconfirmed uffd exit: %v", err)
	}
	assertDeleteExitRetained(t, handler, sandboxID, bundlePath)
	uffdKillRecordedChild(t, record)
	if err := handler.Delete(context.Background(), sandboxID); err != nil {
		t.Fatal(err)
	}
	assertDeleteExitReleased(t, handler, sandboxID, bundlePath)
}

// uffdRollbackFixture builds an instance whose recorded VMM is provably gone
// (an owned, killed, unreaped child) plus a live production-launched uffd
// handler, so a rollback's only unconfirmed process is the handler.
func uffdRollbackFixture(t *testing.T, sandboxID string) (*Handler, *firecrackerInstance, firecrackerUffdRecord) {
	t.Helper()
	root := t.TempDir()
	bundlePath := filepath.Join(root, "bundle")
	if err := os.MkdirAll(filepath.Join(bundlePath, firecrackerArtifactsDir), 0700); err != nil {
		t.Fatal(err)
	}
	handler := &Handler{
		uffdHandlerBin: filepath.Join(root, "uffd-handler"),
		instances:      make(map[string]*firecrackerInstance),
	}
	if err := os.WriteFile(handler.uffdHandlerBin, []byte(uffdSleepHandlerScript), 0o700); err != nil {
		t.Fatal(err)
	}
	instance := &firecrackerInstance{
		state: firecrackerPersistedState{ID: sandboxID, BundlePath: bundlePath},
		done:  make(chan struct{}),
	}
	handler.instances[sandboxID] = instance
	command := startCheckpointPersistenceChild(t, handler, instance)
	stopCheckpointPersistenceChild(t, command)
	record := uffdLaunchLiveHandler(
		t, handler, instance, filepath.Join(root, sandboxID+".sock"),
		filepath.Join(bundlePath, firecrackerArtifactsDir),
	)
	return handler, instance, record
}

func TestStartRollbackRetainsOnUnconfirmedUffd(t *testing.T) {
	handler, instance, record := uffdRollbackFixture(t, "sbox-uffd-rollback")
	original := errors.New("injected restore failure")
	returned, retained := handler.rollbackStartedInstance(instance, original)
	if !retained {
		t.Fatal("rollback released a sandbox whose uffd handler is unconfirmed")
	}
	if !errors.Is(returned, runtimecore.ErrStartCleanupPending) {
		t.Fatalf("retained rollback lost the cleanup-pending sentinel: %v", returned)
	}
	if !errors.Is(returned, original) {
		t.Fatalf("retained rollback lost the original failure: %v", returned)
	}
	if instance.snapshot().Exited {
		t.Fatal("unconfirmed uffd exit finished the instance")
	}
	disk, err := readFirecrackerState(instance.state.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if disk.Uffd.PID != record.PID || disk.Uffd.Phase != firecrackerUffdPhaseReady {
		t.Fatalf("retained uffd record = %+v", disk.Uffd)
	}
	if startTime, err := readFirecrackerProcessStartTime(record.PID); err != nil ||
		startTime != record.StartTime {
		t.Fatalf("rollback signalled the live uffd handler: %d %v", startTime, err)
	}
	// Once the handler leaves, the same rollback confirms and cleans up.
	uffdKillRecordedChild(t, record)
	returned, retained = handler.rollbackStartedInstance(instance, original)
	if retained {
		t.Fatalf("rollback still pending after the handler exited: %v", returned)
	}
	if returned != original {
		t.Fatalf("confirmed rollback replaced the original failure: %v", returned)
	}
	if !instance.snapshot().Exited {
		t.Fatal("confirmed rollback left the instance unfinished")
	}
	handler.mu.RLock()
	_, mapped := handler.instances["sbox-uffd-rollback"]
	handler.mu.RUnlock()
	if mapped {
		t.Fatal("confirmed rollback left the instance mapped")
	}
}

func TestCheckpointFinishRetainsOnUnconfirmedUffd(t *testing.T) {
	handler, instance, record := uffdRollbackFixture(t, "sbox-uffd-checkpoint")
	instance.state.Configured = true
	before := instance.snapshot()
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	if err := handler.finishCheckpointedSandbox(instance, before, before.ID); err == nil ||
		!containsAll(err.Error(), "uffd handler exit", "unconfirmed") {
		t.Fatalf("checkpoint stop accepted an unconfirmed uffd exit: %v", err)
	}
	if instance.snapshot().Exited {
		t.Fatal("unconfirmed uffd exit finished the checkpointed instance")
	}
	disk, err := readFirecrackerState(instance.state.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if disk.Exited {
		t.Fatal("unconfirmed exit persisted a terminal checkpoint state")
	}
	if startTime, err := readFirecrackerProcessStartTime(record.PID); err != nil ||
		startTime != record.StartTime {
		t.Fatalf("checkpoint stop signalled the live uffd handler: %d %v", startTime, err)
	}
	uffdKillRecordedChild(t, record)
	if err := handler.finishCheckpointedSandbox(instance, before, before.ID); err != nil {
		t.Fatal(err)
	}
	disk, err = readFirecrackerState(instance.state.BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if !disk.Exited {
		t.Fatal("confirmed checkpoint exit was not persisted")
	}
}

func containsAll(value string, fragments ...string) bool {
	for _, fragment := range fragments {
		if !strings.Contains(value, fragment) {
			return false
		}
	}
	return true
}

func TestUffdGateGracefullyCancelsUnconnectedHandler(t *testing.T) {
	body := "#!/usr/bin/python3\nimport sys,signal\nsignal.signal(signal.SIGTERM, lambda *_: sys.exit(0))\nopen(sys.argv[2], 'w').close()\nsignal.pause()\n"
	h, i, root := uffdLaunchFixture(t, "sbox-graceful-uffd", body)
	record := uffdLaunchLiveHandler(t, h, i, filepath.Join(root, "graceful.sock"), root)
	fd := checkpointTestPidfd(t, record.PID)
	if err := confirmFirecrackerUffdExit(record); err != nil {
		t.Fatal(err)
	}
	if !checkpointTestExitReady(t, fd) {
		t.Fatal("graceful-stop gate returned before kernel exit")
	}
}
