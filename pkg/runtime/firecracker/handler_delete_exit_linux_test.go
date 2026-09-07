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
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// deleteExitFixture builds the handler state Delete touches: a mapped
// instance with a persisted state file, a runtime socket directory, and a
// writable-layer storage directory, all inside test-owned temporary roots.
func deleteExitFixture(t *testing.T) (*Handler, *firecrackerInstance) {
	t.Helper()
	bundlePath := filepath.Join(t.TempDir(), "bundle")
	if err := os.MkdirAll(filepath.Join(bundlePath, firecrackerArtifactsDir), 0700); err != nil {
		t.Fatal(err)
	}
	handler := &Handler{
		runtimeRoot: t.TempDir(),
		storageRoot: t.TempDir(),
		instances:   make(map[string]*firecrackerInstance),
	}
	instance := &firecrackerInstance{
		state: firecrackerPersistedState{
			ID:         "delete-exit-test",
			BundlePath: bundlePath,
		},
		done: make(chan struct{}),
	}
	runtimeDir := handler.runtimeDirectory(instance.state.ID)
	if err := os.Mkdir(runtimeDir, 0700); err != nil {
		t.Fatal(err)
	}
	instance.state.APIPath = filepath.Join(runtimeDir, firecrackerAPISocket)
	instance.state.VsockPath = filepath.Join(runtimeDir, firecrackerVsock)
	overlayDir := filepath.Join(handler.storageRoot, instance.state.ID)
	if err := os.Mkdir(overlayDir, 0700); err != nil {
		t.Fatal(err)
	}
	instance.state.OverlayPath = filepath.Join(overlayDir, "overlay.ext4")
	if err := os.WriteFile(instance.state.OverlayPath, []byte("overlay"), 0600); err != nil {
		t.Fatal(err)
	}
	handler.instances[instance.state.ID] = instance
	return handler, instance
}

// This owned child supplies native argv/exe identity, not KVM behavior. Actual
// delete/lifecycle validation is a separate VM acceptance requirement.
func startDeleteExitChild(t *testing.T, handler *Handler, instance *firecrackerInstance) *exec.Cmd {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatal(err)
	}
	handler.binary = binary
	command := handler.vmmCommand(instance.state.APIPath, instance.state.ID)
	command.Args = append([]string{binary, "-test.run=^TestVMMCommandProcessIdentity$", "--"}, command.Args[1:]...)
	command.Env = append(os.Environ(), "AKERNEL_VMM_COMMAND_CHILD=1")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("child readiness %q: %v", line, err)
	}
	instance.state.PID = command.Process.Pid
	if !firecrackerProcessMatches(instance.state.PID, binary, instance.state.APIPath, instance.state.ID) {
		t.Fatal("child identity mismatch")
	}
	return command
}

func assertDeleteExitRetained(t *testing.T, handler *Handler, sandboxID, bundlePath string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(
		bundlePath, firecrackerArtifactsDir, firecrackerStateFilename,
	)); err != nil {
		t.Fatalf("persisted state discarded: %v", err)
	}
	if _, err := os.Stat(handler.runtimeDirectory(sandboxID)); err != nil {
		t.Fatalf("runtime directory discarded: %v", err)
	}
	if _, err := os.Stat(filepath.Join(handler.storageRoot, sandboxID)); err != nil {
		t.Fatalf("writable layer discarded: %v", err)
	}
	handler.mu.RLock()
	_, mapped := handler.instances[sandboxID]
	handler.mu.RUnlock()
	if !mapped {
		t.Fatal("instance removed from handler map")
	}
}

func assertDeleteExitReleased(t *testing.T, handler *Handler, sandboxID, bundlePath string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(
		bundlePath, firecrackerArtifactsDir,
	)); !os.IsNotExist(err) {
		t.Fatalf("bundle artifacts still present: %v", err)
	}
	if _, err := os.Stat(handler.runtimeDirectory(sandboxID)); !os.IsNotExist(err) {
		t.Fatalf("runtime directory still present: %v", err)
	}
	if _, err := os.Stat(filepath.Join(handler.storageRoot, sandboxID)); !os.IsNotExist(err) {
		t.Fatalf("writable layer still present: %v", err)
	}
	handler.mu.RLock()
	_, mapped := handler.instances[sandboxID]
	handler.mu.RUnlock()
	if mapped {
		t.Fatal("instance still mapped after delete")
	}
}

func TestDeleteConfirmsExitBeforeCleanup(t *testing.T) {
	handler, instance := deleteExitFixture(t)
	startDeleteExitChild(t, handler, instance)
	fd := checkpointTestPidfd(t, instance.state.PID)
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	sandboxID := instance.state.ID
	bundlePath := instance.state.BundlePath
	if err := handler.Delete(context.Background(), sandboxID); err != nil {
		t.Fatal(err)
	}
	if !checkpointTestExitReady(t, fd) {
		t.Fatal("delete returned before the kernel exit notification")
	}
	assertDeleteExitReleased(t, handler, sandboxID, bundlePath)
}

func TestDeleteRejectsUnconfirmedIdentity(t *testing.T) {
	handler, instance := deleteExitFixture(t)
	startDeleteExitChild(t, handler, instance)
	fd := checkpointTestPidfd(t, instance.state.PID)
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	sandboxID := instance.state.ID
	bundlePath := instance.state.BundlePath
	apiPath := instance.state.APIPath
	binary := handler.binary
	// Model identity becoming unavailable while the captured process still
	// exists. Delete must not mistake that for a completed exit or signal it.
	instance.state.ID = sandboxID + "-unrecognized"
	if err := handler.Delete(context.Background(), sandboxID); err == nil {
		t.Fatal("delete accepted an unconfirmed process exit")
	}
	if checkpointTestExitReady(t, fd) {
		t.Fatal("unrecognized process was stopped")
	}
	if !firecrackerProcessMatches(instance.state.PID, binary, apiPath, sandboxID) {
		t.Fatal("owned child lost its native identity")
	}
	assertDeleteExitRetained(t, handler, sandboxID, bundlePath)
}

func TestDeleteRetriesAfterIdentityRestored(t *testing.T) {
	handler, instance := deleteExitFixture(t)
	startDeleteExitChild(t, handler, instance)
	fd := checkpointTestPidfd(t, instance.state.PID)
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	sandboxID := instance.state.ID
	bundlePath := instance.state.BundlePath
	instance.state.ID = sandboxID + "-unrecognized"
	if err := handler.Delete(context.Background(), sandboxID); err == nil {
		t.Fatal("delete accepted an unconfirmed process exit")
	}
	assertDeleteExitRetained(t, handler, sandboxID, bundlePath)
	instance.state.ID = sandboxID
	if err := handler.Delete(context.Background(), sandboxID); err != nil {
		t.Fatal(err)
	}
	if !checkpointTestExitReady(t, fd) {
		t.Fatal("retry returned before the kernel exit notification")
	}
	assertDeleteExitReleased(t, handler, sandboxID, bundlePath)
}

func TestDeleteRejectsInvalidRecordedPID(t *testing.T) {
	for _, pid := range []int{-1, 0, 1} {
		t.Run(fmt.Sprintf("pid=%d", pid), func(t *testing.T) {
			handler, instance := deleteExitFixture(t)
			instance.state.PID = pid
			if err := handler.persistInstance(instance); err != nil {
				t.Fatal(err)
			}
			sandboxID := instance.state.ID
			bundlePath := instance.state.BundlePath
			// A missing or sentinel PID is an invalid record, not a confirmed
			// exit; PID 1 in particular must never be probed or signalled.
			if err := handler.Delete(context.Background(), sandboxID); err == nil {
				t.Fatal("delete accepted an invalid recorded pid as a confirmed exit")
			}
			assertDeleteExitRetained(t, handler, sandboxID, bundlePath)
		})
	}
}
