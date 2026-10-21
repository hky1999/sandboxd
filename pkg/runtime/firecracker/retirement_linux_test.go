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
	"time"

	"golang.org/x/sys/unix"
)

// This child provides native process identity, not a KVM/guest substitute.
func TestA1FCExitChild(t *testing.T) {
	if os.Getenv("AKERNEL_A1_FC_RETIREMENT_CHILD") != "1" {
		return
	}
	fmt.Println("ready")
	for {
		time.Sleep(time.Hour)
	}
}

func a1FCDeleteFixture(t *testing.T) (*Handler, *firecrackerInstance) {
	t.Helper()
	bundle := filepath.Join(t.TempDir(), "bundle")
	if err := os.MkdirAll(filepath.Join(bundle, firecrackerArtifactsDir), 0700); err != nil {
		t.Fatal(err)
	}
	handler := &Handler{runtimeRoot: t.TempDir(), storageRoot: t.TempDir(), instances: make(map[string]*firecrackerInstance)}
	instance := &firecrackerInstance{state: firecrackerPersistedState{ID: "a1-fc-delete", BundlePath: bundle}, done: make(chan struct{})}
	dir := handler.runtimeDirectory(instance.state.ID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	instance.state.APIPath = filepath.Join(dir, firecrackerAPISocket)
	instance.state.VsockPath = filepath.Join(dir, firecrackerVsock)
	overlayDir := filepath.Join(handler.storageRoot, instance.state.ID)
	if err := os.MkdirAll(overlayDir, 0700); err != nil {
		t.Fatal(err)
	}
	instance.state.OverlayPath = filepath.Join(overlayDir, "overlay.ext4")
	if err := os.WriteFile(instance.state.OverlayPath, []byte("private writable state"), 0600); err != nil {
		t.Fatal(err)
	}
	handler.instances[instance.state.ID] = instance
	return handler, instance
}

func a1FCChild(t *testing.T, handler *Handler, instance *firecrackerInstance, vmm bool) *exec.Cmd {
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
	command := exec.Command(binary, "-test.run=^TestA1FCExitChild$", "--")
	if vmm {
		command.Args = append(command.Args, "--api-sock", instance.state.APIPath, "--id", instance.state.ID)
	}
	command.Env = append(os.Environ(), "AKERNEL_A1_FC_RETIREMENT_CHILD=1")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("owned child readiness %q: %v", line, err)
	}
	if vmm {
		instance.state.PID = command.Process.Pid
		if !firecrackerProcessMatches(instance.state.PID, binary, instance.state.APIPath, instance.state.ID) {
			t.Fatal("owned VMM child native identity mismatch")
		}
	}
	return command
}

func a1FCPidfd(t *testing.T, pid int) int {
	t.Helper()
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

func a1FCExited(t *testing.T, fd int) bool {
	t.Helper()
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	if _, err := unix.Poll(fds, 0); err != nil {
		t.Fatal(err)
	}
	if fds[0].Revents&(unix.POLLNVAL|unix.POLLERR) != 0 {
		t.Fatalf("invalid pidfd events: %#x", fds[0].Revents)
	}
	return fds[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0
}

func a1FCAssertRetained(t *testing.T, handler *Handler, id, bundle string) {
	t.Helper()
	for _, path := range []string{filepath.Join(bundle, firecrackerArtifactsDir, firecrackerStateFilename), handler.runtimeDirectory(id), filepath.Join(handler.storageRoot, id, "overlay.ext4")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("reader artifact discarded: %s: %v", path, err)
		}
	}
	handler.mu.RLock()
	_, mapped := handler.instances[id]
	handler.mu.RUnlock()
	if !mapped {
		t.Fatal("instance removed before reader exit was confirmed")
	}
}

func a1FCAssertReleased(t *testing.T, handler *Handler, id, bundle string) {
	t.Helper()
	for _, path := range []string{filepath.Join(bundle, firecrackerArtifactsDir), handler.runtimeDirectory(id), filepath.Join(handler.storageRoot, id)} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("retired artifact still present: %s: %v", path, err)
		}
	}
	handler.mu.RLock()
	_, mapped := handler.instances[id]
	handler.mu.RUnlock()
	if mapped {
		t.Fatal("instance still mapped after confirmed cleanup")
	}
}

func TestA1FCDeleteConfirmsExitBeforeCleanup(t *testing.T) {
	handler, instance := a1FCDeleteFixture(t)
	a1FCChild(t, handler, instance, true)
	fd := a1FCPidfd(t, instance.state.PID)
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	id, bundle := instance.state.ID, instance.state.BundlePath
	if err := handler.Delete(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if !a1FCExited(t, fd) {
		t.Fatal("delete returned without the kernel exit notification")
	}
	a1FCAssertReleased(t, handler, id, bundle)
}

func TestA1FCDeleteRetainsUnrecognizedLiveProcess(t *testing.T) {
	handler, instance := a1FCDeleteFixture(t)
	a1FCChild(t, handler, instance, true)
	fd := a1FCPidfd(t, instance.state.PID)
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	id, bundle := instance.state.ID, instance.state.BundlePath
	instance.state.ID = id + "-unrecognized"
	if err := handler.Delete(context.Background(), id); err == nil {
		t.Fatal("delete accepted an unconfirmed live process")
	}
	if a1FCExited(t, fd) {
		t.Fatal("unrecognized process was signalled")
	}
	a1FCAssertRetained(t, handler, id, bundle)
}

func TestA1FCDeleteRetriesAfterIdentityRestored(t *testing.T) {
	handler, instance := a1FCDeleteFixture(t)
	a1FCChild(t, handler, instance, true)
	fd := a1FCPidfd(t, instance.state.PID)
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	id, bundle := instance.state.ID, instance.state.BundlePath
	instance.state.ID = id + "-unrecognized"
	if err := handler.Delete(context.Background(), id); err == nil {
		t.Fatal("delete accepted an unconfirmed live process")
	}
	a1FCAssertRetained(t, handler, id, bundle)
	instance.state.ID = id
	if err := handler.Delete(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if !a1FCExited(t, fd) {
		t.Fatal("retry returned without the kernel exit notification")
	}
	a1FCAssertReleased(t, handler, id, bundle)
}

func TestA1FCDeleteRejectsInvalidRecordedPID(t *testing.T) {
	for _, pid := range []int{-1, 0, 1} {
		t.Run(fmt.Sprintf("pid=%d", pid), func(t *testing.T) {
			handler, instance := a1FCDeleteFixture(t)
			instance.state.PID = pid
			if err := handler.persistInstance(instance); err != nil {
				t.Fatal(err)
			}
			id, bundle := instance.state.ID, instance.state.BundlePath
			if err := handler.Delete(context.Background(), id); err == nil {
				t.Fatal("delete accepted an invalid PID as exit evidence")
			}
			a1FCAssertRetained(t, handler, id, bundle)
		})
	}
}

func TestA1FCDeleteRetainsUnconfirmedVirtioFSReader(t *testing.T) {
	handler, instance := a1FCDeleteFixture(t)
	a1FCChild(t, handler, instance, true)
	vmmfd := a1FCPidfd(t, instance.state.PID)
	sidecar := a1FCChild(t, handler, instance, false)
	sidecarfd := a1FCPidfd(t, sidecar.Process.Pid)
	shared := t.TempDir()
	sentinel := filepath.Join(shared, "reader-file")
	if err := os.WriteFile(sentinel, []byte("shared export still referenced"), 0600); err != nil {
		t.Fatal(err)
	}
	instance.state.VirtioFS = &firecrackerVirtioFSState{PID: sidecar.Process.Pid, SocketPath: filepath.Join(shared, "vfs.sock"), SharedDir: shared}
	handler.virtiofsdPath = handler.binary
	if firecrackerVirtioFSProcessMatches(instance.state.VirtioFS, handler.virtiofsdPath) {
		t.Fatal("sidecar must intentionally have an unrecognized native identity")
	}
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	id, bundle := instance.state.ID, instance.state.BundlePath
	if err := handler.Delete(context.Background(), id); err == nil {
		t.Fatal("delete accepted an unconfirmed virtio-fs reader")
	}
	if !a1FCExited(t, vmmfd) {
		t.Fatal("VMM must have exited before the sidecar gate")
	}
	if a1FCExited(t, sidecarfd) {
		t.Fatal("unrecognized sidecar was signalled")
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("sidecar export removed before exit: %v", err)
	}
	a1FCAssertRetained(t, handler, id, bundle)
}
