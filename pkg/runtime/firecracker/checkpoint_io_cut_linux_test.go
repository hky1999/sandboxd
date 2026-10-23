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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/containerd/cgroups/v3"

	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
)

// This subprocess supplies the same executable/cmdline identity checked by
// Checkpoint. The Unix HTTP fixture below models a VMM completing an already
// submitted write when save_state drains its asynchronous block engine. This
// is a component regression, not a KVM or real io_uring fault-injection test.
func TestFirecrackerCaptureIdentityHelper(t *testing.T) {
	if os.Getenv("SANDBOXD_FC_CAPTURE_IDENTITY_HELPER") != "1" {
		return
	}
	time.Sleep(2 * time.Minute)
	os.Exit(0)
}

func TestFirecrackerCheckpointIncludesWriteCompletedDuringDeviceSave(t *testing.T) {
	if os.Getenv("SANDBOXD_FC_CAPTURE_IO_TEST") != "1" {
		t.Skip("explicitly enable inside a task-private writable cgroup namespace")
	}
	if cgroups.Mode() != cgroups.Unified {
		t.Fatal("explicit capture regression requires a private unified cgroup namespace")
	}
	for _, fallback := range []bool{false, true} {
		t.Run(fmt.Sprintf("force_copy_fallback=%t", fallback), func(t *testing.T) {
			if fallback {
				original := cloneFileIoctl
				cloneFileIoctl = func(_, _ *os.File) error { return syscall.EOPNOTSUPP }
				defer func() { cloneFileIoctl = original }()
			}
			testFirecrackerCaptureDeviceCompletion(t, false)
		})
	}
}

func TestFirecrackerCheckpointInvalidatesBaseAfterDiskCaptureFailure(t *testing.T) {
	if os.Getenv("SANDBOXD_FC_CAPTURE_IO_TEST") != "1" {
		t.Skip("explicitly enable inside a task-private writable cgroup namespace")
	}
	if cgroups.Mode() != cgroups.Unified {
		t.Fatal("explicit capture regression requires a private unified cgroup namespace")
	}
	original := cloneFileIoctl
	cloneFileIoctl = func(_, _ *os.File) error { return syscall.EIO }
	defer func() { cloneFileIoctl = original }()
	testFirecrackerCaptureDeviceCompletion(t, true)
}

func testFirecrackerCaptureDeviceCompletion(t *testing.T, failDiskCapture bool) {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "fc-io-cut-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	id := filepath.Base(root)
	sourceCgroup := "/" + id
	sourceCgroupDir := filepath.Join("/sys/fs/cgroup", id)
	if err := os.Mkdir(sourceCgroupDir, 0755); err != nil {
		t.Fatalf("create private source cgroup: %v", err)
	}
	checkpointCgroupDir := "/sys/fs/cgroup/sandboxd-firecracker-checkpoint"
	_, existedErr := os.Stat(checkpointCgroupDir)
	t.Cleanup(func() {
		if err := os.Remove(sourceCgroupDir); err != nil {
			t.Errorf("remove private source cgroup: %v", err)
		}
		if os.IsNotExist(existedErr) {
			if err := os.Remove(checkpointCgroupDir); err != nil && !os.IsNotExist(err) {
				t.Errorf("remove created checkpoint cgroup: %v", err)
			}
		}
	})
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(root, "api.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	process := exec.CommandContext(ctx, binary,
		"-test.run=^TestFirecrackerCaptureIdentityHelper$", "--",
		"--api-sock", socket, "--id", id)
	process.Env = append(os.Environ(), "SANDBOXD_FC_CAPTURE_IDENTITY_HELPER=1")
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = process.Process.Kill()
		_ = process.Wait()
	})
	if err := os.WriteFile(filepath.Join(sourceCgroupDir, "cgroup.procs"),
		[]byte(fmt.Sprint(process.Process.Pid)), 0600); err != nil {
		t.Fatal(err)
	}

	overlay := filepath.Join(root, "overlay.ext4")
	before := bytes.Repeat([]byte{0x41}, 64<<10)
	after := bytes.Repeat([]byte{0x42}, len(before))
	if err := os.WriteFile(overlay, before, 0600); err != nil {
		t.Fatal(err)
	}
	kernel := filepath.Join(root, "kernel")
	if err := os.WriteFile(kernel, []byte("fixture kernel identity"), 0600); err != nil {
		t.Fatal(err)
	}
	previousMemory := filepath.Join(root, "previous-memory")
	previousBytes := []byte("previous generation remains present")
	if err := os.WriteFile(previousMemory, previousBytes, 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/vm" && r.Method == http.MethodPatch {
			// Pausing the vCPUs leaves the write pending, as the pinned VMM does.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/snapshot/create" || r.Method != http.MethodPut {
			http.Error(w, "unexpected fixture endpoint", http.StatusBadRequest)
			return
		}
		var input struct {
			State  string `json:"snapshot_path"`
			Memory string `json:"mem_file_path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// The fixture's barrier: complete the pending operation before saving
		// its device completion and memory state. No timer or scheduler race.
		if err := os.WriteFile(overlay, after, 0600); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		completed := sha256.Sum256(after)
		state := []byte(hex.EncodeToString(completed[:]))
		for _, path := range []string{input.State, input.Memory} {
			if err := os.WriteFile(path, state, 0600); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	bundle := filepath.Join(root, "bundle")
	if err := os.MkdirAll(filepath.Join(bundle, firecrackerArtifactsDir), 0700); err != nil {
		t.Fatal(err)
	}
	instance := &firecrackerInstance{done: make(chan struct{}), state: firecrackerPersistedState{
		ID: id, PID: process.Process.Pid, APIPath: socket,
		VsockPath:   filepath.Join(root, "absent-guest-agent.sock"),
		OverlayPath: overlay, BundlePath: bundle,
		Configured: true, MemoryMiB: 128, Vcpus: 1,
		BaseMemoryPath: previousMemory,
	}}
	handler := &Handler{
		binary: binary, kernelPath: kernel,
		checkpointMode:      firecrackerCheckpointModeFull,
		instances:           map[string]*firecrackerInstance{id: instance},
		checkpointWriteback: &checkpointWritebackScheduler{queue: make(chan string, 1)},
	}
	destination := filepath.Join(root, "checkpoint")
	captureErr := handler.Checkpoint(ctx, runtimecore.CheckpointConfig{
		ID: id, Directory: destination, CgroupPath: sourceCgroup,
	})
	if failDiskCapture {
		if captureErr == nil || !strings.Contains(captureErr.Error(), "snapshot Firecracker writable layer") {
			t.Fatalf("disk failure error = %v", captureErr)
		}
		state := instance.snapshot()
		if !state.BaseMemoryLineageLost || state.BaseMemoryPath != "" || state.BaseMemoryIncremental {
			t.Fatal("consumed memory window was not invalidated after losing its disk")
		}
		prior, err := os.ReadFile(previousMemory)
		if err != nil || !bytes.Equal(prior, previousBytes) {
			t.Fatalf("previous generation was changed or lost: %v", err)
		}
		if !firecrackerProcessMatches(state.PID, binary, socket, id) {
			t.Fatal("source process disappeared after recoverable disk capture failure")
		}
		if _, err := os.Stat(filepath.Join(destination, firecrackerCheckpointManifestName)); !os.IsNotExist(err) {
			t.Fatalf("failed generation retained a manifest: %v", err)
		}
		return
	}
	if captureErr != nil {
		t.Fatalf("capture through real Handler.Checkpoint: %v", captureErr)
	}
	copy, err := os.ReadFile(filepath.Join(destination, firecrackerCheckpointOverlayName))
	if err != nil {
		t.Fatal(err)
	}
	memory, err := os.ReadFile(filepath.Join(destination, firecrackerCheckpointMemoryName))
	if err != nil {
		t.Fatal(err)
	}
	got := sha256.Sum256(copy)
	if hex.EncodeToString(got[:]) != string(memory) {
		t.Fatal("checkpoint disk omits a write already completed in saved device/memory state")
	}
	if !bytes.Equal(copy, after) {
		t.Fatal("checkpoint disk does not contain the completed operation")
	}
}
