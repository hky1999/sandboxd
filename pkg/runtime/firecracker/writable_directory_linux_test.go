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
	"runtime"
	"testing"
	"time"

	"github.com/moby/sys/mountinfo"
	"golang.org/x/sys/unix"
)

func TestFirecrackerWritableAbortRetainsLiveProcessStorage(t *testing.T) {
	base := t.TempDir()
	id := "sbox-writable-abort"
	bundle := filepath.Join(base, "containers", id)
	if err := os.MkdirAll(filepath.Join(bundle, firecrackerArtifactsDir), 0700); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	handler := &Handler{binary: binary, storageRoot: filepath.Join(base, "local"), runtimeRoot: filepath.Join(base, "sockets"), instances: make(map[string]*firecrackerInstance)}
	apiPath := filepath.Join(handler.runtimeDirectory(id), firecrackerAPISocket)
	command := exec.Command(binary, "-test.run=^TestFirecrackerWritableProcessHelper$", "--", "--api-sock", apiPath, "--id", id)
	command.Env = append(os.Environ(), "SANDBOXD_FC_WRITABLE_PROCESS_HELPER=1")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { command.Process.Kill(); command.Wait() }()
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("helper readiness %q %v", line, err)
	}
	root := testWritableRoot(t, t.TempDir())
	handler.writableRoot = root
	ioPath, disk, owner, err := handler.prepareWritableOverlay(id, base)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ioPath, []byte("owned disk stays available"), 0600); err != nil {
		t.Fatal(err)
	}
	instance := &firecrackerInstance{state: firecrackerPersistedState{ID: id, PID: command.Process.Pid, APIPath: apiPath, BundlePath: bundle, OverlayPath: disk, WritableOwner: owner}, done: make(chan struct{})}
	handler.instances[id] = instance
	if err := handler.preserveRunningWritable(instance); err == nil {
		t.Fatal("accepted cleanup while the recorded process still matches")
	}
	state, err := readFirecrackerState(bundle)
	if err != nil || state.WritableOwner != owner || state.PID != command.Process.Pid {
		t.Fatalf("lost durable abort identity: %+v %v", state, err)
	}
	if data, err := os.ReadFile(disk); err != nil || string(data) != "owned disk stays available" {
		t.Fatalf("lost live-process disk: %q %v", data, err)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	command.Wait()
	if err := handler.preserveRunningWritable(instance); err != nil {
		t.Fatal("did not accept confirmed process exit", err)
	}
	if err := handler.Delete(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(disk); !os.IsNotExist(err) {
		t.Fatalf("owned disk not reclaimed after exit: %v", err)
	}
}

func TestFirecrackerWritableProcessHelper(t *testing.T) {
	if os.Getenv("SANDBOXD_FC_WRITABLE_PROCESS_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	fmt.Println("ready")
	time.Sleep(time.Minute)
}

func testWritableRoot(t *testing.T, path string) *firecrackerWritableRoot {
	t.Helper()
	dir, err := openWritableDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	id, err := writableMountID(dir)
	dir.Close()
	if err != nil {
		t.Fatal(err)
	}
	mounts, err := mountinfo.GetMounts(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, mount := range mounts {
		if mount.ID == id {
			root, err := openFirecrackerWritableRoot(path, mount.FSType)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { root.dir.Close() })
			return root
		}
	}
	t.Fatal("test directory has no mount")
	return nil
}

func TestFirecrackerWritableDirectoryConfiguration(t *testing.T) {
	if root, err := openFirecrackerWritableRoot("", ""); err != nil || root != nil {
		t.Fatalf("default: %v %v", root, err)
	}
	path := t.TempDir()
	for _, value := range [][2]string{{path, ""}, {"", "tmpfs"}, {"relative", "tmpfs"}, {"/", "tmpfs"}, {path, "wrong-filesystem"}, {filepath.Join(path, "missing"), "tmpfs"}} {
		if root, err := openFirecrackerWritableRoot(value[0], value[1]); err == nil {
			if root != nil {
				root.dir.Close()
			}
			t.Fatalf("accepted %q", value)
		}
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	root := testWritableRoot(t, path)
	if err := root.verify(); err != nil {
		t.Fatal(err)
	}
	if _, err := openFirecrackerWritableRoot(link, "tmpfs"); err == nil {
		t.Fatal("accepted symlink")
	}
	if _, err := root.create("../escape"); err == nil {
		t.Fatal("accepted traversal")
	}
}

func TestFirecrackerWritableDirectoryOwnershipAndPlacement(t *testing.T) {
	root := testWritableRoot(t, t.TempDir())
	local := t.TempDir()
	handler := &Handler{writableRoot: root}
	id := "sbox-writable-test"
	ioPath, path, owner, err := handler.prepareWritableOverlay(id, local)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) == local {
		t.Fatal("writable image remained local")
	}
	if err := os.WriteFile(ioPath, []byte("private disk"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(local, firecrackerVirtioFSMemory)); !os.IsNotExist(err) {
		t.Fatalf("unexpected memory relocation: %v", err)
	}
	state := firecrackerPersistedState{ID: id, OverlayPath: path, WritableOwner: owner}
	anchored, dir, err := handler.writableOverlay(state)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(anchored)
	dir.Close()
	if err != nil || string(data) != "private disk" {
		t.Fatalf("wrong disk: %q %v", data, err)
	}
	// A new daemon can open the same owned disk without cloning or replacing it.
	reopened := testWritableRoot(t, root.path)
	opened, err := reopened.openOwned(id, owner)
	if err != nil {
		t.Fatal(err)
	}
	opened.Close()
	if _, err := root.openOwned(id, "00000000000000000000000000000000"); err == nil {
		t.Fatal("accepted foreign generation")
	}
	marker := filepath.Join(filepath.Dir(path), writableOwnerFile)
	if err := os.WriteFile(marker, []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := root.cleanup(id, owner); err == nil {
		t.Fatal("deleted foreign ownership")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("lost disk on rejected cleanup", err)
	}
	if err := os.WriteFile(marker, []byte(owner+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := root.cleanup(id, owner); err != nil {
		t.Fatal(err)
	}
	if err := root.cleanup(id, owner); err != nil {
		t.Fatal("cleanup not idempotent", err)
	}
	defaultHandler := &Handler{}
	_, defaultPath, defaultOwner, err := defaultHandler.prepareWritableOverlay(id, local)
	if err != nil || defaultOwner != "" || defaultPath != filepath.Join(local, "overlay.ext4") {
		t.Fatalf("changed default: %q %q %v", defaultPath, defaultOwner, err)
	}
}

func TestFirecrackerWritableDeleteRetryAfterRestart(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "external")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	root := testWritableRoot(t, path)
	base := t.TempDir()
	id := "sbox-writable-delete"
	bundle := filepath.Join(base, "containers", id)
	local := filepath.Join(base, "storage", id)
	for _, dir := range []string{filepath.Join(bundle, firecrackerArtifactsDir), local} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	handler := &Handler{writableRoot: root, sandboxRoot: filepath.Dir(bundle), storageRoot: filepath.Dir(local), runtimeRoot: filepath.Join(base, "sockets"), instances: make(map[string]*firecrackerInstance)}
	ioPath, disk, owner, err := handler.prepareWritableOverlay(id, local)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ioPath, []byte("keep until confirmed cleanup"), 0600); err != nil {
		t.Fatal(err)
	}
	runtimeDir := handler.runtimeDirectory(id)
	instance := &firecrackerInstance{state: firecrackerPersistedState{ID: id, BundlePath: bundle, OverlayPath: disk, WritableOwner: owner, APIPath: filepath.Join(runtimeDir, firecrackerAPISocket), VsockPath: filepath.Join(runtimeDir, firecrackerVsock)}, done: make(chan struct{})}
	handler.instances[id] = instance
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+"-held"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := handler.Delete(context.Background(), id); err == nil {
		t.Fatal("cleanup accepted replaced directory")
	}
	if _, ok := handler.instances[id]; !ok {
		t.Fatal("discarded retry state")
	}
	if _, err := readFirecrackerState(bundle); err != nil {
		t.Fatal("lost persisted ownership", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+"-held", path); err != nil {
		t.Fatal(err)
	}
	restarted := &Handler{writableRoot: testWritableRoot(t, path), sandboxRoot: handler.sandboxRoot, storageRoot: handler.storageRoot, runtimeRoot: handler.runtimeRoot, instances: make(map[string]*firecrackerInstance)}
	if err := restarted.recoverInstances(); err != nil {
		t.Fatal(err)
	}
	if _, ok := restarted.instances[id]; !ok {
		t.Fatal("did not recover cleanup ownership")
	}
	if err := restarted.Delete(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(disk); !os.IsNotExist(err) {
		t.Fatalf("disk not removed: %v", err)
	}
}

func TestFirecrackerWritableMountReplacement(t *testing.T) {
	if os.Getenv("SANDBOXD_FC_WRITABLE_MOUNT_TEST") != "1" {
		t.Skip("requires a private privileged mount namespace")
	}
	command := exec.Command(os.Args[0], "-test.run=^TestFirecrackerWritableMountGuardHelper$", "-test.v")
	command.Env = append(os.Environ(), "SANDBOXD_FC_WRITABLE_MOUNT_HELPER=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("mount guard: %v\n%s", err, output)
	}
}

func TestFirecrackerWritableMountGuardHelper(t *testing.T) {
	if os.Getenv("SANDBOXD_FC_WRITABLE_MOUNT_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	runtime.LockOSThread()
	t.Cleanup(runtime.UnlockOSThread)
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	path := t.TempDir()
	if err := unix.Mount("tmpfs", path, "tmpfs", 0, "size=4m"); err != nil {
		t.Fatal(err)
	}
	layers := 1
	t.Cleanup(func() {
		for layers > 0 {
			if err := unix.Unmount(path, 0); err != nil {
				t.Errorf("unmount test layer: %v", err)
				return
			}
			layers--
		}
	})
	root := testWritableRoot(t, path)
	owner, err := root.create("sbox-mount-guard")
	if err != nil {
		t.Fatal(err)
	}
	disk, _ := root.overlayPath("sbox-mount-guard", owner)
	if err := os.WriteFile(disk, []byte("accepted mount"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", path, "tmpfs", 0, "size=4m"); err != nil {
		t.Fatal(err)
	}
	layers++
	if err := root.verify(); err == nil {
		t.Fatal("same-type replacement accepted")
	}
	if _, err := root.create("sbox-forbidden-fallback"); err == nil {
		t.Fatal("created file on replacement mount")
	}
	if err := root.cleanup("sbox-mount-guard", owner); err == nil {
		t.Fatal("cleanup succeeded on replacement mount")
	}
	if err := unix.Unmount(path, 0); err != nil {
		t.Fatal(err)
	}
	layers--
	if err := root.verify(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(disk); err != nil || string(data) != "accepted mount" {
		t.Fatalf("lost original disk: %q %v", data, err)
	}
	if err := root.cleanup("sbox-mount-guard", owner); err != nil {
		t.Fatal(err)
	}
}
