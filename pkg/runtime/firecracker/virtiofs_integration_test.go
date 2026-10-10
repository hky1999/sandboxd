//go:build linux && firecracker_integration

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
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPrepareFirecrackerVirtioFSSharedReadOnly(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires mount privileges")
	}
	root := t.TempDir()
	source := filepath.Join(root, "source")
	shared := filepath.Join(root, "shared")
	if err := os.Mkdir(source, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "data"), []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}
	state := &firecrackerVirtioFSState{
		SocketPath: filepath.Join(root, "virtiofs.sock"),
		SharedDir:  shared,
	}
	t.Cleanup(func() {
		if err := cleanupFirecrackerVirtioFS(state, "/nonexistent/virtiofsd"); err != nil {
			t.Errorf("cleanup virtio-fs staging: %v", err)
		}
	})
	if err := prepareFirecrackerVirtioFSShared(shared, []firecrackerVirtioFSExport{{
		Source: source, RelativePath: "rootfs",
	}}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(shared, "rootfs", "data"))
	if err != nil || string(data) != "content" {
		t.Fatalf("staged data = %q, %v", data, err)
	}
	err = os.WriteFile(filepath.Join(shared, "rootfs", "blocked"), []byte("write"), 0644)
	if !errors.Is(err, unix.EROFS) {
		t.Fatalf("write through read-only staging mount = %v", err)
	}
	if err := os.WriteFile(filepath.Join(source, "host-write"), []byte("ok"), 0644); err != nil {
		t.Fatalf("source unexpectedly became read-only: %v", err)
	}
}

func TestPrepareFirecrackerVirtioFSSharedMixedAccess(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires mount privileges")
	}
	root := t.TempDir()
	source := filepath.Join(root, "source")
	nested := filepath.Join(source, "nested")
	shared := filepath.Join(root, "shared")
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", nested, "tmpfs", 0, "size=1m"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount(nested, unix.MNT_DETACH) })
	state := &firecrackerVirtioFSState{SharedDir: shared, SocketPath: filepath.Join(root, "fs.sock")}
	t.Cleanup(func() {
		if err := cleanupFirecrackerVirtioFS(state, "/nonexistent/virtiofsd"); err != nil {
			t.Error(err)
		}
	})
	if err := prepareFirecrackerVirtioFSShared(shared, []firecrackerVirtioFSExport{
		{Source: source, RelativePath: "readonly"},
		{Source: source, RelativePath: "writable", Writable: true},
	}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"layout-change", "readonly/data", "readonly/nested/data"} {
		if err := os.WriteFile(filepath.Join(shared, path), []byte("blocked"), 0644); !errors.Is(err, unix.EROFS) {
			t.Fatalf("write to protected %s = %v", path, err)
		}
	}
	for _, path := range []string{"data", "nested/data"} {
		if err := os.WriteFile(filepath.Join(shared, "writable", path), []byte("guest-write"), 0644); err != nil {
			t.Fatal(err)
		}
		for _, view := range []string{source, filepath.Join(shared, "readonly")} {
			data, err := os.ReadFile(filepath.Join(view, path))
			if err != nil || string(data) != "guest-write" {
				t.Fatalf("read %s through %s = %q, %v", path, view, data, err)
			}
		}
	}
	if err := cleanupFirecrackerVirtioFS(state, "/nonexistent/virtiofsd"); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(source, "data")); err != nil || string(data) != "guest-write" {
		t.Fatalf("source lost after cleanup: %q, %v", data, err)
	}
}
