// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/moby/sys/mountinfo"
)

func testRunscWritableRoot(t *testing.T) *runscWritableRoot {
	t.Helper()
	path := t.TempDir()
	dir, err := openRunscWritableDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	id, err := runscWritableMountID(filepath.Join("/proc/self/fdinfo", strconv.FormatUint(uint64(dir.Fd()), 10)))
	dir.Close()
	if err != nil {
		t.Fatal(err)
	}
	mounts, err := mountinfo.GetMounts(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range mounts {
		if m.ID != id {
			continue
		}
		root, err := openRunscWritableRoot(path, m.FSType)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { root.dir.Close() })
		return root
	}
	t.Fatal("test directory mount missing")
	return nil
}

func TestRunscWritableRootRejectsUnavailableAndSubstitutedStorage(t *testing.T) {
	root := testRunscWritableRoot(t)
	for _, tc := range []struct{ path, fs string }{
		{"relative", "fuse.juicefs"}, {"/", "fuse.juicefs"}, {root.path, ""}, {"", "fuse.juicefs"},
		{filepath.Join(root.path, "missing"), "fuse.juicefs"}, {root.path, "not-the-mounted-filesystem"},
	} {
		if r, err := openRunscWritableRoot(tc.path, tc.fs); err == nil {
			if r != nil {
				r.dir.Close()
			}
			t.Errorf("accepted unavailable storage %q/%q", tc.path, tc.fs)
		}
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(root.path, alias); err != nil {
		t.Fatal(err)
	}
	if r, err := openRunscWritableRoot(alias, "fuse.juicefs"); err == nil {
		r.dir.Close()
		t.Fatal("accepted symlink")
	}
	old := root.path + "-original"
	if err := os.Rename(root.path, old); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(old) })
	if err := os.Mkdir(root.path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := root.verify(); err == nil {
		t.Fatal("accepted replacement directory on the same filesystem")
	}
	if _, err := os.Stat(filepath.Join(root.path, "missing")); !os.IsNotExist(err) {
		t.Fatal("validation created storage")
	}
}

func TestRunscWritableRootChecksAnonymousAndAdoptedDescriptors(t *testing.T) {
	root := testRunscWritableRoot(t)
	if err := root.verifyProcessFilestores(os.Getpid(), ""); err == nil {
		t.Fatal("accepted process with no private filestore")
	}
	f, err := os.CreateTemp(root.path, "runsc-filestore-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.Remove(f.Name()); err != nil {
		t.Fatal(err)
	}
	if err := root.verifyProcessFilestores(os.Getpid(), ""); err != nil {
		t.Fatal(err)
	}
	adopt := t.TempDir()
	a, err := os.CreateTemp(adopt, "runsc-filestore-adopt-")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err := os.Remove(a.Name()); err != nil {
		t.Fatal(err)
	}
	if err := root.verifyProcessFilestores(os.Getpid(), ""); err == nil {
		t.Fatal("accepted unrelated filestore without an adopted artifact")
	}
	if err := root.verifyProcessFilestores(os.Getpid(), adopt); err != nil {
		t.Fatal(err)
	}
	if err := root.verifyProcessFilestores(-1, adopt); err == nil {
		t.Fatal("accepted invalid process")
	}
}

func TestRunscWritableRootOverrideKeepsOtherRuntimeLocations(t *testing.T) {
	root := testRunscWritableRoot(t)
	mounts, err := mountinfo.GetMounts(nil)
	if err != nil {
		t.Fatal(err)
	}
	fs := ""
	for _, m := range mounts {
		if m.ID == root.mountID {
			fs = m.FSType
		}
	}
	cfg := config.Config{RootDir: filepath.Join(t.TempDir(), "sandboxd", "root")}
	cfg.RuntimeConfig.FilestoreDir = filepath.Join(t.TempDir(), "common-filestore")
	global := cfg.RuntimeConfig.FilestoreDir
	cfg.RuntimeConfig.Runsc.WritableStorageDir = root.path
	cfg.RuntimeConfig.Runsc.WritableStorageFilesystem = fs
	h, err := NewHandler(cfg, "/usr/local/bin/runsc", nil)
	if err != nil {
		t.Fatal(err)
	}
	c := h.runsc.(*Client)
	defer c.Options.writableRoot.dir.Close()
	if h.filestoreDir != root.path || c.Options.FilestoreDir != root.path {
		t.Fatal("runsc did not use dedicated writable storage")
	}
	if cfg.RuntimeConfig.FilestoreDir != global || cfg.RuntimeConfig.Firecracker.WritableStorageDir != "" {
		t.Fatal("override changed unrelated storage")
	}
}
