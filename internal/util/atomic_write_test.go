package util

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Run this same binary under strace fsync fault injection to verify the
// post-rename failure contract, without changing production I/O functions.
func TestAtomicWritePublication(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "meta.pb")
	err := AtomicWriteFile(path, []byte("new metadata"), 0600)
	if os.Getenv("SANDBOXD_TEST_DIRSYNC_EIO") == "1" {
		if !errors.Is(err, syscall.EIO) {
			t.Fatalf("expected injected EIO, got %v", err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil || string(data) != "new metadata" {
		t.Fatalf("published content: %q, %v", data, readErr)
	}
	info, statErr := os.Stat(path)
	if statErr != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private file mode: %v, %v", info, statErr)
	}
	temps, globErr := filepath.Glob(filepath.Join(dir, ".tmp-*"))
	if globErr != nil || len(temps) != 0 {
		t.Fatalf("temporary files leaked: %v, %v", temps, globErr)
	}
}

func TestAtomicWriteFailedRenameCleansTemporary(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "occupied")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWriteFile(target, []byte("unpublished"), 0600); err == nil {
		t.Fatal("replaced directory")
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 || files[0].Name() != "occupied" {
		t.Fatalf("unexpected files: %v, %v", files, err)
	}
}

func TestSyncDirectoryRejectsFileAndMissingPath(t *testing.T) {
	dir := t.TempDir()
	if err := SyncDirectory(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "plain-file")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := SyncDirectory(path); err == nil {
		t.Fatal("accepted regular file")
	}
	if err := SyncDirectory(filepath.Join(dir, "absent")); err == nil {
		t.Fatal("accepted absent directory")
	}
}
