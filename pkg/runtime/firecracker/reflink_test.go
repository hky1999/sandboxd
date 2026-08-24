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
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func writeReflinkFixture(t *testing.T, path string, size int) {
	t.Helper()
	content := make([]byte, size)
	for i := range content {
		content[i] = byte(i)
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatalf("write reflink fixture: %v", err)
	}
}

func requireSameContent(t *testing.T, source, destination string) {
	t.Helper()
	sourceContent, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read reflink source: %v", err)
	}
	destinationContent, err := os.ReadFile(destination)
	if err != nil {
		t.Fatalf("read reflink destination: %v", err)
	}
	if string(sourceContent) != string(destinationContent) {
		t.Fatalf("clone content diverged: %d vs %d bytes",
			len(sourceContent), len(destinationContent))
	}
}

func TestCloneFileFallsBackWhenReflinkRejected(t *testing.T) {
	original := cloneFileIoctl
	cloneFileIoctl = func(_, _ *os.File) error { return syscall.EOPNOTSUPP }
	defer func() { cloneFileIoctl = original }()

	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	writeReflinkFixture(t, source, 3<<20)

	reflinked, err := cloneFile(source, filepath.Join(dir, "clone"))
	if err != nil {
		t.Fatalf("cloneFile fallback: %v", err)
	}
	if reflinked {
		t.Fatal("cloneFile reported reflink on injected EOPNOTSUPP")
	}
	requireSameContent(t, source, filepath.Join(dir, "clone"))
}

func TestCloneFileFailsOnUnexpectedIoctlError(t *testing.T) {
	original := cloneFileIoctl
	cloneFileIoctl = func(_, _ *os.File) error { return syscall.EIO }
	defer func() { cloneFileIoctl = original }()

	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	writeReflinkFixture(t, source, 4096)

	if _, err := cloneFile(source, filepath.Join(dir, "clone")); err == nil {
		t.Fatal("cloneFile swallowed an unexpected ioctl error")
	}
}

func TestCloneFileRequiresFreshDestination(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	writeReflinkFixture(t, source, 4096)
	destination := filepath.Join(dir, "clone")
	writeReflinkFixture(t, destination, 4096)

	if _, err := cloneFile(source, destination); err == nil {
		t.Fatal("cloneFile overwrote an existing destination")
	}
}

// TestCloneFileRealReflink exercises the true ioctl on whatever filesystem
// backs the test directory (the default test filesystem is usually not
// reflink-capable, so both outcomes are valid as long as the content
// matches). Point SANDBOXD_TEST_REFLINK_DIR at an XFS mount to also assert
// that the reflink path engages.
func TestCloneFileRealReflink(t *testing.T) {
	base := t.TempDir()
	if configured := os.Getenv("SANDBOXD_TEST_REFLINK_DIR"); configured != "" {
		base = filepath.Join(configured, "reflink-test")
		if err := os.MkdirAll(base, 0700); err != nil {
			t.Fatalf("create reflink test dir on %s: %v", configured, err)
		}
		defer os.RemoveAll(base)
	}
	source := filepath.Join(base, "source")
	writeReflinkFixture(t, source, 8<<20)

	destination := filepath.Join(base, "clone")
	reflinked, err := cloneFile(source, destination)
	if err != nil {
		t.Fatalf("cloneFile: %v", err)
	}
	requireSameContent(t, source, destination)
	t.Logf("cloneFile reflinked=%v", reflinked)

	if configured := os.Getenv("SANDBOXD_TEST_REFLINK_DIR"); configured != "" && !reflinked {
		t.Fatalf("reflink did not engage on %s", configured)
	}
}
