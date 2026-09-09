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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/errord"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"golang.org/x/sys/unix"
)

// claimTestBinding builds a distinct valid operation binding for claim tests;
// the caller pins the request digest through claimTestDigest.
func claimTestBinding(operationID, generation string) runtimecore.CheckpointOperationBinding {
	return runtimecore.CheckpointOperationBinding{
		OperationID:      operationID,
		SourceGeneration: generation,
	}
}

// claimTestDigest builds a deterministic strict hex64 digest for an operation,
// distinct per operation identity.
func claimTestDigest(operationID string) string {
	alphabet := "0123456789abcdef"
	seed := 0
	for _, r := range operationID {
		seed += int(r)
	}
	out := make([]byte, 0, 64)
	for i := 0; i < 64; i++ {
		out = append(out, alphabet[(seed+i)%16])
	}
	return string(out)
}

// claimTestDirectoryStats returns the dev/inode birth identity of a directory.
func claimTestDirectoryStats(t *testing.T, dir string) (uint64, uint64) {
	t.Helper()
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("no unix directory identity")
	}
	return uint64(stat.Dev), stat.Ino
}

// writeClaimRaw overwrites the claim file with arbitrary bytes, the shape a
// crash, a tamperer, or a foreign writer would leave behind.
func writeClaimRaw(t *testing.T, dir string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, firecrackerCheckpointClaimName()), data, 0600); err != nil {
		t.Fatal(err)
	}
}

// writeClaimJSON overwrites the claim file with an encoded claim value.
func writeClaimJSON(t *testing.T, dir string, claim firecrackerCheckpointClaim) {
	t.Helper()
	encoded, err := json.Marshal(claim)
	if err != nil {
		t.Fatal(err)
	}
	writeClaimRaw(t, dir, encoded)
}

// TestClaimDirectoryAcquiresNewAndExistingEmptyDirectories proves the claim
// lands at its final path in both a freshly created and a preexisting empty
// directory, is durably complete (a strict read returns the exact binding),
// and records the directory's real birth identity.
func TestClaimDirectoryAcquiresNewAndExistingEmptyDirectories(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, parent string) string
	}{
		{
			name: "new leaf",
			prepare: func(t *testing.T, parent string) string {
				return filepath.Join(parent, "checkpoint")
			},
		},
		{
			name: "existing empty directory",
			prepare: func(t *testing.T, parent string) string {
				dir := filepath.Join(parent, "checkpoint")
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				return dir
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			directory := tc.prepare(t, parent)
			binding := claimTestBinding("op-acquire", "gen-acquire")
			binding.RequestDigest = claimTestDigest("op-acquire")

			dev, inode, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding)
			if err != nil {
				t.Fatalf("claim = %v", err)
			}
			wantDev, wantInode := claimTestDirectoryStats(t, directory)
			if dev != wantDev || inode != wantInode {
				t.Fatalf("claimed identity (dev=%d inode=%d), directory carries (dev=%d inode=%d)",
					dev, inode, wantDev, wantInode)
			}
			claim, readErr := readFirecrackerCheckpointClaim(directory)
			if readErr != nil {
				t.Fatalf("strict read of the fresh claim = %v", readErr)
			}
			if claim.SandboxID != "sandbox-a" || claim.OperationID != binding.OperationID ||
				claim.RequestDigest != binding.RequestDigest ||
				claim.SourceGeneration != binding.SourceGeneration ||
				claim.Directory != filepath.Clean(directory) ||
				claim.DirectoryDev != dev || claim.DirectoryInode != inode {
				t.Fatalf("claim binding drifted: %+v", claim)
			}
		})
	}
}

// An invalid caller binding must be rejected before the exclusive file is
// created. Otherwise a malformed internal request could permanently poison an
// otherwise empty caller-owned directory with a claim no reader can validate.
func TestClaimDirectoryRejectsInvalidBindingBeforeCreation(t *testing.T) {
	directory := t.TempDir()
	binding := claimTestBinding("op-invalid", "gen-invalid")
	binding.RequestDigest = strings.ToUpper(claimTestDigest("op-invalid"))

	_, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding)
	if !errors.Is(err, errord.ErrInvalidArgument) {
		t.Fatalf("invalid binding = %v, want ErrInvalidArgument", err)
	}
	if _, statErr := os.Lstat(filepath.Join(directory, firecrackerCheckpointClaimName())); !os.IsNotExist(statErr) {
		t.Fatalf("invalid binding created a claim: %v", statErr)
	}
}

// TestClaimDirectorySameBindingIsIdempotent proves a retried operation
// re-enters its own claim: the second acquisition succeeds, changes nothing,
// and the claim bytes stay identical.
func TestClaimDirectorySameBindingIsIdempotent(t *testing.T) {
	directory := t.TempDir()
	binding := claimTestBinding("op-idem", "gen-idem")
	binding.RequestDigest = claimTestDigest("op-idem")

	if _, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(directory, firecrackerCheckpointClaimName()))
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 3; attempt++ {
		if _, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding); err != nil {
			t.Fatalf("idempotent re-entry %d = %v", attempt, err)
		}
	}
	// A differently spelled but canonically equal path re-enters the same
	// claim: the binding records the canonical directory, not the spelling.
	spelled := filepath.Join(directory, "sub", "..")
	if _, _, err := claimFirecrackerCheckpointDirectory(spelled, "sandbox-a", binding); err != nil {
		t.Fatalf("canonical re-entry = %v", err)
	}
	after, err := os.ReadFile(filepath.Join(directory, firecrackerCheckpointClaimName()))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("idempotent re-entry rewrote the claim:\nbefore: %s\nafter:  %s", before, after)
	}
}

// TestClaimDirectoryRefusesDifferentBinding proves a directory belongs to
// exactly one binding: a different operation, a different sandbox, and every
// individual field drift are all refused, and the refusal never touches the
// file on disk.
func TestClaimDirectoryRefusesDifferentBinding(t *testing.T) {
	directory := t.TempDir()
	binding := claimTestBinding("op-owner", "gen-owner")
	binding.RequestDigest = claimTestDigest("op-owner")
	if _, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(directory, firecrackerCheckpointClaimName()))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		sandbox string
		mutate  func(*runtimecore.CheckpointOperationBinding)
	}{
		{
			name:    "different operation",
			sandbox: "sandbox-a",
			mutate:  func(b *runtimecore.CheckpointOperationBinding) { b.OperationID = "op-other" },
		},
		{
			name:    "different sandbox",
			sandbox: "sandbox-b",
			mutate:  func(b *runtimecore.CheckpointOperationBinding) {},
		},
		{
			name:    "different request digest",
			sandbox: "sandbox-a",
			mutate:  func(b *runtimecore.CheckpointOperationBinding) { b.RequestDigest = claimTestDigest("op-other") },
		},
		{
			name:    "different source generation",
			sandbox: "sandbox-a",
			mutate:  func(b *runtimecore.CheckpointOperationBinding) { b.SourceGeneration = "gen-other" },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other := binding
			tc.mutate(&other)
			_, _, err := claimFirecrackerCheckpointDirectory(directory, tc.sandbox, other)
			if !errors.Is(err, errord.ErrFailedPrecondition) {
				t.Fatalf("foreign binding = %v, want ErrFailedPrecondition", err)
			}
			if !containsAll(err.Error(), "already claimed") {
				t.Fatalf("refusal must name the owning claim: %v", err)
			}
			if after, readErr := os.ReadFile(filepath.Join(directory, firecrackerCheckpointClaimName())); readErr != nil ||
				string(after) != string(before) {
				t.Fatalf("refused acquisition touched the claim on disk")
			}
		})
	}
}

// TestClaimDirectoryRefusesOnDiskBindingDrift proves a claim whose recorded
// fields drifted from the directory it sits in — including the birth identity
// a replaced directory would invalidate — is refused rather than repaired.
func TestClaimDirectoryRefusesOnDiskBindingDrift(t *testing.T) {
	directory := t.TempDir()
	binding := claimTestBinding("op-drift", "gen-drift")
	binding.RequestDigest = claimTestDigest("op-drift")
	if _, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding); err != nil {
		t.Fatal(err)
	}
	dev, inode := claimTestDirectoryStats(t, directory)
	valid := firecrackerCheckpointClaim{
		Version:          firecrackerCheckpointClaimVersion,
		SandboxID:        "sandbox-a",
		OperationID:      binding.OperationID,
		RequestDigest:    binding.RequestDigest,
		SourceGeneration: binding.SourceGeneration,
		Directory:        directory,
		DirectoryDev:     dev,
		DirectoryInode:   inode,
	}
	for _, tc := range []struct {
		name   string
		mutate func(*firecrackerCheckpointClaim)
	}{
		{
			name:   "directory string",
			mutate: func(c *firecrackerCheckpointClaim) { c.Directory = filepath.Join(c.Directory, "moved") },
		},
		{
			name:   "directory dev",
			mutate: func(c *firecrackerCheckpointClaim) { c.DirectoryDev++ },
		},
		{
			name:   "directory inode",
			mutate: func(c *firecrackerCheckpointClaim) { c.DirectoryInode++ },
		},
		{
			name:   "schema version",
			mutate: func(c *firecrackerCheckpointClaim) { c.Version = firecrackerCheckpointClaimVersion + 1 },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			drifted := valid
			tc.mutate(&drifted)
			writeClaimJSON(t, directory, drifted)
			before, _ := os.ReadFile(filepath.Join(directory, firecrackerCheckpointClaimName()))

			_, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding)
			if err == nil {
				t.Fatal("drifted claim admitted")
			}
			if after, readErr := os.ReadFile(filepath.Join(directory, firecrackerCheckpointClaimName())); readErr != nil ||
				string(after) != string(before) {
				t.Fatalf("drift refusal repaired or replaced the claim")
			}
			// Restore the valid claim so the next subtest starts clean.
			writeClaimJSON(t, directory, valid)
		})
	}
}

// TestClaimDirectoryRefusesCorruptClaims proves every unreadable shape fails
// closed without being deleted or rewritten: an empty file, truncated JSON,
// garbage, an unknown field, trailing content, and an over-sized file.
func TestClaimDirectoryRefusesCorruptClaims(t *testing.T) {
	oversize := append([]byte(strings.Repeat(" ", firecrackerCheckpointClaimMaxBytes+1)), []byte("{}")...)
	for _, tc := range []struct {
		name     string
		content  []byte
		fragment string
	}{
		{name: "empty file", content: nil, fragment: "outside the bounded regular-file shape"},
		{name: "truncated json", content: []byte(`{"version":1,"sandbox_id":"sandbox-a"`), fragment: "cannot be verified"},
		{name: "garbage", content: []byte("not json at all"), fragment: "cannot be verified"},
		{
			name:     "unknown field",
			content:  []byte(`{"version":1,"sandbox_id":"a","operation_id":"b","request_digest":"` + claimTestDigest("x") + `","source_generation":"g","directory":"/d","directory_dev":1,"directory_inode":2,"extra":true}`),
			fragment: "cannot be verified",
		},
		{
			name:     "trailing content",
			content:  []byte(`{"version":1,"sandbox_id":"a","operation_id":"b","request_digest":"` + claimTestDigest("x") + `","source_generation":"g","directory":"/d","directory_dev":1,"directory_inode":2} {"another":1}`),
			fragment: "trailing content",
		},
		{name: "oversize", content: oversize, fragment: "outside the bounded regular-file shape"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			binding := claimTestBinding("op-corrupt", "gen-corrupt")
			binding.RequestDigest = claimTestDigest("op-corrupt")
			writeClaimRaw(t, directory, tc.content)

			_, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding)
			if !errors.Is(err, errord.ErrFailedPrecondition) {
				t.Fatalf("corrupt claim = %v, want ErrFailedPrecondition", err)
			}
			if !containsAll(err.Error(), tc.fragment) {
				t.Fatalf("refusal must name the corruption: %v", err)
			}
			after, readErr := os.ReadFile(filepath.Join(directory, firecrackerCheckpointClaimName()))
			if readErr != nil || string(after) != string(tc.content) {
				t.Fatalf("corrupt claim was modified or removed by the refusal")
			}
			// The same corruption fails the standalone strict read.
			if _, readErr := readFirecrackerCheckpointClaim(directory); readErr == nil {
				t.Fatal("strict read accepted a corrupt claim")
			}
		})
	}
}

// TestClaimDirectoryRefusesSymlinkAndNonRegularClaims proves a symlink is
// never followed — not one pointing at a valid claim — and neither a
// directory nor a FIFO standing in for the claim is read.
func TestClaimDirectoryRefusesSymlinkAndNonRegularClaims(t *testing.T) {
	t.Run("symlink at the claim path", func(t *testing.T) {
		directory := t.TempDir()
		binding := claimTestBinding("op-link", "gen-link")
		binding.RequestDigest = claimTestDigest("op-link")
		target := t.TempDir()
		if _, _, err := claimFirecrackerCheckpointDirectory(target, "sandbox-a", binding); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(
			filepath.Join(target, firecrackerCheckpointClaimName()),
			filepath.Join(directory, firecrackerCheckpointClaimName()),
		); err != nil {
			t.Fatal(err)
		}

		_, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding)
		if !errors.Is(err, errord.ErrFailedPrecondition) {
			t.Fatalf("symlinked claim = %v, want ErrFailedPrecondition", err)
		}
		if !containsAll(err.Error(), "symbolic link") {
			t.Fatalf("refusal must name the link: %v", err)
		}
	})
	t.Run("directory at the claim path", func(t *testing.T) {
		directory := t.TempDir()
		binding := claimTestBinding("op-dir", "gen-dir")
		binding.RequestDigest = claimTestDigest("op-dir")
		if err := os.Mkdir(filepath.Join(directory, firecrackerCheckpointClaimName()), 0700); err != nil {
			t.Fatal(err)
		}

		_, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding)
		if !errors.Is(err, errord.ErrFailedPrecondition) {
			t.Fatalf("directory-as-claim = %v, want ErrFailedPrecondition", err)
		}
		if !containsAll(err.Error(), "not a regular file") {
			t.Fatalf("refusal must name the shape: %v", err)
		}
	})
	t.Run("fifo at the claim path", func(t *testing.T) {
		directory := t.TempDir()
		binding := claimTestBinding("op-fifo", "gen-fifo")
		binding.RequestDigest = claimTestDigest("op-fifo")
		if err := unix.Mkfifo(filepath.Join(directory, firecrackerCheckpointClaimName()), 0600); err != nil {
			t.Fatal(err)
		}

		_, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding)
		if !errors.Is(err, errord.ErrFailedPrecondition) {
			t.Fatalf("fifo-as-claim = %v, want ErrFailedPrecondition", err)
		}
	})
	t.Run("symlinked output directory", func(t *testing.T) {
		target := t.TempDir()
		parent := filepath.Dir(target)
		link := filepath.Join(parent, "checkpoint-link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		binding := claimTestBinding("op-dirlink", "gen-dirlink")
		binding.RequestDigest = claimTestDigest("op-dirlink")

		_, _, err := claimFirecrackerCheckpointDirectory(link, "sandbox-a", binding)
		if !errors.Is(err, errord.ErrFailedPrecondition) {
			t.Fatalf("symlinked output = %v, want ErrFailedPrecondition", err)
		}
		if !containsAll(err.Error(), "symbolic link") {
			t.Fatalf("refusal must name the link: %v", err)
		}
	})
}

// TestClaimDirectoryRefusesNonClaimEntries proves a new claim is never
// established over a directory that already holds anything else, while a
// same-binding claim beside such entries still re-enters idempotently — the
// layout-continuation shape whose components keep their own O_EXCL.
func TestClaimDirectoryRefusesNonClaimEntries(t *testing.T) {
	binding := claimTestBinding("op-stray", "gen-stray")
	binding.RequestDigest = claimTestDigest("op-stray")

	t.Run("stray file blocks a new claim", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.WriteFile(filepath.Join(directory, "stray"), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}

		_, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding)
		if !errors.Is(err, errord.ErrFailedPrecondition) {
			t.Fatalf("stray entry = %v, want ErrFailedPrecondition", err)
		}
		if !containsAll(err.Error(), "not an empty reserved directory") {
			t.Fatalf("refusal must name the emptiness boundary: %v", err)
		}
		if _, statErr := os.Lstat(filepath.Join(directory, firecrackerCheckpointClaimName())); !os.IsNotExist(statErr) {
			t.Fatalf("claim was created over non-claim entries: %v", statErr)
		}
	})
	t.Run("sealed artifact blocks a new claim", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.WriteFile(
			filepath.Join(directory, firecrackerCheckpointManifestName), []byte("{}"), 0600,
		); err != nil {
			t.Fatal(err)
		}

		_, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding)
		if !errors.Is(err, errord.ErrFailedPrecondition) {
			t.Fatalf("sealed directory = %v, want ErrFailedPrecondition", err)
		}
	})
	t.Run("same binding re-enters beside layout components", func(t *testing.T) {
		directory := t.TempDir()
		if _, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding); err != nil {
			t.Fatal(err)
		}
		// The shape of an interrupted layout after the claim was durable.
		if err := os.WriteFile(
			filepath.Join(directory, firecrackerCheckpointMemoryName), []byte("m"), 0600,
		); err != nil {
			t.Fatal(err)
		}

		if _, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding); err != nil {
			t.Fatalf("same-binding re-entry beside components = %v", err)
		}
		other := binding
		other.OperationID = "op-later"
		if _, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", other); !errors.Is(err, errord.ErrFailedPrecondition) {
			t.Fatalf("foreign binding beside components = %v, want ErrFailedPrecondition", err)
		}
	})
	t.Run("deleted claim beside entries is never re-established", func(t *testing.T) {
		directory := t.TempDir()
		if _, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			filepath.Join(directory, firecrackerCheckpointMemoryName), []byte("m"), 0600,
		); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(directory, firecrackerCheckpointClaimName())); err != nil {
			t.Fatal(err)
		}

		// Even the SAME binding may not re-claim: clearing a tombstone
		// requires deleting the whole checkpoint directory, not the file.
		_, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding)
		if !errors.Is(err, errord.ErrFailedPrecondition) {
			t.Fatalf("re-claim after claim deletion = %v, want ErrFailedPrecondition", err)
		}
		if !containsAll(err.Error(), "not an empty reserved directory") {
			t.Fatalf("refusal must name the emptiness boundary: %v", err)
		}
	})
	t.Run("whole-directory deletion clears the tombstone", func(t *testing.T) {
		parent := t.TempDir()
		directory := filepath.Join(parent, "checkpoint")
		if _, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(directory); err != nil {
			t.Fatal(err)
		}
		// A different operation may claim the recreated directory: the old
		// binding died with the explicit deletion.
		other := binding
		other.OperationID = "op-after-wipe"
		if _, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-b", other); err != nil {
			t.Fatalf("claim after whole-directory deletion = %v", err)
		}
	})
}

// TestClaimDirectoryConcurrentDistinctBindingsExactlyOneWins proves the
// exclusivity under real concurrency: many operations racing for one
// existing empty directory produce exactly one winner, and every loser is
// refused without touching the winner's claim.
func TestClaimDirectoryConcurrentDistinctBindingsExactlyOneWins(t *testing.T) {
	const contenders = 8
	directory := t.TempDir()
	bindings := make([]runtimecore.CheckpointOperationBinding, contenders)
	for i := range bindings {
		bindings[i] = runtimecore.CheckpointOperationBinding{
			OperationID:      fmt.Sprintf("op-race-%d", i),
			RequestDigest:    claimTestDigest(fmt.Sprintf("op-race-%d", i)),
			SourceGeneration: "gen-race",
		}
	}
	start := make(chan struct{})
	results := make([]error, contenders)
	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, _, results[i] = claimFirecrackerCheckpointDirectory(
				directory, fmt.Sprintf("sandbox-%d", i), bindings[i],
			)
		}(i)
	}
	close(start)
	wg.Wait()

	winners := 0
	for i, err := range results {
		if err == nil {
			winners++
			continue
		}
		if !errors.Is(err, errord.ErrFailedPrecondition) {
			t.Fatalf("contender %d refused with the wrong error class: %v", i, err)
		}
	}
	if winners != 1 {
		t.Fatalf("exactly one contender must win, got %d (results: %v)", winners, results)
	}
	// The surviving claim is complete and belongs to the winner.
	claim, err := readFirecrackerCheckpointClaim(directory)
	if err != nil {
		t.Fatalf("winner's claim is not strictly readable: %v", err)
	}
	found := false
	for i, binding := range bindings {
		if claim.OperationID == binding.OperationID &&
			claim.RequestDigest == binding.RequestDigest &&
			claim.SandboxID == fmt.Sprintf("sandbox-%d", i) {
			found = true
		}
	}
	if !found {
		t.Fatalf("surviving claim binds no contender: %+v", claim)
	}
}

// TestClaimDirectoryConcurrentSameBindingLeavesOneDurableClaim proves the
// same-binding race stays exclusive and honest: exactly one contender creates
// the claim, a contender that hits the creation window mid-write is refused
// fail-closed (a half-written claim is never re-entered, same binding
// included), the surviving claim is strictly valid, and a sequential re-entry
// AFTER the race is idempotent for every contender.
func TestClaimDirectoryConcurrentSameBindingLeavesOneDurableClaim(t *testing.T) {
	const contenders = 8
	directory := t.TempDir()
	binding := claimTestBinding("op-same", "gen-same")
	binding.RequestDigest = claimTestDigest("op-same")
	start := make(chan struct{})
	results := make([]error, contenders)
	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, _, results[i] = claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding)
		}(i)
	}
	close(start)
	wg.Wait()
	succeeded, refused := 0, 0
	for i, err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, errord.ErrFailedPrecondition):
			// The only legal refusal is the fail-closed unreadable-claim
			// shape: the winner was still mid-write. A same-binding racer
			// must never be told the directory belongs to someone else.
			if !containsAll(err.Error(), "cannot be verified") {
				t.Fatalf("contender %d refused with a foreign-owner error: %v", i, err)
			}
			refused++
		default:
			t.Fatalf("contender %d failed with an unexpected error class: %v", i, err)
		}
	}
	if succeeded < 1 || succeeded+refused != contenders {
		t.Fatalf("race outcome: %d succeeded, %d refused, want >=1 success of %d", succeeded, refused, contenders)
	}
	claim, err := readFirecrackerCheckpointClaim(directory)
	if err != nil {
		t.Fatalf("claim after the race is not strictly readable: %v", err)
	}
	if claim.OperationID != binding.OperationID || claim.SandboxID != "sandbox-a" {
		t.Fatalf("surviving claim binds the wrong operation: %+v", claim)
	}
	// After the claim is durable, the same binding re-enters idempotently.
	if _, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding); err != nil {
		t.Fatalf("sequential same-binding re-entry after the race = %v", err)
	}
}

// TestClaimDirectoryReplacementAndDeletionFailClosed proves the acquisition is
// anchored to the exact directory inode: a directory removed or replaced
// between the descriptor open and the pathname re-verification fails closed —
// the claim never lands against a stale name, and the pathname is never
// reported as claimed by this binding. The injection window is the
// deterministic seam right after the descriptor is opened.
func TestClaimDirectoryReplacementAndDeletionFailClosed(t *testing.T) {
	binding := claimTestBinding("op-replace", "gen-replace")
	binding.RequestDigest = claimTestDigest("op-replace")
	inject := func(t *testing.T, mutate func(canonical string)) {
		t.Helper()
		previous := firecrackerClaimDirectoryOpenedHook
		firecrackerClaimDirectoryOpenedHook = mutate
		t.Cleanup(func() { firecrackerClaimDirectoryOpenedHook = previous })
	}
	for _, tc := range []struct {
		name     string
		claimed  bool // seed an exact existing claim before the injection
		mutate   func(t *testing.T, canonical string)
		fragment string
	}{
		{
			name:    "replaced before a new claim",
			claimed: false,
			mutate: func(t *testing.T, canonical string) {
				// Move the anchored directory aside and put a fresh one at
				// the pathname: the descriptor keeps referring to the moved
				// original, the pathname now resolves to a different inode.
				if err := os.Rename(canonical, canonical+".moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(canonical, 0700); err != nil {
					t.Fatal(err)
				}
			},
			fragment: "replaced while it was being claimed",
		},
		{
			name:    "deleted before a new claim",
			claimed: false,
			mutate: func(t *testing.T, canonical string) {
				if err := os.Remove(canonical); err != nil {
					t.Fatal(err)
				}
			},
			fragment: "refusing fail-closed",
		},
		{
			name:    "replaced before a re-entry",
			claimed: true,
			mutate: func(t *testing.T, canonical string) {
				if err := os.Rename(canonical, canonical+".moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(canonical, 0700); err != nil {
					t.Fatal(err)
				}
			},
			fragment: "replaced while it was being claimed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			directory := filepath.Join(parent, "checkpoint")
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			if tc.claimed {
				if _, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding); err != nil {
					t.Fatal(err)
				}
			}
			inject(t, func(canonical string) { tc.mutate(t, canonical) })

			_, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding)
			if !errors.Is(err, errord.ErrFailedPrecondition) {
				t.Fatalf("replaced/deleted directory = %v, want ErrFailedPrecondition", err)
			}
			if !containsAll(err.Error(), tc.fragment) {
				t.Fatalf("refusal must name the replacement boundary: %v", err)
			}
			// The refused attempt's claim never published at the pathname:
			// the descriptor-anchored write landed in the moved original
			// (still holding the pre-seeded or freshly written claim), while
			// the pathname resolves to the replacement or to nothing.
			if info, statErr := os.Lstat(directory); statErr == nil && info.IsDir() {
				if claim, readErr := readFirecrackerCheckpointClaim(directory); readErr == nil &&
					claim.OperationID == binding.OperationID && claim.SandboxID == "sandbox-a" {
					t.Fatalf("the refused acquisition published its claim at the replaced pathname: %+v", claim)
				}
			}
			if tc.name != "deleted before a new claim" {
				if _, readErr := readFirecrackerCheckpointClaim(directory + ".moved"); readErr != nil {
					t.Fatalf("the claim landed outside the descriptor's directory: %v", readErr)
				}
			}
		})
	}
}

// TestClaimDirectoryPostCreateStrayDetectionFailsClosed proves a foreign
// entry racing the claim creation is never silently adopted: the post-create
// rescan sees it, the acquisition fails closed, and the claim stays in the
// directory as the tombstone. The injection window is the deterministic seam
// right after the new claim was written and synced.
func TestClaimDirectoryPostCreateStrayDetectionFailsClosed(t *testing.T) {
	directory := t.TempDir()
	binding := claimTestBinding("op-stray-race", "gen-stray-race")
	binding.RequestDigest = claimTestDigest("op-stray-race")
	previous := firecrackerClaimPostCreateHook
	firecrackerClaimPostCreateHook = func(canonical string) {
		if err := os.WriteFile(filepath.Join(canonical, "memory"), []byte("raced"), 0600); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { firecrackerClaimPostCreateHook = previous })

	_, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding)
	if !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("raced creation = %v, want ErrFailedPrecondition", err)
	}
	if !containsAll(err.Error(), "gained 1 non-claim entries while it was being claimed") {
		t.Fatalf("refusal must name the raced entry: %v", err)
	}
	// The tombstone stays: the claim is complete and readable beside the
	// foreign entry, a FOREIGN binding is refused against it, and the SAME
	// binding re-enters idempotently — the raced component itself stays the
	// layout's O_EXCL problem, exactly the documented continuation shape.
	claim, readErr := readFirecrackerCheckpointClaim(directory)
	if readErr != nil {
		t.Fatalf("tombstone left by the refused acquisition is unusable: %v", readErr)
	}
	if claim.OperationID != binding.OperationID {
		t.Fatalf("tombstone binds the wrong operation: %+v", claim)
	}
	other := binding
	other.OperationID = "op-after-race"
	if _, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", other); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("foreign binding over the raced directory = %v, want ErrFailedPrecondition", err)
	}
	if _, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding); err != nil {
		t.Fatalf("same binding re-entry over the raced directory = %v", err)
	}
}

// TestClaimReentryReEstablishesDurabilityWithoutRewrite proves an exact
// re-entry re-establishes durability — syncing the claim file and the
// directory before returning success — because the previous acquisition may
// have died after its write but before an ambiguous final fsync, and never
// rewrites or replaces the file. The syncs are observed through the counting
// seams, not timing.
func TestClaimReentryReEstablishesDurabilityWithoutRewrite(t *testing.T) {
	directory := t.TempDir()
	binding := claimTestBinding("op-durable", "gen-durable")
	binding.RequestDigest = claimTestDigest("op-durable")

	var fileSyncs, dirSyncs int
	previousFile, previousDir := firecrackerClaimSyncFile, firecrackerClaimSyncDir
	firecrackerClaimSyncFile = func(f *os.File) error {
		fileSyncs++
		return previousFile(f)
	}
	firecrackerClaimSyncDir = func(f *os.File) error {
		dirSyncs++
		return previousDir(f)
	}
	t.Cleanup(func() {
		firecrackerClaimSyncFile, firecrackerClaimSyncDir = previousFile, previousDir
	})

	if _, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding); err != nil {
		t.Fatal(err)
	}
	createdFileSyncs, createdDirSyncs := fileSyncs, dirSyncs
	if createdFileSyncs != 1 || createdDirSyncs != 1 {
		t.Fatalf("creation synced file=%d dir=%d, want 1 and 1", createdFileSyncs, createdDirSyncs)
	}
	claimPath := filepath.Join(directory, firecrackerCheckpointClaimName())
	before, err := os.ReadFile(claimPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Lstat(claimPath)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding); err != nil {
		t.Fatalf("re-entry = %v", err)
	}
	if fileSyncs <= createdFileSyncs || dirSyncs <= createdDirSyncs {
		t.Fatalf("re-entry synced nothing: file %d->%d dir %d->%d",
			createdFileSyncs, fileSyncs, createdDirSyncs, dirSyncs)
	}
	after, err := os.ReadFile(claimPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("re-entry rewrote the claim:\nbefore: %s\nafter:  %s", before, after)
	}
	afterInfo, err := os.Lstat(claimPath)
	if err != nil {
		t.Fatal(err)
	}
	if !afterInfo.ModTime().Equal(beforeInfo.ModTime()) || afterInfo.Size() != beforeInfo.Size() {
		t.Fatal("re-entry replaced the claim file")
	}
}

// TestClaimDirectoryRefusesUppercaseDigest proves the strict lowercase hex64
// request-digest shape: a claim whose digest merely uppercases is corruption,
// never a weaker match.
func TestClaimDirectoryRefusesUppercaseDigest(t *testing.T) {
	directory := t.TempDir()
	binding := claimTestBinding("op-upper", "gen-upper")
	binding.RequestDigest = claimTestDigest("op-upper")
	dev, inode := claimTestDirectoryStats(t, directory)
	writeClaimJSON(t, directory, firecrackerCheckpointClaim{
		Version:          firecrackerCheckpointClaimVersion,
		SandboxID:        "sandbox-a",
		OperationID:      binding.OperationID,
		RequestDigest:    strings.ToUpper(claimTestDigest(binding.OperationID)),
		SourceGeneration: binding.SourceGeneration,
		Directory:        directory,
		DirectoryDev:     dev,
		DirectoryInode:   inode,
	})

	_, _, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding)
	if !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("uppercase digest = %v, want ErrFailedPrecondition", err)
	}
	if !containsAll(err.Error(), "not lowercase hex") {
		t.Fatalf("refusal must name the digest shape: %v", err)
	}
}

// TestReadClaimDirectoryRefusesSymlinkedDirectory proves the path-based
// strict reader never resolves a symlinked output directory to its target.
func TestReadClaimDirectoryRefusesSymlinkedDirectory(t *testing.T) {
	target := t.TempDir()
	binding := claimTestBinding("op-dirlink2", "gen-dirlink2")
	binding.RequestDigest = claimTestDigest("op-dirlink2")
	if _, _, err := claimFirecrackerCheckpointDirectory(target, "sandbox-a", binding); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(target)
	link := filepath.Join(parent, "checkpoint-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if _, err := readFirecrackerCheckpointClaim(link); !errors.Is(err, errord.ErrFailedPrecondition) {
		t.Fatalf("symlinked directory read = %v, want ErrFailedPrecondition", err)
	} else if !containsAll(err.Error(), "symbolic link") {
		t.Fatalf("refusal must name the link: %v", err)
	}
}

// TestClaimReadersRefuseIntermediateSymlink proves every later claim read and
// witness verification uses the same component-by-component no-follow walk as
// acquisition. Moving an already claimed parent aside and linking the old
// name back to it preserves the leaf inode, so a final-component-only open
// would incorrectly accept this shape.
func TestClaimReadersRefuseIntermediateSymlink(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(parent, "checkpoint")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	binding := claimTestBinding("op-intermediate-read", "gen-intermediate-read")
	binding.RequestDigest = claimTestDigest(binding.OperationID)
	dev, inode, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding)
	if err != nil {
		t.Fatal(err)
	}
	record := schemaTestV3Witness(firecrackerCheckpointOperationPhaseIntent)
	record.OperationID = binding.OperationID
	record.RequestDigest = binding.RequestDigest
	record.SourceGeneration = binding.SourceGeneration
	record.Directory = directory
	record.DirectoryDev = dev
	record.DirectoryInode = inode
	record.SandboxID = "sandbox-a"

	moved := filepath.Join(base, "moved")
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, parent); err != nil {
		t.Fatal(err)
	}

	if _, err := readFirecrackerCheckpointClaim(directory); !errors.Is(err, errord.ErrFailedPrecondition) ||
		!containsAll(err.Error(), "symbolic link") {
		t.Fatalf("claim read through an intermediate symlink = %v, want symlink refusal", err)
	}
	if err := verifyFirecrackerCheckpointDirectoryClaim("sandbox-a", record); !errors.Is(err, errord.ErrFailedPrecondition) || !containsAll(err.Error(), "symbolic link") {
		t.Fatalf("witness verification through an intermediate symlink = %v, want symlink refusal", err)
	}
}

// TestVerifyCheckpointOperationDirectoryClaimScopesToV3 proves the claim
// verification is exactly the claim-bound schema's contract: a matching claim
// verifies, a missing or drifted one refuses, and version-1/2 records verify
// with no claim file present at all.
func TestVerifyCheckpointOperationDirectoryClaimScopesToV3(t *testing.T) {
	directory := t.TempDir()
	binding := claimTestBinding("op-verify", "gen-verify")
	binding.RequestDigest = claimTestDigest("op-verify")
	dev, inode, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-a", binding)
	if err != nil {
		t.Fatal(err)
	}
	v3 := schemaTestV3Witness(firecrackerCheckpointOperationPhaseIntent)
	v3.OperationID = binding.OperationID
	v3.RequestDigest = binding.RequestDigest
	v3.SourceGeneration = binding.SourceGeneration
	v3.Directory = directory
	v3.DirectoryDev = dev
	v3.DirectoryInode = inode
	v3.SandboxID = "sandbox-a"

	if err := verifyFirecrackerCheckpointDirectoryClaim("sandbox-a", v3); err != nil {
		t.Fatalf("matching claim refused: %v", err)
	}
	for _, tc := range []struct {
		name    string
		sandbox string
		mutate  func(*firecrackerCheckpointOperationRecord)
	}{
		{
			name:    "foreign sandbox",
			sandbox: "sandbox-b",
			mutate:  func(r *firecrackerCheckpointOperationRecord) {},
		},
		{
			name:    "foreign operation",
			sandbox: "sandbox-a",
			mutate:  func(r *firecrackerCheckpointOperationRecord) { r.OperationID = "op-other" },
		},
		{
			name:    "foreign digest",
			sandbox: "sandbox-a",
			mutate:  func(r *firecrackerCheckpointOperationRecord) { r.RequestDigest = claimTestDigest("op-other") },
		},
		{
			name:    "foreign generation",
			sandbox: "sandbox-a",
			mutate:  func(r *firecrackerCheckpointOperationRecord) { r.SourceGeneration = "gen-other" },
		},
		{
			name:    "replaced directory identity",
			sandbox: "sandbox-a",
			mutate:  func(r *firecrackerCheckpointOperationRecord) { r.DirectoryInode++ },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			drifted := v3
			tc.mutate(&drifted)
			err := verifyFirecrackerCheckpointDirectoryClaim(tc.sandbox, drifted)
			if !errors.Is(err, errord.ErrFailedPrecondition) {
				t.Fatalf("drifted v3 record = %v, want ErrFailedPrecondition", err)
			}
		})
	}
	t.Run("deleted claim", func(t *testing.T) {
		if err := os.Remove(filepath.Join(directory, firecrackerCheckpointClaimName())); err != nil {
			t.Fatal(err)
		}
		err := verifyFirecrackerCheckpointDirectoryClaim("sandbox-a", v3)
		if !errors.Is(err, errord.ErrFailedPrecondition) {
			t.Fatalf("deleted claim = %v, want ErrFailedPrecondition", err)
		}
		if !containsAll(err.Error(), "claim cannot be verified") {
			t.Fatalf("refusal must name the missing claim: %v", err)
		}
	})
	t.Run("replaced claim", func(t *testing.T) {
		other := binding
		other.OperationID = "op-usurper"
		writeClaimJSON(t, directory, firecrackerCheckpointClaim{
			Version:          firecrackerCheckpointClaimVersion,
			SandboxID:        "sandbox-a",
			OperationID:      other.OperationID,
			RequestDigest:    claimTestDigest(other.OperationID),
			SourceGeneration: binding.SourceGeneration,
			Directory:        directory,
			DirectoryDev:     dev,
			DirectoryInode:   inode,
		})
		err := verifyFirecrackerCheckpointDirectoryClaim("sandbox-a", v3)
		if !errors.Is(err, errord.ErrFailedPrecondition) {
			t.Fatalf("replaced claim = %v, want ErrFailedPrecondition", err)
		}
		if !containsAll(err.Error(), "is now claimed by") {
			t.Fatalf("refusal must name the usurping claim: %v", err)
		}
	})
	t.Run("version 1 and 2 require no claim", func(t *testing.T) {
		// The directory currently holds a foreign claim; older versions
		// neither read nor require one.
		v1 := schemaTestV1Witness(firecrackerCheckpointOperationPhasePrepared)
		v1.Directory = directory
		if err := verifyFirecrackerCheckpointDirectoryClaim("sandbox-a", v1); err != nil {
			t.Fatalf("v1 record must not consult the claim: %v", err)
		}
		v2 := schemaTestV2Witness(firecrackerCheckpointOperationPhaseIntent)
		v2.Directory = directory
		v2.DirectoryDev = dev
		v2.DirectoryInode = inode
		if err := verifyFirecrackerCheckpointDirectoryClaim("sandbox-a", v2); err != nil {
			t.Fatalf("v2 record must not consult the claim: %v", err)
		}
	})
}

// TestClaimDirectoryRefusesIntermediateSymlinkWalks proves the acquisition
// never resolves a symbolic link at an intermediate component: a claim
// addressed through a symlinked parent is refused by name, a missing leaf
// behind such a parent is never created in the link's target, and an
// existing directory behind such a parent is never claimed.
func TestClaimDirectoryRefusesIntermediateSymlinkWalks(t *testing.T) {
	base := t.TempDir()
	realParent := filepath.Join(base, "real")
	if err := os.Mkdir(realParent, 0700); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(base, "link")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	binding := claimTestBinding("op-symlink-walk", "gen-walk")
	binding.RequestDigest = claimTestDigest("op-symlink-walk")

	t.Run("missing leaf behind a symlinked parent", func(t *testing.T) {
		_, _, err := claimFirecrackerCheckpointDirectory(
			filepath.Join(linkedParent, "checkpoint"), "sandbox-walk", binding,
		)
		if err == nil || !containsAll(err.Error(), "symbolic link") {
			t.Fatalf("claim through a symlinked parent = %v, want the symlink refusal", err)
		}
		// Nothing was created anywhere: neither behind the link's target nor
		// beside it.
		if entries, readErr := os.ReadDir(realParent); readErr != nil || len(entries) != 0 {
			t.Fatalf("symlink refusal created %d entries in the link target: %v", len(entries), readErr)
		}
		if entries, readErr := os.ReadDir(base); readErr != nil || len(entries) != 2 {
			t.Fatalf("symlink refusal created entries beside the link: %d %v", len(entries), readErr)
		}
	})
	t.Run("existing directory behind a symlinked parent", func(t *testing.T) {
		realDirectory := filepath.Join(realParent, "checkpoint")
		if err := os.Mkdir(realDirectory, 0700); err != nil {
			t.Fatal(err)
		}
		_, _, err := claimFirecrackerCheckpointDirectory(linkedParent, "sandbox-walk", binding)
		if err == nil || !containsAll(err.Error(), "symbolic link") {
			t.Fatalf("claim of a symlinked directory = %v, want the symlink refusal", err)
		}
		if _, statErr := os.Lstat(filepath.Join(realDirectory, firecrackerCheckpointClaimName())); !os.IsNotExist(statErr) {
			t.Fatalf("symlink refusal wrote into the link target: %v", statErr)
		}
	})
}

// TestClaimDirectoryRefusesMissingIntermediateParent proves a missing
// intermediate component is a refusal — the service contract requires the
// parent to exist — and that nothing is created on the way to it.
func TestClaimDirectoryRefusesMissingIntermediateParent(t *testing.T) {
	base := t.TempDir()
	binding := claimTestBinding("op-missing-parent", "gen-walk")
	binding.RequestDigest = claimTestDigest("op-missing-parent")

	_, _, err := claimFirecrackerCheckpointDirectory(
		filepath.Join(base, "absent", "nested", "checkpoint"), "sandbox-walk", binding,
	)
	if err == nil || !containsAll(err.Error(), "absent") {
		t.Fatalf("claim under a missing parent = %v, want the missing-component refusal", err)
	}
	if entries, readErr := os.ReadDir(base); readErr != nil || len(entries) != 0 {
		t.Fatalf("missing-parent refusal created %d entries: %v", len(entries), readErr)
	}
}

// TestClaimDirectoryCreatesDeepMissingLeaf proves the walk creates exactly
// the missing FINAL component of an existing deep parent chain and leaves
// the claim durably bound to the created leaf's birth identity.
func TestClaimDirectoryCreatesDeepMissingLeaf(t *testing.T) {
	base := t.TempDir()
	deep := filepath.Join(base, "one", "two", "three")
	if err := os.MkdirAll(deep, 0700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(deep, "checkpoint")
	binding := claimTestBinding("op-deep-leaf", "gen-walk")
	binding.RequestDigest = claimTestDigest("op-deep-leaf")

	dev, inode, err := claimFirecrackerCheckpointDirectory(directory, "sandbox-walk", binding)
	if err != nil {
		t.Fatalf("claim of a deep missing leaf = %v", err)
	}
	wantDev, wantInode := claimTestDirectoryStats(t, directory)
	if dev != wantDev || inode != wantInode {
		t.Fatalf("claimed identity (dev=%d inode=%d), directory carries (dev=%d inode=%d)",
			dev, inode, wantDev, wantInode)
	}
	claim, readErr := readFirecrackerCheckpointClaim(directory)
	if readErr != nil || claim.Directory != directory ||
		claim.DirectoryDev != dev || claim.DirectoryInode != inode {
		t.Fatalf("deep claim binding drifted: %+v %v", claim, readErr)
	}
}
