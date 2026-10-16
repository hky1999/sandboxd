// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Controlled files represent producer contracts only; no native process or
// physical retirement is claimed by these ordinary unit checks.
func launchHandoffFixture(t *testing.T) (*Client, *managedLaunchRecord, string) {
	t.Helper()
	client, launch := managedLaunchFixture(t)
	root := t.TempDir()
	require.NoError(t, os.Chmod(root, 0700))
	// Keep the original implementation compilable so the actual dispatch
	// outcome, rather than a missing new field, is the regression assertion.
	field := reflect.ValueOf(&client.Options).Elem().FieldByName("RetirementRoot")
	if field.IsValid() {
		field.SetString(root)
	}
	return client, launch, root
}

func handoffReceiptPath(root, id, generation string) string {
	key, _ := json.Marshal([2]string{id, generation})
	digest := sha256.Sum256(key)
	return filepath.Join(root, "scheduler-retirements", hex.EncodeToString(digest[:])+".json")
}

func saveHandoffReceipt(t *testing.T, root, id, generation string, complete bool) string {
	t.Helper()
	path := handoffReceiptPath(root, id, generation)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
	data, err := json.Marshal(map[string]any{"version": 1, "sandbox_id": id, "generation": generation, "complete": complete})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0600))
	return path
}

func replacementLaunch(original *managedLaunchRecord, generation string) *managedLaunchRecord {
	next := *original
	next.ResourceGeneration = generation
	next.OperationID = uuid.NewString()
	group := *original.Cgroup
	group.Path += "-" + generation
	group.Inode++
	next.Cgroup = &group
	return &next
}

func TestManagedLaunchCompletedRetirementAllowsGenerationHandoff(t *testing.T) {
	client, old, root := launchHandoffFixture(t)
	require.NoError(t, client.publishManagedLaunch(context.Background(), old))
	active := filepath.Join(client.RootDir, managedLaunchDirectory, old.SandboxID+".json")
	original, err := os.ReadFile(active)
	require.NoError(t, err)
	saveHandoffReceipt(t, root, old.SandboxID, old.ResourceGeneration, true)
	next := replacementLaunch(old, "generation-new")
	require.NoError(t, client.publishManagedLaunch(context.Background(), next))
	current, err := os.ReadFile(active)
	require.NoError(t, err)
	var decoded managedLaunchRecord
	require.NoError(t, json.Unmarshal(current, &decoded))
	require.Equal(t, next, &decoded)
	entries, err := os.ReadDir(filepath.Dir(active))
	require.NoError(t, err)
	require.Len(t, entries, 3, "private lock, current intent and immutable retired original")
	var archive []byte
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "retired-") {
			archive, err = os.ReadFile(filepath.Join(filepath.Dir(active), entry.Name()))
			require.NoError(t, err)
		}
	}
	require.Contains(t, string(archive), old.ResourceGeneration)
	require.Contains(t, string(archive), old.OperationID)
	require.Contains(t, string(archive), old.ArgumentsSHA256)
	// Reopening the client retains the configured authoritative receipt root.
	reopened := NewClientWithOptions(client.Binary, client.RootDir, client.Options)
	require.Error(t, reopened.publishManagedLaunch(context.Background(), old))
	again, err := os.ReadFile(active)
	require.NoError(t, err)
	require.Equal(t, current, again)
	require.NotEqual(t, original, current)
}

func TestManagedLaunchPendingRetirementKeepsOwnerUntilCompletion(t *testing.T) {
	client, old, root := launchHandoffFixture(t)
	require.NoError(t, client.publishManagedLaunch(context.Background(), old))
	path := filepath.Join(client.RootDir, managedLaunchDirectory, old.SandboxID+".json")
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	next := replacementLaunch(old, "generation-new")
	saveHandoffReceipt(t, root, old.SandboxID, old.ResourceGeneration, false)
	require.Error(t, client.publishManagedLaunch(context.Background(), next))
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after)
	saveHandoffReceipt(t, root, old.SandboxID, old.ResourceGeneration, true)
	require.NoError(t, client.publishManagedLaunch(context.Background(), next))
}

func TestManagedLaunchRetiringGenerationCannotDispatchEvenWithoutActiveIntent(t *testing.T) {
	for _, complete := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "complete"}[complete], func(t *testing.T) {
			client, launch, root := launchHandoffFixture(t)
			saveHandoffReceipt(t, root, launch.SandboxID, launch.ResourceGeneration, complete)
			require.Error(t, client.publishManagedLaunch(context.Background(), launch))
			require.NoFileExists(t, filepath.Join(client.RootDir, managedLaunchDirectory, launch.SandboxID+".json"))
		})
	}
}

func TestManagedLaunchCompletedRetirementCannotBeBorrowed(t *testing.T) {
	for _, change := range []string{"wrong-generation", "wrong-id", "pending", "duplicate", "unknown-field", "trailing", "symlink", "hardlink", "fifo", "directory-symlink", "public-mode"} {
		t.Run(change, func(t *testing.T) {
			client, old, root := launchHandoffFixture(t)
			require.NoError(t, client.publishManagedLaunch(context.Background(), old))
			active := filepath.Join(client.RootDir, managedLaunchDirectory, old.SandboxID+".json")
			before, err := os.ReadFile(active)
			require.NoError(t, err)
			path := saveHandoffReceipt(t, root, old.SandboxID, old.ResourceGeneration, true)
			raw, err := os.ReadFile(path)
			require.NoError(t, err)
			switch change {
			case "wrong-generation", "wrong-id", "pending", "unknown-field":
				var value map[string]any
				require.NoError(t, json.Unmarshal(raw, &value))
				switch change {
				case "wrong-generation":
					value["generation"] = "foreign"
				case "wrong-id":
					value["sandbox_id"] = "foreign"
				case "pending":
					value["complete"] = false
				case "unknown-field":
					value["invented"] = true
				}
				raw, err = json.Marshal(value)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, raw, 0600))
			case "duplicate":
				require.NoError(t, os.WriteFile(path, append([]byte("{\"complete\":false,"), raw[1:]...), 0600))
			case "trailing":
				require.NoError(t, os.WriteFile(path, append(raw, []byte("{}")...), 0600))
			case "symlink", "hardlink", "fifo":
				require.NoError(t, os.Remove(path))
				other := filepath.Join(t.TempDir(), "receipt")
				require.NoError(t, os.WriteFile(other, raw, 0600))
				if change == "symlink" {
					require.NoError(t, os.Symlink(other, path))
				} else if change == "hardlink" {
					require.NoError(t, os.Link(other, path))
				} else {
					require.NoError(t, unix.Mkfifo(path, 0600))
				}
			case "directory-symlink":
				original := filepath.Dir(path)
				require.NoError(t, os.Rename(original, original+"-held"))
				require.NoError(t, os.Symlink(original+"-held", original))
			case "public-mode":
				require.NoError(t, os.Chmod(path, 0644))
			}
			require.Error(t, client.publishManagedLaunch(context.Background(), replacementLaunch(old, "generation-new")))
			after, err := os.ReadFile(active)
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
}

func TestManagedLaunchConcurrentHandoffPublishesOneNewOwner(t *testing.T) {
	client, old, root := launchHandoffFixture(t)
	require.NoError(t, client.publishManagedLaunch(context.Background(), old))
	saveHandoffReceipt(t, root, old.SandboxID, old.ResourceGeneration, true)
	start := make(chan struct{})
	result := make(chan error, 2)
	var wg sync.WaitGroup
	for _, generation := range []string{"generation-new-a", "generation-new-b"} {
		next := replacementLaunch(old, generation)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			result <- client.publishManagedLaunch(context.Background(), next)
		}()
	}
	close(start)
	wg.Wait()
	close(result)
	succeeded := 0
	for err := range result {
		if err == nil {
			succeeded++
		}
	}
	require.Equal(t, 1, succeeded)
}

func TestManagedLaunchHandoffPublicationFailuresPreserveOwnership(t *testing.T) {
	for _, point := range []string{"receipt-sync", "archive-file-sync", "archive-directory-sync", "active-directory-sync"} {
		t.Run(point, func(t *testing.T) {
			client, old, root := launchHandoffFixture(t)
			require.NoError(t, client.publishManagedLaunch(context.Background(), old))
			saveHandoffReceipt(t, root, old.SandboxID, old.ResourceGeneration, true)
			active := filepath.Join(client.RootDir, managedLaunchDirectory, old.SandboxID+".json")
			before, err := os.ReadFile(active)
			require.NoError(t, err)
			next := replacementLaunch(old, "generation-new")
			directorySyncs := 0
			failed := false
			client.managedLaunchSync = func(file *os.File) error {
				selected := false
				if file.Name() == "original managed launch journal" {
					directorySyncs++
				}
				switch point {
				case "receipt-sync":
					selected = file.Name() == "scheduler-retirements"
				case "archive-file-sync":
					selected = strings.HasPrefix(file.Name(), ".pending-")
				case "archive-directory-sync":
					selected = directorySyncs == 1 && file.Name() == "original managed launch journal"
				case "active-directory-sync":
					selected = directorySyncs == 2 && file.Name() == "original managed launch journal"
				}
				if selected && !failed {
					failed = true
					return unix.EIO
				}
				return file.Sync()
			}
			require.ErrorIs(t, client.publishManagedLaunch(context.Background(), next), unix.EIO)
			require.True(t, failed)
			after, err := os.ReadFile(active)
			require.NoError(t, err)
			client.managedLaunchSync = nil
			if point == "active-directory-sync" {
				var stored managedLaunchRecord
				require.NoError(t, json.Unmarshal(after, &stored))
				require.Equal(t, next, &stored, "post-rename failure retains the unknown new owner")
				require.Error(t, client.publishManagedLaunch(context.Background(), next), "unknown publication must not become a second dispatch")
			} else {
				require.Equal(t, before, after, "unarchived original cannot be replaced")
				require.NoError(t, client.publishManagedLaunch(context.Background(), next), "the same source proof repairs a pre-handoff sync gap")
			}
			require.Error(t, client.publishManagedLaunch(context.Background(), old))
		})
	}
}

func TestManagedLaunchHandoffCannotReplaceCorruptOriginalOrArchive(t *testing.T) {
	for _, point := range []string{"active-json", "active-generation", "archive-json", "archive-fifo"} {
		t.Run(point, func(t *testing.T) {
			client, old, root := launchHandoffFixture(t)
			require.NoError(t, client.publishManagedLaunch(context.Background(), old))
			saveHandoffReceipt(t, root, old.SandboxID, old.ResourceGeneration, true)
			active := filepath.Join(client.RootDir, managedLaunchDirectory, old.SandboxID+".json")
			switch point {
			case "active-json":
				require.NoError(t, os.WriteFile(active, []byte("{}"), 0600))
			case "active-generation":
				changed := *old
				changed.ResourceGeneration = "unconfirmed-owner"
				data, err := json.Marshal(changed)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(active, data, 0600))
			default:
				archive := filepath.Join(filepath.Dir(active), "retired-"+managedLaunchKey(old.SandboxID, old.ResourceGeneration)+".json")
				if point == "archive-fifo" {
					require.NoError(t, unix.Mkfifo(archive, 0600))
				} else {
					require.NoError(t, os.WriteFile(archive, []byte("{}"), 0600))
				}
			}
			before, err := os.ReadFile(active)
			require.NoError(t, err)
			require.Error(t, client.publishManagedLaunch(context.Background(), replacementLaunch(old, "generation-new")))
			after, err := os.ReadFile(active)
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
}

func TestManagedLaunchArchiveStillFencesRetiredGenerationWithoutProducerReceipt(t *testing.T) {
	client, old, root := launchHandoffFixture(t)
	require.NoError(t, client.publishManagedLaunch(context.Background(), old))
	receipt := saveHandoffReceipt(t, root, old.SandboxID, old.ResourceGeneration, true)
	next := replacementLaunch(old, "generation-new")
	require.NoError(t, client.publishManagedLaunch(context.Background(), next))
	active := filepath.Join(client.RootDir, managedLaunchDirectory, old.SandboxID+".json")
	before, err := os.ReadFile(active)
	require.NoError(t, err)
	require.NoError(t, os.Remove(receipt))
	require.Error(t, client.publishManagedLaunch(context.Background(), old))
	after, err := os.ReadFile(active)
	require.NoError(t, err)
	require.Equal(t, before, after)
}
