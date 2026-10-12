// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// These probes only replace this fixture's state entry, never another runtime
// or a platform resource. The externally audited original processes stay alive.
func verifyNativeTransitionRefusals(t *testing.T, ctx context.Context, client *Client, args StartArgs, save func(string, any)) {
	t.Helper()
	g, state, err := client.beginStartTransition(ctx, args)
	require.NoError(t, err)
	defer g.close()
	bounded, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	err = client.Start(bounded, args)
	cancel()
	if err == nil {
		g.close()
		t.Fatal("actual Start bypassed the original held lifecycle lock")
	}
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NoError(t, g.check(ctx))
	verifyNativePhysicalBirth(t, state.Sandbox.ProcessBirth)
	verifyNativePhysicalBirth(t, state.GoferBirth)
	g.close()

	g, state, err = client.beginStartTransition(ctx, args)
	require.NoError(t, err)
	defer g.close()
	path := client.stateFilePath(args.ID)
	saved := filepath.Join(client.RootDir, ".native-test-original-state")
	require.NoFileExists(t, saved)
	data := bytes.Clone(g.stateData)
	original := g.stateIdentity
	require.NoError(t, os.Rename(path, saved))
	var replacement unix.Stat_t
	created := false
	restored := false
	defer func() {
		if restored {
			return
		}
		if created {
			current, err := os.ReadFile(path)
			var stat unix.Stat_t
			if err != nil || !bytes.Equal(current, data) || unix.Lstat(path, &stat) != nil || !sameRuntimeInventoryStat(stat, replacement) {
				t.Error("owned replacement state cannot be safely removed; preserve fixture for diagnosis")
				return
			}
			if err := os.Remove(path); err != nil {
				t.Error(err)
				return
			}
		}
		if err := os.Rename(saved, path); err != nil {
			t.Error(err)
		}
	}()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(original.Mode&0777))
	require.NoError(t, err)
	defer file.Close()
	created = true
	require.NoError(t, unix.Fstat(int(file.Fd()), &replacement))
	require.NoError(t, file.Chmod(os.FileMode(original.Mode&0777)))
	_, err = file.Write(data)
	require.NoError(t, err)
	require.NoError(t, file.Sync())
	require.NoError(t, file.Close())
	created = true
	require.NoError(t, unix.Lstat(path, &replacement))
	require.NotEqual(t, original.Ino, replacement.Ino)
	require.Error(t, g.markRunning(ctx))
	current, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, data, current)
	current, err = os.ReadFile(saved)
	require.NoError(t, err)
	require.Equal(t, data, current)
	verifyNativePhysicalBirth(t, state.Sandbox.ProcessBirth)
	verifyNativePhysicalBirth(t, state.GoferBirth)
	require.NoError(t, os.Remove(path))
	require.NoError(t, os.Rename(saved, path))
	restored = true
	save("native-start-transition-refusals.json", map[string]any{
		"sandbox_id": args.ID, "resource_generation": args.ResourceGeneration,
		"lock_operation_id":        "native-start-lock-deadline-refusal",
		"replacement_operation_id": "native-start-equal-state-refusal",
		"lock_deadline_refused":    true, "replacement_state_unchanged": true,
		"original_state_restored": true, "original_processes_live": true,
		"original_device": original.Dev, "original_inode": original.Ino,
		"replacement_device": replacement.Dev, "replacement_inode": replacement.Ino,
		"equal_state_bytes_sha256": fmt.Sprintf("%x", sha256.Sum256(data)),
		"scope":                    "Held-lock and equal-byte state-entry replacement refusals on real created processes. No replacement runtime, resource resize or node-budget acceptance.",
	})
}
