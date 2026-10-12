// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// A controlled CLI models upstream list's documented skip-on-load-error
// behavior. This is a private metadata check, never a physical runtime.
func TestRunscListCannotTreatSkippedStateFileAsAuthoritativeAbsence(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Chmod(root, 0700))
	bin := filepath.Join(t.TempDir(), "controlled-runsc")
	require.NoError(t, os.WriteFile(bin, []byte("#!/bin/sh\nprintf '[]\\n'\n"), 0700))
	client := NewClient(bin, root)
	require.NoError(t, os.WriteFile(client.stateFilePath("sbox-original"), []byte(`{"id":"sbox-original","status":"running","sandbox":{"id":"sbox-original","controlSocketPath":"/original/control.sock","pid":987654321}}`), 0600))
	output, err := client.ListJSON(context.Background())
	require.Error(t, err, "a successful CLI exit and empty output cannot hide an original state file")
	require.Empty(t, output, "unknown inventory must not reach retirement as an empty list")
}

func inventoryTestClient(t *testing.T, output string) *Client {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.Chmod(root, 0700))
	bin := filepath.Join(t.TempDir(), "controlled-runsc")
	require.NoError(t, os.WriteFile(bin, []byte("#!/bin/sh\nprintf '%s' "+inventoryShellQuote(output)+"\n"), 0700))
	return NewClient(bin, root)
}
func inventoryShellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
func nativeInventoryFixture(t *testing.T, c *Client, id string) {
	t.Helper()
	data, err := json.Marshal(map[string]any{"id": id, "status": "running", "bundleDir": "/original/bundle", "sandbox": map[string]any{"id": id, "pid": 987654321, "controlSocketPath": "/original/control.sock"}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(c.stateFilePath(id), data, 0600))
}

func TestRunscListAcceptsVerifiedEmptyDirectoryAndNativeRunningOrStoppedIdentity(t *testing.T) {
	for _, output := range []string{"[]", "null"} {
		c := inventoryTestClient(t, output)
		data, err := c.ListJSON(context.Background())
		require.NoError(t, err)
		require.JSONEq(t, output, string(data))
	}
	for _, output := range []string{
		`[{"ociVersion":"1.0.2","id":"sbox-original","status":"running","pid":987654321,"bundle":"/original/bundle","annotations":{}}]`,
		`[{"ociVersion":"1.0.2","id":"sbox-original","status":"stopped","pid":-1,"bundle":"/original/bundle"}]`,
	} {
		c := inventoryTestClient(t, output)
		nativeInventoryFixture(t, c, "sbox-original")
		_, err := c.ListJSON(context.Background())
		require.NoError(t, err)
	}
}

func TestRunscListRejectsInventedDuplicateUnknownAndMismatchingIdentity(t *testing.T) {
	for _, output := range []string{
		`[{"id":"sbox-invented","status":"running","pid":987654321,"bundle":"/original/bundle"}]`,
		`[{"id":"sbox-original","status":"running","pid":1,"bundle":"/original/bundle"}]`,
		`[{"id":"sbox-original","status":"running","pid":987654321,"bundle":"/replacement/bundle"}]`,
		`[{"id":"sbox-original","status":"unknown","pid":987654321,"bundle":"/original/bundle"}]`,
		`[null]`,
		`[{"id":"sbox-original","id":"sbox-original","status":"running","pid":987654321,"bundle":"/original/bundle"}]`,
		`[{"id":"sbox-original","status":"running","pid":987654321,"bundle":"/original/bundle"},{"id":"sbox-original","status":"running","pid":987654321,"bundle":"/original/bundle"}]`,
		`[{"id":"sbox-original","status":"running","pid":987654321,"bundle":"/original/bundle","extra":true}]`,
	} {
		c := inventoryTestClient(t, output)
		nativeInventoryFixture(t, c, "sbox-original")
		data, err := c.ListJSON(context.Background())
		require.Error(t, err)
		require.Empty(t, data)
	}
}

func TestRunscListMalformedUnsafeOrIncompleteStateCannotAppearAbsent(t *testing.T) {
	for _, kind := range []string{"malformed", "duplicate", "trailing", "unknown-status", "identity", "symlink", "hardlink", "fifo", "permissions", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			c := inventoryTestClient(t, "[]")
			nativeInventoryFixture(t, c, "sbox-original")
			path := c.stateFilePath("sbox-original")
			switch kind {
			case "malformed":
				require.NoError(t, os.WriteFile(path, []byte(`{"id":`), 0600))
			case "duplicate":
				require.NoError(t, os.WriteFile(path, []byte(`{"id":"sbox-original","id":"sbox-original"}`), 0600))
			case "trailing":
				data, err := os.ReadFile(path)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, append(data, []byte(` {}`)...), 0600))
			case "unknown-status":
				require.NoError(t, os.WriteFile(path, []byte(`{"id":"sbox-original","status":"unknown","sandbox":{"id":"sbox-original","pid":1}}`), 0600))
			case "identity":
				require.NoError(t, os.WriteFile(path, []byte(`{"id":"sbox-other","status":"running","sandbox":{"id":"sbox-original","pid":1}}`), 0600))
			case "symlink":
				require.NoError(t, os.Rename(path, path+"-original"))
				require.NoError(t, os.Symlink(path+"-original", path))
			case "hardlink":
				require.NoError(t, os.Link(path, path+"-duplicate"))
			case "fifo":
				require.NoError(t, os.Remove(path))
				require.NoError(t, unix.Mkfifo(path, 0600))
			case "permissions":
				require.NoError(t, os.Chmod(path, 0666))
			case "oversized":
				f, err := os.OpenFile(path, os.O_WRONLY, 0600)
				require.NoError(t, err)
				require.NoError(t, f.Truncate(runtimeStateBytes+1))
				require.NoError(t, f.Close())
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			data, err := c.ListJSON(ctx)
			require.Error(t, err)
			require.Empty(t, data)
		})
	}
}

func TestRunscListReplacementOrRemovalDuringCLIProducesUnknownInventory(t *testing.T) {
	for _, kind := range []string{"state", "root", "remove"} {
		t.Run(kind, func(t *testing.T) {
			output := `[{"id":"sbox-original","status":"running","pid":987654321,"bundle":"/original/bundle"}]`
			c := inventoryTestClient(t, output)
			nativeInventoryFixture(t, c, "sbox-original")
			path := c.stateFilePath("sbox-original")
			var mutation string
			switch kind {
			case "state":
				mutation = "cp -- " + inventoryShellQuote(path) + " " + inventoryShellQuote(path+"-new") + "\nmv -- " + inventoryShellQuote(path+"-new") + " " + inventoryShellQuote(path) + "\n"
			case "root":
				mutation = "mv -- " + inventoryShellQuote(c.RootDir) + " " + inventoryShellQuote(c.RootDir+"-old") + "\nmkdir -- " + inventoryShellQuote(c.RootDir) + "\n"
			case "remove":
				mutation = "rm -- " + inventoryShellQuote(path) + "\n"
			}
			require.NoError(t, os.WriteFile(c.Binary, []byte("#!/bin/sh\nset -eu\n"+mutation+"printf '%s' "+inventoryShellQuote(output)+"\n"), 0700))
			data, err := c.ListJSON(context.Background())
			require.Error(t, err)
			require.Empty(t, data)
		})
	}
}

func TestRunscListMissingOrSymlinkRootCannotProveEmptyInventory(t *testing.T) {
	c := inventoryTestClient(t, "[]")
	require.NoError(t, os.Remove(c.RootDir))
	data, err := c.ListJSON(context.Background())
	require.Error(t, err)
	require.Empty(t, data)
	target := t.TempDir()
	require.NoError(t, os.Symlink(target, c.RootDir))
	data, err = c.ListJSON(context.Background())
	require.Error(t, err)
	require.Empty(t, data)
}

func TestRunscListOutputLimitAndCancellationNeverReturnPartialInventory(t *testing.T) {
	var out boundedRuntimeOutput
	_, err := out.Write(make([]byte, runtimeInventoryBytes))
	require.NoError(t, err)
	_, err = out.Write([]byte("x"))
	require.Error(t, err)
	var streamed boundedRuntimeOutput
	_, err = io.Copy(&streamed, strings.NewReader(strings.Repeat("x", runtimeInventoryBytes+1)))
	require.Error(t, err, "io.Copy must not bypass the output cap through promoted buffer methods")
	require.LessOrEqual(t, streamed.Len(), runtimeInventoryBytes)
	c := inventoryTestClient(t, "[]")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	data, err := c.ListJSON(ctx)
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, data)
}

func TestRunscListCLIReceivesTheSameHeldRootDescriptor(t *testing.T) {
	c := inventoryTestClient(t, "[]")
	script := "#!/bin/sh\nset -eu\ntest -d /proc/self/fd/3\ncase \"$*\" in\n*'--root /proc/self/fd/3 list --format json') printf '[]\\n';;\n*) exit 98;;\nesac\n"
	require.NoError(t, os.WriteFile(c.Binary, []byte(script), 0700))
	_, err := c.ListJSON(context.Background())
	require.NoError(t, err)
}

// Explicit physical-host compatibility check. Only an isolated private state
// directory is read; no runtime is created, signalled or deleted.
func TestRunscListRealBinaryHeldRootAndCorruptInventory(t *testing.T) {
	if os.Getenv("SANDBOXD_RUN_RUNSC_INVENTORY_INTEGRATION") != "1" {
		t.Skip("requires explicit designated-host runsc inventory integration")
	}
	bin := os.Getenv("RUNSC_INVENTORY_TEST_BINARY")
	require.True(t, filepath.IsAbs(bin))
	data, err := os.ReadFile(bin)
	require.NoError(t, err)
	digest := sha256.Sum256(data)
	expected := os.Getenv("RUNSC_INVENTORY_TEST_BINARY_SHA256")
	require.Len(t, expected, 64)
	require.Equal(t, expected, hex.EncodeToString(digest[:]))
	root := t.TempDir()
	require.NoError(t, os.Chmod(root, 0700))
	client := NewClient(bin, root)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	output, err := client.ListJSON(ctx)
	require.NoError(t, err)
	var empty []*runtimeListedState
	require.NoError(t, json.Unmarshal(output, &empty))
	require.Empty(t, empty)
	// Upstream skips this corrupt native file and returns a successful empty
	// list. The guarded reader must reject it before invoking that CLI.
	path := client.stateFilePath("sbox-original")
	require.NoError(t, os.WriteFile(path, []byte(`{"id":`), 0600))
	plain := exec.CommandContext(ctx, bin, "--root", root, "list", "--format", "json")
	plainOutput, err := plain.Output()
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(plainOutput, &empty))
	require.Empty(t, empty)
	output, err = client.ListJSON(ctx)
	require.Error(t, err)
	require.Empty(t, output)
}
