// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func generationStateBytes(t *testing.T, id, generation, bundle string) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"id": id, "status": "created", "bundleDir": bundle,
		"resourceGeneration": generation, "processBirthVersion": 1, "runtimeDispatched": true,
		"spec": map[string]any{"annotations": runtimeGenerationAnnotations(generation)},
		"sandbox": map[string]any{"id": id, "pid": 987654321, "controlSocketPath": "/original/control.sock",
			"resourceGeneration": generation, "processBirth": controlledBirth(id, generation, "sentry", 987654321)},
	})
	require.NoError(t, err)
	return data
}

func controlledBirth(id, generation, role string, pid int) map[string]any {
	return map[string]any{"version": 1, "container_id": id, "resource_generation": generation, "role": role,
		"pid": pid, "start_ticks": 10, "initializer_pid": 123,
		"executable_sha256": strings.Repeat("a", 64), "arguments_sha256": strings.Repeat("b", 64),
		"cgroup_sha256": strings.Repeat("c", 64),
		"scope":         map[string]any{"boot_id": "controlled-unit-boot", "pid_namespace_device": 5, "pid_namespace_inode": 9}}
}

func managedGenerationClient(t *testing.T) (*Client, StartArgs, string) {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.Chmod(root, 0700))
	bundle := t.TempDir()
	require.NoError(t, os.Chmod(bundle, 0700))
	data, err := json.Marshal(map[string]any{"annotations": runtimeGenerationAnnotations("generation-original")})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(bundle, "config.json"), data, 0600))
	marker := filepath.Join(t.TempDir(), "unexpected-command")
	bin := filepath.Join(t.TempDir(), "controlled-runsc")
	require.NoError(t, os.WriteFile(bin, []byte("#!/bin/sh\n: > \"$GENERATION_TEST_COMMAND_MARKER\"\ncp \"$GENERATION_TEST_NATIVE_TEMPLATE\" \"$GENERATION_TEST_NATIVE_STATE\"\n"), 0700))
	t.Setenv("GENERATION_TEST_COMMAND_MARKER", marker)
	client := NewClientWithOptions(bin, root, Options{FilestoreDir: t.TempDir()})
	args := StartArgs{ID: "sbox-original", ResourceGeneration: "generation-original", BundleDir: bundle, Network: NetworkConfig{Interface: &net.Interface{Name: "must-not-open"}}}
	template := filepath.Join(t.TempDir(), "native-state-template.json")
	require.NoError(t, os.WriteFile(template, generationStateBytes(t, args.ID, args.ResourceGeneration, bundle), 0600))
	t.Setenv("GENERATION_TEST_NATIVE_TEMPLATE", template)
	t.Setenv("GENERATION_TEST_NATIVE_STATE", client.stateFilePath(args.ID))
	return client, args, marker
}

func TestRunscManagedCreateRejectsUnownedBundleAndExistingStateBeforeCommand(t *testing.T) {
	for _, change := range []string{"missing", "wrong-generation", "duplicate", "symlink", "fifo", "existing-state", "invalid-generation", "symlink-root", "relative-root", "cancelled"} {
		t.Run(change, func(t *testing.T) {
			client, args, marker := managedGenerationClient(t)
			path := filepath.Join(args.BundleDir, "config.json")
			switch change {
			case "missing":
				require.NoError(t, os.Remove(path))
			case "wrong-generation":
				data, err := json.Marshal(map[string]any{"annotations": runtimeGenerationAnnotations("replacement")})
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, data, 0600))
			case "duplicate":
				data, err := os.ReadFile(path)
				require.NoError(t, err)
				data = []byte(strings.Replace(string(data), "\"annotations\":", "\"annotations\":{},\"annotations\":", 1))
				require.NoError(t, os.WriteFile(path, data, 0600))
			case "symlink":
				target := filepath.Join(t.TempDir(), "foreign.json")
				require.NoError(t, os.Rename(path, target))
				require.NoError(t, os.Symlink(target, path))
			case "fifo":
				require.NoError(t, os.Remove(path))
				require.NoError(t, unix.Mkfifo(path, 0600))
			case "existing-state":
				require.NoError(t, os.WriteFile(client.stateFilePath(args.ID), generationStateBytes(t, args.ID, "replacement", args.BundleDir), 0600))
			case "invalid-generation":
				args.ResourceGeneration = "../generation-original"
			case "symlink-root":
				target := filepath.Join(t.TempDir(), "original-root")
				require.NoError(t, os.Rename(client.RootDir, target))
				require.NoError(t, os.Symlink(target, client.RootDir))
			case "relative-root":
				client.RootDir = "relative-runtime-root"
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if change == "cancelled" {
				cancel()
			}
			require.Error(t, client.Create(ctx, args))
			require.NoFileExists(t, marker)
		})
	}
}

func TestRunscManagedCreateChecksReturnedNativeGeneration(t *testing.T) {
	for _, generation := range []string{"generation-original", "replacement", ""} {
		t.Run(generation, func(t *testing.T) {
			client, args, marker := managedGenerationClient(t)
			require.NoError(t, os.WriteFile(os.Getenv("GENERATION_TEST_NATIVE_TEMPLATE"), generationStateBytes(t, args.ID, generation, args.BundleDir), 0600))
			err := client.Create(context.Background(), args)
			require.FileExists(t, marker, "controlled command ran; this is the post-create ownership check")
			if generation == args.ResourceGeneration {
				require.NoError(t, err)
				_, err = client.loadStartState(args)
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, "unconfirmed ownership")
			}
		})
	}
}

func TestRunscStartAndRestoreRejectAnotherGenerationBeforeTAPOrControl(t *testing.T) {
	for _, generation := range []string{"replacement", ""} {
		t.Run(generation, func(t *testing.T) {
			client, args, _ := managedGenerationClient(t)
			require.NoError(t, os.WriteFile(client.stateFilePath(args.ID), generationStateBytes(t, args.ID, generation, args.BundleDir), 0600))
			client.connectControl = func(string) (controlRPC, error) {
				t.Fatal("unexpected control connection")
				return nil, errors.New("unexpected")
			}
			require.ErrorContains(t, client.Start(context.Background(), args), "resource generation")
			require.ErrorContains(t, client.Restore(context.Background(), args, "/unused/checkpoint.img"), "resource generation")
		})
	}
}

func TestRunscControlStateRejectsMalformedAndUnsafeOriginalSource(t *testing.T) {
	for _, change := range []string{"duplicate", "trailing", "symlink", "hardlink", "fifo", "unsafe-mode", "oversized", "wrong-bundle", "stopped", "zero-pid"} {
		t.Run(change, func(t *testing.T) {
			client, args, _ := managedGenerationClient(t)
			path := client.stateFilePath(args.ID)
			data := generationStateBytes(t, args.ID, args.ResourceGeneration, args.BundleDir)
			require.NoError(t, os.WriteFile(path, data, 0600))
			switch change {
			case "duplicate":
				data = []byte(strings.Replace(string(data), "\"status\":\"created\"", "\"status\":\"replacement\",\"status\":\"created\"", 1))
				require.NoError(t, os.WriteFile(path, data, 0600))
			case "trailing":
				require.NoError(t, os.WriteFile(path, append(data, []byte(" {}")...), 0600))
			case "symlink":
				target := filepath.Join(t.TempDir(), "foreign-state")
				require.NoError(t, os.Rename(path, target))
				require.NoError(t, os.Symlink(target, path))
			case "hardlink":
				require.NoError(t, os.Link(path, filepath.Join(t.TempDir(), "other-link")))
			case "fifo":
				require.NoError(t, os.Remove(path))
				require.NoError(t, unix.Mkfifo(path, 0600))
			case "unsafe-mode":
				require.NoError(t, os.Chmod(path, 0666))
			case "oversized":
				require.NoError(t, os.Truncate(path, runtimeStateBytes+1))
			case "wrong-bundle":
				require.NoError(t, os.WriteFile(path, generationStateBytes(t, args.ID, args.ResourceGeneration, "/replacement/bundle"), 0600))
			case "stopped":
				require.NoError(t, os.WriteFile(path, []byte(strings.Replace(string(data), "\"created\"", "\"stopped\"", 1)), 0600))
			case "zero-pid":
				require.NoError(t, os.WriteFile(path, []byte(strings.Replace(string(data), "987654321", "0", 1)), 0600))
			}
			_, err := client.loadStartState(args)
			require.Error(t, err)
		})
	}
}

type generationRecordingClient struct {
	successfulRunscClient
	created, started, restored         []StartArgs
	deleteCalls                        int
	failCreate, failStart, failRestore bool
}

func (c *generationRecordingClient) Create(_ context.Context, args StartArgs) error {
	c.created = append(c.created, args)
	if c.failCreate {
		return errors.New("create outcome unknown")
	}
	return nil
}

func (c *generationRecordingClient) Start(_ context.Context, args StartArgs) error {
	c.started = append(c.started, args)
	if c.failStart {
		return errors.New("start outcome unknown")
	}
	return nil
}

func (c *generationRecordingClient) Restore(_ context.Context, args StartArgs, _ string) error {
	c.restored = append(c.restored, args)
	if c.failRestore {
		return errors.New("restore outcome unknown")
	}
	return nil
}

func (c *generationRecordingClient) Delete(context.Context, string, bool) error {
	c.deleteCalls++
	return nil
}

func generationHandlerFixture(t *testing.T) (*Handler, *generationRecordingClient, runtimecore.StartConfig) {
	t.Helper()
	bundles := t.TempDir()
	rootfs := t.TempDir()
	for _, name := range []string{"proc", "dev", "sys"} {
		require.NoError(t, os.Mkdir(filepath.Join(rootfs, name), 0755))
	}
	loader, err := runtimecore.NewBundleLoader("", bundles)
	require.NoError(t, err)
	client := &generationRecordingClient{}
	h := &Handler{runsc: client, ociLoader: loader, filestoreDir: t.TempDir(), rootfsOverlayTmpfsSize: "10G", sandboxRoot: bundles}
	config := runtimecore.StartConfig{ID: "sbox-original", ResourceGeneration: "generation-original", Rootfs: rootfs, DisableCgroup: true, Network: &networkmanager.NetResource{}, Annotations: map[string]string{runtimeResourceGenerationAnnotation: "caller-forged"}, SpecUpdates: &runtimecore.SpecUpdates{Annotations: map[string]string{runtimeResourceGenerationAnnotation: "provider-forged"}}}
	return h, client, config
}

func TestRunscHandlerTrustedGenerationOverridesRequestAndProviderForStartAndRestore(t *testing.T) {
	for _, restore := range []bool{false, true} {
		t.Run(map[bool]string{false: "start", true: "restore"}[restore], func(t *testing.T) {
			h, client, config := generationHandlerFixture(t)
			if restore {
				require.NoError(t, h.Restore(context.Background(), config, filepath.Join(t.TempDir(), "checkpoint.img")))
			} else {
				require.NoError(t, h.Start(context.Background(), config))
			}
			require.Len(t, client.created, 1)
			require.Equal(t, config.ResourceGeneration, client.created[0].ResourceGeneration)
			spec, err := runtimecore.LoadSpec(filepath.Join(client.created[0].BundleDir, "config.json"))
			require.NoError(t, err)
			require.Equal(t, config.ResourceGeneration, spec.Annotations[runtimeResourceGenerationAnnotation])
			require.Equal(t, "caller-forged", config.Annotations[runtimeResourceGenerationAnnotation])
			require.Equal(t, "provider-forged", config.SpecUpdates.Annotations[runtimeResourceGenerationAnnotation])
			if restore {
				require.Equal(t, client.created, client.restored)
			} else {
				require.Equal(t, client.created, client.started)
			}
		})
	}
}

func TestRunscManagedFailureNeverFallsBackToUnconditionalRuntimeDelete(t *testing.T) {
	for _, phase := range []string{"create-start", "start", "create-restore", "restore"} {
		t.Run(phase, func(t *testing.T) {
			h, client, config := generationHandlerFixture(t)
			client.failCreate = strings.HasPrefix(phase, "create-")
			client.failStart = phase == "start"
			client.failRestore = phase == "restore"
			var err error
			if strings.HasSuffix(phase, "restore") {
				err = h.Restore(context.Background(), config, filepath.Join(t.TempDir(), "checkpoint.img"))
				require.ErrorIs(t, err, runtimecore.ErrRestoreCleanupIncomplete)
			} else {
				err = h.Start(context.Background(), config)
				require.ErrorIs(t, err, runtimecore.ErrRuntimeCreationUnconfirmed)
			}
			require.Zero(t, client.deleteCalls)
			require.DirExists(t, filepath.Join(h.sandboxRoot, config.ID))
		})
	}
}
