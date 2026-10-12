// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
)

// The token remains in the shell's memory. The file lives in the sandbox's
// writable layer. The host probe is created only after the source has exited
// and Restore has returned, so a newly started workload cannot pass by reading
// the saved token from the host export.
const nativeRestoreMemoryWorkload = "seed=$(/bin/busybox od -An -N16 -tx1 /dev/urandom | /bin/busybox tr -d ' \\n'); " +
	"printf '%s\\n' \"$seed\" >/native-memory-token; cat /home/marker; printf 'workload-ready\\n'; " +
	"printf 'memory-seed=%s\\n' \"$seed\"; " +
	"while :; do if [ -f /home/restore-probe ]; then printf 'restored-memory=%s\\n' \"$seed\"; " +
	"printf 'restored-file='; cat /native-memory-token; exec /bin/sleep 120; fi; /bin/sleep 0.1; done"

type nativePhysicalCheckpoint struct {
	directory string
	seed      string
	files     map[string]string
	source    *containerState
}

func TestRealNativeWorkloadRestoreBirthAndLivePeer(t *testing.T) {
	runNativePhysicalFixture(t, true, true)
}

func nativeCheckpointFiles(t *testing.T, directory string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		require.NoError(t, err)
		require.True(t, info.Mode().IsRegular(), "checkpoint entries must be regular files")
		name, err := filepath.Rel(directory, path)
		require.NoError(t, err)
		files[name] = nativePhysicalSHA(t, path)
		return nil
	})
	require.NoError(t, err)
	require.Contains(t, files, checkpointImageName)
	require.Contains(t, files, filepath.Join("fs", "fscheckpoint.json"))
	return files
}

func prepareNativePhysicalCheckpoint(t *testing.T, ctx context.Context, client *Client, args StartArgs, source *containerState, save func(string, any)) *nativePhysicalCheckpoint {
	t.Helper()
	pattern := regexp.MustCompile(`(?m)^memory-seed=([0-9a-f]{32})$`)
	var seed string
	for seed == "" {
		data, err := os.ReadFile(args.UserStdout)
		require.NoError(t, err)
		if match := pattern.FindSubmatch(data); match != nil {
			seed = string(match[1])
			break
		}
		require.NoError(t, ctx.Err(), "source did not publish its in-memory token")
		time.Sleep(10 * time.Millisecond)
	}
	directory := filepath.Join(filepath.Dir(client.RootDir), "restore-checkpoint")
	require.NoError(t, os.Mkdir(directory, 0700))
	// Use the production paired checkpoint path. LeaveRunning preserves the
	// original processes for generation-conditional retirement after saving.
	handler := &Handler{runsc: client}
	if err := handler.Checkpoint(ctx, args.ID, directory, runtimecore.CheckpointOptions{IncludeFilesystem: true, LeaveRunning: true}); err != nil {
		save("native-checkpoint-failure.json", map[string]any{"sandbox_id": args.ID, "resource_generation": args.ResourceGeneration, "error": err.Error()})
		require.NoError(t, err)
	}
	verifyNativePhysicalBirth(t, source.Sandbox.ProcessBirth)
	verifyNativePhysicalBirth(t, source.GoferBirth)
	files := nativeCheckpointFiles(t, directory)
	save("native-checkpoint-source.json", map[string]any{"sandbox_id": args.ID, "resource_generation": args.ResourceGeneration,
		"operation_id": "native-paired-checkpoint", "in_memory_seed": seed, "files_sha256": files,
		"source_left_running_for_conditional_retirement": true, "scope": "Real paired memory/filesystem checkpoint; file size is not a restore-memory budget."})
	return &nativePhysicalCheckpoint{directory: directory, seed: seed, files: files, source: source}
}

func restoreNativePhysicalCheckpoint(t *testing.T, ctx context.Context, client *Client, loader *runtimecore.BundleLoader, checkpoint *nativePhysicalCheckpoint, config runtimecore.StartConfig, peer *containerState, shared *nativePhysicalSharedNamespace, tapIndex int, save func(string, any)) *nativePhysicalTAP {
	t.Helper()
	config.ID, config.ResourceGeneration = "birth-restored", "generation-restored"
	bundle, _, err := loader.GenerateOci(runtimecore.OciLoadOptions{SandboxID: config.ID, Config: config,
		UseGVisorRootfsImageAnnotations: true, RootfsOverlayDir: client.Options.FilestoreDir, RootfsOverlaySize: "64M",
		ManagedAnnotations: runtimeGenerationAnnotations(config.ResourceGeneration)})
	require.NoError(t, err)
	tap := newNativePhysicalTAP(t, tapIndex)
	args := StartArgs{ID: config.ID, ResourceGeneration: config.ResourceGeneration, BundleDir: bundle,
		RootOverlay: RootFileOverlay(client.Options.FilestoreDir, "64M"), Network: tap.network,
		FsRestoreImagePath: filepath.Join(checkpoint.directory, "fs"),
		UserStdout:         filepath.Join(filepath.Dir(client.RootDir), config.ID+".stdout"),
		UserStderr:         filepath.Join(filepath.Dir(client.RootDir), config.ID+".stderr")}
	if err := client.Create(ctx, args); err != nil {
		save("native-restore-create-failure.json", map[string]any{"sandbox_id": args.ID, "resource_generation": args.ResourceGeneration, "error": err.Error()})
		require.NoError(t, err)
	}
	created, err := client.loadStartState(args)
	require.NoError(t, err)
	verifyNativePhysicalBirth(t, created.Sandbox.ProcessBirth)
	verifyNativePhysicalBirth(t, created.GoferBirth)
	sentry, gofer := nativePhysicalPidfd(t, created.Sandbox.ProcessBirth), nativePhysicalPidfd(t, created.GoferBirth)
	require.NotEqual(t, checkpoint.source.ResourceGeneration, created.ResourceGeneration)
	require.NotEqual(t, checkpoint.source.Sandbox.ProcessBirth, created.Sandbox.ProcessBirth)
	require.NotEqual(t, checkpoint.source.GoferBirth, created.GoferBirth)
	shared.verify(t, created.GoferBirth)
	save("birth-restored-birth.json", created)
	save("restored-births-ready.json", map[string]any{"states": []*containerState{created, peer}, "scope": "Fresh Restore target and the original live peer; source already independently confirmed exited."})
	for {
		if _, err := os.Stat(filepath.Join(os.Getenv("NATIVE_BIRTH_EVIDENCE"), "allow-restored-delete")); err == nil {
			break
		}
		require.NoError(t, ctx.Err(), "external observer did not verify the fresh Restore target")
		time.Sleep(10 * time.Millisecond)
	}
	image := filepath.Join(checkpoint.directory, checkpointImageName)
	verifyNativePhysicalRestoreRefusals(t, ctx, client, args, image, created, peer, save)
	if err := client.Restore(ctx, args, image); err != nil {
		save("native-restore-failure.json", map[string]any{"sandbox_id": args.ID, "resource_generation": args.ResourceGeneration, "error": err.Error()})
		require.NoError(t, err)
	}
	// The source is gone. Only the restored shell can observe this fresh probe.
	export := config.Mounts[0].GetHostPath()
	require.NoError(t, os.WriteFile(filepath.Join(export, "restore-probe"), []byte("resume-original-memory\n"), 0600))
	var output []byte
	for {
		output, err = os.ReadFile(args.UserStdout)
		require.NoError(t, err)
		if strings.Contains(string(output), "restored-memory="+checkpoint.seed+"\n") && strings.Contains(string(output), "restored-file="+checkpoint.seed+"\n") {
			break
		}
		if err := ctx.Err(); err != nil {
			save("native-restore-readiness-failure.json", map[string]any{"sandbox_id": args.ID, "stdout": string(output), "error": err.Error()})
			require.NoError(t, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	running, err := client.loadState(args.ID)
	require.NoError(t, err)
	require.Equal(t, "running", running.Status)
	require.NoError(t, validateNativeRuntimeBirth(running, args.ID, args.ResourceGeneration))
	require.Equal(t, created.Sandbox.ProcessBirth, running.Sandbox.ProcessBirth)
	require.Equal(t, created.GoferBirth, running.GoferBirth)
	verifyNativePhysicalBirth(t, running.Sandbox.ProcessBirth)
	verifyNativePhysicalBirth(t, running.GoferBirth)
	verifyNativePhysicalBirth(t, peer.Sandbox.ProcessBirth)
	verifyNativePhysicalBirth(t, peer.GoferBirth)
	require.Equal(t, checkpoint.files, nativeCheckpointFiles(t, checkpoint.directory))
	save("native-restored-workload-running.json", map[string]any{"state": running, "in_memory_seed": checkpoint.seed,
		"restored_memory_and_file_match": true, "stdout": string(output), "checkpoint_files_unchanged": true,
		"source_already_retired": true, "new_producer_birth_preserved": true, "live_peer_preserved": true, "tap": tap.evidence(t)})
	require.Error(t, client.DeleteIfGeneration(ctx, args.ID, checkpoint.source.ResourceGeneration))
	verifyNativePhysicalBirth(t, running.Sandbox.ProcessBirth)
	verifyNativePhysicalBirth(t, peer.Sandbox.ProcessBirth)
	require.NoError(t, client.DeleteIfGeneration(ctx, args.ID, args.ResourceGeneration))
	verifyNativePhysicalExit(t, sentry)
	verifyNativePhysicalExit(t, gofer)
	require.NoFileExists(t, client.stateFilePath(args.ID))
	verifyNativePhysicalBirth(t, peer.Sandbox.ProcessBirth)
	verifyNativePhysicalBirth(t, peer.GoferBirth)
	shared.verify(t, peer.GoferBirth)
	save("native-restored-retired-peer-live.json", map[string]any{"sandbox_id": args.ID, "resource_generation": args.ResourceGeneration,
		"old_source_generation_refused": true, "two_fresh_pidfd_exits_confirmed": true, "original_peer_live": true})
	return tap
}

func verifyNativePhysicalRestoreRefusals(t *testing.T, ctx context.Context, client *Client, args StartArgs, image string, original, peer *containerState, save func(string, any)) {
	t.Helper()
	originalBytes, err := os.ReadFile(client.stateFilePath(original.ID))
	require.NoError(t, err)
	peerBytes, err := os.ReadFile(client.stateFilePath(peer.ID))
	require.NoError(t, err)
	wrong := args
	wrong.ResourceGeneration = "generation-original"
	require.Error(t, client.Restore(ctx, wrong, image))
	dial := client.connectControl
	client.connectControl = func(string) (controlRPC, error) { return dial(peer.Sandbox.ControlSocketPath) }
	defer func() { client.connectControl = dial }()
	err = client.Restore(ctx, args, image)
	require.ErrorContains(t, err, "not from the original serving process")
	for _, state := range []*containerState{original, peer} {
		verifyNativePhysicalBirth(t, state.Sandbox.ProcessBirth)
		verifyNativePhysicalBirth(t, state.GoferBirth)
	}
	data, err := os.ReadFile(client.stateFilePath(original.ID))
	require.NoError(t, err)
	require.Equal(t, originalBytes, data)
	data, err = os.ReadFile(client.stateFilePath(peer.ID))
	require.NoError(t, err)
	require.Equal(t, peerBytes, data)
	save("native-restore-refusals.json", map[string]any{"sandbox_id": args.ID, "resource_generation": args.ResourceGeneration,
		"operation_id": "native-restore-wrong-generation-and-peer-refusal", "wrong_generation_refused": true,
		"wrong_peer_reply_refused": true, "both_original_states_unchanged": true, "four_original_processes_live": true})
}
