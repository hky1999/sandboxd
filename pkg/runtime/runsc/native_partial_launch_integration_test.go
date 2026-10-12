// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	runtimeapi "github.com/inclusionAI/sandboxd/api/runtime/v1"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
)

// The external ptrace wrapper stops the real producer after a successful
// directory fsync. It never writes native owner state. An observer outside the
// container cgroup audits the creator and all births before terminating the
// creator by its original pidfd. No partial state is synthesized here.
func TestRealNativePartialGoferBirthRetirementAndLivePeer(t *testing.T) {
	runNativePartialLaunchFixture(t, false)
}

func TestRealNativeLaunchCgroupBindingBeforeChildBirthAndLivePeer(t *testing.T) {
	runNativePartialLaunchFixture(t, true)
}

func runNativePartialLaunchFixture(t *testing.T, bindCgroup bool) {
	t.Helper()
	if os.Getenv("SANDBOXD_RUN_NATIVE_BIRTH_INTEGRATION") != "1" {
		t.Skip("requires an explicit isolated BareMetal1 partial native launch test")
	}
	binary, binarySHA := os.Getenv("NATIVE_BIRTH_RUNSC_BINARY"), os.Getenv("NATIVE_BIRTH_RUNSC_SHA256")
	rootfs, rootfsSHA := os.Getenv("NATIVE_BIRTH_ROOTFS"), os.Getenv("NATIVE_BIRTH_ROOTFS_SHA256")
	tracer, tracerSHA := os.Getenv("NATIVE_BIRTH_CREATE_TRACER"), os.Getenv("NATIVE_BIRTH_CREATE_TRACER_SHA256")
	evidence := os.Getenv("NATIVE_BIRTH_EVIDENCE")
	for path, digest := range map[string]string{binary: binarySHA, rootfs: rootfsSHA, tracer: tracerSHA} {
		require.True(t, filepath.IsAbs(path) && nativeDigest(digest))
		require.Equal(t, digest, nativePhysicalSHA(t, path))
	}
	require.True(t, filepath.IsAbs(evidence))
	require.NoError(t, os.MkdirAll(evidence, 0700))
	save := func(name string, value any) {
		data, err := json.MarshalIndent(value, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(evidence, name), append(data, '\n'), 0600))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	wait := func(name string) {
		for {
			if _, err := os.Stat(filepath.Join(evidence, name)); err == nil {
				return
			}
			require.NoError(t, ctx.Err(), "original external observer did not finish %s", name)
			time.Sleep(10 * time.Millisecond)
		}
	}
	work := t.TempDir()
	root, filestore := filepath.Join(work, "runsc"), filepath.Join(work, "filestore")
	require.NoError(t, os.MkdirAll(root, 0700))
	require.NoError(t, os.MkdirAll(filestore, 0700))
	loader, err := runtimecore.NewBundleLoader("", filepath.Join(work, "bundles"))
	require.NoError(t, err)
	client := NewClientWithOptions(binary, root, Options{FilestoreDir: filestore, OverlayTmpfsSize: "64M", IgnoreCgroups: true})
	groups := make(map[string]string)
	if bindCgroup {
		prefix := os.Getenv("NATIVE_LAUNCH_CGROUP_PARENT")
		parent, identity, err := openOriginalLaunchCgroup(prefix)
		require.NoError(t, err)
		defer parent.Close()
		// The outside observer supplies an original owned non-root parent.
		// The fixture never discovers or writes a different cgroup root.
		var expected struct {
			Device uint64 `json:"device"`
			Inode  uint64 `json:"inode"`
		}
		require.NoError(t, json.Unmarshal([]byte(os.Getenv("NATIVE_LAUNCH_CGROUP_PARENT_IDENTITY")), &expected))
		require.Equal(t, expected.Device, identity.Device)
		require.Equal(t, expected.Inode, identity.Inode)
		for _, id := range []string{"partial-peer", "partial-original"} {
			groups[id] = filepath.Join(prefix, "launch-"+id)
			require.NoError(t, os.Mkdir(filepath.Join("/sys/fs/cgroup", groups[id]), 0755))
		}
	}
	makeArgs := func(id, generation string) StartArgs {
		export := filepath.Join(work, id+"-export")
		require.NoError(t, os.Mkdir(export, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(export, "marker"), []byte(id+"\n"), 0600))
		config := runtimecore.StartConfig{
			ID: id, ResourceGeneration: generation, Rootfs: rootfs, RootfsReadonly: true,
			DisableCgroup: true, Cwd: "/", Command: []string{"/bin/sh", "-c", "cat /home/marker; printf 'workload-ready\\n'; exec /bin/sleep 240"},
			Mounts: []*runtimeapi.Mount{{Type: "bind", Source: &runtimeapi.Mount_HostPath{HostPath: export}, Target: "/home", Options: []string{"ro", "rbind"}}},
		}
		config.CgroupPath = groups[id]
		config.DisableCgroup = !bindCgroup
		if bindCgroup {
			config.Resources = &runtimeapi.LinuxSandboxResources{}
		}
		bundle, _, err := loader.GenerateOci(runtimecore.OciLoadOptions{
			SandboxID: id, Config: config, UseGVisorRootfsImageAnnotations: true,
			CgroupPath:       config.CgroupPath,
			RootfsOverlayDir: filestore, RootfsOverlaySize: "64M", ManagedAnnotations: runtimeGenerationAnnotations(generation),
		})
		require.NoError(t, err)
		return StartArgs{ID: id, ResourceGeneration: generation, BundleDir: bundle, CgroupPath: config.CgroupPath, RootOverlay: RootFileOverlay(filestore, "64M"),
			UserStdout: filepath.Join(work, id+".stdout"), UserStderr: filepath.Join(work, id+".stderr")}
	}
	peerArgs := makeArgs("partial-peer", "generation-peer")
	peerTAP := newNativePhysicalTAP(t, 0)
	peerArgs.Network = peerTAP.network
	require.NoError(t, client.Create(ctx, peerArgs))
	peer, err := client.loadStartState(peerArgs)
	require.NoError(t, err)
	require.Equal(t, 1, peer.ProcessLaunchVersion)
	require.Equal(t, nativeBirthPublished, peer.SentryLaunchState)
	require.Equal(t, nativeBirthPublished, peer.GoferLaunchState)
	peerSentry, peerGofer := nativePhysicalPidfd(t, peer.Sandbox.ProcessBirth), nativePhysicalPidfd(t, peer.GoferBirth)
	shared := nativePhysicalNullNamespace(t, root)
	shared.verify(t, peer.GoferBirth)
	require.NoError(t, client.Start(ctx, peerArgs))
	for {
		output, err := os.ReadFile(peerArgs.UserStdout)
		require.NoError(t, err)
		if strings.Contains(string(output), peerArgs.ID+"\nworkload-ready\n") {
			break
		}
		require.NoError(t, ctx.Err())
		time.Sleep(10 * time.Millisecond)
	}
	peer, err = client.loadState(peerArgs.ID)
	require.NoError(t, err)
	save("partial-peer-birth.json", peer)
	partialArgs := makeArgs("partial-original", "generation-partial")
	tracedClient := *client
	tracedClient.Binary = tracer
	creation := make(chan error, 1)
	go func() { creation <- tracedClient.Create(ctx, partialArgs) }()
	for {
		if _, err := os.Stat(filepath.Join(evidence, "partial-create-paused.json")); err == nil {
			break
		}
		select {
		case err := <-creation:
			save("partial-create-failure.json", map[string]any{"error": fmt.Sprint(err), "stdout": readOutputSnippet(partialArgs.UserStdout), "stderr": readOutputSnippet(partialArgs.UserStderr)})
			t.Fatalf("actual producer did not reach original partial publication: %v", err)
		default:
		}
		require.NoError(t, ctx.Err())
		time.Sleep(10 * time.Millisecond)
	}
	partial, err := client.loadNativeRetirementState(partialArgs.ID)
	require.NoError(t, err)
	require.Empty(t, partial.Sandbox.ID)
	require.Equal(t, "creating", partial.Status)
	require.Equal(t, nativeNotDispatched, partial.SentryLaunchState)
	require.Equal(t, nativeBirthPublished, partial.GoferLaunchState)
	partialGofer := nativePhysicalPidfd(t, partial.GoferBirth)
	if bindCgroup {
		for id, group := range groups {
			data, err := os.ReadFile(filepath.Join(root, managedLaunchDirectory, id+".json"))
			require.NoError(t, err)
			var record managedLaunchRecord
			require.NoError(t, json.Unmarshal(data, &record))
			require.Equal(t, 1, record.Version)
			require.Equal(t, id, record.SandboxID)
			require.True(t, record.CloneIntoCgroup)
			require.Equal(t, "dispatching", record.Stage)
			require.Equal(t, group, record.Cgroup.Path)
			fd, actual, err := openOriginalLaunchCgroup(group)
			require.NoError(t, err)
			require.Equal(t, record.Cgroup, actual)
			require.NoError(t, fd.Close())
			save(id+"-launch-intent.json", record)
		}
	}
	original, err := os.ReadFile(client.stateFilePath(partialArgs.ID))
	require.NoError(t, err)
	require.NoError(t, client.VerifyRuntimeGeneration(ctx, partialArgs.ID, partialArgs.ResourceGeneration))
	_, err = client.loadStartState(partialArgs)
	require.Error(t, err, "partial retirement source cannot authorize a control operation")
	save("partial-births-ready.json", map[string]any{"partial": partial, "peer": peer,
		"state_sha256": nativePhysicalSHA(t, client.stateFilePath(partialArgs.ID)), "control_source_refused": true})
	wait("allow-partial-delete")
	select {
	case err := <-creation:
		require.Error(t, err, "creator termination cannot become a successful create reply")
		save("partial-create-outcome.json", map[string]any{"error": err.Error(), "creation_success_reply_received": false})
	case <-ctx.Done():
		t.Fatal("original terminated creator did not return its failed create outcome")
	}
	current, err := os.ReadFile(client.stateFilePath(partialArgs.ID))
	require.NoError(t, err)
	require.Equal(t, original, current, "creator exit changed original partial owner bytes")
	require.Error(t, client.DeleteIfGeneration(ctx, partialArgs.ID, "generation-wrong"))
	current, err = os.ReadFile(client.stateFilePath(partialArgs.ID))
	require.NoError(t, err)
	require.Equal(t, original, current)
	verifyNativePhysicalBirth(t, peer.Sandbox.ProcessBirth)
	verifyNativePhysicalBirth(t, peer.GoferBirth)
	save("partial-wrong-generation-refused.json", map[string]any{"original_state_bytes_unchanged": true, "peer": peer})
	require.NoError(t, client.VerifyRuntimeGeneration(ctx, partialArgs.ID, partialArgs.ResourceGeneration))
	require.NoError(t, client.DeleteIfGeneration(ctx, partialArgs.ID, partialArgs.ResourceGeneration))
	verifyNativePhysicalExit(t, partialGofer)
	require.NoFileExists(t, client.stateFilePath(partialArgs.ID))
	verifyNativePhysicalBirth(t, peer.Sandbox.ProcessBirth)
	verifyNativePhysicalBirth(t, peer.GoferBirth)
	shared.verify(t, peer.GoferBirth)
	running, err := client.loadState(peerArgs.ID)
	require.NoError(t, err)
	require.Equal(t, "running", running.Status)
	peerTAP.verify(t)
	save("partial-deleted-peer-live.json", map[string]any{"original_id": partialArgs.ID, "original_generation": partialArgs.ResourceGeneration,
		"original_gofer_exit_confirmed_by_independent_pidfd": true, "peer": running})
	require.NoError(t, client.DeleteIfGeneration(ctx, peerArgs.ID, peerArgs.ResourceGeneration))
	verifyNativePhysicalExit(t, peerSentry)
	verifyNativePhysicalExit(t, peerGofer)
	inventory, err := client.ListJSON(ctx)
	require.NoError(t, err)
	var final []any
	require.NoError(t, json.Unmarshal(inventory, &final))
	require.Empty(t, final)
	save("final-native-inventory.json", map[string]any{"inventory": final})
	save("shared-fixture-namespace-cleanup.json", shared.retireEmptyFixtureRoot(t))
	save("fixture-tap-cleanup.json", peerTAP.retire(t))
	if bindCgroup {
		for _, group := range groups {
			path := filepath.Join("/sys/fs/cgroup", group)
			members, err := os.ReadFile(filepath.Join(path, "cgroup.procs"))
			require.NoError(t, err)
			require.Empty(t, strings.TrimSpace(string(members)))
			require.NoError(t, os.Remove(path))
		}
		save("launch-cgroup-fixture-cleanup.json", map[string]any{"groups": groups, "original_empty_groups_normally_removed": true,
			"scope": "This test's two original child cgroups only; no managed production cgroup cache or node budget settlement."})
	}
	save("partial-launch-summary.json", map[string]any{"producer_state_was_synthesized": false, "creator_terminated_by_external_original_pidfd": true,
		"three_original_birth_exits_confirmed": true, "peer_workload_started": true,
		"scope": "Actual gofer-only published birth followed by externally audited creator termination and original conditional retirement. First unpublished birth, complete daemon resources, deployment and node budget remain unverified."})
}
