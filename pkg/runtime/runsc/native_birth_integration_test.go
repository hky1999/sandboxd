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
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	runtimeapi "github.com/inclusionAI/sandboxd/api/runtime/v1"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func nativePhysicalSHA(t *testing.T, path string) string {
	t.Helper()
	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()
	hash := sha256.New()
	_, err = io.Copy(hash, file)
	require.NoError(t, err)
	return hex.EncodeToString(hash.Sum(nil))
}

func verifyNativePhysicalBirth(t *testing.T, birth *nativeRuntimeBirth) {
	t.Helper()
	require.NotNil(t, birth)
	root := filepath.Join("/proc", strconv.Itoa(birth.PID))
	data, err := os.ReadFile(filepath.Join(root, "stat"))
	require.NoError(t, err)
	fields := strings.Fields(string(data)[strings.LastIndexByte(string(data), ')')+1:])
	require.GreaterOrEqual(t, len(fields), 20)
	start, err := strconv.ParseUint(fields[19], 10, 64)
	require.NoError(t, err)
	require.Equal(t, birth.StartTicks, start)
	require.Equal(t, birth.ExecutableSHA256, nativePhysicalSHA(t, filepath.Join(root, "exe")))
	for name, expected := range map[string]string{"cmdline": birth.ArgumentsSHA256, "cgroup": birth.CgroupSHA256} {
		require.Equal(t, expected, nativePhysicalSHA(t, filepath.Join(root, name)))
	}
}

func nativePhysicalPidfd(t *testing.T, birth *nativeRuntimeBirth) int {
	t.Helper()
	verifyNativePhysicalBirth(t, birth)
	fd, err := unix.PidfdOpen(birth.PID, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(fd) })
	verifyNativePhysicalBirth(t, birth)
	return fd
}

func verifyNativePhysicalExit(t *testing.T, fd int) {
	t.Helper()
	polls := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	count, err := unix.Poll(polls, 2000)
	require.NoError(t, err)
	require.Equal(t, 1, count, "the independent original process handle did not confirm exit")
	require.NotZero(t, polls[0].Revents&(unix.POLLIN|unix.POLLHUP))
}

// The null network namespace belongs to this private runtime root and is
// shared by its gofers. It must survive either container's retirement.
type nativePhysicalSharedNamespace struct {
	directory     *os.File
	directoryStat unix.Stat_t
	namespace     *os.File
	namespaceStat unix.Stat_t
	root          string
}

func nativePhysicalNullNamespace(t *testing.T, root string) *nativePhysicalSharedNamespace {
	t.Helper()
	directory, original, err := openRuntimeIdentityDirectory(root)
	require.NoError(t, err)
	t.Cleanup(func() { _ = directory.Close() })
	fd, err := unix.Openat(int(directory.Fd()), "null-netns", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	require.NoError(t, err)
	namespace := os.NewFile(uintptr(fd), "original private shared null namespace")
	t.Cleanup(func() { _ = namespace.Close() })
	var source unix.Stat_t
	require.NoError(t, unix.Fstat(fd, &source))
	var filesystem unix.Statfs_t
	require.NoError(t, unix.Fstatfs(fd, &filesystem))
	require.EqualValues(t, unix.NSFS_MAGIC, filesystem.Type)
	kind, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
	require.NoError(t, err)
	require.Equal(t, unix.CLONE_NEWNET, kind)
	return &nativePhysicalSharedNamespace{directory: directory, directoryStat: original, namespace: namespace, namespaceStat: source, root: root}
}

func (original *nativePhysicalSharedNamespace) verify(t *testing.T, gofer *nativeRuntimeBirth) {
	t.Helper()
	var directory, namespace unix.Stat_t
	require.NoError(t, unix.Lstat(original.root, &directory))
	require.Equal(t, original.directoryStat.Dev, directory.Dev)
	require.Equal(t, original.directoryStat.Ino, directory.Ino)
	require.Equal(t, original.directoryStat.Mode, directory.Mode)
	require.Equal(t, original.directoryStat.Uid, directory.Uid)
	require.NoError(t, unix.Fstatat(int(original.directory.Fd()), "null-netns", &namespace, unix.AT_SYMLINK_NOFOLLOW))
	require.Equal(t, original.namespaceStat.Dev, namespace.Dev)
	require.Equal(t, original.namespaceStat.Ino, namespace.Ino)
	require.Equal(t, original.namespaceStat.Mode, namespace.Mode)
	if gofer != nil {
		var current unix.Stat_t
		require.NoError(t, unix.Stat(filepath.Join("/proc", strconv.Itoa(gofer.PID), "ns/net"), &current))
		require.Equal(t, namespace.Dev, current.Dev)
		require.Equal(t, namespace.Ino, current.Ino)
	}
}

func (original *nativePhysicalSharedNamespace) retireEmptyFixtureRoot(t *testing.T) map[string]any {
	t.Helper()
	original.verify(t, nil)
	// All four independent process handles and the final empty inventory must
	// already be confirmed. Release our namespace FD before normal unmount;
	// never detach a busy mount or tear it down while the peer is alive.
	require.NoError(t, original.namespace.Close())
	path := filepath.Join("/proc/self/fd", strconv.Itoa(int(original.directory.Fd())), "null-netns")
	require.NoError(t, unix.Unmount(path, 0))
	fd, err := unix.Openat(int(original.directory.Fd()), "null-netns", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	require.NoError(t, err)
	defer unix.Close(fd)
	var filesystem unix.Statfs_t
	require.NoError(t, unix.Fstatfs(fd, &filesystem))
	require.NotEqualValues(t, unix.NSFS_MAGIC, filesystem.Type)
	return map[string]any{"root_device": original.directoryStat.Dev, "root_inode": original.directoryStat.Ino,
		"namespace_device": original.namespaceStat.Dev, "namespace_inode": original.namespaceStat.Ino,
		"normal_unmount_confirmed": true, "force_or_lazy_detach_used": false,
		"scope": "This test's private shared runtime root after four independent process exits and empty inventory; not a per-container resource or daemon root."}
}

func TestRealNativeCreationBirthConditionalDeletionAndLivePeer(t *testing.T) {
	runNativePhysicalFixture(t, false)
}

func TestRealNativeWorkloadStartConditionalDeletionAndLivePeer(t *testing.T) {
	runNativePhysicalFixture(t, true)
}

func runNativePhysicalFixture(t *testing.T, startWorkloads bool) {
	t.Helper()
	if os.Getenv("SANDBOXD_RUN_NATIVE_BIRTH_INTEGRATION") != "1" {
		t.Skip("requires an explicit isolated BareMetal1 native runtime test")
	}
	binary, expected := os.Getenv("NATIVE_BIRTH_RUNSC_BINARY"), os.Getenv("NATIVE_BIRTH_RUNSC_SHA256")
	rootfs, rootfsSHA := os.Getenv("NATIVE_BIRTH_ROOTFS"), os.Getenv("NATIVE_BIRTH_ROOTFS_SHA256")
	evidence := os.Getenv("NATIVE_BIRTH_EVIDENCE")
	require.True(t, filepath.IsAbs(binary) && filepath.IsAbs(rootfs) && filepath.IsAbs(evidence))
	require.True(t, nativeDigest(expected) && nativeDigest(rootfsSHA))
	require.Equal(t, expected, nativePhysicalSHA(t, binary))
	require.Equal(t, rootfsSHA, nativePhysicalSHA(t, rootfs))
	require.NoError(t, os.MkdirAll(evidence, 0700))
	scope := "Two actual created runtimes; no workload start, restore or budget acceptance."
	if startWorkloads {
		scope = "Two actual running workloads through native birth validation, private TAP and control RPC; no restore, daemon resource or node budget acceptance."
	}
	save := func(name string, value any) {
		data, err := json.MarshalIndent(value, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(evidence, name), append(data, '\n'), 0600))
	}
	work := t.TempDir()
	root, filestore, bundles := filepath.Join(work, "runsc"), filepath.Join(work, "filestore"), filepath.Join(work, "bundles")
	require.NoError(t, os.MkdirAll(root, 0700))
	require.NoError(t, os.MkdirAll(filestore, 0700))
	loader, err := runtimecore.NewBundleLoader("", bundles)
	require.NoError(t, err)
	client := NewClientWithOptions(binary, root, Options{FilestoreDir: filestore, OverlayTmpfsSize: "64M", IgnoreCgroups: true})
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	identities := [][2]string{{"birth-original", "generation-original"}, {"birth-peer", "generation-peer"}}
	states := make([]*containerState, 0, len(identities))
	handles := make([][2]int, 0, len(identities))
	starts := make([]StartArgs, 0, len(identities))
	var taps []*nativePhysicalTAP
	var sharedNamespace *nativePhysicalSharedNamespace
	for _, identity := range identities {
		export := filepath.Join(work, identity[0]+"-export")
		require.NoError(t, os.Mkdir(export, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(export, "marker"), []byte(identity[0]), 0600))
		config := runtimecore.StartConfig{
			ID: identity[0], ResourceGeneration: identity[1], Rootfs: rootfs, RootfsReadonly: true,
			DisableCgroup: true, Command: []string{"/bin/sleep", "120"},
			Mounts: []*runtimeapi.Mount{{Type: "bind", Source: &runtimeapi.Mount_HostPath{HostPath: export}, Target: "/tmp/native-birth-export", Options: []string{"ro", "rbind"}}},
		}
		if startWorkloads {
			config.Command = []string{"/bin/sh", "-c", "cat /tmp/native-birth-export/marker; printf 'workload-ready\\n'; exec /bin/sleep 120"}
		}
		bundle, _, err := loader.GenerateOci(runtimecore.OciLoadOptions{
			SandboxID: config.ID, Config: config, UseGVisorRootfsImageAnnotations: true,
			RootfsOverlayDir: filestore, RootfsOverlaySize: "64M",
			ManagedAnnotations: runtimeGenerationAnnotations(config.ResourceGeneration),
		})
		require.NoError(t, err)
		args := StartArgs{ID: config.ID, ResourceGeneration: config.ResourceGeneration, BundleDir: bundle,
			RootOverlay: RootFileOverlay(filestore, "64M"), UserStdout: filepath.Join(work, config.ID+".stdout"), UserStderr: filepath.Join(work, config.ID+".stderr")}
		if startWorkloads {
			tap := newNativePhysicalTAP(t, len(starts))
			args.Network = tap.network
			taps = append(taps, tap)
		}
		starts = append(starts, args)
		err = client.Create(ctx, args)
		if err != nil {
			save(config.ID+"-create-failure.json", map[string]any{"id": config.ID, "generation": config.ResourceGeneration, "error": err.Error(), "scope": "Original native create failure; no successful retirement inferred."})
		}
		require.NoError(t, err)
		state, err := client.loadStartState(args)
		require.NoError(t, err)
		require.True(t, state.GoferRequired, "the independent read-only export must exercise a real gofer")
		verifyNativePhysicalBirth(t, state.Sandbox.ProcessBirth)
		verifyNativePhysicalBirth(t, state.GoferBirth)
		handles = append(handles, [2]int{nativePhysicalPidfd(t, state.Sandbox.ProcessBirth), nativePhysicalPidfd(t, state.GoferBirth)})
		if sharedNamespace == nil {
			sharedNamespace = nativePhysicalNullNamespace(t, root)
		}
		sharedNamespace.verify(t, state.GoferBirth)
		save(config.ID+"-birth.json", state)
		states = append(states, state)
	}
	// The host observer must map all four native PIDs, verify actual process
	// bytes and start times outside the target cgroup before any SIGKILL path.
	save("births-ready.json", map[string]any{"states": states, "scope": scope})
	for {
		if _, err := os.Stat(filepath.Join(evidence, "allow-original-delete")); err == nil {
			break
		}
		require.NoError(t, ctx.Err(), "external original-process audit did not authorize the fixed owned test actions")
		time.Sleep(10 * time.Millisecond)
	}
	if startWorkloads {
		for index, args := range starts {
			if err := client.Start(ctx, args); err != nil {
				save(args.ID+"-start-failure.json", map[string]any{"id": args.ID, "generation": args.ResourceGeneration, "error": err.Error()})
				require.NoError(t, err)
			}
			for {
				output, err := os.ReadFile(args.UserStdout)
				require.NoError(t, err)
				if strings.Contains(string(output), args.ID+"\nworkload-ready\n") {
					break
				}
				require.NoError(t, ctx.Err(), "the actual workload did not read its own export and report readiness")
				time.Sleep(10 * time.Millisecond)
			}
			running, err := client.loadState(args.ID)
			require.NoError(t, err)
			require.Equal(t, "running", running.Status)
			require.NoError(t, validateNativeRuntimeBirth(running, args.ID, args.ResourceGeneration))
			require.Equal(t, states[index].Sandbox.ProcessBirth, running.Sandbox.ProcessBirth)
			require.Equal(t, states[index].GoferBirth, running.GoferBirth)
			verifyNativePhysicalBirth(t, running.Sandbox.ProcessBirth)
			verifyNativePhysicalBirth(t, running.GoferBirth)
			save(args.ID+"-workload-running.json", map[string]any{"state": running, "own_export_read": true, "workload_readiness_confirmed": true, "tap": taps[index].evidence(t)})
		}
	}
	require.Error(t, client.DeleteIfGeneration(ctx, identities[0][0], "generation-wrong"))
	for _, state := range states {
		verifyNativePhysicalBirth(t, state.Sandbox.ProcessBirth)
		verifyNativePhysicalBirth(t, state.GoferBirth)
	}
	save("wrong-generation-rejected.json", map[string]any{"states_unchanged": true})
	require.NoError(t, client.DeleteIfGeneration(ctx, identities[0][0], identities[0][1]))
	verifyNativePhysicalExit(t, handles[0][0])
	verifyNativePhysicalExit(t, handles[0][1])
	require.NoFileExists(t, client.stateFilePath(identities[0][0]))
	verifyNativePhysicalBirth(t, states[1].Sandbox.ProcessBirth)
	verifyNativePhysicalBirth(t, states[1].GoferBirth)
	sharedNamespace.verify(t, states[1].GoferBirth)
	if startWorkloads {
		running, err := client.loadState(starts[1].ID)
		require.NoError(t, err)
		require.Equal(t, "running", running.Status)
		for _, tap := range taps {
			tap.verify(t)
		}
	}
	save("original-deleted-peer-live.json", map[string]any{"original_id": identities[0][0], "original_exit_confirmed_by_independent_pidfds": true, "peer": states[1]})
	require.NoError(t, client.DeleteIfGeneration(ctx, identities[1][0], identities[1][1]))
	verifyNativePhysicalExit(t, handles[1][0])
	verifyNativePhysicalExit(t, handles[1][1])
	require.NoFileExists(t, client.stateFilePath(identities[1][0]))
	inventory, err := client.ListJSON(ctx)
	require.NoError(t, err)
	var final []any
	require.NoError(t, json.Unmarshal(inventory, &final))
	require.Empty(t, final)
	save("final-native-inventory.json", map[string]any{"inventory": final, "scope": scope})
	save("shared-fixture-namespace-cleanup.json", sharedNamespace.retireEmptyFixtureRoot(t))
	if startWorkloads {
		var cleaned []map[string]any
		for _, tap := range taps {
			cleaned = append(cleaned, tap.retire(t))
		}
		save("private-tap-cleanup.json", cleaned)
	}
}
