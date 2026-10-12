// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// This record is a controlled verifier input for this ordinary test process,
// not a claim that a production initializer emitted a Sentry birth.
func testServingBirth(t *testing.T) *nativeRuntimeBirth {
	t.Helper()
	pid := os.Getpid()
	root := "/proc/" + strconv.Itoa(pid)
	data, err := os.ReadFile(root + "/stat")
	require.NoError(t, err)
	start, err := peerStartTicks(data, pid)
	require.NoError(t, err)
	birth := &nativeRuntimeBirth{Version: 1, ContainerID: "unit-original", Generation: "unit-generation", Role: "sentry", PID: pid, StartTicks: start, InitializerPID: pid}
	for path, target := range map[string]*string{"exe": &birth.ExecutableSHA256, "cmdline": &birth.ArgumentsSHA256, "cgroup": &birth.CgroupSHA256} {
		data, err := os.ReadFile(root + "/" + path)
		require.NoError(t, err)
		sum := sha256.Sum256(data)
		*target = hex.EncodeToString(sum[:])
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	require.NoError(t, err)
	birth.Scope.BootID = strings.TrimSpace(string(boot))
	var namespace unix.Stat_t
	require.NoError(t, unix.Stat("/proc/thread-self/ns/pid", &namespace))
	birth.Scope.PIDNamespaceDevice = uint64(namespace.Dev)
	birth.Scope.PIDNamespaceInode = namespace.Ino
	return birth
}

func TestServingProcessVerifierRequiresOriginalKernelBirth(t *testing.T) {
	original := testServingBirth(t)
	for _, kind := range []string{"valid", "start", "executable", "arguments", "cgroup", "boot", "namespace", "generation", "role", "nil"} {
		t.Run(kind, func(t *testing.T) {
			birth := *original
			source := &birth
			switch kind {
			case "start":
				birth.StartTicks++
			case "executable":
				birth.ExecutableSHA256 = strings.Repeat("a", 64)
			case "arguments":
				birth.ArgumentsSHA256 = strings.Repeat("a", 64)
			case "cgroup":
				birth.CgroupSHA256 = strings.Repeat("a", 64)
			case "boot":
				birth.Scope.BootID = "another-boot"
			case "namespace":
				birth.Scope.PIDNamespaceInode++
			case "generation":
				birth.Generation = "replacement"
			case "role":
				birth.Role = "gofer"
			case "nil":
				source = nil
			}
			p, err := openNativeServingProcess(context.Background(), source, original.ContainerID, original.Generation)
			if kind == "valid" {
				require.NoError(t, err)
				defer p.close()
				require.NoError(t, p.live(context.Background()))
			} else {
				require.Error(t, err)
				require.Nil(t, p)
			}
		})
	}
}

func TestServingProcessVerifierCancellationDoesNotAcquireAuthority(t *testing.T) {
	birth := testServingBirth(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p, err := openNativeServingProcess(ctx, birth, birth.ContainerID, birth.Generation)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, p)
}

func TestControlAncillaryFailureClosesAllDeliveredDescriptors(t *testing.T) {
	f, err := os.Open(os.DevNull)
	require.NoError(t, err)
	defer f.Close()
	fd, err := unix.Dup(int(f.Fd()))
	require.NoError(t, err)
	credentials := unix.UnixCredentials(&unix.Ucred{Pid: int32(os.Getpid()), Uid: uint32(os.Getuid()), Gid: uint32(os.Getgid())})
	oob := append(append(append([]byte{}, credentials...), credentials...), unix.UnixRights(fd)...)
	files, _, err := parseControlData(oob)
	require.Error(t, err)
	require.Empty(t, files)
	_, err = unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	require.ErrorIs(t, err, unix.EBADF)
}
