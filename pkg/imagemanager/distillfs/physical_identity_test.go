// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package distillfs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// A controlled original birth; these hooks never signal or unmount the host.
func attachTestPhysicalBirth(t *testing.T, d *Daemon) *physicalIdentity {
	t.Helper()
	require.NoError(t, os.MkdirAll(d.meta.DaemonDir, 0700))
	require.NoError(t, os.MkdirAll(d.meta.MountPoint, 0700))
	require.NoError(t, d.applyConfig())
	generation := strings.Repeat("a", 64)
	d.meta.PidFilePath = filepath.Join(d.meta.DaemonDir, "pid-"+generation)
	source, err := d.sourceIdentitySHA()
	require.NoError(t, err)
	p := &physicalIdentity{Generation: generation, Scope: physicalScope{BootID: "00000000-0000-0000-0000-000000000001", MountNSDevice: 1, MountNSInode: 2, PIDNSDevice: 1, PIDNSInode: 3}, Target: d.meta.MountPoint, PIDFile: d.meta.PidFilePath, ExecutableSHA256: strings.Repeat("b", 64), ArgumentsSHA256: strings.Repeat("c", 64), SourceSHA256: source, Phase: "running"}
	p.Process = &physicalProcessIdentity{PID: 987654321, StartTicks: 10, ExecutableSHA256: p.ExecutableSHA256, ArgumentsSHA256: p.ArgumentsSHA256}
	p.Mount = &physicalMountIdentity{MountID: 20, UniqueMountID: 9001, Major: 0, Minor: 15, Root: "/", Filesystem: "fuse.distillfs", Source: "original"}
	d.physicalScopeFunc = func() (physicalScope, error) { return p.Scope, nil }
	d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) { copy := *p.Process; return &copy, nil }
	d.physicalMountFunc = func(string) (*physicalMountIdentity, error) { copy := *p.Mount; return &copy, nil }
	d.physicalSignalFunc = func(*physicalProcessIdentity, syscall.Signal) error { return errors.New("unexpected test signal") }
	require.NoError(t, os.WriteFile(d.meta.PidFilePath, []byte(strconv.Itoa(p.Process.PID)), 0600))
	require.NoError(t, d.publishPhysicalIdentity(p))
	return clonePhysicalIdentity(p)
}

func TestDaemonPhysicalBirthReplacementMountIsNotUnmounted(t *testing.T) {
	d := newMockDaemon(t.TempDir()).Daemon
	original := attachTestPhysicalBirth(t, d)
	d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) { return nil, nil }
	replacement := *original.Mount
	replacement.UniqueMountID++
	d.physicalMountFunc = func(string) (*physicalMountIdentity, error) { return &replacement, nil }
	calls := 0
	d.unmountTargetFunc = func(string, int) error { calls++; return nil }
	require.Error(t, d.UnmountIfPhysicalGeneration(original.Generation))
	require.Zero(t, calls)
	require.FileExists(t, d.meta.PidFilePath)
	require.Equal(t, original.Mount, d.originalPhysicalIdentity().Mount)
	require.Error(t, d.Mount())
}

func TestDaemonPhysicalBirthScopeChangePreventsSignals(t *testing.T) {
	for _, mode := range []string{"boot", "mount namespace", "PID namespace"} {
		t.Run(mode, func(t *testing.T) {
			d := newMockDaemon(t.TempDir()).Daemon
			original := attachTestPhysicalBirth(t, d)
			scope := original.Scope
			switch mode {
			case "boot":
				scope.BootID = "00000000-0000-0000-0000-000000000002"
			case "mount namespace":
				scope.MountNSInode++
			default:
				scope.PIDNSInode++
			}
			d.physicalScopeFunc = func() (physicalScope, error) { return scope, nil }
			calls := 0
			d.physicalSignalFunc = func(*physicalProcessIdentity, syscall.Signal) error { calls++; return nil }
			require.Error(t, d.signalOriginalProcess(syscall.SIGTERM))
			require.Error(t, d.signalOriginalProcess(syscall.SIGKILL))
			require.Zero(t, calls)
		})
	}
}

func TestDaemonPhysicalBirthReusedPIDPreventsSignals(t *testing.T) {
	d := newMockDaemon(t.TempDir()).Daemon
	original := attachTestPhysicalBirth(t, d)
	reused := *original.Process
	reused.StartTicks++ // Same PID, executable and command line are insufficient.
	d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) { return &reused, nil }
	calls := 0
	d.physicalSignalFunc = func(*physicalProcessIdentity, syscall.Signal) error { calls++; return nil }
	require.Error(t, d.signalOriginalProcess(syscall.SIGTERM))
	require.Error(t, d.UnmountIfPhysicalGeneration(original.Generation))
	require.Zero(t, calls)
	require.FileExists(t, d.meta.PidFilePath)
}

func TestDaemonPhysicalBirthUnknownProcessKeepsRetirementPending(t *testing.T) {
	d := newMockDaemon(t.TempDir()).Daemon
	original := attachTestPhysicalBirth(t, d)
	d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) {
		return nil, errors.New("original observation unavailable")
	}
	calls := 0
	d.unmountTargetFunc = func(string, int) error { calls++; return nil }
	require.Error(t, d.UnmountIfPhysicalGeneration(original.Generation))
	require.Zero(t, calls)
	require.FileExists(t, d.meta.PidFilePath)
	require.Equal(t, "releasing", d.originalPhysicalIdentity().Phase)
}

func TestDaemonPhysicalBirthRestartRetainsSuccessfulUnmount(t *testing.T) {
	d := newMockDaemon(t.TempDir()).Daemon
	original := attachTestPhysicalBirth(t, d)
	d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) { return nil, nil }
	probes, calls := 0, 0
	d.physicalMountFunc = func(string) (*physicalMountIdentity, error) {
		probes++
		if probes >= 3 {
			return nil, errors.New("post-unmount read unavailable")
		}
		copy := *original.Mount
		return &copy, nil
	}
	d.unmountTargetFunc = func(string, int) error { calls++; return nil }
	require.Error(t, d.UnmountIfPhysicalGeneration(original.Generation))
	require.Equal(t, 1, calls)
	reloaded := &Daemon{ctx: context.Background(), binPath: d.binPath}
	require.NoError(t, reloaded.LoadExisted(d.savedPath))
	require.True(t, reloaded.targetUnmountSucceeded)
	require.True(t, reloaded.releasePending)
	reloaded.physicalScopeFunc = func() (physicalScope, error) { return original.Scope, nil }
	reloaded.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) { return nil, nil }
	replacement := *original.Mount
	replacement.UniqueMountID++
	reloaded.physicalMountFunc = func(string) (*physicalMountIdentity, error) { return &replacement, nil }
	reloaded.unmountTargetFunc = func(string, int) error { calls++; return nil }
	require.Error(t, reloaded.UnmountIfPhysicalGeneration(original.Generation))
	require.Equal(t, 1, calls)
	reloaded.physicalMountFunc = func(string) (*physicalMountIdentity, error) { return nil, nil }
	require.NoError(t, reloaded.UnmountIfPhysicalGeneration(original.Generation))
	require.Equal(t, 1, calls)
	require.Equal(t, "released", reloaded.originalPhysicalIdentity().Phase)
}

func TestDaemonPhysicalBirthCompletedReplayDoesNotTouchReplacement(t *testing.T) {
	d := newMockDaemon(t.TempDir()).Daemon
	original := attachTestPhysicalBirth(t, d)
	d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) { return nil, nil }
	d.physicalMountFunc = func(string) (*physicalMountIdentity, error) { return nil, nil }
	require.NoError(t, d.UnmountIfPhysicalGeneration(original.Generation))
	before, err := os.ReadFile(d.savedPath)
	require.NoError(t, err)
	observations := 0
	d.physicalMountFunc = func(string) (*physicalMountIdentity, error) {
		observations++
		return nil, errors.New("replacement observation is forbidden")
	}
	d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) {
		observations++
		return nil, errors.New("replacement observation is forbidden")
	}
	require.NoError(t, d.UnmountIfPhysicalGeneration(original.Generation))
	require.Zero(t, observations)
	after, err := os.ReadFile(d.savedPath)
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.Error(t, d.UnmountIfPhysicalGeneration(strings.Repeat("d", 64)))
}

func TestDaemonPhysicalBirthLatePublicationCannotCancelRelease(t *testing.T) {
	d := newMockDaemon(t.TempDir()).Daemon
	original := attachTestPhysicalBirth(t, d)
	late := clonePhysicalIdentity(original)
	d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) { return nil, nil }
	probes, unmounts := 0, 0
	d.physicalMountFunc = func(string) (*physicalMountIdentity, error) {
		probes++
		if probes >= 3 {
			return nil, errors.New("post-unmount observation unavailable")
		}
		copy := *original.Mount
		return &copy, nil
	}
	d.unmountTargetFunc = func(string, int) error { unmounts++; return nil }
	require.Error(t, d.UnmountIfPhysicalGeneration(original.Generation))
	require.Equal(t, 1, unmounts)
	require.NoError(t, d.publishPhysicalIdentity(late)) // A late birth may add facts, never reopen.
	current := d.originalPhysicalIdentity()
	require.Equal(t, "releasing", current.Phase)
	require.True(t, current.UnmountSucceeded)
	data, err := os.ReadFile(d.savedPath)
	require.NoError(t, err)
	meta, err := decodeDaemonMetadata(data)
	require.NoError(t, err)
	require.Equal(t, current, meta.PhysicalIdentity)
	d.physicalMountFunc = func(string) (*physicalMountIdentity, error) { return nil, nil }
	require.NoError(t, d.UnmountIfPhysicalGeneration(original.Generation))
	require.Error(t, d.publishPhysicalIdentity(late))
	require.Equal(t, "released", d.originalPhysicalIdentity().Phase)
	require.Equal(t, 1, unmounts)
}

func TestDaemonPhysicalBirthCompletionPublicationFailureCannotReplaySuccess(t *testing.T) {
	d := newMockDaemon(t.TempDir()).Daemon
	original := attachTestPhysicalBirth(t, d)
	observations, syncAttempts := 0, 0
	d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) { observations++; return nil, nil }
	d.physicalMountFunc = func(string) (*physicalMountIdentity, error) { observations++; return nil, nil }
	failCompletion := true
	d.metadataDirectorySyncFunc = func(directory *os.File) error {
		if d.meta.PhysicalIdentity.Phase == "released" {
			syncAttempts++
			if failCompletion {
				return errors.New("completion directory sync unavailable")
			}
		}
		return directory.Sync()
	}
	require.Error(t, d.UnmountIfPhysicalGeneration(original.Generation))
	require.True(t, d.releasePending)
	before := observations
	require.Error(t, d.UnmountIfPhysicalGeneration(original.Generation))
	require.True(t, d.releasePending)
	require.Equal(t, before, observations)
	require.Equal(t, 2, syncAttempts)
	failCompletion = false
	require.NoError(t, d.UnmountIfPhysicalGeneration(original.Generation))
	require.False(t, d.releasePending)
	require.Equal(t, before, observations)
	require.Equal(t, 3, syncAttempts)
	data, err := os.ReadFile(d.savedPath)
	require.NoError(t, err)
	meta, err := decodeDaemonMetadata(data)
	require.NoError(t, err)
	require.Equal(t, "released", meta.PhysicalIdentity.Phase)
	require.NoError(t, d.UnmountIfPhysicalGeneration(original.Generation))
	require.Equal(t, 3, syncAttempts)
}

func TestDaemonPhysicalBirthOriginalRecordCannotBeRewritten(t *testing.T) {
	changes := map[string]func(*physicalIdentity){
		"boot":          func(p *physicalIdentity) { p.Scope.BootID = "00000000-0000-0000-0000-000000000002" },
		"target":        func(p *physicalIdentity) { p.Target += "-replacement" },
		"PID file":      func(p *physicalIdentity) { p.PIDFile += "-replacement" },
		"source":        func(p *physicalIdentity) { p.SourceSHA256 = strings.Repeat("d", 64) },
		"arguments":     func(p *physicalIdentity) { p.ArgumentsSHA256 = strings.Repeat("d", 64) },
		"executable":    func(p *physicalIdentity) { p.ExecutableSHA256 = strings.Repeat("d", 64) },
		"process birth": func(p *physicalIdentity) { p.Process.StartTicks++ },
		"mount birth":   func(p *physicalIdentity) { p.Mount.UniqueMountID++ },
		"skip release":  func(p *physicalIdentity) { p.Phase = "released" },
		"new generation": func(p *physicalIdentity) {
			p.Generation = strings.Repeat("d", 64)
			p.PIDFile = filepath.Join(filepath.Dir(p.PIDFile), "pid-"+p.Generation)
			p.Phase, p.Process, p.Mount = "launching", nil, nil
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			d := newMockDaemon(t.TempDir()).Daemon
			original := attachTestPhysicalBirth(t, d)
			before, err := os.ReadFile(d.savedPath)
			require.NoError(t, err)
			replacement := clonePhysicalIdentity(original)
			change(replacement)
			require.Error(t, d.publishPhysicalIdentity(replacement))
			require.Equal(t, original, d.originalPhysicalIdentity())
			require.Equal(t, original.PIDFile, d.meta.PidFilePath)
			after, err := os.ReadFile(d.savedPath)
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
}

func TestDaemonPhysicalBirthPendingCompletionBlocksNewLaunch(t *testing.T) {
	d := newMockDaemon(t.TempDir()).Daemon
	original := attachTestPhysicalBirth(t, d)
	observations := 0
	d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) { observations++; return nil, nil }
	d.physicalMountFunc = func(string) (*physicalMountIdentity, error) { observations++; return nil, nil }
	d.metadataDirectorySyncFunc = func(directory *os.File) error {
		if d.meta.PhysicalIdentity.Phase == "released" {
			return errors.New("completion publication unavailable")
		}
		return directory.Sync()
	}
	require.Error(t, d.UnmountIfPhysicalGeneration(original.Generation))
	before := observations
	require.Error(t, d.preparePhysicalLaunch())
	require.Equal(t, before, observations)
	require.Equal(t, original.Generation, d.originalPhysicalIdentity().Generation)
	require.Equal(t, original.PIDFile, d.meta.PidFilePath)
	require.True(t, d.releasePending)
}

func TestDaemonPhysicalBirthLegacyRecordDoesNotAdoptCurrentPID(t *testing.T) {
	mock := newMockDaemon(t.TempDir())
	require.NoError(t, mock.applyConfig())
	require.NoError(t, mock.saveMeta()) // Metadata alone contains no original birth.
	d := &Daemon{ctx: context.Background(), binPath: mock.binPath}
	require.NoError(t, d.LoadExisted(mock.savedPath))
	require.True(t, d.releasePending)
	observations := 0
	d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) { observations++; return nil, nil }
	require.Error(t, d.Mount())
	require.Error(t, d.Unmount())
	require.Zero(t, observations)
}

func TestDaemonPhysicalBirthLaunchIntentIsDurableBeforeDispatch(t *testing.T) {
	d := newMockDaemon(t.TempDir()).Daemon
	require.NoError(t, os.MkdirAll(d.meta.DaemonDir, 0700))
	require.NoError(t, d.applyConfig())
	d.binPath = filepath.Join(d.meta.DaemonDir, "fake-never-executed")
	require.NoError(t, os.WriteFile(d.binPath, []byte("fake executable identity only"), 0600))
	d.physicalMountFunc = func(string) (*physicalMountIdentity, error) { return nil, nil }
	d.physicalScopeFunc = func() (physicalScope, error) {
		return physicalScope{BootID: "00000000-0000-0000-0000-000000000001", MountNSInode: 2, PIDNSInode: 3}, nil
	}
	require.NoError(t, d.preparePhysicalLaunch())
	data, err := os.ReadFile(d.savedPath)
	require.NoError(t, err)
	meta, err := decodeDaemonMetadata(data)
	require.NoError(t, err)
	require.Equal(t, "launching", meta.PhysicalIdentity.Phase)
	require.Nil(t, meta.PhysicalIdentity.Process)
	require.Nil(t, meta.PhysicalIdentity.Mount)
	require.Equal(t, filepath.Join(d.meta.DaemonDir, "pid-"+meta.PhysicalIdentity.Generation), meta.PidFilePath)
	reloaded := &Daemon{ctx: context.Background(), binPath: d.binPath}
	require.NoError(t, reloaded.LoadExisted(d.savedPath))
	require.Error(t, reloaded.Unmount())
	require.Equal(t, meta.PhysicalIdentity.Generation, reloaded.originalPhysicalIdentity().Generation)
}

func TestDaemonPhysicalBirthChangedSourceStopsMountRelease(t *testing.T) {
	d := newMockDaemon(t.TempDir()).Daemon
	original := attachTestPhysicalBirth(t, d)
	require.NoError(t, os.WriteFile(d.meta.CfgPath, []byte(`{"type":"other-original-source"}`), 0600))
	d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) { return nil, nil }
	calls := 0
	d.unmountTargetFunc = func(string, int) error { calls++; return nil }
	require.Error(t, d.UnmountIfPhysicalGeneration(original.Generation))
	require.Zero(t, calls)
}

func TestDaemonPhysicalBirthProcessStatParsing(t *testing.T) {
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0], fields[19] = "S", "101"
	data := []byte(fmt.Sprintf("42 (name ) containing spaces) %s\n", strings.Join(fields, " ")))
	start, err := parseProcessStart(data, 42)
	require.NoError(t, err)
	require.Equal(t, uint64(101), start)
	require.Error(t, func() error { _, err := parseProcessStart(data, 43); return err }())
	fields[19] = "0"
	_, err = parseProcessStart([]byte("42 (name) "+strings.Join(fields, " ")), 42)
	require.Error(t, err)
}
