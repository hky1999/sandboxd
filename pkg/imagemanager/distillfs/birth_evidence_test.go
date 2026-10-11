// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package distillfs

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// All process, mount and signal observations are controlled. No real daemon,
// cgroup, kernel mount or physical fault is used by these private-file checks.
func birthEvidenceFixture(t *testing.T) (*Daemon, *physicalIdentity, *physicalProcessIdentity) {
	t.Helper()
	d, _ := lateDispatchFixture(t)
	require.NoError(t, d.applyConfig())
	require.NoError(t, d.preparePhysicalLaunch())
	p := d.originalPhysicalIdentity()
	process := &physicalProcessIdentity{PID: 987654321, StartTicks: 10, ExecutableSHA256: p.ExecutableSHA256, ArgumentsSHA256: p.ArgumentsSHA256}
	d.physicalScopeFunc = func() (physicalScope, error) { return p.Scope, nil }
	d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) { copy := *process; return &copy, nil }
	d.physicalSignalFunc = func(*physicalProcessIdentity, syscall.Signal) error {
		t.Fatal("unexpected physical signal")
		return nil
	}
	require.NoError(t, os.WriteFile(p.PIDFile, []byte(strconv.Itoa(process.PID)), 0600))
	return d, p, process
}

func reopenBirthEvidenceFixture(t *testing.T, d *Daemon) *Daemon {
	t.Helper()
	p := d.originalPhysicalIdentity()
	reopened := newMockDaemon(t.TempDir()).Daemon
	require.NoError(t, reopened.loadDaemonMetadata(d.savedPath))
	reopened.isAliveFunc = nil
	reopened.physicalScopeFunc = func() (physicalScope, error) { return p.Scope, nil }
	reopened.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) { return nil, nil }
	reopened.physicalMountFunc = func(string) (*physicalMountIdentity, error) { return nil, nil }
	reopened.physicalSignalFunc = func(*physicalProcessIdentity, syscall.Signal) error { t.Fatal("unexpected signal"); return nil }
	reopened.unmountTargetFunc = func(string, int) error { t.Fatal("unexpected unmount"); return nil }
	return reopened
}

func TestDaemonPhysicalBirthEvidencePublicationFailureDoesNotPublishMetadata(t *testing.T) {
	d, original, process := birthEvidenceFixture(t)
	d.birthDirectorySyncFunc = func(*os.File) error { return errors.New("controlled independent directory sync failure") }
	require.Error(t, d.captureOriginalProcess())
	require.Nil(t, d.originalPhysicalIdentity().Process)
	reopened := reopenBirthEvidenceFixture(t, d)
	require.Nil(t, reopened.originalPhysicalIdentity().Process)
	require.NoError(t, reopened.UnmountIfPhysicalGeneration(original.Generation))
	require.Equal(t, process, reopened.originalPhysicalIdentity().Process)
	require.Equal(t, "released", reopened.originalPhysicalIdentity().Phase)
}

func TestDaemonPhysicalBirthEvidenceImmutableReplayRejectsDifferentProcess(t *testing.T) {
	d, original, process := birthEvidenceFixture(t)
	require.NoError(t, d.captureOriginalProcess())
	path := d.physicalBirthPath(original, "process")
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, d.captureOriginalProcess())
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after)
	changed := *process
	changed.StartTicks++
	d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) { return &changed, nil }
	require.Error(t, d.captureOriginalProcess())
	after, err = os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.Equal(t, process, d.originalPhysicalIdentity().Process)
}

func TestDaemonPhysicalBirthEvidenceMissingCannotAdoptCurrentPID(t *testing.T) {
	d, original, _ := birthEvidenceFixture(t)
	reopened := reopenBirthEvidenceFixture(t, d)
	reopened.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) {
		t.Fatal("missing original fact cannot authorize a PID lookup")
		return nil, nil
	}
	require.Error(t, reopened.UnmountIfPhysicalGeneration(original.Generation))
	require.Nil(t, reopened.originalPhysicalIdentity().Process)
	require.False(t, reopened.originalPhysicalIdentity().NoDispatchConfirmed)
	require.Equal(t, "releasing", reopened.originalPhysicalIdentity().Phase)
	require.FileExists(t, original.PIDFile)
}

func TestDaemonPhysicalBirthEvidenceMissingMountCannotAdoptCurrentMount(t *testing.T) {
	d, original, _ := birthEvidenceFixture(t)
	require.NoError(t, d.captureOriginalProcess())
	reopened := reopenBirthEvidenceFixture(t, d)
	reopened.physicalMountFunc = func(string) (*physicalMountIdentity, error) {
		return &physicalMountIdentity{MountID: 20, UniqueMountID: 9001, Filesystem: "fuse.distillfs"}, nil
	}
	require.Error(t, reopened.UnmountIfPhysicalGeneration(original.Generation))
	require.Nil(t, reopened.originalPhysicalIdentity().Mount)
	require.Equal(t, "releasing", reopened.originalPhysicalIdentity().Phase)
	require.FileExists(t, original.PIDFile)
}

func TestDaemonPhysicalBirthEvidenceReusedPIDRetainsOriginal(t *testing.T) {
	d, original, process := birthEvidenceFixture(t)
	require.NoError(t, d.captureOriginalProcess())
	reopened := reopenBirthEvidenceFixture(t, d)
	changed := *process
	changed.StartTicks++
	reopened.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) { return &changed, nil }
	require.Error(t, reopened.UnmountIfPhysicalGeneration(original.Generation))
	require.Equal(t, process, reopened.originalPhysicalIdentity().Process)
	require.Equal(t, "releasing", reopened.originalPhysicalIdentity().Phase)
	require.FileExists(t, original.PIDFile)
}

func TestDaemonPhysicalBirthEvidenceWrongGenerationDoesNotReconcile(t *testing.T) {
	d, original, _ := birthEvidenceFixture(t)
	old, err := os.ReadFile(d.savedPath)
	require.NoError(t, err)
	require.NoError(t, d.captureOriginalProcess())
	require.NoError(t, os.WriteFile(d.savedPath, old, 0600))
	reopened := reopenBirthEvidenceFixture(t, d)
	require.Error(t, reopened.UnmountIfPhysicalGeneration("wrong-generation"))
	require.Nil(t, reopened.originalPhysicalIdentity().Process)
	require.Equal(t, "launching", reopened.originalPhysicalIdentity().Phase)
	after, err := os.ReadFile(d.savedPath)
	require.NoError(t, err)
	require.Equal(t, old, after)
	require.FileExists(t, original.PIDFile)
}

func TestDaemonPhysicalBirthEvidenceReplacementDirectoryPreservesNeighbor(t *testing.T) {
	d, original, _ := birthEvidenceFixture(t)
	require.NoError(t, d.captureOriginalProcess())
	reopened := reopenBirthEvidenceFixture(t, d)
	require.NoError(t, os.Rename(d.meta.DaemonDir, d.meta.DaemonDir+"-original"))
	require.NoError(t, os.Mkdir(d.meta.DaemonDir, 0700))
	neighbor := filepath.Join(d.meta.DaemonDir, "neighbor-resource")
	require.NoError(t, os.WriteFile(neighbor, []byte("neighbor"), 0600))
	require.Error(t, reopened.UnmountIfPhysicalGeneration(original.Generation))
	require.FileExists(t, neighbor)
	require.FileExists(t, filepath.Join(d.meta.DaemonDir+"-original", physicalBirthName(original, "process")))
	require.Equal(t, "releasing", reopened.originalPhysicalIdentity().Phase)
}

func TestDaemonPhysicalBirthEvidenceInvalidRecordCannotReconcile(t *testing.T) {
	cases := map[string]func(*physicalBirthRecord){
		"schema":           func(r *physicalBirthRecord) { r.SchemaVersion = 2 },
		"daemon":           func(r *physicalBirthRecord) { r.DaemonID = "neighbor" },
		"kind":             func(r *physicalBirthRecord) { r.Kind = "mount" },
		"generation":       func(r *physicalBirthRecord) { r.Original.Generation = metadataSHA([]byte("neighbor")) },
		"source":           func(r *physicalBirthRecord) { r.Original.SourceSHA256 = metadataSHA([]byte("neighbor")) },
		"scope":            func(r *physicalBirthRecord) { r.Original.Scope.PIDNSInode++ },
		"directory":        func(r *physicalBirthRecord) { r.Original.BirthDirectory.Inode++ },
		"phase":            func(r *physicalBirthRecord) { r.Original.Phase = "running" },
		"unstarted":        func(r *physicalBirthRecord) { r.Original.NoDispatchConfirmed = true },
		"process":          func(r *physicalBirthRecord) { r.Process.StartTicks = 0 },
		"missing_process":  func(r *physicalBirthRecord) { r.Process = nil },
		"unexpected_mount": func(r *physicalBirthRecord) { r.Mount = &physicalMountIdentity{MountID: 1} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d, original, _ := birthEvidenceFixture(t)
			old, err := os.ReadFile(d.savedPath)
			require.NoError(t, err)
			require.NoError(t, d.captureOriginalProcess())
			path := d.physicalBirthPath(original, "process")
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			var record physicalBirthRecord
			require.NoError(t, json.Unmarshal(data, &record))
			mutate(&record)
			record.IntegritySHA256 = physicalBirthDigest(record)
			data, err = json.Marshal(record)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(path, data, 0600))
			require.NoError(t, os.WriteFile(d.savedPath, old, 0600))
			reopened := reopenBirthEvidenceFixture(t, d)
			require.Error(t, reopened.UnmountIfPhysicalGeneration(original.Generation))
			require.Nil(t, reopened.originalPhysicalIdentity().Process)
			require.FileExists(t, original.PIDFile)
		})
	}
}

func TestDaemonPhysicalBirthEvidenceUnsafeFileCannotReconcile(t *testing.T) {
	for _, fault := range []string{"missing", "checksum", "duplicate", "unknown", "trailing", "oversized", "symlink", "hardlink", "fifo", "permissions"} {
		t.Run(fault, func(t *testing.T) {
			d, original, _ := birthEvidenceFixture(t)
			require.NoError(t, d.captureOriginalProcess())
			path := d.physicalBirthPath(original, "process")
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			switch fault {
			case "missing":
				require.NoError(t, os.Remove(path))
			case "checksum":
				data = bytes.Replace(data, []byte(`"start_ticks":10`), []byte(`"start_ticks":11`), 1)
				require.NoError(t, os.WriteFile(path, data, 0600))
			case "duplicate":
				data = append([]byte(`{"schema_version":1,`), data[1:]...)
				require.NoError(t, os.WriteFile(path, data, 0600))
			case "unknown":
				data = append([]byte(`{"unknown":true,`), data[1:]...)
				require.NoError(t, os.WriteFile(path, data, 0600))
			case "trailing":
				require.NoError(t, os.WriteFile(path, append(data, []byte(`{}`)...), 0600))
			case "oversized":
				require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte("x"), physicalBirthLimit+1), 0600))
			case "symlink", "fifo":
				require.NoError(t, os.Rename(path, path+"-original"))
				if fault == "symlink" {
					require.NoError(t, os.Symlink(path+"-original", path))
				} else {
					require.NoError(t, syscall.Mkfifo(path, 0600))
				}
			case "hardlink":
				require.NoError(t, os.Link(path, path+"-alias"))
			case "permissions":
				require.NoError(t, os.Chmod(path, 0644))
			}
			reopened := reopenBirthEvidenceFixture(t, d)
			require.Error(t, reopened.UnmountIfPhysicalGeneration(original.Generation))
			require.Equal(t, "releasing", reopened.originalPhysicalIdentity().Phase)
			require.FileExists(t, original.PIDFile)
		})
	}
}

func TestDaemonPhysicalBirthEvidenceCompletedReplayDoesNotReadReplacement(t *testing.T) {
	d, original, _ := birthEvidenceFixture(t)
	require.NoError(t, d.captureOriginalProcess())
	reopened := reopenBirthEvidenceFixture(t, d)
	require.NoError(t, reopened.UnmountIfPhysicalGeneration(original.Generation))
	require.NoError(t, os.Rename(d.meta.DaemonDir, d.meta.DaemonDir+"-original"))
	require.NoError(t, os.Mkdir(d.meta.DaemonDir, 0700))
	neighbor := filepath.Join(d.meta.DaemonDir, "neighbor-resource")
	require.NoError(t, os.WriteFile(neighbor, []byte("neighbor"), 0600))
	reopened.physicalScopeFunc = func() (physicalScope, error) {
		t.Fatal("completed replay cannot inspect scope")
		return physicalScope{}, nil
	}
	require.NoError(t, reopened.UnmountIfPhysicalGeneration(original.Generation))
	require.FileExists(t, neighbor)
}

func TestDaemonPhysicalBirthEvidenceMetadataFailureKeepsPendingRetirement(t *testing.T) {
	d, original, _ := birthEvidenceFixture(t)
	old, err := os.ReadFile(d.savedPath)
	require.NoError(t, err)
	require.NoError(t, d.captureOriginalProcess())
	require.NoError(t, os.WriteFile(d.savedPath, old, 0600))
	reopened := reopenBirthEvidenceFixture(t, d)
	reopened.metadataDirectorySyncFunc = func(*os.File) error { return errors.New("controlled release sync failure") }
	require.Error(t, reopened.UnmountIfPhysicalGeneration(original.Generation))
	require.NotEqual(t, "released", reopened.originalPhysicalIdentity().Phase)
	require.FileExists(t, original.PIDFile)
	reopened.metadataDirectorySyncFunc = nil
	require.NoError(t, reopened.UnmountIfPhysicalGeneration(original.Generation))
	require.Equal(t, "released", reopened.originalPhysicalIdentity().Phase)
}

func TestDaemonPhysicalBirthEvidenceAdoptionSyncFailurePreventsCleanup(t *testing.T) {
	d, original, _ := birthEvidenceFixture(t)
	old, err := os.ReadFile(d.savedPath)
	require.NoError(t, err)
	require.NoError(t, d.captureOriginalProcess())
	require.NoError(t, os.WriteFile(d.savedPath, old, 0600))
	reopened := reopenBirthEvidenceFixture(t, d)
	calls := 0
	reopened.metadataDirectorySyncFunc = func(directory *os.File) error {
		calls++
		if calls == 2 {
			return errors.New("controlled adopted identity sync failure")
		}
		return directory.Sync()
	}
	require.Error(t, reopened.UnmountIfPhysicalGeneration(original.Generation))
	require.True(t, reopened.physicalPublicationPending)
	require.Equal(t, "releasing", reopened.originalPhysicalIdentity().Phase)
	require.FileExists(t, original.PIDFile)
	reopened.metadataDirectorySyncFunc = nil
	require.NoError(t, reopened.UnmountIfPhysicalGeneration(original.Generation))
	require.Equal(t, "released", reopened.originalPhysicalIdentity().Phase)
}

func TestDaemonPhysicalBirthEvidenceReplacementMountPreservesOriginal(t *testing.T) {
	d, original, _ := birthEvidenceFixture(t)
	require.NoError(t, d.captureOriginalProcess())
	mount := &physicalMountIdentity{MountID: 20, UniqueMountID: 9001, Major: 0, Minor: 15, Root: "/", Filesystem: "fuse.distillfs", Source: "original"}
	d.physicalMountFunc = func(string) (*physicalMountIdentity, error) { copy := *mount; return &copy, nil }
	require.NoError(t, d.captureOriginalMount())
	reopened := reopenBirthEvidenceFixture(t, d)
	changed := *mount
	changed.UniqueMountID++
	reopened.physicalMountFunc = func(string) (*physicalMountIdentity, error) { return &changed, nil }
	require.Error(t, reopened.UnmountIfPhysicalGeneration(original.Generation))
	require.Equal(t, mount, reopened.originalPhysicalIdentity().Mount)
	require.FileExists(t, original.PIDFile)
}

func TestDaemonPhysicalBirthEvidenceProtocolCannotBeChanged(t *testing.T) {
	d, _, _ := birthEvidenceFixture(t)
	changed := d.originalPhysicalIdentity()
	changed.BirthProtocol, changed.BirthDirectory = 0, nil
	require.Error(t, d.publishPhysicalIdentity(changed))
	changed = d.originalPhysicalIdentity()
	changed.BirthDirectory.Inode++
	require.Error(t, d.publishPhysicalIdentity(changed))
	require.Equal(t, uint8(1), d.originalPhysicalIdentity().BirthProtocol)
}

func TestDaemonPhysicalBirthEvidenceLegacyUnknownIgnoresNewRecord(t *testing.T) {
	d, original, _ := birthEvidenceFixture(t)
	require.NoError(t, d.captureOriginalProcess())
	legacy := clonePhysicalIdentity(original)
	legacy.BirthProtocol, legacy.BirthDirectory = 0, nil
	// Controlled old-format snapshot: an unrelated new-format fact cannot
	// upgrade an old launch identity or grant it cleanup authorization.
	d.physicalMu.Lock()
	d.meta.PhysicalIdentity = legacy
	err := d.persistDaemonMetadata()
	d.physicalMu.Unlock()
	require.NoError(t, err)
	reopened := reopenBirthEvidenceFixture(t, d)
	require.Error(t, reopened.UnmountIfPhysicalGeneration(original.Generation))
	require.Nil(t, reopened.originalPhysicalIdentity().Process)
	require.Equal(t, uint8(0), reopened.originalPhysicalIdentity().BirthProtocol)
	require.FileExists(t, d.physicalBirthPath(original, "process"))
}

func TestDaemonPhysicalBirthEvidenceReplacementDirectoryPreventsDispatch(t *testing.T) {
	d, marker := lateDispatchFixture(t)
	require.NoError(t, d.applyConfig())
	require.NoError(t, d.preparePhysicalLaunch())
	original := d.originalPhysicalIdentity()
	require.NoError(t, os.Rename(d.meta.DaemonDir, d.meta.DaemonDir+"-original"))
	require.NoError(t, os.Mkdir(d.meta.DaemonDir, 0700))
	command := exec.Command(d.binPath, d.buildMountArgs()...)
	require.Error(t, d.startOriginalDaemonCommand(command, original))
	require.NoFileExists(t, marker)
	require.False(t, d.originalPhysicalIdentity().NoDispatchConfirmed)
}

func TestDaemonPhysicalBirthEvidenceIncompleteMountNeverPublishes(t *testing.T) {
	d, original, _ := birthEvidenceFixture(t)
	require.NoError(t, d.captureOriginalProcess())
	d.physicalMountFunc = func(string) (*physicalMountIdentity, error) {
		return &physicalMountIdentity{MountID: 20, UniqueMountID: 9001, Filesystem: "fuse.distillfs"}, nil
	}
	require.Error(t, d.captureOriginalMount())
	require.NoFileExists(t, d.physicalBirthPath(original, "mount"))
	require.Nil(t, d.originalPhysicalIdentity().Mount)
}

func TestDaemonPhysicalBirthEvidenceLegacyMetadataKeepsOriginalEncoding(t *testing.T) {
	d, _, _ := birthEvidenceFixture(t)
	p := d.originalPhysicalIdentity()
	p.BirthProtocol, p.BirthDirectory = 0, nil
	meta := d.meta
	meta.PhysicalIdentity = p
	require.NoError(t, validatePhysicalMetadata(meta))
	encoded, err := json.Marshal(p)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "birth_protocol")
	require.NotContains(t, string(encoded), "birth_directory")
	for _, protocol := range []uint8{0, 2} {
		changed := clonePhysicalIdentity(p)
		changed.BirthProtocol = protocol
		changed.BirthDirectory = &directoryBirth{Inode: 1}
		meta.PhysicalIdentity = changed
		require.Error(t, validatePhysicalMetadata(meta))
	}
	p.BirthProtocol = 1
	meta.PhysicalIdentity = p
	require.Error(t, validatePhysicalMetadata(meta))
}

func TestDaemonPhysicalBirthEvidenceProcessSurvivesMetadataFailureAndOldDurableSnapshot(t *testing.T) {
	d, original, _ := birthEvidenceFixture(t)
	old, err := os.ReadFile(d.savedPath)
	require.NoError(t, err)
	d.metadataDirectorySyncFunc = func(*os.File) error { return errors.New("controlled metadata directory sync failure") }
	require.Error(t, d.captureOriginalProcess())
	// Model the previously committed metadata version surviving a failed sync.
	// This controlled snapshot is not evidence of a real host crash.
	require.NoError(t, os.WriteFile(d.savedPath, old, 0600))
	reopened := newMockDaemon(t.TempDir()).Daemon
	require.NoError(t, reopened.loadDaemonMetadata(d.savedPath))
	reopened.isAliveFunc = nil
	reopened.physicalScopeFunc = func() (physicalScope, error) { return original.Scope, nil }
	reopened.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) { return nil, nil }
	reopened.physicalMountFunc = func(string) (*physicalMountIdentity, error) { return nil, nil }
	reopened.unmountTargetFunc = func(string, int) error { t.Fatal("unallocated mount must not be unmounted"); return nil }
	require.NoError(t, reopened.UnmountIfPhysicalGeneration(original.Generation), "durable original process birth must survive a later metadata publication failure")
	require.Equal(t, "released", reopened.originalPhysicalIdentity().Phase)
	require.NotNil(t, reopened.originalPhysicalIdentity().Process)
	require.False(t, reopened.originalPhysicalIdentity().NoDispatchConfirmed)
}

func TestDaemonPhysicalBirthEvidenceMountSurvivesMetadataFailureAndOldDurableSnapshot(t *testing.T) {
	d, original, _ := birthEvidenceFixture(t)
	require.NoError(t, d.captureOriginalProcess())
	old, err := os.ReadFile(d.savedPath)
	require.NoError(t, err)
	mount := &physicalMountIdentity{MountID: 20, UniqueMountID: 9001, Major: 0, Minor: 15, Root: "/", Filesystem: "fuse.distillfs", Source: "original"}
	d.physicalMountFunc = func(string) (*physicalMountIdentity, error) { copy := *mount; return &copy, nil }
	d.metadataDirectorySyncFunc = func(*os.File) error { return errors.New("controlled metadata directory sync failure") }
	require.Error(t, d.captureOriginalMount())
	require.NoError(t, os.WriteFile(d.savedPath, old, 0600))
	reopened := newMockDaemon(t.TempDir()).Daemon
	require.NoError(t, reopened.loadDaemonMetadata(d.savedPath))
	reopened.isAliveFunc = nil
	reopened.physicalScopeFunc = func() (physicalScope, error) { return original.Scope, nil }
	reopened.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) { return nil, nil }
	mounted, calls := true, 0
	reopened.physicalMountFunc = func(string) (*physicalMountIdentity, error) {
		if !mounted {
			return nil, nil
		}
		copy := *mount
		return &copy, nil
	}
	reopened.unmountTargetFunc = func(string, int) error { calls++; mounted = false; return nil }
	require.NoError(t, reopened.UnmountIfPhysicalGeneration(original.Generation), "durable original mount birth must survive a later metadata publication failure")
	require.Equal(t, 1, calls)
	require.Equal(t, mount, reopened.originalPhysicalIdentity().Mount)
	require.Equal(t, "released", reopened.originalPhysicalIdentity().Phase)
}
