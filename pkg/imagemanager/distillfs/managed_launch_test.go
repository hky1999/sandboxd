// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package distillfs

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Except for the explicitly supplied non-privileged producer binary, these
// cases use private files and controlled process/mount observations only.
func managedLaunchFixture(t *testing.T, bin string) (*Daemon, *physicalIdentity, *physicalProcessIdentity) {
	t.Helper()
	config := ownershipManagerConfig(t)
	config.BinPath = bin
	require.NoError(t, os.Chmod(config.Root, 0700))
	m := ownedManager(t, config)
	id := strings.Repeat("b", 64)
	require.NoError(t, m.PrepareDaemon(&DaemonCreateOpt{ID: id, Name: "controlled.erofs"}, preparationOwner(), func(string, string) error { return nil }))
	d := m.GetDaemon(id)
	d.config = &BackendConfig{BackendType: "controlled-invalid-backend"}
	require.NoError(t, d.applyConfig())
	require.NoError(t, d.preparePhysicalLaunch())
	p := d.originalPhysicalIdentity()
	require.NotNil(t, p.ManagedLaunch)
	process := &physicalProcessIdentity{PID: 987654321, StartTicks: 10, ExecutableSHA256: p.ExecutableSHA256, ArgumentsSHA256: p.ArgumentsSHA256}
	return d, p, process
}

func managedFactBytes(t *testing.T, d *Daemon, p *physicalIdentity, process *physicalProcessIdentity, mount *physicalMountIdentity) []byte {
	t.Helper()
	kind := "process"
	if mount != nil {
		kind = "mount"
	}
	fact := managedLaunchFact{Kind: kind, DaemonID: d.meta.ID, Generation: p.Generation, OperationID: p.ManagedLaunch.Manifest.OperationID, RequestFingerprint: p.ManagedLaunch.Manifest.RequestFingerprint, IntentSHA256: p.ManagedLaunch.IntentSHA256, MountToken: "akernel-" + p.Generation, Scope: p.Scope, Process: process, Mount: mount}
	payload, err := json.Marshal(fact)
	require.NoError(t, err)
	data, err := json.Marshal(managedLaunchEnvelope{SchemaVersion: 1, Payload: string(payload), IntegritySHA256: metadataSHA(payload)})
	require.NoError(t, err)
	return data
}

func saveManagedFact(t *testing.T, d *Daemon, p *physicalIdentity, process *physicalProcessIdentity, mount *physicalMountIdentity) string {
	t.Helper()
	kind := "process"
	if mount != nil {
		kind = "mount"
	}
	path := filepath.Join(d.meta.DaemonDir, "launch-birth-"+p.Generation+"-"+kind+".json")
	require.NoError(t, os.WriteFile(path, managedFactBytes(t, d, p, process, mount), 0600))
	return path
}

func controlledManagedMount(p *physicalIdentity) *physicalMountIdentity {
	return &physicalMountIdentity{MountID: 21, UniqueMountID: 10001, Major: 0, Minor: 1, Root: "/", Filesystem: "fuse.distill_fs", Source: "akernel-" + p.Generation}
}

func TestDaemonManagedLaunchAdoptsOriginalProcessWithoutPIDFile(t *testing.T) {
	d, p, process := managedLaunchFixture(t, "/bin/true")
	saveManagedFact(t, d, p, process, nil)
	d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) { copy := *process; return &copy, nil }
	require.NoError(t, d.captureOriginalProcess())
	require.Equal(t, process, d.originalPhysicalIdentity().Process)
	require.Equal(t, process.PID, d.getPid())
	require.NoFileExists(t, p.PIDFile)
	require.FileExists(t, d.physicalBirthPath(p, "process"))
}

func TestDaemonManagedLaunchMissingFactCannotBorrowPIDFileOrCurrentProcess(t *testing.T) {
	d, p, _ := managedLaunchFixture(t, "/bin/true")
	require.NoError(t, os.WriteFile(p.PIDFile, []byte("neighbor-pid"), 0600))
	d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) {
		t.Fatal("missing original fact must not authorize PID lookup")
		return nil, nil
	}
	require.Error(t, d.UnmountIfPhysicalGeneration(p.Generation))
	require.Nil(t, d.originalPhysicalIdentity().Process)
	require.False(t, d.originalPhysicalIdentity().NoDispatchConfirmed)
	data, err := os.ReadFile(p.PIDFile)
	require.NoError(t, err)
	require.Equal(t, "neighbor-pid", string(data))
}

func TestDaemonManagedLaunchRejectsUnsafeOrContradictoryOriginalFacts(t *testing.T) {
	for _, fault := range []string{"integrity", "intent", "operation", "scope", "unknown", "duplicate", "trailing", "symlink", "hardlink", "permissions", "oversized", "fifo"} {
		t.Run(fault, func(t *testing.T) {
			d, p, process := managedLaunchFixture(t, "/bin/true")
			path := saveManagedFact(t, d, p, process, nil)
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			var envelope managedLaunchEnvelope
			require.NoError(t, json.Unmarshal(data, &envelope))
			var fact managedLaunchFact
			require.NoError(t, json.Unmarshal([]byte(envelope.Payload), &fact))
			switch fault {
			case "integrity":
				envelope.IntegritySHA256 = strings.Repeat("0", 64)
			case "intent":
				fact.IntentSHA256 = strings.Repeat("0", 64)
			case "operation":
				fact.OperationID = strings.Repeat("0", 64)
			case "scope":
				fact.Scope.MountNSInode++
			case "unknown":
				data = []byte(strings.TrimSuffix(string(data), "}") + ",\"unknown\":true}")
			case "duplicate":
				data = []byte(strings.Replace(string(data), "\"schema_version\":1", "\"schema_version\":1,\"schema_version\":1", 1))
			case "trailing":
				data = append(data, []byte("{}")...)
			case "symlink":
				require.NoError(t, os.Rename(path, path+"-original"))
				require.NoError(t, os.Symlink(path+"-original", path))
			case "hardlink":
				require.NoError(t, os.Link(path, path+"-alias"))
			case "permissions":
				require.NoError(t, os.Chmod(path, 0644))
			case "oversized":
				data = make([]byte, physicalBirthLimit+1)
			case "fifo":
				require.NoError(t, os.Remove(path))
				require.NoError(t, syscall.Mkfifo(path, 0600))
			}
			if fault == "intent" || fault == "operation" || fault == "scope" {
				payload, err := json.Marshal(fact)
				require.NoError(t, err)
				envelope.Payload = string(payload)
				envelope.IntegritySHA256 = metadataSHA(payload)
			}
			if fault == "integrity" || fault == "intent" || fault == "operation" || fault == "scope" {
				data, err = json.Marshal(envelope)
				require.NoError(t, err)
			}
			if fault == "integrity" || fault == "intent" || fault == "operation" || fault == "scope" || fault == "unknown" || fault == "duplicate" || fault == "trailing" || fault == "oversized" {
				require.NoError(t, os.WriteFile(path, data, 0600))
			}
			d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) {
				t.Fatal("invalid record must not authorize process lookup")
				return nil, nil
			}
			require.Error(t, d.adoptManagedLaunchFacts(false, false))
			require.Nil(t, d.originalPhysicalIdentity().Process)
		})
	}
}

func TestDaemonManagedLaunchMountFactRequiresSameIndependentProcess(t *testing.T) {
	d, p, process := managedLaunchFixture(t, "/bin/true")
	saveManagedFact(t, d, p, process, controlledManagedMount(p))
	require.Error(t, d.adoptManagedLaunchFacts(true, false))
	require.Nil(t, d.originalPhysicalIdentity().Process)
	require.Nil(t, d.originalPhysicalIdentity().Mount)
}

func TestDaemonManagedLaunchReadyRequiresOriginalLiveProcessAndMount(t *testing.T) {
	d, p, process := managedLaunchFixture(t, "/bin/true")
	mount := controlledManagedMount(p)
	saveManagedFact(t, d, p, process, nil)
	saveManagedFact(t, d, p, process, mount)
	d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) { copy := *process; return &copy, nil }
	d.physicalMountFunc = func(string) (*physicalMountIdentity, error) { copy := *mount; return &copy, nil }
	require.NoError(t, d.captureOriginalMount())
	require.Equal(t, "running", d.originalPhysicalIdentity().Phase)
	changed := *process
	changed.StartTicks++
	d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) { return &changed, nil }
	require.Error(t, d.captureOriginalMount())
	require.Equal(t, process, d.originalPhysicalIdentity().Process)
}

func TestDaemonManagedLaunchMetadataFailureRecoversOnlyOriginalFacts(t *testing.T) {
	d, p, process := managedLaunchFixture(t, "/bin/true")
	old, err := os.ReadFile(d.savedPath)
	require.NoError(t, err)
	saveManagedFact(t, d, p, process, nil)
	d.metadataDirectorySyncFunc = func(*os.File) error { return errors.New("controlled metadata directory sync failure") }
	require.Error(t, d.adoptManagedLaunchFacts(false, false))
	// Controlled old-valid-snapshot model; not a physical power-loss claim.
	require.NoError(t, os.WriteFile(d.savedPath, old, 0600))
	reopened := &Daemon{ownership: d.ownership, ctx: d.ctx, binPath: d.binPath}
	require.NoError(t, reopened.loadDaemonMetadata(d.savedPath))
	reopened.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) { return nil, nil }
	reopened.physicalMountFunc = func(string) (*physicalMountIdentity, error) { return nil, nil }
	reopened.physicalSignalFunc = func(*physicalProcessIdentity, syscall.Signal) error {
		t.Fatal("exited original must not receive a signal")
		return nil
	}
	require.NoError(t, reopened.UnmountIfPhysicalGeneration(p.Generation))
	require.Equal(t, process, reopened.originalPhysicalIdentity().Process)
	require.Equal(t, "released", reopened.originalPhysicalIdentity().Phase)
}

func TestDaemonManagedLaunchMissingMountAcknowledgementRecoversOriginalKernelTokenAfterExit(t *testing.T) {
	d, p, process := managedLaunchFixture(t, "/bin/true")
	saveManagedFact(t, d, p, process, nil)
	mount := controlledManagedMount(p)
	unmounts := 0
	d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) { return nil, nil }
	d.physicalMountFunc = func(string) (*physicalMountIdentity, error) { return mount, nil }
	d.unmountTargetFunc = func(string, int) error { unmounts++; mount = nil; return nil }
	require.NoError(t, d.UnmountIfPhysicalGeneration(p.Generation))
	require.Equal(t, 1, unmounts)
	require.Equal(t, "released", d.originalPhysicalIdentity().Phase)
	require.Equal(t, process, d.originalPhysicalIdentity().Process)
	require.FileExists(t, d.physicalBirthPath(p, "mount"))
}

func TestDaemonManagedLaunchKernelRecoveryPreservesReplacementMount(t *testing.T) {
	d, p, process := managedLaunchFixture(t, "/bin/true")
	saveManagedFact(t, d, p, process, nil)
	mount := controlledManagedMount(p)
	mount.Source = "neighbor-generation"
	d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) { return nil, nil }
	d.physicalMountFunc = func(string) (*physicalMountIdentity, error) { return mount, nil }
	d.unmountTargetFunc = func(string, int) error { t.Fatal("replacement must not be unmounted"); return nil }
	require.Error(t, d.UnmountIfPhysicalGeneration(p.Generation))
	require.Nil(t, d.originalPhysicalIdentity().Mount)
	require.Equal(t, "releasing", d.originalPhysicalIdentity().Phase)
}

func TestDaemonManagedLaunchFinalDispatchRejectsOwnerAndTargetReplacement(t *testing.T) {
	for _, fault := range []string{"session", "root", "target", "lock"} {
		t.Run(fault, func(t *testing.T) {
			d, p, _ := managedLaunchFixture(t, "/bin/true")
			command := exec.Command(d.binPath, d.buildMountArgs()...)
			switch fault {
			case "session":
				d.ownership.session = strings.Repeat("e", 64)
			case "root":
				path := d.ownership.root
				require.NoError(t, os.Rename(path, path+"-original"))
				t.Cleanup(func() { os.RemoveAll(path + "-original") })
				require.NoError(t, os.Mkdir(path, 0700))
			case "target":
				require.NoError(t, os.Rename(p.Target, p.Target+"-original"))
				require.NoError(t, os.Mkdir(p.Target, 0700))
			case "lock":
				path := filepath.Join(d.ownership.root, managerOwnerLockName)
				require.NoError(t, os.Rename(path, path+"-original"))
				require.NoError(t, os.WriteFile(path, nil, 0600))
			}
			require.Error(t, d.startOriginalDaemonCommand(command, p))
			require.Nil(t, command.Process)
			require.False(t, d.originalPhysicalIdentity().NoDispatchConfirmed)
		})
	}
}

func TestDaemonManagedLaunchCleanupPersistsOriginalProcessBeforeStoppingInitializer(t *testing.T) {
	d, p, process := managedLaunchFixture(t, "/bin/true")
	saveManagedFact(t, d, p, process, nil)
	child := &managedLaunchChild{Generation: p.Generation, Command: &exec.Cmd{Process: &os.Process{Pid: process.PID}}, Done: make(chan struct{})}
	d.managedChild = child
	d.setState(DaemonStateMounting)
	alive := true
	signals := 0
	d.physicalProcessFunc = func(int) (*physicalProcessIdentity, error) {
		if !alive {
			return nil, nil
		}
		copy := *process
		return &copy, nil
	}
	d.physicalMountFunc = func(string) (*physicalMountIdentity, error) { return nil, nil }
	d.physicalSignalFunc = func(got *physicalProcessIdentity, signal syscall.Signal) error {
		require.Equal(t, syscall.SIGTERM, signal)
		require.Equal(t, process, got)
		stored := &Daemon{}
		require.NoError(t, stored.loadDaemonMetadata(d.savedPath))
		require.Equal(t, "releasing", stored.originalPhysicalIdentity().Phase)
		require.Equal(t, process, stored.originalPhysicalIdentity().Process)
		signals++
		alive = false
		close(child.Done)
		return nil
	}
	require.NoError(t, d.UnmountIfPhysicalGeneration(p.Generation))
	require.Equal(t, 1, signals)
	require.Equal(t, "released", d.originalPhysicalIdentity().Phase)
}

func TestDaemonManagedLaunchRealProducerRecordsBeforeControlledBackendFailure(t *testing.T) {
	bin := os.Getenv("SCHEDULER_MANAGED_TEST_BINARY")
	if bin == "" {
		t.Skip("requires explicitly supplied non-privileged producer candidate")
	}
	executable, err := os.ReadFile(bin)
	require.NoError(t, err)
	require.Equal(t, os.Getenv("SCHEDULER_MANAGED_TEST_BINARY_SHA256"), metadataSHA(executable))
	d, p, _ := managedLaunchFixture(t, bin)
	command := exec.Command(bin, d.buildMountArgs()...)
	require.NoError(t, d.startOriginalDaemonCommand(command, p))
	d.physicalMu.Lock()
	child := d.managedChild
	d.physicalMu.Unlock()
	require.NotNil(t, child)
	// The private CLI is still hashing its original program, before backend
	// preparation. Close the Go owner and verify its inherited flock remains.
	select {
	case <-child.Done:
		t.Fatal("controlled initializer exited before lease observation")
	default:
	}
	d.ownership.requestClose()
	select {
	case <-d.ownership.done:
	case <-time.After(5 * time.Second):
		t.Fatal("original Go owner did not close")
	}
	duplicate, err := openManagerOwnership(context.Background(), d.ownership.root)
	if duplicate != nil {
		duplicate.requestClose()
		<-duplicate.done
	}
	require.Error(t, err, "the direct initializer's inherited flock must block a replacement owner")
	select {
	case <-child.Done:
	case <-time.After(70 * time.Second):
		t.Fatal("bounded producer did not exit")
	}
	require.Error(t, child.Err, "controlled invalid backend must fail before any FUSE mount")
	owner, err := openManagerOwnership(context.Background(), d.ownership.root)
	require.NoError(t, err)
	t.Cleanup(func() { owner.requestClose(); <-owner.done })
	reopened := &Daemon{ownership: owner, ctx: context.Background(), binPath: bin}
	require.NoError(t, reopened.loadDaemonMetadata(d.savedPath))
	require.NoError(t, reopened.adoptManagedLaunchFacts(false, false))
	require.Equal(t, command.Process.Pid, reopened.originalPhysicalIdentity().Process.PID)
	require.NoFileExists(t, p.PIDFile)
	require.Nil(t, reopened.originalPhysicalIdentity().Mount)
	require.NoError(t, reopened.UnmountIfPhysicalGeneration(p.Generation))
	require.Equal(t, "released", reopened.originalPhysicalIdentity().Phase)
}
