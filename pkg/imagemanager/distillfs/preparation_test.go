// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package distillfs

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// These checks use empty local configuration and inventory, with cgroups
// disabled. They allocate only private directories and never start a daemon.
func TestDaemonMountOperationPreparationPersistsBeforeAnyWorkingDirectory(t *testing.T) {
	config := ownershipManagerConfig(t)
	m := ownedManager(t, config)
	id := strings.Repeat("a", 64)
	require.NoError(t, m.CreateDaemon(&DaemonCreateOpt{ID: id, Name: "original.erofs"}))
	d := m.GetDaemon(id)
	require.NotNil(t, d)
	record := filepath.Join(config.Root, "daemon_configs", id+".json")
	require.FileExists(t, record, "directory allocation needs durable original ownership")
	reopened := &Daemon{}
	require.NoError(t, reopened.loadDaemonMetadata(record), "pre-launch recovery must not require a backend file that was never prepared")
	require.Equal(t, d.MountPoint(), reopened.MountPoint())
}

func TestDaemonMountOperationPreparationFailureSurvivesManagerReopen(t *testing.T) {
	config := ownershipManagerConfig(t)
	m := ownedManager(t, config)
	id := strings.Repeat("b", 64)
	// Block legacy image metadata allocation after its mountpoint was created.
	block := filepath.Join(config.Root, "image_metas", id)
	require.NoError(t, os.WriteFile(block, []byte("foreign obstruction"), 0600))
	err := m.CreateDaemon(&DaemonCreateOpt{ID: id, Name: "original.erofs"})
	if err == nil {
		// A new private layout does not borrow the obstructed legacy path.
		d := m.GetDaemon(id)
		require.NotNil(t, d)
		require.NotEqual(t, block, d.meta.ImageMetaDir)
	}
	record := filepath.Join(config.Root, "daemon_configs", id+".json")
	require.FileExists(t, record, "partial allocation must retain a recoverable owner")
	require.NoError(t, m.Close(context.Background()))
	reopened := ownedManager(t, config)
	require.NotNil(t, reopened.GetDaemon(id), "pre-launch preparation survives a real manager reopen")
	raw, err := os.ReadFile(block)
	require.NoError(t, err)
	require.Equal(t, "foreign obstruction", string(raw))
}

func preparationOwner() PreparationOwner {
	return PreparationOwner{OperationID: strings.Repeat("c", 64), RequestFingerprint: strings.Repeat("d", 64)}
}

func TestDaemonMountOperationPreparationBindsBeforeAllocationAndIndependentQuery(t *testing.T) {
	config := ownershipManagerConfig(t)
	m := ownedManager(t, config)
	id, owner := strings.Repeat("e", 64), preparationOwner()
	entered, finish := make(chan string, 1), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- m.PrepareDaemon(&DaemonCreateOpt{ID: id, Name: "original.erofs"}, owner, func(generation, target string) error {
			entered <- generation
			<-finish
			return nil
		})
	}()
	var generation string
	select {
	case generation = <-entered:
	case <-time.After(time.Second):
		t.Fatal("preparation never reached binding")
	}
	t.Cleanup(func() {
		select {
		case <-finish:
		default:
			close(finish)
		}
	})
	data, err := readDaemonMetadataFile(filepath.Join(config.Root, "daemon_configs", id+".json"))
	require.NoError(t, err)
	meta, err := decodeDaemonMetadata(data)
	require.NoError(t, err)
	require.Equal(t, generation, meta.Preparation.Generation)
	require.Equal(t, owner, meta.Preparation.Owner)
	require.Nil(t, meta.Preparation.Birth)
	require.NoDirExists(t, meta.Preparation.Directory)
	queried := make(chan *PreparationInfo, 1)
	go func() { info, _ := m.FindPreparation(owner); queried <- info }()
	select {
	case info := <-queried:
		require.NotNil(t, info)
		require.Equal(t, generation, info.Generation)
	case <-time.After(time.Second):
		t.Fatal("independent query waited for the original producer")
	}
	_, err = m.GetDaemon(id).InspectPhysicalGeneration(generation)
	require.Error(t, err, "busy original publication is unknown, never ready")
	close(finish)
	require.NoError(t, <-done)
	require.DirExists(t, meta.Preparation.Directory)
}

func TestDaemonMountOperationPreparationBindingFailureReopensAndRetiresOriginal(t *testing.T) {
	config := ownershipManagerConfig(t)
	m := ownedManager(t, config)
	id, owner := strings.Repeat("e", 64), preparationOwner()
	require.Error(t, m.PrepareDaemon(&DaemonCreateOpt{ID: id, Name: "original.erofs"}, owner, func(string, string) error { return errors.New("upper journal publication failed") }))
	info, err := m.FindPreparation(owner)
	require.NoError(t, err)
	require.NotNil(t, info)
	require.NoDirExists(t, filepath.Dir(info.Target))
	require.NoError(t, m.Close(context.Background()))
	m = ownedManager(t, config)
	reopened, err := m.FindPreparation(owner)
	require.NoError(t, err)
	require.Equal(t, info, reopened)
	d := m.GetDaemon(id)
	require.Error(t, d.Mount(), "recovery cannot dispatch the interrupted original")
	require.Error(t, d.UnmountIfPhysicalGeneration(strings.Repeat("f", 64)))
	require.NoError(t, d.UnmountIfPhysicalGeneration(info.Generation))
	phase, err := d.InspectPhysicalGeneration(info.Generation)
	require.NoError(t, err)
	require.Equal(t, "released", phase)
	require.NoError(t, d.UnmountIfPhysicalGeneration(info.Generation))
	require.NoError(t, m.Close(context.Background()))
	m = ownedManager(t, config)
	phase, err = m.GetDaemon(id).InspectPhysicalGeneration(info.Generation)
	require.NoError(t, err)
	require.Equal(t, "released", phase)
}

func TestDaemonMountOperationPreparationPartialDirectoryFailureReopensAndCleans(t *testing.T) {
	config := ownershipManagerConfig(t)
	m := ownedManager(t, config)
	id := strings.Repeat("e", 64)
	d, err := m.newDaemon(&DaemonCreateOpt{ID: id, Name: "original.erofs"})
	require.NoError(t, err)
	m.mu.Lock()
	m.daemons[id] = d
	m.mu.Unlock()
	publications := 0
	d.metadataDirectorySyncFunc = func(dir *os.File) error {
		publications++
		if publications == 2 {
			// Fault inside the private allocation after durable birth, before
			// its children can all be created. No external resource is touched.
			if err := os.WriteFile(d.meta.ImageMetaDir, []byte("controlled child allocation failure"), 0600); err != nil {
				return err
			}
		}
		return dir.Sync()
	}
	require.Error(t, d.allocatePreparation(preparationOwner(), func(string, string) error { return nil }))
	generation, dir := d.meta.Preparation.Generation, d.meta.Preparation.Directory
	require.DirExists(t, d.meta.DaemonDir)
	require.FileExists(t, d.meta.ImageMetaDir)
	require.NoError(t, m.Close(context.Background()))
	m = ownedManager(t, config)
	d = m.GetDaemon(id)
	require.NotNil(t, d)
	require.NoError(t, d.UnmountIfPhysicalGeneration(generation))
	require.NoDirExists(t, dir)
}

func TestDaemonMountOperationPreparationReplacementDirectoryIsNeverDeleted(t *testing.T) {
	config := ownershipManagerConfig(t)
	m := ownedManager(t, config)
	id := strings.Repeat("e", 64)
	require.NoError(t, m.CreateDaemon(&DaemonCreateOpt{ID: id, Name: "original.erofs"}))
	d := m.GetDaemon(id)
	p := d.originalPreparation()
	require.NoError(t, os.Rename(p.Directory, p.Directory+"-original"))
	require.NoError(t, os.Mkdir(p.Directory, 0700))
	marker := filepath.Join(p.Directory, "replacement")
	require.NoError(t, os.WriteFile(marker, []byte("neighbor"), 0600))
	require.Error(t, d.UnmountIfPhysicalGeneration(p.Generation))
	require.FileExists(t, marker)
	require.DirExists(t, p.Directory+"-original")
	phase, err := d.InspectPhysicalGeneration(p.Generation)
	require.NoError(t, err)
	require.Equal(t, "releasing", phase)
}

func TestDaemonMountOperationPreparationUnknownDirectoryBirthKeepsOriginalUnknown(t *testing.T) {
	config := ownershipManagerConfig(t)
	m := ownedManager(t, config)
	id := strings.Repeat("e", 64)
	require.Error(t, m.PrepareDaemon(&DaemonCreateOpt{ID: id, Name: "original.erofs"}, preparationOwner(), func(generation, target string) error {
		// A foreign directory occupies the reserved name before our mkdir.
		dir := filepath.Dir(target)
		if err := os.Mkdir(dir, 0700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, "foreign"), []byte("retain"), 0600)
	}))
	d := m.GetDaemon(id)
	p := d.originalPreparation()
	require.Nil(t, p.Birth)
	require.NoError(t, m.Close(context.Background()))
	m = ownedManager(t, config)
	require.Error(t, m.GetDaemon(id).UnmountIfPhysicalGeneration(p.Generation))
	require.FileExists(t, filepath.Join(p.Directory, "foreign"))
}

func TestDaemonMountOperationPreparationCleanupPreservesNeighborAndCallerTarget(t *testing.T) {
	config := ownershipManagerConfig(t)
	m := ownedManager(t, config)
	firstID, secondID := strings.Repeat("a", 64), strings.Repeat("b", 64)
	callerTarget := t.TempDir()
	marker := filepath.Join(callerTarget, "caller-content")
	require.NoError(t, os.WriteFile(marker, []byte("caller-owned"), 0600))
	require.NoError(t, m.CreateDaemon(&DaemonCreateOpt{ID: firstID, Name: "first.erofs", MountPoint: callerTarget}))
	require.NoError(t, m.CreateDaemon(&DaemonCreateOpt{ID: secondID, Name: "second.erofs"}))
	first, second := m.GetDaemon(firstID), m.GetDaemon(secondID)
	require.NoError(t, first.UnmountIfPhysicalGeneration(first.originalPreparation().Generation))
	require.NoError(t, m.CleanupDaemon(firstID))
	require.FileExists(t, marker)
	require.DirExists(t, second.meta.DaemonDir)
	require.NotEqual(t, first.originalPreparation().Generation, second.originalPreparation().Generation)
}

func TestDaemonMountOperationPreparationLaunchUsesBoundGenerationAndReleaseFencesIt(t *testing.T) {
	config := ownershipManagerConfig(t)
	config.BinPath = "/bin/true" // Identity read only; never executed.
	m := ownedManager(t, config)
	id := strings.Repeat("a", 64)
	require.NoError(t, m.CreateDaemon(&DaemonCreateOpt{ID: id, Name: "first.erofs"}))
	d := m.GetDaemon(id)
	generation := d.originalPreparation().Generation
	require.NoError(t, d.applyConfig())
	require.NoError(t, d.preparePhysicalLaunch())
	require.Equal(t, generation, d.originalPhysicalIdentity().Generation)
	require.Error(t, d.UnmountIfPhysicalGeneration(generation), "a prepared launch intent has unresolved dispatch, never fabricated no-dispatch proof")
	require.Error(t, d.preparePhysicalLaunch(), "late launch cannot cross original release")
}

func TestDaemonMountOperationPreparationRetirementFencesActiveInitializer(t *testing.T) {
	config := ownershipManagerConfig(t)
	m := ownedManager(t, config)
	id := strings.Repeat("a", 64)
	require.NoError(t, m.CreateDaemon(&DaemonCreateOpt{ID: id, Name: "first.erofs"}))
	d := m.GetDaemon(id)
	p := d.originalPreparation()
	d.setState(DaemonStateMounting)
	require.ErrorContains(t, d.UnmountIfPhysicalGeneration(p.Generation), "active initializer")
	require.DirExists(t, p.Directory, "a producer may still be writing original child files")
	require.Equal(t, "releasing", d.originalPreparation().Phase)
	require.Error(t, d.verifyPreparationForLaunch(), "the initializer cannot reopen its retired preparation")
	d.setState(DaemonStateStopped)
	require.NoError(t, d.UnmountIfPhysicalGeneration(p.Generation))
	require.NoDirExists(t, p.Directory)
}

func TestDaemonMountOperationPreparationFinalDispatchRejectsReplacedDirectory(t *testing.T) {
	config := ownershipManagerConfig(t)
	config.BinPath = "/bin/true" // Rejected before execution; no daemon is started.
	m := ownedManager(t, config)
	id := strings.Repeat("a", 64)
	require.NoError(t, m.CreateDaemon(&DaemonCreateOpt{ID: id, Name: "first.erofs"}))
	d := m.GetDaemon(id)
	require.NoError(t, d.applyConfig())
	require.NoError(t, d.preparePhysicalLaunch())
	original := d.originalPhysicalIdentity()
	p := d.originalPreparation()
	command := exec.Command(d.binPath, d.buildMountArgs()...)
	require.NoError(t, os.Rename(p.Directory, p.Directory+"-original"))
	require.NoError(t, os.Mkdir(p.Directory, 0700))
	require.ErrorContains(t, d.startOriginalDaemonCommand(command, original), "directory changed")
	require.Nil(t, command.Process)
	require.False(t, d.originalPhysicalIdentity().NoDispatchConfirmed, "a guard rejection is not an attempted Start failure")
}
