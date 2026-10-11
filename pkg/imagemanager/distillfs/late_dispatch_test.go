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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// This executable only writes a private marker; it cannot mount a filesystem,
// signal a daemon, or create a sandbox. Kernel observations are controlled.
func lateDispatchFixture(t *testing.T) (*Daemon, string) {
	t.Helper()
	d := newMockDaemon(t.TempDir()).Daemon
	require.NoError(t, os.MkdirAll(d.meta.DaemonDir, 0700))
	require.NoError(t, os.MkdirAll(d.meta.MountPoint, 0700))
	marker := filepath.Join(t.TempDir(), "must-not-execute")
	d.binPath = filepath.Join(t.TempDir(), "controlled-no-mount-command")
	require.NoError(t, os.WriteFile(d.binPath, []byte("#!/bin/sh\nprintf executed > '"+marker+"'\n"), 0700))
	d.physicalMountFunc = func(string) (*physicalMountIdentity, error) { return nil, nil }
	d.unmountTargetFunc = func(string, int) error { return errors.New("physical unmount is forbidden") }
	return d, marker
}

func TestDaemonMountOperationDispatchRechecksOriginalIdentityBeforeExec(t *testing.T) {
	for _, changed := range []string{"scope", "source", "executable", "arguments", "pid_file", "generation"} {
		t.Run(changed, func(t *testing.T) {
			d, marker := lateDispatchFixture(t)
			timing, ctx := StartTimedOperation(context.Background(), "controlled-original-command-change", d.meta.ID)
			defer timing.End()
			err := d.initializeDaemonWithBinding(ctx, timing, func(generation, target string) error {
				switch changed {
				case "scope":
					scope := d.originalPhysicalIdentity().Scope
					scope.PIDNSInode++
					d.physicalScopeFunc = func() (physicalScope, error) { return scope, nil }
				case "source":
					require.NoError(t, os.WriteFile(d.meta.CfgPath, []byte("changed original configuration"), 0600))
				case "executable":
					require.NoError(t, os.WriteFile(d.binPath, []byte("#!/bin/sh\nprintf changed > '"+marker+"'\n"), 0700))
				case "arguments":
					d.meta.Name += "-changed"
				case "pid_file":
					d.meta.PidFilePath += "-changed"
				case "generation":
					d.physicalMu.Lock()
					d.meta.PhysicalIdentity.Generation = strings.Repeat("b", 64)
					d.physicalMu.Unlock()
				}
				return nil
			})
			require.Error(t, err)
			require.NoFileExists(t, marker)
			require.False(t, d.originalPhysicalIdentity().NoDispatchConfirmed, "a failed observation does not prove a failed Start")
		})
	}
}

func TestDaemonMountOperationSuccessfulStartKeepsInterruptedBirthUnknown(t *testing.T) {
	d, marker := lateDispatchFixture(t)
	require.NoError(t, d.applyConfig())
	require.NoError(t, d.preparePhysicalLaunch())
	original := d.originalPhysicalIdentity()
	entered, proceed := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(proceed) }) })
	d.physicalScopeFunc = func() (physicalScope, error) {
		close(entered)
		<-proceed
		return original.Scope, nil
	}
	command := exec.Command(d.binPath, d.buildMountArgs()...)
	started := make(chan error, 1)
	go func() { started <- d.startOriginalDaemonCommand(command, original) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("original dispatch did not enter its identity check")
	}
	released := make(chan error, 1)
	go func() { released <- d.UnmountIfPhysicalGeneration(original.Generation) }()
	select {
	case err := <-released:
		t.Fatalf("release publication crossed the original Start lock: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	unblock.Do(func() { close(proceed) })
	select {
	case err := <-started:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("original dispatch did not finish")
	}
	select {
	case err := <-released:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("original release did not finish")
	}
	require.NoError(t, command.Wait())
	require.FileExists(t, marker, "the controlled command won the dispatch lock")
	p := d.originalPhysicalIdentity()
	require.Equal(t, "releasing", p.Phase)
	require.False(t, p.NoDispatchConfirmed)
	require.Nil(t, p.Process)
	require.Nil(t, p.Mount)
}

func TestDaemonMountOperationFailedStartProofSurvivesReleaseFailureAndReopen(t *testing.T) {
	d, marker := lateDispatchFixture(t)
	require.NoError(t, os.WriteFile(d.binPath, []byte("not an executable format"), 0700))
	timing, ctx := StartTimedOperation(context.Background(), "controlled-start-syscall-error", d.meta.ID)
	defer timing.End()
	require.Error(t, d.initializeDaemonWithBinding(ctx, timing, func(string, string) error { return nil }))
	p := d.originalPhysicalIdentity()
	require.Equal(t, "not_started", p.Phase)
	require.True(t, p.NoDispatchConfirmed)
	require.NoFileExists(t, marker)
	phase, err := d.InspectPhysicalGeneration(p.Generation)
	require.NoError(t, err)
	require.Equal(t, "not_started", phase)
	d.physicalMountFunc = func(string) (*physicalMountIdentity, error) { return nil, errors.New("mount observation unavailable") }
	require.Error(t, d.UnmountIfPhysicalGeneration(p.Generation))
	require.Equal(t, "releasing", d.originalPhysicalIdentity().Phase)
	require.True(t, d.originalPhysicalIdentity().NoDispatchConfirmed)
	reopened := newMockDaemon(t.TempDir()).Daemon
	require.NoError(t, reopened.loadDaemonMetadata(d.savedPath))
	reopened.isAliveFunc = nil
	reopened.physicalMountFunc = func(string) (*physicalMountIdentity, error) { return nil, nil }
	require.NoError(t, reopened.UnmountIfPhysicalGeneration(p.Generation))
	require.Equal(t, "released", reopened.originalPhysicalIdentity().Phase)
	require.True(t, reopened.originalPhysicalIdentity().NoDispatchConfirmed)
	require.Nil(t, reopened.originalPhysicalIdentity().Process)
	require.Nil(t, reopened.originalPhysicalIdentity().Mount)
}

func TestDaemonMountOperationUnknownBirthCannotInventUnstartedProof(t *testing.T) {
	d, _ := lateDispatchFixture(t)
	require.NoError(t, d.applyConfig())
	require.NoError(t, d.preparePhysicalLaunch())
	p := d.originalPhysicalIdentity()
	require.Error(t, d.UnmountIfPhysicalGeneration(p.Generation))
	require.Equal(t, "releasing", d.originalPhysicalIdentity().Phase)
	forged := d.originalPhysicalIdentity()
	forged.NoDispatchConfirmed = true
	require.Error(t, d.publishPhysicalIdentity(forged))
	reopened := newMockDaemon(t.TempDir()).Daemon
	require.NoError(t, reopened.loadDaemonMetadata(d.savedPath))
	require.False(t, reopened.originalPhysicalIdentity().NoDispatchConfirmed)
	require.Error(t, reopened.UnmountIfPhysicalGeneration(p.Generation))
	require.Equal(t, "releasing", reopened.originalPhysicalIdentity().Phase)
}

func TestDaemonMountOperationLegacyNotStartedPreservesProofDuringCleanup(t *testing.T) {
	d, _ := lateDispatchFixture(t)
	require.NoError(t, d.applyConfig())
	require.NoError(t, d.preparePhysicalLaunch())
	p := d.originalPhysicalIdentity()
	p.Phase = "not_started" // Original schema 1 used the phase alone.
	require.NoError(t, d.publishPhysicalIdentity(p))
	raw, err := os.ReadFile(d.savedPath)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "no_dispatch_confirmed", "false is omitted to preserve old canonical metadata digests")
	reopened := newMockDaemon(t.TempDir()).Daemon
	require.NoError(t, reopened.loadDaemonMetadata(d.savedPath))
	reopened.physicalMountFunc = func(string) (*physicalMountIdentity, error) {
		return nil, errors.New("original target observation unavailable")
	}
	require.Error(t, reopened.UnmountIfPhysicalGeneration(p.Generation))
	require.Equal(t, "releasing", reopened.originalPhysicalIdentity().Phase)
	require.True(t, reopened.originalPhysicalIdentity().NoDispatchConfirmed)
	reopenedAgain := newMockDaemon(t.TempDir()).Daemon
	require.NoError(t, reopenedAgain.loadDaemonMetadata(d.savedPath))
	require.True(t, reopenedAgain.originalPhysicalIdentity().NoDispatchConfirmed)
	reopenedAgain.physicalMountFunc = func(string) (*physicalMountIdentity, error) { return nil, nil }
	require.NoError(t, reopenedAgain.UnmountIfPhysicalGeneration(p.Generation))
	require.Equal(t, "released", reopenedAgain.originalPhysicalIdentity().Phase)
}

func TestDaemonMountOperationLateDispatchAfterReleaseNeverExecutes(t *testing.T) {
	d, marker := lateDispatchFixture(t)
	timing, ctx := StartTimedOperation(context.Background(), "controlled-late-dispatch", d.meta.ID)
	defer timing.End()
	var original string
	err := d.initializeDaemonWithBinding(ctx, timing, func(generation, target string) error {
		original = generation
		require.Error(t, d.UnmountIfPhysicalGeneration(generation), "missing birth remains unresolved")
		return nil // The original dispatch continues after the cleanup request.
	})
	require.Error(t, err)
	require.NoFileExists(t, marker, "a late original attempt cannot launch after cleanup is requested")
	p := d.originalPhysicalIdentity()
	require.Equal(t, original, p.Generation)
	require.Equal(t, "releasing", p.Phase)
	require.Nil(t, p.Process)
	require.Nil(t, p.Mount)
	raw, err := os.ReadFile(d.savedPath)
	require.NoError(t, err)
	stored, err := decodeDaemonMetadata(raw)
	require.NoError(t, err)
	require.Equal(t, p, stored.PhysicalIdentity)
}

func TestDaemonMountOperationUnconfirmedReleasePublicationNeverExecutes(t *testing.T) {
	d, marker := lateDispatchFixture(t)
	timing, ctx := StartTimedOperation(context.Background(), "controlled-release-sync-failure", d.meta.ID)
	defer timing.End()
	err := d.initializeDaemonWithBinding(ctx, timing, func(generation, target string) error {
		d.metadataDirectorySyncFunc = func(*os.File) error {
			if d.meta.PhysicalIdentity.Phase == "releasing" {
				return errors.New("original release directory sync unavailable")
			}
			return nil
		}
		require.Error(t, d.UnmountIfPhysicalGeneration(generation))
		return nil
	})
	require.Error(t, err)
	require.NoFileExists(t, marker)
	require.Equal(t, "releasing", d.originalPhysicalIdentity().Phase)
	require.True(t, d.physicalPublicationPending)
	require.True(t, d.releasePending)
}
