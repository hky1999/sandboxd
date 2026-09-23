// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"


	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/cgroupmanager"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDeleteIfGenerationRejectsStaleAndReturnsPhysicalReceipt(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	const id = "generation-delete"
	store := func(generation string) {
		storeSandboxForDelete(t, s, id)
		require.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
			ID: id, RuntimeHandler: "runsc", Labels: map[string]string{resourceGenerationLabel: generation},
		}))
	}
	store("physical-one")
	for _, request := range []*runtime.DeleteIfGenerationRequest{nil, {ID: id}, {ExpectedGeneration: "physical-one"}} {
		_, err := s.DeleteIfGeneration(context.Background(), request)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
	}
	_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "wrong"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Zero(t, handler.calls)
	response, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "physical-one"})
	require.NoError(t, err)
	require.Equal(t, "physical-one", response.RetiredGeneration)
	require.Equal(t, 1, handler.calls)
	_, err = s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "physical-one"})
	require.NoError(t, err) // replay the durable receipt
	store("physical-two")
	_, err = s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "physical-one"})
	require.NoError(t, err) // old-generation receipt cannot delete the replacement
	require.Equal(t, 1, handler.calls)
	current, err := s.sandboxManager.Get(id)
	require.NoError(t, err)
	require.Equal(t, "physical-two", current.Metadata.Labels[resourceGenerationLabel])
}

func TestRetirementReceiptSurvivesServiceReopen(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	const id = "receipt-reopen"
	storeSandboxForDelete(t, s, id)
	require.NoError(t, s.sandboxManager.UpdateLabels(id, map[string]string{resourceGenerationLabel: "generation"}))
	request := &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "generation"}
	_, err := s.DeleteIfGeneration(context.Background(), request)
	require.NoError(t, err)
	reopenedHandler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	reopened := newTestService(t, map[string]svc.Handler{"runsc": reopenedHandler})
	// A fresh service has no in-memory sandbox/receipt state, but uses the journal directory.
	reopened.config.RootDir = s.config.RootDir
	receipt, err := reopened.DeleteIfGeneration(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, "generation", receipt.RetiredGeneration)
	require.Zero(t, reopenedHandler.calls)
}

func TestPendingOrCorruptRetirementCannotProveDeletion(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	request := &runtime.DeleteIfGenerationRequest{ID: "missing", ExpectedGeneration: "generation"}
	require.NoError(t, s.writeRetirement(request.ID, request.ExpectedGeneration, false))
	_, err := s.DeleteIfGeneration(context.Background(), request)
	require.Equal(t, codes.NotFound, status.Code(err))
	_, path := s.retirementPath(request.ID, request.ExpectedGeneration)
	require.NoError(t, os.WriteFile(path, []byte("broken"), 0600))
	_, err = s.DeleteIfGeneration(context.Background(), request)
	require.Error(t, err)
	require.Zero(t, handler.calls)
}

func TestRetirementJournalFailurePreventsPhysicalDelete(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	storeSandboxForDelete(t, s, "blocked")
	require.NoError(t, s.sandboxManager.UpdateLabels("blocked", map[string]string{resourceGenerationLabel: "generation"}))
	require.NoError(t, os.WriteFile(filepath.Join(s.config.RootDir, "scheduler-retirements"), []byte("not a directory"), 0600))
	_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: "blocked", ExpectedGeneration: "generation"})
	require.Error(t, err)
	require.Zero(t, handler.calls)
	_, err = s.sandboxManager.Get("blocked")
	require.NoError(t, err)
}

func TestPendingRetirementRetriesOnlyMatchingLiveGeneration(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})
	const id = "pending-live"
	storeSandboxForDelete(t, s, id)
	require.NoError(t, s.sandboxManager.UpdateLabels(id, map[string]string{resourceGenerationLabel: "new"}))
	require.NoError(t, s.writeRetirement(id, "old", false))
	_, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "old"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Zero(t, handler.calls)
	require.NoError(t, s.writeRetirement(id, "new", false))
	receipt, err := s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "new"})
	require.NoError(t, err)
	require.Equal(t, "new", receipt.RetiredGeneration)
	require.Equal(t, 1, handler.calls)
	saved, err := s.readRetirement(id, "new")
	require.NoError(t, err)
	require.True(t, saved.Complete)
}

// An unconfirmed physical release must NOT produce the durable completion
// receipt: with the cgroup release failing inside the REAL Recycle
// transaction (toggleable fake through the exported seams), every delete
// attempt fails, the journal carries no completed receipt, and the identity
// survives; once the fault clears, the same generation/resource facts
// complete for real and idempotently.
func TestDeleteIfGenerationWithholdsReceiptWhenReleaseFails(t *testing.T) {
	handler := &recordingDeleteHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newTestService(t, map[string]svc.Handler{"runsc": handler})

	fake := &failingCgroupMgr{}
	s.cgroupMgr = fake

	const id = "release-fails"
	const cgroup = "/akernel/release-fails"
	storeSandboxForDelete(t, s, id)
	require.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID: id, RuntimeHandler: "runsc",
		Labels:       map[string]string{resourceGenerationLabel: "generation"},
		ResourceFacts: map[string]string{config.ResourceNameCgroup: cgroup},
	}))
	request := &runtime.DeleteIfGenerationRequest{ID: id, ExpectedGeneration: "generation"}

	// Fault on: two delete attempts both fail inside the real release path.
	fake.recycleErr = fmt.Errorf("cgroup /akernel/release-fails cleanup unverified: drain fault")
	for attempt := 0; attempt < 2; attempt++ {
		_, err := s.DeleteIfGeneration(context.Background(), request)
		require.Error(t, err, "attempt %d: unconfirmed release must not complete", attempt)
		require.Contains(t, err.Error(), "release resource cgroup")
	}

	// The journal proves the absence: the receipt for this generation (the
	// intent marker written before the runtime delete) must read Complete
	// exactly false while the release is unconfirmed.
	record, readErr := s.readRetirement(id, "generation")
	require.NoError(t, readErr, "the intent receipt must be readable")
	require.False(t, record.Complete,
		"no completed receipt may exist while the release is unconfirmed")

	// Identity survives the unconfirmed release.
	current, err := s.sandboxManager.Get(id)
	require.NoError(t, err)
	require.Equal(t, "generation", current.Metadata.Labels[resourceGenerationLabel])
	require.Equal(t, cgroup, current.Metadata.ResourceFacts[config.ResourceNameCgroup],
		"resource facts must stay intact across failed attempts")

	// Fault cleared: the SAME generation and facts now complete for real,
	// and the journal's receipt flips to Complete=true.
	fake.recycleErr = nil
	response, err := s.DeleteIfGeneration(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, "generation", response.RetiredGeneration)
	record, readErr = s.readRetirement(id, "generation")
	require.NoError(t, readErr)
	require.True(t, record.Complete, "the confirmed release must complete the receipt")

	// And the completed receipt is durable: the replay confirms idempotently.
	_, err = s.DeleteIfGeneration(context.Background(), request)
	require.NoError(t, err)
}

// failingCgroupMgr fakes the service's own sandboxCgroups seam with a
// toggleable Recycle failure, driving the REAL release/receipt chain.
type failingCgroupMgr struct {
	recycleErr error
	recycles   []string
}

func (f *failingCgroupMgr) Allocate() (string, error) { return "", nil }
func (f *failingCgroupMgr) Recycle(name string) error {
	f.recycles = append(f.recycles, name)
	if f.recycleErr != nil {
		return f.recycleErr
	}
	return nil
}
func (f *failingCgroupMgr) Prepare(string, *runtime.LinuxSandboxResources) error { return nil }
func (f *failingCgroupMgr) Stats(string) (cgroupmanager.Stats, error) {
	return cgroupmanager.Stats{}, nil
}
func (f *failingCgroupMgr) CgroupIdentity(string) (cgroupmanager.CgroupIdentity, error) {
	return cgroupmanager.CgroupIdentity{}, nil
}
func (f *failingCgroupMgr) ReadMemoryLimit(string) (int64, error) { return 0, nil }
func (f *failingCgroupMgr) ReadFreeze(string) (cgroupmanager.FreezeState, error) {
	return cgroupmanager.FreezeState{}, nil
}
func (f *failingCgroupMgr) WriteFreeze(string, bool) error       { return nil }
func (f *failingCgroupMgr) WriteMemoryLimits(string, uint64, uint64) error { return nil }
func (f *failingCgroupMgr) SupportsMemoryShrink() bool           { return true }
func (f *failingCgroupMgr) ShutDown() error                       { return nil }
