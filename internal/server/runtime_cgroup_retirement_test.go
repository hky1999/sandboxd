// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	runtimeapi "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/cgroupmanager"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/require"
)

// Controlled interfaces plus the real private retirement journal. There are
// no physical cgroup changes or process signals in these ordinary tests.
type closeRetirementGroups struct {
	*failingCgroupMgr
	t                    *testing.T
	service              *sandboxService
	id, generation       string
	snapshot             cgroupmanager.GenerationLeaseSnapshot
	request              *cgroupmanager.GenerationCgroupCloseRequest
	closeError           error
	continuationError    error
	closeCalls, releases int
	continuationCalls    int
	proofFile            *os.File
}

func (g *closeRetirementGroups) InspectGenerationLease(path, generation string) (cgroupmanager.GenerationLeaseSnapshot, error) {
	if path != g.snapshot.Identity.Path || generation != g.generation {
		return cgroupmanager.GenerationLeaseSnapshot{}, errors.New("original lease path changed")
	}
	snapshot := g.snapshot
	if g.request != nil {
		request := *g.request
		snapshot.CloseRequest = &request
	}
	return snapshot, nil
}

func (g *closeRetirementGroups) CloseForGeneration(_ context.Context, request cgroupmanager.GenerationCgroupCloseRequest) (*cgroupmanager.ClosedGenerationCgroup, error) {
	g.closeCalls++
	progress, err := g.service.readRetirementProgress(g.id, request.Generation)
	require.NoError(g.t, err)
	require.NotNil(g.t, progress.CgroupClose)
	require.Equal(g.t, request, progress.CgroupClose.Request, "daemon intent must be saved before the manager effect")
	if g.request != nil {
		require.Equal(g.t, *g.request, request, "retry must keep the original operation, revision and deadline")
	}
	if g.request == nil && errors.Is(g.closeError, context.DeadlineExceeded) {
		return nil, g.closeError
	}
	copy := request
	g.request = &copy
	if g.closeError != nil {
		return nil, g.closeError
	}
	g.snapshot.Closed = true
	return &cgroupmanager.ClosedGenerationCgroup{Identity: g.snapshot.Identity, Parent: g.proofFile}, nil
}

func (g *closeRetirementGroups) RecycleForGeneration(_ string, _ string) error {
	g.releases++
	if !g.snapshot.Closed {
		return errors.New("original close not complete")
	}
	return nil
}

func (g *closeRetirementGroups) ContinueCloseForGeneration(_ context.Context, original, continuation cgroupmanager.GenerationCgroupCloseRequest) (*cgroupmanager.ClosedGenerationCgroup, error) {
	g.continuationCalls++
	progress, err := g.service.readRetirementProgress(g.id, g.generation)
	require.NoError(g.t, err)
	require.Equal(g.t, original, progress.CgroupClose.Request)
	require.Equal(g.t, continuation, progress.CgroupClose.Continuations[len(progress.CgroupClose.Continuations)-1], "continuation must be durable before dispatch")
	if g.request == nil {
		copy := original
		g.request = &copy
	}
	require.Equal(g.t, *g.request, original)
	if len(g.snapshot.Continuations) == 0 {
		g.snapshot.Continuations = []cgroupmanager.GenerationCgroupCloseRequest{continuation}
	} else {
		require.Equal(g.t, g.snapshot.Continuations[len(g.snapshot.Continuations)-1], continuation)
	}
	if g.continuationError != nil {
		return nil, g.continuationError
	}
	g.snapshot.Closed = true
	return &cgroupmanager.ClosedGenerationCgroup{Identity: g.snapshot.Identity, Parent: g.proofFile}, nil
}

type closeRetirementRuntime struct {
	nativeRetirementHandler
	t                             *testing.T
	present                       bool
	sourceError, nativeError      error
	verificationCalls, proofCalls int
	onVerification                func(int)
}

func (r *closeRetirementRuntime) VerifyRuntimeGeneration(context.Context, string, string) error {
	return errors.New("first birth not published")
}
func (r *closeRetirementRuntime) VerifyRuntimeCgroupGeneration(_ context.Context, id, generation string, identity svc.CgroupRuntimeIdentity) error {
	r.verificationCalls++
	if r.onVerification != nil {
		r.onVerification(r.verificationCalls)
	}
	require.Equal(r.t, r.id, id)
	require.Equal(r.t, r.generation, generation)
	require.Equal(r.t, svc.CgroupRuntimeIdentity{Path: "/sandbox/original", Device: 7, Inode: 31}, identity)
	return r.sourceError
}
func (r *closeRetirementRuntime) DeleteRuntimeAfterCgroupClosed(_ context.Context, id, generation string, proof svc.CgroupRuntimeProof) error {
	r.proofCalls++
	require.Equal(r.t, r.id, id)
	require.Equal(r.t, r.generation, generation)
	require.NotNil(r.t, proof.Parent)
	require.Nil(r.t, proof.Directory)
	if r.nativeError != nil {
		return r.nativeError
	}
	r.present = false
	return nil
}
func (r *closeRetirementRuntime) List(context.Context) ([]*svc.State, error) {
	if r.present {
		return []*svc.State{{ID: r.id, Status: "creating"}}, nil
	}
	return []*svc.State{}, nil
}

func newRuntimeCloseFixture(t *testing.T) (*sandboxService, *runtimeapi.SandboxMetadata, *runtimeapi.StartOperationRequest, *closeRetirementRuntime, *closeRetirementGroups) {
	t.Helper()
	r := &closeRetirementRuntime{t: t, present: true, nativeRetirementHandler: nativeRetirementHandler{failedCreationHandler: failedCreationHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}}}
	s, metadata, request := failedCreationRetirementFixture(t, r)
	r.id, r.generation = metadata.ID, metadata.Labels[resourceGenerationLabel]
	metadata.ResourceFacts = map[string]string{config.ResourceNameCgroup: "/sandbox/original"}
	require.NoError(t, s.sandboxManager.PersistMetadata(metadata.ID, metadata))
	g := &closeRetirementGroups{t: t, service: s, failingCgroupMgr: &failingCgroupMgr{}, snapshot: cgroupmanager.GenerationLeaseSnapshot{Identity: cgroupmanager.CgroupIdentity{Path: "/sandbox/original", Device: 7, Inode: 31}}}
	g.id, g.generation = r.id, r.generation
	s.cgroupMgr = g
	return s, metadata, request, r, g
}

func (g *closeRetirementGroups) provideFreshProof(t *testing.T) {
	t.Helper()
	file, err := os.Open(t.TempDir())
	require.NoError(t, err)
	g.proofFile = file
}

func TestDaemonCgroupCloseUnknownNativeResultKeepsResourcesAndOriginalRequest(t *testing.T) {
	s, metadata, request, r, g := newRuntimeCloseFixture(t)
	g.provideFreshProof(t)
	r.nativeError = errors.New("native reply lost")
	require.ErrorContains(t, s.reconcilePhysicalIntent(context.Background(), metadata), "native reply lost")
	require.Equal(t, 1, g.closeCalls)
	require.Equal(t, 1, r.proofCalls)
	require.Zero(t, g.releases)
	require.Zero(t, r.nativeCalls)
	require.Zero(t, r.legacyCalls)
	first := *g.request
	response, err := s.GetStartOperation(context.Background(), startOperationQuery(request))
	require.NoError(t, err)
	require.Equal(t, runtimeapi.StartOperationState_START_OPERATION_STATE_PENDING, response.State)
	r.nativeError = nil
	g.provideFreshProof(t)
	require.NoError(t, s.reconcilePhysicalIntent(context.Background(), metadata))
	require.Equal(t, first, *g.request)
	require.Equal(t, 1, g.releases)
}

func TestDaemonCgroupCloseReopenAfterNativeEffectBeforeCompletionUsesOriginalProof(t *testing.T) {
	s, metadata, _, r, g := newRuntimeCloseFixture(t)
	g.provideFreshProof(t)
	r.nativeError = errors.New("completion reply unknown")
	require.Error(t, s.reconcilePhysicalIntent(context.Background(), metadata))
	require.NotNil(t, g.request, "original close intent must reach the manager before the injected native failure")
	first := *g.request
	r.present = false
	r.nativeError = nil
	reopened := reopenFailedCreationRetirement(t, s, r)
	// Reopen the original durable filesystem store, rather than the new
	// empty store allocated by the generic service fixture.
	reopened.fsMgr = newFSManager(nil, s.fsMgr.store)
	g.service = reopened
	reopened.cgroupMgr = g
	g.provideFreshProof(t)
	require.NoError(t, reopened.reconcilePhysicalIntents(context.Background()))
	require.Equal(t, first, *g.request)
	require.Equal(t, 1, r.proofCalls, "known absent runtime must not repeat a native mutation")
	require.Equal(t, 1, g.releases)
}

func TestDaemonCgroupCloseSourceOrManagerFailureCannotReleaseBudget(t *testing.T) {
	for _, phase := range []string{"source", "close"} {
		t.Run(phase, func(t *testing.T) {
			s, metadata, request, r, g := newRuntimeCloseFixture(t)
			if phase == "source" {
				r.sourceError = errors.New("producer binding changed")
			} else {
				g.closeError = errors.New("close completion unavailable")
			}
			require.Error(t, s.reconcilePhysicalIntent(context.Background(), metadata))
			require.Zero(t, g.releases)
			require.Zero(t, r.proofCalls)
			require.Zero(t, r.nativeCalls)
			require.Zero(t, r.legacyCalls)
			response, err := s.GetStartOperation(context.Background(), startOperationQuery(request))
			require.NoError(t, err)
			require.Equal(t, runtimeapi.StartOperationState_START_OPERATION_STATE_PENDING, response.State)
			if phase == "source" {
				require.Zero(t, g.closeCalls)
			}
		})
	}
}

func TestDaemonCgroupCloseCannotAdoptUnassociatedOrChangedManagerRequest(t *testing.T) {
	for _, phase := range []string{"unassociated", "fingerprint", "identity"} {
		t.Run(phase, func(t *testing.T) {
			s, metadata, _, r, g := newRuntimeCloseFixture(t)
			if phase == "unassociated" {
				g.request = &cgroupmanager.GenerationCgroupCloseRequest{Path: g.snapshot.Identity.Path, Generation: r.generation, OperationID: "different-original-close", Deadline: time.Now().Add(time.Minute)}
			} else {
				g.closeError = errors.New("retain intent")
				require.Error(t, s.reconcilePhysicalIntent(context.Background(), metadata))
				g.closeError = nil
				if phase == "fingerprint" {
					g.request.Deadline = g.request.Deadline.Add(time.Second)
				} else {
					g.snapshot.Identity.Inode++
				}
			}
			before := g.closeCalls
			require.Error(t, s.reconcilePhysicalIntent(context.Background(), metadata))
			require.Equal(t, before, g.closeCalls)
			require.Zero(t, g.releases)
			require.Zero(t, r.proofCalls)
		})
	}
}

func stageExpiredDaemonClose(t *testing.T, s *sandboxService, metadata *runtimeapi.SandboxMetadata, g *closeRetirementGroups) cgroupmanager.GenerationCgroupCloseRequest {
	t.Helper()
	resources, err := s.physicalResources(metadata)
	require.NoError(t, err)
	progress, err := s.beginRetirementProgress(metadata, resources)
	require.NoError(t, err)
	original := cgroupmanager.GenerationCgroupCloseRequest{Path: g.snapshot.Identity.Path, Generation: g.generation, OperationID: "original-expired-close", Deadline: time.Now().Add(-time.Minute).UTC()}
	progress.Version = 2
	progress.CgroupClose = &retirementCgroupClose{Identity: g.snapshot.Identity, Request: original, RuntimeSourceVerified: true}
	require.NoError(t, s.writeRetirementProgress(progress))
	return original
}

func TestDaemonCgroupCloseExpiredIntentContinuesAcrossReopenWithoutChangingOriginal(t *testing.T) {
	for _, managerPrepared := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-manager-dispatch", true: "manager-intent-saved"}[managerPrepared], func(t *testing.T) {
			s, metadata, request, r, g := newRuntimeCloseFixture(t)
			original := stageExpiredDaemonClose(t, s, metadata, g)
			if managerPrepared {
				g.request = &original
			}
			g.closeError = context.DeadlineExceeded
			g.continuationError = errors.New("continuation completion unavailable")
			require.ErrorContains(t, s.reconcilePhysicalIntent(context.Background(), metadata), "completion unavailable")
			require.Equal(t, original, *g.request)
			require.Zero(t, g.releases)
			require.Zero(t, r.proofCalls)
			require.Len(t, g.snapshot.Continuations, 1)
			continuation := g.snapshot.Continuations[0]
			require.Equal(t, uint64(1), continuation.ExpectedRevision)
			require.NotEqual(t, original.OperationID, continuation.OperationID)
			reopened := reopenFailedCreationRetirement(t, s, r)
			reopened.fsMgr = newFSManager(nil, s.fsMgr.store)
			g.service, reopened.cgroupMgr = reopened, g
			g.continuationError = nil
			g.provideFreshProof(t)
			require.NoError(t, reopened.reconcilePhysicalIntents(context.Background()))
			require.Equal(t, original, *g.request)
			require.Equal(t, []cgroupmanager.GenerationCgroupCloseRequest{continuation}, g.snapshot.Continuations)
			require.Equal(t, 2, g.continuationCalls)
			require.Equal(t, 1, g.releases)
			response, err := reopened.GetStartOperation(context.Background(), startOperationQuery(request))
			require.NoError(t, err)
			require.Equal(t, runtimeapi.StartOperationState_START_OPERATION_STATE_RETIRED, response.State)
		})
	}
}

func TestDaemonCgroupCloseIntentSaveFailurePreventsPhysicalDispatch(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "first-close", true: "continuation"}[expired], func(t *testing.T) {
			s, metadata, _, r, g := newRuntimeCloseFixture(t)
			if expired {
				original := stageExpiredDaemonClose(t, s, metadata, g)
				g.request = &original
				g.closeError = context.DeadlineExceeded
			}
			// Replace the bound lock only after source verification, before
			// the new intent is saved. The existing durable record stays intact.
			r.onVerification = func(call int) {
				wanted := 1
				if expired {
					wanted = 2
				}
				if call != wanted {
					return
				}
				lock := filepath.Join(s.config.RootDir, "scheduler-retirement-progress", ".lock")
				require.NoError(t, os.Rename(lock, lock+".original"))
				require.NoError(t, os.WriteFile(lock, nil, 0600))
			}
			require.Error(t, s.reconcilePhysicalIntent(context.Background(), metadata))
			require.Zero(t, g.continuationCalls)
			require.Zero(t, g.releases)
			require.Zero(t, r.proofCalls)
			if !expired {
				require.Zero(t, g.closeCalls)
			}
		})
	}
}

func TestDaemonCgroupCloseFirstIntentAndSnapshotCannotBeRewritten(t *testing.T) {
	for _, change := range []string{"operation", "deadline", "inode", "resources", "drop-close", "source-verified"} {
		t.Run(change, func(t *testing.T) {
			s, metadata, _, _, g := newRuntimeCloseFixture(t)
			stageExpiredDaemonClose(t, s, metadata, g)
			_, path := s.retirementProgressPath(metadata.ID, g.generation)
			before, err := os.ReadFile(path)
			require.NoError(t, err)
			progress, err := s.readRetirementProgress(metadata.ID, g.generation)
			require.NoError(t, err)
			switch change {
			case "operation":
				progress.CgroupClose.Request.OperationID = "different-original"
			case "deadline":
				progress.CgroupClose.Request.Deadline = time.Now().Add(time.Minute)
			case "inode":
				progress.CgroupClose.Identity.Inode++
			case "resources":
				progress.Resources.Resources["foreign"] = "replacement"
			case "drop-close":
				progress.Version, progress.CgroupClose = 1, nil
			case "source-verified":
				progress.CgroupClose.RuntimeSourceVerified = false
			}
			require.Error(t, s.writeRetirementProgress(progress))
			after, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Zero(t, g.closeCalls)
		})
	}
}

func TestDaemonCgroupCloseCompletedRuntimeStepDoesNotReacquireReleasedLease(t *testing.T) {
	s, metadata, _, r, g := newRuntimeCloseFixture(t)
	resources, err := s.physicalResources(metadata)
	require.NoError(t, err)
	progress, err := s.beginRetirementProgress(metadata, resources)
	require.NoError(t, err)
	g.provideFreshProof(t)
	require.NoError(t, s.retireOriginalRuntime(context.Background(), r, metadata, progress))
	require.NoError(t, s.completeRetirementProgressStep(progress, "runtime"))
	// Other resource cleanup may have released this lease before a later
	// failure. Its completed runtime step plus fresh inventory is sufficient
	// to avoid trying to close the old lease again.
	g.snapshot.Identity.Path = "/no-active-original-lease"
	require.NoError(t, s.retireOriginalRuntime(context.Background(), r, metadata, progress))
	require.Equal(t, 1, g.closeCalls)
	require.Equal(t, 1, r.proofCalls)
	r.present = true
	require.ErrorContains(t, s.retireOriginalRuntime(context.Background(), r, metadata, progress), "reappeared")
	require.Equal(t, 1, r.proofCalls)
}
