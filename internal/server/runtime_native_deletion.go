// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	runtimeapi "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/cgroupmanager"

	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
)

type generationCgroupCloser interface {
	InspectGenerationLease(string, string) (cgroupmanager.GenerationLeaseSnapshot, error)
	CloseForGeneration(context.Context, cgroupmanager.GenerationCgroupCloseRequest) (*cgroupmanager.ClosedGenerationCgroup, error)
}

type generationCgroupCloseContinuer interface {
	ContinueCloseForGeneration(context.Context, cgroupmanager.GenerationCgroupCloseRequest, cgroupmanager.GenerationCgroupCloseRequest) (*cgroupmanager.ClosedGenerationCgroup, error)
}

func sameOriginalCloseRequest(a, b cgroupmanager.GenerationCgroupCloseRequest) bool {
	return a.Path == b.Path && a.Generation == b.Generation && a.OperationID == b.OperationID &&
		a.ExpectedRevision == b.ExpectedRevision && a.Deadline.Equal(b.Deadline)
}

func boundedCloseDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(20 * time.Second)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	return deadline.UTC()
}

func cgroupRuntimeIdentity(identity cgroupmanager.CgroupIdentity) svc.CgroupRuntimeIdentity {
	return svc.CgroupRuntimeIdentity{Path: identity.Path, Device: identity.Device, Inode: identity.Inode}
}

// This is the single runtime retirement route for committed executions and
// failed intents. The caller owns the physical lock and original progress.
func (h *sandboxService) retireOriginalRuntime(ctx context.Context, handler svc.Handler, metadata *runtimeapi.SandboxMetadata, progress *retirementProgress) error {
	if progress != nil && (len(progress.Steps) != 0 || progress.CgroupClose != nil) {
		states, err := handler.List(ctx)
		if err != nil {
			return fmt.Errorf("read runtime inventory before retirement retry: %w", err)
		}
		present := false
		for _, state := range states {
			if state == nil {
				return errors.New("runtime inventory is incomplete before retirement retry")
			}
			present = present || state.ID == metadata.ID
		}
		if len(progress.Steps) != 0 && present {
			return errors.New("runtime reappeared after original retirement completion")
		}
		if !present {
			return h.confirmAbsentRuntimeCgroup(ctx, handler, progress)
		}
	}
	generation := metadata.Labels[resourceGenerationLabel]
	path := ""
	if progress != nil {
		path = progress.Resources.Resources[config.ResourceNameCgroup]
	}
	if retire, ok := handler.(svc.CgroupRuntimeRetirer); ok && generation != "" && path != "" {
		closer, ok := h.cgroupMgr.(generationCgroupCloser)
		if !ok {
			return errors.New("original runtime cgroup close capability unavailable")
		}
		proof, err := h.closeOriginalRuntimeCgroup(ctx, retire, closer, progress, true)
		if err != nil {
			return err
		}
		defer proof.Close()
		return retire.DeleteRuntimeAfterCgroupClosed(ctx, metadata.ID, generation, svc.CgroupRuntimeProof{Identity: cgroupRuntimeIdentity(proof.Identity), Directory: proof.Directory, Parent: proof.Parent})
	}
	if progress != nil && progress.CgroupClose != nil {
		return errors.New("original cgroup retirement cannot revert to ordinary runtime deletion")
	}
	if generation != "" {
		if verifier, ok := handler.(svc.RuntimeGenerationVerifier); ok {
			if err := verifier.VerifyRuntimeGeneration(ctx, metadata.ID, generation); err != nil {
				return fmt.Errorf("verify original runtime generation: %w", err)
			}
		}
	}
	return deleteOriginalRuntime(ctx, handler, metadata.ID, generation)
}

func (h *sandboxService) closeOriginalRuntimeCgroup(ctx context.Context, retire svc.CgroupRuntimeRetirer, closer generationCgroupCloser, progress *retirementProgress, runtimePresent bool) (*cgroupmanager.ClosedGenerationCgroup, error) {
	if progress == nil {
		return nil, errors.New("original cgroup retirement progress is missing")
	}
	if err := h.verifyRetirementProgressSnapshot(progress); err != nil {
		return nil, err
	}
	path := progress.Resources.Resources[config.ResourceNameCgroup]
	snapshot, err := closer.InspectGenerationLease(path, progress.Generation)
	if err != nil {
		return nil, err
	}
	if progress.CgroupClose == nil {
		if !runtimePresent || snapshot.CloseRequest != nil {
			return nil, errors.New("unassociated original cgroup close cannot be adopted")
		}
		if err := retire.VerifyRuntimeCgroupGeneration(ctx, progress.SandboxID, progress.Generation, cgroupRuntimeIdentity(snapshot.Identity)); err != nil {
			return nil, fmt.Errorf("verify original runtime cgroup before close intent: %w", err)
		}
		progress.CgroupClose = &retirementCgroupClose{Identity: snapshot.Identity, RuntimeSourceVerified: true, Request: cgroupmanager.GenerationCgroupCloseRequest{Path: path, Generation: progress.Generation, OperationID: uuid.NewString(), Deadline: boundedCloseDeadline(ctx)}}
		progress.Version = 2
		if err := h.writeRetirementProgress(progress); err != nil {
			return nil, err
		}
	} else {
		if progress.CgroupClose.Identity != snapshot.Identity {
			return nil, errors.New("original retirement cgroup differs from generation lease")
		}
		if runtimePresent {
			if err := retire.VerifyRuntimeCgroupGeneration(ctx, progress.SandboxID, progress.Generation, cgroupRuntimeIdentity(snapshot.Identity)); err != nil {
				return nil, err
			}
		}
	}
	request := progress.CgroupClose.Request
	continuations := progress.CgroupClose.Continuations
	if snapshot.CloseRequest != nil {
		original := *snapshot.CloseRequest
		if !sameOriginalCloseRequest(original, request) {
			return nil, errors.New("cgroup close request differs between the two original journals")
		}
	}
	// The daemon may be exactly one prepared continuation ahead of the
	// manager, because its intent is saved before dispatch. It may never
	// adopt a manager history missing from its original retirement journal.
	if len(snapshot.Continuations) > len(continuations) || len(continuations) > len(snapshot.Continuations)+1 ||
		snapshot.CloseRequest == nil && (len(snapshot.Continuations) != 0 || snapshot.Closed) {
		return nil, errors.New("cgroup close continuation histories cannot be associated")
	}
	for i, original := range snapshot.Continuations {
		if !sameOriginalCloseRequest(original, continuations[i]) {
			return nil, errors.New("cgroup close continuation differs between the original journals")
		}
	}
	if err := h.verifyRetirementProgressSnapshot(progress); err != nil {
		return nil, err
	}
	active := request
	var proof *cgroupmanager.ClosedGenerationCgroup
	if len(continuations) == 0 {
		proof, err = closer.CloseForGeneration(ctx, request)
	} else {
		active = continuations[len(continuations)-1]
		continuer, ok := closer.(generationCgroupCloseContinuer)
		if !ok {
			return nil, errors.New("original cgroup close continuation capability unavailable")
		}
		proof, err = continuer.ContinueCloseForGeneration(ctx, request, active)
	}
	if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil && !time.Now().Before(active.Deadline) && runtimePresent && !snapshot.Closed {
		continuer, ok := closer.(generationCgroupCloseContinuer)
		if !ok {
			return nil, errors.New("expired original cgroup close continuation capability unavailable")
		}
		if err := retire.VerifyRuntimeCgroupGeneration(ctx, progress.SandboxID, progress.Generation, cgroupRuntimeIdentity(snapshot.Identity)); err != nil {
			return nil, err
		}
		if err := h.verifyRetirementProgressSnapshot(progress); err != nil {
			return nil, err
		}
		continuation := cgroupmanager.GenerationCgroupCloseRequest{Path: request.Path, Generation: request.Generation, OperationID: uuid.NewString(), ExpectedRevision: uint64(1 + len(continuations)), Deadline: boundedCloseDeadline(ctx)}
		progress.CgroupClose.Continuations = append(append([]cgroupmanager.GenerationCgroupCloseRequest(nil), continuations...), continuation)
		if err := h.writeRetirementProgress(progress); err != nil {
			return nil, err
		}
		proof, err = continuer.ContinueCloseForGeneration(ctx, request, continuation)
	}
	if err != nil {
		return nil, err
	}
	if proof == nil || proof.Identity != progress.CgroupClose.Identity {
		if proof != nil {
			_ = proof.Close()
		}
		return nil, errors.New("closed cgroup proof differs from original retirement binding")
	}
	return proof, nil
}

func (h *sandboxService) confirmAbsentRuntimeCgroup(ctx context.Context, handler svc.Handler, progress *retirementProgress) error {
	if progress == nil || progress.CgroupClose == nil || len(progress.Steps) != 0 {
		return nil
	}
	retire, ok := handler.(svc.CgroupRuntimeRetirer)
	if !ok {
		return errors.New("original cgroup retirement handler is unavailable")
	}
	closer, ok := h.cgroupMgr.(generationCgroupCloser)
	if !ok {
		return errors.New("original cgroup retirement manager is unavailable")
	}
	proof, err := h.closeOriginalRuntimeCgroup(ctx, retire, closer, progress, false)
	if err != nil {
		return err
	}
	return proof.Close()
}

func deleteOriginalRuntime(ctx context.Context, handler svc.Handler, id, generation string) error {
	if generation != "" {
		if native, ok := handler.(svc.GenerationRuntimeDeleter); ok {
			return native.DeleteRuntimeIfGeneration(ctx, id, generation)
		}
		if _, ok := handler.(svc.RuntimeGenerationVerifier); ok {
			return errors.New("runtime generation verification cannot authorize unconditional deletion")
		}
	}
	return handler.Delete(ctx, id)
}
