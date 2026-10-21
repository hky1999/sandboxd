// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"fmt"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
)

// Retirement and admission use the SAME journal write lock. An absent operation
// is fenced durably, not accepted as evidence merely because a query missed it.
// Historical phases are preserved: success and retirement are different facts.
func retirementRefusal(id string) error {
	return errord.ToGRPCf(errord.ErrFailedPrecondition, "start operation %s is fenced for retirement; re-execution forbidden", id)
}

func (s *startOperationStore) beginRetirement(id, sandboxID string) (*startOperationRecord, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	record, exists := s.published(id)
	if exists && record.SandboxID != sandboxID {
		return nil, errord.ToGRPCf(errord.ErrFailedPrecondition, "operation %s belongs to another sandbox", id)
	}
	if exists && record.RetirementComplete {
		return record, nil
	}
	if !exists {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		record = &startOperationRecord{
			Version: 1, OperationID: id, SandboxID: sandboxID,
			Generation: newResourceGeneration(), Runtime: "unadmitted",
			RequestDigest: digestBytes([]byte("retired-before-admission")),
			Phase:         startOperationPhaseFailed, CreatedAt: now, UpdatedAt: now,
			RetirementNeverAdmitted: true,
			Message:                 "retired before admission; this operation never acquired an executor",
		}
	}
	next := *record
	next.RetirementRequested = true
	if next.RetirementReceipt == "" {
		next.RetirementReceipt = newResourceGeneration()
	}
	next.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := validateStartOperationRecord(&next); err != nil {
		return nil, err
	}
	if err := s.persist(&next); err != nil {
		// A failed directory sync may follow a successful rename. Keep the fence
		// in memory too; retries MUST persist it again before returning any proof.
		s.publish(&next)
		return nil, errord.ToGRPCf(errord.ErrUnavailable, "persist retirement fence: %v; no retirement proof", err)
	}
	s.publish(&next)
	return &next, nil
}

func (s *startOperationStore) completeRetirement(id string) (*startOperationRecord, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	record, exists := s.published(id)
	if !exists || !record.RetirementRequested {
		return nil, fmt.Errorf("retirement fence missing")
	}
	if record.RetirementComplete {
		return record, nil
	}
	next := *record
	next.RetirementComplete = true
	next.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := s.persist(&next); err != nil {
		return nil, fmt.Errorf("persist completed retirement: %w", err)
	}
	s.publish(&next)
	return &next, nil
}

// Called while holding the physical-ID lock, before any start side effect.
// New identified incarnations may reuse an ID; a legacy unbound start cannot
// bypass an outstanding retirement by dropping its operation identity.
func (s *startOperationStore) allowPhysicalStart(sandboxID string, binding *startOperationBinding) error {
	if s == nil {
		if binding != nil {
			return errord.ToGRPCf(errord.ErrUnavailable, "start journal unavailable")
		}
		return nil
	}
	if binding != nil {
		record := s.snapshot(binding.operationID)
		if record == nil || record.RetirementRequested {
			return retirementRefusal(binding.operationID)
		}
		return nil
	}
	for _, id := range s.operationIDs() {
		record := s.snapshot(id)
		if record != nil && record.SandboxID == sandboxID && record.RetirementRequested {
			return retirementRefusal(id)
		}
	}
	return nil
}

func (s *startOperationStore) markSucceededWithIP(id, ip, message string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	record, ok := s.published(id)
	if !ok {
		return fmt.Errorf("start operation %s missing", id)
	}
	if isTerminalOperationPhase(record.Phase) {
		return nil
	}
	next := *record
	next.Phase = startOperationPhaseSucceeded
	next.Message = message
	if len(next.Message) > startOperationMaxMsg {
		next.Message = next.Message[:startOperationMaxMsg]
	}
	next.SandboxIP = ip
	next.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := validateStartOperationRecord(&next); err != nil {
		return err
	}
	if err := s.persist(&next); err != nil {
		return err
	}
	s.publish(&next)
	return nil
}

// RetireStartOperation succeeds only after fencing all future executions AND
// the admitted executor has actually returned. Cancellation ends the wait, not
// the executor and not the fence. Unknown start outcomes retain their readers.
func (h *sandboxService) RetireStartOperation(ctx context.Context, request *runtime.RetireStartOperationRequest) (*runtime.RetireStartOperationResponse, error) {
	if request == nil || !validStartOperationID(request.GetOperationID()) || !config.IsValidSandboxID(request.GetSandboxID()) {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "valid operation_id and sandbox_id are required")
	}
	if h.startOperations == nil {
		return nil, errord.ToGRPCf(errord.ErrUnavailable, "start journal unavailable")
	}
	unlock, err := h.operationRetirementLocks.acquire(ctx, request.GetOperationID())
	if err != nil {
		return nil, err
	}
	defer unlock()
	record, err := h.startOperations.beginRetirement(request.GetOperationID(), request.GetSandboxID())
	if err != nil {
		return nil, err
	}
	if !record.RetirementComplete {
		if done, running := h.startOperations.executionDone(record.OperationID); running {
			select {
			case <-done:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		record = h.startOperations.snapshot(record.OperationID)
		if !record.RetirementNeverAdmitted {
			// An intent owns resources even when the operation's terminal publication
			// was interrupted. Never turn absence of an executor into a cleanup proof.
			if h.startIntents.Pending(record.SandboxID) {
				return nil, errord.ToGRPCf(errord.ErrFailedPrecondition, "pending start intent requires reconciliation; no retirement proof")
			}
			switch record.Phase {
			case startOperationPhaseFailed:
				// The start flow persisted this fact only after proven full rollback.
			case startOperationPhaseSucceeded:
				if err := h.deleteSandbox(ctx, record.SandboxID, record.Generation); err != nil {
					return nil, err
				}
			default:
				return nil, errord.ToGRPCf(errord.ErrFailedPrecondition, "start outcome %s is unproven; no retirement proof", record.Phase)
			}
		}
		record, err = h.startOperations.completeRetirement(record.OperationID)
		if err != nil {
			return nil, errord.ToGRPC(err)
		}
	}
	return &runtime.RetireStartOperationResponse{
		OperationID: record.OperationID, SandboxID: record.SandboxID,
		ResourceGeneration: record.Generation, RetirementReceipt: record.RetirementReceipt,
	}, nil
}
