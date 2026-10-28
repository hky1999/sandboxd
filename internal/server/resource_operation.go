// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/cgroupmanager"
	"github.com/inclusionAI/sandboxd/pkg/errord"
)

// The node-defined minimum headroom a shrink must preserve between the frozen
// memory.current and the target memory.high. It is a floor, not a knob a
// request can lower; deployments may raise it through
// ResourceConfig.MemoryShrinkHeadroomMiB.
const minimumShrinkHeadroomMiB = 16

// shrinkHeadroomBytes is the enforced safety margin; a configured value below
// the minimum is raised to it, never honored as a smaller margin.
func (h *sandboxService) shrinkHeadroomBytes() uint64 {
	if configured := h.config.ResourceConfig.MemoryShrinkHeadroomMiB; configured > minimumShrinkHeadroomMiB {
		return uint64(configured) << 20
	}
	return uint64(minimumShrinkHeadroomMiB) << 20
}

// memoryHighRatio is the node's enforced memory.high policy.
func (h *sandboxService) memoryHighRatio() float64 {
	return h.config.ResourceConfig.MemoryHighRatio
}

// expectedMemoryHighBytes is the one authoritative memory.high this node
// enforces for a memory limit: page-aligned MemoryHighBytes when the ratio is
// enabled, otherwise the kernel's unlimited sentinel. Grow readback, shrink
// writes, and shrink safety margins all derive from here.
func (h *sandboxService) expectedMemoryHighBytes(limitBytes uint64) (highBytes uint64, unlimited bool) {
	if ratio := h.memoryHighRatio(); ratio > 0 {
		return cgroupmanager.MemoryHighBytes(limitBytes, ratio), false
	}
	return 0, true
}

// memoryHighMatches requires a proven observation equal to the enforced high.
func (h *sandboxService) memoryHighMatches(stats *runtime.StatsResponse, limitBytes uint64) bool {
	if !stats.MemoryHighKnown {
		return false
	}
	want, unlimited := h.expectedMemoryHighBytes(limitBytes)
	if unlimited {
		return stats.MemoryHighUnlimited
	}
	return !stats.MemoryHighUnlimited && stats.MemoryHighBytes == want
}

// resourceMutationRequest is the version-neutral grow/shrink command. Both
// RPCs carry the identical seven-field contract; the kind participates in the
// fingerprint so an operation ID can never migrate between them.
type resourceMutationRequest struct {
	Kind               string
	SandboxID          string
	ResourceGeneration string
	Expected           *runtime.ResourceLimits
	Target             *runtime.ResourceLimits
	DeadlineUnixMs     int64
	OperationID        string
	ExpectedRevision   uint64
}

// normalizeResourceMutation enforces the shape shared by both operations:
// identity, finite positive limits, a bounded absolute deadline, a bounded
// printable operation ID, and a non-zero expected revision. A request without
// a revision is rejected rather than silently skipping the compare — the
// pre-revision grow client must not bypass the bidirectional contract.
func normalizeResourceMutation(kind string, sandboxID, generation string, expected, target *runtime.ResourceLimits, deadlineUnixMs int64, operationID string, expectedRevision uint64) (*resourceMutationRequest, error) {
	if sandboxID == "" || generation == "" || expected == nil || target == nil {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "sandbox, generation, expected and target limits are required")
	}
	if kind != resourceOperationGrow && kind != resourceOperationShrink {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "unknown resource operation kind %q", kind)
	}
	if deadlineUnixMs <= 0 || deadlineUnixMs > time.Now().Add(time.Minute).UnixMilli() {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "resource operations require a command deadline within one minute")
	}
	if operationID == "" || len(operationID) > 128 {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "resource operation ID is required and bounded to 128 bytes")
	}
	for _, r := range operationID {
		if r < 0x21 || r > 0x7e {
			return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "resource operation ID must be printable without whitespace")
		}
	}
	if expectedRevision < 1 {
		return nil, errord.ToGRPCf(errord.ErrFailedPrecondition, "resource operations require a proven expected revision; refresh Stats")
	}
	for _, limits := range []*runtime.ResourceLimits{expected, target} {
		if limits.CpuQuotaUsec <= 0 || limits.CpuPeriodUsec == 0 || limits.MemoryLimitBytes == 0 || limits.MemoryLimitBytes > math.MaxInt64 {
			return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "finite positive CPU/memory limits are required")
		}
	}
	return &resourceMutationRequest{
		Kind: kind, SandboxID: sandboxID, ResourceGeneration: generation,
		Expected: expected, Target: target, DeadlineUnixMs: deadlineUnixMs,
		OperationID: operationID, ExpectedRevision: expectedRevision,
	}, nil
}

// fingerprint binds one operation ID to its complete request identity:
// sandbox, generation, kind, expected revision, both limit triples, and the
// absolute deadline. The same ID under any other request is a conflict.
func (m *resourceMutationRequest) fingerprint() string {
	payload, _ := json.Marshal(struct {
		Kind               string                  `json:"kind"`
		SandboxID          string                  `json:"sandbox_id"`
		ResourceGeneration string                  `json:"resource_generation"`
		ExpectedRevision   uint64                  `json:"expected_revision"`
		DeadlineUnixMs     int64                   `json:"deadline_unix_ms"`
		Expected           *runtime.ResourceLimits `json:"expected"`
		Target             *runtime.ResourceLimits `json:"target"`
	}{
		Kind: m.Kind, SandboxID: m.SandboxID, ResourceGeneration: m.ResourceGeneration,
		ExpectedRevision: m.ExpectedRevision, DeadlineUnixMs: m.DeadlineUnixMs,
		Expected: m.Expected, Target: m.Target,
	})
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func resourceStateLimitsFromProto(limits *runtime.ResourceLimits) *resourceStateLimits {
	if limits == nil {
		return nil
	}
	return &resourceStateLimits{
		CpuQuotaUsec: limits.CpuQuotaUsec, CpuPeriodUsec: limits.CpuPeriodUsec,
		MemoryLimitBytes: limits.MemoryLimitBytes,
	}
}

// resourceRecordedOutcome is the journal's terminal answer for one operation
// ID. Replay serves exactly this recorded fact — including a partial one —
// and never re-executes the request.
type resourceRecordedOutcome struct {
	Complete bool
	Message  string
}

// resolveResourceOperation runs the shared, side-effect-free admission under
// the incarnation's physical resource lock: identity, revision state, replay,
// and the revision compare. It returns either the loaded state ready to open
// a new operation, or a recorded outcome to replay.
func (h *sandboxService) resolveResourceOperation(m *resourceMutationRequest) (*resourceOperationState, *resourceRecordedOutcome, error) {
	current, err := h.sandboxManager.Get(m.SandboxID)
	if err != nil {
		return nil, nil, errord.ToGRPC(err)
	}
	if current.Metadata == nil || current.Status == nil || current.Status.Get().State() != runtime.SandboxState_SANDBOX_STATE_RUNNING {
		return nil, nil, errord.ToGRPCf(errord.ErrFailedPrecondition, "resource operations require a running sandbox")
	}
	labels := current.Metadata.Labels
	if labels[resourceGenerationLabel] != m.ResourceGeneration {
		return nil, nil, errord.ToGRPCf(errord.ErrFailedPrecondition, "stale resource generation")
	}
	if labels[elasticResourcesLabel] == "" {
		return nil, nil, errord.ToGRPCf(errord.ErrFailedPrecondition, "sandbox has no elastic policy")
	}
	state, result, err := h.loadResourceOperationState(m.SandboxID, m.ResourceGeneration)
	if err != nil {
		return nil, nil, errord.ToGRPCf(errord.ErrUnavailable, "resource revision state for sandbox %s is unreadable: %v", m.SandboxID, err)
	}
	switch result {
	case resourceStateMissing:
		return nil, nil, errord.ToGRPCf(errord.ErrFailedPrecondition,
			"sandbox %s has no proven resource revision; bidirectional operations are rejected until it is recreated", m.SandboxID)
	case resourceStateCorrupt:
		return nil, nil, errord.ToGRPCf(errord.ErrFailedPrecondition,
			"sandbox %s resource revision state is damaged; reconciliation required", m.SandboxID)
	}
	fingerprint := m.fingerprint()
	if state.LastOperationID != "" && state.LastOperationID == m.OperationID {
		if state.LastFingerprint != fingerprint {
			return nil, nil, errord.ToGRPCf(errord.ErrFailedPrecondition,
				"operation ID %s was already used by a different request", m.OperationID)
		}
		if state.open() {
			return nil, nil, errord.ToGRPCf(errord.ErrUnavailable,
				"operation %s is still pending on sandbox %s; reconciliation required", m.OperationID, m.SandboxID)
		}
		return nil, &resourceRecordedOutcome{
			Complete: state.LastOutcome == resourceOutcomeComplete,
			Message:  state.LastOutcomeMessage,
		}, nil
	}
	if state.open() {
		return nil, nil, errord.ToGRPCf(errord.ErrUnavailable,
			"sandbox %s has an unclosed resource operation (%s); reconciliation required", m.SandboxID, state.LastOperationID)
	}
	if m.ExpectedRevision != state.Revision {
		return nil, nil, errord.ToGRPCf(errord.ErrFailedPrecondition,
			"stale resource revision %d; current revision is %d", m.ExpectedRevision, state.Revision)
	}
	return state, nil, nil
}

// openResourceOperationIntent durably records the next revision and the
// complete command before any resource side effect. For shrink the persisted
// freeze ownership intent precedes the freeze write, so a crash between the
// two still leaves an owned, recoverable freeze intent. The revision must
// still be incrementable: UINT64_MAX refuses the operation instead of
// wrapping back to a value old commands could match again.
func (h *sandboxService) openResourceOperationIntent(state *resourceOperationState, m *resourceMutationRequest, freezeIntent bool, before *runtime.StatsResponse) error {
	if state.Revision >= math.MaxUint64 {
		return fmt.Errorf("resource revision for sandbox %s is exhausted", state.SandboxID)
	}
	high, unlimited := h.expectedMemoryHighBytes(before.MemoryLimitBytes)
	oldHigh := uint64(0)
	if !unlimited {
		oldHigh = high
	}
	state.Stage = resourceStageIntent
	state.FreezeOwned = freezeIntent
	state.OperationKind = m.Kind
	state.OperationDeadlineUnixMs = m.DeadlineUnixMs
	state.Expected = resourceStateLimitsFromProto(m.Expected)
	state.Target = resourceStateLimitsFromProto(m.Target)
	state.OldMemoryMaxBytes = before.MemoryLimitBytes
	state.OldMemoryHighBytes = oldHigh
	state.LastOperationID = m.OperationID
	state.LastFingerprint = m.fingerprint()
	state.LastOperationType = m.Kind
	state.LastOutcome = ""
	state.LastOutcomeMessage = ""
	state.LastCompletionUnixMs = 0
	state.Actual = nil
	state.Revision++
	state.UpdatedAtUnixMs = time.Now().UnixMilli()
	return h.saveResourceOperationState(state)
}

// advanceResourceStage persists one durable stage transition; a failure means
// the record stays at the previous stage and the operation must abort into
// its bounded cleanup instead of proceeding on unrecorded state.
func (h *sandboxService) advanceResourceStage(state *resourceOperationState, stage string) error {
	state.Stage = stage
	state.UpdatedAtUnixMs = time.Now().UnixMilli()
	return h.saveResourceOperationState(state)
}

// limitsVerified is the full post-operation truth test for the CPU/memory
// hard limits: proven readings equal to the requested values.
func limitsVerified(stats *runtime.StatsResponse, limits *runtime.ResourceLimits) bool {
	return stats.CpuLimitsKnown && stats.MemoryLimitKnown &&
		stats.CpuQuotaUsec == limits.CpuQuotaUsec && stats.CpuPeriodUsec == limits.CpuPeriodUsec &&
		stats.MemoryLimitBytes == limits.MemoryLimitBytes
}

// resourceOperationSucceeded is the complete condition both operations share:
// hard limits, the enforced memory.high, and — for the frozen path — an
// unfrozen sandbox. Any unknown or mismatched reading keeps the outcome
// partial with the revision already advanced.
func (h *sandboxService) resourceOperationSucceeded(stats *runtime.StatsResponse, target *runtime.ResourceLimits, requireUnfrozen bool) bool {
	if !limitsVerified(stats, target) || !h.memoryHighMatches(stats, target.MemoryLimitBytes) {
		return false
	}
	if requireUnfrozen && (!stats.FrozenKnown || stats.Frozen) {
		return false
	}
	return true
}

// elasticTargetWithinPolicy validates that the target limits respect the
// persisted elastic policy: explicit minimum (or initial) and ceiling. The floor is read
// from the policy the sandbox was created with, never from the request.
func (h *sandboxService) elasticTargetWithinPolicy(metadataLabels map[string]string, target *runtime.ResourceLimits) error {
	targetConfig := &runtime.StartRequest{
		Runtime: config.RuntimeNameRunsc, Labels: metadataLabels,
		Resources: map[string]float64{
			"CPU":    1000 * float64(target.CpuQuotaUsec) / float64(target.CpuPeriodUsec),
			"Memory": float64(target.MemoryLimitBytes) / (1024 * 1024),
		},
	}
	if err := validateElasticResources(targetConfig, h.config, true); err != nil {
		return errord.ToGRPCf(errord.ErrInvalidArgument, "target violates the persisted elastic policy: %v", err)
	}
	return nil
}
