// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/sirupsen/logrus"
)

const (
	resourceHealInterval    = 2 * time.Second
	resourceHealRetryDelay  = 50 * time.Millisecond
	resourceHealStartBudget = 5 * time.Second
)

// decodeResourceOperationState strictly decodes journal bytes. Damaged input
// is corrupt, never treated as a usable or missing record.
func decodeResourceOperationState(data []byte) (*resourceOperationState, resourceStateLoadResult) {
	if len(data) > resourceStateRecordLimitBytes {
		return nil, resourceStateCorrupt
	}
	var state resourceOperationState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return nil, resourceStateCorrupt
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, resourceStateCorrupt
	}
	if state.SchemaVersion != resourceStateSchemaVersion ||
		state.SandboxID == "" || state.ResourceGeneration == "" ||
		state.CgroupPath == "" || state.Revision < 1 || state.CreatedAtUnixMs <= 0 {
		return nil, resourceStateCorrupt
	}
	switch state.Stage {
	case resourceStageIdle, resourceStageIntent, resourceStageFreezeWritten, resourceStageFrozen, resourceStageApplied:
	default:
		return nil, resourceStateCorrupt
	}
	if (state.LastOperationID == "") != (state.LastFingerprint == "") {
		return nil, resourceStateCorrupt
	}
	if state.LastOperationID == "" && state.LastOperationType != "" {
		return nil, resourceStateCorrupt
	}
	if state.LastOperationID != "" && state.LastOperationType != resourceOperationGrow && state.LastOperationType != resourceOperationShrink {
		return nil, resourceStateCorrupt
	}
	return &state, resourceStateLoaded
}

// recoverResourceOperationStates runs before the daemon reports recovery
// ready. It scans the bounded per-incarnation journal and closes what can be
// closed safely:
//
//   - Only a record whose sandbox, generation label, cgroup path and cgroup
//     inode/device all still match is touched. A mismatched or missing
//     sandbox is never unfrozen and never reported as success; the record is
//     retained with a diagnostic.
//   - A record with an owned freeze intent for the verified incarnation is
//     unfrozen (bounded), read back, and closed at its advanced revision with
//     a recovered outcome. Complete is claimed only when the recorded target
//     fully verifies against the physical readback.
//   - A matching completed retirement receipt permits exact record cleanup,
//     including closed records. No cgroup is touched for a retired execution.
//   - A damaged record stays untouched and keeps the incarnation fail-closed.
//
// Nothing here proves a shrink released scheduler budget: only the physical
// facts are recorded for the controller's reconciliation.
func (h *sandboxService) recoverResourceOperationStates(ctx context.Context) error {
	open, failures := h.healOpenResourceStates(ctx)
	if failures > 0 {
		logrus.Warnf("resource operation recovery closed what it could: %d records remain open, %d attempts failed; self-heal continues",
			open, failures)
	}
	h.scheduleResourceStateHeal()
	return nil
}

// resourceIncarnationStillMatches verifies the live sandbox against the
// record: same generation label and the same physical cgroup directory.
// A mismatch means the record describes a retired incarnation.
func (h *sandboxService) resourceIncarnationStillMatches(state *resourceOperationState) (bool, error) {
	current, err := h.sandboxManager.Get(state.SandboxID)
	if err != nil {
		if errors.Is(err, errord.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	if current.Metadata == nil {
		return false, nil
	}
	if current.Metadata.GetLabels()[resourceGenerationLabel] != state.ResourceGeneration {
		return false, nil
	}
	facts, err := h.physicalResources(current.Metadata)
	if err != nil {
		return false, err
	}
	cgroup := facts.Resources[config.ResourceNameCgroup]
	if cgroup == "" || cgroup != state.CgroupPath {
		return false, nil
	}
	if h.cgroupMgr == nil {
		return false, fmt.Errorf("cgroup manager is unavailable")
	}
	identity, err := h.cgroupMgr.CgroupIdentity(cgroup)
	if err != nil {
		return false, err
	}
	if identity.Inode != state.CgroupInode || identity.Device != state.CgroupDevice {
		return false, nil
	}
	return true, nil
}

// reconcileOpenResourceState closes one open record under the sandbox's
// physical lock. An unresolvable identity is a retained diagnostic, not an
// error: the daemon simply never touches the incarnation, and the record
// keeps its operations rejected.
func (h *sandboxService) reconcileOpenResourceState(ctx context.Context, state *resourceOperationState, unfreezeBudget time.Duration) error {
	unlock, err := h.resourceLocks.acquire(ctx, state.SandboxID)
	if err != nil {
		return err
	}
	defer unlock()
	// A scanner may have waited behind a live command. Never act on its old
	// freeze ownership or write an obsolete revision after acquiring the lock.
	current, loaded, err := h.loadResourceOperationState(state.SandboxID, state.ResourceGeneration)
	if err != nil {
		return err
	}
	if loaded != resourceStateLoaded {
		return fmt.Errorf("resource state changed or became unavailable before recovery")
	}
	receipt, err := h.readRetirement(current.SandboxID, current.ResourceGeneration)
	if err != nil {
		return err
	}
	if receipt != nil && receipt.Complete {
		// A receipt for this exact generation authorizes metadata reclamation,
		// never an unfreeze or any action on a replacement's cgroup.
		return h.removeRetiredResourceOperationState(current.SandboxID, current.ResourceGeneration)
	}
	if !current.open() || current.Revision != state.Revision || current.LastOperationID != state.LastOperationID || current.LastFingerprint != state.LastFingerprint {
		return nil
	}
	state = current
	matches, err := h.resourceIncarnationStillMatches(state)
	if err != nil {
		return err
	}
	if !matches {
		logrus.Warnf("open resource operation %s for sandbox %s generation %s no longer matches the live incarnation; retained without action",
			state.LastOperationID, state.SandboxID, state.ResourceGeneration)
		return nil
	}
	if state.FreezeOwned {
		if err := h.releaseOwnedFreeze(state.SandboxID, state.CgroupPath, unfreezeBudget); err != nil {
			return fmt.Errorf("release owned freeze for sandbox %s: %w", state.SandboxID, err)
		}
	}
	stats, err := h.resourceStats(state.SandboxID)
	if err != nil {
		return fmt.Errorf("read back sandbox %s after recovery: %w", state.SandboxID, err)
	}
	outcome, message := resourceOutcomeRecovered, "reconciled after daemon restart; physical readback recorded"
	if state.Target != nil && h.resourceOperationSucceeded(stats, limitsFromState(state.Target), true) {
		outcome, message = resourceOutcomeComplete, "recovered operation verified against the physical readback"
	}
	if err := h.closeResourceOperation(state, outcome, message, snapshotResourceReadback(stats)); err != nil {
		return fmt.Errorf("record recovered outcome for sandbox %s: %w", state.SandboxID, err)
	}
	logrus.WithFields(logrus.Fields{
		"sandbox_id": state.SandboxID, "resource_generation": state.ResourceGeneration,
		"operation_id": state.LastOperationID, "outcome": outcome, "revision": state.Revision,
	}).Info("scheduler resource operation recovered")
	return nil
}

func limitsFromState(limits *resourceStateLimits) *runtime.ResourceLimits {
	if limits == nil {
		return nil
	}
	return &runtime.ResourceLimits{
		CpuQuotaUsec: limits.CpuQuotaUsec, CpuPeriodUsec: limits.CpuPeriodUsec,
		MemoryLimitBytes: limits.MemoryLimitBytes,
	}
}

// releaseOwnedFreezeForDelete releases the daemon's own open freeze intent
// for an incarnation that is about to be physically deleted. The delete is
// the authority for retiring the incarnation; leaving the cgroup frozen
// would also hang the runtime handler's control path. Failures are logged
// and never block the delete itself — the record stays for reconciliation.
// Caller holds the sandbox's physical resource lock.
func (h *sandboxService) releaseOwnedFreezeForDelete(sandboxID, generation string) {
	state, result, err := h.loadResourceOperationState(sandboxID, generation)
	if err != nil || result != resourceStateLoaded || !state.open() || !state.FreezeOwned {
		return
	}
	matches, err := h.resourceIncarnationStillMatches(state)
	if err != nil || !matches {
		logrus.WithError(err).Warnf(
			"skip pre-delete freeze release for sandbox %s generation %s: record does not match the live incarnation",
			sandboxID, generation)
		return
	}
	if err := h.releaseOwnedFreeze(sandboxID, state.CgroupPath, resourceHealStartBudget); err != nil {
		logrus.WithError(err).Warnf(
			"pre-delete freeze release for sandbox %s generation %s incomplete; continuing the delete",
			sandboxID, generation)
	}
}

// releaseOwnedFreeze clears this daemon's own freeze request and waits for
// the kernel-confirmed unfrozen state within a bounded budget.
func (h *sandboxService) releaseOwnedFreeze(sandboxID, cgroup string, budget time.Duration) error {
	if h.cgroupMgr == nil {
		return fmt.Errorf("cgroup manager is unavailable")
	}
	if err := h.cgroupMgr.WriteFreeze(cgroup, false); err != nil {
		return fmt.Errorf("write freeze=0: %w", err)
	}
	deadline := time.Now().Add(budget)
	for {
		freeze, err := h.cgroupMgr.ReadFreeze(cgroup)
		if err != nil {
			return fmt.Errorf("read freeze state: %w", err)
		}
		// The release is only proven when both the request bit and the
		// confirmed state read back unfrozen.
		if freeze.RequestKnown && !freeze.RequestFrozen && freeze.EventsKnown && !freeze.Frozen {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("sandbox %s did not confirm the released freeze request and unfrozen state within %s (request known=%t frozen=%t, events known=%t frozen=%t)",
				sandboxID, budget, freeze.RequestKnown, freeze.RequestFrozen, freeze.EventsKnown, freeze.Frozen)
		}
		time.Sleep(resourceHealRetryDelay)
	}
}

// scheduleResourceStateHeal wakes the background self-heal loop. Records that
// could not be closed keep their incarnations' operations rejected until the
// loop reconciles them; the loop never turns an RPC error into a success.
// The loop only runs with the daemon's operation lifecycle (tests drive
// recovery synchronously).
func (h *sandboxService) scheduleResourceStateHeal() {
	h.resourceStateMu.Lock()
	if h.resourceStateHeal == nil {
		h.resourceStateHeal = make(chan struct{}, 1)
	}
	if !h.resourceStateHealStarted && h.operationCtx != nil {
		h.resourceStateHealStarted = true
		h.operationWG.Add(1)
		go h.runResourceStateHeal(h.operationCtx)
	}
	ch := h.resourceStateHeal
	h.resourceStateMu.Unlock()
	select {
	case ch <- struct{}{}:
	default:
	}
}

// runResourceStateHeal retries open records until they close or the daemon
// stops. Each pass rescans the bounded journal so records left by any path
// are picked up.
func (h *sandboxService) runResourceStateHeal(ctx context.Context) {
	defer h.operationWG.Done()
	ticker := time.NewTicker(resourceHealInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-h.resourceHealWake():
		}
		open, failures := h.healOpenResourceStates(ctx)
		if failures > 0 || open > 0 {
			logrus.Debugf("resource state self-heal pass: %d open, %d failures", open, failures)
		}
	}
}

// resourceHealWake lazily creates and returns the wake channel; callers that
// only read may race with scheduleResourceStateHeal's creation, so both go
// through resourceStateMu.
func (h *sandboxService) resourceHealWake() <-chan struct{} {
	h.resourceStateMu.Lock()
	defer h.resourceStateMu.Unlock()
	if h.resourceStateHeal == nil {
		h.resourceStateHeal = make(chan struct{}, 1)
	}
	return h.resourceStateHeal
}

// healOpenResourceStates reconciles every open record once. It returns the
// number of records that remain open and the number of failed attempts.
// Damaged records count as failures: they stay untouched and fail closed.
func (h *sandboxService) healOpenResourceStates(ctx context.Context) (int, int) {
	dir := h.resourceStateDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, 0
		}
		logrus.WithError(err).Warn("scan resource state journal failed")
		return 0, 1
	}
	open, failures := 0, 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") ||
			strings.HasPrefix(entry.Name(), ".resource-state-") {
			continue
		}
		if !entry.Type().IsRegular() {
			failures++
			continue // never follow a journal symlink
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			failures++
			continue
		}
		state, result := decodeResourceOperationState(data)
		if result != resourceStateLoaded {
			logrus.Errorf("resource state record %s is damaged; its incarnation stays fail-closed", entry.Name())
			failures++
			continue
		}
		_, canonical := h.resourceStatePath(state.SandboxID, state.ResourceGeneration)
		if filepath.Base(canonical) != entry.Name() {
			logrus.Errorf("resource state record %s has a foreign filename; retained", entry.Name())
			failures++
			continue
		}
		if !state.open() {
			// Closed live records need no physical lock. A completed receipt is
			// only a scan hint here; the locked reconciliation rechecks it.
			receipt, err := h.readRetirement(state.SandboxID, state.ResourceGeneration)
			if err != nil {
				failures++
				continue
			}
			if receipt == nil || !receipt.Complete {
				continue
			}
		}
		open++
		healCtx, cancel := context.WithTimeout(ctx, resourceHealStartBudget)
		if err := h.reconcileOpenResourceState(healCtx, state, resourceHealStartBudget); err != nil {
			logrus.WithError(err).Warnf("resource state recovery for sandbox %s generation %s incomplete; will retry",
				state.SandboxID, state.ResourceGeneration)
			failures++
		} else {
			open--
		}
		cancel()
	}
	return open, failures
}
