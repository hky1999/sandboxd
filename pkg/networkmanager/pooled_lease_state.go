// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package networkmanager

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
	"github.com/inclusionAI/sandboxd/pkg/errord"
)

const pooledLeaseJournalLimit = 65536

func pooledLeaseFingerprint(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// Caller holds storeMu. The proposed completion is not published in memory
// until the active-set removal and this receipt are committed together.
func (m *InterfaceManager) proposedPooledCompletions(id string) (map[string]string, error) {
	completed := make(map[string]string, len(m.completedPooledLeases)+1)
	for lease, fingerprint := range m.completedPooledLeases {
		completed[lease] = fingerprint
	}
	if id == "" {
		return completed, nil
	}
	resource, err := NewNetResource(id)
	if err != nil {
		return nil, err
	}
	if resource.LeaseID != "" {
		if m.db == nil {
			return nil, fmt.Errorf("network lease store is unavailable: %w", errord.ErrUnavailable)
		}
		completed[resource.LeaseID] = pooledLeaseFingerprint(id)
	}
	return completed, nil
}

// A missing active entry does not prove that an owned lease was released.
// Only the exact original completion can replay without kernel operations.
func (m *InterfaceManager) inactivePooledLeaseResult(id string) error {
	resource, err := NewNetResource(id)
	if err != nil {
		return err
	}
	if resource.LeaseID == "" {
		return nil // Existing unowned resources retain legacy no-op semantics.
	}
	m.storeMu.Lock()
	defer m.storeMu.Unlock()
	if m.completedPooledLeases[resource.LeaseID] != pooledLeaseFingerprint(id) {
		return fmt.Errorf("network lease has no matching completed release: %w", errord.ErrFailedPrecondition)
	}
	return nil
}

func validatePooledLeaseState(state storedInterfaceIDs) error {
	if (state.SchemaVersion != 0 && state.SchemaVersion != 2) ||
		(state.SchemaVersion == 0 && len(state.CompletedPooledLeases) != 0) {
		return fmt.Errorf("network lease journal schema is invalid: %w", errord.ErrFailedPrecondition)
	}
	if len(state.Items)+len(state.CompletedPooledLeases) > pooledLeaseJournalLimit {
		return fmt.Errorf("network lease journal is full: %w", errord.ErrResourceExhausted)
	}
	seen := make(map[string]bool, len(state.Items))
	for _, id := range state.Items {
		resource, err := NewNetResource(id)
		if err != nil {
			return fmt.Errorf("network lease journal contains invalid facts: %w", err)
		}
		if resource.LeaseID == "" {
			continue
		}
		if state.SchemaVersion != 2 {
			return fmt.Errorf("owned network lease requires the current journal schema: %w", errord.ErrFailedPrecondition)
		}
		lease, err := uuid.Parse(resource.LeaseID)
		if err != nil || lease == uuid.Nil || lease.String() != resource.LeaseID ||
			seen[resource.LeaseID] || state.CompletedPooledLeases[resource.LeaseID] != "" {
			return fmt.Errorf("network lease journal ownership is invalid: %w", errord.ErrFailedPrecondition)
		}
		seen[resource.LeaseID] = true
	}
	for leaseID, fingerprint := range state.CompletedPooledLeases {
		lease, err := uuid.Parse(leaseID)
		bytes, decodeErr := hex.DecodeString(fingerprint)
		if err != nil || lease == uuid.Nil || lease.String() != leaseID || decodeErr != nil ||
			len(bytes) != sha256.Size || hex.EncodeToString(bytes) != fingerprint {
			return fmt.Errorf("network lease journal completion is invalid: %w", errord.ErrFailedPrecondition)
		}
	}
	return nil
}
