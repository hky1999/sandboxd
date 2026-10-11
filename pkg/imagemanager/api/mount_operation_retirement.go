// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/distillfs"
	bolt "go.etcd.io/bbolt"
)

// Only an explicitly requested retirement can create a terminal allocation
// fence. A query or an empty inventory alone cannot create this proof.
type MountOperationRetirement struct {
	OperationID        string `json:"operation_id"`
	RequestFingerprint string `json:"request_fingerprint"`
	Kind               string `json:"kind"`
	ImageURL           string `json:"image_url"`
}

type MountOperationRetirementService interface {
	RetireMountOperation(*MountOperationRetirement) (*MountOperationResult, error)
}

func validateMountRetirement(req *MountOperationRetirement) error {
	if req == nil {
		return fmt.Errorf("original mount retirement is required")
	}
	return validateMountOperation(&mountOperationRecord{OperationID: req.OperationID, RequestFingerprint: req.RequestFingerprint, Kind: req.Kind, ImageURL: req.ImageURL, Phase: "intent"})
}

func (w *HttpWorker) tryMountOperationLock(id string) (func(), bool) {
	w.operationLocksMu.Lock()
	if w.operationLocks == nil {
		w.operationLocks = make(map[string]*mountRouteLock)
	}
	entry := w.operationLocks[id]
	if entry == nil {
		entry = &mountRouteLock{}
		w.operationLocks[id] = entry
	}
	entry.refs++
	w.operationLocksMu.Unlock()
	forget := func() {
		w.operationLocksMu.Lock()
		defer w.operationLocksMu.Unlock()
		entry.refs--
		if entry.refs == 0 {
			delete(w.operationLocks, id)
		}
	}
	if !entry.mu.TryLock() {
		forget()
		return nil, false
	}
	return func() { entry.mu.Unlock(); forget() }, true
}

func (s *MountStore) closeUnallocatedMount(req *MountOperationRetirement, expected *mountOperationRecord) error {
	if err := validateMountRetirement(req); err != nil {
		return err
	}
	closed := &mountOperationRecord{OperationID: req.OperationID, RequestFingerprint: req.RequestFingerprint, Kind: req.Kind, ImageURL: req.ImageURL, PreparationProtocol: 1, Phase: "not_allocated"}
	raw, err := encodeMountOperation(closed)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		current, err := readMountOperation(tx, req.OperationID)
		if err != nil {
			return err
		}
		if current != nil && *current == *closed {
			return nil
		}
		if expected == nil {
			if current != nil {
				return fmt.Errorf("original allocation intent appeared before closure")
			}
			if mountJournalEntries(tx) >= mountJournalLimit {
				return fmt.Errorf("image mount journal is full")
			}
		} else if current == nil || *current != *expected || current.Phase != "intent" || current.PreparationProtocol != 1 {
			return fmt.Errorf("original allocation intent changed or has no durable preparation protocol")
		}
		return tx.Bucket(mountOperationsBucket).Put([]byte(req.OperationID), raw)
	})
}

func (w *HttpWorker) RetireMountOperation(req *MountOperationRetirement) (*MountOperationResult, error) {
	release, err := w.admit()
	if err != nil {
		return nil, err
	}
	defer release()
	if err := validateMountRetirement(req); err != nil {
		return nil, err
	}
	if w.mountStore == nil {
		return nil, fmt.Errorf("mount retirement requires its persistent journal")
	}
	unlock, acquired := w.tryMountOperationLock(req.OperationID)
	if !acquired {
		return nil, fmt.Errorf("original mount producer is still active")
	}
	defer unlock()
	query := &MountOperationQuery{OperationID: req.OperationID, RequestFingerprint: req.RequestFingerprint}
	r, err := w.mountStore.getMountOperation(query)
	if err != nil {
		return nil, err
	}
	if r != nil && (r.Kind != req.Kind || r.ImageURL != req.ImageURL) {
		return nil, fmt.Errorf("original mount retirement source changed")
	}
	if r != nil && r.Phase != "intent" {
		return w.inspectMountOperation(r) // Exact terminal replay never touches a replacement.
	}
	if r != nil && r.PreparationProtocol != 1 {
		return nil, fmt.Errorf("legacy original mount intent is unresolved")
	}
	manager, ok := w.mgr.(distillfs.PreparationRetirementManager)
	if !ok {
		return nil, fmt.Errorf("mount retirement requires authoritative preparation inventory")
	}
	if r != nil {
		bound, err := w.findOriginalPreparation(r)
		if err != nil {
			return nil, err
		}
		if bound != nil {
			if err := w.mountStore.publishMountBinding(bound); err != nil {
				return nil, err
			}
			return w.inspectMountOperation(bound) // Actual allocation remains owned and pending cleanup.
		}
	}
	owner := distillfs.PreparationOwner{OperationID: req.OperationID, RequestFingerprint: req.RequestFingerprint}
	if err := manager.ConfirmNoPreparation(owner); err != nil {
		return nil, err
	}
	// All native managed effects require the original binding to succeed. The
	// operation lock excludes the original producer; this durable tombstone makes
	// later begin/bind calls fail. Native absence alone was never the authority.
	if err := w.mountStore.closeUnallocatedMount(req, r); err != nil {
		return nil, err
	}
	closed, err := w.mountStore.getMountOperation(query)
	if err != nil || closed == nil || closed.Phase != "not_allocated" {
		return nil, fmt.Errorf("original no-allocation closure is not confirmed")
	}
	return w.inspectMountOperation(closed)
}
