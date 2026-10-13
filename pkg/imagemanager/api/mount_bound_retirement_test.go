// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

func TestPreparedBoundMountRetirementSurvivesJournalReopen(t *testing.T) {
	w, request, original, manager := cleanupMountOperationFixture(t, "oss", "launching", false)
	original.PreparationProtocol = 1
	raw, err := encodeMountOperation(original)
	require.NoError(t, err)
	require.NoError(t, w.mountStore.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(mountOperationsBucket).Put([]byte(original.OperationID), raw)
	}))
	query := &MountOperationQuery{original.OperationID, original.RequestFingerprint}
	result, err := w.RetireMountOperation(&MountOperationRetirement{
		OperationID: original.OperationID, RequestFingerprint: original.RequestFingerprint, Kind: original.Kind,
	})
	require.NoError(t, err)
	require.Equal(t, "release_pending", result.State)
	reopenMountOperationWorker(t, w)
	stored, err := w.mountStore.getMountOperation(query)
	require.NoError(t, err)
	require.True(t, stored.RetirementRequested)
	withoutFence := *stored
	withoutFence.RetirementRequested = false
	require.Equal(t, *original, withoutFence)
	readback, err := QueryOriginalMountOperation(w, request, original.OperationID, "oss", true)
	require.NoError(t, err)
	require.Equal(t, result, readback)
	_, err = QueryOriginalMountOperation(w, request, original.OperationID, "oss", false)
	require.Error(t, err)
	require.Zero(t, manager.activations)
}

func TestMountOperationOptionalFieldsRemainStrict(t *testing.T) {
	_, _, original := mountOperationFixture(t)
	for _, protocol := range []int{0, 1} {
		for _, retirement := range []bool{false, true} {
			record := *original
			record.PreparationProtocol = protocol
			record.RetirementRequested = retirement
			raw, err := encodeMountOperation(&record)
			require.NoError(t, err)
			decoded, err := decodeMountOperation(raw)
			require.NoError(t, err)
			require.Equal(t, &record, decoded)
			var envelope map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(raw, &envelope))
			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(envelope["record"], &fields))
			fields["foreign_authority"] = json.RawMessage("true")
			envelope["record"], err = json.Marshal(fields)
			require.NoError(t, err)
			altered, err := json.Marshal(envelope)
			require.NoError(t, err)
			_, err = decodeMountOperation(altered)
			require.Error(t, err)
		}
	}
}

func TestBoundUnreadyMountRetirementGrantsCleanupWithoutActivation(t *testing.T) {
	w, request, original, manager := cleanupMountOperationFixture(t, "oss", "launching", false)
	_, err := QueryOriginalMountOperation(w, request, original.OperationID, "oss", false)
	require.Error(t, err)
	retirement := &MountOperationRetirement{OperationID: original.OperationID, RequestFingerprint: original.RequestFingerprint, Kind: original.Kind}
	result, err := w.RetireMountOperation(retirement)
	require.NoError(t, err)
	require.Equal(t, "release_pending", result.State)
	require.Equal(t, original.PhysicalGeneration, result.PhysicalGeneration)
	require.Equal(t, original.MountPoint, result.MountPoint)
	stored, err := w.mountStore.getMountOperation(&MountOperationQuery{original.OperationID, original.RequestFingerprint})
	require.NoError(t, err)
	require.True(t, stored.RetirementRequested)
	withoutFence := *stored
	withoutFence.RetirementRequested = false
	require.Equal(t, *original, withoutFence, "retirement must preserve every original binding")
	require.Error(t, w.mountStore.publishMountBinding(original), "late dispatch cannot reuse a fenced allocation")
	require.Error(t, w.mountStore.confirmMountOperation(&MountOperationQuery{original.OperationID, original.RequestFingerprint}, original.PhysicalGeneration, original.MountPoint), "late confirmation cannot publish ready")
	_, err = QueryOriginalMountOperation(w, request, original.OperationID, "oss", false)
	require.Error(t, err, "a cleanup fence never creates a successful acquisition")
	readback, err := QueryOriginalMountOperation(w, request, original.OperationID, "oss", true)
	require.NoError(t, err)
	require.Equal(t, result, readback)
	info, err := w.MountOSS(request.(*OSSMountRequest))
	require.NoError(t, err)
	require.True(t, info.ReleasePending)
	require.False(t, info.Released)
	require.Zero(t, manager.activations)
	second, err := w.RetireMountOperation(retirement)
	require.NoError(t, err)
	require.Equal(t, result, second)
}

func TestBoundMountRetirementRejectsDifferentFingerprintWithoutFence(t *testing.T) {
	w, _, original, manager := cleanupMountOperationFixture(t, "oss", "launching", false)
	_, err := w.RetireMountOperation(&MountOperationRetirement{OperationID: original.OperationID,
		RequestFingerprint: strings.Repeat("b", 64), Kind: original.Kind})
	require.Error(t, err)
	stored, err := w.mountStore.getMountOperation(&MountOperationQuery{original.OperationID, original.RequestFingerprint})
	require.NoError(t, err)
	require.Equal(t, original, stored)
	require.Zero(t, manager.activations)
}

func TestUnboundMountCannotBorrowBoundRetirementFence(t *testing.T) {
	record := &mountOperationRecord{OperationID: strings.Repeat("a", 64), RequestFingerprint: strings.Repeat("b", 64),
		Kind: "oss", Phase: "intent", PreparationProtocol: 1, RetirementRequested: true}
	require.Error(t, validateMountOperation(record))
	record.Phase = "not_allocated"
	require.Error(t, validateMountOperation(record))
}
