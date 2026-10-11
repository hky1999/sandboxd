// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
)

var mountOperationsBucket = []byte("mount_operations")

// MountOperationQuery identifies an original request, never a current URL.
type MountOperationQuery struct {
	OperationID        string `json:"operation_id"`
	RequestFingerprint string `json:"request_fingerprint"`
}

// An absent or unresolved observation is not proof that dispatch never happened.
type MountOperationResult struct {
	OperationID        string `json:"operation_id"`
	RequestFingerprint string `json:"request_fingerprint"`
	Kind               string `json:"kind"`
	State              string `json:"state"`
	PhysicalGeneration string `json:"physical_generation"`
	MountPoint         string `json:"mount_point"`
}

type mountOperationRecord struct {
	OperationID        string `json:"operation_id"`
	RequestFingerprint string `json:"request_fingerprint"`
	Kind               string `json:"kind"`
	Phase              string `json:"phase"`
	PhysicalGeneration string `json:"physical_generation"`
	DaemonID           string `json:"daemon_id"`
	MountPoint         string `json:"mount_point"`
	ImageURL           string `json:"image_url"`
	NydusImageURL      string `json:"nydus_image_url"`
}

type storedMountOperation struct {
	SchemaVersion int                   `json:"schema_version"`
	Record        *mountOperationRecord `json:"record"`
	Integrity     string                `json:"integrity_sha256"`
}

// MountRequestFingerprint includes the full original request, including a hash
// of credentials. Raw credentials are never stored in the operation journal.
// A recovery selector does not change the original request's fingerprint.
func MountRequestFingerprint(request any) (string, error) {
	var kind string
	var normalized any
	switch req := request.(type) {
	case *OSSMountRequest:
		if req == nil {
			return "", fmt.Errorf("mount source is required")
		}
		copy := *req
		copy.OperationID, copy.PhysicalGeneration = "", ""
		kind, normalized = "oss", copy
	case *NydusMountRequest:
		if req == nil {
			return "", fmt.Errorf("mount source is required")
		}
		copy := *req
		copy.OperationID, copy.PhysicalGeneration = "", ""
		kind, normalized = "nydus", copy
	case *OCIMountRequest:
		if req == nil {
			return "", fmt.Errorf("mount source is required")
		}
		copy := *req
		copy.OperationID, copy.PhysicalGeneration = "", ""
		kind, normalized = "oci", copy
	default:
		return "", fmt.Errorf("unsupported mount request")
	}
	raw, err := json.Marshal([]any{"akernel.mount-operation.v1", kind, normalized})
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
}

func mountJournalEntries(tx *bolt.Tx) int {
	return tx.Bucket(mountRecordsBucket).Stats().KeyN + tx.Bucket(mountCompletionsBucket).Stats().KeyN + tx.Bucket(mountOperationsBucket).Stats().KeyN
}

func validateMountOperation(r *mountOperationRecord) error {
	if r == nil || !validMountGeneration(r.OperationID) || !validMountGeneration(r.RequestFingerprint) {
		return fmt.Errorf("mount operation identity is invalid")
	}
	if r.Kind != "oss" && r.Kind != "nydus" && r.Kind != "oci" {
		return fmt.Errorf("mount operation kind is invalid")
	}
	if (r.Kind == "oci") != (r.ImageURL != "") {
		return fmt.Errorf("mount operation facade is invalid")
	}
	if r.Phase == "intent" {
		if r.PhysicalGeneration != "" || r.DaemonID != "" || r.MountPoint != "" || r.NydusImageURL != "" {
			return fmt.Errorf("unbound mount operation contains physical claims")
		}
		return nil
	}
	if r.Phase != "bound" && r.Phase != "ready" {
		return fmt.Errorf("mount operation phase is invalid")
	}
	if !validMountGeneration(r.PhysicalGeneration) || !validMountGeneration(r.DaemonID) || !filepath.IsAbs(r.MountPoint) || filepath.Clean(r.MountPoint) != r.MountPoint {
		return fmt.Errorf("mount operation binding is invalid")
	}
	if r.Kind == "oss" && r.NydusImageURL != "" || r.Kind != "oss" && r.NydusImageURL == "" {
		return fmt.Errorf("mount operation backend is invalid")
	}
	if r.Kind != "oss" && r.DaemonID != generateNydusID(r.NydusImageURL) {
		return fmt.Errorf("mount operation backend identity changed")
	}
	return nil
}

func encodeMountOperation(r *mountOperationRecord) ([]byte, error) {
	if err := validateMountOperation(r); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(raw)
	sealed, err := json.Marshal(storedMountOperation{1, r, hex.EncodeToString(h[:])})
	if err != nil {
		return nil, err
	}
	if len(sealed) > mountRecordLimit {
		return nil, fmt.Errorf("mount operation exceeds byte limit")
	}
	return sealed, nil
}

func decodeMountOperation(raw []byte) (*mountOperationRecord, error) {
	if len(raw) > mountRecordLimit {
		return nil, fmt.Errorf("mount operation exceeds byte limit")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueMountJSONValue(d, 0); err != nil {
		return nil, fmt.Errorf("mount operation JSON is ambiguous")
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("mount operation contains trailing data")
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil || len(envelope) != 3 {
		return nil, fmt.Errorf("mount operation envelope is invalid")
	}
	if err := exactMountJSONFields(envelope, "schema_version", "record", "integrity_sha256"); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(envelope["record"], &fields); err != nil || len(fields) != 9 {
		return nil, fmt.Errorf("mount operation fields are incomplete")
	}
	if err := exactMountJSONFields(fields, "operation_id", "request_fingerprint", "kind", "phase", "physical_generation", "daemon_id", "mount_point", "image_url", "nydus_image_url"); err != nil {
		return nil, err
	}
	var stored storedMountOperation
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&stored); err != nil || stored.SchemaVersion != 1 || stored.Record == nil {
		return nil, fmt.Errorf("mount operation schema is invalid")
	}
	if err := validateMountOperation(stored.Record); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(stored.Record)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(encoded)
	if stored.Integrity != hex.EncodeToString(h[:]) {
		return nil, fmt.Errorf("mount operation integrity changed")
	}
	return stored.Record, nil
}

func readMountOperation(tx *bolt.Tx, id string) (*mountOperationRecord, error) {
	raw := tx.Bucket(mountOperationsBucket).Get([]byte(id))
	if raw == nil {
		return nil, nil
	}
	r, err := decodeMountOperation(raw)
	if err != nil {
		return nil, err
	}
	if r.OperationID != id {
		return nil, fmt.Errorf("mount operation key changed")
	}
	return r, nil
}

func (s *MountStore) beginMountOperation(intent *mountOperationRecord) (*mountOperationRecord, bool, error) {
	if intent == nil || intent.Phase != "intent" {
		return nil, false, fmt.Errorf("original mount intent is required")
	}
	raw, err := encodeMountOperation(intent)
	if err != nil {
		return nil, false, err
	}
	var result *mountOperationRecord
	fresh := false
	err = s.db.Update(func(tx *bolt.Tx) error {
		prior, err := readMountOperation(tx, intent.OperationID)
		if err != nil {
			return err
		}
		if prior != nil {
			if prior.RequestFingerprint != intent.RequestFingerprint || prior.Kind != intent.Kind || prior.ImageURL != intent.ImageURL {
				return fmt.Errorf("mount operation request changed")
			}
			result = prior
			return nil
		}
		if mountJournalEntries(tx) >= mountJournalLimit {
			return fmt.Errorf("image mount journal is full")
		}
		if err := tx.Bucket(mountOperationsBucket).Put([]byte(intent.OperationID), raw); err != nil {
			return err
		}
		copy := *intent
		result, fresh = &copy, true
		return nil
	})
	return result, fresh, err
}

// Only the original dispatcher may attach the physical generation, before exec.
func (s *MountStore) publishMountBinding(binding *mountOperationRecord) error {
	raw, err := encodeMountOperation(binding)
	if err != nil {
		return err
	}
	if binding.Phase != "bound" {
		return fmt.Errorf("original mount binding is required")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		prior, err := readMountOperation(tx, binding.OperationID)
		if err != nil {
			return err
		}
		if prior == nil || prior.RequestFingerprint != binding.RequestFingerprint || prior.Kind != binding.Kind || prior.ImageURL != binding.ImageURL {
			return fmt.Errorf("original mount intent changed")
		}
		if prior.Phase != "intent" {
			copy := *prior
			copy.Phase = "bound"
			if copy != *binding {
				return fmt.Errorf("original mount binding changed")
			}
			return nil
		}
		return tx.Bucket(mountOperationsBucket).Put([]byte(binding.OperationID), raw)
	})
}

func (s *MountStore) getMountOperation(query *MountOperationQuery) (*mountOperationRecord, error) {
	if query == nil || !validMountGeneration(query.OperationID) || !validMountGeneration(query.RequestFingerprint) {
		return nil, fmt.Errorf("original mount query identity is required")
	}
	var result *mountOperationRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		result, err = readMountOperation(tx, query.OperationID)
		if err != nil {
			return err
		}
		if result != nil && result.RequestFingerprint != query.RequestFingerprint {
			return fmt.Errorf("mount operation request changed")
		}
		return nil
	})
	return result, err
}

func (s *MountStore) confirmMountOperation(query *MountOperationQuery, generation, target string) error {
	if query == nil || !validMountGeneration(query.OperationID) || !validMountGeneration(query.RequestFingerprint) {
		return fmt.Errorf("original mount confirmation is required")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		r, err := readMountOperation(tx, query.OperationID)
		if err != nil {
			return err
		}
		if r == nil || r.Phase == "intent" || r.RequestFingerprint != query.RequestFingerprint || r.PhysicalGeneration != generation || r.MountPoint != target {
			return fmt.Errorf("original mount confirmation changed")
		}
		r.Phase = "ready"
		raw, err := encodeMountOperation(r)
		if err != nil {
			return err
		}
		return tx.Bucket(mountOperationsBucket).Put([]byte(r.OperationID), raw)
	})
}
