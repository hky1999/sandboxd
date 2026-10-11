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

package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	bolt "go.etcd.io/bbolt"
)

var mountRecordsBucket = []byte("mount_records")
var mountCompletionsBucket = []byte("mount_completions")

const mountJournalLimit = 65536
const mountRecordLimit = 32768

// MountRecord stores the mount type and metadata for an OCI mount.
type MountRecord struct {
	PhysicalGeneration string `json:"physical_generation,omitempty"`
	ImageURL           string `json:"image_url"`
	MountType          string `json:"mount_type"`      // "nydus" or "oci"
	NydusImageURL      string `json:"nydus_image_url"` // actual URL used for Nydus mount (may have suffix)
	MountPoint         string `json:"mount_point"`
}

// MountStore persists OCI mount records in BoltDB.
type MountStore struct {
	db *bolt.DB
}

type storedMountRecord struct {
	SchemaVersion int          `json:"schema_version"`
	Record        *MountRecord `json:"record"`
	Integrity     string       `json:"integrity_sha256"`
}

func mountRecordIntegrity(record *MountRecord) (string, error) {
	raw, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
}

// OpenMountStore opens or creates the BoltDB file at dbPath.
func OpenMountStore(dbPath string) (*MountStore, error) {
	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open mount store: %w", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(mountRecordsBucket); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(mountCompletionsBucket)
		return err
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create bucket: %w", err)
	}
	return &MountStore{db: db}, nil
}

// Put writes a mount record keyed by imageURL.
func (s *MountStore) Put(imageURL string, record *MountRecord) error {
	return s.writeMountRecord(imageURL, record, false)
}

// Publish preserves any prior route in the same transaction as publication.
func (s *MountStore) Publish(imageURL string, record *MountRecord) error {
	return s.writeMountRecord(imageURL, record, true)
}

func (s *MountStore) writeMountRecord(imageURL string, record *MountRecord, preserveOriginal bool) error {
	if record == nil {
		return fmt.Errorf("mount record is missing")
	}
	if record.PhysicalGeneration != "" {
		if err := validateMountRoute(imageURL, record); err != nil {
			return err
		}
	}
	integrity, err := mountRecordIntegrity(record)
	if err != nil {
		return err
	}
	data, err := json.Marshal(storedMountRecord{1, record, integrity})
	if err != nil {
		return fmt.Errorf("failed to marshal record: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if len(data) > mountRecordLimit {
			return fmt.Errorf("image mount route exceeds its byte limit")
		}
		if record.PhysicalGeneration != "" && tx.Bucket(mountCompletionsBucket).Get(mountCompletionKey(imageURL, record.PhysicalGeneration)) != nil {
			return fmt.Errorf("completed physical mount generation cannot be republished")
		}
		if preserveOriginal {
			if raw := tx.Bucket(mountRecordsBucket).Get([]byte(imageURL)); raw != nil {
				prior, err := decodeMountRecord(raw)
				if err != nil || *prior != *record {
					return fmt.Errorf("original image mount route changed")
				}
				return nil
			}
		}
		if tx.Bucket(mountRecordsBucket).Get([]byte(imageURL)) == nil && tx.Bucket(mountRecordsBucket).Stats().KeyN+tx.Bucket(mountCompletionsBucket).Stats().KeyN >= mountJournalLimit {
			return fmt.Errorf("image mount journal is full")
		}
		return tx.Bucket(mountRecordsBucket).Put([]byte(imageURL), data)
	})
}

// Get retrieves a mount record by imageURL. Returns nil, nil if not found.
func (s *MountStore) Get(imageURL string) (*MountRecord, error) {
	var record *MountRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(mountRecordsBucket).Get([]byte(imageURL))
		if v == nil {
			return nil
		}
		var err error
		record, err = decodeMountRecord(v)
		return err
	})
	return record, err
}

// Delete removes a mount record by imageURL.
func (s *MountStore) Delete(imageURL string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(mountRecordsBucket).Delete([]byte(imageURL))
	})
}

// DeleteIfRecord never removes a changed replacement record. Missing state is
// unknown here; only the original caller's durable completion can prove replay.
func (s *MountStore) DeleteIfRecord(imageURL string, expected *MountRecord) error {
	if expected == nil || expected.ImageURL != imageURL {
		return fmt.Errorf("original mount route is required")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(mountRecordsBucket)
		raw := bucket.Get([]byte(imageURL))
		if raw == nil {
			return fmt.Errorf("original mount route is missing")
		}
		current, err := decodeMountRecord(raw)
		if err != nil {
			return fmt.Errorf("original mount route is unreadable")
		}
		if *current != *expected {
			return fmt.Errorf("original mount route changed")
		}
		if expected.PhysicalGeneration != "" {
			if err := validateMountRoute(imageURL, expected); err != nil {
				return err
			}
			if !validMountGeneration(expected.PhysicalGeneration) {
				return fmt.Errorf("invalid original mount generation")
			}
			completed := tx.Bucket(mountCompletionsBucket)
			key := mountCompletionKey(imageURL, expected.PhysicalGeneration)
			if prior := completed.Get(key); prior != nil && !bytes.Equal(prior, raw) {
				return fmt.Errorf("original mount completion changed")
			}
			if err := completed.Put(key, raw); err != nil {
				return err
			}
		}
		return bucket.Delete([]byte(imageURL))
	})
}

func validMountGeneration(g string) bool {
	b, err := hex.DecodeString(g)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == g
}

func mountCompletionKey(imageURL, generation string) []byte {
	h := sha256.Sum256([]byte(imageURL + "\x00" + generation))
	return h[:]
}

func (s *MountStore) Completed(imageURL, generation string) (*MountRecord, error) {
	if !validMountGeneration(generation) {
		return nil, fmt.Errorf("invalid original mount generation")
	}
	var result *MountRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(mountCompletionsBucket).Get(mountCompletionKey(imageURL, generation))
		if raw == nil {
			return nil
		}
		var err error
		result, err = decodeMountRecord(raw)
		if err != nil {
			return err
		}
		if result.ImageURL != imageURL || result.PhysicalGeneration != generation {
			return fmt.Errorf("original mount completion identity changed")
		}
		return validateMountRoute(imageURL, result)
	})
	return result, err
}

func decodeMountRecord(raw []byte) (*MountRecord, error) {
	if len(raw) > mountRecordLimit {
		return nil, fmt.Errorf("mount record exceeds byte limit")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueMountJSONValue(d, 0); err != nil {
		return nil, fmt.Errorf("mount record JSON is ambiguous")
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("mount record contains trailing data")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, fmt.Errorf("mount record fields are invalid")
	}
	var record *MountRecord
	if _, hasSchema := fields["schema_version"]; hasSchema {
		if err := exactMountJSONFields(fields, "schema_version", "record", "integrity_sha256"); err != nil {
			return nil, err
		}
		var stored storedMountRecord
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&stored); err != nil || stored.SchemaVersion != 1 || stored.Record == nil {
			return nil, fmt.Errorf("mount record schema is invalid")
		}
		var source map[string]json.RawMessage
		if err := json.Unmarshal(fields["record"], &source); err != nil || source == nil {
			return nil, fmt.Errorf("mount record is missing")
		}
		if err := exactMountJSONFields(source, "physical_generation", "image_url", "mount_type", "nydus_image_url", "mount_point"); err != nil {
			return nil, err
		}
		integrity, err := mountRecordIntegrity(stored.Record)
		if err != nil || stored.Integrity != integrity {
			return nil, fmt.Errorf("mount record integrity changed")
		}
		record = stored.Record
	} else {
		// Historical routes have no original physical generation. Never upgrade
		// an unsealed generation claim into an original mount or completion.
		if err := exactMountJSONFields(fields, "image_url", "mount_type", "nydus_image_url", "mount_point"); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &record); err != nil || record == nil {
			return nil, fmt.Errorf("legacy mount record is invalid")
		}
	}
	if record.PhysicalGeneration != "" && !validMountGeneration(record.PhysicalGeneration) {
		return nil, fmt.Errorf("mount record fields are invalid")
	}
	return record, nil
}

func exactMountJSONFields(fields map[string]json.RawMessage, allowed ...string) error {
	known := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		known[key] = true
	}
	for key := range fields {
		if !known[key] {
			return fmt.Errorf("unknown mount record field")
		}
	}
	return nil
}

func uniqueMountJSONValue(d *json.Decoder, depth int) error {
	if depth > 8 {
		return fmt.Errorf("mount record JSON depth exceeded")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for d.More() {
			token, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok || seen[key] {
				return fmt.Errorf("duplicate mount record field")
			}
			seen[key] = true
			if err := uniqueMountJSONValue(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := uniqueMountJSONValue(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("invalid mount record JSON")
	}
	_, err = d.Token()
	return err
}

// Close closes the underlying BoltDB.
func (s *MountStore) Close() error {
	return s.db.Close()
}
