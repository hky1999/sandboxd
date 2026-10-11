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
	"encoding/json"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

var mountRecordsBucket = []byte("mount_records")

// MountRecord stores the mount type and metadata for an OCI mount.
type MountRecord struct {
	ImageURL      string `json:"image_url"`
	MountType     string `json:"mount_type"`      // "nydus" or "oci"
	NydusImageURL string `json:"nydus_image_url"` // actual URL used for Nydus mount (may have suffix)
	MountPoint    string `json:"mount_point"`
}

// MountStore persists OCI mount records in BoltDB.
type MountStore struct {
	db *bolt.DB
}

// OpenMountStore opens or creates the BoltDB file at dbPath.
func OpenMountStore(dbPath string) (*MountStore, error) {
	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open mount store: %w", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(mountRecordsBucket)
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
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal record: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
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
		record = &MountRecord{}
		return json.Unmarshal(v, record)
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
		var current MountRecord
		if err := json.Unmarshal(raw, &current); err != nil {
			return fmt.Errorf("original mount route is unreadable")
		}
		if current != *expected {
			return fmt.Errorf("original mount route changed")
		}
		return bucket.Delete([]byte(imageURL))
	})
}

// Close closes the underlying BoltDB.
func (s *MountStore) Close() error {
	return s.db.Close()
}
