// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	bolt "go.etcd.io/bbolt"
)

// resetStateIfPodChanged retains its historical name, but never resets state.
// The hostname stamp permits normal same-container restart; it does not prove
// namespace or physical resource ownership. Foreign or missing ownership with
// existing state requires explicit recovery rather than deletion or adoption.
func resetStateIfPodChanged(storeDir, rootDir, imageManagerRoot string) error {
	current, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("get hostname: %w", err)
	}
	stampPath := filepath.Join(storeDir, ".pod_host")
	if info, err := os.Lstat(stampPath); err == nil {
		if !info.Mode().IsRegular() || info.Size() > 255 {
			return fmt.Errorf("invalid startup owner stamp; persisted state retained")
		}
		stored, readErr := os.ReadFile(stampPath)
		after, statErr := os.Lstat(stampPath)
		if readErr != nil || statErr != nil || !os.SameFile(info, after) || string(stored) != current {
			return fmt.Errorf("startup owner stamp unavailable, replaced or foreign; persisted state retained")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read startup owner stamp: %w", err)
	}
	for _, path := range []string{storeDir, rootDir, imageManagerRoot} {
		if path == "" {
			continue
		}
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect unstamped state directory: %w", err)
		}
		if !info.IsDir() {
			return fmt.Errorf("unstamped state path is not a directory; state retained")
		}
		dir, err := os.Open(path)
		if err != nil {
			return err
		}
		_, readErr := dir.Readdirnames(1)
		closeErr := dir.Close()
		if readErr != io.EOF || closeErr != nil {
			return fmt.Errorf("startup owner stamp missing for nonempty or unreadable state directory; state retained")
		}
	}
	if err := os.MkdirAll(storeDir, 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(storeDir, ".startup-owner-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.WriteString(current); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporary.Name(), stampPath); err != nil {
		return fmt.Errorf("publish startup owner stamp without replacement: %w", err)
	}
	if err := os.Remove(temporary.Name()); err != nil {
		return err
	}
	dir, err := os.Open(storeDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// Validation is read-only and bounded. A resource decoding error must not
// discard unrelated leases, pending operations or evidence for reconciliation.
func resetMetadataIfResourceStateIncompatible(storePath string) error {
	info, err := os.Lstat(storePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect metadata database: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("metadata database is not a regular file; original state retained")
	}
	db, err := bolt.Open(storePath, 0600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		return fmt.Errorf("open original metadata read-only: %w", err)
	}
	defer db.Close()
	return db.View(func(tx *bolt.Tx) error {
		for _, key := range []string{config.CgroupBucket, config.BridgeIpBucket} {
			bucket := tx.Bucket([]byte(key))
			if bucket == nil {
				continue
			}
			data := bucket.Get([]byte(key))
			if data == nil {
				continue
			}
			var state struct {
				Items []string `json:"items"`
			}
			if trimmed := bytes.TrimSpace(data); len(trimmed) == 0 || trimmed[0] != '{' {
				return fmt.Errorf("incompatible metadata bucket %s; original database retained", key)
			}
			if err := json.Unmarshal(data, &state); err != nil {
				return fmt.Errorf("incompatible metadata bucket %s; original database retained: %w", key, err)
			}
		}
		return nil
	})
}
