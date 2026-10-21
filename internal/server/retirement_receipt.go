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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// resourceGenerationLabel is the daemon-owned physical incarnation identity.
// Start assigns it; a caller-supplied value under the same key is replaced,
// never honored.
const resourceGenerationLabel = "akernel.scheduler/resource-generation"

// retirementReceiptLimit bounds the journal so an unreachable reconciliation
// path cannot grow it without bound.
const retirementReceiptLimit = 65536

type retirementReceipt struct {
	Version    int    `json:"version"`
	SandboxID  string `json:"sandbox_id"`
	Generation string `json:"generation"`
	Complete   bool   `json:"complete"`
}

func syncRetirementDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (h *sandboxService) retirementPath(id, generation string) (string, string) {
	key, _ := json.Marshal([2]string{id, generation})
	digest := sha256.Sum256(key)
	dir := filepath.Join(h.config.RootDir, "scheduler-retirements")
	return dir, filepath.Join(dir, hex.EncodeToString(digest[:])+".json")
}

// Caller holds the sandbox's physical resource lock. The directory is daemon
// state, never a sandbox-mounted path. Missing/pending records prove no
// completion.
func (h *sandboxService) readRetirement(id, generation string) (*retirementReceipt, error) {
	dir, path := h.retirementPath(id, generation)
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 4096 {
		return nil, fmt.Errorf("invalid retirement record size/type")
	}
	var record retirementReceipt
	decoder := json.NewDecoder(io.LimitReader(f, 4097))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("trailing retirement record content")
	}
	if record.Version != 1 || record.SandboxID != id || record.Generation != generation {
		return nil, fmt.Errorf("retirement identity mismatch")
	}
	// Retry a directory sync if a prior rename succeeded but its sync failed.
	if record.Complete {
		if err := syncRetirementDirectory(dir); err != nil {
			return nil, err
		}
	}
	return &record, nil
}

func (h *sandboxService) writeRetirement(id, generation string, complete bool) error {
	h.retirementMu.Lock()
	defer h.retirementMu.Unlock()
	dir, path := h.retirementPath(id, generation)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := syncRetirementDirectory(h.config.RootDir); err != nil {
		return err
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		if len(entries) >= retirementReceiptLimit {
			return fmt.Errorf("retirement journal full; reconciliation required")
		}
	} else if err != nil {
		return err
	}
	data, err := json.Marshal(retirementReceipt{1, id, generation, complete})
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".receipt-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncRetirementDirectory(dir)
}
