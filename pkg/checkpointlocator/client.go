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

package checkpointlocator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// FetchNode reads one node's record from its checkpoint catalog endpoint
// (GET {address}/api/v1/node). A node that cannot be reached or serves an
// invalid record is an error, not a silent skip: the caller decides whether
// an unreachable node shrinks the candidate set or fails the request.
func FetchNode(ctx context.Context, address string) (NodeRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	url := strings.TrimRight(address, "/") + "/api/v1/node"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return NodeRecord{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return NodeRecord{}, fmt.Errorf("fetch node %s: %w", address, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return NodeRecord{}, fmt.Errorf("fetch node %s: status %d", address, resp.StatusCode)
	}
	var record NodeRecord
	if err := json.NewDecoder(resp.Body).Decode(&record); err != nil {
		return NodeRecord{}, fmt.Errorf("decode node %s: %w", address, err)
	}
	if record.ID == "" {
		return NodeRecord{}, fmt.Errorf("node %s served a record without an id", address)
	}
	if record.Address == "" {
		record.Address = address
	}
	return record, nil
}

// FetchAll reads every node concurrently. Unreachable addresses are
// reported separately: a placement usually wants to proceed with the live
// registry (and treat a missing origin accordingly) rather than fail on one
// flapped node.
func FetchAll(ctx context.Context, addresses []string) ([]NodeRecord, []error) {
	records := make([]NodeRecord, len(addresses))
	errs := make([]error, len(addresses))
	var wg sync.WaitGroup
	for i, address := range addresses {
		wg.Add(1)
		go func(i int, address string) {
			defer wg.Done()
			record, err := FetchNode(ctx, address)
			records[i], errs[i] = record, err
		}(i, address)
	}
	wg.Wait()
	live := make([]NodeRecord, 0, len(records))
	failed := make([]error, 0)
	for i, err := range errs {
		if err != nil {
			failed = append(failed, err)
			continue
		}
		live = append(live, records[i])
	}
	return live, failed
}

// ReadCheckpointCompat extracts the compatibility tuple from a Firecracker
// v2 checkpoint manifest on disk. A sealed v2 checkpoint without a tuple
// returns (nil, nil): the artifact predates tuples and verifies anywhere.
func ReadCheckpointCompat(dir string) (*CheckpointCompat, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("read checkpoint manifest in %s: %w", dir, err)
	}
	var manifest struct {
		Version int               `json:"version"`
		Compat  *CheckpointCompat `json:"compat"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("decode checkpoint manifest in %s: %w", dir, err)
	}
	if manifest.Version != 2 {
		return nil, errors.New("unsupported checkpoint manifest version")
	}
	return manifest.Compat, nil
}

// FetchTemplates reads one node's template listing
// (GET {address}/api/v1/templates) as plain ids.
func FetchTemplates(ctx context.Context, address string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	url := strings.TrimRight(address, "/") + "/api/v1/templates"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch templates %s: %w", address, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch templates %s: status %d", address, resp.StatusCode)
	}
	var listed struct {
		Templates []struct {
			ID     string            `json:"id"`
			Compat *CheckpointCompat `json:"compat"`
		} `json:"templates"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		return nil, fmt.Errorf("decode templates %s: %w", address, err)
	}
	ids := make([]string, 0, len(listed.Templates))
	for _, t := range listed.Templates {
		ids = append(ids, t.ID)
	}
	return ids, nil
}
