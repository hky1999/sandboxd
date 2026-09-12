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

package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

// firecrackerInstanceInfoMaxBytes bounds one GET / (InstanceInfo) body. The
// object is a fixed small set of short strings; anything larger is a protocol
// surprise and the read fails closed.
const firecrackerInstanceInfoMaxBytes = 4 << 10

type firecrackerAPI struct {
	socket string
	client *http.Client
}

func newFirecrackerAPI(socket string) *firecrackerAPI {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, "unix", socket)
		},
		DisableKeepAlives: true,
	}
	return &firecrackerAPI{
		socket: socket,
		client: &http.Client{
			Transport: transport,
		},
	}
}

func (api *firecrackerAPI) waitReady(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		connection, err := net.DialTimeout("unix", api.socket, 50*time.Millisecond)
		if err == nil {
			connection.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for Firecracker API socket %s: %w", api.socket, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (api *firecrackerAPI) put(ctx context.Context, path string, value any) error {
	return api.request(ctx, http.MethodPut, path, value)
}

func (api *firecrackerAPI) patch(ctx context.Context, path string, value any) error {
	return api.request(ctx, http.MethodPatch, path, value)
}

// firecrackerInstanceInfoStateNotStarted and friends are the MicroVM states
// the Firecracker API reports through GET / (InstanceInfo.state). The set is
// deliberately closed: an answer outside it is a protocol surprise the caller
// must refuse, never reinterpret.
const (
	firecrackerInstanceInfoStateNotStarted = "Not started"
	firecrackerInstanceInfoStateRunning    = "Running"
	firecrackerInstanceInfoStatePaused     = "Paused"
)

// firecrackerInstanceInfo is the bounded subset of the Firecracker InstanceInfo
// object (GET /) the reconciliation paths consult: the configured machine ID
// and the current MicroVM state. app_name and vmm_version are accepted but not
// retained.
type firecrackerInstanceInfo struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

// instanceInfo reads GET / under the caller's context. The answer must be a
// complete HTTP 200 whose body is one bounded JSON object carrying a nonempty
// id and one of the known MicroVM states; anything else — a transport failure,
// another status, an undecodable, truncated, oversized, or trailing body, a
// missing field, or an unknown state — is an explicit error, because a
// reconciliation that cannot positively read the source's state must refuse
// instead of guessing it.
func (api *firecrackerAPI) instanceInfo(ctx context.Context) (firecrackerInstanceInfo, error) {
	request, err := http.NewRequestWithContext(
		ctx, http.MethodGet, "http://localhost/", nil,
	)
	if err != nil {
		return firecrackerInstanceInfo{}, err
	}
	response, err := api.client.Do(request)
	if err != nil {
		return firecrackerInstanceInfo{}, fmt.Errorf("Firecracker GET /: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, firecrackerInstanceInfoMaxBytes+1))
	if err != nil {
		return firecrackerInstanceInfo{}, fmt.Errorf("Firecracker GET /: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return firecrackerInstanceInfo{}, fmt.Errorf(
			"Firecracker GET / returned %s: %s",
			response.Status, bytes.TrimSpace(body),
		)
	}
	if len(body) > firecrackerInstanceInfoMaxBytes {
		return firecrackerInstanceInfo{}, fmt.Errorf(
			"Firecracker GET / body exceeds %d bytes", firecrackerInstanceInfoMaxBytes,
		)
	}
	var info firecrackerInstanceInfo
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&info); err != nil {
		return firecrackerInstanceInfo{}, fmt.Errorf(
			"Firecracker GET / body is not InstanceInfo JSON: %w", err,
		)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return firecrackerInstanceInfo{}, fmt.Errorf(
			"Firecracker GET / body carries trailing content",
		)
	}
	if info.ID == "" {
		return firecrackerInstanceInfo{}, fmt.Errorf(
			"Firecracker GET / body carries no instance id",
		)
	}
	switch info.State {
	case firecrackerInstanceInfoStateNotStarted,
		firecrackerInstanceInfoStateRunning,
		firecrackerInstanceInfoStatePaused:
	default:
		return firecrackerInstanceInfo{}, fmt.Errorf(
			"Firecracker GET / reports unknown MicroVM state %q", info.State,
		)
	}
	return info, nil
}

func (api *firecrackerAPI) request(
	ctx context.Context,
	method,
	path string,
	value any,
) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(
		ctx,
		method,
		"http://localhost"+path,
		bytes.NewReader(payload),
	)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := api.client.Do(request)
	if err != nil {
		return fmt.Errorf("Firecracker %s %s: %w", method, path, err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusBadRequest {
		_, _ = io.Copy(io.Discard, response.Body)
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	return fmt.Errorf(
		"Firecracker %s %s returned %s: %s",
		method,
		path,
		response.Status,
		bytes.TrimSpace(body),
	)
}

func (api *firecrackerAPI) pause(ctx context.Context) error {
	return api.patch(ctx, "/vm", map[string]string{"state": "Paused"})
}

func (api *firecrackerAPI) resume(ctx context.Context) error {
	return api.patch(ctx, "/vm", map[string]string{"state": "Resumed"})
}

func (api *firecrackerAPI) createSnapshot(
	ctx context.Context,
	statePath,
	memoryPath,
	fsStatePath,
	snapshotType string,
) error {
	return api.createSnapshotWithSparse(ctx, statePath, memoryPath, fsStatePath, snapshotType, false)
}

func (api *firecrackerAPI) createSnapshotWithSparse(ctx context.Context, statePath, memoryPath, fsStatePath, snapshotType string, sparseFull bool) error {
	return api.createSnapshotWithMemoryAudit(ctx, statePath, memoryPath, fsStatePath, snapshotType, sparseFull, false, false)
}

func (api *firecrackerAPI) createSnapshotWithMemoryAudit(ctx context.Context, statePath, memoryPath, fsStatePath, snapshotType string, sparseFull, skipUnchanged, verifyIncrementalMemory bool) error {
	return api.createSnapshotWithChunkAlign(ctx, statePath, memoryPath, fsStatePath, snapshotType, sparseFull, skipUnchanged, verifyIncrementalMemory, 0, false)
}

// DeferDumpStatus is the Phase-B progress view of a deferred dump.
type DeferDumpStatus struct {
	Active  bool    `json:"active"`
	Written bool    `json:"written"`
	Failed  *string `json:"failed"`
}

func (api *firecrackerAPI) snapshotDeferStatus(ctx context.Context) (*DeferDumpStatus, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://localhost/snapshot/defer-status", nil)
	if err != nil {
		return nil, err
	}
	response, err := api.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("Firecracker GET /snapshot/defer-status: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf(
			"Firecracker GET /snapshot/defer-status returned %s: %s",
			response.Status, bytes.TrimSpace(body))
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	var status DeferDumpStatus
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

func (api *firecrackerAPI) snapshotDeferFinish(ctx context.Context, statePath string) error {
	return api.put(ctx, "/snapshot/defer-finish", map[string]any{
		"snapshot_path": statePath,
	})
}

// createSnapshotWithChunkAlign adds chunk_align_bytes: incremental writes
// round OUT to this grid so every written chunk is complete. A baseless
// window target is sparse and its holes mean "parent-owned bytes"; an
// unaligned dirty range would leave a partially written chunk that no local
// digest can represent (the seal refuses those — see scanFileChunks).
func (api *firecrackerAPI) createSnapshotWithChunkAlign(ctx context.Context, statePath, memoryPath, fsStatePath, snapshotType string, sparseFull, skipUnchanged, verifyIncrementalMemory bool, chunkAlignBytes int64, deferDump bool) error {
	if verifyIncrementalMemory && snapshotType != firecrackerSnapshotTypeSoftDirty && snapshotType != firecrackerSnapshotTypeIncremental {
		return fmt.Errorf("verify_incremental_memory requires Incremental or SoftDirty")
	}
	// The Firecracker snapshot-create request surface is exactly the six
	// fields the remote line accepts (deny_unknown_fields rejects anything
	// else). The fork-only knobs sparse_full/skip_unchanged/
	// verify_incremental_memory/chunk_align_bytes/defer_dump were absorbed
	// by the remote external-dirty-ranges model and are refused at config
	// load; they must never reach the request body.
	body := map[string]any{
		"snapshot_type": snapshotType,
		"snapshot_path": statePath,
		"mem_file_path": memoryPath,
		"deferred_sync": true,
	}
	if fsStatePath != "" {
		body["fs_state_path"] = fsStatePath
	}
	// Checkpoint artifacts deliberately remain in the host page cache. The
	// caller accepts that success does not imply immediate power-loss
	// durability; avoiding a forced writeback keeps the pause path short.
	return api.put(ctx, "/snapshot/create", body)
}

func (api *firecrackerAPI) loadSnapshot(
	ctx context.Context,
	statePath,
	memoryPath,
	liveMemoryPath,
	tapName,
	vsockPath,
	virtioFSSocketPath,
	virtioFSStatePath,
	memBackendType,
	memBackendPath string,
) error {
	// The UFFD backend takes precedence over both file backends: lazy page
	// supply replaces loading bytes at restore time.
	backend := map[string]string{
		"backend_type": "File",
		"backend_path": memoryPath,
	}
	if memBackendType != "" {
		backend = map[string]string{
			"backend_type": memBackendType,
			"backend_path": memBackendPath,
		}
	}
	if virtioFSSocketPath != "" {
		backend = map[string]string{
			"backend_type": "SharedFile",
			"backend_path": liveMemoryPath,
			"source_path":  memoryPath,
		}
	}
	body := map[string]any{
		"snapshot_path":     statePath,
		"mem_backend":       backend,
		"track_dirty_pages": true,
		"resume_vm":         true,
		"network_overrides": []map[string]string{{
			"iface_id":      "eth0",
			"host_dev_name": tapName,
		}},
		"vsock_override": map[string]string{
			"uds_path": vsockPath,
		},
	}
	if virtioFSSocketPath != "" {
		body["fs_override"] = map[string]string{
			"fs_id":       "root",
			"socket_path": virtioFSSocketPath,
			"state_path":  virtioFSStatePath,
		}
	}
	return api.put(ctx, "/snapshot/load", body)
}

func firecrackerDrivePath(id string) string {
	return "/drives/" + url.PathEscape(id)
}

func configureFirecrackerVM(
	ctx context.Context,
	api *firecrackerAPI,
	kernelPath,
	initrdPath,
	kernelArgs string,
	vcpus,
	memoryMiB uint32,
	tapName,
	guestMAC,
	vsockPath string,
	virtioFSSocketPath string,
	drives []firecrackerDrive,
) error {
	if err := api.put(ctx, "/boot-source", map[string]any{
		"kernel_image_path": kernelPath,
		"initrd_path":       initrdPath,
		"boot_args":         kernelArgs,
	}); err != nil {
		return err
	}
	if err := api.put(ctx, "/machine-config", map[string]any{
		"vcpu_count":        vcpus,
		"mem_size_mib":      memoryMiB,
		"smt":               false,
		"track_dirty_pages": true,
	}); err != nil {
		return err
	}
	if virtioFSSocketPath != "" {
		if err := api.put(ctx, "/fs/root", map[string]any{
			"fs_id":       "root",
			"socket_path": virtioFSSocketPath,
			"tag":         firecrackerVirtioFSTag,
		}); err != nil {
			return err
		}
	}
	for _, drive := range drives {
		payload := map[string]any{
			"drive_id":       drive.ID,
			"path_on_host":   drive.Path,
			"is_root_device": false,
			"is_read_only":   drive.ReadOnly,
		}
		if drive.IOEngine != "" {
			payload["io_engine"] = drive.IOEngine
		}
		if drive.CacheType != "" {
			payload["cache_type"] = drive.CacheType
		}
		if err := api.put(ctx, firecrackerDrivePath(drive.ID), payload); err != nil {
			return err
		}
	}
	if err := api.put(ctx, "/network-interfaces/eth0", map[string]any{
		"iface_id":      "eth0",
		"host_dev_name": tapName,
		"guest_mac":     guestMAC,
	}); err != nil {
		return err
	}
	if err := api.put(ctx, "/vsock", map[string]any{
		"guest_cid": 3,
		"uds_path":  vsockPath,
	}); err != nil {
		return err
	}
	return api.put(ctx, "/actions", map[string]any{
		"action_type": "InstanceStart",
	})
}

func removeFirecrackerSocket(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
