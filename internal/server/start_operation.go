// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const startOperationLabel = "akernel.scheduler/start-operation-id"
const startOperationEntryLimit = 65536
const startOperationRecordLimit = 64 * 1024
const startOperationIndexHeader = "sandboxd-start-operations-v1\n"

// Intent files are immutable admission markers. Losing a mutable outcome
// cannot make an admitted operation look new or authorize a second dispatch.
// No request bytes, environment values or error messages are persisted.
type startOperationRecord struct {
	Version            int                         `json:"version"`
	OperationID        string                      `json:"operation_id"`
	RequestFingerprint string                      `json:"request_fingerprint"`
	PayloadFingerprint string                      `json:"payload_fingerprint"`
	DeadlineUnixMillis uint64                      `json:"deadline_unix_millis"`
	SandboxID          string                      `json:"sandbox_id"`
	Generation         string                      `json:"generation"`
	State              runtime.StartOperationState `json:"state"`
	Result             *runtime.StartResponse      `json:"result,omitempty"`
	SealedMissing      bool                        `json:"sealed_missing,omitempty"`
}

type startOperationJournal struct {
	directory *os.File
	lock      *os.File
	index     *os.File
	admitted  map[string]struct{}
	path      string
}

func validateStartOperationIdentity(id, fingerprint string, deadline uint64) error {
	parsed, err := uuid.Parse(id)
	if err != nil || parsed.String() != id || parsed == uuid.Nil {
		return status.Error(codes.InvalidArgument, "canonical nonzero operation UUID required")
	}
	digest, err := hex.DecodeString(fingerprint)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != fingerprint {
		return status.Error(codes.InvalidArgument, "lowercase full request SHA256 required")
	}
	if deadline == 0 || deadline > math.MaxInt64 {
		return status.Error(codes.InvalidArgument, "valid operation deadline required")
	}
	return nil
}

func (r *startOperationRecord) validate() error {
	if r.Version != 1 || validateStartOperationIdentity(r.OperationID, r.RequestFingerprint, r.DeadlineUnixMillis) != nil {
		return fmt.Errorf("invalid durable start operation identity")
	}
	digest, err := hex.DecodeString(r.PayloadFingerprint)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != r.PayloadFingerprint ||
		r.SandboxID != "sbox-"+r.OperationID {
		return fmt.Errorf("invalid durable start payload or sandbox identity")
	}
	generation, err := uuid.Parse(r.Generation)
	if err != nil || generation == uuid.Nil || generation.String() != r.Generation {
		return fmt.Errorf("invalid durable start generation")
	}
	switch r.State {
	case runtime.StartOperationState_START_OPERATION_STATE_PENDING, runtime.StartOperationState_START_OPERATION_STATE_NOT_CREATED:
		if r.Result != nil {
			return fmt.Errorf("unexpected result for incomplete or rejected start")
		}
	case runtime.StartOperationState_START_OPERATION_STATE_STARTED:
		if r.SealedMissing || r.Result == nil || r.Result.Code != 0 || r.Result.ID != r.SandboxID || r.Result.ResourceGeneration != r.Generation {
			return fmt.Errorf("start result does not match admitted physical identity")
		}
	default:
		return fmt.Errorf("invalid durable start outcome")
	}
	return nil
}

func (r *startOperationRecord) sameIdentity(other *startOperationRecord) bool {
	return r.Version == other.Version && r.OperationID == other.OperationID &&
		r.RequestFingerprint == other.RequestFingerprint && r.PayloadFingerprint == other.PayloadFingerprint &&
		r.DeadlineUnixMillis == other.DeadlineUnixMillis && r.SandboxID == other.SandboxID && r.Generation == other.Generation &&
		r.SealedMissing == other.SealedMissing
}

func (r *startOperationRecord) response() *runtime.StartOperationResponse {
	result := &runtime.StartResponse{ID: r.SandboxID, ResourceGeneration: r.Generation}
	if r.Result != nil {
		result = proto.Clone(r.Result).(*runtime.StartResponse)
	}
	return &runtime.StartOperationResponse{OperationID: r.OperationID, RequestFingerprint: r.RequestFingerprint,
		DeadlineUnixMillis: r.DeadlineUnixMillis, State: r.State, Result: result}
}

// Caller holds startOperationMu for every journal operation. A stable flock
// fences other daemon processes; inode checks reject a removed/replaced directory.
func (h *sandboxService) openStartOperationJournal() (*startOperationJournal, error) {
	if h.startJournal != nil {
		return h.startJournal, h.startJournal.checkDirectory()
	}
	path := filepath.Join(h.config.RootDir, "scheduler-start-operations")
	err := os.Mkdir(path, 0700)
	created := err == nil
	if err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	directory, err := os.OpenFile(path, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(path, ".lock"), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		directory.Close()
		return nil, err
	}
	j := &startOperationJournal{directory: directory, lock: lock, path: path, admitted: make(map[string]struct{})}
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		j.close()
		return nil, fmt.Errorf("start journal lock must be a private regular file")
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		j.close()
		return nil, err
	}
	flags := os.O_RDWR | os.O_APPEND | unix.O_NOFOLLOW
	if created {
		flags |= os.O_CREATE | os.O_EXCL
	}
	index, err := os.OpenFile(path+".index", flags, 0600)
	if err != nil {
		j.close()
		return nil, err
	}
	j.index = index
	if created {
		if _, err := index.WriteString(startOperationIndexHeader); err != nil {
			j.close()
			return nil, err
		}
		if err := index.Sync(); err != nil {
			j.close()
			return nil, err
		}
	}
	info, err = index.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 ||
		info.Size() > int64(len(startOperationIndexHeader)+37*startOperationEntryLimit) {
		j.close()
		return nil, fmt.Errorf("invalid start admission index type, mode or size")
	}
	_, err = index.Seek(0, io.SeekStart)
	if err != nil {
		j.close()
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(index, int64(len(startOperationIndexHeader)+37*startOperationEntryLimit+1)))
	if err != nil || !strings.HasPrefix(string(data), startOperationIndexHeader) {
		j.close()
		return nil, fmt.Errorf("invalid start admission index header")
	}
	entries := string(data[len(startOperationIndexHeader):])
	if len(entries)%37 != 0 {
		j.close()
		return nil, fmt.Errorf("incomplete start admission index")
	}
	for len(entries) > 0 {
		id := entries[:36]
		parsed, err := uuid.Parse(id)
		_, duplicate := j.admitted[id]
		if err != nil || parsed.String() != id || parsed == uuid.Nil || entries[36] != '\n' || duplicate {
			j.close()
			return nil, fmt.Errorf("invalid start admission index entry")
		}
		j.admitted[id] = struct{}{}
		entries = entries[37:]
	}
	if err := j.checkDirectory(); err != nil {
		j.close()
		return nil, err
	}
	if err := lock.Sync(); err != nil {
		j.close()
		return nil, err
	}
	if err := directory.Sync(); err != nil {
		j.close()
		return nil, err
	}
	if err := syncRetirementDirectory(h.config.RootDir); err != nil {
		j.close()
		return nil, err
	}
	h.startJournal = j
	return j, nil
}

func (j *startOperationJournal) checkDirectory() error {
	opened, err := j.directory.Stat()
	if err != nil {
		return err
	}
	current, err := os.Lstat(j.path)
	if err != nil {
		return err
	}
	if !current.IsDir() || current.Mode().Perm() != 0700 || !os.SameFile(opened, current) {
		return fmt.Errorf("start journal directory is not the original private directory")
	}
	index, err := j.index.Stat()
	if err != nil {
		return err
	}
	currentIndex, err := os.Lstat(j.path + ".index")
	if err != nil {
		return err
	}
	if !currentIndex.Mode().IsRegular() || currentIndex.Mode().Perm() != 0600 || !os.SameFile(index, currentIndex) ||
		currentIndex.Size() != int64(len(startOperationIndexHeader)+37*len(j.admitted)) {
		return fmt.Errorf("start admission index was removed, replaced or truncated")
	}
	return nil
}

func (j *startOperationJournal) close() {
	j.lock.Close()
	j.directory.Close()
	if j.index != nil {
		j.index.Close()
	}
}

func (h *sandboxService) closeStartOperationJournal() {
	h.startOperationMu.Lock()
	defer h.startOperationMu.Unlock()
	if h.startJournal != nil {
		h.startJournal.close()
		h.startJournal = nil
	}
}

func (j *startOperationJournal) readFile(name string) (*startOperationRecord, error) {
	f, err := os.OpenFile(filepath.Join(j.path, name), os.O_RDONLY|unix.O_NOFOLLOW, 0)
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
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > startOperationRecordLimit {
		return nil, fmt.Errorf("invalid start operation record type, mode or size")
	}
	decoder := json.NewDecoder(io.LimitReader(f, startOperationRecordLimit+1))
	decoder.DisallowUnknownFields()
	var record startOperationRecord
	if err := decoder.Decode(&record); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("trailing start operation data")
	}
	return &record, record.validate()
}

func (j *startOperationJournal) read(id string) (*startOperationRecord, error) {
	if err := j.checkDirectory(); err != nil {
		return nil, err
	}
	intent, err := j.readFile(id + ".intent.json")
	if err != nil {
		return nil, err
	}
	outcome, err := j.readFile(id + ".json")
	if err != nil {
		return nil, err
	}
	_, admitted := j.admitted[id]
	if !admitted && intent == nil && outcome == nil {
		return nil, nil
	}
	if !admitted || intent == nil || outcome == nil || intent.OperationID != id ||
		intent.State != runtime.StartOperationState_START_OPERATION_STATE_PENDING || !intent.sameIdentity(outcome) {
		return nil, fmt.Errorf("missing or mismatched start admission/outcome pair")
	}
	// A previous publication may have renamed before a failed directory sync.
	if err := j.directory.Sync(); err != nil {
		return nil, err
	}
	return outcome, nil
}

func (j *startOperationJournal) writeFile(name string, record *startOperationRecord, immutable bool) error {
	if err := j.checkDirectory(); err != nil {
		return err
	}
	if err := record.validate(); err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil || len(data) > startOperationRecordLimit {
		return fmt.Errorf("start operation record cannot be encoded within its bound")
	}
	f, err := os.CreateTemp(j.path, ".record-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	path := filepath.Join(j.path, name)
	if immutable {
		if err := os.Link(f.Name(), path); err != nil {
			return err
		}
		if err := os.Remove(f.Name()); err != nil {
			return err
		}
	} else if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	return j.directory.Sync()
}

func (j *startOperationJournal) admit(record *startOperationRecord) error {
	if err := j.checkDirectory(); err != nil {
		return err
	}
	entries, err := os.ReadDir(j.path)
	if err != nil {
		return err
	}
	if len(entries)+2 > startOperationEntryLimit {
		return fmt.Errorf("start journal full; reconciliation required")
	}
	if _, exists := j.admitted[record.OperationID]; exists {
		return fmt.Errorf("start operation is already admitted")
	}
	// Index first: every crash gap thereafter is an admitted unknown operation,
	// including the loss of BOTH per-operation files after daemon restart.
	j.admitted[record.OperationID] = struct{}{}
	if n, err := j.index.WriteString(record.OperationID + "\n"); err != nil || n != 37 {
		return fmt.Errorf("start admission index append failed")
	}
	if err := j.index.Sync(); err != nil {
		return err
	}
	if err := j.writeFile(record.OperationID+".intent.json", record, true); err != nil {
		return err
	}
	return j.writeFile(record.OperationID+".json", record, false)
}

func (h *sandboxService) startOperationResult(ctx context.Context, record *startOperationRecord) (*runtime.StartOperationResponse, error) {
	response := record.response()
	if record.State == runtime.StartOperationState_START_OPERATION_STATE_NOT_CREATED {
		return response, nil
	}
	unlock, err := h.resourceLocks.acquire(ctx, record.SandboxID)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "cannot inspect original start retirement")
	}
	receipt, err := h.readRetirement(record.SandboxID, record.Generation)
	if err != nil {
		unlock()
		return nil, status.Error(codes.Unavailable, "cannot read original start retirement")
	}
	if receipt != nil && receipt.Complete {
		unlock()
		response.State = runtime.StartOperationState_START_OPERATION_STATE_RETIRED
		return response, nil
	}
	var recovered *runtime.StartResponse
	if record.State == runtime.StartOperationState_START_OPERATION_STATE_PENDING && !record.SealedMissing {
		recovered, err = h.observeCommittedStartResult(ctx, record)
	}
	// Never acquire the admission mutex under the physical lock: missing
	// admission sealing takes them in the opposite order. The result below
	// is a historical creation observation, not a lease or liveness promise.
	unlock()
	if err != nil {
		return nil, status.Error(codes.Unavailable, "original physical start observation is unavailable")
	}
	if recovered == nil {
		return response, nil
	}
	h.startOperationMu.Lock()
	defer h.startOperationMu.Unlock()
	j, err := h.openStartOperationJournal()
	if err != nil {
		return nil, status.Error(codes.Unavailable, "start recovery journal is unavailable")
	}
	current, err := j.read(record.OperationID)
	if err != nil || current == nil || !current.sameIdentity(record) ||
		current.State == runtime.StartOperationState_START_OPERATION_STATE_NOT_CREATED {
		return nil, status.Error(codes.Unavailable, "start recovery identity or outcome changed")
	}
	if current.State == runtime.StartOperationState_START_OPERATION_STATE_PENDING {
		current.State = runtime.StartOperationState_START_OPERATION_STATE_STARTED
		current.Result = recovered
		if err := j.writeFile(current.OperationID+".json", current, false); err != nil {
			return nil, status.Error(codes.Unavailable, "recovered start result publication failed")
		}
	}
	return current.response(), nil
}

// Caller holds the original sandbox's physical lock. A cached RUNNING status
// is insufficient; require matching committed identity and a fresh runtime
// observation, then reconstruct only daemon-owned original network facts.
func (h *sandboxService) observeCommittedStartResult(ctx context.Context, record *startOperationRecord) (*runtime.StartResponse, error) {
	if !h.recoveryReady.Load() {
		return nil, nil
	}
	current, err := h.sandboxManager.Get(record.SandboxID)
	if errors.Is(err, errord.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if current == nil || current.Metadata == nil {
		return nil, nil
	}
	metadata := proto.Clone(current.Metadata).(*runtime.SandboxMetadata)
	if metadata.ID != record.SandboxID || metadata.PhysicalPhase != runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED ||
		metadata.Labels[startOperationLabel] != record.OperationID || metadata.Labels[resourceGenerationLabel] != record.Generation {
		return nil, nil
	}
	handler, ok := h.serviceHandler.Get(metadata.RuntimeHandler)
	if !ok || handler == nil {
		return nil, fmt.Errorf("original runtime handler is unavailable")
	}
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	states, err := handler.List(checkCtx)
	if err != nil {
		return nil, err
	}
	count, running := 0, false
	for _, state := range states {
		if state == nil {
			return nil, fmt.Errorf("runtime observation is incomplete")
		}
		if state.ID == record.SandboxID {
			count++
			running = state.Status == svc.SandboxStatusRunning
		}
	}
	if count != 1 || !running {
		return nil, nil
	}
	resources, err := h.physicalResources(metadata)
	if err != nil {
		return nil, err
	}
	encoded, ok := resources.Resources[config.ResourceNameInterface]
	if !ok {
		return nil, nil
	}
	network, err := networkmanager.NewNetResource(encoded)
	if err != nil || network.Ip.To4() == nil || network.Ip.IsUnspecified() {
		return nil, fmt.Errorf("original start network facts are incomplete")
	}
	// Even a fresh runtime query cannot authorize facts from a replacement
	// metadata record. Recheck the complete captured original under this
	// physical lock before publishing the historical creation result.
	confirmed, err := h.sandboxManager.Get(record.SandboxID)
	if err != nil {
		return nil, err
	}
	if confirmed == nil || confirmed.Metadata == nil || !proto.Equal(confirmed.Metadata, metadata) {
		return nil, fmt.Errorf("original start metadata changed during observation")
	}
	if err := checkCtx.Err(); err != nil {
		return nil, err
	}
	return &runtime.StartResponse{ID: record.SandboxID, ResourceGeneration: record.Generation,
		SandboxIp: network.Ip.String(), Ports: clonePorts(metadata.Ports)}, nil
}

func (h *sandboxService) GetStartOperation(ctx context.Context, request *runtime.GetStartOperationRequest) (*runtime.StartOperationResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "start query required")
	}
	if err := validateStartOperationIdentity(request.OperationID, request.RequestFingerprint, request.DeadlineUnixMillis); err != nil {
		return nil, err
	}
	h.startOperationMu.Lock()
	j, err := h.openStartOperationJournal()
	var record *startOperationRecord
	if err == nil {
		record, err = j.read(request.OperationID)
	}
	if err == nil && record == nil && request.SealMissing &&
		time.Now().UnixMilli() >= int64(request.DeadlineUnixMillis) {
		record, err = h.sealMissingStartOperation(ctx, j, request)
	}
	if err == nil && record != nil && record.SealedMissing &&
		record.State == runtime.StartOperationState_START_OPERATION_STATE_PENDING &&
		record.RequestFingerprint == request.RequestFingerprint && record.DeadlineUnixMillis == request.DeadlineUnixMillis {
		// The durable sealed admission itself blocks dispatch. Finish a crash
		// gap between its publication and the terminal outcome publication.
		record.State = runtime.StartOperationState_START_OPERATION_STATE_NOT_CREATED
		err = j.writeFile(record.OperationID+".json", record, false)
	}
	h.startOperationMu.Unlock()
	if err != nil {
		return nil, status.Error(codes.Unavailable, "start operation journal is unavailable")
	}
	if record == nil {
		return &runtime.StartOperationResponse{OperationID: request.OperationID, RequestFingerprint: request.RequestFingerprint,
			DeadlineUnixMillis: request.DeadlineUnixMillis, State: runtime.StartOperationState_START_OPERATION_STATE_UNKNOWN}, nil
	}
	if record.RequestFingerprint != request.RequestFingerprint || record.DeadlineUnixMillis != request.DeadlineUnixMillis {
		return nil, status.Error(codes.FailedPrecondition, "start query identity mismatch")
	}
	return h.startOperationResult(ctx, record)
}

// Caller holds the journal admission mutex. The per-ID physical lock keeps
// checks and publication together; the indexed tombstone blocks every later
// StartOperation, including a request that has not reached this daemon yet.
func (h *sandboxService) sealMissingStartOperation(
	ctx context.Context,
	j *startOperationJournal,
	request *runtime.GetStartOperationRequest,
) (*startOperationRecord, error) {
	if !h.recoveryReady.Load() {
		return nil, fmt.Errorf("physical recovery is incomplete")
	}
	id := "sbox-" + request.OperationID
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	unlock, err := h.resourceLocks.acquire(checkCtx, id)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if _, err := h.sandboxManager.Get(id); !errors.Is(err, errord.ErrNotFound) {
		return nil, fmt.Errorf("physical sandbox absence cannot be confirmed")
	}
	for _, intent := range h.sandboxManager.ListPhysicalIntents() {
		if intent == nil || intent.ID == id {
			return nil, fmt.Errorf("physical intent cannot be excluded")
		}
	}
	if _, err := os.Lstat(filepath.Join(h.config.RootDir, "containers", id)); !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("physical metadata absence cannot be confirmed")
	}
	for name := range h.config.PluginConfig.RuntimeConfig.RuntimeBinary {
		handler, ok := h.serviceHandler.Get(name)
		if !ok {
			return nil, fmt.Errorf("configured runtime is unavailable")
		}
		states, err := handler.List(checkCtx)
		if err != nil {
			return nil, fmt.Errorf("runtime inventory is unknown")
		}
		for _, state := range states {
			if state == nil || state.ID == id {
				return nil, fmt.Errorf("physical runtime cannot be excluded")
			}
		}
	}
	if err := checkCtx.Err(); err != nil {
		return nil, err
	}
	record := &startOperationRecord{Version: 1, OperationID: request.OperationID,
		RequestFingerprint: request.RequestFingerprint, PayloadFingerprint: strings.Repeat("0", 64),
		DeadlineUnixMillis: request.DeadlineUnixMillis, SandboxID: id, Generation: uuid.NewString(),
		State: runtime.StartOperationState_START_OPERATION_STATE_PENDING, SealedMissing: true}
	if err := j.admit(record); err != nil {
		return nil, err
	}
	record.State = runtime.StartOperationState_START_OPERATION_STATE_NOT_CREATED
	if err := j.writeFile(record.OperationID+".json", record, false); err != nil {
		return nil, err
	}
	return record, nil
}

func (h *sandboxService) StartOperation(ctx context.Context, request *runtime.StartOperationRequest) (*runtime.StartOperationResponse, error) {
	if request == nil || request.Start == nil || request.Start.SandboxID != "" {
		return nil, status.Error(codes.InvalidArgument, "start payload with daemon-owned sandbox ID required")
	}
	if err := validateStartOperationIdentity(request.OperationID, request.RequestFingerprint, request.DeadlineUnixMillis); err != nil {
		return nil, err
	}
	if !h.recoveryReady.Load() {
		return nil, status.Error(codes.Unavailable, "physical recovery is incomplete")
	}
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(request.Start)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "start payload cannot be encoded")
	}
	digest := sha256.Sum256(payload)
	h.startOperationMu.Lock()
	j, err := h.openStartOperationJournal()
	var record *startOperationRecord
	if err == nil {
		record, err = j.read(request.OperationID)
	}
	if err != nil {
		h.startOperationMu.Unlock()
		return nil, status.Error(codes.Unavailable, "start operation journal is unavailable")
	}
	if record != nil {
		h.startOperationMu.Unlock()
		if record.SealedMissing {
			return nil, status.Error(codes.FailedPrecondition, "late creation was durably sealed; query its final outcome")
		}
		if record.RequestFingerprint != request.RequestFingerprint || record.PayloadFingerprint != hex.EncodeToString(digest[:]) ||
			record.DeadlineUnixMillis != request.DeadlineUnixMillis {
			return nil, status.Error(codes.FailedPrecondition, "start operation payload or identity mismatch")
		}
		return h.startOperationResult(ctx, record)
	}
	record = &startOperationRecord{Version: 1, OperationID: request.OperationID,
		RequestFingerprint: request.RequestFingerprint, PayloadFingerprint: hex.EncodeToString(digest[:]),
		DeadlineUnixMillis: request.DeadlineUnixMillis, SandboxID: "sbox-" + request.OperationID,
		Generation: uuid.NewString(), State: runtime.StartOperationState_START_OPERATION_STATE_PENDING}
	if err := j.admit(record); err != nil {
		h.startOperationMu.Unlock()
		return nil, status.Error(codes.Unavailable, "start intent publication failed")
	}
	h.startOperationMu.Unlock()
	done, admitted := h.acquireCheckpointOperation()
	if !admitted {
		record.State = runtime.StartOperationState_START_OPERATION_STATE_NOT_CREATED
		h.startOperationMu.Lock()
		err := j.writeFile(record.OperationID+".json", record, false)
		h.startOperationMu.Unlock()
		if err != nil {
			return nil, status.Error(codes.Unavailable, "stopping rejection publication failed")
		}
		return record.response(), nil
	}
	start := proto.Clone(request.Start).(*runtime.StartRequest)
	start.SandboxID = record.SandboxID
	if start.Labels == nil {
		start.Labels = make(map[string]string)
	}
	start.Labels[startOperationLabel] = record.OperationID
	operationCtx, cancel := context.WithDeadline(h.checkpointOperationContext(ctx), time.UnixMilli(int64(record.DeadlineUnixMillis)))
	finished := make(chan struct{})
	go func() {
		defer done()
		defer cancel()
		defer close(finished)
		sideEffects := false
		var result *runtime.StartResponse
		var createErr error
		if operationCtx.Err() == nil {
			result, createErr = h.createSandbox(operationCtx, start, createOptions{
				resourceGeneration: record.Generation,
				beforeSideEffects: func() error {
					if err := operationCtx.Err(); err != nil {
						return err
					}
					sideEffects = true
					return nil
				},
			})
		}
		if !sideEffects {
			record.State = runtime.StartOperationState_START_OPERATION_STATE_NOT_CREATED
		} else if createErr == nil && result != nil && result.Code == 0 && result.ID == record.SandboxID && result.ResourceGeneration == record.Generation {
			record.State = runtime.StartOperationState_START_OPERATION_STATE_STARTED
			record.Result = proto.Clone(result).(*runtime.StartResponse)
			record.Result.Message = ""
		} else {
			// Rollback can have partial failures. Never manufacture a terminal
			// non-creation result from an RPC error or a temporarily empty List.
			return
		}
		h.startOperationMu.Lock()
		defer h.startOperationMu.Unlock()
		if current, err := j.read(record.OperationID); err == nil && current != nil && current.sameIdentity(record) &&
			current.State == runtime.StartOperationState_START_OPERATION_STATE_PENDING {
			// Failed publication leaves PENDING, and a query refuses damaged pairs.
			if err := j.writeFile(record.OperationID+".json", record, false); err != nil {
				logrus.Warnf("start operation %s final publication failed; outcome remains uncertain", record.OperationID)
			}
		}
	}()
	select {
	case <-ctx.Done():
		return nil, status.FromContextError(ctx.Err()).Err()
	case <-finished:
		return h.GetStartOperation(ctx, &runtime.GetStartOperationRequest{OperationID: request.OperationID,
			RequestFingerprint: request.RequestFingerprint, DeadlineUnixMillis: request.DeadlineUnixMillis})
	}
}
