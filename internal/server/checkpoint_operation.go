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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Checkpoint operations are the durable idempotency records behind
// CheckpointWithOperation: one record per caller-chosen operation ID, written
// before any checkpoint side effect, and kept forever so a client that lost
// the reply can still learn the original outcome — including after the source
// sandbox is deleted. Like start operations they are node-local: this is
// per-node operation idempotency, not a cross-node writer lease or fencing
// token, and the records are never cleaned automatically.
//
// The phase discipline follows the checkpoint retention boundary: `failed` is
// recorded only when the runtime checkpoint was never entered (no artifact can
// exist), while everything after entry — runtime error, timeout, cancellation,
// panic, daemon restart, or a terminal write that failed — resolves to
// `unknown` with the c2cd786 directory semantics (the output is retained).
// `succeeded` requires the checkpoint flow to have returned nil, the sealed
// content root of the output directory to have been read through
// pkg/checkpointroot, and that fact to have been made durable; it is a
// historical record of completion, not an attestation that the artifacts
// still exist unchanged or that the publish path's durability gate ran.
const (
	checkpointOperationsDirName = "scheduler-checkpoint-operations"

	checkpointOperationPhaseAdmitted  = "admitted"
	checkpointOperationPhaseSucceeded = "succeeded"
	checkpointOperationPhaseFailed    = "failed"
	checkpointOperationPhaseUnknown   = "unknown"

	// Checkpoint operation record versions. The JSON field set is identical;
	// the version marks the recovery protocol the admission ran under.
	//
	// Version 1 (legacy): the admission verified only the sealed-root writer
	// capability and never sent an operation binding to the runtime, so no
	// runtime witness exists for these records. They are read unchanged and
	// their historical Get/same-request replay keep working, but their
	// undetermined outcomes cannot be proven recoverable — explicit recovery
	// refuses them instead of guessing.
	//
	// Version 2 (witness): the admission verified the runtime supports both
	// the writer and the CheckpointOperationWitness capabilities, sent the
	// exact operation binding to the runtime, and persists the success fact
	// before acknowledging the retained evidence. Only these records are
	// eligible for explicit recovery.
	//
	// Rollback refusal: a binary that predates version 2 validates records
	// with `version != 1` as corrupt and fails startup, so a daemon root that
	// carries a version-2 record cannot be silently downgraded — it must be
	// upgraded again before the journal loads. This is deliberate and
	// documented; the alternative (silently dropping or reinterpreting v2
	// records) would claim an unproven recovery protocol.
	checkpointOperationRecordVersionLegacy  = 1
	checkpointOperationRecordVersionWitness = 2

	// checkpointOperationMaxBytes bounds one record. Records carry identity
	// and outcome text only, so the cap is tight on purpose.
	checkpointOperationMaxBytes = 64 << 10
	checkpointOperationMaxMsg   = 4096
	// checkpointOperationLimit bounds the directory. Records are never
	// expired — a historical checkpoint fact does not require the source to
	// exist — so a full journal refuses new operations and demands
	// reconciliation.
	checkpointOperationLimit             = 65536
	checkpointOperationMaxTimeoutSeconds = 600

	// checkpointOperationMaxGeneration matches the expected-generation bound
	// the CheckpointIfGeneration RPC enforces.
	checkpointOperationMaxGeneration = 256
	checkpointOperationMaxRuntime    = 64
	checkpointOperationMaxDir        = 4096
	checkpointOperationMaxScheme     = 64
)

// checkpointOperationArtifact is the sealed content root of the output
// directory, read after the checkpoint completed. It is the completion-time
// evidence behind SUCCEEDED, not a liveness claim about the directory.
type checkpointOperationArtifact struct {
	RootDigest string `json:"root_digest"`
	Scheme     string `json:"scheme"`
}

type checkpointOperationRecord struct {
	Version       int                          `json:"version"`
	OperationID   string                       `json:"operation_id"`
	SandboxID     string                       `json:"sandbox_id"`
	Generation    string                       `json:"generation"`
	Runtime       string                       `json:"runtime"`
	CheckpointDir string                       `json:"checkpoint_dir"`
	RequestDigest string                       `json:"request_digest"`
	Phase         string                       `json:"phase"`
	Artifact      *checkpointOperationArtifact `json:"artifact,omitempty"`
	CreatedAt     string                       `json:"created_at"`
	UpdatedAt     string                       `json:"updated_at"`
	Message       string                       `json:"message,omitempty"`
}

// checkpointOperationExecution is the single executor slot of an admitted
// checkpoint operation, mirroring the start-operation execution slot: done is
// closed exactly once after the executor has fully returned, and cancel is
// guarded by the store's admission lock and set by the executor right after
// admission so shutdown can request convergence.
type checkpointOperationExecution struct {
	doneOnce sync.Once
	done     chan struct{}
	cancel   context.CancelFunc
}

func (e *checkpointOperationExecution) finish() {
	e.doneOnce.Do(func() { close(e.done) })
}

// contextMutex is a mutual-exclusion lock whose acquisition can be bounded by
// a context. It is a one-token semaphore: the zero value is usable (the token
// channel is created on first use), Lock/Unlock keep the plain sync.Mutex
// call shape every ordinary writer already uses, and Acquire waits for the
// token OR the context — never a background goroutine parked on a lock it
// would abandon on timeout, and never busy TryLock polling. A context that is
// already expired never wins the lock, even when the token is free: winning
// the token is re-checked against the context before it is returned, because
// granting a slot (or a write path) to a caller whose budget is gone is worse
// than a late refusal. Unlock of an unlocked mutex panics exactly like
// sync.Mutex, so ownership discipline stays observable in tests.
type contextMutex struct {
	once  sync.Once
	token chan struct{}
}

func (m *contextMutex) semaphore() chan struct{} {
	m.once.Do(func() { m.token = make(chan struct{}, 1) })
	return m.token
}

// Lock acquires the token uninterruptibly, exactly like sync.Mutex.Lock.
func (m *contextMutex) Lock() {
	token := m.semaphore()
	token <- struct{}{}
}

// Unlock releases the token; unlocking an unlocked mutex is a programming
// error and panics as sync.Mutex does.
func (m *contextMutex) Unlock() {
	select {
	case <-m.token:
	default:
		panic("unlock of unlocked contextMutex")
	}
}

// Acquire waits for the token bounded by ctx. It returns the context's error
// when ctx is done first (or already done), having taken nothing, and having
// released the token again if the select raced a ready token against a done
// context.
func (m *contextMutex) Acquire(ctx context.Context) error {
	token := m.semaphore()
	select {
	case token <- struct{}{}:
		if err := ctx.Err(); err != nil {
			// The token was free and grabbed in the same instant the context
			// expired: refuse rather than grant.
			<-token
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// checkpointOperationStore owns the durable checkpoint operation journal for
// one daemon root. The locking tiers are the same as the start-operation
// store: viewsMu guards the published view (queries never block on durable
// I/O), writeMu serializes state transitions end to end (durable write before
// publication, so a claimed fact is never observable before it is durable),
// and lifeMu guards admission/shutdown atomicity plus the in-flight registry
// and is never held across a durable write. writeMu is a contextMutex: the
// plain writers keep the Lock/Unlock discipline, while a recovery admission
// that has not yet won its execution slot waits for it bounded by the
// caller's own budget instead of queueing unbounded behind a durable write.
type checkpointOperationStore struct {
	dir     string
	rootDir string

	viewsMu sync.RWMutex
	records map[string]*checkpointOperationRecord

	writeMu contextMutex

	lifeMu       sync.Mutex
	inflight     map[string]*checkpointOperationExecution
	shuttingDown bool

	writesMu sync.Mutex

	// persistHook is an in-package test seam standing in for the durable
	// write behind terminal publication; production is nil.
	persistHook func(*checkpointOperationRecord) error
	// admitHook is an in-package test seam invoked right after an admission
	// won its execution slot and before the executor's cancellation is
	// registered; production is nil.
	admitHook func()
}

func checkpointOperationPath(dir, id string) string {
	return filepath.Join(dir, id+".json")
}

// loadCheckpointOperations reads the checkpoint operation journal. Every
// admitted record has an undetermined outcome after a restart — its executor
// is gone — so it is durably rewritten to the unknown phase: never guessed as
// success from the manifest or the source state, never re-executed.
// Corruption fails the load (and startup) explicitly.
func loadCheckpointOperations(rootDir string) (*checkpointOperationStore, error) {
	dir := filepath.Join(rootDir, checkpointOperationsDirName)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create checkpoint operation directory: %w", err)
	}
	store := &checkpointOperationStore{
		dir:      dir,
		rootDir:  rootDir,
		records:  make(map[string]*checkpointOperationRecord),
		inflight: make(map[string]*checkpointOperationExecution),
	}

	directory, err := os.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("open checkpoint operation directory: %w", err)
	}
	entries, readErr := directory.ReadDir(checkpointOperationLimit + 1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, fmt.Errorf("read checkpoint operation directory: %w", readErr)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(entries) > checkpointOperationLimit {
		return nil, fmt.Errorf("checkpoint operation journal exceeds record limit")
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".operation-") {
			// A leftover temp file never became a record; the rename is the
			// atomic commit point, so it proves nothing and is discarded.
			if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("remove stale checkpoint operation temp file %s: %w", name, err)
			}
			continue
		}
		// Record files must be plain regular files: a symlink is not read at
		// all, let alone followed.
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return nil, fmt.Errorf("checkpoint operation journal entry %s is not a regular file", name)
		}
		if !strings.HasSuffix(name, ".json") {
			return nil, fmt.Errorf("unexpected entry %s in checkpoint operation journal", name)
		}
		id := strings.TrimSuffix(name, ".json")
		record, err := readCheckpointOperationRecord(dir, id)
		if err != nil {
			return nil, err
		}
		if record.Phase == checkpointOperationPhaseAdmitted {
			unknown := *record
			unknown.Phase = checkpointOperationPhaseUnknown
			unknown.Message = "operation was admitted but the daemon restarted before its outcome was recorded; outcome unproven, re-execution forbidden"
			unknown.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
			if err := store.durablyWrite(&unknown); err != nil {
				// Fail closed: a record whose unknown outcome cannot be made
				// durable must not load as still-admitted either.
				return nil, fmt.Errorf("record unknown outcome for admitted checkpoint operation %s: %w", id, err)
			}
			record = &unknown
		}
		store.publish(record)
	}
	return store, nil
}

func readCheckpointOperationRecord(dir, id string) (*checkpointOperationRecord, error) {
	path := checkpointOperationPath(dir, id)
	// Pin the opened regular file and cap the read itself. A pre-open Lstat
	// cannot prevent a swapped symlink or bound a file that grows after stat.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open checkpoint operation %s: %w", id, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > checkpointOperationMaxBytes {
		return nil, fmt.Errorf("invalid checkpoint operation record %s: not a regular file within the size bound", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, checkpointOperationMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read checkpoint operation %s: %w", id, err)
	}
	if len(data) > checkpointOperationMaxBytes {
		return nil, fmt.Errorf("checkpoint operation %s exceeds the size bound", path)
	}
	record, err := decodeCheckpointOperationRecord(data)
	if err != nil {
		return nil, fmt.Errorf("invalid checkpoint operation %s: %w", path, err)
	}
	if record.OperationID != id {
		return nil, fmt.Errorf("checkpoint operation %s records mismatched operation ID %q", path, record.OperationID)
	}
	return record, nil
}

func decodeCheckpointOperationRecord(data []byte) (*checkpointOperationRecord, error) {
	var record checkpointOperationRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("record has trailing content")
	}
	if err := validateCheckpointOperationRecord(&record); err != nil {
		return nil, err
	}
	return &record, nil
}

func validCheckpointOperationDigest(value string) bool {
	if len(value) != checkpointroot.DigestHexLen {
		return false
	}
	for _, c := range []byte(value) {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func validateCheckpointOperationRecord(record *checkpointOperationRecord) error {
	if record.Version != checkpointOperationRecordVersionLegacy &&
		record.Version != checkpointOperationRecordVersionWitness {
		return fmt.Errorf("unsupported version %d", record.Version)
	}
	if !validStartOperationID(record.OperationID) {
		return fmt.Errorf("invalid operation ID %q", record.OperationID)
	}
	if !config.IsValidSandboxID(record.SandboxID) {
		return fmt.Errorf("invalid sandbox ID %q", record.SandboxID)
	}
	if strings.TrimSpace(record.Generation) == "" || len(record.Generation) > checkpointOperationMaxGeneration {
		return fmt.Errorf("invalid generation for operation %s", record.OperationID)
	}
	if !validStartOperationID(record.Runtime) || len(record.Runtime) > checkpointOperationMaxRuntime {
		return fmt.Errorf("invalid runtime for operation %s", record.OperationID)
	}
	if err := validateCanonicalCheckpointDir(record.CheckpointDir); err != nil {
		return fmt.Errorf("invalid checkpoint dir for operation %s: %w", record.OperationID, err)
	}
	if !validCheckpointOperationDigest(record.RequestDigest) {
		return fmt.Errorf("invalid request digest for operation %s", record.OperationID)
	}
	switch record.Phase {
	case checkpointOperationPhaseAdmitted, checkpointOperationPhaseSucceeded,
		checkpointOperationPhaseFailed, checkpointOperationPhaseUnknown:
	default:
		return fmt.Errorf("invalid phase %q for operation %s", record.Phase, record.OperationID)
	}
	// SUCCEEDED is exactly the phase that carries the completion evidence:
	// success requires the sealed root to have been read, and a root digest
	// is never recorded beside an unproven phase.
	if (record.Artifact != nil) != (record.Phase == checkpointOperationPhaseSucceeded) {
		return fmt.Errorf("artifact binding disagrees with phase %q for operation %s", record.Phase, record.OperationID)
	}
	if record.Artifact != nil {
		if !validCheckpointOperationDigest(record.Artifact.RootDigest) {
			return fmt.Errorf("invalid artifact root digest for operation %s", record.OperationID)
		}
		if record.Artifact.Scheme != checkpointroot.Scheme {
			return fmt.Errorf("invalid artifact root scheme for operation %s", record.OperationID)
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, record.CreatedAt); err != nil {
		return fmt.Errorf("invalid created_at for operation %s: %w", record.OperationID, err)
	}
	if _, err := time.Parse(time.RFC3339Nano, record.UpdatedAt); err != nil {
		return fmt.Errorf("invalid updated_at for operation %s: %w", record.OperationID, err)
	}
	if len(record.Message) > checkpointOperationMaxMsg {
		return fmt.Errorf("message for operation %s exceeds the size bound", record.OperationID)
	}
	return nil
}

// validateCanonicalCheckpointDir accepts only the absolute, cleaned, non-root
// form the store persists; it never touches the filesystem, so admission and
// replay never depend on the output directory still existing.
func validateCanonicalCheckpointDir(dir string) error {
	if strings.TrimSpace(dir) == "" || !filepath.IsAbs(dir) || len(dir) > checkpointOperationMaxDir {
		return fmt.Errorf("checkpoint directory must be an absolute path: %w", errord.ErrInvalidArgument)
	}
	if dir != filepath.Clean(dir) || dir == string(filepath.Separator) {
		return fmt.Errorf("checkpoint directory must be canonical and cannot be root: %w", errord.ErrInvalidArgument)
	}
	return nil
}

// published returns a copy of the record currently visible for the operation.
func (s *checkpointOperationStore) published(id string) (*checkpointOperationRecord, bool) {
	s.viewsMu.RLock()
	defer s.viewsMu.RUnlock()
	record, ok := s.records[id]
	if !ok {
		return nil, false
	}
	copyRecord := *record
	return &copyRecord, true
}

// publish makes a record visible. Callers hold writeMu and have already made
// the record durable (or are publishing the claims-nothing unknown phase).
func (s *checkpointOperationStore) publish(record *checkpointOperationRecord) {
	s.viewsMu.Lock()
	s.records[record.OperationID] = record
	s.viewsMu.Unlock()
}

// snapshot copies the currently published record for the operation, or nil
// when unknown.
func (s *checkpointOperationStore) snapshot(id string) *checkpointOperationRecord {
	if s == nil || id == "" {
		return nil
	}
	record, ok := s.published(id)
	if !ok {
		return nil
	}
	return record
}

// executionDone reports the running executor's done channel, if any. It takes
// only the admission lock, which is never held across durable I/O.
func (s *checkpointOperationStore) executionDone(id string) (<-chan struct{}, bool) {
	if s == nil || id == "" {
		return nil, false
	}
	s.lifeMu.Lock()
	defer s.lifeMu.Unlock()
	if exec := s.inflight[id]; exec != nil {
		return exec.done, true
	}
	return nil, false
}

// admit durably records the operation before any side effect. The returned
// joined channel is non-nil when an executor is already running the
// operation; the returned execution is non-nil when the caller became the
// single executor. The fast path (existing record) answers without any
// durable I/O; a new admission serializes under writeMu, makes the record
// durable, registers the in-flight execution under lifeMu (atomic with the
// shutdown flag), and only then publishes — so a visible admitted record
// always carries its executor. A store that began draining never executes a
// fresh admission; the raced record is republished as unknown.
func (s *checkpointOperationStore) admit(draft *checkpointOperationRecord) (
	execution *checkpointOperationExecution,
	joined <-chan struct{},
	err error,
) {
	if exec, done, err, resolved := s.resolveExisting(draft); resolved {
		return exec, done, err
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if exec, done, err, resolved := s.resolveExisting(draft); resolved {
		return exec, done, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	// New admissions are version-2 records: the caller (CheckpointWithOperation)
	// has already verified the runtime holds both the writer and the witness
	// capability, and will send the exact operation binding to the runtime so
	// the witness evidence this version promises actually exists.
	draft.Version = checkpointOperationRecordVersionWitness
	draft.Phase = checkpointOperationPhaseAdmitted
	draft.CreatedAt = now
	draft.UpdatedAt = now
	draft.Message = ""
	if err := validateCheckpointOperationRecord(draft); err != nil {
		return nil, nil, errord.ToGRPCf(errord.ErrInvalidArgument, "invalid checkpoint operation: %v", err)
	}
	if err := s.durablyWrite(draft); err != nil {
		// The admission write's outcome may be unknown (a post-rename
		// directory-sync failure leaves a possibly-landed record), so the ID
		// is spent rather than treated as side-effect free: the published
		// record moves to unknown, replays are answered from it, and no
		// execution ever runs. Retrying must use a new operation ID.
		unknown := *draft
		unknown.Phase = checkpointOperationPhaseUnknown
		unknown.Message = fmt.Sprintf(
			"admission write failed (%v); outcome unknown, the operation ID is spent and re-execution is forbidden", err,
		)
		unknown.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if writeErr := s.durablyWrite(&unknown); writeErr != nil {
			logrus.Errorf("persist unknown outcome for checkpoint operation %s: %v", draft.OperationID, writeErr)
		}
		s.publish(&unknown)
		return nil, nil, errord.ToGRPCf(
			errord.ErrUnavailable,
			"persist checkpoint operation %s: %v; the admission outcome is unknown and the operation ID must not be retried",
			draft.OperationID, err,
		)
	}
	exec := &checkpointOperationExecution{done: make(chan struct{})}
	s.lifeMu.Lock()
	if s.shuttingDown {
		s.lifeMu.Unlock()
		unknown := *draft
		unknown.Phase = checkpointOperationPhaseUnknown
		unknown.Message = "daemon began shutting down after the admission was recorded; the operation never executed and its outcome is unknown"
		unknown.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if writeErr := s.durablyWrite(&unknown); writeErr != nil {
			logrus.Errorf("persist unknown outcome for checkpoint operation %s: %v", draft.OperationID, writeErr)
		}
		s.publish(&unknown)
		return nil, nil, errord.ToGRPCf(
			errord.ErrUnavailable,
			"daemon is shutting down; checkpoint operation %s was recorded but will not execute (its outcome resolves to unknown)",
			draft.OperationID,
		)
	}
	s.inflight[draft.OperationID] = exec
	s.lifeMu.Unlock()
	s.publish(draft)
	return exec, nil, nil
}

// resolveExisting answers an admission for an already-recorded operation: a
// conflicting request is refused, a running execution is joined, and a
// terminal (or restart-resolved unknown) record replays from history without
// requiring the source sandbox or the artifacts to still exist.
func (s *checkpointOperationStore) resolveExisting(draft *checkpointOperationRecord) (
	execution *checkpointOperationExecution,
	joined <-chan struct{},
	err error,
	resolved bool,
) {
	existing, ok := s.published(draft.OperationID)
	if !ok {
		return nil, nil, nil, false
	}
	if err := sameCheckpointOperationRequest(existing, draft); err != nil {
		return nil, nil, err, true
	}
	if done, running := s.executionDone(draft.OperationID); running {
		return nil, done, nil, true
	}
	return nil, nil, nil, true
}

// registerExecutionCancel attaches the executor's cancellation under the same
// lock shutdown uses, compensating a shutdown that snapshotted before the
// cancel was attached. exec.cancel is only ever read and written under lifeMu.
func (s *checkpointOperationStore) registerExecutionCancel(
	id string,
	exec *checkpointOperationExecution,
	cancel context.CancelFunc,
) {
	s.lifeMu.Lock()
	if current, ok := s.inflight[id]; ok && current == exec {
		exec.cancel = cancel
	}
	closing := s.shuttingDown
	s.lifeMu.Unlock()
	if closing {
		cancel()
	}
}

// sameCheckpointOperationRequest refuses to reuse an operation ID for a
// different intent. The digest covers the deterministic encoding of the whole
// wrapped request — checkpoint ID, directory, timeout, compression,
// leave_running, snapshot type, and the exact expected generation — so no
// field can be swapped under a recorded ID; the remaining comparisons give
// the mismatch a precise error. The sandbox-bound generation and directory
// are caller-controlled and always compared; the runtime is server-derived
// metadata, compared only on the admission path whose draft carries it — a
// replay never reads the source sandbox, so it cannot and must not re-derive
// the runtime to prove its own intent.
func sameCheckpointOperationRequest(existing, next *checkpointOperationRecord) error {
	if existing.SandboxID != next.SandboxID {
		return errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"checkpoint operation %s is bound to sandbox %s, not %s",
			existing.OperationID, existing.SandboxID, next.SandboxID,
		)
	}
	if existing.Generation != next.Generation {
		return errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"checkpoint operation %s is bound to source generation %s, not %s",
			existing.OperationID, existing.Generation, next.Generation,
		)
	}
	if existing.RequestDigest != next.RequestDigest {
		return errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"checkpoint operation %s is bound to a different request",
			existing.OperationID,
		)
	}
	if existing.CheckpointDir != next.CheckpointDir {
		return errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"checkpoint operation %s is bound to checkpoint directory %s, not %s",
			existing.OperationID, existing.CheckpointDir, next.CheckpointDir,
		)
	}
	if next.Runtime != "" && existing.Runtime != next.Runtime {
		return errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"checkpoint operation %s is bound to runtime %s, not %s",
			existing.OperationID, existing.Runtime, next.Runtime,
		)
	}
	return nil
}

// --- explicit recovery of recorded operations (internal store stage) ---

// checkpointOperationRecovery is the handle of the single executor that won a
// recovery slot for one already-recorded operation. It wraps the very same
// in-flight execution slot the original admission uses — so shutdown, joining
// replayers, and cancellation converge on one lifecycle — plus the published
// record the recovery was admitted under, which the completion transition
// re-verifies before claiming anything. It is a store primitive for the later
// recovery service stage: it carries no runtime evidence, and holding it
// proves an execution slot, never a checkpoint outcome.
type checkpointOperationRecovery struct {
	store *checkpointOperationStore
	exec  *checkpointOperationExecution

	// bound is the record as published when recovery was admitted. Its
	// binding fields are immutable for the record's lifetime; keeping the
	// snapshot lets the completion transition refuse a record that was
	// replaced or drifted rather than completed. Only read after admission,
	// never mutated.
	bound *checkpointOperationRecord

	// ackOnly marks a slot admitted for a SUCCEEDED record. Its sole purpose
	// is the side-effecting Ack retry of an already-durable success: it owns a
	// fully lifecycle-managed executor slot, but it may never create or
	// rewrite a success fact — the recorded root stays the authority. Set once
	// at admission, only read afterwards.
	ackOnly bool
}

// acknowledgmentOnly reports whether the slot was admitted for a SUCCEEDED
// record, so the recovery service stage delivers its Ack instead of
// reconciling an undetermined outcome.
func (r *checkpointOperationRecovery) acknowledgmentOnly() bool {
	return r != nil && r.ackOnly
}

// boundRecord returns a copy of the record the recovery was admitted under, so
// the recovery service stage can rebuild the runtime binding — operation ID,
// request digest, source generation, directory — without re-deriving anything
// from a source sandbox that may no longer exist. The copy is independent all
// the way down: the artifact receipt is duplicated too, so a caller cannot
// mutate the published record — least of all a sealed root already recorded as
// SUCCEEDED — through the handle it was handed.
func (r *checkpointOperationRecovery) boundRecord() *checkpointOperationRecord {
	if r == nil {
		return nil
	}
	copyRecord := *r.bound
	if r.bound.Artifact != nil {
		artifact := *r.bound.Artifact
		copyRecord.Artifact = &artifact
	}
	return &copyRecord
}

// registerCancel attaches the recovery executor's cancellation under the same
// admission lock shutdown uses, with the same compensation for a shutdown that
// snapshotted before the cancel was attached, as the original execution path.
func (r *checkpointOperationRecovery) registerCancel(cancel context.CancelFunc) {
	if r == nil {
		return
	}
	r.store.registerExecutionCancel(r.bound.OperationID, r.exec, cancel)
}

// finish releases the recovery slot and wakes every joined replayer and a
// draining shutdown. Like the original executor's last action, a recovery must
// call it only after it has fully returned from its work.
func (r *checkpointOperationRecovery) finish() {
	if r == nil {
		return
	}
	r.store.finishExecution(r.bound.OperationID, r.exec)
}

// recoverExisting admits the recovery of one already-recorded checkpoint
// operation. It never creates a record, never executes a checkpoint, and never
// touches the source sandbox or the artifacts: a missing record is NotFound, a
// mismatched binding is refused, and a FAILED record stays failed forever. The
// undetermined outcomes — admitted without a live executor (a restart, or a
// terminal write that never landed) and unknown — are the records a recovery
// may reconcile; a SUCCEEDED record admits only the side-effecting half that is
// still owed, the Ack retry, through an acknowledgment-only slot.
//
// A SUCCEEDED record is therefore not answered as a query shortcut here: pure
// history reads belong to GetCheckpointOperation and the replay path, while an
// explicit recovery may still owe an acknowledgment. Every phase decision comes
// after the lifecycle ones — a live executor is joined first, so a recovery
// racing the original execution's post-success acknowledgment tail waits on
// that executor instead of acting beside it, and only a store that is not
// draining may register a fresh slot.
//
// Recovery shares the original execution's lifecycle: while any executor (the
// original one or an earlier recovery) holds the slot, the caller is handed its
// done channel to join instead of a second slot. Winning a slot registers it
// under lifeMu atomically with the shutdown flag — a store that began draining
// never starts a recovery, an acknowledgment-only one included — and admission
// performs no durable write at all, so no lock is held across one: the record
// already exists, and its history (generation, runtime, directory, request
// digest, created_at) must not change.
//
// Admission itself comes in two shapes with one shared decision: the legacy
// recoverExisting waits for the store's admission lock uninterruptibly (plain
// Lock/Unlock, the shape every other writer uses), while recoverExistingContext
// — the one the public RPC drives — waits for that lock bounded by the
// caller's context, because a request whose budget expires while queueing
// behind a durable write must refuse instead of blocking past its deadline
// before it has even won an execution slot.
func (s *checkpointOperationStore) recoverExisting(draft *checkpointOperationRecord) (
	recovery *checkpointOperationRecovery,
	joined <-chan struct{},
	err error,
) {
	if s == nil {
		return nil, nil, fmt.Errorf("recover checkpoint operation requires a store")
	}
	// The legacy uninterruptible admission: internal callers that own no
	// deadline keep the exact previous behavior.
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.recoverExistingAdmitted(draft)
}

// recoverExistingContext is the context-aware recovery admission the public
// RPC uses: waiting for the store's admission lock is part of the caller's
// recovery budget, so a durable write (or any other writer) holding writeMu
// past the budget ends this attempt with the context's error — DeadlineExceeded
// or Canceled — having granted no slot and mutated nothing. An already-expired
// context never wins admission even when the lock is free. Once the lock is
// held the eligibility decision itself is pure memory work under lifeMu, so
// the writeMu discipline (no durable write on the admission path, other
// writers stay serialized) is unchanged.
func (s *checkpointOperationStore) recoverExistingContext(
	ctx context.Context,
	draft *checkpointOperationRecord,
) (
	recovery *checkpointOperationRecovery,
	joined <-chan struct{},
	err error,
) {
	if s == nil {
		return nil, nil, fmt.Errorf("recover checkpoint operation requires a store")
	}
	if err := s.writeMu.Acquire(ctx); err != nil {
		return nil, nil, errord.ToGRPCf(
			err,
			"admit the recovery of checkpoint operation %s: the store admission lock wait exceeded the caller's budget; "+
				"no execution slot was granted and nothing was reconciled",
			draft.OperationID,
		)
	}
	defer s.writeMu.Unlock()
	return s.recoverExistingAdmitted(draft)
}

// recoverExistingAdmitted is the eligibility decision under a held writeMu,
// shared by the legacy and the context-aware admission: writeMu serializes it
// with admission and with competing recoveries, so exactly one applicant can
// register the slot. Nothing here performs durable I/O, so the writeMu
// discipline (durable write before publication) is preserved trivially.
func (s *checkpointOperationStore) recoverExistingAdmitted(draft *checkpointOperationRecord) (
	recovery *checkpointOperationRecovery,
	joined <-chan struct{},
	err error,
) {

	existing, ok := s.published(draft.OperationID)
	if !ok {
		return nil, nil, errord.ToGRPCf(
			errord.ErrNotFound, "checkpoint operation %s is unknown", draft.OperationID)
	}
	if err := sameCheckpointOperationRequest(existing, draft); err != nil {
		return nil, nil, err
	}
	switch existing.Phase {
	case checkpointOperationPhaseAdmitted, checkpointOperationPhaseUnknown,
		checkpointOperationPhaseSucceeded:
	case checkpointOperationPhaseFailed:
		return nil, nil, errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"checkpoint operation %s is recorded failed; a failed operation cannot be recovered",
			existing.OperationID,
		)
	default:
		return nil, nil, errord.ToGRPCf(
			errord.ErrUnknown,
			"checkpoint operation %s has invalid phase %q",
			existing.OperationID, existing.Phase,
		)
	}
	if done, running := s.executionDone(draft.OperationID); running {
		// The original executor — including the tail in which its success fact
		// is already durable but its acknowledgment work has not finished — or
		// an earlier recovery still owns the operation; join it instead of
		// creating a second executor.
		return nil, done, nil
	}
	exec := &checkpointOperationExecution{done: make(chan struct{})}
	s.lifeMu.Lock()
	if s.shuttingDown {
		s.lifeMu.Unlock()
		return nil, nil, errord.ToGRPCf(
			errord.ErrUnavailable,
			"daemon is shutting down; checkpoint operation %s cannot be recovered",
			existing.OperationID,
		)
	}
	s.inflight[draft.OperationID] = exec
	s.lifeMu.Unlock()
	bound := *existing
	return &checkpointOperationRecovery{
		store:   s,
		exec:    exec,
		bound:   &bound,
		ackOnly: existing.Phase == checkpointOperationPhaseSucceeded,
	}, nil, nil
}

// assertExecutionOwnership verifies that exec still holds the operation's
// in-flight slot. Callers hold writeMu; lifeMu is taken only for the
// comparison and never across a durable write.
func (s *checkpointOperationStore) assertExecutionOwnership(
	id string,
	exec *checkpointOperationExecution,
) error {
	s.lifeMu.Lock()
	current, ok := s.inflight[id]
	s.lifeMu.Unlock()
	if !ok || current != exec {
		return errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"the recovery slot for checkpoint operation %s no longer owns the operation; re-admit the recovery before claiming its outcome",
			id,
		)
	}
	return nil
}

// markRecoveredSucceeded is the dedicated completion transition of a recovery
// slot: the only path that may move an undetermined record (admitted without
// an executor, or unknown) to SUCCEEDED, and only while this recovery still
// owns the operation's execution slot and the record still carries the binding
// the recovery was admitted under. Like markTerminal's claiming phases it is
// durable-first and serialized under writeMu: the success fact is constructed,
// persisted, and only then published, so a slow, blocked, or failed write
// leaves every query at the undetermined outcome. A failure may be retried
// with the same slot — or, after it is released, by re-admitting the recovery
// of the same operation.
//
// markTerminal itself is deliberately not relaxed: unknown is terminal there,
// and the ordinary executor fallbacks must keep being unable to rewrite an
// undetermined record. An already-SUCCEEDED record is answered idempotently
// only for the exact same root and scheme — the durable record, not a later
// recovery, is the authority — and any other root is a conflict. An
// acknowledgment-only slot can never do more than confirm that recorded root:
// it may not create a success fact at all.
//
// The store verifies input format and these state preconditions only. The
// sealed root must come from the caller's runtime-witness reconciliation of
// the canonical artifact root; this primitive never treats a manifest, a
// directory, or any other caller payload as completion evidence.
//
// A draining shutdown cancels the recovery executor's context to request
// convergence but does not revoke the slot: the executor may still land the
// original operation's durable fact before it returns, and shutdown waits for
// that real exit.
func (r *checkpointOperationRecovery) markRecoveredSucceeded(
	artifact *checkpointOperationArtifact,
	message string,
) error {
	if r == nil {
		return fmt.Errorf("checkpoint operation recovery is nil")
	}
	if artifact == nil || !validCheckpointOperationDigest(artifact.RootDigest) ||
		artifact.Scheme != checkpointroot.Scheme {
		return errord.ToGRPCf(
			errord.ErrInvalidArgument,
			"recovered completion of checkpoint operation %s requires a sealed root digest and the %s scheme",
			r.bound.OperationID, checkpointroot.Scheme,
		)
	}
	if len(message) > checkpointOperationMaxMsg {
		message = message[:checkpointOperationMaxMsg]
	}
	s := r.store
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.assertExecutionOwnership(r.bound.OperationID, r.exec); err != nil {
		return err
	}
	record, ok := s.published(r.bound.OperationID)
	if !ok {
		return fmt.Errorf("recover checkpoint operation %s without a record", r.bound.OperationID)
	}
	if err := sameCheckpointOperationRequest(record, r.bound); err != nil {
		// The record's binding drifted from the one this recovery was admitted
		// under, so the success fact would land on a different operation.
		return err
	}
	switch record.Phase {
	case checkpointOperationPhaseSucceeded:
		if record.Artifact.RootDigest == artifact.RootDigest &&
			record.Artifact.Scheme == artifact.Scheme {
			// Idempotent replay of the already-durable fact: a recovery
			// retrying after an ambiguous reply — including an
			// acknowledgment-only slot confirming the recorded receipt —
			// claims nothing new and rewrites nothing.
			return nil
		}
		return errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"checkpoint operation %s is already recorded succeeded with sealed root %s (%s); a different recovered root is a conflict",
			record.OperationID, record.Artifact.RootDigest, record.Artifact.Scheme,
		)
	case checkpointOperationPhaseAdmitted, checkpointOperationPhaseUnknown:
		if r.ackOnly {
			// The slot was admitted against a SUCCEEDED record; an
			// acknowledgment-only executor may not turn an undetermined record
			// into a success fact. Unreachable while phases only move forward,
			// and structural rather than incidental for exactly that reason.
			return errord.ToGRPCf(
				errord.ErrFailedPrecondition,
				"the recovery slot for checkpoint operation %s was admitted for acknowledgment only; it may not create a success fact",
				record.OperationID,
			)
		}
	case checkpointOperationPhaseFailed:
		return errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"checkpoint operation %s is recorded failed; a failed operation cannot be completed",
			record.OperationID,
		)
	default:
		return errord.ToGRPCf(
			errord.ErrUnknown,
			"checkpoint operation %s has invalid phase %q",
			record.OperationID, record.Phase,
		)
	}
	updated := *record
	updated.Phase = checkpointOperationPhaseSucceeded
	sealed := *artifact
	updated.Artifact = &sealed
	updated.Message = message
	updated.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := s.persist(&updated); err != nil {
		// Durable-first: the published view keeps the undetermined phase, so
		// queries keep reporting an unproven outcome and no success is
		// observable before it is durable.
		return fmt.Errorf("persist recovered success of checkpoint operation %s: %w", r.bound.OperationID, err)
	}
	s.publish(&updated)
	return nil
}

// markSucceeded durably records the completion fact — the sealed content root
// of the output directory — and only then publishes it. While it fails, the
// outcome stays unresolved and must be reported as unknown.
func (s *checkpointOperationStore) markSucceeded(
	id string,
	artifact *checkpointOperationArtifact,
	message string,
) error {
	return s.markTerminal(id, checkpointOperationPhaseSucceeded, artifact, message, true)
}

// markFailedConfirmed durably records a failure proven to predate the runtime
// checkpoint entry — no artifact can exist — before publishing it.
func (s *checkpointOperationStore) markFailedConfirmed(id, message string) error {
	return s.markTerminal(id, checkpointOperationPhaseFailed, nil, message, true)
}

// markUnknown records an undetermined outcome; re-execution stays forbidden.
// The unknown phase claims nothing, so it may be published in memory even
// when its durable write fails — a later restart reads the still-admitted
// record and resolves it to unknown again.
func (s *checkpointOperationStore) markUnknown(id, message string) {
	_ = s.markTerminal(id, checkpointOperationPhaseUnknown, nil, message, false)
}

// markTerminal transitions the record once; later transitions are no-ops so
// executor fallbacks cannot overwrite a fact already recorded. Phases that
// claim an outcome (succeeded, failed) are durable-first and serialized under
// writeMu: the durable write happens while no query-visible lock is held, and
// the new phase is published only after the write succeeded — so a slow,
// blocked, or failed write (including a rename that landed but whose
// directory fsync failed) never exposes an unpersisted terminal fact.
func (s *checkpointOperationStore) markTerminal(
	id, phase string,
	artifact *checkpointOperationArtifact,
	message string,
	claiming bool,
) error {
	if s == nil || id == "" {
		return fmt.Errorf("mark checkpoint operation requires an ID")
	}
	if len(message) > checkpointOperationMaxMsg {
		message = message[:checkpointOperationMaxMsg]
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	record, ok := s.published(id)
	if !ok {
		return fmt.Errorf("mark checkpoint operation %s without a record", id)
	}
	if isTerminalCheckpointOperationPhase(record.Phase) {
		return nil
	}
	updated := *record
	updated.Phase = phase
	updated.Artifact = artifact
	updated.Message = message
	updated.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)

	if err := s.persist(&updated); err != nil {
		if claiming {
			// The published view keeps the previous phase; the flow above
			// must treat this outcome as unknown, never as the claimed fact.
			return err
		}
		logrus.Errorf("persist %s checkpoint operation %s: %v", phase, id, err)
	}
	s.publish(&updated)
	return nil
}

// persist performs the durable write behind terminal publication, through the
// test seam when installed.
func (s *checkpointOperationStore) persist(record *checkpointOperationRecord) error {
	if s.persistHook != nil {
		return s.persistHook(record)
	}
	return s.durablyWrite(record)
}

func isTerminalCheckpointOperationPhase(phase string) bool {
	switch phase {
	case checkpointOperationPhaseSucceeded, checkpointOperationPhaseFailed, checkpointOperationPhaseUnknown:
		return true
	}
	return false
}

// finishExecution releases the executor slot and wakes every joined replayer
// and a draining shutdown. It is the executor's last action, so closing done
// means the execution has fully returned.
func (s *checkpointOperationStore) finishExecution(id string, exec *checkpointOperationExecution) {
	if s == nil || exec == nil {
		return
	}
	s.lifeMu.Lock()
	if current, ok := s.inflight[id]; ok && current == exec {
		delete(s.inflight, id)
	}
	s.lifeMu.Unlock()
	exec.finish()
}

// shutdown closes admission, requests convergence of every admitted execution
// by cancelling its context, and then waits for each executor to actually
// return before the caller tears shared runtime resources down. The wait is
// unbounded on purpose: a context deadline proves nothing about goroutine
// convergence, and releasing the runtime handle an executor may still be
// using would break the retention invariants the checkpoint flow enforces.
func (s *checkpointOperationStore) shutdown() {
	if s == nil {
		return
	}
	s.lifeMu.Lock()
	s.shuttingDown = true
	execs := make([]*checkpointOperationExecution, 0, len(s.inflight))
	cancels := make([]context.CancelFunc, 0, len(s.inflight))
	for _, exec := range s.inflight {
		execs = append(execs, exec)
		if exec.cancel != nil {
			cancels = append(cancels, exec.cancel)
		}
	}
	s.lifeMu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	for _, exec := range execs {
		<-exec.done
	}
}

func (s *checkpointOperationStore) durablyWrite(record *checkpointOperationRecord) error {
	s.writesMu.Lock()
	defer s.writesMu.Unlock()
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return fmt.Errorf("create checkpoint operation directory: %w", err)
	}
	if err := syncDirectory(s.rootDir); err != nil {
		return fmt.Errorf("sync checkpoint operation parent: %w", err)
	}
	path := checkpointOperationPath(s.dir, record.OperationID)
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("checkpoint operation record %s is not a regular file", path)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		entries, err := os.ReadDir(s.dir)
		if err != nil {
			return err
		}
		if len(entries) >= checkpointOperationLimit {
			return fmt.Errorf("checkpoint operation journal full; reconciliation required")
		}
	} else {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dir, ".operation-*")
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
	return syncDirectory(s.dir)
}

// --- request identity ---

// checkpointOperationRequestDigest fingerprints a checkpoint operation request
// with deterministic proto encoding. Every field is semantic — the exact
// checkpoint directory string, timeout, compression, leave_running, snapshot
// type, and the exact expected generation — and none is normalized away, so
// identity cannot drift through trimming or ignored fields. The operation ID
// is the key being bound, not part of the intent, and is excluded.
func checkpointOperationRequestDigest(request *runtime.CheckpointWithOperationRequest) (string, error) {
	normalized := proto.Clone(request).(*runtime.CheckpointWithOperationRequest)
	normalized.OperationID = ""
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("encode checkpoint operation request deterministically: %w", err)
	}
	return digestBytes(data), nil
}

// --- RPC surface ---

// CheckpointWithOperation admits, executes, or replays one identified source
// checkpoint. Only stop-and-copy Firecracker directory checkpoints are
// admitted: leave_running must be false and the source runtime must be
// Firecracker, and neither rejection may fall back to the legacy RPCs.
func (h *sandboxService) CheckpointWithOperation(
	ctx context.Context,
	request *runtime.CheckpointWithOperationRequest,
) (*runtime.CheckpointOperationStatus, error) {
	if request == nil {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "checkpoint operation request is nil")
	}
	if !h.recoveryReady.Load() {
		return nil, errord.ToGRPCf(errord.ErrUnavailable, "distillfs recovery is incomplete")
	}
	checkpointReq, canonicalDir, digest, err := validatedCheckpointOperation(request)
	if err != nil {
		return nil, err
	}

	// Replay fast path: an existing record is answered entirely from durable
	// state — no sandbox lookup, no artifact read — so a finished operation
	// replays after the source was deleted and the output directory was
	// removed or rewritten.
	incoming := &checkpointOperationRecord{
		OperationID:   request.GetOperationID(),
		SandboxID:     checkpointReq.ID,
		Generation:    request.ExpectedGeneration,
		CheckpointDir: canonicalDir,
		RequestDigest: digest,
	}
	if existing := h.checkpointOperations.snapshot(request.GetOperationID()); existing != nil {
		if err := sameCheckpointOperationRequest(existing, incoming); err != nil {
			return nil, err
		}
		if done, running := h.checkpointOperations.executionDone(request.GetOperationID()); running {
			// A same-request replay while the admitted execution runs: wait
			// for its outcome. Caller cancellation ends only this wait.
			select {
			case <-done:
			case <-ctx.Done():
				return nil, status.FromContextError(ctx.Err()).Err()
			}
		}
		return h.checkpointOperationStatus(request.GetOperationID())
	}

	// Pre-admission source inspection: the runtime capability gate needs the
	// source's runtime handler. This is read-only and refuses before the
	// operation ID is spent. It does NOT validate the generation or the
	// running state — those stay inside the checkpoint path under the
	// per-ID physical lock, where the admission record cannot substitute for
	// the real check. Only runtimes that write sealed, root-bindable
	// stop-and-copy checkpoints are admitted (the CheckpointOperationWriter
	// capability, currently Firecracker alone); there is no fallback to the
	// legacy checkpoint RPCs.
	sandbox, err := h.sandboxManager.Get(checkpointReq.ID)
	if err != nil {
		return nil, errord.ToGRPC(err)
	}
	if sandbox.Metadata == nil || sandbox.Metadata.RuntimeHandler == "" {
		return nil, errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"sandbox %s has no runtime metadata",
			checkpointReq.ID,
		)
	}
	handler, ok := h.serviceHandler.Get(sandbox.Metadata.RuntimeHandler)
	if !ok {
		return nil, errord.ToGRPC(errord.ErrNotImplemented)
	}
	if _, ok := handler.(svc.CheckpointHandler); !ok {
		return nil, errord.ToGRPCf(
			errord.ErrNotImplemented,
			"runtime %q does not support checkpoint",
			sandbox.Metadata.RuntimeHandler,
		)
	}
	if writer, ok := handler.(svc.CheckpointOperationWriter); !ok || !writer.SupportsCheckpointOperations() {
		return nil, errord.ToGRPCf(
			errord.ErrNotImplemented,
			"runtime %q does not support identified checkpoint operations; "+
				"only sealed stop-and-copy checkpoints with a bindable content root are admitted",
			sandbox.Metadata.RuntimeHandler,
		)
	}
	// A new admission is a version-2 record, and that version promises the
	// runtime reconciliation contract: durable prepared/completed witnesses
	// bound to the exact request, and an acknowledgment that releases the
	// retained evidence. A runtime with the writer capability but without the
	// witness capability cannot honor that promise, so it is refused here —
	// before the operation ID is spent — rather than admitted as a record
	// whose UNKNOWN outcomes could never be reconciled.
	if _, ok := handler.(svc.CheckpointOperationWitness); !ok {
		return nil, errord.ToGRPCf(
			errord.ErrNotImplemented,
			"runtime %q does not support checkpoint operation witnesses; "+
				"identified checkpoint operations require a runtime that records recoverable operation evidence",
			sandbox.Metadata.RuntimeHandler,
		)
	}

	draft := &checkpointOperationRecord{
		OperationID:   request.GetOperationID(),
		SandboxID:     checkpointReq.ID,
		Generation:    request.ExpectedGeneration,
		Runtime:       sandbox.Metadata.RuntimeHandler,
		CheckpointDir: canonicalDir,
		RequestDigest: digest,
	}
	exec, joined, err := h.checkpointOperations.admit(draft)
	if err != nil {
		return nil, err
	}
	if exec == nil {
		if joined != nil {
			select {
			case <-joined:
			case <-ctx.Done():
				return nil, status.FromContextError(ctx.Err()).Err()
			}
		}
		// A concurrent caller won admission with the same request between the
		// fast-path check and here; its outcome is the recorded one.
		return h.checkpointOperationStatus(request.GetOperationID())
	}
	defer h.checkpointOperations.finishExecution(request.GetOperationID(), exec)
	if h.checkpointOperations.admitHook != nil {
		h.checkpointOperations.admitHook()
	}

	// The admitted work is detached from the caller's cancellation and bounded
	// by the request's own timeout — the same bound the legacy checkpoint
	// path applies to its whole operation, which is the reasonable maximum
	// here. It runs in this handler goroutine, never as an unbounded
	// background goroutine. Shutdown discovers the execution under the
	// admission lock, cancels this context to request convergence, and waits
	// for the executor to actually return.
	execCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx),
		time.Duration(checkpointReq.TimeoutSeconds)*time.Second,
	)
	defer cancel()
	h.checkpointOperations.registerExecutionCancel(request.GetOperationID(), exec, cancel)

	binding := &checkpointOperationBinding{
		store:            h.checkpointOperations,
		operationID:      request.GetOperationID(),
		requestDigest:    digest,
		sourceGeneration: request.ExpectedGeneration,
	}
	_, checkpointErr := func() (resp *runtime.CheckpointResponse, err error) {
		defer func() {
			if p := recover(); p != nil {
				binding.store.markUnknown(
					binding.operationID,
					fmt.Sprintf("checkpoint operation panicked: %v", p),
				)
				panic(p)
			}
		}()
		return h.checkpoint(execCtx, checkpointReq, request.ExpectedGeneration, binding)
	}()
	if !binding.terminal() {
		if binding.runtimeEntered() {
			// The runtime checkpoint was entered, so the error proves nothing
			// about the artifacts or the source; the checkpoint path already
			// retained the output directory with the c2cd786 semantics.
			message := "checkpoint was entered and failed; outcome unknown and the output directory is retained"
			if checkpointErr != nil {
				message = checkpointErr.Error()
			}
			h.checkpointOperations.markUnknown(request.GetOperationID(), message)
		} else {
			// The runtime was never invoked, so no artifact can exist; the
			// checkpoint path cleaned the attempt's output. The refusal is a
			// proven failure of this operation, and the ID is spent.
			message := "checkpoint was refused before any side effect"
			if checkpointErr != nil {
				message = checkpointErr.Error()
			}
			if err := h.checkpointOperations.markFailedConfirmed(request.GetOperationID(), message); err != nil {
				// The outcome stays admitted in memory; once this executor
				// exits, an admitted record without an executor reports
				// unknown.
				logrus.Errorf("persist failed outcome for checkpoint operation %s: %v", request.GetOperationID(), err)
			}
		}
	}
	// Release the executor slot before building the reply so a record that
	// could not reach a terminal phase reports unknown, not eternally
	// running. The deferred call is the backstop and is idempotent. The
	// acknowledgment tail below runs BEFORE the release: the slot — and with
	// it the shutdown drain — must cover every side effect of this execution.
	evidenceReleased := false
	if checkpointErr == nil && binding.succeeded() {
		// Durable success first, acknowledgment second: the runtime releases
		// its evidence-retention gate only for a service receipt that is
		// already durable, so this order is the protocol, not an
		// optimization. A failure here never downgrades the recorded success;
		// the RPC reports an explicit error instead, the record stays
		// SUCCEEDED, and the caller reconciles through one explicit
		// RecoverCheckpointOperation of the same operation.
		if ackErr := h.acknowledgeCheckpointOperation(
			execCtx, checkpointReq.ID, request.GetOperationID(), sandbox.Metadata.RuntimeHandler, binding.runtimeBinding(),
		); ackErr != nil {
			h.checkpointOperations.finishExecution(request.GetOperationID(), exec)
			return nil, errord.ToGRPCf(ackErr,
				"checkpoint operation %s succeeded and its receipt is durable, but the runtime acknowledgment failed; "+
					"the success fact is retained and must be reconciled by an explicit recovery of the same operation",
				request.GetOperationID(),
			)
		}
		evidenceReleased = true
	}
	h.checkpointOperations.finishExecution(request.GetOperationID(), exec)
	status, err := h.checkpointOperationStatus(request.GetOperationID())
	if err != nil {
		return nil, err
	}
	// evidence_released is per-invocation: true only because THIS executor
	// completed the acknowledgment after its own durable success. A later
	// replay of the same SUCCEEDED record reports false by construction.
	status.EvidenceReleased = evidenceReleased
	if checkpointErr != nil {
		return status, checkpointErr
	}
	return status, nil
}

// acknowledgeCheckpointOperation releases the evidence-retention gate of one
// identified checkpoint operation whose service receipt is already durable.
// The runtime binding must be the exact admitted identity, and the runtime is
// looked up from the recorded handler name — never re-derived from a source
// sandbox that may since have been replaced or deleted.
func (h *sandboxService) acknowledgeCheckpointOperation(
	ctx context.Context,
	sandboxID, operationID, runtimeName string,
	binding svc.CheckpointOperationBinding,
) error {
	handler, ok := h.serviceHandler.Get(runtimeName)
	if !ok {
		return errord.ToGRPC(errord.ErrNotImplemented)
	}
	witness, ok := handler.(svc.CheckpointOperationWitness)
	if !ok {
		return errord.ToGRPCf(
			errord.ErrNotImplemented,
			"runtime %q no longer provides the checkpoint operation witness required to acknowledge operation %s",
			runtimeName, operationID,
		)
	}
	return witness.AckCheckpointOperation(ctx, sandboxID, binding)
}

// GetCheckpointOperation returns the durable state of one checkpoint
// operation and never starts or re-executes anything. It reads only the
// operation journal.
func (h *sandboxService) GetCheckpointOperation(
	ctx context.Context,
	request *runtime.GetCheckpointOperationRequest,
) (*runtime.CheckpointOperationStatus, error) {
	if request == nil {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "get checkpoint operation request is nil")
	}
	if !validStartOperationID(request.GetOperationID()) {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "invalid operation_id")
	}
	return h.checkpointOperationStatus(request.GetOperationID())
}

// validatedCheckpointOperation validates the complete wrapped request of an
// identified checkpoint operation — the same rules for the initial admission
// and for an explicit recovery of that admission — and returns the inner
// checkpoint request, the canonical output directory, and the deterministic
// request digest computed from the request as presented. The digest is always
// derived here, from the complete payload; a caller-echoed digest is never
// accepted, because a recovery must authorize itself with the original
// request alone.
func validatedCheckpointOperation(request *runtime.CheckpointWithOperationRequest) (
	*runtime.CheckpointRequest, string, string, error,
) {
	if !validStartOperationID(request.GetOperationID()) {
		return nil, "", "", errord.ToGRPCf(
			errord.ErrInvalidArgument,
			"operation_id must be 1-%d characters matching %s and path-free",
			startOperationMaxID, startOperationIDPattern.String(),
		)
	}
	checkpointReq := request.GetCheckpoint()
	if checkpointReq == nil {
		return nil, "", "", errord.ToGRPCf(errord.ErrInvalidArgument, "checkpoint request is required")
	}
	if strings.TrimSpace(checkpointReq.ID) == "" {
		return nil, "", "", errord.ToGRPCf(errord.ErrInvalidArgument, "sandbox ID is required")
	}
	if checkpointReq.TimeoutSeconds == 0 || checkpointReq.TimeoutSeconds > checkpointOperationMaxTimeoutSeconds {
		return nil, "", "", errord.ToGRPCf(
			errord.ErrInvalidArgument,
			"checkpoint timeout_seconds must be between 1 and %d", checkpointOperationMaxTimeoutSeconds,
		)
	}
	// The identified form exists for stop-and-copy migration checkpoints only;
	// a leave-running request is refused outright instead of being admitted
	// and executed with quieter semantics.
	if checkpointReq.LeaveRunning {
		return nil, "", "", errord.ToGRPCf(
			errord.ErrInvalidArgument,
			"checkpoint operations support only stop-and-copy checkpoints; leave_running must be false",
		)
	}
	if strings.TrimSpace(request.ExpectedGeneration) == "" {
		return nil, "", "", errord.ToGRPCf(errord.ErrInvalidArgument, "expected_generation is required")
	}
	if len(request.ExpectedGeneration) > checkpointOperationMaxGeneration {
		return nil, "", "", errord.ToGRPCf(
			errord.ErrInvalidArgument,
			"expected_generation exceeds %d bytes",
			checkpointOperationMaxGeneration,
		)
	}
	canonicalDir := filepath.Clean(checkpointReq.CheckpointDir)
	if err := validateCanonicalCheckpointDir(canonicalDir); err != nil {
		return nil, "", "", errord.ToGRPC(err)
	}
	digest, err := checkpointOperationRequestDigest(request)
	if err != nil {
		return nil, "", "", errord.ToGRPCf(errord.ErrInvalidArgument, "fingerprint checkpoint operation request: %v", err)
	}
	return checkpointReq, canonicalDir, digest, nil
}

// --- explicit recovery of recorded operations (public service stage) ---

// RecoverCheckpointOperation reconciles one already-recorded checkpoint
// operation through the witness recovery protocol. The request must repeat
// the COMPLETE original payload unchanged: the service recomputes the request
// digest from that payload — never from a caller-echoed digest — and refuses
// the operation ID unless it matches the recorded binding exactly. Recovery
// never admits a record, never executes a checkpoint, never takes a snapshot,
// never resumes the source, and never falls back to the legacy checkpoint
// RPCs: a missing record is NotFound, a FAILED record is refused forever, a
// legacy version-1 record is refused because its outcome cannot be proven
// recoverable without a runtime witness, and a binding conflict is refused.
//
// Lifecycle: the recovery shares the store's single-execution slots (including
// the acknowledgment-only slots of SUCCEEDED records). One absolute deadline
// taken at request admission bounds the whole call — the join of a live
// executor (which listens to that deadline AND to the caller's cancellation,
// so even an uncancellable Background caller cannot wait unbounded), the
// physical-lock queue, the runtime reconciliation, and the acknowledgment all
// share it, and the work context after a slot is won detaches from the caller
// but carries the same deadline rather than a fresh timeout. Once a slot is
// won, its cancellation is registered with the store's shutdown drain
// immediately, and the per-ID physical resource lock is acquired, so a
// recovery never acts beside a checkpoint, start, or delete of the same
// sandbox; the source metadata binding is verified only after that lock is
// held, so a sandbox replaced while the recovery was queued cannot pass a
// stale pre-lock read. The slot is retained until the real work has returned;
// nothing is left to an abandoned goroutine.
//
// Undetermined version-2 records (admitted without an executor, or unknown)
// are reconciled through the runtime witness: RecoverCheckpointOperation
// returns the recorded completion, whose sealed root and scheme must equal
// checkpointroot.Bind of the service's canonical directory, and only then is
// the SUCCEEDED fact made durable through the dedicated transition — followed
// by the acknowledgment. A SUCCEEDED version-2 record owes only the
// acknowledgment: the recorded artifact is the authority, the possibly-GCed
// directory is deliberately not re-read, and the runtime Recover is not
// called, because an already-acknowledged runtime refuses it by contract.
//
// The acknowledgment tail is fail-closed in both branches: an Ack whose
// target no longer exists (NotFound) is NOT a release — the source may have
// been replaced, and treating a missing witness as success would unbind the
// delete gate from any proven fact — so the RPC fails while preserving the
// durable record for explicit reconciliation.
func (h *sandboxService) RecoverCheckpointOperation(
	ctx context.Context,
	request *runtime.RecoverCheckpointOperationRequest,
) (*runtime.CheckpointOperationStatus, error) {
	if request == nil {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "recover checkpoint operation request is nil")
	}
	if !h.recoveryReady.Load() {
		return nil, errord.ToGRPCf(errord.ErrUnavailable, "distillfs recovery is incomplete")
	}
	if request.GetRecoveryTimeoutSeconds() == 0 ||
		request.GetRecoveryTimeoutSeconds() > checkpointOperationMaxTimeoutSeconds {
		return nil, errord.ToGRPCf(
			errord.ErrInvalidArgument,
			"recovery timeout_seconds must be between 1 and %d", checkpointOperationMaxTimeoutSeconds,
		)
	}
	operation := request.GetOperation()
	if operation == nil {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "operation request is required")
	}
	_, canonicalDir, digest, err := validatedCheckpointOperation(operation)
	if err != nil {
		return nil, err
	}
	draft := &checkpointOperationRecord{
		OperationID:   operation.GetOperationID(),
		SandboxID:     operation.GetCheckpoint().ID,
		Generation:    operation.ExpectedGeneration,
		CheckpointDir: canonicalDir,
		RequestDigest: digest,
	}
	// The record version is static for an operation's lifetime, so a legacy
	// record is refused before any slot is taken: its admission predates the
	// witness protocol, no runtime evidence exists for it, and guessing
	// recoverability from files or source state is exactly what this RPC must
	// not do. Historical reads of the record keep working through
	// GetCheckpointOperation and same-request replay.
	if existing := h.checkpointOperations.snapshot(operation.GetOperationID()); existing != nil &&
		existing.Version != checkpointOperationRecordVersionWitness {
		return nil, errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"checkpoint operation %s is a legacy version-%d record without a runtime witness; "+
				"its outcome cannot be proven recoverable and explicit recovery is refused "+
				"(queries and same-request replays keep answering from the record)",
			operation.GetOperationID(), existing.Version,
		)
	}

	// One absolute recovery deadline governs the whole call, taken at request
	// admission: the store's admission-lock queue, the join below, the
	// physical-lock queue, the runtime reconciliation, and the acknowledgment
	// all share it, and none of them ever resets it. admitCtx carries BOTH the
	// caller's cancellation and this deadline into the context-aware recovery
	// admission, so a recovery still queueing behind a durable write for the
	// admission lock answers the budget instead of blocking past it before it
	// has won a slot; the join below listens to the same two ends — a
	// Background caller without a deadline of its own must not turn a
	// one-second recovery into an unbounded wait on an executor that never
	// returns. The join holds no lock; a slot won afterwards is released by
	// the deferred finish below, and shutdown waits for that real exit instead
	// of revoking the work.
	deadline := time.Now().Add(time.Duration(request.GetRecoveryTimeoutSeconds()) * time.Second)
	admitCtx, admitCancel := context.WithDeadline(ctx, deadline)
	defer admitCancel()
	var recovery *checkpointOperationRecovery
	for {
		candidate, joined, err := h.checkpointOperations.recoverExistingContext(admitCtx, draft)
		if err != nil {
			return nil, err
		}
		if candidate != nil {
			recovery = candidate
			break
		}
		timer := time.NewTimer(time.Until(deadline))
		select {
		case <-joined:
			timer.Stop()
		case <-timer.C:
			return nil, errord.ToGRPCf(
				context.DeadlineExceeded,
				"the existing execution of checkpoint operation %s did not finish within the recovery deadline; "+
					"nothing was reconciled and the operation ID is unchanged",
				operation.GetOperationID(),
			)
		case <-ctx.Done():
			timer.Stop()
			return nil, status.FromContextError(ctx.Err()).Err()
		}
		// The joined executor finished, but the budget it consumed counts
		// here: a re-admission with no remaining budget answers the deadline
		// instead of starting fresh work.
		if !time.Now().Before(deadline) {
			return nil, errord.ToGRPCf(
				context.DeadlineExceeded,
				"the recovery deadline of checkpoint operation %s expired while joining its existing execution; "+
					"nothing was reconciled and the operation ID is unchanged",
				operation.GetOperationID(),
			)
		}
	}
	defer recovery.finish()
	bound := recovery.boundRecord()
	// Defense in depth beside the pre-admission check: the slot's binding is
	// the authority for everything below.
	if bound.Version != checkpointOperationRecordVersionWitness {
		return nil, errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"checkpoint operation %s is a legacy version-%d record without a runtime witness; recovery is refused",
			bound.OperationID, bound.Version,
		)
	}
	// The recovery work detaches from the caller's cancellation but carries
	// the SAME absolute deadline — the join's leftover budget is the work's
	// budget; it is never refreshed. Registering the cancellation immediately
	// after the slot is won keeps a draining shutdown able to request
	// convergence of every step below, not only of the runtime calls, while
	// the slot itself is retained until this executor has really returned.
	execCtx, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline)
	defer cancel()
	recovery.registerCancel(cancel)
	handler, ok := h.serviceHandler.Get(bound.Runtime)
	if !ok {
		return nil, errord.ToGRPC(errord.ErrNotImplemented)
	}
	witness, ok := handler.(svc.CheckpointOperationWitness)
	if !ok {
		// A missing witness capability is a refusal, never a reason to run a
		// legacy checkpoint instead: the record is bound to an operation whose
		// evidence only this runtime holds.
		return nil, errord.ToGRPCf(
			errord.ErrNotImplemented,
			"runtime %q no longer provides the checkpoint operation witness required to recover operation %s; "+
				"no checkpoint fallback exists for an undetermined record",
			bound.Runtime, bound.OperationID,
		)
	}
	// Serialize the reconciliation against checkpoint, start, and delete for
	// this sandbox. The queue wait shares the absolute deadline: a recovery
	// that cannot acquire the physical lock in its remaining budget fails
	// with that deadline having reconciled nothing.
	unlock, lockErr := h.resourceLocks.acquire(execCtx, bound.SandboxID)
	if lockErr != nil {
		return nil, errord.ToGRPC(lockErr)
	}
	defer unlock()
	// If the source sandbox is still managed here, its live metadata must
	// still answer for the recorded binding — read HERE, under the physical
	// lock and after the queue wait, so a sandbox replaced while this recovery
	// was queued cannot slip past a stale pre-lock read. An absent source is
	// legitimate — it may have been deleted after a durable success — and the
	// runtime's own cold/hot identity gates then decide from their durable
	// state. A replaced generation or a re-created sandbox under another
	// runtime is a conflict this reconciliation refuses before touching
	// anything.
	if sandbox, getErr := h.sandboxManager.Get(bound.SandboxID); getErr == nil {
		if sandbox.Metadata == nil || sandbox.Metadata.RuntimeHandler == "" ||
			sandbox.Metadata.RuntimeHandler != bound.Runtime ||
			sandbox.Metadata.Labels[resourceGenerationLabel] != bound.Generation {
			return nil, errord.ToGRPCf(
				errord.ErrFailedPrecondition,
				"source sandbox %s no longer matches the recorded binding of checkpoint operation %s "+
					"(runtime %q, generation %q); refusing to reconcile against a replaced source",
				bound.SandboxID, bound.OperationID, bound.Runtime, bound.Generation,
			)
		}
	} else if !errors.Is(getErr, errord.ErrNotFound) {
		return nil, errord.ToGRPC(getErr)
	}

	binding := svc.CheckpointOperationBinding{
		OperationID:      bound.OperationID,
		RequestDigest:    bound.RequestDigest,
		SourceGeneration: bound.Generation,
	}
	if !recovery.acknowledgmentOnly() {
		completion, recoverErr := witness.RecoverCheckpointOperation(execCtx, bound.SandboxID, binding)
		if recoverErr != nil {
			return nil, errord.ToGRPC(recoverErr)
		}
		// The runtime's recorded root must be the sealed root of the service's
		// canonical directory — derived through the one shared algorithm, not
		// trusted from the reply alone: this is what binds the runtime's
		// completion evidence to the directory this service admitted.
		root, bindErr := checkpointroot.Bind(bound.CheckpointDir)
		if bindErr != nil {
			return nil, errord.ToGRPCf(
				errord.ErrFailedPrecondition,
				"the canonical checkpoint directory %s of operation %s can no longer be bound (%v); "+
					"the runtime completion is not accepted as success",
				bound.CheckpointDir, bound.OperationID, bindErr,
			)
		}
		if completion.RootDigest != root.RootDigest || completion.RootScheme != root.Scheme {
			return nil, errord.ToGRPCf(
				errord.ErrFailedPrecondition,
				"the runtime recovery of operation %s reports sealed root %s (%s) but the canonical directory %s binds %s (%s); "+
					"refusing to record a success that does not match the admitted directory",
				bound.OperationID, completion.RootDigest, completion.RootScheme,
				bound.CheckpointDir, root.RootDigest, root.Scheme,
			)
		}
		// Durable-first through the dedicated transition: while this write is
		// slow or fails, every query keeps reporting the undetermined outcome.
		if markErr := recovery.markRecoveredSucceeded(
			&checkpointOperationArtifact{RootDigest: root.RootDigest, Scheme: root.Scheme},
			fmt.Sprintf(
				"recovery reconciled the runtime witness of operation %s; sealed content root %s (%s) is a completion-time fact, not an artifact liveness claim",
				bound.OperationID, root.RootDigest, root.Scheme,
			),
		); markErr != nil {
			return nil, errord.ToGRPC(fmt.Errorf(
				"persist the recovered success of checkpoint operation %s: %w; "+
					"the outcome stays undetermined and the same recovery may be retried",
				bound.OperationID, markErr,
			))
		}
	}
	// Acknowledgment tail, in both branches, strictly after any durable
	// success above. A NotFound answer is not a release: fail closed and keep
	// the record for another explicit attempt.
	if ackErr := witness.AckCheckpointOperation(execCtx, bound.SandboxID, binding); ackErr != nil {
		return nil, errord.ToGRPC(fmt.Errorf(
			"acknowledge the recovered checkpoint operation %s: %w; "+
				"the durable record is retained (a SUCCEEDED fact is not downgraded) and the evidence release is unproven",
			bound.OperationID, ackErr,
		))
	}
	recovered, err := h.checkpointOperationStatus(bound.OperationID)
	if err != nil {
		return nil, err
	}
	recovered.EvidenceReleased = true
	return recovered, nil
}

func (h *sandboxService) checkpointOperationStatus(operationID string) (*runtime.CheckpointOperationStatus, error) {
	record := h.checkpointOperations.snapshot(operationID)
	if record == nil {
		return nil, errord.ToGRPCf(errord.ErrNotFound, "checkpoint operation %s is unknown", operationID)
	}
	status := &runtime.CheckpointOperationStatus{
		OperationID:      record.OperationID,
		SandboxID:        record.SandboxID,
		SourceGeneration: record.Generation,
		CheckpointDir:    record.CheckpointDir,
		RequestDigest:    record.RequestDigest,
		Message:          record.Message,
	}
	// The protocol is a property of the record, reported by every reply.
	// evidence_released is deliberately NOT set here: it is per-invocation —
	// true only when the call itself completed the runtime acknowledgment
	// after the durable success — so read-only queries and historical
	// replays keep reporting false.
	if record.Version == checkpointOperationRecordVersionWitness {
		status.RecoveryProtocol = runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS
	}
	switch record.Phase {
	case checkpointOperationPhaseAdmitted:
		if _, running := h.checkpointOperations.executionDone(operationID); running {
			status.State = runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_RUNNING
			status.Message = "operation admitted; outcome pending"
			return status, nil
		}
		// Admitted without an executor: the daemon restarted or the terminal
		// write failed; either way the outcome is unproven and the ID is spent.
		status.State = runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN
		status.Message = "operation outcome was not durably recorded; treat as unknown, re-execution forbidden"
		return status, nil
	case checkpointOperationPhaseSucceeded:
		status.State = runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED
		status.ArtifactRootDigest = record.Artifact.RootDigest
		status.ArtifactRootScheme = record.Artifact.Scheme
		if status.Message == "" {
			status.Message = "checkpoint succeeded; historical completion fact, not an artifact liveness claim"
		}
	case checkpointOperationPhaseFailed:
		status.State = runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED
	case checkpointOperationPhaseUnknown:
		status.State = runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN
	default:
		return nil, errord.ToGRPCf(
			errord.ErrUnknown,
			"checkpoint operation %s has invalid phase %q",
			operationID, record.Phase,
		)
	}
	return status, nil
}

// checkpointOperationBinding is the trusted server-side handle the shared
// checkpoint path consumes. It marks the exact runtime-entry boundary inside
// the memory-wrapper callback and records the durable success fact only after
// the runtime returned nil AND the sealed content root of the output
// directory was read; it never infers entry from error text. It also carries
// the complete admitted identity — the request digest and the expected source
// generation — so the runtime receives the exact operation binding its
// durable witness must record, never a binding reconstructed from a later
// view of the request.
type checkpointOperationBinding struct {
	store       *checkpointOperationStore
	operationID string
	// requestDigest is the deterministic digest of the complete wrapped
	// request the operation was admitted under.
	requestDigest string
	// sourceGeneration is the exact expected generation of that admission.
	sourceGeneration string

	// entered is written inside the runtime-invocation callback and read only
	// after the callback's wrapper has returned, always on this executor
	// goroutine, mirroring the runtimeCheckpointEntered flag it augments.
	entered bool
}

// runtimeBinding projects the admitted identity onto the internal runtime
// binding (pkg/runtime CheckpointOperationBinding) the checkpoint path passes
// to the handler: the exact operation ID, request digest, and source
// generation the runtime's durable witness must record for a later explicit
// recovery to reconcile against.
func (b *checkpointOperationBinding) runtimeBinding() svc.CheckpointOperationBinding {
	if b == nil {
		return svc.CheckpointOperationBinding{}
	}
	return svc.CheckpointOperationBinding{
		OperationID:      b.operationID,
		RequestDigest:    b.requestDigest,
		SourceGeneration: b.sourceGeneration,
	}
}

// noteRuntimeEntered marks that the runtime checkpoint call was actually
// entered; from this point every failure, timeout, cancellation, or panic
// resolves to unknown.
func (b *checkpointOperationBinding) noteRuntimeEntered() {
	if b != nil {
		b.entered = true
	}
}

func (b *checkpointOperationBinding) runtimeEntered() bool {
	return b != nil && b.entered
}

func (b *checkpointOperationBinding) terminal() bool {
	if b == nil {
		return false
	}
	record := b.store.snapshot(b.operationID)
	return record != nil && isTerminalCheckpointOperationPhase(record.Phase)
}

// succeeded reports whether the durable record carries the completion fact.
func (b *checkpointOperationBinding) succeeded() bool {
	if b == nil {
		return false
	}
	record := b.store.snapshot(b.operationID)
	return record != nil && record.Phase == checkpointOperationPhaseSucceeded
}

// recordSuccess completes an identified checkpoint: the runtime returned nil,
// so the sealed content root of the directory it wrote is read through the
// shared pkg/checkpointroot algorithm (never a re-hash of artifact payloads),
// and the success fact — root digest and scheme — is made durable before the
// checkpoint may report success. A root that cannot be read or a terminal
// write that fails returns an error, and the caller must report the outcome
// as unknown instead of success.
func (b *checkpointOperationBinding) recordSuccess(directory string) error {
	if b == nil {
		return nil
	}
	root, err := checkpointroot.Bind(directory)
	if err != nil {
		return fmt.Errorf(
			"read the sealed content root of %s: %w; the checkpoint completed but its outcome cannot be confirmed as succeeded",
			directory, err,
		)
	}
	message := fmt.Sprintf(
		"checkpoint completed; sealed content root %s (%s) is a completion-time fact, not an artifact liveness claim",
		root.RootDigest, root.Scheme,
	)
	if err := b.store.markSucceeded(
		b.operationID,
		&checkpointOperationArtifact{RootDigest: root.RootDigest, Scheme: root.Scheme},
		message,
	); err != nil {
		return fmt.Errorf(
			"persist the success fact for the checkpoint of %s: %w; the checkpoint completed but its outcome cannot be confirmed as succeeded",
			directory, err,
		)
	}
	return nil
}
