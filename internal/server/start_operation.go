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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

// Start operations are the durable idempotency records behind
// StartWithOperation: one record per caller-chosen operation ID, written
// before any start side effect, and kept after the sandbox is deleted so a
// client that lost the reply can still learn the original outcome. The
// records are node-local: this is per-node operation idempotency, not a
// cross-node writer lease or fencing token.
const (
	startOperationsDirName = "scheduler-start-operations"

	startOperationPhaseAdmitted  = "admitted"
	startOperationPhaseSucceeded = "succeeded"
	startOperationPhaseFailed    = "failed"
	startOperationPhaseUnknown   = "unknown"

	// startOperationMaxBytes bounds one record. Records carry identity and
	// outcome text only, so the cap is tight on purpose.
	startOperationMaxBytes = 64 << 10
	startOperationMaxMsg   = 4096
	startOperationMaxID    = 128
	// startOperationLimit bounds the directory. Tombstones are never expired
	// automatically — not on sandbox deletion and not on pod-identity reset —
	// because the historical fact does not require the sandbox to exist; a
	// full journal refuses new operations and demands reconciliation.
	startOperationLimit = 65536

	// startOperationExecutionLimit bounds one admitted execution after the
	// caller's context is detached, so detached work cannot run unbounded.
	// It does NOT bound daemon shutdown: Shutdown waits for the executor to
	// actually return before tearing anything down (see shutdown).
	startOperationExecutionLimit = 10 * time.Minute

	// restoreDigestHexLen is the length of every hex content-root digest the
	// restore binding compares; it mirrors checkpointroot.DigestHexLen.
	restoreDigestHexLen = checkpointroot.DigestHexLen
)

var startOperationIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// startOperationRestoreBinding records what the restore artifacts were bound
// to at admission. CheckpointDir alone is never an artifact identity: the
// same path can hold different content between attempts. A restore operation
// always carries a complete verifiable root: a sealed manifest plus a root
// for every artifact the manifest deliberately does not digest (the
// Firecracker writable overlay through its chunk sidecar).
type startOperationRestoreBinding struct {
	CheckpointDir string `json:"checkpoint_dir"`
	RootDigest    string `json:"root_digest"`
	Scheme        string `json:"scheme"`
	// ManifestBound reports whether the directory carried a sealed
	// manifest.json. Admissions reject unsealed directories, so records
	// persisted by this daemon always carry true; the field keeps the on-disk
	// evidence explicit instead of implied by a non-empty digest.
	ManifestBound bool `json:"manifest_bound"`
	// OverlaySidecarBound reports whether the Firecracker overlay chunk
	// sidecar was present and folded into the root digest.
	OverlaySidecarBound bool `json:"overlay_sidecar_bound,omitempty"`
}

type startOperationRecord struct {
	Version       int                           `json:"version"`
	OperationID   string                        `json:"operation_id"`
	SandboxID     string                        `json:"sandbox_id"`
	Generation    string                        `json:"generation"`
	Runtime       string                        `json:"runtime"`
	RequestDigest string                        `json:"request_digest"`
	Phase         string                        `json:"phase"`
	Restore       *startOperationRestoreBinding `json:"restore,omitempty"`
	CreatedAt     string                        `json:"created_at"`
	UpdatedAt     string                        `json:"updated_at"`
	Message       string                        `json:"message,omitempty"`
}

// startOperationExecution is the single executor slot of an admitted
// operation. done is closed exactly once, after the executor has fully
// returned; cancel is guarded by the store mutex and is set by the executor
// right after admission so shutdown can request convergence.
type startOperationExecution struct {
	doneOnce sync.Once
	done     chan struct{}
	cancel   context.CancelFunc
}

func (e *startOperationExecution) finish() {
	e.doneOnce.Do(func() { close(e.done) })
}

// startOperationStore owns the durable operation journal for one daemon root.
//
// Locking has three tiers, ordered writeMu > lifeMu > viewsMu:
//
//   - viewsMu guards the published record view. Queries take only its read
//     side and never block on durable I/O: a record becomes visible in the
//     view after its durable write succeeded, so a slow or blocked fsync can
//     never hold up a Get.
//   - writeMu serializes state transitions end to end — read, durable write,
//     publish — so terminal publication is ordered and once-only, and a
//     success or failure fact is never observable before it is durable.
//   - lifeMu guards admission/shutdown atomicity and the in-flight registry.
//     It is never held across a durable write: an admission either completes
//     its in-flight registration before shutdown marks the store draining or
//     is refused (a race lost to a draining shutdown spends the ID as
//     unknown rather than executing), and running-execution lookups are
//     never blocked by fsync.
type startOperationStore struct {
	dir     string
	rootDir string

	viewsMu sync.RWMutex
	records map[string]*startOperationRecord

	writeMu sync.Mutex

	lifeMu       sync.Mutex
	inflight     map[string]*startOperationExecution
	shuttingDown bool

	writesMu sync.Mutex

	// persistHook is an in-package test seam standing in for the durable
	// write behind terminal publication; production is nil.
	persistHook func(*startOperationRecord) error
	// admitHook is an in-package test seam invoked right after an admission
	// won its execution slot and before the executor's cancellation is
	// registered, so tests can interleave a shutdown at that exact point;
	// production is nil.
	admitHook func()
}

func startOperationPath(dir, id string) string {
	return filepath.Join(dir, id+".json")
}

// published returns a copy of the record currently visible for the operation.
// It takes only the view read lock, so it stays fast while a transition is
// persisting.
func (s *startOperationStore) published(id string) (*startOperationRecord, bool) {
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
func (s *startOperationStore) publish(record *startOperationRecord) {
	s.viewsMu.Lock()
	s.records[record.OperationID] = record
	s.viewsMu.Unlock()
}

// loadStartOperations reads the operation journal. Every admitted record has
// an undetermined outcome after a restart — its executor is gone — so it is
// durably rewritten to the unknown phase: never guessed as success, never
// re-executed. Corruption fails the load (and startup) explicitly.
func loadStartOperations(rootDir string) (*startOperationStore, error) {
	dir := filepath.Join(rootDir, startOperationsDirName)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create start operation directory: %w", err)
	}
	store := &startOperationStore{
		dir:      dir,
		rootDir:  rootDir,
		records:  make(map[string]*startOperationRecord),
		inflight: make(map[string]*startOperationExecution),
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read start operation directory: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".operation-") {
			// A leftover temp file never became a record; the rename is the
			// atomic commit point, so it proves nothing and is discarded.
			if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("remove stale start operation temp file %s: %w", name, err)
			}
			continue
		}
		if entry.IsDir() {
			return nil, fmt.Errorf("unexpected directory %s in start operation journal", name)
		}
		if !strings.HasSuffix(name, ".json") {
			return nil, fmt.Errorf("unexpected entry %s in start operation journal", name)
		}
		id := strings.TrimSuffix(name, ".json")
		record, err := readStartOperationRecord(dir, id)
		if err != nil {
			return nil, err
		}
		if record.Phase == startOperationPhaseAdmitted {
			unknown := *record
			unknown.Phase = startOperationPhaseUnknown
			unknown.Message = "operation was admitted but the daemon restarted before its outcome was recorded; outcome unproven, re-execution forbidden"
			unknown.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
			if err := store.durablyWrite(&unknown); err != nil {
				// Fail closed: a record whose unknown outcome cannot be made
				// durable must not load as still-admitted either.
				return nil, fmt.Errorf("record unknown outcome for admitted start operation %s: %w", id, err)
			}
			record = &unknown
		}
		store.publish(record)
	}
	return store, nil
}

func readStartOperationRecord(dir, id string) (*startOperationRecord, error) {
	path := startOperationPath(dir, id)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open start operation %s: %w", id, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat start operation %s: %w", id, err)
	}
	if !info.Mode().IsRegular() || info.Size() > startOperationMaxBytes {
		return nil, fmt.Errorf("invalid start operation record %s: not a regular file within the size bound", path)
	}
	var record startOperationRecord
	decoder := json.NewDecoder(io.LimitReader(f, startOperationMaxBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return nil, fmt.Errorf("decode start operation %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("start operation %s has trailing content", path)
	}
	if err := validateStartOperationRecord(&record); err != nil {
		return nil, fmt.Errorf("invalid start operation %s: %w", path, err)
	}
	if record.OperationID != id {
		return nil, fmt.Errorf("start operation %s records mismatched operation ID %q", path, record.OperationID)
	}
	return &record, nil
}

func validateStartOperationRecord(record *startOperationRecord) error {
	if record.Version != 1 {
		return fmt.Errorf("unsupported version %d", record.Version)
	}
	if !validStartOperationID(record.OperationID) {
		return fmt.Errorf("invalid operation ID %q", record.OperationID)
	}
	if !config.IsValidSandboxID(record.SandboxID) {
		return fmt.Errorf("invalid sandbox ID %q", record.SandboxID)
	}
	if record.Generation == "" || len(record.Generation) > startIntentMaxGeneration {
		return fmt.Errorf("invalid generation for operation %s", record.OperationID)
	}
	if record.Runtime == "" || len(record.Runtime) > startIntentMaxRuntime {
		return fmt.Errorf("invalid runtime for operation %s", record.OperationID)
	}
	if len(record.RequestDigest) != restoreDigestHexLen {
		return fmt.Errorf("invalid request digest for operation %s", record.OperationID)
	}
	switch record.Phase {
	case startOperationPhaseAdmitted, startOperationPhaseSucceeded,
		startOperationPhaseFailed, startOperationPhaseUnknown:
	default:
		return fmt.Errorf("invalid phase %q for operation %s", record.Phase, record.OperationID)
	}
	if record.Restore != nil {
		if record.Restore.CheckpointDir == "" || !filepath.IsAbs(record.Restore.CheckpointDir) {
			return fmt.Errorf("invalid restore checkpoint dir for operation %s", record.OperationID)
		}
		if !record.Restore.ManifestBound || len(record.Restore.RootDigest) != restoreDigestHexLen {
			return fmt.Errorf("restore binding for operation %s lacks a complete content root", record.OperationID)
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, record.CreatedAt); err != nil {
		return fmt.Errorf("invalid created_at for operation %s: %w", record.OperationID, err)
	}
	if _, err := time.Parse(time.RFC3339Nano, record.UpdatedAt); err != nil {
		return fmt.Errorf("invalid updated_at for operation %s: %w", record.OperationID, err)
	}
	if len(record.Message) > startOperationMaxMsg {
		return fmt.Errorf("message for operation %s exceeds the size bound", record.OperationID)
	}
	return nil
}

func validStartOperationID(id string) bool {
	if len(id) == 0 || len(id) > startOperationMaxID {
		return false
	}
	if !startOperationIDPattern.MatchString(id) {
		return false
	}
	return filepath.Base(id) == id && filepath.Clean(id) == id
}

// promoteCommittedTakeover upgrades an admitted or unknown operation to the
// succeeded phase when recovery proves the start's success the same way the
// intent journal does: a committed start-intent record taken over by fully
// matching sandbox metadata. The promotion is durable-first: a record whose
// success fact cannot be persisted returns an error, and the caller must keep
// the committed intent record (its proof) instead of removing it. Metadata
// presence alone never promotes.
func (s *startOperationStore) promoteCommittedTakeover(sandboxID, generation string) error {
	if s == nil || sandboxID == "" || generation == "" {
		return nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	for _, id := range s.operationIDs() {
		record, ok := s.published(id)
		if !ok {
			continue
		}
		if record.SandboxID != sandboxID || record.Generation != generation {
			continue
		}
		switch record.Phase {
		case startOperationPhaseAdmitted, startOperationPhaseUnknown:
		default:
			continue
		}
		if _, running := s.executionDone(id); running {
			continue
		}
		promoted := *record
		promoted.Phase = startOperationPhaseSucceeded
		promoted.Message = "success recovered from the committed start intent and matching sandbox metadata after restart"
		promoted.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if err := s.persist(&promoted); err != nil {
			return fmt.Errorf(
				"persist promoted success for start operation %s (sandbox %s): %w; keeping the committed intent record as proof",
				record.OperationID, sandboxID, err,
			)
		}
		s.publish(&promoted)
		logrus.Infof("start operation %s promoted to succeeded via committed intent takeover for sandbox %s", record.OperationID, sandboxID)
	}
	return nil
}

// operationIDs snapshots the visible operation IDs under the view read lock.
func (s *startOperationStore) operationIDs() []string {
	s.viewsMu.RLock()
	defer s.viewsMu.RUnlock()
	ids := make([]string, 0, len(s.records))
	for id := range s.records {
		ids = append(ids, id)
	}
	return ids
}

// admit durably records the operation before any side effect. The returned
// joined channel is non-nil when an executor is already running the
// operation: the caller waits on it and reads the recorded outcome instead of
// starting. The returned execution is non-nil when the caller became the
// single executor. An error means admission failed.
//
// The fast path (existing record) answers under the admission lock without
// any durable I/O. A new admission serializes with every other transition
// under writeMu and, in order: makes the record durable, registers the
// in-flight execution under lifeMu (atomic with the shutdown flag, which is
// never held across the durable write), and only then publishes the record.
// Registration-before-publication is what concurrent replays observe
// consistently — a visible admitted record always has its executor, so a
// replay joins the running execution instead of reading a phantom
// admitted-without-executor state, while a replay that does not yet see the
// record blocks on writeMu until the admission completes. A store that began
// draining never executes a fresh admission; the raced record is republished
// as unknown, so nothing that never executed is ever reported as running.
func (s *startOperationStore) admit(draft *startOperationRecord) (
	execution *startOperationExecution,
	joined <-chan struct{},
	err error,
) {
	// Fast path: an existing record is answered without touching the disk.
	if exec, done, err, resolved := s.resolveExisting(draft); resolved {
		return exec, done, err
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	// A concurrent admission may have won while writeMu was free.
	if exec, done, err, resolved := s.resolveExisting(draft); resolved {
		return exec, done, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	draft.Version = 1
	draft.Phase = startOperationPhaseAdmitted
	draft.CreatedAt = now
	draft.UpdatedAt = now
	draft.Message = ""
	if err := validateStartOperationRecord(draft); err != nil {
		return nil, nil, errord.ToGRPCf(errord.ErrInvalidArgument, "invalid start operation: %v", err)
	}
	if err := s.durablyWrite(draft); err != nil {
		// The admission write's outcome may be unknown (a post-rename
		// directory-sync failure leaves a possibly-landed record), so the ID
		// is spent rather than treated as side-effect free: the published
		// record moves to unknown, replays are answered from it, and no
		// execution ever runs. Retrying must use a new operation ID.
		unknown := *draft
		unknown.Phase = startOperationPhaseUnknown
		unknown.Message = fmt.Sprintf(
			"admission write failed (%v); outcome unknown, the operation ID is spent and re-execution is forbidden", err,
		)
		unknown.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if writeErr := s.durablyWrite(&unknown); writeErr != nil {
			logrus.Errorf("persist unknown outcome for start operation %s: %v", draft.OperationID, writeErr)
		}
		s.publish(&unknown)
		return nil, nil, errord.ToGRPCf(
			errord.ErrUnavailable,
			"persist start operation %s: %v; the admission outcome is unknown and the operation ID must not be retried",
			draft.OperationID, err,
		)
	}
	exec := &startOperationExecution{done: make(chan struct{})}
	s.lifeMu.Lock()
	if s.shuttingDown {
		s.lifeMu.Unlock()
		// The admitted record is durable but will never execute; republish it
		// as unknown so no view ever reports a phantom running admission —
		// exactly what a later query or a restart resolves to.
		unknown := *draft
		unknown.Phase = startOperationPhaseUnknown
		unknown.Message = "daemon began shutting down after the admission was recorded; the operation never executed and its outcome is unknown"
		unknown.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if writeErr := s.durablyWrite(&unknown); writeErr != nil {
			logrus.Errorf("persist unknown outcome for start operation %s: %v", draft.OperationID, writeErr)
		}
		s.publish(&unknown)
		return nil, nil, errord.ToGRPCf(
			errord.ErrUnavailable,
			"daemon is shutting down; start operation %s was recorded but will not execute (its outcome resolves to unknown)",
			draft.OperationID,
		)
	}
	s.inflight[draft.OperationID] = exec
	s.lifeMu.Unlock()
	// Publication comes last so a visible admitted record ALWAYS carries its
	// registered executor: concurrent replays join instead of observing the
	// admitted-without-executor window, while replays that do not see the
	// record yet block on writeMu until this admission completes.
	s.publish(draft)
	return exec, nil, nil
}

// resolveExisting answers an admission for an already-recorded operation:
// a conflicting request is refused, a running execution is joined, and a
// terminal (or restart-resolved unknown) record replays from history. The
// resolved flag reports whether the record existed.
func (s *startOperationStore) resolveExisting(draft *startOperationRecord) (
	execution *startOperationExecution,
	joined <-chan struct{},
	err error,
	resolved bool,
) {
	existing, ok := s.published(draft.OperationID)
	if !ok {
		return nil, nil, nil, false
	}
	if err := sameOperationRequest(existing, draft); err != nil {
		return nil, nil, err, true
	}
	if done, running := s.executionDone(draft.OperationID); running {
		return nil, done, nil, true
	}
	// Terminal or unknown-without-executor: replay answers from history; the
	// operation is never re-executed.
	return nil, nil, nil, true
}

// registerExecutionCancel attaches the executor's cancellation under the same
// lock shutdown uses. A shutdown that already snapshotted this execution
// before the cancel was attached would never call it, so the closing flag is
// read under the same lock and the cancel runs outside it: either shutdown
// sees the attached cancel in its snapshot, or this call compensates — never
// both missing. The exec.cancel field is only ever read and written under
// lifeMu.
func (s *startOperationStore) registerExecutionCancel(id string, exec *startOperationExecution, cancel context.CancelFunc) {
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

// sameOperationRequest refuses to reuse an operation ID for a different
// request: the digest covers the deterministic request encoding, and a
// restore adds the artifact root (server-derived at admission, caller-pinned
// on replay) so the same path holding different content is a different
// operation. The comparison never touches the checkpoint directory.
func sameOperationRequest(existing, next *startOperationRecord) error {
	if existing.SandboxID != next.SandboxID {
		return errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"start operation %s is bound to sandbox %s, not %s",
			existing.OperationID, existing.SandboxID, next.SandboxID,
		)
	}
	if existing.RequestDigest != next.RequestDigest {
		return errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"start operation %s is bound to a different request",
			existing.OperationID,
		)
	}
	if (existing.Restore == nil) != (next.Restore == nil) {
		return errord.ToGRPCf(
			errord.ErrFailedPrecondition,
			"start operation %s is bound to a different restore artifact identity",
			existing.OperationID,
		)
	}
	if existing.Restore != nil {
		if existing.Restore.CheckpointDir != next.Restore.CheckpointDir ||
			existing.Restore.RootDigest != next.Restore.RootDigest {
			return errord.ToGRPCf(
				errord.ErrFailedPrecondition,
				"start operation %s is bound to different restore artifacts (path or content root changed)",
				existing.OperationID,
			)
		}
	}
	return nil
}

// snapshot copies the currently published record for the operation, or nil
// when unknown. It takes only the view read lock.
func (s *startOperationStore) snapshot(id string) *startOperationRecord {
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
func (s *startOperationStore) executionDone(id string) (<-chan struct{}, bool) {
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

// markSucceeded durably records the success fact and only then publishes it.
// It is the hook between the intent journal's committed write and its record
// removal: while it fails, the committed intent record stays on disk, so no
// crash window exists in which the original success fact is lost.
func (s *startOperationStore) markSucceeded(id, message string) error {
	return s.markTerminal(id, startOperationPhaseSucceeded, message, true)
}

// markFailedConfirmed durably records a fully confirmed rollback before
// publishing it.
func (s *startOperationStore) markFailedConfirmed(id, message string) error {
	return s.markTerminal(id, startOperationPhaseFailed, message, true)
}

// markUnknown records an undetermined outcome; re-execution stays forbidden.
// The unknown phase claims nothing, so it may be published in memory even
// when its durable write fails — a later restart reads the still-admitted
// record and resolves it to unknown again.
func (s *startOperationStore) markUnknown(id, message string) {
	_ = s.markTerminal(id, startOperationPhaseUnknown, message, false)
}

// markTerminal transitions the record once; later transitions are no-ops so
// executor fallbacks cannot overwrite a fact already recorded. Facts that
// claim an outcome (succeeded, failed) are durable-first and are serialized
// with every other transition under writeMu: the durable write happens while
// no query-visible lock is held, and the new phase is published only after
// the write succeeded — so while the write is slow, blocked, or failed
// (including a rename that landed but whose directory fsync failed, whose
// true outcome is unknown), concurrent readers keep seeing the previous
// phase and can never observe an unpersisted terminal fact. The unknown
// phase claims nothing and may publish even when its write fails.
func (s *startOperationStore) markTerminal(id, phase, message string, claiming bool) error {
	if s == nil || id == "" {
		return fmt.Errorf("mark start operation requires an ID")
	}
	if len(message) > startOperationMaxMsg {
		message = message[:startOperationMaxMsg]
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	record, ok := s.published(id)
	if !ok {
		return fmt.Errorf("mark start operation %s without a record", id)
	}
	if isTerminalOperationPhase(record.Phase) {
		return nil
	}
	updated := *record
	updated.Phase = phase
	updated.Message = message
	updated.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)

	if err := s.persist(&updated); err != nil {
		if claiming {
			// The published view keeps the previous phase; the flow above
			// must treat this outcome as unknown, never as the claimed fact.
			return err
		}
		logrus.Errorf("persist %s start operation %s: %v", phase, id, err)
	}
	s.publish(&updated)
	return nil
}

// persist performs the durable write behind terminal publication, through the
// test seam when installed.
func (s *startOperationStore) persist(record *startOperationRecord) error {
	if s.persistHook != nil {
		return s.persistHook(record)
	}
	return s.durablyWrite(record)
}

func isTerminalOperationPhase(phase string) bool {
	switch phase {
	case startOperationPhaseSucceeded, startOperationPhaseFailed, startOperationPhaseUnknown:
		return true
	}
	return false
}

// finishExecution releases the executor slot and wakes every joined replayer
// and a draining shutdown. It is the executor's last action, so closing done
// means the execution has fully returned.
func (s *startOperationStore) finishExecution(id string, exec *startOperationExecution) {
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

// shutdown closes admission, requests convergence of every admitted
// execution by cancelling its context, and then waits for each executor to
// actually return before letting the caller tear shared resources down.
//
// The cancel functions are snapshotted under lifeMu together with the
// executions and invoked outside it, so exec.cancel is never read or written
// across the lock; a cancel attached after the snapshot is compensated by
// registerExecutionCancel's closing check. Admission closes atomically under
// the same lock (never held across durable I/O), so a shutdown that begins
// either refuses a racing fresh admission before it executes or leaves it a
// spent unknown ID — an admission that never executes is never published as
// running. The wait is unbounded on purpose: a context deadline proves
// nothing about goroutine convergence, and tearing down resources an executor
// may still be using (filesystem state, network leases, the runtime handle)
// would break the rollback and retention invariants the Start flow enforces.
// An executor that ignores cancellation therefore blocks shutdown until it
// exits; that is the documented contract, not an accident.
func (s *startOperationStore) shutdown() {
	if s == nil {
		return
	}
	s.lifeMu.Lock()
	s.shuttingDown = true
	execs := make([]*startOperationExecution, 0, len(s.inflight))
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

func (s *startOperationStore) durablyWrite(record *startOperationRecord) error {
	s.writesMu.Lock()
	defer s.writesMu.Unlock()
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return fmt.Errorf("create start operation directory: %w", err)
	}
	if err := syncDirectory(s.rootDir); err != nil {
		return fmt.Errorf("sync start operation parent: %w", err)
	}
	path := startOperationPath(s.dir, record.OperationID)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		entries, err := os.ReadDir(s.dir)
		if err != nil {
			return err
		}
		if len(entries) >= startOperationLimit {
			return fmt.Errorf("start operation journal full; reconciliation required")
		}
	} else if err != nil {
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

// --- restore artifact root binding ---

// bindRestoreRoot derives the checkpoint directory's content-root identity
// through the shared checkpointroot package, so the server's admission and
// the runtime's restore boundary compute the identity with ONE algorithm.
// It never reads cold guest memory (lazy restore is preserved) and never
// re-hashes artifact payloads at admission: the strictness contract — sealed
// manifest shape, sidecar schema/version/mode/file/size/grid/root closure,
// coverage of every regular file, regular-files-only — lives in
// pkg/checkpointroot and refuses anything it cannot bind verifiably. The
// overlay's actual bytes are verified at the runtime's restore boundary
// against its sidecar; see doc/checkpoint-restore.md for the division.
func bindRestoreRoot(checkpointDir string) (*startOperationRestoreBinding, error) {
	binding, err := checkpointroot.Bind(checkpointDir)
	if err != nil {
		if errors.Is(err, checkpointroot.ErrUnverifiable) {
			return nil, errord.ToGRPC(fmt.Errorf("%v: %w", err, errord.ErrFailedPrecondition))
		}
		return nil, errord.ToGRPC(err)
	}
	return &startOperationRestoreBinding{
		CheckpointDir:       checkpointDir,
		RootDigest:          binding.RootDigest,
		Scheme:              binding.Scheme,
		ManifestBound:       binding.ManifestBound,
		OverlaySidecarBound: binding.OverlaySidecarBound,
	}, nil
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// startRequestDigest fingerprints a start request with deterministic proto
// encoding. Only explicitly non-semantic fields are removed: the trace ID and
// the reserved daemon-owned generation label, which Start overwrites anyway.
// Any other field difference refuses operation-ID reuse. The digest never
// touches the checkpoint directory, so replays of finished operations do not
// depend on the artifacts still existing.
func startRequestDigest(request *runtime.StartRequest) (string, error) {
	normalized := proto.Clone(request).(*runtime.StartRequest)
	normalized.TraceID = ""
	if len(normalized.Labels) > 0 {
		delete(normalized.Labels, resourceGenerationLabel)
	}
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("encode start request deterministically: %w", err)
	}
	return digestBytes(data), nil
}

// --- RPC surface ---

// StartWithOperation admits, executes, or replays one identified start.
func (h *sandboxService) StartWithOperation(
	ctx context.Context,
	request *runtime.StartWithOperationRequest,
) (*runtime.StartOperationStatus, error) {
	if request == nil {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "start operation request is nil")
	}
	if !h.recoveryReady.Load() {
		return nil, errord.ToGRPCf(errord.ErrUnavailable, "distillfs recovery is incomplete")
	}
	if !validStartOperationID(request.GetOperationID()) {
		return nil, errord.ToGRPCf(
			errord.ErrInvalidArgument,
			"operation_id must be 1-%d characters matching %s and path-free",
			startOperationMaxID, startOperationIDPattern.String(),
		)
	}
	startReq := request.GetStart()
	if startReq == nil {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "start request is required")
	}
	if !config.IsValidSandboxID(request.GetSandboxID()) {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "sandbox_id is required and must be a valid sandbox ID")
	}
	if startReq.SandboxID != "" && startReq.SandboxID != request.GetSandboxID() {
		return nil, errord.ToGRPCf(
			errord.ErrInvalidArgument,
			"start.sandbox_id %q conflicts with sandbox_id %q",
			startReq.SandboxID, request.GetSandboxID(),
		)
	}
	startReq = proto.Clone(startReq).(*runtime.StartRequest)
	startReq.SandboxID = request.GetSandboxID()

	digest, err := startRequestDigest(startReq)
	if err != nil {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "fingerprint start request: %v", err)
	}
	runtimeName := startReq.Runtime
	if runtimeName == "" {
		runtimeName = config.RuntimeNameRunsc
	}

	// Replay fast path: an existing record is answered entirely from durable
	// state — the request digest, the sandbox ID, and the caller-pinned root
	// are compared in memory, so a finished restore operation replays without
	// re-reading a checkpoint directory that may since have been deleted.
	incoming := &startOperationRecord{
		OperationID:   request.GetOperationID(),
		SandboxID:     request.GetSandboxID(),
		RequestDigest: digest,
	}
	if artifacts := request.GetRestoreArtifacts(); artifacts != nil {
		expected := artifacts.GetExpectedRootDigest()
		if len(expected) != restoreDigestHexLen {
			return nil, errord.ToGRPCf(
				errord.ErrInvalidArgument,
				"restore_artifacts.expected_root_digest must be the %d-character hex content root pin",
				restoreDigestHexLen,
			)
		}
		incoming.Restore = &startOperationRestoreBinding{
			CheckpointDir: artifacts.GetCheckpointDir(),
			RootDigest:    expected,
		}
	}
	if existing := h.startOperations.snapshot(request.GetOperationID()); existing != nil {
		if err := sameOperationRequest(existing, incoming); err != nil {
			return nil, err
		}
		if done, running := h.startOperations.executionDone(request.GetOperationID()); running {
			// A same-request replay while the admitted execution runs: wait
			// for its outcome. Caller cancellation ends only this wait.
			select {
			case <-done:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return h.startOperationStatus(request.GetOperationID())
	}

	// New admission: bind the restore artifact identity from the directory
	// itself, before any side effect, so the durable operation record states
	// exactly which content root the restore consumes.
	var restore *startOperationRestoreBinding
	if checkpoint := startReq.GetCheckpointInfo(); checkpoint != nil {
		artifacts := request.GetRestoreArtifacts()
		if artifacts == nil {
			return nil, errord.ToGRPCf(
				errord.ErrInvalidArgument,
				"restore_artifacts is required when start.checkpoint_info is set",
			)
		}
		if artifacts.GetCheckpointDir() != checkpoint.GetCheckpointDir() {
			return nil, errord.ToGRPCf(
				errord.ErrInvalidArgument,
				"restore_artifacts.checkpoint_dir must equal start.checkpoint_info.checkpoint_dir",
			)
		}
		if len(artifacts.GetExpectedRootDigest()) != restoreDigestHexLen {
			return nil, errord.ToGRPCf(
				errord.ErrInvalidArgument,
				"restore_artifacts.expected_root_digest must be the %d-character hex content root pin",
				restoreDigestHexLen,
			)
		}
		// An identified restore must be verified at the runtime's actual
		// consumption boundary; a runtime without that capability would
		// silently ignore the binding, so it is refused here instead.
		handler, ok := h.serviceHandler.Get(runtimeName)
		if !ok {
			return nil, errord.ToGRPC(errord.ErrNotImplemented)
		}
		verifier, ok := handler.(svc.CheckpointRootVerifier)
		if !ok || !verifier.SupportsCheckpointRootVerification() {
			return nil, errord.ToGRPCf(
				errord.ErrNotImplemented,
				"runtime %q does not support checkpoint root verification; identified restore operations require it",
				runtimeName,
			)
		}
		cleanDir, err := validateCheckpointInputDirectory(checkpoint.GetCheckpointDir())
		if err != nil {
			return nil, errord.ToGRPC(err)
		}
		binding, err := bindRestoreRoot(cleanDir)
		if err != nil {
			return nil, errord.ToGRPC(err)
		}
		if binding.RootDigest != artifacts.GetExpectedRootDigest() {
			return nil, errord.ToGRPCf(
				errord.ErrFailedPrecondition,
				"checkpoint content root %s does not match the expected digest %s",
				binding.RootDigest, artifacts.GetExpectedRootDigest(),
			)
		}
		restore = binding
	} else if request.GetRestoreArtifacts() != nil {
		return nil, errord.ToGRPCf(
			errord.ErrInvalidArgument,
			"restore_artifacts is only valid for restore starts",
		)
	}

	restoreRoot := ""
	if restore != nil {
		restoreRoot = restore.RootDigest
	}
	draft := &startOperationRecord{
		OperationID:   request.GetOperationID(),
		SandboxID:     request.GetSandboxID(),
		Generation:    newResourceGeneration(),
		Runtime:       runtimeName,
		RequestDigest: digest,
		Restore:       restore,
	}
	exec, joined, err := h.startOperations.admit(draft)
	if err != nil {
		return nil, err
	}
	if exec == nil {
		if joined != nil {
			select {
			case <-joined:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		// A concurrent caller won admission with the same request between the
		// fast-path check and here; its outcome is the recorded one.
		return h.startOperationStatus(request.GetOperationID())
	}
	defer h.startOperations.finishExecution(request.GetOperationID(), exec)
	if h.startOperations.admitHook != nil {
		h.startOperations.admitHook()
	}

	// The admitted work is detached from the caller's cancellation and bounded
	// by an explicit deadline; it runs in this handler goroutine, never as an
	// unbounded background goroutine. Shutdown discovers the execution under
	// the admission lock, cancels this context to request convergence, and
	// waits for the executor to actually return.
	execCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx), startOperationExecutionLimit,
	)
	defer cancel()
	h.startOperations.registerExecutionCancel(request.GetOperationID(), exec, cancel)

	binding := &startOperationBinding{
		store:       h.startOperations,
		operationID: request.GetOperationID(),
		generation:  draft.Generation,
		restoreRoot: restoreRoot,
	}
	_, startErr := func() (resp *runtime.StartResponse, err error) {
		defer func() {
			if p := recover(); p != nil {
				binding.store.markUnknown(
					binding.operationID,
					fmt.Sprintf("start operation panicked: %v", p),
				)
				panic(p)
			}
		}()
		return h.start(execCtx, startReq, binding)
	}()
	if !binding.terminal() {
		message := "start was rejected before any side effect"
		if startErr != nil {
			message = startErr.Error()
		}
		if err := h.startOperations.markFailedConfirmed(request.GetOperationID(), message); err != nil {
			// The outcome stays admitted in memory; once this executor exits,
			// an admitted record without an executor reports unknown.
			logrus.Errorf("persist failed outcome for start operation %s: %v", request.GetOperationID(), err)
		}
	}
	// Release the executor slot before building the reply so a record that
	// could not reach a terminal phase reports unknown, not eternally
	// running. The deferred call is the panic/backstop and is idempotent.
	h.startOperations.finishExecution(request.GetOperationID(), exec)
	status, err := h.startOperationStatus(request.GetOperationID())
	if err != nil {
		return nil, err
	}
	if startErr != nil {
		return status, startErr
	}
	return status, nil
}

// GetStartOperation returns the durable state of one operation and never
// creates or re-executes anything. It reads only the operation journal.
func (h *sandboxService) GetStartOperation(
	ctx context.Context,
	request *runtime.GetStartOperationRequest,
) (*runtime.StartOperationStatus, error) {
	if request == nil {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "get start operation request is nil")
	}
	if !validStartOperationID(request.GetOperationID()) {
		return nil, errord.ToGRPCf(errord.ErrInvalidArgument, "invalid operation_id")
	}
	return h.startOperationStatus(request.GetOperationID())
}

func (h *sandboxService) startOperationStatus(operationID string) (*runtime.StartOperationStatus, error) {
	record := h.startOperations.snapshot(operationID)
	if record == nil {
		return nil, errord.ToGRPCf(errord.ErrNotFound, "start operation %s is unknown", operationID)
	}
	status := &runtime.StartOperationStatus{
		OperationID:        record.OperationID,
		SandboxID:          record.SandboxID,
		ResourceGeneration: record.Generation,
		Message:            record.Message,
	}
	switch record.Phase {
	case startOperationPhaseAdmitted:
		if _, running := h.startOperations.executionDone(operationID); running {
			status.State = runtime.StartOperationState_START_OPERATION_STATE_RUNNING
			status.Message = "operation admitted; outcome pending"
			return status, nil
		}
		// Admitted without an executor: the daemon restarted or the terminal
		// write failed; either way the outcome is unproven and the ID is spent.
		status.State = runtime.StartOperationState_START_OPERATION_STATE_UNKNOWN
		status.Message = "operation outcome was not durably recorded; treat as unknown, re-execution forbidden"
		return status, nil
	case startOperationPhaseSucceeded:
		status.State = runtime.StartOperationState_START_OPERATION_STATE_SUCCEEDED
		if status.Message == "" {
			status.Message = "start succeeded; historical fact, not a liveness claim"
		}
	case startOperationPhaseFailed:
		status.State = runtime.StartOperationState_START_OPERATION_STATE_FAILED
	case startOperationPhaseUnknown:
		status.State = runtime.StartOperationState_START_OPERATION_STATE_UNKNOWN
	default:
		return nil, errord.ToGRPCf(errord.ErrUnknown, "start operation %s has invalid phase %q", operationID, record.Phase)
	}
	return status, nil
}

// startOperationBinding is the trusted server-side operation handle Start
// consumes. It carries the daemon-assigned generation (a caller label can
// never choose it) and records the operation's terminal facts at the exact
// ordering points the start flow reaches.
type startOperationBinding struct {
	store       *startOperationStore
	operationID string
	generation  string
	// restoreRoot is the admission-bound checkpoint content root an
	// identified restore hands to the runtime; empty for fresh starts and
	// for the legacy Start flow.
	restoreRoot string
}

func (b *startOperationBinding) terminal() bool {
	record := b.store.snapshot(b.operationID)
	return record != nil && isTerminalOperationPhase(record.Phase)
}

// expectedCheckpointRoot exposes the admission-bound content root to the
// start flow; the legacy Start (nil binding) carries none.
func (b *startOperationBinding) expectedCheckpointRoot() string {
	if b == nil {
		return ""
	}
	return b.restoreRoot
}
