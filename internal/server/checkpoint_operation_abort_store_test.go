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
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// These tests cover the internal abort primitives of the checkpoint operation
// store — the version-3 record schema, the explicit abortable admission, and
// the abort slot's dedicated failure transition — which no public RPC reaches
// yet. They are store semantics only: the confirmed failures they land stand
// for a runtime abort the later abort service stage has verified, never for
// evidence the store accepted on its own, and nothing here exercises a
// runtime Abort call.

// seedAbortableOperationRecord writes one durable version-3 journal record —
// the state an abortable admission leaves behind after a restart or once its
// executor is spent.
func seedAbortableOperationRecord(
	t *testing.T,
	root string,
	request *runtime.CheckpointWithOperationRequest,
	phase string,
	confirmed bool,
	artifact *checkpointOperationArtifact,
) *checkpointOperationRecord {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	record := &checkpointOperationRecord{
		Version:        checkpointOperationRecordVersionAbortable,
		OperationID:    request.GetOperationID(),
		SandboxID:      request.GetCheckpoint().GetID(),
		Generation:     request.GetExpectedGeneration(),
		Runtime:        config.RuntimeNameRunsc,
		CheckpointDir:  filepath.Clean(request.GetCheckpoint().GetCheckpointDir()),
		RequestDigest:  requestDigestOf(t, request),
		Phase:          phase,
		Artifact:       artifact,
		CreatedAt:      now,
		UpdatedAt:      now,
		Message:        "seeded abortable record",
		AbortConfirmed: confirmed,
	}
	seedCheckpointOperationRecord(t, root, record)
	return record
}

// abortDraftForRequest rebuilds the identity an abort caller submits: exactly
// the complete identity a recovery submits, because an abort must authorize
// itself with the original request alone.
func abortDraftForRequest(
	t *testing.T,
	request *runtime.CheckpointWithOperationRequest,
) *checkpointOperationRecord {
	t.Helper()
	return recoveryDraftForRequest(t, request)
}

// admitAbort is the direct store admission the later abort service stage will
// call after its own request validation and runtime-capability verification.
func admitAbort(
	t *testing.T,
	s *sandboxService,
	request *runtime.CheckpointWithOperationRequest,
) (*checkpointOperationAbort, <-chan struct{}) {
	t.Helper()
	abort, joined, err := s.checkpointOperations.abortExistingContext(
		context.Background(), abortDraftForRequest(t, request))
	require.NoError(t, err)
	return abort, joined
}

// --- the version-3 record schema ---

// TestCheckpointOperationAbortableRecordSchema pins the abort confirmation's
// binding rules and the JSON compatibility: only a FAILED version-3 record may
// carry it, the flag is omitted when false so older JSON is byte-stable, and
// a restart loads confirmed history unchanged.
func TestCheckpointOperationAbortableRecordSchema(t *testing.T) {
	validDigest := strings.Repeat("a", checkpointroot.DigestHexLen)
	base := func(phase string) *checkpointOperationRecord {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		record := &checkpointOperationRecord{
			Version:       checkpointOperationRecordVersionAbortable,
			OperationID:   "op-abort-schema",
			SandboxID:     "sbox-abort-schema",
			Generation:    "gen-1",
			Runtime:       config.RuntimeNameRunsc,
			CheckpointDir: "/tmp/abort-schema-checkpoint",
			RequestDigest: validDigest,
			Phase:         phase,
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		if phase == checkpointOperationPhaseSucceeded {
			record.Artifact = &checkpointOperationArtifact{
				RootDigest: strings.Repeat("b", checkpointroot.DigestHexLen),
				Scheme:     checkpointroot.Scheme,
			}
		}
		return record
	}

	t.Run("validation binds the flag to a failed version-3 record", func(t *testing.T) {
		confirmed := base(checkpointOperationPhaseFailed)
		confirmed.AbortConfirmed = true
		require.NoError(t, validateCheckpointOperationRecord(confirmed))

		ordinary := base(checkpointOperationPhaseFailed)
		require.NoError(t, validateCheckpointOperationRecord(ordinary),
			"an ordinary v3 failure keeps the flag false and stays valid")

		for name, mutate := range map[string]func(*checkpointOperationRecord){
			"v3 admitted with confirmation": func(r *checkpointOperationRecord) {
				r.AbortConfirmed = true
			},
			"v3 unknown with confirmation": func(r *checkpointOperationRecord) {
				r.Phase = checkpointOperationPhaseUnknown
				r.AbortConfirmed = true
			},
			"v3 succeeded with confirmation": func(r *checkpointOperationRecord) {
				r.AbortConfirmed = true
			},
			"v2 failed with confirmation": func(r *checkpointOperationRecord) {
				r.Version = checkpointOperationRecordVersionWitness
				r.Phase = checkpointOperationPhaseFailed
				r.AbortConfirmed = true
			},
			"v1 failed with confirmation": func(r *checkpointOperationRecord) {
				r.Version = checkpointOperationRecordVersionLegacy
				r.Phase = checkpointOperationPhaseFailed
				r.AbortConfirmed = true
			},
			"confirmed failure beside a sealed root": func(r *checkpointOperationRecord) {
				r.AbortConfirmed = true
				r.Artifact = &checkpointOperationArtifact{
					RootDigest: strings.Repeat("b", checkpointroot.DigestHexLen),
					Scheme:     checkpointroot.Scheme,
				}
			},
			"unsupported version": func(r *checkpointOperationRecord) {
				r.Version = checkpointOperationRecordVersionAbortable + 1
			},
		} {
			t.Run(name, func(t *testing.T) {
				// The succeeded base keeps its artifact binding; every other
				// case starts from a record whose remaining shape is valid.
				record := base(checkpointOperationPhaseSucceeded)
				record.Phase = checkpointOperationPhaseSucceeded
				mutate(record)
				assert.Error(t, validateCheckpointOperationRecord(record))
			})
		}
		// The unchanged root-artifact rule: success still requires the sealed
		// root and nothing else may carry one.
		succeeded := base(checkpointOperationPhaseSucceeded)
		require.NoError(t, validateCheckpointOperationRecord(succeeded))
	})

	t.Run("JSON keeps old records byte-stable and round-trips the flag", func(t *testing.T) {
		confirmed := base(checkpointOperationPhaseFailed)
		confirmed.AbortConfirmed = true
		data, err := json.Marshal(confirmed)
		require.NoError(t, err)
		assert.Contains(t, string(data), `"abort_confirmed":true`)

		decoded, err := decodeCheckpointOperationRecord(data)
		require.NoError(t, err)
		assert.True(t, decoded.AbortConfirmed)
		assert.Equal(t, checkpointOperationPhaseFailed, decoded.Phase)
		assert.Equal(t, checkpointOperationRecordVersionAbortable, decoded.Version)

		for name, record := range map[string]*checkpointOperationRecord{
			"ordinary v3 failure": func() *checkpointOperationRecord {
				r := base(checkpointOperationPhaseFailed)
				return r
			}(),
			"v3 admitted":  base(checkpointOperationPhaseAdmitted),
			"v3 succeeded": base(checkpointOperationPhaseSucceeded),
			"v2 failed": func() *checkpointOperationRecord {
				r := base(checkpointOperationPhaseFailed)
				r.Version = checkpointOperationRecordVersionWitness
				return r
			}(),
			"v1 failed": func() *checkpointOperationRecord {
				r := base(checkpointOperationPhaseFailed)
				r.Version = checkpointOperationRecordVersionLegacy
				return r
			}(),
		} {
			data, err := json.Marshal(record)
			require.NoError(t, err)
			assert.NotContains(t, string(data), "abort_confirmed", "%s must not grow the field", name)
			decoded, err := decodeCheckpointOperationRecord(data)
			require.NoError(t, err, "%s must keep decoding", name)
			assert.False(t, decoded.AbortConfirmed)
		}

		// A record written before the flag existed decodes with it false.
		now := time.Now().UTC().Format(time.RFC3339Nano)
		legacy := fmt.Sprintf(
			`{"version":2,"operation_id":"op-abort-old","sandbox_id":"sbox-abort-old","generation":"gen-1",`+
				`"runtime":"runsc","checkpoint_dir":"/tmp/abort-schema-checkpoint","request_digest":"%s",`+
				`"phase":"failed","created_at":"%s","updated_at":"%s"}`,
			validDigest, now, now)
		decoded, err = decodeCheckpointOperationRecord([]byte(legacy))
		require.NoError(t, err)
		assert.False(t, decoded.AbortConfirmed)
	})

	t.Run("a restart loads confirmed history unchanged and spends admitted records", func(t *testing.T) {
		root := t.TempDir()
		directory := filepath.Join(t.TempDir(), "checkpoint")
		request := checkpointOperationRequest("op-abort-restart", "sbox-abort-restart", directory, "gen-1", 30)
		confirmed := seedAbortableOperationRecord(t, root, request, checkpointOperationPhaseFailed, true, nil)
		admitted := seedAbortableOperationRecord(t, root,
			checkpointOperationRequest("op-abort-restart-adm", "sbox-abort-restart", directory, "gen-1", 30),
			checkpointOperationPhaseAdmitted, false, nil)

		store, err := loadCheckpointOperations(root)
		require.NoError(t, err)
		loaded, ok := store.published("op-abort-restart")
		require.True(t, ok)
		assert.Equal(t, checkpointOperationPhaseFailed, loaded.Phase)
		assert.True(t, loaded.AbortConfirmed)
		assert.Nil(t, loaded.Artifact)
		// The confirmed fact was not rewritten: only the load-time spent of the
		// admitted record wrote anything.
		assert.Equal(t, confirmed.UpdatedAt,
			readJournalCheckpointOperation(t, root, "op-abort-restart").UpdatedAt)
		assert.Equal(t, checkpointOperationPhaseUnknown,
			readJournalCheckpointOperation(t, root, "op-abort-restart-adm").Phase)
		assert.Equal(t, checkpointOperationPhaseAdmitted, admitted.Phase,
			"the seeder's in-memory copy is untouched")
	})
}

// --- the explicit abortable admission against the existing default ---

// TestCheckpointOperationAbortableAdmissionVersions pins the admission split:
// the plain admit keeps writing version-2 records for every current caller,
// only the explicit abortable entry writes version 3, and an operation that is
// already recorded replays from history without changing its version in
// either direction. The public RPC keeps admitting version 2 only.
func TestCheckpointOperationAbortableAdmissionVersions(t *testing.T) {
	draft := func(operationID string) *checkpointOperationRecord {
		return &checkpointOperationRecord{
			OperationID:   operationID,
			SandboxID:     "sbox-abort-versions",
			Generation:    "gen-1",
			Runtime:       config.RuntimeNameRunsc,
			CheckpointDir: "/tmp/abort-versions-checkpoint",
			RequestDigest: strings.Repeat("a", checkpointroot.DigestHexLen),
		}
	}

	t.Run("the plain admission keeps writing version 2", func(t *testing.T) {
		root := t.TempDir()
		store, err := loadCheckpointOperations(root)
		require.NoError(t, err)
		exec, joined, err := store.admit(draft("op-abort-plain"))
		require.NoError(t, err)
		require.NotNil(t, exec)
		assert.Nil(t, joined)
		record := readJournalCheckpointOperation(t, root, "op-abort-plain")
		assert.Equal(t, checkpointOperationRecordVersionWitness, record.Version)
		assert.Equal(t, checkpointOperationPhaseAdmitted, record.Phase)
		assert.False(t, record.AbortConfirmed)
		store.finishExecution("op-abort-plain", exec)
	})

	t.Run("the explicit abortable admission writes version 3", func(t *testing.T) {
		root := t.TempDir()
		store, err := loadCheckpointOperations(root)
		require.NoError(t, err)
		exec, joined, err := store.admitAbortable(draft("op-abort-explicit"))
		require.NoError(t, err)
		require.NotNil(t, exec)
		assert.Nil(t, joined)
		record := readJournalCheckpointOperation(t, root, "op-abort-explicit")
		assert.Equal(t, checkpointOperationRecordVersionAbortable, record.Version)
		assert.Equal(t, checkpointOperationPhaseAdmitted, record.Phase)
		assert.False(t, record.AbortConfirmed)
		// The abortable admission is a first-class executor: it holds the
		// shared slot until it is released.
		_, running := store.executionDone("op-abort-explicit")
		assert.True(t, running)
		store.finishExecution("op-abort-explicit", exec)
	})

	t.Run("an existing record replays without changing version", func(t *testing.T) {
		root := t.TempDir()
		store, err := loadCheckpointOperations(root)
		require.NoError(t, err)
		witnessDraft := draft("op-abort-replay")
		exec, _, err := store.admit(witnessDraft)
		require.NoError(t, err)
		require.NotNil(t, exec)
		store.finishExecution("op-abort-replay", exec)
		// An abortable admission of the already-recorded v2 operation replays
		// from history; it neither upgrades the record nor runs anything.
		execUp, joinedUp, err := store.admitAbortable(witnessDraft)
		require.NoError(t, err)
		assert.Nil(t, execUp)
		assert.Nil(t, joinedUp)
		record := readJournalCheckpointOperation(t, root, "op-abort-replay")
		assert.Equal(t, checkpointOperationRecordVersionWitness, record.Version)

		abortableDraft := draft("op-abort-replay-v3")
		exec3, _, err := store.admitAbortable(abortableDraft)
		require.NoError(t, err)
		require.NotNil(t, exec3)
		store.finishExecution("op-abort-replay-v3", exec3)
		// The plain admission of the already-recorded v3 operation replays
		// without downgrading it.
		execDown, joinedDown, err := store.admit(abortableDraft)
		require.NoError(t, err)
		assert.Nil(t, execDown)
		assert.Nil(t, joinedDown)
		assert.Equal(t, checkpointOperationRecordVersionAbortable,
			readJournalCheckpointOperation(t, root, "op-abort-replay-v3").Version)
	})

	t.Run("the public RPC admits by runtime capability", func(t *testing.T) {
		handler := newCheckpointOperationRuntimeHandler()
		root := t.TempDir()
		s := newCheckpointOperationService(t, handler, root)
		storeCheckpointOperationSandbox(t, s, "sbox-abort-public", "gen-1")
		directory := filepath.Join(t.TempDir(), "checkpoint")
		request := checkpointOperationRequest("op-abort-public", "sbox-abort-public", directory, "gen-1", 30)

		// A witness-only runtime keeps admitting version-2 records: the
		// abortable protocol is gated on the runtime's explicit abort
		// capability, not on the server revision.
		reply, err := s.CheckpointWithOperation(context.Background(), request)
		require.NoError(t, err)
		assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, reply.GetState())
		assert.Equal(t, checkpointOperationRecordVersionWitness,
			readJournalCheckpointOperation(t, root, "op-abort-public").Version)

		// A seeded version-3 record replays through the public RPC without
		// executing and without being downgraded, and the public recovery now
		// reconciles it through the same witness protocol as version 2.
		v3Root := t.TempDir()
		v3Directory := filepath.Join(t.TempDir(), "checkpoint")
		artifact := sealedRootArtifact(t, v3Directory)
		v3Request := checkpointOperationRequest("op-abort-public-v3", "sbox-abort-public", v3Directory, "gen-1", 30)
		seedAbortableOperationRecord(t, v3Root, v3Request, checkpointOperationPhaseUnknown, false, nil)
		v3Handler := newCheckpointOperationRuntimeHandler()
		v3Handler.witnessDirectory = v3Directory
		v3Service := newCheckpointOperationService(t, v3Handler, v3Root)
		replayed, rerr := v3Service.CheckpointWithOperation(context.Background(), v3Request)
		require.NoError(t, rerr)
		assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN, replayed.GetState())
		assert.Equal(t, checkpointOperationRecordVersionAbortable,
			readJournalCheckpointOperation(t, v3Root, "op-abort-public-v3").Version)

		recovered, rerr := v3Service.RecoverCheckpointOperation(
			context.Background(), witnessRecoveryRequest(v3Request, 30))
		require.NoError(t, rerr)
		assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_SUCCEEDED, recovered.GetState())
		assert.Equal(t, runtime.CheckpointOperationRecoveryProtocol_CHECKPOINT_OPERATION_RECOVERY_PROTOCOL_WITNESS_ABORTABLE,
			recovered.GetRecoveryProtocol())
		assert.True(t, recovered.GetEvidenceReleased())
		assert.Equal(t, artifact.RootDigest, recovered.GetArtifactRootDigest())
		assert.Zero(t, v3Handler.checkpointCount(), "an abortable record never re-executes the runtime")
	})
}

// --- abort eligibility ---

// TestCheckpointOperationAbortAdmissionEligibility pins which records an abort
// may take over: only an exact-binding abortable one. The undetermined phases
// yield the abort slot, a confirmed failure yields the acknowledgment-only
// slot, and everything else — missing, conflicting, succeeded, ordinary
// failure, and every pre-abortable version — is refused without a write.
func TestCheckpointOperationAbortAdmissionEligibility(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "checkpoint")
	request := checkpointOperationRequest("op-abort-elig", "sbox-abort-elig", directory, "gen-1", 30)

	t.Run("missing record is NotFound with zero writes", func(t *testing.T) {
		fresh := t.TempDir()
		s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), fresh)
		abort, joined, err := s.checkpointOperations.abortExistingContext(
			context.Background(), abortDraftForRequest(t, request))
		assert.Nil(t, abort)
		assert.Nil(t, joined)
		assert.Equal(t, codes.NotFound, status.Code(err))
		assert.Zero(t, journalRecordCount(t, fresh), "an abort must not create the record it aborts")
	})

	root := t.TempDir()
	seedAbortableOperationRecord(t, root, request, checkpointOperationPhaseUnknown, false, nil)
	s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)

	t.Run("binding conflicts are refused", func(t *testing.T) {
		for name, conflicting := range map[string]*runtime.CheckpointWithOperationRequest{
			"different sandbox":    checkpointOperationRequest("op-abort-elig", "sbox-abort-other", directory, "gen-1", 30),
			"different generation": checkpointOperationRequest("op-abort-elig", "sbox-abort-elig", directory, "gen-2", 30),
			"different directory":  checkpointOperationRequest("op-abort-elig", "sbox-abort-elig", filepath.Join(t.TempDir(), "other"), "gen-1", 30),
			"different digest":     checkpointOperationRequest("op-abort-elig", "sbox-abort-elig", directory, "gen-1", 31),
		} {
			abort, joined, err := s.checkpointOperations.abortExistingContext(
				context.Background(), abortDraftForRequest(t, conflicting))
			assert.Nil(t, abort, name)
			assert.Nil(t, joined, name)
			assert.Equal(t, codes.FailedPrecondition, status.Code(err), name)
		}
		assert.Equal(t, 1, journalRecordCount(t, root), "a refused abort must not write the journal")
		assert.Equal(t, checkpointOperationPhaseUnknown,
			readJournalCheckpointOperation(t, root, "op-abort-elig").Phase)
	})

	t.Run("older versions are refused as not abortable", func(t *testing.T) {
		// Version 1 through the legacy seeder...
		v1Root := t.TempDir()
		v1Request := checkpointOperationRequest("op-abort-elig-v1", "sbox-abort-elig", directory, "gen-1", 30)
		seedCheckpointOperationRecord(t, v1Root, seededCheckpointOperationRecord(
			v1Request, config.RuntimeNameRunsc, requestDigestOf(t, v1Request),
			checkpointOperationPhaseUnknown, "outcome unproven, re-execution forbidden"))
		v1 := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), v1Root)
		// ...and version 2 through the witness seeder: neither record promised
		// the runtime can retire the operation, so neither may be aborted.
		v2Root := t.TempDir()
		v2Request := checkpointOperationRequest("op-abort-elig-v2", "sbox-abort-elig", directory, "gen-1", 30)
		seedWitnessOperationRecord(t, v2Root, v2Request, checkpointOperationPhaseUnknown, nil)
		v2 := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), v2Root)

		for name, tc := range map[string]struct {
			s       *sandboxService
			request *runtime.CheckpointWithOperationRequest
			version int
		}{
			"version 1": {v1, v1Request, checkpointOperationRecordVersionLegacy},
			"version 2": {v2, v2Request, checkpointOperationRecordVersionWitness},
		} {
			abort, joined, err := tc.s.checkpointOperations.abortExistingContext(
				context.Background(), abortDraftForRequest(t, tc.request))
			assert.Nil(t, abort, name)
			assert.Nil(t, joined, name)
			assert.Equal(t, codes.FailedPrecondition, status.Code(err), name)
			assert.ErrorContains(t, err, "abortable protocol", name)
			assert.Equal(t, tc.version,
				readJournalCheckpointOperation(t, tc.s.config.RootDir, tc.request.GetOperationID()).Version, name)
		}
	})

	t.Run("succeeded and ordinary failures are refused", func(t *testing.T) {
		for name, seed := range map[string]struct {
			phase     string
			confirmed bool
		}{
			"succeeded":        {checkpointOperationPhaseSucceeded, false},
			"ordinary failure": {checkpointOperationPhaseFailed, false},
		} {
			refusedRoot := t.TempDir()
			refusedRequest := checkpointOperationRequest(
				"op-abort-elig-refused", "sbox-abort-elig", directory, "gen-1", 30)
			if seed.phase == checkpointOperationPhaseSucceeded {
				seedAbortableOperationRecord(t, refusedRoot, refusedRequest, seed.phase, seed.confirmed,
					&checkpointOperationArtifact{RootDigest: strings.Repeat("b", checkpointroot.DigestHexLen), Scheme: checkpointroot.Scheme})
			} else {
				seedAbortableOperationRecord(t, refusedRoot, refusedRequest, seed.phase, seed.confirmed, nil)
			}
			refused := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), refusedRoot)
			abort, joined, err := refused.checkpointOperations.abortExistingContext(
				context.Background(), abortDraftForRequest(t, refusedRequest))
			assert.Nil(t, abort, name)
			assert.Nil(t, joined, name)
			assert.Equal(t, codes.FailedPrecondition, status.Code(err), name)
			assert.Equal(t, seed.phase,
				readJournalCheckpointOperation(t, refusedRoot, "op-abort-elig-refused").Phase, name)
		}
	})

	t.Run("an ordinary failed v3 record produced by the original semantics stays unauditable", func(t *testing.T) {
		failedRoot := t.TempDir()
		failedRequest := checkpointOperationRequest(
			"op-abort-elig-ordinary", "sbox-abort-elig", directory, "gen-1", 30)
		failed := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), failedRoot)
		draft := &checkpointOperationRecord{
			OperationID:   failedRequest.GetOperationID(),
			SandboxID:     "sbox-abort-elig",
			Generation:    "gen-1",
			Runtime:       config.RuntimeNameRunsc,
			CheckpointDir: filepath.Clean(directory),
			RequestDigest: requestDigestOf(t, failedRequest),
		}
		exec, _, err := failed.checkpointOperations.admitAbortable(draft)
		require.NoError(t, err)
		require.NotNil(t, exec)
		require.NoError(t, failed.checkpointOperations.markFailedConfirmed(
			failedRequest.GetOperationID(), "checkpoint was refused before any side effect"))
		failed.checkpointOperations.finishExecution(failedRequest.GetOperationID(), exec)
		record := readJournalCheckpointOperation(t, failedRoot, "op-abort-elig-ordinary")
		assert.Equal(t, checkpointOperationPhaseFailed, record.Phase)
		assert.False(t, record.AbortConfirmed,
			"the ordinary FAILED semantics stay exactly as they were for v3 records")

		abort, joined, err := failed.checkpointOperations.abortExistingContext(
			context.Background(), abortDraftForRequest(t, failedRequest))
		assert.Nil(t, abort)
		assert.Nil(t, joined)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.ErrorContains(t, err, "ordinary failure")
	})

	t.Run("undetermined phases grant the abort slot", func(t *testing.T) {
		for _, phase := range []string{checkpointOperationPhaseUnknown, checkpointOperationPhaseAdmitted} {
			undeterminedRoot := t.TempDir()
			undetermined := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), undeterminedRoot)
			draft := &checkpointOperationRecord{
				OperationID:   "op-abort-elig-undetermined",
				SandboxID:     "sbox-abort-elig",
				Generation:    "gen-1",
				Runtime:       config.RuntimeNameRunsc,
				CheckpointDir: filepath.Clean(directory),
				RequestDigest: requestDigestOf(t, request),
			}
			exec, _, err := undetermined.checkpointOperations.admitAbortable(draft)
			require.NoError(t, err)
			require.NotNil(t, exec)
			if phase == checkpointOperationPhaseAdmitted {
				// A slot released without a terminal fact leaves the published
				// record admitted with no executor — the restart-equivalent
				// shape an abort must be able to take over.
				undetermined.checkpointOperations.finishExecution(draft.OperationID, exec)
			} else {
				undetermined.checkpointOperations.markUnknown(draft.OperationID, "outcome unproven")
				undetermined.checkpointOperations.finishExecution(draft.OperationID, exec)
			}
			seeded := readJournalCheckpointOperation(t, undeterminedRoot, draft.OperationID)
			undeterminedRequest := checkpointOperationRequest(
				"op-abort-elig-undetermined", "sbox-abort-elig", directory, "gen-1", 30)
			// The on-disk shape for the admitted case is the one the loader
			// spends; rebuild the service to load it as it would restart.
			if phase == checkpointOperationPhaseAdmitted {
				undetermined = newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), undeterminedRoot)
			}

			abort, joined := admitAbort(t, undetermined, undeterminedRequest)
			require.NotNil(t, abort, phase)
			assert.Nil(t, joined, phase)
			assert.False(t, abort.acknowledgmentOnly(), phase)
			_, running := undetermined.checkpointOperations.executionDone(draft.OperationID)
			assert.True(t, running, "%s: the abort slot is a registered executor", phase)
			// Admission wrote nothing: the record is byte-identical.
			current := readJournalCheckpointOperation(t, undeterminedRoot, draft.OperationID)
			if phase == checkpointOperationPhaseAdmitted {
				assert.Equal(t, checkpointOperationPhaseUnknown, current.Phase,
					"the loader spends admitted records before anything may abort them")
			} else {
				assert.Equal(t, seeded, current, phase)
			}
			abort.finish()
		}
	})

	t.Run("a confirmed failure grants the acknowledgment-only slot", func(t *testing.T) {
		confirmedRoot := t.TempDir()
		confirmedRequest := checkpointOperationRequest(
			"op-abort-elig-confirmed", "sbox-abort-elig", directory, "gen-1", 30)
		seeded := seedAbortableOperationRecord(
			t, confirmedRoot, confirmedRequest, checkpointOperationPhaseFailed, true, nil)
		confirmed := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), confirmedRoot)

		abort, joined := admitAbort(t, confirmed, confirmedRequest)
		require.NotNil(t, abort)
		assert.Nil(t, joined)
		assert.True(t, abort.acknowledgmentOnly())
		_, running := confirmed.checkpointOperations.executionDone("op-abort-elig-confirmed")
		assert.True(t, running, "an acknowledgment-only abort slot is a tracked executor")
		// The durable fact is the authority: admission rewrites nothing.
		assert.Equal(t, seeded, readJournalCheckpointOperation(t, confirmedRoot, "op-abort-elig-confirmed"))

		// A second abort of the confirmed record joins the acknowledgment-only
		// slot rather than gaining a second executor, and the idempotent
		// confirmation rewrites nothing while the joiner waits.
		second, joinedSecond, jerr := confirmed.checkpointOperations.abortExistingContext(
			context.Background(), abortDraftForRequest(t, confirmedRequest))
		require.NoError(t, jerr)
		assert.Nil(t, second)
		require.NotNil(t, joinedSecond)
		var ackDone <-chan struct{} = abort.exec.done
		assert.Equal(t, ackDone, joinedSecond)
		require.NoError(t, abort.markAborted("acknowledgment retry"))
		assert.Equal(t, seeded, readJournalCheckpointOperation(t, confirmedRoot, "op-abort-elig-confirmed"))

		abort.finish()
		select {
		case <-joinedSecond:
		default:
			t.Fatal("the joining abort outlived the acknowledgment-only executor")
		}
		_, running = confirmed.checkpointOperations.executionDone("op-abort-elig-confirmed")
		assert.False(t, running)
		assert.Equal(t, seeded, readJournalCheckpointOperation(t, confirmedRoot, "op-abort-elig-confirmed"))
	})
}

// --- the shared single execution slot ---

// TestCheckpointOperationAbortJoinsAnyExecutor pins that an abort never runs
// beside another executor of the same operation: it joins the original
// execution, an earlier recovery, or an earlier abort through the very same
// done channel, and concurrent abort applicants converge on one slot.
func TestCheckpointOperationAbortJoinsAnyExecutor(t *testing.T) {
	t.Run("joins a running original execution", func(t *testing.T) {
		root := t.TempDir()
		store, err := loadCheckpointOperations(root)
		require.NoError(t, err)
		request := checkpointOperationRequest(
			"op-abort-join-original", "sbox-abort-join", "/tmp/abort-join-original", "gen-1", 30)
		draft := abortDraftForRequest(t, request)
		draft.Runtime = config.RuntimeNameRunsc
		exec, _, err := store.admitAbortable(draft)
		require.NoError(t, err)
		require.NotNil(t, exec)
		defer store.finishExecution(request.GetOperationID(), exec)

		abort, joined, err := store.abortExistingContext(context.Background(), abortDraftForRequest(t, request))
		require.NoError(t, err)
		assert.Nil(t, abort, "a live executor must not gain a second slot")
		require.NotNil(t, joined)
		originalDone, running := store.executionDone(request.GetOperationID())
		require.True(t, running)
		assert.Equal(t, originalDone, joined)

		store.finishExecution(request.GetOperationID(), exec)
		select {
		case <-joined:
		case <-time.After(5 * time.Second):
			t.Fatal("the abort did not observe the original executor's exit")
		}
	})

	t.Run("joins a running recovery executor", func(t *testing.T) {
		root := t.TempDir()
		directory := filepath.Join(t.TempDir(), "checkpoint")
		request := checkpointOperationRequest("op-abort-join-recovery", "sbox-abort-join", directory, "gen-1", 30)
		seedAbortableOperationRecord(t, root, request, checkpointOperationPhaseUnknown, false, nil)
		s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)
		recovery, _ := admitRecovery(t, s, request)
		require.NotNil(t, recovery)
		defer recovery.finish()

		abort, joined := admitAbort(t, s, request)
		assert.Nil(t, abort)
		require.NotNil(t, joined)
		recoveryDone, running := s.checkpointOperations.executionDone("op-abort-join-recovery")
		require.True(t, running)
		assert.Equal(t, recoveryDone, joined)
		recovery.finish()
		select {
		case <-joined:
		case <-time.After(5 * time.Second):
			t.Fatal("the abort did not observe the recovery executor's exit")
		}
	})

	t.Run("a public replay joins a running abort executor", func(t *testing.T) {
		root := t.TempDir()
		directory := filepath.Join(t.TempDir(), "checkpoint")
		request := checkpointOperationRequest("op-abort-join-replay", "sbox-abort-join", directory, "gen-1", 30)
		handler := newCheckpointOperationRuntimeHandler()
		s := newCheckpointOperationService(t, handler, root)
		abort := func() *checkpointOperationAbort {
			draft := &checkpointOperationRecord{
				OperationID:   request.GetOperationID(),
				SandboxID:     "sbox-abort-join",
				Generation:    "gen-1",
				Runtime:       config.RuntimeNameRunsc,
				CheckpointDir: filepath.Clean(directory),
				RequestDigest: requestDigestOf(t, request),
			}
			exec, _, err := s.checkpointOperations.admitAbortable(draft)
			require.NoError(t, err)
			require.NotNil(t, exec)
			s.checkpointOperations.markUnknown(request.GetOperationID(), "outcome unproven")
			// Release the admission executor first, so the abort wins its own
			// slot instead of joining the admission.
			s.checkpointOperations.finishExecution(request.GetOperationID(), exec)
			a, joined, err := s.checkpointOperations.abortExistingContext(
				context.Background(), abortDraftForRequest(t, request))
			require.NoError(t, err)
			require.NotNil(t, a)
			assert.Nil(t, joined)
			return a
		}()
		defer abort.finish()

		replayDone := make(chan *runtime.CheckpointOperationStatus, 1)
		go func() {
			replayed, rerr := s.CheckpointWithOperation(context.Background(), request)
			require.NoError(t, rerr)
			replayDone <- replayed
		}()
		select {
		case replayed := <-replayDone:
			t.Fatalf("the replay answered before the abort recorded its outcome: %+v", replayed)
		case <-time.After(200 * time.Millisecond):
		}
		require.NoError(t, abort.markAborted("runtime confirmed the abort"))
		abort.finish()

		select {
		case replayed := <-replayDone:
			require.NotNil(t, replayed)
			assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED, replayed.GetState())
		case <-time.After(5 * time.Second):
			t.Fatal("the replay did not resolve after the abort completed")
		}
		assert.Zero(t, handler.checkpointCount(), "a replay joining an abort must not execute the runtime")
		assert.Equal(t, checkpointOperationRecordVersionAbortable,
			readJournalCheckpointOperation(t, root, "op-abort-join-replay").Version)
	})

	t.Run("concurrent abort applicants share one slot", func(t *testing.T) {
		root := t.TempDir()
		directory := filepath.Join(t.TempDir(), "checkpoint")
		request := checkpointOperationRequest("op-abort-join-race", "sbox-abort-join", directory, "gen-1", 30)
		seedAbortableOperationRecord(t, root, request, checkpointOperationPhaseUnknown, false, nil)
		s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)

		const applicants = 8
		draft := abortDraftForRequest(t, request)
		var mu sync.Mutex
		var winner *checkpointOperationAbort
		var winnerDone <-chan struct{}
		joins := make([]<-chan struct{}, 0, applicants)
		errs := make([]error, applicants)
		started := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < applicants; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-started
				abort, joined, err := s.checkpointOperations.abortExistingContext(context.Background(), draft)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					errs[i] = err
					return
				}
				if abort != nil {
					if winner != nil {
						errs[i] = fmt.Errorf("a second abort slot was granted")
						return
					}
					winner = abort
					winnerDone = abort.exec.done
					return
				}
				if joined == nil {
					errs[i] = fmt.Errorf("a losing applicant was given no executor to join")
					return
				}
				joins = append(joins, joined)
			}(i)
		}
		close(started)
		wg.Wait()
		for i, err := range errs {
			require.NoErrorf(t, err, "applicant %d", i)
		}
		require.NotNil(t, winner, "no applicant won the abort slot")
		require.Len(t, joins, applicants-1)
		require.NoError(t, winner.markAborted("runtime confirmed the abort"))
		winner.finish()
		for _, joined := range joins {
			assert.Equal(t, winnerDone, joined, "every applicant joined the winner's executor")
			select {
			case <-joined:
			default:
				t.Fatal("a joined applicant outlived the winning abort executor")
			}
		}
		record := readJournalCheckpointOperation(t, root, "op-abort-join-race")
		assert.Equal(t, checkpointOperationPhaseFailed, record.Phase)
		assert.True(t, record.AbortConfirmed)
	})
}

// --- the bounded admission and the shutdown barrier ---

// TestCheckpointOperationAbortAdmissionBudget pins the context discipline of
// the abort admission: an expired or cancelled context never wins a slot, the
// admission-lock queue wait consumes the caller's budget instead of blocking
// past it, and a refusal grants nothing and mutates nothing.
func TestCheckpointOperationAbortAdmissionBudget(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "checkpoint")
	newSeeded := func(t *testing.T) *sandboxService {
		root := t.TempDir()
		request := checkpointOperationRequest("op-abort-budget", "sbox-abort-budget", directory, "gen-1", 30)
		seedAbortableOperationRecord(t, root, request, checkpointOperationPhaseUnknown, false, nil)
		return newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)
	}
	request := checkpointOperationRequest("op-abort-budget", "sbox-abort-budget", directory, "gen-1", 30)
	draft := abortDraftForRequest(t, request)

	t.Run("an expired context never wins a slot", func(t *testing.T) {
		s := newSeeded(t)
		seeded := readJournalCheckpointOperation(t, s.config.RootDir, "op-abort-budget")
		for name, build := range map[string]func() context.Context{
			"already cancelled": func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			"already expired": func() context.Context {
				ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				cancel()
				return ctx
			},
		} {
			abort, joined, err := s.checkpointOperations.abortExistingContext(build(), draft)
			assert.Nil(t, abort, name)
			assert.Nil(t, joined, name)
			assert.Error(t, err, name)
			_, running := s.checkpointOperations.executionDone("op-abort-budget")
			assert.False(t, running, "%s: an expired context must not win an execution slot", name)
			assert.Equal(t, seeded, readJournalCheckpointOperation(t, s.config.RootDir, "op-abort-budget"), name)
			// The refusal left the lock usable for the next writer.
			s.checkpointOperations.writeMu.Lock()
			s.checkpointOperations.writeMu.Unlock()
		}
	})

	t.Run("a held admission lock is bounded by the caller's budget", func(t *testing.T) {
		s := newSeeded(t)
		seeded := readJournalCheckpointOperation(t, s.config.RootDir, "op-abort-budget")
		s.checkpointOperations.writeMu.Lock()
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		started := time.Now()
		abort, joined, err := s.checkpointOperations.abortExistingContext(ctx, draft)
		elapsed := time.Since(started)
		s.checkpointOperations.writeMu.Unlock()
		assert.Nil(t, abort)
		assert.Nil(t, joined)
		assert.Equal(t, codes.DeadlineExceeded, status.Code(err))
		assert.ErrorContains(t, err, "admission lock wait exceeded the caller's budget")
		assert.Less(t, elapsed, time.Second,
			"the abort must answer its requested budget while the admission lock is held (took %s)", elapsed)
		_, running := s.checkpointOperations.executionDone("op-abort-budget")
		assert.False(t, running)
		assert.Equal(t, seeded, readJournalCheckpointOperation(t, s.config.RootDir, "op-abort-budget"))

		// Once the owning writer exited, the same abort is admitted and lands
		// its fact.
		abort, joined, err = s.checkpointOperations.abortExistingContext(context.Background(), draft)
		require.NoError(t, err)
		require.NotNil(t, abort)
		assert.Nil(t, joined)
		require.NoError(t, abort.markAborted("runtime confirmed the abort"))
		abort.finish()
		record := readJournalCheckpointOperation(t, s.config.RootDir, "op-abort-budget")
		assert.Equal(t, checkpointOperationPhaseFailed, record.Phase)
		assert.True(t, record.AbortConfirmed)
	})

	t.Run("a cancelled caller ends only its own queue wait", func(t *testing.T) {
		s := newSeeded(t)
		s.checkpointOperations.writeMu.Lock()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, _, err := s.checkpointOperations.abortExistingContext(ctx, draft)
			done <- err
		}()
		time.Sleep(100 * time.Millisecond)
		cancel()
		select {
		case err := <-done:
			assert.Equal(t, codes.Canceled, status.Code(err))
		case <-time.After(5 * time.Second):
			t.Fatal("the cancelled abort did not leave the admission queue")
		}
		s.checkpointOperations.writeMu.Unlock()
		_, running := s.checkpointOperations.executionDone("op-abort-budget")
		assert.False(t, running)

		abort, joined, err := s.checkpointOperations.abortExistingContext(context.Background(), draft)
		require.NoError(t, err)
		require.NotNil(t, abort)
		assert.Nil(t, joined)
		abort.finish()
	})
}

// TestCheckpointOperationAbortShutdown pins the shutdown barrier: a draining
// store never starts an abort, shutdown cancels an abort executor to request
// convergence, waits for its real exit, and does not revoke a confirmed abort
// the executor lands before returning.
func TestCheckpointOperationAbortShutdown(t *testing.T) {
	newSeededService := func(t *testing.T) (*sandboxService, *runtime.CheckpointWithOperationRequest) {
		root := t.TempDir()
		directory := filepath.Join(t.TempDir(), "checkpoint")
		request := checkpointOperationRequest("op-abort-drain", "sbox-abort-drain", directory, "gen-1", 30)
		seedAbortableOperationRecord(t, root, request, checkpointOperationPhaseUnknown, false, nil)
		return newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root), request
	}

	t.Run("admission is closed once draining", func(t *testing.T) {
		s, request := newSeededService(t)
		s.checkpointOperations.shutdown()
		abort, joined, err := s.checkpointOperations.abortExistingContext(
			context.Background(), abortDraftForRequest(t, request))
		assert.Nil(t, abort)
		assert.Nil(t, joined)
		assert.Equal(t, codes.Unavailable, status.Code(err))
		assert.ErrorContains(t, err, "shutting down")
		_, running := s.checkpointOperations.executionDone("op-abort-drain")
		assert.False(t, running)
		assert.Equal(t, checkpointOperationPhaseUnknown,
			readJournalCheckpointOperation(t, s.config.RootDir, "op-abort-drain").Phase)
		assert.Equal(t, 1, journalRecordCount(t, s.config.RootDir))
	})

	t.Run("a queued abort is refused once draining opened the lock", func(t *testing.T) {
		s, request := newSeededService(t)
		s.checkpointOperations.writeMu.Lock()
		drained := make(chan struct{})
		go func() {
			defer close(drained)
			s.checkpointOperations.shutdown()
		}()
		// Draining never queues on the admission lock: it flips the lifecycle
		// flag under lifeMu and waits only for live executors (there are
		// none), so it returns while the test still holds writeMu.
		select {
		case <-drained:
		case <-time.After(2 * time.Second):
			t.Fatal("shutdown blocked on the held admission lock")
		}
		s.checkpointOperations.writeMu.Unlock()

		abort, joined, err := s.checkpointOperations.abortExistingContext(
			context.Background(), abortDraftForRequest(t, request))
		assert.Nil(t, abort)
		assert.Nil(t, joined)
		assert.Equal(t, codes.Unavailable, status.Code(err))
		assert.ErrorContains(t, err, "shutting down")
		_, running := s.checkpointOperations.executionDone("op-abort-drain")
		assert.False(t, running, "a draining store must not grant an abort slot")
	})

	t.Run("shutdown cancels the executor, waits for the real exit, and never revokes the slot", func(t *testing.T) {
		s, request := newSeededService(t)
		abort, joined := admitAbort(t, s, request)
		require.NotNil(t, abort)
		assert.Nil(t, joined)
		abortCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		abort.registerCancel(cancel)

		shutdownDone := make(chan struct{})
		go func() {
			s.checkpointOperations.shutdown()
			close(shutdownDone)
		}()
		select {
		case <-abortCtx.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("shutdown did not cancel the abort executor")
		}
		select {
		case <-shutdownDone:
			t.Fatal("shutdown returned while the abort executor was still running")
		case <-time.After(200 * time.Millisecond):
		}
		// The convergence request does not revoke the slot: the executor may
		// still land the durable confirmed abort before it returns.
		require.NoError(t, abort.markAborted("runtime confirmed the abort during the drain"))
		abort.finish()
		select {
		case <-shutdownDone:
		case <-time.After(10 * time.Second):
			t.Fatal("shutdown did not return after the abort executor exited")
		}
		record := readJournalCheckpointOperation(t, s.config.RootDir, "op-abort-drain")
		assert.Equal(t, checkpointOperationPhaseFailed, record.Phase)
		assert.True(t, record.AbortConfirmed)
	})
}

// --- the dedicated failure transition ---

// TestCheckpointOperationAbortMarkAbortedDurableFirst pins the transition's
// ordering and durability: the confirmed FAILED+AbortConfirmed fact is durable
// before it is published, a blocked failed or ambiguous write keeps every
// query at the undetermined outcome while the same slot may retry, and the
// landed fact survives a restart and replays idempotently.
func TestCheckpointOperationAbortMarkAbortedDurableFirst(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(t.TempDir(), "checkpoint")
	request := checkpointOperationRequest("op-abort-mark", "sbox-abort-mark", directory, "gen-1", 30)
	seedAbortableOperationRecord(t, root, request, checkpointOperationPhaseUnknown, false, nil)
	s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)

	gate := make(chan struct{})
	var failConfirmedWrites atomic.Bool
	s.checkpointOperations.persistHook = func(record *checkpointOperationRecord) error {
		if !record.AbortConfirmed {
			return s.checkpointOperations.durablyWrite(record)
		}
		<-gate
		if failConfirmedWrites.Load() {
			return errors.New("journal fsync failed")
		}
		return s.checkpointOperations.durablyWrite(record)
	}

	abort, joined := admitAbort(t, s, request)
	require.NotNil(t, abort)
	assert.Nil(t, joined)
	markDone := make(chan error, 1)
	go func() {
		markDone <- abort.markAborted("runtime confirmed the abort")
	}()

	undetermined := func() *runtime.CheckpointOperationStatus {
		queried, qerr := s.GetCheckpointOperation(context.Background(),
			&runtime.GetCheckpointOperationRequest{OperationID: "op-abort-mark"})
		require.NoError(t, qerr)
		return queried
	}
	time.Sleep(100 * time.Millisecond)
	queried := undetermined()
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN, queried.GetState())
	assert.Equal(t, checkpointOperationPhaseUnknown,
		readJournalCheckpointOperation(t, root, "op-abort-mark").Phase)
	select {
	case err := <-markDone:
		t.Fatalf("the confirmed abort reported before its write resolved: %v", err)
	default:
	}

	// The write fails: the transition returns an error, nothing is published,
	// and the durable record still claims nothing.
	failConfirmedWrites.Store(true)
	close(gate)
	require.ErrorContains(t, <-markDone, "persist the confirmed abort")
	queried = undetermined()
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN, queried.GetState())
	assert.Equal(t, checkpointOperationPhaseUnknown,
		readJournalCheckpointOperation(t, root, "op-abort-mark").Phase)

	// After the journal is repaired the same slot retries and the fact lands.
	failConfirmedWrites.Store(false)
	require.NoError(t, abort.markAborted("runtime confirmed the abort after the journal was repaired"))
	queried = undetermined()
	assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED, queried.GetState())
	record := readJournalCheckpointOperation(t, root, "op-abort-mark")
	assert.Equal(t, checkpointOperationPhaseFailed, record.Phase)
	assert.True(t, record.AbortConfirmed)
	assert.Nil(t, record.Artifact)
	assert.Equal(t, "runtime confirmed the abort after the journal was repaired", record.Message)

	// The already-durable fact replays idempotently: a retry claims nothing
	// new and rewrites nothing — not even the message or updated_at.
	require.NoError(t, abort.markAborted("a retried confirmation must not rewrite history"))
	assert.Equal(t, record, readJournalCheckpointOperation(t, root, "op-abort-mark"))
	abort.finish()

	// A restart reads the same durable confirmed abort, and a later abort of
	// the operation is the acknowledgment-only half.
	restarted := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)
	afterRestart := readJournalCheckpointOperation(t, root, "op-abort-mark")
	assert.Equal(t, record, afterRestart)
	ackSlot, joinedAfter := admitAbort(t, restarted, request)
	require.NotNil(t, ackSlot)
	assert.Nil(t, joinedAfter)
	assert.True(t, ackSlot.acknowledgmentOnly())
	require.NoError(t, ackSlot.markAborted("acknowledgment retry after restart"))
	assert.Equal(t, record, readJournalCheckpointOperation(t, root, "op-abort-mark"),
		"an acknowledgment-only retry rewrites nothing")
	ackSlot.finish()

	t.Run("an ambiguous write stays undetermined in memory and retryable", func(t *testing.T) {
		ambiguousRoot := t.TempDir()
		ambiguousRequest := checkpointOperationRequest(
			"op-abort-ambiguous", "sbox-abort-mark", directory, "gen-1", 30)
		seedAbortableOperationRecord(t, ambiguousRoot, ambiguousRequest, checkpointOperationPhaseUnknown, false, nil)
		ambiguous := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), ambiguousRoot)
		var landed atomic.Bool
		ambiguous.checkpointOperations.persistHook = func(record *checkpointOperationRecord) error {
			if !record.AbortConfirmed {
				return ambiguous.checkpointOperations.durablyWrite(record)
			}
			// The write lands but the reply is an error — the ambiguous shape
			// a post-rename fsync failure leaves behind.
			if err := ambiguous.checkpointOperations.durablyWrite(record); err != nil {
				return err
			}
			landed.Store(true)
			return errors.New("directory fsync failed after the rename")
		}
		abort, _ := admitAbort(t, ambiguous, ambiguousRequest)
		require.NotNil(t, abort)
		defer abort.finish()
		require.ErrorContains(t, abort.markAborted("runtime confirmed the abort"), "persist the confirmed abort")
		assert.True(t, landed.Load())
		// Nothing is published: the in-memory view keeps the undetermined
		// outcome while the durable record may already carry the fact.
		queried, qerr := ambiguous.GetCheckpointOperation(context.Background(),
			&runtime.GetCheckpointOperationRequest{OperationID: "op-abort-ambiguous"})
		require.NoError(t, qerr)
		assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_UNKNOWN, queried.GetState())
		durable := readJournalCheckpointOperation(t, ambiguousRoot, "op-abort-ambiguous")
		assert.Equal(t, checkpointOperationPhaseFailed, durable.Phase)
		assert.True(t, durable.AbortConfirmed)

		// The same slot retries the same fact and succeeds — the retry
		// re-persists rather than replaying success from memory.
		ambiguous.checkpointOperations.persistHook = nil
		require.NoError(t, abort.markAborted("runtime confirmed the abort (retry)"))
		queried, qerr = ambiguous.GetCheckpointOperation(context.Background(),
			&runtime.GetCheckpointOperationRequest{OperationID: "op-abort-ambiguous"})
		require.NoError(t, qerr)
		assert.Equal(t, runtime.CheckpointOperationState_CHECKPOINT_OPERATION_STATE_FAILED, queried.GetState())
	})
}

// TestCheckpointOperationAbortMarkAbortedRefusals pins the transition's own
// preconditions: slots that no longer own the operation, records that drifted
// into another version or binding, phases the abort protocol may not
// reinterpret, and acknowledgment-only slots are all refused without any
// durable write, while the ordinary markTerminal path keeps treating unknown
// as terminal — which is exactly why markAborted exists.
func TestCheckpointOperationAbortMarkAbortedRefusals(t *testing.T) {
	newAbortOfUnknown := func(t *testing.T, operationID string) (*sandboxService, *checkpointOperationAbort, *runtime.CheckpointWithOperationRequest) {
		root := t.TempDir()
		request := checkpointOperationRequest(operationID, "sbox-abort-refuse", filepath.Join(t.TempDir(), "checkpoint"), "gen-1", 30)
		seedAbortableOperationRecord(t, root, request, checkpointOperationPhaseUnknown, false, nil)
		s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)
		abort, _ := admitAbort(t, s, request)
		require.NotNil(t, abort)
		return s, abort, request
	}

	forcedPhase := func(s *sandboxService, operationID, phase string, confirmed bool) {
		s.checkpointOperations.viewsMu.Lock()
		s.checkpointOperations.records[operationID].Phase = phase
		s.checkpointOperations.records[operationID].AbortConfirmed = confirmed
		if phase != checkpointOperationPhaseSucceeded {
			s.checkpointOperations.records[operationID].Artifact = nil
		}
		s.checkpointOperations.viewsMu.Unlock()
	}

	t.Run("a released slot is a stale owner", func(t *testing.T) {
		s, abort, request := newAbortOfUnknown(t, "op-abort-stale")
		abort.finish()
		err := abort.markAborted("late confirmation")
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.ErrorContains(t, err, "no longer owns the operation")
		assert.Equal(t, checkpointOperationPhaseUnknown,
			readJournalCheckpointOperation(t, s.config.RootDir, request.GetOperationID()).Phase)
	})

	t.Run("an earlier abort cannot confirm through a later slot", func(t *testing.T) {
		s, earlier, request := newAbortOfUnknown(t, "op-abort-owner")
		earlier.finish()
		later, joined := admitAbort(t, s, request)
		require.NotNil(t, later)
		assert.Nil(t, joined)

		err := earlier.markAborted("confirmation through a stale slot")
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.ErrorContains(t, err, "no longer owns the operation")
		assert.Equal(t, checkpointOperationPhaseUnknown,
			readJournalCheckpointOperation(t, s.config.RootDir, request.GetOperationID()).Phase)

		require.NoError(t, later.markAborted("confirmation by the owning abort"))
		record := readJournalCheckpointOperation(t, s.config.RootDir, request.GetOperationID())
		assert.Equal(t, checkpointOperationPhaseFailed, record.Phase)
		assert.True(t, record.AbortConfirmed)
		later.finish()
	})

	t.Run("terminal facts and foreign records are refused without a write", func(t *testing.T) {
		for name, tc := range map[string]struct {
			phase     string
			confirmed bool
			force     string
		}{
			"succeeded":                 {checkpointOperationPhaseSucceeded, false, "reinterpreted as a confirmed abort"},
			"ordinary failure":          {checkpointOperationPhaseFailed, false, "ordinary failure"},
			"downgraded version record": {checkpointOperationPhaseUnknown, false, "abortable record"},
		} {
			s, abort, request := newAbortOfUnknown(t, "op-abort-refuse-terminal")
			var writes atomic.Int64
			s.checkpointOperations.persistHook = func(record *checkpointOperationRecord) error {
				writes.Add(1)
				return s.checkpointOperations.durablyWrite(record)
			}
			forcedPhase(s, request.GetOperationID(), tc.phase, tc.confirmed)
			if name == "downgraded version record" {
				s.checkpointOperations.viewsMu.Lock()
				s.checkpointOperations.records[request.GetOperationID()].Version = checkpointOperationRecordVersionWitness
				s.checkpointOperations.viewsMu.Unlock()
			}
			err := abort.markAborted("refused confirmation")
			assert.Equal(t, codes.FailedPrecondition, status.Code(err), name)
			assert.ErrorContains(t, err, tc.force, name)
			assert.Zero(t, writes.Load(), "%s: a refused confirmation must not reach the journal", name)
			// The durable record was never touched by the refusal.
			assert.Equal(t, checkpointOperationPhaseUnknown,
				readJournalCheckpointOperation(t, s.config.RootDir, request.GetOperationID()).Phase, name)
			abort.finish()
		}
	})

	t.Run("a drifted binding is refused", func(t *testing.T) {
		s, abort, request := newAbortOfUnknown(t, "op-abort-drift")
		s.checkpointOperations.viewsMu.Lock()
		s.checkpointOperations.records[request.GetOperationID()].SandboxID = "sbox-abort-replaced"
		s.checkpointOperations.viewsMu.Unlock()
		err := abort.markAborted("confirmation on a replaced binding")
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.ErrorContains(t, err, "bound to sandbox")
		abort.finish()
	})

	t.Run("an acknowledgment-only slot cannot create the outcome", func(t *testing.T) {
		s, abort, request := newAbortOfUnknown(t, "op-abort-ackonly-create")
		// Force the impossible state — an undetermined record under a slot
		// admitted for a confirmed abort — directly; the guard must hold
		// regardless, exactly as the recovery analog does.
		abort.ackOnly = true
		err := abort.markAborted("an acknowledgment slot creating the fact")
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assert.ErrorContains(t, err, "acknowledgment only")
		assert.Equal(t, checkpointOperationPhaseUnknown,
			readJournalCheckpointOperation(t, s.config.RootDir, request.GetOperationID()).Phase)
		abort.finish()
	})

	t.Run("the ordinary terminal path keeps treating unknown as terminal", func(t *testing.T) {
		s, _, request := newAbortOfUnknown(t, "op-abort-closed")
		// markTerminal no-ops over unknown, so the ordinary failure path must
		// keep refusing to rewrite it — which is exactly why the abort needs
		// its own dedicated, slot-owned transition.
		assert.NoError(t, s.checkpointOperations.markFailedConfirmed(
			request.GetOperationID(), "an ordinary executor fallback"))
		assert.Equal(t, checkpointOperationPhaseUnknown,
			readJournalCheckpointOperation(t, s.config.RootDir, request.GetOperationID()).Phase)
	})
}

// TestCheckpointOperationAbortBoundRecordIsIndependent pins that the handle
// hands out an independent copy: a caller cannot reach the published record
// through the handle it was handed, and a mutated copy cannot smuggle a
// different fact past the slot's own transition.
func TestCheckpointOperationAbortBoundRecordIsIndependent(t *testing.T) {
	root := t.TempDir()
	request := checkpointOperationRequest(
		"op-abort-bound", "sbox-abort-bound", filepath.Join(t.TempDir(), "checkpoint"), "gen-1", 30)
	seedAbortableOperationRecord(t, root, request, checkpointOperationPhaseUnknown, false, nil)
	s := newCheckpointOperationService(t, newCheckpointOperationRuntimeHandler(), root)

	abort, _ := admitAbort(t, s, request)
	require.NotNil(t, abort)
	defer abort.finish()

	bound := abort.boundRecord()
	require.NotNil(t, bound)
	assert.Equal(t, checkpointOperationRecordVersionAbortable, bound.Version)
	assert.Equal(t, checkpointOperationPhaseUnknown, bound.Phase)
	// Scribbling on the handed-out copy changes neither the published view
	// nor the durable record.
	bound.Phase = checkpointOperationPhaseSucceeded
	bound.AbortConfirmed = true
	bound.SandboxID = "sbox-forged"
	bound.RequestDigest = strings.Repeat("c", checkpointroot.DigestHexLen)

	published, ok := s.checkpointOperations.published("op-abort-bound")
	require.True(t, ok)
	assert.Equal(t, checkpointOperationPhaseUnknown, published.Phase)
	assert.Equal(t, "sbox-abort-bound", published.SandboxID)
	assert.Equal(t, requestDigestOf(t, request), published.RequestDigest)
	assert.False(t, published.AbortConfirmed)
	assert.Equal(t, checkpointOperationPhaseUnknown,
		readJournalCheckpointOperation(t, root, "op-abort-bound").Phase)

	require.NoError(t, abort.markAborted("runtime confirmed the abort"))
	record := readJournalCheckpointOperation(t, root, "op-abort-bound")
	assert.Equal(t, checkpointOperationPhaseFailed, record.Phase)
	assert.True(t, record.AbortConfirmed)
	assert.Equal(t, "sbox-abort-bound", record.SandboxID)
}

// TestCheckpointOperationAbortStoreMakesNoRuntimeCalls pins that the whole
// abort store stage is runtime-silent: an admitted abort and its confirmed
// failure transition never enter the checkpoint path, the witness, or the
// acknowledgment of any handler.
func TestCheckpointOperationAbortStoreMakesNoRuntimeCalls(t *testing.T) {
	root := t.TempDir()
	handler := newCheckpointOperationRuntimeHandler()
	request := checkpointOperationRequest(
		"op-abort-silent", "sbox-abort-silent", filepath.Join(t.TempDir(), "checkpoint"), "gen-1", 30)
	seedAbortableOperationRecord(t, root, request, checkpointOperationPhaseUnknown, false, nil)
	s := newCheckpointOperationService(t, handler, root)

	abort, joined := admitAbort(t, s, request)
	require.NotNil(t, abort)
	assert.Nil(t, joined)
	require.NoError(t, abort.markAborted("runtime confirmed the abort"))
	abort.finish()

	assert.Zero(t, handler.checkpointCount())
	recovers, acks := handler.witnessCounts()
	assert.Zero(t, recovers)
	assert.Zero(t, acks)
	assert.Equal(t, checkpointOperationPhaseFailed,
		readJournalCheckpointOperation(t, root, "op-abort-silent").Phase)
}
