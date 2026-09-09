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
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/inclusionAI/sandboxd/pkg/checkpointroot"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
)

// schemaTestBootID is a fixed canonical nonzero UUID: validation only needs
// the canonical shape, so the schema tests stay hermetic without /proc.
const schemaTestBootID = "0f4e2a34-1c3f-4f0f-9f5f-3a3f3f3f3f3f"

// schemaTestV1Witness builds a complete valid version-1 sealed-operation
// witness in the given phase, exactly the shape every existing writer
// produces.
func schemaTestV1Witness(phase string) firecrackerCheckpointOperationRecord {
	return firecrackerCheckpointOperationRecord{
		Version:          firecrackerCheckpointOperationRecordVersion,
		Phase:            phase,
		OperationID:      "op-schema-1",
		RequestDigest:    strings.Repeat("ab", 32),
		SourceGeneration: "gen-schema",
		RootDigest:       strings.Repeat("cd", 32),
		RootScheme:       checkpointroot.Scheme,
		Directory:        "/var/lib/sandboxd/checkpoints/op-schema-1",
		VMMPID:           4242,
		VMMStartTime:     987654,
		VMMBootID:        schemaTestBootID,
		VMMAPIPath:       "/run/sandboxd/op-schema-1/api.sock",
	}
}

// schemaTestV2Witness builds a complete valid version-2 witness in the given
// phase, carrying the full common identity plus the directory birth identity,
// and the root shape the phase requires: the sealed phases bind one, the
// early-intent phases carry none.
func schemaTestV2Witness(phase string) firecrackerCheckpointOperationRecord {
	record := firecrackerCheckpointOperationRecord{
		Version:          firecrackerCheckpointOperationRecordVersion2,
		Phase:            phase,
		OperationID:      "op-schema-2",
		RequestDigest:    strings.Repeat("ab", 32),
		SourceGeneration: "gen-schema",
		Directory:        "/var/lib/sandboxd/checkpoints/op-schema-2",
		DirectoryDev:     0xfd00,
		DirectoryInode:   0x2c9f,
		VMMPID:           4242,
		VMMStartTime:     987654,
		VMMBootID:        schemaTestBootID,
		VMMAPIPath:       "/run/sandboxd/op-schema-2/api.sock",
	}
	if firecrackerCheckpointOperationPhaseRequiresSealedRoot(phase) {
		record.RootDigest = strings.Repeat("cd", 32)
		record.RootScheme = checkpointroot.Scheme
	}
	return record
}

// schemaTestOperationInstance maps a hot instance whose persisted state
// matches the witness binding exactly (generation, pid, API path, uffd), so
// AckCheckpointOperation and RecoverCheckpointOperation run past the binding
// match and stop precisely on the phase policy under test. The initial state
// is made durable so refusals can also be proven write-free on disk.
func schemaTestOperationInstance(
	t *testing.T,
	record firecrackerCheckpointOperationRecord,
) (*Handler, *firecrackerInstance, runtimecore.CheckpointOperationBinding) {
	t.Helper()
	handler, instance := checkpointPersistenceFixture(t)
	state := instance.snapshot()
	state.Generation = record.SourceGeneration
	state.PID = record.VMMPID
	state.APIPath = record.VMMAPIPath
	state.CheckpointOperation = record
	instance.mu.Lock()
	instance.state = state
	instance.mu.Unlock()
	handler.instances = map[string]*firecrackerInstance{state.ID: instance}
	if err := handler.persistInstance(instance); err != nil {
		t.Fatal(err)
	}
	return handler, instance, runtimecore.CheckpointOperationBinding{
		OperationID:      record.OperationID,
		RequestDigest:    record.RequestDigest,
		SourceGeneration: record.SourceGeneration,
	}
}

func schemaTestStateBytes(t *testing.T, instance *firecrackerInstance) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(
		instance.snapshot().BundlePath,
		firecrackerArtifactsDir, firecrackerStateFilename,
	))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestCheckpointOperationSchemaV1Compatibility pins the version-1 schema
// exactly: the three sealed phases keep validating, the retention
// classification keeps its historical answer, and the JSON field set is
// unchanged — no directory identity keys appear, so a valid version-1 record
// serializes byte for byte as it did before version 2 existed.
func TestCheckpointOperationSchemaV1Compatibility(t *testing.T) {
	for _, phase := range []string{
		firecrackerCheckpointOperationPhasePrepared,
		firecrackerCheckpointOperationPhaseCompleted,
		firecrackerCheckpointOperationPhaseAcked,
	} {
		record := schemaTestV1Witness(phase)
		if err := validateFirecrackerCheckpointOperationRecord(record); err != nil {
			t.Fatalf("valid v1 %s witness rejected: %v", phase, err)
		}
		wantRetained := phase != firecrackerCheckpointOperationPhaseAcked
		if record.retainsEvidence() != wantRetained {
			t.Fatalf("v1 %s retention = %v, want %v", phase, record.retainsEvidence(), wantRetained)
		}
	}
	// The zero record keeps meaning "no evidence": not retained, and never
	// fed to validation on any production path.
	if zero := (firecrackerCheckpointOperationRecord{}); zero.retainsEvidence() || !zero.isZero() {
		t.Fatal("zero witness record must retain no evidence")
	}

	// Exact JSON shape: the version-2 fields are omitempty and absent, so
	// the marshaled bytes are identical to the pre-version-2 encoding.
	record := schemaTestV1Witness(firecrackerCheckpointOperationPhasePrepared)
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"version":1,"phase":"prepared","operation_id":"op-schema-1",` +
		`"request_digest":"` + strings.Repeat("ab", 32) + `",` +
		`"source_generation":"gen-schema",` +
		`"root_digest":"` + strings.Repeat("cd", 32) + `",` +
		`"root_scheme":"` + checkpointroot.Scheme + `",` +
		`"directory":"/var/lib/sandboxd/checkpoints/op-schema-1",` +
		`"vmm_pid":4242,"vmm_start_time":987654,` +
		`"vmm_boot_id":"` + schemaTestBootID + `",` +
		`"vmm_api_path":"/run/sandboxd/op-schema-1/api.sock","uffd":{}}`
	if string(data) != expected {
		t.Fatalf("v1 JSON drifted:\n got: %s\nwant: %s", data, expected)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"directory_dev", "directory_inode"} {
		if _, ok := fields[key]; ok {
			t.Fatalf("v1 JSON carries the version-2 key %q", key)
		}
	}
	roundTripped := firecrackerCheckpointOperationRecord{}
	if err := json.Unmarshal(data, &roundTripped); err != nil || roundTripped != record {
		t.Fatalf("v1 JSON round-trip drifted: %+v %v", roundTripped, err)
	}

	// A v1 witness inside the persisted state round-trips unchanged.
	_, instance, _ := schemaTestOperationInstance(t, record)
	disk, err := readFirecrackerState(instance.snapshot().BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if disk.CheckpointOperation != record {
		t.Fatalf("v1 witness drifted across the state round-trip: %+v", disk.CheckpointOperation)
	}
}

// TestCheckpointOperationSchemaV1RejectsEarlyIntentPhasesAndDirectoryIdentity
// proves no mixed schema exists: a version-1 record never admits the
// version-2-only phases or the directory identity fields.
func TestCheckpointOperationSchemaV1RejectsEarlyIntentPhasesAndDirectoryIdentity(t *testing.T) {
	for _, phase := range []string{
		firecrackerCheckpointOperationPhaseIntent,
		firecrackerCheckpointOperationPhaseAborting,
		firecrackerCheckpointOperationPhaseAborted,
		firecrackerCheckpointOperationPhaseAbortAcked,
	} {
		record := schemaTestV1Witness(phase)
		err := validateFirecrackerCheckpointOperationRecord(record)
		if err == nil || !containsAll(err.Error(), "invalid checkpoint operation record phase") {
			t.Fatalf("v1 record with phase %s = %v, want the invalid-phase refusal", phase, err)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*firecrackerCheckpointOperationRecord)
	}{
		{
			name:   "directory dev only",
			mutate: func(record *firecrackerCheckpointOperationRecord) { record.DirectoryDev = 0xfd00 },
		},
		{
			name:   "directory inode only",
			mutate: func(record *firecrackerCheckpointOperationRecord) { record.DirectoryInode = 2 },
		},
		{
			name: "both directory fields",
			mutate: func(record *firecrackerCheckpointOperationRecord) {
				record.DirectoryDev, record.DirectoryInode = 0xfd00, 2
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := schemaTestV1Witness(firecrackerCheckpointOperationPhasePrepared)
			tc.mutate(&record)
			err := validateFirecrackerCheckpointOperationRecord(record)
			if err == nil || !containsAll(err.Error(), "must not carry directory identity") {
				t.Fatalf("mixed-schema v1 record = %v, want the directory-identity refusal", err)
			}
		})
	}
}

// TestCheckpointOperationSchemaV2AcceptsCompleteShapes proves every
// version-2 phase validates in exactly one complete shape: the full common
// operation and source identity plus the directory birth identity, with the
// sealed phases carrying a bound root and the early-intent phases carrying
// none — and that the record survives a durable state round-trip with its
// directory identity intact.
func TestCheckpointOperationSchemaV2AcceptsCompleteShapes(t *testing.T) {
	for _, phase := range []string{
		firecrackerCheckpointOperationPhasePrepared,
		firecrackerCheckpointOperationPhaseCompleted,
		firecrackerCheckpointOperationPhaseAcked,
		firecrackerCheckpointOperationPhaseIntent,
		firecrackerCheckpointOperationPhaseAborting,
		firecrackerCheckpointOperationPhaseAborted,
		firecrackerCheckpointOperationPhaseAbortAcked,
	} {
		t.Run(phase, func(t *testing.T) {
			record := schemaTestV2Witness(phase)
			if err := validateFirecrackerCheckpointOperationRecord(record); err != nil {
				t.Fatalf("complete v2 %s witness rejected: %v", phase, err)
			}
			data, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"directory_dev", "directory_inode"} {
				if _, ok := fields[key]; !ok {
					t.Fatalf("v2 %s JSON omits %q: %s", phase, key, data)
				}
			}
			_, instance, _ := schemaTestOperationInstance(t, record)
			disk, err := readFirecrackerState(instance.snapshot().BundlePath)
			if err != nil {
				t.Fatal(err)
			}
			if disk.CheckpointOperation != record {
				t.Fatalf("v2 %s witness drifted across the state round-trip: %+v", phase, disk.CheckpointOperation)
			}
			if disk.CheckpointOperation.DirectoryDev != record.DirectoryDev ||
				disk.CheckpointOperation.DirectoryInode != record.DirectoryInode {
				t.Fatalf("v2 %s witness lost its directory identity: %+v", phase, disk.CheckpointOperation)
			}
		})
	}
}

// TestCheckpointOperationSchemaV2RejectsIncompleteOrWrongIdentity proves the
// common version-2 identity is mandatory and complete in every phase: a
// missing binding or directory field, a half directory identity, a bad
// numeric or boot identity, a partial uffd record, and an unknown phase are
// all rejected.
func TestCheckpointOperationSchemaV2RejectsIncompleteOrWrongIdentity(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutate   func(*firecrackerCheckpointOperationRecord)
		fragment string
	}{
		{
			name:     "missing operation id",
			mutate:   func(r *firecrackerCheckpointOperationRecord) { r.OperationID = "" },
			fragment: "carries no operation id",
		},
		{
			name:     "missing request digest",
			mutate:   func(r *firecrackerCheckpointOperationRecord) { r.RequestDigest = "" },
			fragment: "carries no request digest",
		},
		{
			name:     "missing source generation",
			mutate:   func(r *firecrackerCheckpointOperationRecord) { r.SourceGeneration = "" },
			fragment: "carries no source generation",
		},
		{
			name:     "missing directory",
			mutate:   func(r *firecrackerCheckpointOperationRecord) { r.Directory = "" },
			fragment: "carries no directory",
		},
		{
			name:     "missing vmm api path",
			mutate:   func(r *firecrackerCheckpointOperationRecord) { r.VMMAPIPath = "" },
			fragment: "carries no vmm api path",
		},
		{
			name:     "directory dev only",
			mutate:   func(r *firecrackerCheckpointOperationRecord) { r.DirectoryInode = 0 },
			fragment: "no complete directory identity",
		},
		{
			name:     "directory inode only",
			mutate:   func(r *firecrackerCheckpointOperationRecord) { r.DirectoryDev = 0 },
			fragment: "no complete directory identity",
		},
		{
			name:     "vmm pid zero",
			mutate:   func(r *firecrackerCheckpointOperationRecord) { r.VMMPID = 0 },
			fragment: "no complete vmm identity",
		},
		{
			name:     "vmm pid one",
			mutate:   func(r *firecrackerCheckpointOperationRecord) { r.VMMPID = 1 },
			fragment: "no complete vmm identity",
		},
		{
			name:     "vmm pid negative",
			mutate:   func(r *firecrackerCheckpointOperationRecord) { r.VMMPID = -4242 },
			fragment: "no complete vmm identity",
		},
		{
			name:     "vmm start time zero",
			mutate:   func(r *firecrackerCheckpointOperationRecord) { r.VMMStartTime = 0 },
			fragment: "no complete vmm identity",
		},
		{
			name:     "vmm boot id not a uuid",
			mutate:   func(r *firecrackerCheckpointOperationRecord) { r.VMMBootID = "not-a-uuid" },
			fragment: "canonical nonzero UUID",
		},
		{
			name:     "vmm boot id nil uuid",
			mutate:   func(r *firecrackerCheckpointOperationRecord) { r.VMMBootID = uuid.Nil.String() },
			fragment: "canonical nonzero UUID",
		},
		{
			name:     "vmm boot id non canonical",
			mutate:   func(r *firecrackerCheckpointOperationRecord) { r.VMMBootID = strings.ToUpper(schemaTestBootID) },
			fragment: "canonical nonzero UUID",
		},
		{
			name: "partial uffd identity",
			mutate: func(r *firecrackerCheckpointOperationRecord) {
				r.Uffd = firecrackerUffdRecord{
					Version: firecrackerUffdRecordVersion,
					Phase:   firecrackerUffdPhasePending,
					PID:     4242,
				}
			},
			fragment: "unusable uffd identity",
		},
		{
			name:     "unknown phase",
			mutate:   func(r *firecrackerCheckpointOperationRecord) { r.Phase = "finalized" },
			fragment: `invalid checkpoint operation record phase "finalized"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := schemaTestV2Witness(firecrackerCheckpointOperationPhaseIntent)
			tc.mutate(&record)
			err := validateFirecrackerCheckpointOperationRecord(record)
			if err == nil || !containsAll(err.Error(), tc.fragment) {
				t.Fatalf("v2 identity refusal for %s = %v, want fragment %q", tc.name, err, tc.fragment)
			}
			// The sealed phases share every one of these identity refusals.
			sealed := schemaTestV2Witness(firecrackerCheckpointOperationPhasePrepared)
			tc.mutate(&sealed)
			if err := validateFirecrackerCheckpointOperationRecord(sealed); err == nil ||
				!containsAll(err.Error(), tc.fragment) {
				t.Fatalf("v2 sealed identity refusal for %s = %v, want fragment %q", tc.name, err, tc.fragment)
			}
		})
	}
}

// TestCheckpointOperationSchemaRejectsUnknownVersions proves an unknown
// schema version is never reinterpreted — including version zero and any
// version beyond the version-2 draft.
func TestCheckpointOperationSchemaRejectsUnknownVersions(t *testing.T) {
	for _, version := range []int{
		0, -1, 3, firecrackerCheckpointOperationRecordVersion2 + 5,
	} {
		record := schemaTestV2Witness(firecrackerCheckpointOperationPhaseIntent)
		record.Version = version
		err := validateFirecrackerCheckpointOperationRecord(record)
		if err == nil || !containsAll(err.Error(), "unsupported checkpoint operation record version") {
			t.Fatalf("version %d record = %v, want the unsupported-version refusal", version, err)
		}
	}
}

// TestCheckpointOperationSchemaV2RejectsRootOnUnsealedPhases proves an intent
// or abort record never carries root material: a full root, a digest without
// its scheme, or a scheme without its digest are all mixed shapes a
// success-hungry reader could misinterpret, so all three are rejected.
func TestCheckpointOperationSchemaV2RejectsRootOnUnsealedPhases(t *testing.T) {
	for _, phase := range []string{
		firecrackerCheckpointOperationPhaseIntent,
		firecrackerCheckpointOperationPhaseAborting,
		firecrackerCheckpointOperationPhaseAborted,
		firecrackerCheckpointOperationPhaseAbortAcked,
	} {
		for _, tc := range []struct {
			name   string
			mutate func(*firecrackerCheckpointOperationRecord)
		}{
			{
				name: "digest only",
				mutate: func(r *firecrackerCheckpointOperationRecord) {
					r.RootDigest = strings.Repeat("cd", 32)
				},
			},
			{
				name: "scheme only",
				mutate: func(r *firecrackerCheckpointOperationRecord) {
					r.RootScheme = checkpointroot.Scheme
				},
			},
			{
				name: "digest and scheme",
				mutate: func(r *firecrackerCheckpointOperationRecord) {
					r.RootDigest, r.RootScheme = strings.Repeat("cd", 32), checkpointroot.Scheme
				},
			},
		} {
			t.Run(phase+"/"+tc.name, func(t *testing.T) {
				record := schemaTestV2Witness(phase)
				tc.mutate(&record)
				err := validateFirecrackerCheckpointOperationRecord(record)
				if err == nil || !containsAll(err.Error(), "must carry no root") {
					t.Fatalf("unsealed v2 %s record with %s = %v, want the no-root refusal", phase, tc.name, err)
				}
			})
		}
	}
}

// TestCheckpointOperationSchemaV2RejectsMissingRootOnSealedPhases proves a
// version-2 sealed phase keeps the version-1 root validation exactly: no
// root, a missing scheme, a missing, short, or non-hex digest are all
// rejected.
func TestCheckpointOperationSchemaV2RejectsMissingRootOnSealedPhases(t *testing.T) {
	for _, phase := range []string{
		firecrackerCheckpointOperationPhasePrepared,
		firecrackerCheckpointOperationPhaseCompleted,
		firecrackerCheckpointOperationPhaseAcked,
	} {
		for _, tc := range []struct {
			name     string
			mutate   func(*firecrackerCheckpointOperationRecord)
			fragment string
		}{
			{
				name: "no root at all",
				mutate: func(r *firecrackerCheckpointOperationRecord) {
					r.RootDigest, r.RootScheme = "", ""
				},
				fragment: "carries no root scheme",
			},
			{
				name: "scheme missing",
				mutate: func(r *firecrackerCheckpointOperationRecord) {
					r.RootScheme = ""
				},
				fragment: "carries no root scheme",
			},
			{
				name: "digest missing",
				mutate: func(r *firecrackerCheckpointOperationRecord) {
					r.RootDigest = ""
				},
				fragment: "root digest is not",
			},
			{
				name: "short digest",
				mutate: func(r *firecrackerCheckpointOperationRecord) {
					r.RootDigest = "cdef"
				},
				fragment: "root digest is not",
			},
			{
				name: "non hex digest",
				mutate: func(r *firecrackerCheckpointOperationRecord) {
					r.RootDigest = strings.Repeat("zz", 32)
				},
				fragment: "root digest is not hex",
			},
		} {
			t.Run(phase+"/"+tc.name, func(t *testing.T) {
				record := schemaTestV2Witness(phase)
				tc.mutate(&record)
				err := validateFirecrackerCheckpointOperationRecord(record)
				if err == nil || !containsAll(err.Error(), tc.fragment) {
					t.Fatalf("sealed v2 %s record with %s = %v, want fragment %q", phase, tc.name, err, tc.fragment)
				}
			})
		}
	}
}

// TestCheckpointOperationEvidenceRetentionMatrix pins the full retention
// classification: the acknowledged phases and the zero record release, every
// other known phase retains, and — deliberately — malformed or forward-dated
// phase values a corrupted record could carry keep the gate rather than
// releasing evidence nobody can prove was acknowledged.
func TestCheckpointOperationEvidenceRetentionMatrix(t *testing.T) {
	v1Phases := map[string]bool{
		firecrackerCheckpointOperationPhasePrepared:  true,
		firecrackerCheckpointOperationPhaseCompleted: true,
		firecrackerCheckpointOperationPhaseAcked:     false,
	}
	for phase, want := range v1Phases {
		if got := schemaTestV1Witness(phase).retainsEvidence(); got != want {
			t.Fatalf("v1 %s retention = %v, want %v", phase, got, want)
		}
	}
	for _, phase := range []string{
		firecrackerCheckpointOperationPhasePrepared,
		firecrackerCheckpointOperationPhaseCompleted,
		firecrackerCheckpointOperationPhaseIntent,
		firecrackerCheckpointOperationPhaseAborting,
		firecrackerCheckpointOperationPhaseAborted,
	} {
		if !schemaTestV2Witness(phase).retainsEvidence() {
			t.Fatalf("v2 %s must retain evidence", phase)
		}
	}
	for _, phase := range []string{
		firecrackerCheckpointOperationPhaseAcked,
		firecrackerCheckpointOperationPhaseAbortAcked,
	} {
		if schemaTestV2Witness(phase).retainsEvidence() {
			t.Fatalf("v2 %s must release evidence", phase)
		}
	}
	// Malformed shapes keep the gate: an early-intent phase on a version-1
	// record, an abort-acked phase on a version-1 record, and an entirely
	// unknown phase value are all unreadable witnesses.
	malformedIntent := schemaTestV1Witness(firecrackerCheckpointOperationPhaseIntent)
	if !malformedIntent.retainsEvidence() {
		t.Fatal("v1 record with an early-intent phase must keep the gate")
	}
	malformedAbortAcked := schemaTestV1Witness(firecrackerCheckpointOperationPhaseAbortAcked)
	if !malformedAbortAcked.retainsEvidence() {
		t.Fatal("v1 record with abort-acked phase must keep the gate")
	}
	unknown := schemaTestV2Witness("finalized")
	if !unknown.retainsEvidence() {
		t.Fatal("record with an unknown phase must keep the gate")
	}
	nonzeroEmptyPhase := schemaTestV2Witness(firecrackerCheckpointOperationPhaseIntent)
	nonzeroEmptyPhase.Phase = ""
	if !nonzeroEmptyPhase.retainsEvidence() {
		t.Fatal("nonzero record with an empty phase must keep the gate")
	}

	// The gate follows the classification exactly, and reports no root for
	// the unsealed phases instead of an empty binding.
	for _, tc := range []struct {
		record  firecrackerCheckpointOperationRecord
		blocked bool
	}{
		{schemaTestV1Witness(firecrackerCheckpointOperationPhasePrepared), true},
		{schemaTestV1Witness(firecrackerCheckpointOperationPhaseAcked), false},
		{schemaTestV2Witness(firecrackerCheckpointOperationPhaseIntent), true},
		{schemaTestV2Witness(firecrackerCheckpointOperationPhaseAborting), true},
		{schemaTestV2Witness(firecrackerCheckpointOperationPhaseAborted), true},
		{schemaTestV2Witness(firecrackerCheckpointOperationPhaseAbortAcked), false},
		{schemaTestV2Witness("finalized"), true},
		{firecrackerCheckpointOperationRecord{}, false},
	} {
		state := firecrackerPersistedState{ID: "schema-matrix", CheckpointOperation: tc.record}
		err := refuseCheckpointOperationEvidence(state.ID, state)
		if tc.blocked != (err != nil) {
			t.Fatalf("evidence gate for phase %q blocked=%v, got err %v", tc.record.Phase, tc.blocked, err)
		}
		if err != nil && !errors.Is(err, errord.ErrFailedPrecondition) {
			t.Fatalf("evidence gate error = %v, want ErrFailedPrecondition", err)
		}
		if err != nil && tc.record.RootDigest == "" && !containsAll(err.Error(), "root none") {
			t.Fatalf("unsealed evidence refusal must report no root: %v", err)
		}
	}
}

// TestAckCheckpointOperationRefusesEarlyIntentPhases proves the success
// acknowledgment releases none of the unsealed early-intent phases: intent,
// aborting, aborted, and abort-acked records are refused without any state
// mutation — an aborted operation is retired only through the explicit abort
// acknowledgment, which no path implements yet.
func TestAckCheckpointOperationRefusesEarlyIntentPhases(t *testing.T) {
	for _, phase := range []string{
		firecrackerCheckpointOperationPhaseIntent,
		firecrackerCheckpointOperationPhaseAborting,
		firecrackerCheckpointOperationPhaseAborted,
		firecrackerCheckpointOperationPhaseAbortAcked,
	} {
		t.Run(phase, func(t *testing.T) {
			record := schemaTestV2Witness(phase)
			handler, instance, binding := schemaTestOperationInstance(t, record)
			before := schemaTestStateBytes(t, instance)

			err := handler.AckCheckpointOperation(
				context.Background(), instance.snapshot().ID, binding,
			)
			if !errors.Is(err, errord.ErrFailedPrecondition) {
				t.Fatalf("success ack of %s record = %v, want ErrFailedPrecondition", phase, err)
			}
			if !containsAll(err.Error(), "not completed") {
				t.Fatalf("success ack refusal must stay on the not-completed contract: %v", err)
			}
			if instance.snapshot().CheckpointOperation != record {
				t.Fatalf("refused ack mutated the witness: %+v", instance.snapshot().CheckpointOperation)
			}
			if after := schemaTestStateBytes(t, instance); string(before) != string(after) {
				t.Fatalf("refused ack rewrote durable state:\nbefore: %s\nafter:  %s", before, after)
			}
			// The evidence gate the ack refused to release is still in force
			// for every phase that owes an answer. (An abort-acked record is
			// already released by its own protocol fact; the point here is
			// that the SUCCESS acknowledgment is not what released it.)
			if phase != firecrackerCheckpointOperationPhaseAbortAcked &&
				!instance.snapshot().CheckpointOperation.retainsEvidence() {
				t.Fatalf("%s record lost its evidence retention", phase)
			}
		})
	}
}

// TestRecoverCheckpointOperationRefusesAbortPhases proves the success
// recovery path invents no semantics for the abort protocol's phases, and
// that a durable intent is promoted only from its own verifiable seal: here
// the recorded directory does not exist, so even the intent is refused
// fail-closed rather than guessed into a completion. Every refusal observes
// the record without touching the durable state.
func TestRecoverCheckpointOperationRefusesAbortPhases(t *testing.T) {
	for _, tc := range []struct {
		phase     string
		fragments []string
	}{
		{
			phase:     firecrackerCheckpointOperationPhaseAborting,
			fragments: []string{"explicit abort protocol"},
		},
		{
			phase:     firecrackerCheckpointOperationPhaseAborted,
			fragments: []string{"explicit abort protocol"},
		},
		{
			phase:     firecrackerCheckpointOperationPhaseAbortAcked,
			fragments: []string{"explicit abort protocol"},
		},
		{
			phase:     firecrackerCheckpointOperationPhaseIntent,
			fragments: []string{"records directory"},
		},
	} {
		t.Run(tc.phase, func(t *testing.T) {
			record := schemaTestV2Witness(tc.phase)
			handler, instance, binding := schemaTestOperationInstance(t, record)
			before := schemaTestStateBytes(t, instance)

			_, err := handler.RecoverCheckpointOperation(
				context.Background(), instance.snapshot().ID, binding,
			)
			if !errors.Is(err, errord.ErrFailedPrecondition) {
				t.Fatalf("recovery of %s record = %v, want ErrFailedPrecondition", tc.phase, err)
			}
			if !containsAll(err.Error(), tc.fragments...) {
				t.Fatalf("recovery refusal must name the boundary: %v", err)
			}
			if instance.snapshot().CheckpointOperation != record {
				t.Fatalf("refused recovery mutated the witness: %+v", instance.snapshot().CheckpointOperation)
			}
			if after := schemaTestStateBytes(t, instance); string(before) != string(after) {
				t.Fatalf("refused recovery rewrote durable state:\nbefore: %s\nafter:  %s", before, after)
			}
		})
	}
}

// TestAckCheckpointOperationReleasesV2CompletedWitness pins the promotion
// seam the version-2 schema exists for: a v2 completed record with directory
// identity is acknowledgeable through the existing success path, and the
// release keeps the record's version and directory identity instead of
// dropping them.
func TestAckCheckpointOperationReleasesV2CompletedWitness(t *testing.T) {
	record := schemaTestV2Witness(firecrackerCheckpointOperationPhaseCompleted)
	handler, instance, binding := schemaTestOperationInstance(t, record)

	if err := handler.AckCheckpointOperation(
		context.Background(), instance.snapshot().ID, binding,
	); err != nil {
		t.Fatalf("ack of a v2 completed witness = %v", err)
	}
	disk, err := readFirecrackerState(instance.snapshot().BundlePath)
	if err != nil {
		t.Fatal(err)
	}
	acknowledged := disk.CheckpointOperation
	if acknowledged.Phase != firecrackerCheckpointOperationPhaseAcked {
		t.Fatalf("durable phase after ack = %q, want acked", acknowledged.Phase)
	}
	if acknowledged.Version != firecrackerCheckpointOperationRecordVersion2 ||
		acknowledged.DirectoryDev != record.DirectoryDev ||
		acknowledged.DirectoryInode != record.DirectoryInode {
		t.Fatalf("acknowledged witness dropped its v2 identity: %+v", acknowledged)
	}
	if acknowledged.retainsEvidence() {
		t.Fatal("acked witness must release the evidence gate")
	}
}
