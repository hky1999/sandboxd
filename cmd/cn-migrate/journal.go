// Copyright 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

// The durable migration journal: one bounded, strictly validated JSON record
// per migration that survives the CLI process, so a retry after a lost reply
// or a crashed orchestrator resumes the SAME migration instead of issuing a
// second one.
//
// Scope deliberately kept narrow (staged integration, not final fencing):
// the journal records this CLI's orchestration progress only. It is not a
// cross-node write lease, not a fencing token, and not authority over what
// any VM or daemon does — the node-local operation records, the
// generation-scoped conditional RPCs, and the eventual authoritative
// coordinator remain the real ownership mechanisms. A journal that says
// "restore succeeded" tells the operator what THIS flow observed, nothing
// more.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	// journalVersion is the only record schema this build reads and writes.
	journalVersion = 1

	// maxJournalBytes bounds the record read and write. The journal carries
	// short identity strings only; anything larger is corruption, not data.
	maxJournalBytes = 64 << 10

	// maxMigrationIDBytes bounds -migration-id so the derived checkpoint
	// directory and target operation ID stay inside the service's 128-byte
	// operation identity limit.
	maxMigrationIDBytes = 64
)

// Migration stages, in execution order. A stage is recorded only once its
// meaning is durably true: "checkpoint-issued" is written BEFORE the
// checkpoint command runs (its outcome may be forever unknown), while
// "checkpoint-sealed" is written only after the command replied success.
const (
	stagePrepared         = "prepared"          // intent durably recorded, nothing issued
	stageSourcePinned     = "source-pinned"     // source generation captured from inspect
	stageCheckpointIssued = "checkpoint-issued" // checkpoint command issued, outcome unknown
	stageCheckpointSealed = "checkpoint-sealed" // checkpoint command replied success
	stageRootBound        = "root-bound"        // source content root digest pinned
	stagePublished        = "published"         // cn-publish replied success
	stagePlaced           = "placed"            // target node chosen and pinned
	stageMaterialized     = "materialized"      // artifact on the target matches the pinned root
	stageRestoreIssued    = "restore-issued"    // operation restore issued, outcome unknown
	stageRestoreSucceeded = "restore-succeeded" // proven SUCCEEDED receipt with birth generation
	stageDone             = "done"              // source conditionally retired; replay is a no-op
	journalStageMinimum   = stagePrepared
	journalStageMaximum   = stageDone
)

// stageRank orders the stages for resume decisions. Lookups of unknown
// stages return -1 and fail validation instead of being ordered by guess.
func stageRank(stage string) int {
	order := []string{
		stagePrepared, stageSourcePinned, stageCheckpointIssued, stageCheckpointSealed,
		stageRootBound, stagePublished, stagePlaced, stageMaterialized,
		stageRestoreIssued, stageRestoreSucceeded, stageDone,
	}
	for rank, name := range order {
		if name == stage {
			return rank
		}
	}
	return -1
}

// reached reports whether the journal has durably passed the given stage.
func (j *migrationJournal) reached(stage string) bool {
	return stageRank(j.Stage) >= stageRank(stage)
}

// migrationIntent is the caller's declared migration, pinned in the journal
// on first use: a retry that changes any of these is a different migration
// wearing the same ID, so it is refused instead of silently retargeted. The
// executor template is pinned with the rest — a different -exec reaches
// different nodes through a different transport, which is a different
// migration even when every identity string matches.
type migrationIntent struct {
	MigrationID  string
	Sandbox      string
	Source       string
	Store        string
	RequestFile  string
	ExecTemplate string
	PreferredTo  string
	// ExpectedSourceGen is the optional -source-generation expectation; the
	// empty value means "capture whatever the source inspect pins".
	ExpectedSourceGen string
}

// migrationJournal is the complete durable state of one resumable migration.
// Field set is closed: loading rejects unknown fields so a newer journal can
// never be silently truncated by an older CLI. RequestDigest pins the exact
// restore request bytes (the sha-256 the source node's checkpoint-root
// reported over --request-file): once pinned at root-bound it is never
// refreshed, so a retry that finds different bytes at the same path fails
// instead of quietly re-pinning them.
type migrationJournal struct {
	Version           int    `json:"version"`
	MigrationID       string `json:"migration_id"`
	Sandbox           string `json:"sandbox"`
	Source            string `json:"source"`
	Store             string `json:"store"`
	RequestFile       string `json:"request_file"`
	ExecTemplate      string `json:"exec_template"`
	PreferredTo       string `json:"preferred_to,omitempty"`
	ExpectedSourceGen string `json:"expected_source_generation,omitempty"`
	CheckpointDir     string `json:"checkpoint_dir"`
	OperationID       string `json:"operation_id"`
	SourceGeneration  string `json:"source_generation,omitempty"`
	RootDigest        string `json:"root_digest,omitempty"`
	RootScheme        string `json:"root_scheme,omitempty"`
	RequestDigest     string `json:"request_digest,omitempty"`
	Target            string `json:"target,omitempty"`
	TargetGeneration  string `json:"target_generation,omitempty"`
	Stage             string `json:"stage"`
	UpdatedAtUnixNano int64  `json:"updated_at_unix_nano"`
}

// validateMigrationID accepts exactly the identities that keep both derived
// values safe: ^[A-Za-z0-9][A-Za-z0-9._-]*$ and at most 64 bytes. The same
// charset as the service's operation IDs, so "migrate-<id>" is always a
// legal operation ID, and the leading alphanumeric rules out ".", "..", and
// other relative path elements inside the derived checkpoint directory name.
func validateMigrationID(id string) error {
	if id == "" {
		return errors.New("-migration-id must not be empty")
	}
	if len(id) > maxMigrationIDBytes {
		return fmt.Errorf("-migration-id must be at most %d bytes", maxMigrationIDBytes)
	}
	first := id[0]
	if !((first >= '0' && first <= '9') ||
		(first >= 'a' && first <= 'z') ||
		(first >= 'A' && first <= 'Z')) {
		return fmt.Errorf("-migration-id must match ^[A-Za-z0-9][A-Za-z0-9._-]*$ (%q starts with %q)", id, first)
	}
	for index := 1; index < len(id); index++ {
		character := id[index]
		switch {
		case character >= '0' && character <= '9',
			character >= 'a' && character <= 'z',
			character >= 'A' && character <= 'Z',
			character == '-', character == '_', character == '.':
		default:
			return fmt.Errorf("-migration-id contains unsupported character %q at byte %d (must match ^[A-Za-z0-9][A-Za-z0-9._-]*$)", character, index)
		}
	}
	return nil
}

// migrationCheckpointDirFor derives the checkpoint directory of a migration:
// the per-sandbox base plus the migration ID. It is a pure function of the
// identity, so every retry of the same migration addresses the same
// directory — unlike the legacy per-attempt timestamped directory, a retry
// must resume the previous attempt's published and materialized artifact.
func migrationCheckpointDirFor(sandbox, migrationID string) string {
	return migrationCheckpointDir(sandbox) + "-" + migrationID
}

// migrationOperationIDFor derives the target's start operation ID from the
// migration identity. It never changes across retries: a lost reply is
// recovered by querying and re-issuing THIS ID, never by minting a new one.
func migrationOperationIDFor(migrationID string) string {
	return "migrate-" + migrationID
}

// journalStore owns the journal file and its exclusive lock for the lifetime
// of one CLI process. The lock is a separate lock file flock'd until the
// process exits; the journal controller's progress is not VM write
// authority, and the lock only serializes journal writers, not node state.
type journalStore struct {
	path     string
	lockPath string
	lock     *os.File
}

// openJournal loads (or creates) the migration journal under an exclusive
// lock. It fails closed on every ambiguity: a corrupt record, an unknown
// schema, a self-inconsistent stage, or a retry that changed the pinned
// intent is an error — the journal is never recreated over an unreadable
// file, because that would discard unknown durable progress.
func openJournal(path string, intent migrationIntent) (*migrationJournal, *journalStore, error) {
	store := &journalStore{path: path, lockPath: path + ".lock"}
	// The lock file is never unlinked: a second inode would let two
	// orchestrators run "exclusively" at once. It is held until process
	// exit; there is deliberately no unlock-on-failure path that could
	// leave a half-updated record with the lock released mid-transition.
	lock, err := os.OpenFile(store.lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open journal lock %s: %w", store.lockPath, err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, nil, fmt.Errorf(
				"another cn-migrate process holds the journal lock %s — a migration journal may have exactly one writer; refusing to run concurrently",
				store.lockPath,
			)
		}
		return nil, nil, fmt.Errorf("lock journal %s: %w", store.lockPath, err)
	}
	store.lock = lock
	keepLock := false
	defer func() {
		if !keepLock {
			lock.Close()
		}
	}()
	// Decide whether to create only after acquiring the lock: another
	// process may have committed progress before this lock was acquired.
	info, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("inspect journal %s: %w", path, err)
	}
	if info != nil && !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("journal path %s is not a regular file", path)
	}

	if errors.Is(err, os.ErrNotExist) || info == nil {
		record := &migrationJournal{
			Version:           journalVersion,
			MigrationID:       intent.MigrationID,
			Sandbox:           intent.Sandbox,
			Source:            intent.Source,
			Store:             intent.Store,
			RequestFile:       intent.RequestFile,
			ExecTemplate:      intent.ExecTemplate,
			PreferredTo:       intent.PreferredTo,
			ExpectedSourceGen: intent.ExpectedSourceGen,
			CheckpointDir:     migrationCheckpointDirFor(intent.Sandbox, intent.MigrationID),
			OperationID:       migrationOperationIDFor(intent.MigrationID),
			Stage:             stagePrepared,
			UpdatedAtUnixNano: time.Now().UnixNano(),
		}
		if err := store.save(record); err != nil {
			return nil, nil, err
		}
		keepLock = true
		return record, store, nil
	}
	record, err := loadJournal(path)
	if err != nil {
		return nil, nil, err
	}
	if conflict := record.intentConflict(intent); conflict != "" {
		return nil, nil, fmt.Errorf(
			"journal %s records a different migration intent and is not overwritten — %s; use the recorded intent to resume or a new -migration-id for a new migration",
			path, conflict,
		)
	}
	keepLock = true
	return record, store, nil
}

// intentConflict compares the pinned intent with the flags of this
// invocation and names the first difference, or returns "" when the retry
// repeats the same intent.
func (j *migrationJournal) intentConflict(intent migrationIntent) string {
	current := []struct {
		field, recorded, passed string
	}{
		{"-migration-id", j.MigrationID, intent.MigrationID},
		{"-sandbox", j.Sandbox, intent.Sandbox},
		{"-source", j.Source, intent.Source},
		{"-store", j.Store, intent.Store},
		{"-request-file", j.RequestFile, intent.RequestFile},
		{"-exec", j.ExecTemplate, intent.ExecTemplate},
		{"-to", j.PreferredTo, intent.PreferredTo},
		{"-source-generation", j.ExpectedSourceGen, intent.ExpectedSourceGen},
	}
	for _, field := range current {
		if field.recorded != field.passed {
			return fmt.Sprintf(
				"%s is %q in the journal but %q was passed",
				field.field, field.recorded, field.passed,
			)
		}
	}
	return ""
}

// loadJournal reads and strictly validates one journal record. Unknown
// fields, trailing content, an oversized file, a wrong schema version, a
// missing identity, or a stage whose prerequisites are absent are all
// corruption: the caller refuses to run rather than guessing.
func loadJournal(path string) (*migrationJournal, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect journal %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("journal %s is not a regular file", path)
	}
	if info.Size() > maxJournalBytes {
		return nil, fmt.Errorf("journal %s is %d bytes, exceeds %d — refusing to guess at a corrupt record", path, info.Size(), maxJournalBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxJournalBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read journal %s: %w", path, err)
	}
	if len(raw) > maxJournalBytes {
		return nil, fmt.Errorf("journal %s exceeds the size bound while reading", path)
	}
	record := new(migrationJournal)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(record); err != nil {
		return nil, fmt.Errorf("journal %s is corrupt (strict JSON decode failed: %v) — refusing to recreate it over unknown durable progress", path, err)
	}
	if err := decoder.Decode(new(json.RawMessage)); err != io.EOF {
		return nil, fmt.Errorf("journal %s carries trailing content — refusing to recreate it over unknown durable progress", path)
	}
	if err := record.validate(path); err != nil {
		return nil, err
	}
	return record, nil
}

// validate enforces the record schema beyond JSON syntax: version, identity,
// a known stage, and the prerequisites each recorded stage implies.
func (j *migrationJournal) validate(path string) error {
	if j.Version != journalVersion {
		return fmt.Errorf("journal %s carries version %d, this build writes %d — refusing to guess at a different schema", path, j.Version, journalVersion)
	}
	rank := stageRank(j.Stage)
	if rank < 0 {
		return fmt.Errorf("journal %s records unknown stage %q — refusing to guess at a corrupt record", path, j.Stage)
	}
	for name, value := range map[string]string{
		"migration_id":   j.MigrationID,
		"sandbox":        j.Sandbox,
		"source":         j.Source,
		"store":          j.Store,
		"request_file":   j.RequestFile,
		"exec_template":  j.ExecTemplate,
		"checkpoint_dir": j.CheckpointDir,
		"operation_id":   j.OperationID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("journal %s is corrupt: empty %s — refusing to recreate it over unknown durable progress", path, name)
		}
	}
	if err := validateMigrationID(j.MigrationID); err != nil {
		return fmt.Errorf("journal %s records an invalid migration_id: %v", path, err)
	}
	if j.OperationID != migrationOperationIDFor(j.MigrationID) ||
		j.CheckpointDir != migrationCheckpointDirFor(j.Sandbox, j.MigrationID) {
		return fmt.Errorf(
			"journal %s records derived identity (checkpoint_dir %q, operation_id %q) inconsistent with migration %q — refusing to run a retargeted migration",
			path, j.CheckpointDir, j.OperationID, j.MigrationID,
		)
	}
	if rank >= stageRank(stageSourcePinned) && strings.TrimSpace(j.SourceGeneration) == "" {
		return fmt.Errorf("journal %s is corrupt: stage %s without a captured source_generation", path, j.Stage)
	}
	// Root readiness includes the request pin: a migration that is about to
	// restore must have BOTH the artifact identity and the exact request
	// bytes it will replay, or the restore would be free to send unpinned
	// content under the operation ID.
	if rank >= stageRank(stageRootBound) {
		if len(j.RootDigest) != 64 || !isHex(j.RootDigest) || j.RootScheme == "" {
			return fmt.Errorf("journal %s is corrupt: stage %s without a pinned 64-hex root digest and scheme", path, j.Stage)
		}
		if len(j.RequestDigest) != 64 || !isHex(j.RequestDigest) {
			return fmt.Errorf("journal %s is corrupt: stage %s without a pinned 64-hex request digest", path, j.Stage)
		}
	}
	if rank >= stageRank(stagePlaced) && strings.TrimSpace(j.Target) == "" {
		return fmt.Errorf("journal %s is corrupt: stage %s without a chosen target", path, j.Stage)
	}
	if rank >= stageRank(stageRestoreSucceeded) && strings.TrimSpace(j.TargetGeneration) == "" {
		return fmt.Errorf("journal %s is corrupt: stage %s without the receipt's target generation", path, j.Stage)
	}
	return nil
}

// isHex reports whether s is entirely lowercase-or-uppercase hexadecimal.
func isHex(s string) bool {
	for index := 0; index < len(s); index++ {
		character := s[index]
		switch {
		case character >= '0' && character <= '9',
			character >= 'a' && character <= 'f',
			character >= 'A' && character <= 'F':
		default:
			return false
		}
	}
	return true
}

// save durably rewrites the journal: temporary file in the same directory,
// fsync, rename over the record, directory fsync. The caller only continues
// to the next side effect after the stage naming that side effect has
// survived this full sequence.
func (s *journalStore) save(record *migrationJournal) error {
	record.Version = journalVersion
	record.UpdatedAtUnixNano = time.Now().UnixNano()
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("encode journal %s: %w", s.path, err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxJournalBytes {
		return fmt.Errorf("journal %s would be %d bytes, exceeds %d", s.path, len(encoded), maxJournalBytes)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("create journal directory %s: %w", filepath.Dir(s.path), err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".journal-"+filepath.Base(s.path)+"-*")
	if err != nil {
		return fmt.Errorf("stage journal write for %s: %w", s.path, err)
	}
	tempName := temporary.Name()
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		os.Remove(tempName)
		return fmt.Errorf("write staged journal %s: %w", tempName, err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		os.Remove(tempName)
		return fmt.Errorf("fsync staged journal %s: %w", tempName, err)
	}
	if err := temporary.Close(); err != nil {
		os.Remove(tempName)
		return fmt.Errorf("close staged journal %s: %w", tempName, err)
	}
	if err := os.Rename(tempName, s.path); err != nil {
		os.Remove(tempName)
		return fmt.Errorf("commit journal %s: %w", s.path, err)
	}
	directory, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return fmt.Errorf("open journal directory for fsync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("fsync journal directory %s: %w", filepath.Dir(s.path), err)
	}
	return nil
}
