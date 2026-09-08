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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

// Start intents are the management plane's durable record of an in-flight
// sandbox start. One record is written before the runtime is invoked, holds the
// daemon-generated identity (sandbox ID, resource generation, runtime name),
// the allocated resource leases, and the committed filesystem ownership, and is
// removed only when the start either fully succeeds (sandbox metadata takes
// over) or fully rolls back (runtime exit proven, everything released).
//
// The records live in their own scheduler-start-intents directory, separate
// from the containers/ tree that sandbox metadata recovery and rollback clean,
// so no cleanup path can destroy them as a side effect.
const (
	startIntentsDirName = "scheduler-start-intents"

	startIntentPhasePrepared  = "prepared"
	startIntentPhaseRetained  = "retained"
	startIntentPhaseCommitted = "committed"

	// startIntentMaxBytes bounds one record. The filesystem section mirrors the
	// persisted sandbox FS state (rootfs descriptor plus S3/OCI references), so
	// the cap leaves room for many mounts while rejecting corruption.
	startIntentMaxBytes = 256 << 10

	startIntentMaxGeneration = 128
	startIntentMaxRuntime    = 64
	startIntentMaxReason     = 4096

	// startIntentLimit bounds the directory so unreachable intents (this step
	// provides retention, not automatic reclamation) cannot grow without bound.
	startIntentLimit = 65536
)

// startIntentFilesystem mirrors the filesystem ownership a start committed
// before invoking the runtime. It is reconciliation metadata: recovery rehouses
// the references themselves through the fsManager's own persisted state.
type startIntentFilesystem struct {
	Rootfs []byte              `json:"rootfs,omitempty"`
	S3     []*runtime.S3Config `json:"s3,omitempty"`
	OCI    []string            `json:"oci,omitempty"`
}

type startIntentRecord struct {
	Version        int                    `json:"version"`
	SandboxID      string                 `json:"sandbox_id"`
	Generation     string                 `json:"generation"`
	Runtime        string                 `json:"runtime"`
	Phase          string                 `json:"phase"`
	Resources      map[string]string      `json:"resources,omitempty"`
	Filesystem     *startIntentFilesystem `json:"filesystem,omitempty"`
	CreatedAt      string                 `json:"created_at"`
	UpdatedAt      string                 `json:"updated_at"`
	RetainedReason string                 `json:"retained_reason,omitempty"`
}

// startIntentStore owns the durable intent journal for one daemon root.
// All mutations happen under the caller's per-ID physical lock; the internal
// mutex only protects the in-memory pending view against concurrent readers
// (Delete, Checkpoint, Start admission, fs restore).
type startIntentStore struct {
	dir     string
	rootDir string

	mu       sync.RWMutex
	pending  map[string]*startIntentRecord
	writesMu sync.Mutex
}

func startIntentPath(dir, id string) string {
	return filepath.Join(dir, id+".json")
}

// sandboxMetadataIdentity is the durable identity of a stored sandbox
// metadata file, used to bind a start-intent record to the incarnation it
// describes. Exists is the only field meaningful when the file is unreadable:
// an unreadable metadata never proves anything.
type sandboxMetadataIdentity struct {
	Exists     bool
	ID         string
	Runtime    string
	Generation string
}

// loadStartIntents reads the intent journal before any sandbox recovery runs.
// metadataIdentity reports the durable identity stored in
// containers/<id>/meta.pb. Recovery may take over a record only in the
// committed phase with fully matching identity — ID, runtime handler, and
// daemon-assigned generation: committed is the durable success
// linearization point the Start flow writes only after the runtime and every
// post-runtime step (filesystem commit, metadata persistence) succeeded, so
// metadata presence alone can never promote a record. prepared and retained
// records stay pending regardless of what the metadata says — a crash cannot
// be distinguished from a partial StoreMetadata failure by looking at the
// disk, so the protection wins. A committed record contradicted by missing,
// unreadable, or mismatched metadata fails startup explicitly; a corrupt
// record fails startup explicitly; neither is dropped.
func loadStartIntents(
	rootDir string,
	metadataIdentity func(id string) sandboxMetadataIdentity,
) (*startIntentStore, error) {
	dir := filepath.Join(rootDir, startIntentsDirName)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create start intent directory: %w", err)
	}
	store := &startIntentStore{
		dir:     dir,
		rootDir: rootDir,
		pending: make(map[string]*startIntentRecord),
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read start intent directory: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".intent-") {
			// A leftover temporary file never became a record (the rename is
			// atomic), so it protects nothing and can be discarded.
			if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("remove stale start intent temp file %s: %w", name, err)
			}
			continue
		}
		if entry.IsDir() {
			return nil, fmt.Errorf("unexpected directory %s in start intent journal", name)
		}
		id, ok := startIntentFileID(name)
		if !ok {
			return nil, fmt.Errorf("unexpected entry %s in start intent journal", name)
		}
		record, err := readStartIntentRecord(dir, id)
		if err != nil {
			return nil, err
		}
		meta := metadataIdentity(id)
		switch record.Phase {
		case startIntentPhaseCommitted:
			if err := bindCommittedIntent(id, record, meta); err != nil {
				return nil, err
			}
			if err := store.durablyRemove(id); err != nil {
				return nil, fmt.Errorf("retire committed start intent %s: %w", id, err)
			}
			logrus.Infof("committed start intent for %s taken over by matching sandbox metadata; record removed", id)
			continue
		case startIntentPhasePrepared, startIntentPhaseRetained:
			if meta.Exists {
				logrus.Errorf(
					"start intent %s (phase %s, generation %s, runtime %s) coexists with sandbox metadata "+
						"without a committed handover; the protection stays until reconciliation",
					id, record.Phase, record.Generation, record.Runtime,
				)
			}
			store.pending[id] = record
		default:
			return nil, fmt.Errorf("invalid start intent phase %q for %s", record.Phase, id)
		}
		logrus.Warnf(
			"pending start intent %s (generation %s, runtime %s, phase %s) retained; "+
				"ID is blocked until reconciliation",
			id, record.Generation, record.Runtime, record.Phase,
		)
	}
	return store, nil
}

// bindCommittedIntent verifies that a committed record is backed by sandbox
// metadata with exactly the same durable identity. A committed record states
// that the start linearized; metadata that is missing, unreadable, or bound
// to a different identity contradicts that statement, and the contradiction
// fails recovery explicitly instead of being resolved by guessing.
func bindCommittedIntent(id string, record *startIntentRecord, meta sandboxMetadataIdentity) error {
	switch {
	case !meta.Exists:
		return fmt.Errorf(
			"committed start intent %s (generation %s) has no sandbox metadata; identity cannot be verified",
			id, record.Generation,
		)
	case meta.ID != id:
		return fmt.Errorf(
			"sandbox metadata ID %q conflicts with committed start intent for %s",
			meta.ID, id,
		)
	case meta.Runtime != record.Runtime:
		return fmt.Errorf(
			"sandbox metadata runtime %q conflicts with committed start intent %s (runtime %s) for %s",
			meta.Runtime, record.Generation, record.Runtime, id,
		)
	case meta.Generation == "":
		return fmt.Errorf(
			"sandbox metadata for %s carries no incarnation generation while committed start intent %s exists",
			id, record.Generation,
		)
	case meta.Generation != record.Generation:
		return fmt.Errorf(
			"sandbox metadata generation %q conflicts with committed start intent %s for %s",
			meta.Generation, record.Generation, id,
		)
	}
	return nil
}

// readSandboxMetadataIdentity returns the durable identity recorded in a
// sandbox's stored metadata. Metadata that exists but cannot be read or
// decoded reports Exists with empty fields, which never matches a record and
// therefore fails closed in the loader.
func readSandboxMetadataIdentity(rootDir string) func(id string) sandboxMetadataIdentity {
	metaDir := filepath.Join(rootDir, "containers")
	return func(id string) sandboxMetadataIdentity {
		if !config.IsValidSandboxID(id) {
			return sandboxMetadataIdentity{}
		}
		data, err := os.ReadFile(filepath.Join(metaDir, id, config.SandboxMetaFile))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return sandboxMetadataIdentity{}
			}
			return sandboxMetadataIdentity{Exists: true}
		}
		var meta runtime.SandboxMetadata
		if err := proto.Unmarshal(data, &meta); err != nil {
			return sandboxMetadataIdentity{Exists: true}
		}
		return sandboxMetadataIdentity{
			Exists:     true,
			ID:         meta.GetID(),
			Runtime:    meta.GetRuntimeHandler(),
			Generation: meta.GetLabels()[resourceGenerationLabel],
		}
	}
}

// syncDirectory flushes a directory entry change (rename or remove) so the
// journal update survives a crash immediately after it returns.
func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// startIntentFileID maps a journal filename back to its sandbox ID, accepting
// only the strict "<valid-sandbox-id>.json" shape.
func startIntentFileID(name string) (string, bool) {
	if !strings.HasSuffix(name, ".json") {
		return "", false
	}
	id := strings.TrimSuffix(name, ".json")
	if !config.IsValidSandboxID(id) {
		return "", false
	}
	return id, true
}

func readStartIntentRecord(dir, id string) (*startIntentRecord, error) {
	path := startIntentPath(dir, id)
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open start intent %s: %w", id, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat start intent %s: %w", id, err)
	}
	if !info.Mode().IsRegular() || info.Size() > startIntentMaxBytes {
		return nil, fmt.Errorf("invalid start intent record %s: not a regular file within the size bound", path)
	}
	var record startIntentRecord
	decoder := json.NewDecoder(io.LimitReader(f, startIntentMaxBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return nil, fmt.Errorf("decode start intent %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("start intent %s has trailing content", path)
	}
	if err := validateStartIntentRecord(&record); err != nil {
		return nil, fmt.Errorf("invalid start intent %s: %w", path, err)
	}
	if record.SandboxID != id {
		return nil, fmt.Errorf("start intent %s records mismatched sandbox ID %q", path, record.SandboxID)
	}
	return &record, nil
}

func validateStartIntentRecord(record *startIntentRecord) error {
	if record.Version != 1 {
		return fmt.Errorf("unsupported version %d", record.Version)
	}
	if !config.IsValidSandboxID(record.SandboxID) {
		return fmt.Errorf("invalid sandbox ID %q", record.SandboxID)
	}
	if record.Generation == "" || len(record.Generation) > startIntentMaxGeneration {
		return fmt.Errorf("invalid generation for %s", record.SandboxID)
	}
	if record.Runtime == "" || len(record.Runtime) > startIntentMaxRuntime {
		return fmt.Errorf("invalid runtime for %s", record.SandboxID)
	}
	switch record.Phase {
	case startIntentPhasePrepared, startIntentPhaseRetained, startIntentPhaseCommitted:
	default:
		return fmt.Errorf("invalid phase %q for %s", record.Phase, record.SandboxID)
	}
	for name, value := range record.Resources {
		if name == "" || len(name) > startIntentMaxRuntime || value == "" || len(value) > startIntentMaxBytes {
			return fmt.Errorf("invalid resource %q for %s", name, record.SandboxID)
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, record.CreatedAt); err != nil {
		return fmt.Errorf("invalid created_at for %s: %w", record.SandboxID, err)
	}
	if _, err := time.Parse(time.RFC3339Nano, record.UpdatedAt); err != nil {
		return fmt.Errorf("invalid updated_at for %s: %w", record.SandboxID, err)
	}
	if record.Phase == startIntentPhaseRetained && record.RetainedReason == "" {
		return fmt.Errorf("retained intent %s lacks a reason", record.SandboxID)
	}
	if record.Phase != startIntentPhaseRetained && record.RetainedReason != "" {
		return fmt.Errorf("non-retained intent %s carries a retained reason", record.SandboxID)
	}
	if len(record.RetainedReason) > startIntentMaxReason {
		return fmt.Errorf("retained reason for %s exceeds the size bound", record.SandboxID)
	}
	return nil
}

// preservedOCIImages collects the OCI image URLs that pending start intents
// still reference, for shutdown paths that must not unmount the mounts a
// retained start may still depend on.
func preservedOCIImages(s *startIntentStore) map[string]bool {
	if s == nil {
		return nil
	}
	preserve := make(map[string]bool)
	for _, record := range s.List() {
		if record.Filesystem == nil {
			continue
		}
		for _, url := range record.Filesystem.OCI {
			if url != "" {
				preserve[url] = true
			}
		}
	}
	return preserve
}

// preservedInterfaceResources collects the interface lease identities that
// pending start intents still own, for shutdown paths that must not destroy
// leased devices a retained start may still depend on.
func preservedInterfaceResources(s *startIntentStore) map[string]struct{} {
	if s == nil {
		return nil
	}
	preserve := make(map[string]struct{})
	for _, record := range s.List() {
		if key := record.Resources[config.ResourceNameInterface]; key != "" {
			preserve[key] = struct{}{}
		}
	}
	return preserve
}

// Pending reports whether an unreconciled start intent protects the ID.
func (s *startIntentStore) Pending(id string) bool {
	if s == nil || id == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.pending[id]
	return ok
}

// List returns a stable snapshot of the pending records.
func (s *startIntentStore) List() []startIntentRecord {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	records := make([]startIntentRecord, 0, len(s.pending))
	for _, record := range s.pending {
		records = append(records, *record)
	}
	return records
}

// begin durably records a fresh start intent (phase prepared) before the
// runtime is invoked. The write is fsynced and renamed into place, and the
// directory entry is synced, before the record becomes visible in memory.
func (s *startIntentStore) begin(record *startIntentRecord) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	record.Version = 1
	record.Phase = startIntentPhasePrepared
	record.RetainedReason = ""
	record.CreatedAt = now
	record.UpdatedAt = now
	if err := validateStartIntentRecord(record); err != nil {
		return err
	}
	if err := s.durablyWrite(record); err != nil {
		return err
	}
	s.mu.Lock()
	s.pending[record.SandboxID] = record
	s.mu.Unlock()
	return nil
}

// retain marks the intent retained with the reason the start could not be
// safely unwound. The durable rewrite is best effort — the in-memory pending
// view is updated regardless so Delete/Checkpoint/Start admission refuse the
// ID even when the disk state could not be refreshed.
func (s *startIntentStore) retain(id string, seed *startIntentRecord, reason string) error {
	if len(reason) > startIntentMaxReason {
		reason = reason[:startIntentMaxReason]
	}
	s.mu.Lock()
	record, ok := s.pending[id]
	if !ok {
		if seed == nil {
			s.mu.Unlock()
			return fmt.Errorf("retain start intent %s without a record", id)
		}
		record = seed
	}
	retained := *record
	retained.Phase = startIntentPhaseRetained
	retained.RetainedReason = reason
	retained.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	s.pending[id] = &retained
	s.mu.Unlock()
	return s.durablyWrite(&retained)
}

// complete durably marks the intent committed — the success linearization
// point a Start reaches only after the runtime and every post-runtime step
// (filesystem commit, sandbox metadata persistence) succeeded — and then
// removes the record. A committed write that fails leaves the durable state
// unproven (the record stays prepared or absent, never guessed): the ID
// remains protected in memory and, after a restart, by whatever record the
// disk actually holds. Once the committed phase is durably written the start
// is complete, so a file-removal failure only leaves a committed record that
// recovery takes over against matching metadata.
func (s *startIntentStore) complete(id string, seed *startIntentRecord) error {
	if s == nil || id == "" {
		return fmt.Errorf("complete start intent requires an ID")
	}
	s.mu.Lock()
	record, ok := s.pending[id]
	if !ok {
		if seed == nil {
			s.mu.Unlock()
			return fmt.Errorf("complete start intent %s without a record", id)
		}
		record = seed
	}
	committed := *record
	committed.Phase = startIntentPhaseCommitted
	committed.RetainedReason = ""
	committed.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	s.mu.Unlock()

	if err := validateStartIntentRecord(&committed); err != nil {
		return err
	}
	if err := s.durablyWrite(&committed); err != nil {
		// Unknown durable outcome: the in-memory protection stays exactly as
		// it was; the caller must not roll back an already-running sandbox.
		return err
	}
	if err := s.durablyRemove(id); err != nil {
		logrus.Warnf("remove committed start intent %s: %v; recovery will take it over", id, err)
	}
	s.mu.Lock()
	delete(s.pending, id)
	s.mu.Unlock()
	return nil
}

// clear durably removes the intent record. Callers use it after a fully
// confirmed rollback. On error the pending view keeps the ID protected.
func (s *startIntentStore) clear(id string) error {
	if s == nil || id == "" {
		return nil
	}
	if err := s.durablyRemove(id); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.pending, id)
	s.mu.Unlock()
	return nil
}

func (s *startIntentStore) durablyRemove(id string) error {
	path := startIntentPath(s.dir, id)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove start intent %s: %w", id, err)
	}
	return syncDirectory(s.dir)
}

func (s *startIntentStore) durablyWrite(record *startIntentRecord) error {
	s.writesMu.Lock()
	defer s.writesMu.Unlock()
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return fmt.Errorf("create start intent directory: %w", err)
	}
	// The journal directory is daemon state under the root; syncing the root
	// persists its directory entry the first time it is created.
	if err := syncDirectory(s.rootDir); err != nil {
		return fmt.Errorf("sync start intent parent: %w", err)
	}
	path := startIntentPath(s.dir, record.SandboxID)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		entries, err := os.ReadDir(s.dir)
		if err != nil {
			return err
		}
		if len(entries) >= startIntentLimit {
			return fmt.Errorf("start intent journal full; reconciliation required")
		}
	} else if err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dir, ".intent-*")
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
