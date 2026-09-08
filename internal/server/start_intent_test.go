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
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
	"github.com/inclusionAI/sandboxd/pkg/store"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// intentRuntimeHandler is a simulated runtime with recordable Start, legacy
// Delete, and strict Delete, plus injectable failures and an observation hook
// that runs inside Start before it returns.
type intentRuntimeHandler struct {
	*svc.FakeRuntimeHandler

	mu            sync.Mutex
	startCalls    int
	legacyDeletes int
	strictDeletes int
	lastStrictGen string
	startErr      error
	deleteErr     error
	strictErr     error
	onStart       func(svc.StartConfig)
}

func (h *intentRuntimeHandler) Start(_ context.Context, cfg svc.StartConfig) error {
	h.mu.Lock()
	h.startCalls++
	startErr := h.startErr
	onStart := h.onStart
	h.mu.Unlock()
	if onStart != nil {
		onStart(cfg)
	}
	return startErr
}

func (h *intentRuntimeHandler) Delete(_ context.Context, _ string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.legacyDeletes++
	return h.deleteErr
}

func (h *intentRuntimeHandler) DeleteStrict(_ context.Context, _, expectedGeneration string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.strictDeletes++
	h.lastStrictGen = expectedGeneration
	return h.strictErr
}

func (h *intentRuntimeHandler) counts() (int, int, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.startCalls, h.legacyDeletes, h.strictDeletes
}

func (h *intentRuntimeHandler) setStartErr(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.startErr = err
}

func (h *intentRuntimeHandler) setDeleteErr(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.deleteErr = err
}

func (h *intentRuntimeHandler) setStrictErr(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.strictErr = err
}

// The simulated runtime declares the Firecracker-style failed-start contract:
// plain errors prove its own side already cleaned up.
func (h *intentRuntimeHandler) StartFailureCleanupProven() bool {
	return true
}

// newIntentTestService wires a service whose Start entry runs end to end with
// a simulated runtime, real on-disk intent journal, and persisted filesystem
// state; only the resource pools are replaced by simulated leases.
func newIntentTestService(t *testing.T, handler svc.Handler) *sandboxService {
	t.Helper()
	return newIntentTestServiceAtRoot(t, handler, t.TempDir(), store.NewMockStore())
}

// newIntentTestServiceAtRoot builds the same service over an explicit root
// (and filesystem state store) so a test can simulate a daemon restart that
// recovers the same durable state.
func newIntentTestServiceAtRoot(
	t *testing.T,
	handler svc.Handler,
	root string,
	fsStateStore store.DbStore,
) *sandboxService {
	t.Helper()

	handlerMap := cmap.New[svc.Handler]()
	handlerMap.Set(config.RuntimeNameRunsc, handler)
	runtimeBinary := map[string]string{config.RuntimeNameRunsc: "/fake/runsc"}

	// Production startup order: the operation journal loads before the intent
	// journal (so committed takeovers can promote operation facts), and the
	// intent journal loads before the sandbox manager reads containers/, so
	// pending roots survive metadata recycling. The same metadata-existence
	// rule production recovery uses decides which records a completed start
	// has already satisfied.
	operations, err := loadStartOperations(root)
	require.NoError(t, err)
	intents, err := loadStartIntents(root, readSandboxMetadataIdentity(root), operations.promoteCommittedTakeover)
	require.NoError(t, err)

	healthChan := make(chan bool, 10)
	manager, err := sandbox.NewManager(
		root,
		handlerMap,
		healthChan,
		nil,
		1000,
		sandbox.WithPreservedSandboxRoots(intents.Pending),
	)
	require.NoError(t, err)
	for _, record := range intents.List() {
		// Mirrors production: an already-reserved ID (recovered sandbox in
		// the ambiguous prepared-plus-metadata state) blocks reuse equally.
		if _, resErr := manager.ReserveID(record.SandboxID); resErr != nil &&
			!errors.Is(resErr, errord.ErrAlreadyExists) {
			t.Fatalf("reserve pending intent %s: %v", record.SandboxID, resErr)
		}
	}

	s := &sandboxService{
		config: config.Config{
			RootDir: root,
			PluginConfig: config.PluginConfig{
				RuntimeConfig: config.RuntimeConfig{
					RuntimeBinary: runtimeBinary,
				},
			},
		},
		serviceHandler:                    handlerMap,
		sandboxManager:                    manager,
		UnimplementedSandboxServiceServer: runtime.UnimplementedSandboxServiceServer{},
		fsMgr:                             newFSManager(nil, fsStateStore),
		networkMgr:                        newNetworkManager(nil, "", false),
		startIntents:                      intents,
		startOperations:                   operations,
	}
	s.ready.Store(true)
	s.recoveryReady.Store(true)
	s.allocateStartResourceFn = func(_, _, name string) (string, *networkmanager.NetResource, error) {
		if name == config.ResourceNameInterface {
			return "", &networkmanager.NetResource{Ip: net.ParseIP("10.0.0.2")}, nil
		}
		return "", nil, nil
	}
	return s
}

func intentTestStartRequest(t *testing.T, id string) *runtime.StartRequest {
	t.Helper()
	rootfsDir := filepath.Join(t.TempDir(), "rootfs")
	require.NoError(t, os.MkdirAll(rootfsDir, 0755))
	return &runtime.StartRequest{
		SandboxID: id,
		Runtime:   config.RuntimeNameRunsc,
		Rootfs: &runtime.RootfsConfig{
			Type:   runtime.RootfsSrcType_LOCAL,
			Source: &runtime.RootfsConfig_Path{Path: rootfsDir},
		},
		Command: []string{"/bin/true"},
		Stdout:  os.DevNull,
		Stderr:  os.DevNull,
	}
}

func intentJournalDir(s *sandboxService) string {
	return filepath.Join(s.config.RootDir, startIntentsDirName)
}

func readIntentFromDisk(t *testing.T, s *sandboxService, id string) *startIntentRecord {
	t.Helper()
	record, err := readStartIntentRecord(intentJournalDir(s), id)
	require.NoError(t, err)
	return record
}

func intentRecordExistsOnDisk(t *testing.T, s *sandboxService, id string) bool {
	t.Helper()
	_, err := os.Lstat(startIntentPath(intentJournalDir(s), id))
	return err == nil
}

func fsStateOwned(s *sandboxService, id string) bool {
	s.fsMgr.mu.Lock()
	defer s.fsMgr.mu.Unlock()
	_, ok := s.fsMgr.sandboxState[id]
	return ok
}

// --- durable store round trip ---

func TestStartIntentStoreBeginRetainClearRoundTrip(t *testing.T) {
	root := t.TempDir()
	intentStore, err := loadStartIntents(root, func(string) sandboxMetadataIdentity { return sandboxMetadataIdentity{} }, nil)
	require.NoError(t, err)

	record := &startIntentRecord{
		SandboxID:  "sbox-store-roundtrip",
		Generation: "gen-1",
		Runtime:    config.RuntimeNameRunsc,
	}
	require.NoError(t, intentStore.begin(record))
	require.True(t, intentStore.Pending("sbox-store-roundtrip"))
	require.FileExists(t, startIntentPath(filepath.Join(root, startIntentsDirName), "sbox-store-roundtrip"))

	require.NoError(t, intentStore.retain("sbox-store-roundtrip", record, "exit unconfirmed"))
	loaded := readStartIntentRecordOrFatal(t, filepath.Join(root, startIntentsDirName), "sbox-store-roundtrip")
	require.Equal(t, startIntentPhaseRetained, loaded.Phase)
	require.NotEmpty(t, loaded.RetainedReason)
	require.True(t, intentStore.Pending("sbox-store-roundtrip"))

	require.NoError(t, intentStore.clear("sbox-store-roundtrip"))
	require.False(t, intentStore.Pending("sbox-store-roundtrip"))
	_, err = os.Lstat(startIntentPath(filepath.Join(root, startIntentsDirName), "sbox-store-roundtrip"))
	require.True(t, os.IsNotExist(err))

	// complete() durably records the committed phase and then removes the
	// record; a failure of the committed write keeps the ID protected.
	require.NoError(t, intentStore.begin(record))
	require.True(t, intentStore.Pending("sbox-store-roundtrip"))
	require.NoError(t, intentStore.complete("sbox-store-roundtrip", record, nil))
	require.False(t, intentStore.Pending("sbox-store-roundtrip"))
	_, err = os.Lstat(startIntentPath(filepath.Join(root, startIntentsDirName), "sbox-store-roundtrip"))
	require.True(t, os.IsNotExist(err))

	// The durable state matches what a fresh load sees.
	reopened, err := loadStartIntents(root, func(string) sandboxMetadataIdentity { return sandboxMetadataIdentity{} }, nil)
	require.NoError(t, err)
	require.False(t, reopened.Pending("sbox-store-roundtrip"))

	// A complete() whose committed write cannot succeed (the record path is
	// an unwritable non-empty directory) leaves the outcome unproven: the
	// pending protection stays.
	require.NoError(t, intentStore.begin(record))
	recordPath := startIntentPath(filepath.Join(root, startIntentsDirName), "sbox-store-roundtrip")
	require.NoError(t, os.Remove(recordPath))
	require.NoError(t, os.MkdirAll(recordPath, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(recordPath, "child"), []byte("x"), 0600))
	require.Error(t, intentStore.complete("sbox-store-roundtrip", record, nil))
	require.True(t, intentStore.Pending("sbox-store-roundtrip"), "an unknown committed-write outcome keeps the ID protected")
}

func readStartIntentRecordOrFatal(t *testing.T, dir, id string) *startIntentRecord {
	t.Helper()
	record, err := readStartIntentRecord(dir, id)
	require.NoError(t, err)
	return record
}

// --- restart recovery ---

func TestLoadStartIntentsRetainsPendingWithoutMetadata(t *testing.T) {
	root := t.TempDir()
	journal := filepath.Join(root, startIntentsDirName)
	require.NoError(t, os.MkdirAll(journal, 0700))
	writeIntentFile(t, journal, "sbox-pending-restart", "gen-restart", startIntentPhasePrepared)

	loaded, err := loadStartIntents(root, func(string) sandboxMetadataIdentity { return sandboxMetadataIdentity{} }, nil)
	require.NoError(t, err)
	require.True(t, loaded.Pending("sbox-pending-restart"))
	require.FileExists(t, filepath.Join(journal, "sbox-pending-restart.json"))
}

func writeSandboxMetadataFile(t *testing.T, root, id, runtimeName, generation string) {
	t.Helper()
	metaDir := filepath.Join(root, "containers", id)
	require.NoError(t, os.MkdirAll(metaDir, 0755))
	meta := &runtime.SandboxMetadata{
		ID:             id,
		RuntimeHandler: runtimeName,
		Labels:         map[string]string{resourceGenerationLabel: generation},
	}
	data, err := proto.Marshal(meta)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(metaDir, config.SandboxMetaFile), data, 0600))
}

// Metadata presence — even fully matching metadata — is not a completion
// proof for a prepared record: a crash cannot be distinguished from a partial
// StoreMetadata failure by looking at the disk, so the protection stays.
func TestLoadStartIntentsKeepsPreparedIntentDespiteMatchingMetadata(t *testing.T) {
	root := t.TempDir()
	journal := filepath.Join(root, startIntentsDirName)
	require.NoError(t, os.MkdirAll(journal, 0700))
	writeIntentFile(t, journal, "sbox-prepared-meta", "gen-prepared", startIntentPhasePrepared)
	writeSandboxMetadataFile(t, root, "sbox-prepared-meta", config.RuntimeNameRunsc, "gen-prepared")

	loaded, err := loadStartIntents(root, readSandboxMetadataIdentity(root), nil)
	require.NoError(t, err)
	require.True(t, loaded.Pending("sbox-prepared-meta"))
	require.FileExists(t, filepath.Join(journal, "sbox-prepared-meta.json"))
}

// Only the committed phase — the durable success linearization point — may be
// taken over by recovery, and only against fully matching identity.
func TestLoadStartIntentsRetiresCommittedIntentOnFullIdentity(t *testing.T) {
	root := t.TempDir()
	journal := filepath.Join(root, startIntentsDirName)
	require.NoError(t, os.MkdirAll(journal, 0700))
	writeIntentFile(t, journal, "sbox-committed-ok", "gen-committed", startIntentPhaseCommitted)
	writeSandboxMetadataFile(t, root, "sbox-committed-ok", config.RuntimeNameRunsc, "gen-committed")

	loaded, err := loadStartIntents(root, readSandboxMetadataIdentity(root), nil)
	require.NoError(t, err)
	require.False(t, loaded.Pending("sbox-committed-ok"))
	_, statErr := os.Lstat(filepath.Join(journal, "sbox-committed-ok.json"))
	require.True(t, os.IsNotExist(statErr))
}

func TestLoadStartIntentsKeepsRetainedIntentDespiteMetadata(t *testing.T) {
	root := t.TempDir()
	journal := filepath.Join(root, startIntentsDirName)
	require.NoError(t, os.MkdirAll(journal, 0700))
	// StoreMetadata succeeded and then the strict exit proof failed: the
	// retained record and matching metadata coexist. Matching metadata is not
	// a completion proof for a retained start, so the protection stays.
	writeIntentFile(t, journal, "sbox-retained-meta", "gen-retained", startIntentPhaseRetained)
	writeSandboxMetadataFile(t, root, "sbox-retained-meta", config.RuntimeNameRunsc, "gen-retained")

	loaded, err := loadStartIntents(root, readSandboxMetadataIdentity(root), nil)
	require.NoError(t, err)
	require.True(t, loaded.Pending("sbox-retained-meta"))
	require.FileExists(t, filepath.Join(journal, "sbox-retained-meta.json"))
}

func writeIntentFile(t *testing.T, journal, id, generation, phase string) {
	t.Helper()
	record := startIntentRecord{
		Version:    1,
		SandboxID:  id,
		Generation: generation,
		Runtime:    config.RuntimeNameRunsc,
		Phase:      phase,
		CreatedAt:  "2026-09-08T00:00:00Z",
		UpdatedAt:  "2026-09-08T00:00:00Z",
	}
	if phase == startIntentPhaseRetained {
		record.RetainedReason = "restart test"
	}
	data, err := json.Marshal(record)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(journal, id+".json"), data, 0600))
}

func TestLoadStartIntentsRejectsCorruptRecords(t *testing.T) {
	valid := `{"version":1,"sandbox_id":"sbox-corrupt","generation":"g","runtime":"runsc","phase":"prepared","created_at":"2026-09-08T00:00:00Z","updated_at":"2026-09-08T00:00:00Z"}`
	cases := map[string]string{
		"truncated json":     `{"version":1,`,
		"unknown field":      valid[:len(valid)-1] + `,"extra":1}`,
		"wrong version":      replaceJSONField(t, valid, `"version":1`, `"version":2`),
		"invalid phase":      replaceJSONField(t, valid, `"phase":"prepared"`, `"phase":"running"`),
		"empty generation":   replaceJSONField(t, valid, `"generation":"g"`, `"generation":""`),
		"id mismatch":        replaceJSONField(t, valid, `"sandbox_id":"sbox-corrupt"`, `"sandbox_id":"sbox-other"`),
		"trailing content":   valid + " {}",
		"retained no reason": replaceJSONField(t, valid, `"phase":"prepared"`, `"phase":"retained"`),
		"invalid created_at": replaceJSONField(t, valid, `"created_at":"2026-09-08T00:00:00Z"`, `"created_at":"not-a-time"`),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			journal := filepath.Join(root, startIntentsDirName)
			require.NoError(t, os.MkdirAll(journal, 0700))
			require.NoError(t, os.WriteFile(filepath.Join(journal, "sbox-corrupt.json"), []byte(content), 0600))
			_, err := loadStartIntents(root, func(string) sandboxMetadataIdentity { return sandboxMetadataIdentity{} }, nil)
			require.Error(t, err, "corrupt record %q must fail startup explicitly", name)
		})
	}
}

func replaceJSONField(t *testing.T, source, old, new string) string {
	t.Helper()
	require.Contains(t, source, old)
	return strings.Replace(source, old, new, 1)
}

func TestLoadStartIntentsRejectsUnexpectedEntries(t *testing.T) {
	t.Run("directory with record name", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, startIntentsDirName, "sbox-dir.json"), 0700))
		_, err := loadStartIntents(root, func(string) sandboxMetadataIdentity { return sandboxMetadataIdentity{} }, nil)
		require.ErrorContains(t, err, "unexpected directory")
	})
	t.Run("foreign file name", func(t *testing.T) {
		root := t.TempDir()
		journal := filepath.Join(root, startIntentsDirName)
		require.NoError(t, os.MkdirAll(journal, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(journal, "evil.json"), []byte("{}"), 0600))
		_, err := loadStartIntents(root, func(string) sandboxMetadataIdentity { return sandboxMetadataIdentity{} }, nil)
		require.ErrorContains(t, err, "unexpected entry")
	})
}

func TestLoadStartIntentsRemovesStaleTempFiles(t *testing.T) {
	root := t.TempDir()
	journal := filepath.Join(root, startIntentsDirName)
	require.NoError(t, os.MkdirAll(journal, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(journal, ".intent-1234"), []byte("partial"), 0600))

	loaded, err := loadStartIntents(root, func(string) sandboxMetadataIdentity { return sandboxMetadataIdentity{} }, nil)
	require.NoError(t, err)
	require.False(t, loaded.Pending("sbox-any"))
	_, statErr := os.Lstat(filepath.Join(journal, ".intent-1234"))
	require.True(t, os.IsNotExist(statErr))
}

// A pending intent must stop metadata recovery from recycling the containers
// directory its start still owns, and the server reserves the ID afterwards.
func TestManagerLoadSkipsRecycleForPendingIntentRoots(t *testing.T) {
	root := t.TempDir()
	kept := filepath.Join(root, "containers", "sbox-keep-intent")
	dropped := filepath.Join(root, "containers", "sbox-drop-nometa")
	for _, dir := range []string{kept, dropped} {
		require.NoError(t, os.MkdirAll(dir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "bundle"), []byte("x"), 0600))
	}

	require.NoError(t, os.MkdirAll(filepath.Join(root, startIntentsDirName), 0700))
	writeIntentFile(t, filepath.Join(root, startIntentsDirName), "sbox-keep-intent", "gen-restart", startIntentPhaseRetained)
	loaded2, err := loadStartIntents(root, func(string) sandboxMetadataIdentity { return sandboxMetadataIdentity{} }, nil)
	require.NoError(t, err)
	require.True(t, loaded2.Pending("sbox-keep-intent"))

	manager, err := sandbox.NewManager(
		root,
		cmap.New[svc.Handler](),
		make(chan bool, 1),
		nil,
		1000,
		sandbox.WithPreservedSandboxRoots(loaded2.Pending),
	)
	require.NoError(t, err)

	_, statErr := os.Lstat(filepath.Join(kept, "bundle"))
	require.NoError(t, statErr, "pending-intent root must survive metadata recovery")
	_, statErr = os.Lstat(filepath.Join(root, config.RecycleBin, "sbox-drop-nometa"))
	require.NoError(t, statErr, "unprotected no-metadata root must still be recycled")

	// The server reserves pending IDs after loading: reuse is refused.
	_, err = manager.ReserveID("sbox-keep-intent")
	require.NoError(t, err)
	_, err = manager.ReserveID("sbox-keep-intent")
	require.ErrorIs(t, err, errord.ErrAlreadyExists)
}

func TestFSRestoreKeepsPendingIntentStateAsOwned(t *testing.T) {
	stateStore := store.NewMockStore()
	imageService := newFSTestImageService()
	beforeCrash := newFSManager(imageService, stateStore)
	prepareAndCommitFS(t, beforeCrash, "sbox-fspending")
	prepareAndCommitFS(t, beforeCrash, "sbox-fsorphan")

	afterCrash := newFSManager(imageService, stateStore)
	pending := func(id string) bool { return id == "sbox-fspending" }
	require.NoError(t, afterCrash.Restore(func(id string) bool {
		return pending(id)
	}))

	afterCrash.mu.Lock()
	_, kept := afterCrash.sandboxState["sbox-fspending"]
	_, orphaned := afterCrash.sandboxState["sbox-fsorphan"]
	afterCrash.mu.Unlock()
	require.True(t, kept, "pending-intent filesystem state must be restored, not orphan-cleaned")
	require.False(t, orphaned, "state without an owner or intent must still be released")
	require.Equal(t, 0, imageService.umountCalls("registry.example/data:latest"),
		"the pending sandbox's shared mount must not be unmounted")
}

// --- service entry: intent ordering ---

func TestStartPersistsIntentAndFSBeforeRuntimeInvocation(t *testing.T) {
	handler := &intentRuntimeHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newIntentTestService(t, handler)
	const id = "sbox-order-intent"

	var observedGeneration string
	handler.mu.Lock()
	handler.onStart = func(cfg svc.StartConfig) {
		// Everything the runtime may strand must already be durable.
		require.FileExists(t, startIntentPath(intentJournalDir(s), id))
		record := readIntentFromDisk(t, s, id)
		require.Equal(t, id, record.SandboxID)
		require.Equal(t, config.RuntimeNameRunsc, record.Runtime)
		require.Equal(t, startIntentPhasePrepared, record.Phase)
		require.NotEmpty(t, record.Generation)
		require.True(t, fsStateOwned(s, id), "filesystem state must be committed before the runtime runs")
		_, statErr := os.Lstat(filepath.Join(s.config.RootDir, "containers", id, config.SandboxMetaFile))
		require.True(t, os.IsNotExist(statErr), "sandbox metadata must not exist before the runtime runs")
		observedGeneration = cfg.Annotations[resourceGenerationLabel]
	}
	handler.mu.Unlock()

	response, err := s.Start(context.Background(), intentTestStartRequest(t, id))
	require.NoError(t, err)
	require.Equal(t, int32(0), response.Code)
	require.Equal(t, observedGeneration, response.ResourceGeneration)
	require.False(t, s.startIntents.Pending(id))
	require.False(t, intentRecordExistsOnDisk(t, s, id), "a fully successful start must hand the intent over")
	require.True(t, fsStateOwned(s, id))
	starts, _, _ := handler.counts()
	require.Equal(t, 1, starts)
}

// --- service entry: retention on uncertain runtime outcome ---

func TestStartRuntimeCleanupPendingRetainsEverything(t *testing.T) {
	handler := &intentRuntimeHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	handler.setStartErr(fmt.Errorf(
		"%w: VMM exit unconfirmed: %w", svc.ErrStartCleanupPending, errors.New("signal timeout"),
	))
	s := newIntentTestService(t, handler)
	const id = "sbox-pending-cleanup"
	request := intentTestStartRequest(t, id)

	response, err := s.Start(context.Background(), request)
	require.Error(t, err)
	require.NotNil(t, response)
	require.Contains(t, response.Message, "start cleanup pending", "the original runtime error must survive to the RPC boundary")

	// The durable record moved to retained; nothing was released.
	record := readIntentFromDisk(t, s, id)
	require.Equal(t, startIntentPhaseRetained, record.Phase)
	require.Contains(t, record.RetainedReason, "start cleanup pending")
	require.True(t, s.startIntents.Pending(id))
	_, legacyDeletes, strictDeletes := handler.counts()
	require.Zero(t, legacyDeletes, "a cleanup-pending runtime must not be signalled again")
	require.Zero(t, strictDeletes)
	require.True(t, fsStateOwned(s, id), "retained start keeps its filesystem ownership")
	_, statErr := os.Lstat(filepath.Join(s.config.RootDir, "containers", id, "sandbox-files"))
	require.NoError(t, statErr, "retained start keeps its sandbox files")

	// Every public entry refuses the protected ID.
	_, err = s.Start(context.Background(), intentTestStartRequest(t, id))
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Contains(t, err.Error(), "pending start intent")

	_, err = s.Delete(context.Background(), &runtime.DeleteRequest{ID: id})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Contains(t, err.Error(), "pending start intent")

	_, err = s.DeleteIfGeneration(context.Background(), &runtime.DeleteIfGenerationRequest{
		ID: id, ExpectedGeneration: record.Generation,
	})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Contains(t, err.Error(), "pending start intent")

	_, err = s.Checkpoint(context.Background(), &runtime.CheckpointRequest{
		ID: id, TimeoutSeconds: 5,
	})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Contains(t, err.Error(), "pending start intent")

	// No runtime side effect happened for any of the refused calls.
	_, legacyDeletes, _ = handler.counts()
	require.Zero(t, legacyDeletes)
}

func TestStartRuntimeFailureRollsBackWithProvenCleanupContract(t *testing.T) {
	handler := &intentRuntimeHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	handler.setStartErr(errors.New("command not found"))
	s := newIntentTestService(t, handler)
	const id = "sbox-rollback-confirmed"

	response, err := s.Start(context.Background(), intentTestStartRequest(t, id))
	require.Error(t, err)
	require.Contains(t, response.Message, "command not found")

	_, legacyDeletes, _ := handler.counts()
	require.Zero(t, legacyDeletes,
		"a runtime with a proven failed-start contract needs no delete; its plain error already proves its side")
	require.False(t, s.startIntents.Pending(id))
	require.False(t, intentRecordExistsOnDisk(t, s, id), "a fully confirmed rollback drops the intent record")
	require.False(t, fsStateOwned(s, id), "a fully confirmed rollback releases filesystem state")

	// The ID returns to the pool: a second start under it succeeds cleanly.
	handler.setStartErr(nil)
	second, err := s.Start(context.Background(), intentTestStartRequest(t, id))
	require.NoError(t, err)
	require.Equal(t, int32(0), second.Code)
	require.NotEmpty(t, second.ResourceGeneration)
	require.False(t, intentRecordExistsOnDisk(t, s, id))
}

// A runtime without the failed-start cleanup contract proves nothing by
// failing: no sentinel, and no legacy Delete nil, may release the start.
func TestStartRuntimeFailureRetainsWithoutProofContract(t *testing.T) {
	handler := &plainFailingHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newIntentTestService(t, handler)
	const id = "sbox-no-proof-contract"

	response, err := s.Start(context.Background(), intentTestStartRequest(t, id))
	require.Error(t, err)
	require.Contains(t, response.Message, "plain start failure")

	require.True(t, s.startIntents.Pending(id), "a plain failure from a non-proving runtime must retain")
	record := readIntentFromDisk(t, s, id)
	require.Equal(t, startIntentPhaseRetained, record.Phase)
	require.Contains(t, record.RetainedReason, "no proven failed-start cleanup contract")
	require.True(t, fsStateOwned(s, id))
	require.Zero(t, handler.deletes,
		"the rollback must not lean on a legacy delete whose nil is not an exit proof")

	_, err = s.Start(context.Background(), intentTestStartRequest(t, id))
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// plainFailingHandler is a runtime with no failure contract: Start fails
// plainly and Delete would succeed, which must not count as an exit proof.
type plainFailingHandler struct {
	*svc.FakeRuntimeHandler
	deletes int
}

func (h *plainFailingHandler) Start(context.Context, svc.StartConfig) error {
	return errors.New("plain start failure")
}

func (h *plainFailingHandler) Delete(context.Context, string) error {
	h.deletes++
	return nil
}

// A start whose runtime already reported success may only be unwound through
// the generation-checked strict delete.
func TestStartPostSuccessFailureUsesStrictExitProof(t *testing.T) {
	handler := &intentRuntimeHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newIntentTestService(t, handler)
	const id = "sbox-strict-proof"

	var startedGeneration string
	handler.mu.Lock()
	handler.onStart = func(cfg svc.StartConfig) {
		startedGeneration = cfg.Annotations[resourceGenerationLabel]
	}
	handler.mu.Unlock()

	s.config.NatBackend = testNetworkType
	fakeNat := &fakeNetworkManager{failNext: true}
	networkmanager.Register(testNetworkType, fakeNat)
	t.Cleanup(func() { delete(networkmanager.NetworkManagers, testNetworkType) })
	s.networkMgr = newNetworkManager(nil, testNetworkType, false)

	request := intentTestStartRequest(t, id)
	request.Ports = []string{"tcp:8080:80"}
	response, err := s.Start(context.Background(), request)
	require.Error(t, err)
	require.Contains(t, response.Message, "Failed to setup DNAT rules")

	_, legacyDeletes, strictDeletes := handler.counts()
	require.Equal(t, 1, strictDeletes, "post-success failure must retire through the strict exit proof")
	require.Zero(t, legacyDeletes, "legacy delete must not decide a post-success rollback")
	handler.mu.Lock()
	require.Equal(t, startedGeneration, handler.lastStrictGen)
	handler.mu.Unlock()

	require.False(t, s.startIntents.Pending(id))
	require.False(t, intentRecordExistsOnDisk(t, s, id))
	require.False(t, fsStateOwned(s, id))

	// The ID was released: a retry under it starts a new generation.
	retry, err := s.Start(context.Background(), intentTestStartRequest(t, id))
	require.NoError(t, err)
	require.Equal(t, int32(0), retry.Code)
}

func TestStartPostSuccessFailureRetainsWithoutStrictSupport(t *testing.T) {
	handler := svc.NewFakeRuntimeHandler()
	s := newIntentTestService(t, handler)
	const id = "sbox-no-strict-support"

	s.config.NatBackend = testNetworkType
	fakeNat := &fakeNetworkManager{failNext: true}
	networkmanager.Register(testNetworkType, fakeNat)
	t.Cleanup(func() { delete(networkmanager.NetworkManagers, testNetworkType) })
	s.networkMgr = newNetworkManager(nil, testNetworkType, false)

	request := intentTestStartRequest(t, id)
	request.Ports = []string{"tcp:8080:80"}
	_, err := s.Start(context.Background(), request)
	require.Error(t, err)

	require.True(t, s.startIntents.Pending(id), "runtimes without a strict exit proof force retention")
	record := readIntentFromDisk(t, s, id)
	require.Equal(t, startIntentPhaseRetained, record.Phase)
	require.Contains(t, record.RetainedReason, "cannot prove exit by generation")
	require.True(t, fsStateOwned(s, id))

	_, err = s.Delete(context.Background(), &runtime.DeleteRequest{ID: id})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// --- unknown intent write outcome ---

func TestStartIntentWriteFailureRollsBackWhenRemovalConfirmed(t *testing.T) {
	handler := &intentRuntimeHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newIntentTestService(t, handler)
	const id = "sbox-intent-write-fail"
	// An empty directory at the record path makes the atomic rename fail but
	// the removal succeed: the pre-runtime rollback is then safe.
	recordPath := startIntentPath(intentJournalDir(s), id)
	require.NoError(t, os.MkdirAll(recordPath, 0700))

	response, err := s.Start(context.Background(), intentTestStartRequest(t, id))
	require.Error(t, err)
	require.Contains(t, response.Message, "Failed to persist start intent")
	require.Contains(t, err.Error(), "persist start intent")

	require.False(t, s.startIntents.Pending(id))
	require.False(t, fsStateOwned(s, id))
	_, _, strictDeletes := handler.counts()
	require.Zero(t, strictDeletes, "the runtime was never invoked")

	// The ID is reusable after the confirmed rollback.
	retry, err := s.Start(context.Background(), intentTestStartRequest(t, id))
	require.NoError(t, err)
	require.Equal(t, int32(0), retry.Code)
}

func TestStartIntentWriteFailureRetainsWhenRemovalUnknown(t *testing.T) {
	handler := &intentRuntimeHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newIntentTestService(t, handler)
	const id = "sbox-intent-write-unknown"
	// A non-empty directory defeats both the rename and the removal: the
	// write's outcome stays unknown, so nothing may be released.
	recordPath := startIntentPath(intentJournalDir(s), id)
	require.NoError(t, os.MkdirAll(recordPath, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(recordPath, "child"), []byte("x"), 0600))

	response, err := s.Start(context.Background(), intentTestStartRequest(t, id))
	require.Error(t, err)
	require.Contains(t, response.Message, "Failed to persist start intent")
	require.Contains(t, err.Error(), "persist start intent")

	require.True(t, s.startIntents.Pending(id), "an unknown write outcome must block the ID")
	require.True(t, fsStateOwned(s, id), "an unknown write outcome must keep the committed filesystem state")
	_, err = s.Start(context.Background(), intentTestStartRequest(t, id))
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// --- legacy delete must not mutate a pending sandbox ---

func TestDeleteLegacyDoesNotStripPendingIntentDNAT(t *testing.T) {
	handler := &intentRuntimeHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newIntentTestService(t, handler)
	const id = "sbox-dnat-protected"

	networkmanager.Register(testNetworkType, &fakeNetworkManager{})
	t.Cleanup(func() { delete(networkmanager.NetworkManagers, testNetworkType) })
	s.config.NatBackend = testNetworkType
	s.networkMgr = newNetworkManager(nil, testNetworkType, false)
	require.NoError(t, s.networkMgr.setupDnatRules(id, []string{"tcp:8080:80"}, "10.0.0.2"))

	record := &startIntentRecord{
		SandboxID:  id,
		Generation: "gen-dnat",
		Runtime:    config.RuntimeNameRunsc,
	}
	require.NoError(t, s.startIntents.begin(record))

	_, err := s.Delete(context.Background(), &runtime.DeleteRequest{ID: id})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.NotEmpty(t, s.networkMgr.rulesFor(id), "legacy delete must not strip a pending sandbox's DNAT rules")
	starts, legacyDeletes, _ := handler.counts()
	require.Zero(t, starts)
	require.Zero(t, legacyDeletes)
}

// --- restart cut-point: daemon recovery over the same durable state ---

// TestRestartAfterRetainedStartKeepsProtectionChain drives the full recovery
// chain a daemon restart executes — journal load before the manager, metadata
// recycle protection, ID reservation, filesystem restore — over the same root
// and state store a retained start left behind.
func TestRestartAfterRetainedStartKeepsProtectionChain(t *testing.T) {
	root := t.TempDir()
	fsStateStore := store.NewMockStore()

	handler := &intentRuntimeHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	handler.setStartErr(fmt.Errorf(
		"%w: exit unconfirmed: %w", svc.ErrStartCleanupPending, errors.New("vmm survives"),
	))
	first := newIntentTestServiceAtRoot(t, handler, root, fsStateStore)
	const id = "sbox-restart-chain"

	_, err := first.Start(context.Background(), intentTestStartRequest(t, id))
	require.Error(t, err)
	require.True(t, first.startIntents.Pending(id))
	_, statErr := os.Lstat(filepath.Join(root, "containers", id, "sandbox-files"))
	require.NoError(t, statErr, "the retained start left its sandbox files in containers/")

	// Daemon restart: a fresh process recovers the same durable state. The
	// intent journal is loaded before the sandbox manager reads containers/,
	// so the retained directory survives metadata recycling; the pending ID is
	// reserved; and the filesystem restore re-acquires instead of orphan-
	// cleaning the committed references.
	secondHandler := &intentRuntimeHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	second := newIntentTestServiceAtRoot(t, secondHandler, root, fsStateStore)
	require.True(t, second.startIntents.Pending(id))

	_, statErr = os.Lstat(filepath.Join(root, "containers", id, "sandbox-files"))
	require.NoError(t, statErr, "recovery must not recycle the pending intent's containers directory")
	require.NoDirExists(t, filepath.Join(root, config.RecycleBin, id))

	_, err = second.sandboxManager.ReserveID(id)
	require.ErrorIs(t, err, errord.ErrAlreadyExists, "recovery reserves the pending ID against reuse")

	require.NoError(t, second.fsMgr.Restore(func(sandboxID string) bool {
		if _, getErr := second.sandboxManager.Get(sandboxID); getErr == nil {
			return true
		}
		return second.startIntents.Pending(sandboxID)
	}))
	require.True(t, fsStateOwned(second, id), "restart restore must keep the retained start's filesystem state")

	_, err = second.Start(context.Background(), intentTestStartRequest(t, id))
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	_, err = second.Delete(context.Background(), &runtime.DeleteRequest{ID: id})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	starts, _, _ := secondHandler.counts()
	require.Zero(t, starts)

	// Unrelated IDs keep working through the restart.
	other, err := second.Start(context.Background(), intentTestStartRequest(t, "sbox-restart-other"))
	require.NoError(t, err)
	require.Equal(t, int32(0), other.Code)
	require.False(t, second.startIntents.Pending("sbox-restart-other"))
}

// TestRestartAfterSuccessfulStartCutPoints exercises both crash windows of
// the success handover: before the committed write (metadata is durable but
// the journal still says prepared — the outcome is unproven, protection
// stays) and after the committed write but before the record's removal
// (committed + matching metadata — recovery takes over).
func TestRestartAfterSuccessfulStartCutPoints(t *testing.T) {
	stageBundleSpec := func(t *testing.T, root, id string) {
		t.Helper()
		require.NoError(t, os.WriteFile(
			filepath.Join(root, "containers", id, config.SandboxSpecFile),
			[]byte(`{"ociVersion":"1.0.2","process":{"cwd":"/"},"root":{"path":"rootfs"},"linux":{"cgroupsPath":""},"annotations":{}}`),
			0600,
		))
	}

	t.Run("crash before committed write keeps protection", func(t *testing.T) {
		root := t.TempDir()
		fsStateStore := store.NewMockStore()
		handler := &intentRuntimeHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
		first := newIntentTestServiceAtRoot(t, handler, root, fsStateStore)
		const id = "sbox-restart-precommit"

		response, err := first.Start(context.Background(), intentTestStartRequest(t, id))
		require.NoError(t, err)
		// Model the crash: the completed flow removed the record, so recreate
		// the prepared record exactly as it looked before the committed write.
		require.NoError(t, os.MkdirAll(filepath.Join(root, startIntentsDirName), 0700))
		writeIntentFile(t, filepath.Join(root, startIntentsDirName), id, response.ResourceGeneration, startIntentPhasePrepared)
		_, statErr := os.Lstat(filepath.Join(root, "containers", id, config.SandboxMetaFile))
		require.NoError(t, statErr, "the metadata outlived the crash")

		second := newIntentTestServiceAtRoot(t, svc.NewFakeRuntimeHandler(), root, fsStateStore)
		require.True(t, second.startIntents.Pending(id),
			"matching metadata cannot prove a start that never recorded committed")
		_, err = second.Delete(context.Background(), &runtime.DeleteRequest{ID: id})
		require.Equal(t, codes.FailedPrecondition, status.Code(err),
			"the unproven handover keeps the pending protections")
	})

	t.Run("crash after committed write takes over", func(t *testing.T) {
		root := t.TempDir()
		fsStateStore := store.NewMockStore()
		handler := &intentRuntimeHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
		first := newIntentTestServiceAtRoot(t, handler, root, fsStateStore)
		const id = "sbox-restart-postcommit"

		response, err := first.Start(context.Background(), intentTestStartRequest(t, id))
		require.NoError(t, err)
		// Model the crash after the committed write but before the removal:
		// the record on disk says committed with the real generation.
		require.NoError(t, os.MkdirAll(filepath.Join(root, startIntentsDirName), 0700))
		writeIntentFile(t, filepath.Join(root, startIntentsDirName), id, response.ResourceGeneration, startIntentPhaseCommitted)

		second := newIntentTestServiceAtRoot(t, svc.NewFakeRuntimeHandler(), root, fsStateStore)
		require.False(t, second.startIntents.Pending(id), "committed + matching identity is the takeover proof")
		_, statErr := os.Lstat(filepath.Join(root, startIntentsDirName, id+".json"))
		require.True(t, os.IsNotExist(statErr), "recovery durably retires the taken-over record")

		// The recovered sandbox is a normal sandbox: legacy delete may retire
		// it. Stage the OCI spec a real runtime would have written.
		stageBundleSpec(t, root, id)
		_, err = second.Delete(context.Background(), &runtime.DeleteRequest{ID: id})
		require.NoError(t, err)
	})
}

// --- pod-change reset cannot clear retained protections ---

func TestResetStateIfPodChangedRefusesWithPendingIntents(t *testing.T) {
	root := t.TempDir()
	storeDir := filepath.Join(t.TempDir(), "store")
	require.NoError(t, os.MkdirAll(storeDir, 0755))
	journal := filepath.Join(root, startIntentsDirName)
	require.NoError(t, os.MkdirAll(journal, 0700))
	writeIntentFile(t, journal, "sbox-pod-reset", "gen-pod", startIntentPhaseRetained)
	metaDir := filepath.Join(root, "containers", "sbox-pod-reset")
	require.NoError(t, os.MkdirAll(metaDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(metaDir, "bundle"), []byte("x"), 0600))

	// A differing stamp (or none at all) is not an exit proof: the reset is
	// refused and both the record and the state it references survive.
	err := resetStateIfPodChanged(storeDir, root, "")
	require.ErrorContains(t, err, "start-intent record")
	require.FileExists(t, filepath.Join(journal, "sbox-pod-reset.json"))
	require.DirExists(t, metaDir)
	require.DirExists(t, storeDir, "the store must not be wiped past the refusal either")

	// A corrupt record file still blocks the reset: the filename carries the
	// ID being protected, and unreadable content must not read as "no intents".
	corruptRoot := t.TempDir()
	corruptJournal := filepath.Join(corruptRoot, startIntentsDirName)
	require.NoError(t, os.MkdirAll(corruptJournal, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(corruptJournal, "sbox-corrupt-reset.json"), []byte("{not json"), 0600))
	corruptStore := filepath.Join(t.TempDir(), "store3")
	require.NoError(t, os.MkdirAll(corruptStore, 0755))
	err = resetStateIfPodChanged(corruptStore, corruptRoot, "")
	require.ErrorContains(t, err, "start-intent record")
	require.FileExists(t, filepath.Join(corruptJournal, "sbox-corrupt-reset.json"))

	// With an empty journal the historical reset behavior is unchanged.
	emptyRoot := t.TempDir()
	emptyStore := filepath.Join(t.TempDir(), "store2")
	require.NoError(t, os.MkdirAll(emptyStore, 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(emptyRoot, "containers"), 0755))
	require.NoError(t, resetStateIfPodChanged(emptyStore, emptyRoot, ""))
	require.NoDirExists(t, filepath.Join(emptyRoot, "containers"))
	require.FileExists(t, filepath.Join(emptyStore, ".pod_host"))
}

// --- graceful shutdown preserves a retained start's ownership ---

func TestShutdownPreservesRetainedStartFilesystemOwnership(t *testing.T) {
	// Control arm: without preservation, shutdown clears the persisted owner
	// and unmounts everything the manager still held.
	controlStore := store.NewMockStore()
	controlService := newFSTestImageService()
	control := newFSManager(controlService, controlStore)
	prepareAndCommitFS(t, control, "sbox-shutdown-control")
	control.Shutdown(nil)
	data, err := controlStore.LoadRaw(config.SandboxFSStateBucket)
	require.NoError(t, err)
	var controlPersisted storedSandboxFSStates
	require.NoError(t, json.Unmarshal(data, &controlPersisted))
	require.Empty(t, controlPersisted.Items)
	require.Equal(t, 1, controlService.umountCalls("registry.example/rootfs:latest"))
	require.Equal(t, 1, controlService.umountCalls("registry.example/data:latest"))

	// Retained arm: the preserved start keeps its ownership record in the
	// persisted store, keeps its reference (the shared rootfs is not
	// unmounted because its count never drops), and keeps its mounts.
	stateStore := store.NewMockStore()
	imageService := newFSTestImageService()
	manager := newFSManager(imageService, stateStore)
	prepareAndCommitFS(t, manager, "sbox-shutdown-retained")
	prepareAndCommitFS(t, manager, "sbox-shutdown-released")

	preserve := func(id string) bool { return id == "sbox-shutdown-retained" }
	manager.Shutdown(preserve)

	data, err = stateStore.LoadRaw(config.SandboxFSStateBucket)
	require.NoError(t, err)
	var persisted storedSandboxFSStates
	require.NoError(t, json.Unmarshal(data, &persisted))
	require.Contains(t, persisted.Items, "sbox-shutdown-retained")
	require.NotContains(t, persisted.Items, "sbox-shutdown-released")
	require.Equal(t, 0, imageService.umountCalls("registry.example/rootfs:latest"),
		"the retained start's rootfs reference must survive shutdown")
	require.Equal(t, 0, imageService.umountCalls("registry.example/data:latest"),
		"the retained start's additional mount must survive shutdown")
}

// A failed start's proof contract covers only what THIS call created. The
// server must not wipe the whole containers/<id> directory on a plain failed
// start: a pre-existing same-ID incarnation's state there survives, and a
// post-success failure whose strict proof fails retains everything.
func TestStartFailureDoesNotWipePreExistingSameIDState(t *testing.T) {
	preExistingMarker := func(t *testing.T, root, id string) string {
		t.Helper()
		marker := filepath.Join(root, "containers", id, "runtime-state", "incarnation.json")
		require.NoError(t, os.MkdirAll(filepath.Dir(marker), 0755))
		require.NoError(t, os.WriteFile(marker, []byte(`{"generation":"old"}`), 0600))
		return marker
	}

	t.Run("plain failed start keeps pre-existing state", func(t *testing.T) {
		handler := &intentRuntimeHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
		handler.setStartErr(errors.New("instance already running under this ID"))
		s := newIntentTestService(t, handler)
		const id = "sbox-collision-plain"
		marker := preExistingMarker(t, s.config.RootDir, id)

		_, err := s.Start(context.Background(), intentTestStartRequest(t, id))
		require.Error(t, err)
		require.FileExists(t, marker,
			"the prover's plain error proves this call's cleanup, not authorization to wipe the same-ID directory")
		require.True(t, s.startIntents.Pending(id) || !intentRecordExistsOnDisk(t, s, id),
			"either retained or cleanly rolled back; the pre-existing state is untouched either way")
		require.FileExists(t, marker)
	})

	t.Run("post-success failure with failed strict proof retains everything", func(t *testing.T) {
		handler := &intentRuntimeHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
		handler.setStrictErr(errors.New("strict delete could not confirm exit"))
		s := newIntentTestService(t, handler)
		const id = "sbox-collision-strict"
		marker := preExistingMarker(t, s.config.RootDir, id)

		networkmanager.Register(testNetworkType, &fakeNetworkManager{failNext: true})
		t.Cleanup(func() { delete(networkmanager.NetworkManagers, testNetworkType) })
		s.config.NatBackend = testNetworkType
		s.networkMgr = newNetworkManager(nil, testNetworkType, false)

		request := intentTestStartRequest(t, id)
		request.Ports = []string{"tcp:8080:80"}
		_, err := s.Start(context.Background(), request)
		require.Error(t, err)
		require.FileExists(t, marker, "an unproven strict exit keeps every artifact")
		require.True(t, s.startIntents.Pending(id))
	})
}

// The full-service Shutdown bridge: a retained start (sentinel failure) keeps
// its persisted filesystem ownership, mounts, sandbox files, and DNAT rules
// through a real sandboxService.Shutdown, while everything the manager lists
// is force-deleted as before.
func TestFullServiceShutdownPreservesRetainedStartChain(t *testing.T) {
	root := t.TempDir()
	fsStateStore := store.NewMockStore()
	imageService := newFSTestImageService()

	handler := &intentRuntimeHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
	s := newIntentTestServiceAtRoot(t, handler, root, fsStateStore)
	s.fsMgr = newFSManager(imageService, fsStateStore)

	networkmanager.Register(testNetworkType, &fakeNetworkManager{})
	t.Cleanup(func() { delete(networkmanager.NetworkManagers, testNetworkType) })
	s.config.NatBackend = testNetworkType
	s.networkMgr = newNetworkManager(nil, testNetworkType, false)

	retainedRequest := fsTestStartRequest("sbox-shutdown-chain")
	retainedRequest.Runtime = config.RuntimeNameRunsc
	retainedRequest.Stdout = os.DevNull
	retainedRequest.Stderr = os.DevNull
	handler.setStartErr(fmt.Errorf(
		"%w: exit unconfirmed: %w", svc.ErrStartCleanupPending, errors.New("vmm survives"),
	))
	_, err := s.Start(context.Background(), retainedRequest)
	require.Error(t, err)
	const retainedID = "sbox-shutdown-chain"
	require.True(t, s.startIntents.Pending(retainedID))
	require.NoError(t, s.networkMgr.setupDnatRules(retainedID, []string{"tcp:8080:80"}, "10.0.0.2"))
	_, statErr := os.Lstat(filepath.Join(root, "containers", retainedID, "sandbox-files"))
	require.NoError(t, statErr)

	s.Shutdown()

	data, err := fsStateStore.LoadRaw(config.SandboxFSStateBucket)
	require.NoError(t, err)
	var persisted storedSandboxFSStates
	require.NoError(t, json.Unmarshal(data, &persisted))
	require.Contains(t, persisted.Items, retainedID,
		"the retained start keeps its persisted filesystem ownership through shutdown")
	require.Equal(t, 0, imageService.umountCalls("registry.example/rootfs:latest"),
		"the retained start's rootfs must not be unmounted by shutdown")
	require.Equal(t, 0, imageService.umountCalls("registry.example/data:latest"),
		"the retained start's additional mount must not be unmounted by shutdown")
	require.NotEmpty(t, s.networkMgr.rulesFor(retainedID),
		"shutdown must not strip a retained start's DNAT rules")
	_, statErr = os.Lstat(filepath.Join(root, "containers", retainedID, "sandbox-files"))
	require.NoError(t, statErr, "shutdown must not remove a retained start's sandbox files")
}

// TestStartCommitWriteFailureMustNotReportSuccess bridges the 0051 terminal
// checker fixture: after the runtime succeeded and the prepared record is
// durable, a committed write that fails with ENOTDIR must surface as a
// non-success (unknown completion) RPC while everything the start owns stays
// protected and no runtime rollback runs. The success control arm runs the
// same flow without the fault.
func TestStartCommitWriteFailureMustNotReportSuccess(t *testing.T) {
	for _, fault := range []bool{false, true} {
		name := "success-control"
		if fault {
			name = "commit-enotdir"
		}
		t.Run(name, func(t *testing.T) {
			handler := &intentRuntimeHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
			s := newIntentTestService(t, handler)
			originalDir := s.startIntents.dir
			const id = "sbox-cn0051-commit-result"

			if fault {
				// After begin() succeeded, redirect the journal directory
				// under a regular file so the committed write fails with
				// ENOTDIR. This is a pre-write failure, not a post-rename
				// fsync uncertainty.
				blocker := filepath.Join(t.TempDir(), "regular-file")
				require.NoError(t, os.WriteFile(blocker, []byte("not a directory"), 0600))
				handler.mu.Lock()
				handler.onStart = func(svc.StartConfig) {
					s.startIntents.dir = filepath.Join(blocker, "journal")
				}
				handler.mu.Unlock()
			}

			resp, err := s.Start(context.Background(), intentTestStartRequest(t, id))
			s.startIntents.dir = originalDir

			if !fault {
				require.NoError(t, err)
				require.NotNil(t, resp)
				require.Equal(t, int32(0), resp.GetCode())
				require.False(t, s.startIntents.Pending(id))
				return
			}

			reportedSuccess := err == nil && resp != nil && resp.GetCode() == 0
			require.False(t, reportedSuccess,
				"an uncommitted start handover must not be reported as successful (resp=%v err=%v)", resp, err)
			require.NotNil(t, resp, "the unknown-completion response must still identify the sandbox")
			require.Equal(t, id, resp.GetID())

			require.True(t, s.startIntents.Pending(id), "the commit failure must keep the pending protection")
			require.True(t, fsStateOwned(s, id), "the commit failure must keep the filesystem ownership")
			_, resErr := s.sandboxManager.ReserveID(id)
			require.Error(t, resErr, "the commit failure must keep the ID reserved")
			require.FileExists(t, filepath.Join(originalDir, id+".json"),
				"the original durable prepared record must survive unchanged")
			record := readIntentFromDisk(t, s, id)
			require.Equal(t, startIntentPhasePrepared, record.Phase,
				"the failed completion must not leave a committed or retained phase on disk")

			_, legacyDeletes, strictDeletes := handler.counts()
			require.Zero(t, legacyDeletes, "an unknown completion must not trigger a runtime rollback")
			require.Zero(t, strictDeletes, "an unknown completion must not trigger a strict runtime rollback")
		})
	}
}
