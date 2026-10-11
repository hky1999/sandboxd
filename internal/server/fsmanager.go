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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/langrtmanager"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	imageapi "github.com/inclusionAI/sandboxd/pkg/imagemanager/api"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

const fsJournalSchema = 5
const fsJournalLimit = 65536

type fsLeasePhase string

const (
	fsReserved       fsLeasePhase = "reserved"
	fsAcquiring      fsLeasePhase = "acquiring"
	fsAcquired       fsLeasePhase = "acquired"
	fsReleasePending fsLeasePhase = "release_pending"
	fsReleased       fsLeasePhase = "released"
)

type fsManager struct {
	rootfs          *langrtmanager.LangRTManager
	s3              *s3MountManager
	oci             *ociMountManager
	mu              sync.Mutex
	sandboxRootfs   map[string]*langrtmanager.LanguageRuntime
	sandboxS3Mount  map[string][]*runtime.S3Config
	sandboxOCIMount map[string][]string
	sandboxState    map[string]sandboxFSState
	completed       map[string]fsCompletion
	store           store.DbStore
	persistMu       sync.Mutex // serializes ownership, backend references and journal writes
	loaded          bool
}

type preparedFS struct {
	manager    *fsManager
	sandboxID  string
	generation string
	rootfs     *langrtmanager.LanguageRuntime
	source     *runtime.RootfsConfig
	mounts     []*runtime.Mount
	s3         []*runtime.S3Config
	oci        []string
}

type sandboxFSState struct {
	MountOperationProtocol uint8               `json:"mount_operation_protocol,omitempty"`
	ReleaseRequested       bool                `json:"release_requested,omitempty"`
	RootfsMountGeneration  string              `json:"rootfs_mount_generation,omitempty"`
	S3MountGenerations     []string            `json:"s3_mount_generations,omitempty"`
	OCIMountGenerations    []string            `json:"oci_mount_generations,omitempty"`
	SourceFingerprint      string              `json:"source_fingerprint"`
	Generation             string              `json:"generation,omitempty"`
	Rootfs                 []byte              `json:"rootfs,omitempty"`
	S3                     []*runtime.S3Config `json:"s3,omitempty"`
	OCI                    []string            `json:"oci,omitempty"`
	RootfsPhase            fsLeasePhase        `json:"rootfs_phase"`
	S3Phases               []fsLeasePhase      `json:"s3_phases,omitempty"`
	OCIPhases              []fsLeasePhase      `json:"oci_phases,omitempty"`
}

type fsCompletion struct {
	SandboxID         string `json:"sandbox_id"`
	Generation        string `json:"generation"`
	SourceFingerprint string `json:"source_fingerprint"`
}

type storedSandboxFSStates struct {
	IntegritySHA256 string                    `json:"integrity_sha256,omitempty"`
	SchemaVersion   int                       `json:"schema_version,omitempty"`
	Items           map[string]sandboxFSState `json:"items"`
	Completed       map[string]fsCompletion   `json:"completed,omitempty"`
}

func newFSManager(imgSvc imageapi.Service, stores ...store.DbStore) *fsManager {
	m := &fsManager{
		s3: newS3MountManagerForFS(imgSvc), oci: newOciMountManagerForFS(imgSvc),
		sandboxRootfs:   make(map[string]*langrtmanager.LanguageRuntime),
		sandboxS3Mount:  make(map[string][]*runtime.S3Config),
		sandboxOCIMount: make(map[string][]string), sandboxState: make(map[string]sandboxFSState),
		completed: make(map[string]fsCompletion),
	}
	if len(stores) > 0 {
		m.store = stores[0]
	}
	m.rootfs = langrtmanager.NewLanguageRuntimeManager(&fsImageMounter{
		manager: m, local: langrtmanager.NewDefaultMounter(imgSvc),
	})
	return m
}

func newS3MountManagerForFS(imgSvc imageapi.Service) *s3MountManager {
	if imgSvc != nil {
		return newS3MountManager(imgSvc)
	}
	return &s3MountManager{entries: make(map[string]*imageMountEntry), unmountF: func(_, _, _ string) error { return nil }}
}
func newOciMountManagerForFS(imgSvc imageapi.Service) *ociMountManager {
	if imgSvc != nil {
		return newOciMountManager(imgSvc)
	}
	return &ociMountManager{entries: make(map[string]*imageMountEntry), unmountF: func(string) error { return nil }}
}

func (m *fsManager) Prepare(request *runtime.StartRequest) (*preparedFS, error) {
	if request == nil || request.Rootfs == nil || request.SandboxID == "" {
		return nil, fmt.Errorf("filesystem preparation requires an ID and rootfs source")
	}
	request = proto.Clone(request).(*runtime.StartRequest)
	p := &preparedFS{manager: m, sandboxID: request.SandboxID,
		generation: request.Labels[resourceGenerationLabel],
		source:     proto.Clone(request.Rootfs).(*runtime.RootfsConfig), mounts: cloneMounts(request.Mounts)}
	rootfs, err := proto.Marshal(p.source)
	if err != nil {
		return nil, err
	}
	state := sandboxFSState{Generation: p.generation, Rootfs: rootfs, RootfsPhase: fsReserved}
	if p.generation != "" {
		state.MountOperationProtocol = 1
	}
	if p.sandboxID == "" || strings.ContainsRune(p.sandboxID, 0) || strings.ContainsRune(p.generation, 0) {
		return nil, fmt.Errorf("invalid filesystem owner identity")
	}
	for _, mount := range p.mounts {
		if mount == nil {
			continue
		}
		switch source := mount.GetSource().(type) {
		case *runtime.Mount_S3Config:
			if err := requireReadOnlyMount(mount); err != nil {
				return nil, err
			}
			if source.S3Config == nil {
				return nil, fmt.Errorf("S3 source is missing")
			}
			state.S3 = append(state.S3, proto.Clone(source.S3Config).(*runtime.S3Config))
			state.S3Phases = append(state.S3Phases, fsReserved)
			state.S3MountGenerations = append(state.S3MountGenerations, "")
		case *runtime.Mount_ImageUrl:
			if err := requireReadOnlyMount(mount); err != nil {
				return nil, err
			}
			if source.ImageUrl == "" {
				return nil, fmt.Errorf("OCI source is missing")
			}
			state.OCI = append(state.OCI, source.ImageUrl)
			state.OCIPhases = append(state.OCIPhases, fsReserved)
			state.OCIMountGenerations = append(state.OCIMountGenerations, "")
		}
	}
	if err := validateFSSources(state); err != nil {
		return nil, err
	}
	state.SourceFingerprint, err = fsSourceFingerprint(p.sandboxID, state)
	if err != nil {
		return nil, err
	}
	if state.MountOperationProtocol == 1 {
		if m.store == nil {
			return nil, fmt.Errorf("managed filesystem operations require a persistent ownership journal")
		}
		if id := fsMountOperationID(state, "rootfs", 0); id != "" {
			svc := m.oci.svc
			if p.source.Type == runtime.RootfsSrcType_S3 {
				svc = m.s3.svc
			}
			if err := requireFSMountOperationService(svc, id); err != nil {
				return nil, err
			}
		}
		if len(state.S3) > 0 {
			if err := requireFSMountOperationService(m.s3.svc, fsMountOperationID(state, "s3", 0)); err != nil {
				return nil, err
			}
		}
		if len(state.OCI) > 0 {
			if err := requireFSMountOperationService(m.oci.svc, fsMountOperationID(state, "oci", 0)); err != nil {
				return nil, err
			}
		}
	}
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	if err := m.loadLocked(); err != nil {
		return nil, err
	}
	// Existing owners must be reconstructed before this source can be shared.
	if err := m.recoverAllLocked(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	_, exists := m.sandboxState[p.sandboxID]
	_, retired := m.completed[fsCompletionKey(p.sandboxID, p.generation)]
	if !exists && (p.generation == "" || !retired) && len(m.sandboxState)+len(m.completed) < fsJournalLimit {
		if p.generation == "" {
			delete(m.completed, fsCompletionKey(p.sandboxID, ""))
		}
		m.sandboxState[p.sandboxID] = cloneFSState(state)
	} else {
		m.mu.Unlock()
		return nil, fmt.Errorf("filesystem owner exists or journal is full")
	}
	m.mu.Unlock()
	if err := m.persistCurrentState(); err != nil {
		return p, err
	}
	if err := m.checkSourceAdmissionLocked(state); err != nil {
		return p, err
	}
	state.RootfsPhase = fsAcquiring
	if err := m.saveStateLocked(p.sandboxID, state); err != nil {
		return p, err
	}
	lr, err := m.rootfs.AddLangRuntimeWithMountOperation(request, true, "", p.generation != "", false, fsMountOperationID(state, "rootfs", 0))
	if err != nil {
		return p, err
	}
	lr.IncRef()
	p.rootfs = lr
	m.mu.Lock()
	m.sandboxRootfs[p.sandboxID] = lr
	m.mu.Unlock()
	state.RootfsPhase = fsAcquired
	state.RootfsMountGeneration = lr.RootFS.PhysicalGeneration()
	if err := m.saveStateLocked(p.sandboxID, state); err != nil {
		return p, err
	}
	si, oi := 0, 0
	for _, mount := range p.mounts {
		if mount == nil {
			continue
		}
		switch source := mount.GetSource().(type) {
		case *runtime.Mount_S3Config:
			state.S3Phases[si] = fsAcquiring
			if err := m.saveStateLocked(p.sandboxID, state); err != nil {
				return p, err
			}
			entry, err := m.s3.mountS3Operation(source.S3Config, "", p.generation != "", false, fsMountOperationID(state, "s3", si))
			if err != nil {
				return p, err
			}
			m.setS3Handle(p.sandboxID, si, len(state.S3), state.S3[si])
			p.s3 = append(p.s3, state.S3[si])
			mount.Source = &runtime.Mount_HostPath{HostPath: entry.path}
			state.S3Phases[si] = fsAcquired
			state.S3MountGenerations[si] = entry.physicalGeneration
			if err := m.saveStateLocked(p.sandboxID, state); err != nil {
				return p, err
			}
			si++
		case *runtime.Mount_ImageUrl:
			state.OCIPhases[oi] = fsAcquiring
			if err := m.saveStateLocked(p.sandboxID, state); err != nil {
				return p, err
			}
			entry, err := m.oci.mountOCIOperation(source.ImageUrl, "", p.generation != "", false, fsMountOperationID(state, "oci", oi))
			if err != nil {
				return p, err
			}
			m.setOCIHandle(p.sandboxID, oi, len(state.OCI), source.ImageUrl)
			p.oci = append(p.oci, source.ImageUrl)
			mount.Source = &runtime.Mount_HostPath{HostPath: entry.path}
			state.OCIPhases[oi] = fsAcquired
			state.OCIMountGenerations[oi] = entry.physicalGeneration
			if err := m.saveStateLocked(p.sandboxID, state); err != nil {
				return p, err
			}
			oi++
		}
	}
	return p, nil
}

func (m *fsManager) Commit(sandboxID string, prepared *preparedFS) error {
	if prepared == nil || prepared.manager != m || prepared.sandboxID != sandboxID {
		return fmt.Errorf("filesystem commit does not own the prepared identity")
	}
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	m.mu.Lock()
	state, exists := m.sandboxState[sandboxID]
	m.mu.Unlock()
	if !exists || state.Generation != prepared.generation {
		return fmt.Errorf("filesystem owner changed")
	}
	// A failed write keeps the in-memory owner and the earlier durable intent.
	return m.persistCurrentState()
}

func (m *fsManager) Release(sandboxID string) error {
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	if err := m.loadLocked(); err != nil {
		return err
	}
	m.mu.Lock()
	state, exists := m.sandboxState[sandboxID]
	m.mu.Unlock()
	if exists && state.Generation != "" {
		return fmt.Errorf("filesystem release requires the original resource generation")
	}
	return m.releaseLocked(sandboxID, "", false)
}

func (m *fsManager) ReleaseIfGeneration(sandboxID, generation string) error {
	if sandboxID == "" || generation == "" {
		return fmt.Errorf("filesystem release requires original identity")
	}
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	if err := m.loadLocked(); err != nil {
		return err
	}
	return m.releaseLocked(sandboxID, generation, true)
}

func fsCompletionKey(id, generation string) string {
	sum := sha256.Sum256([]byte(id + "\x00" + generation))
	return hex.EncodeToString(sum[:])
}

func (m *fsManager) releaseLocked(id, generation string, conditional bool) error {
	key := fsCompletionKey(id, generation)
	m.mu.Lock()
	receipt, completed := m.completed[key]
	state, exists := m.sandboxState[id]
	m.mu.Unlock()
	if conditional && completed && receipt.SandboxID == id && receipt.Generation == generation {
		return nil // original completion never touches a replacement owner
	}
	if !exists {
		if conditional {
			return fmt.Errorf("filesystem completion is unknown: %w", errord.ErrNotFound)
		}
		return nil
	}
	if state.Generation != generation {
		return fmt.Errorf("filesystem generation changed")
	}
	// Flush any in-memory confirmation whose preceding write failed, BEFORE
	// taking another reference or changing a backend. This prevents double release.
	if err := m.persistCurrentState(); err != nil {
		return err
	}
	state = cloneFSState(state)
	state.ReleaseRequested = true
	if err := m.saveStateLocked(id, state); err != nil {
		return err
	}
	if err := m.recoverAllLocked(); err != nil {
		return err
	}
	m.mu.Lock()
	state = cloneFSState(m.sandboxState[id])
	m.mu.Unlock()
	releaseStep := func(phase *fsLeasePhase, release func() error) error {
		if *phase == fsReleased {
			return nil
		}
		if *phase == fsReserved {
			*phase = fsReleased
			return m.saveStateLocked(id, state)
		}
		*phase = fsReleasePending
		if err := m.saveStateLocked(id, state); err != nil {
			return err
		}
		if err := release(); err != nil {
			return err
		}
		*phase = fsReleased
		return m.saveStateLocked(id, state)
	}
	if err := releaseStep(&state.RootfsPhase, func() error {
		m.mu.Lock()
		lr := m.sandboxRootfs[id]
		m.mu.Unlock()
		if lr == nil {
			return fmt.Errorf("rootfs reference is unknown")
		}
		if state.RootfsMountGeneration != lr.RootFS.PhysicalGeneration() {
			return fmt.Errorf("original rootfs reference generation changed")
		}
		if err := lr.DecRef(); err != nil {
			return err
		}
		m.mu.Lock()
		delete(m.sandboxRootfs, id)
		m.mu.Unlock()
		return nil
	}); err != nil {
		return err
	}
	for i := range state.S3 {
		if err := releaseStep(&state.S3Phases[i], func() error {
			m.mu.Lock()
			handles := m.sandboxS3Mount[id]
			known := i < len(handles) && handles[i] != nil
			m.mu.Unlock()
			if !known {
				return fmt.Errorf("S3 reference is unknown")
			}
			if err := m.s3.unmountS3Generation(state.S3[i], state.S3MountGenerations[i]); err != nil {
				return err
			}
			m.setS3Handle(id, i, len(state.S3), nil)
			return nil
		}); err != nil {
			return err
		}
	}
	for i := range state.OCI {
		if err := releaseStep(&state.OCIPhases[i], func() error {
			m.mu.Lock()
			handles := m.sandboxOCIMount[id]
			known := i < len(handles) && handles[i] != ""
			m.mu.Unlock()
			if !known {
				return fmt.Errorf("OCI reference is unknown")
			}
			if err := m.oci.unmountOCIGeneration(state.OCI[i], state.OCIMountGenerations[i]); err != nil {
				return err
			}
			m.setOCIHandle(id, i, len(state.OCI), "")
			return nil
		}); err != nil {
			return err
		}
	}
	m.mu.Lock()
	previousReceipt, previousExists := m.completed[key]
	m.completed[key] = fsCompletion{SandboxID: id, Generation: generation, SourceFingerprint: state.SourceFingerprint}
	delete(m.sandboxState, id)
	m.mu.Unlock()
	if err := m.persistCurrentState(); err != nil {
		m.mu.Lock()
		m.sandboxState[id] = cloneFSState(state)
		if previousExists {
			m.completed[key] = previousReceipt
		} else {
			delete(m.completed, key)
		}
		m.mu.Unlock()
		return err
	}
	m.mu.Lock()
	delete(m.sandboxS3Mount, id)
	delete(m.sandboxOCIMount, id)
	m.mu.Unlock()
	return nil
}

func (m *fsManager) RootfsConfig(id string) (*runtime.RootfsConfig, error) {
	m.mu.Lock()
	state, exists := m.sandboxState[id]
	state = cloneFSState(state)
	m.mu.Unlock()
	if !exists || len(state.Rootfs) == 0 {
		return nil, fmt.Errorf("rootfs source is unknown: %w", errord.ErrNotFound)
	}
	rootfs := &runtime.RootfsConfig{}
	if err := proto.Unmarshal(state.Rootfs, rootfs); err != nil {
		return nil, err
	}
	return rootfs, nil
}

func (m *fsManager) Shutdown() {
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	if err := m.loadLocked(); err != nil {
		logrus.Warnf("preserve unreadable filesystem journal during shutdown: %v", err)
		return
	}
	// Daemon shutdown is not sandbox retirement. Preserve all owners and mounts.
	if err := m.persistCurrentState(); err != nil {
		logrus.Warnf("persist filesystem shutdown state: %v", err)
	}
}

func cloneS3Configs(configs []*runtime.S3Config) []*runtime.S3Config {
	result := make([]*runtime.S3Config, len(configs))
	for i, cfg := range configs {
		if cfg != nil {
			result[i] = proto.Clone(cfg).(*runtime.S3Config)
		}
	}
	return result
}
func cloneFSState(s sandboxFSState) sandboxFSState {
	s.Rootfs = append([]byte(nil), s.Rootfs...)
	s.S3 = cloneS3Configs(s.S3)
	s.OCI = append([]string(nil), s.OCI...)
	s.S3Phases = append([]fsLeasePhase(nil), s.S3Phases...)
	s.OCIPhases = append([]fsLeasePhase(nil), s.OCIPhases...)
	s.S3MountGenerations = append([]string(nil), s.S3MountGenerations...)
	s.OCIMountGenerations = append([]string(nil), s.OCIMountGenerations...)
	return s
}
func (m *fsManager) saveStateLocked(id string, state sandboxFSState) error {
	m.mu.Lock()
	original, exists := m.sandboxState[id]
	if !exists || original.Generation != state.Generation || original.SourceFingerprint != state.SourceFingerprint || original.MountOperationProtocol != state.MountOperationProtocol || original.ReleaseRequested && !state.ReleaseRequested || changedKnownMountGeneration(original.RootfsMountGeneration, state.RootfsMountGeneration) || changedKnownMountGenerations(original.S3MountGenerations, state.S3MountGenerations) || changedKnownMountGenerations(original.OCIMountGenerations, state.OCIMountGenerations) {
		m.mu.Unlock()
		return fmt.Errorf("original filesystem owner or mount identity changed")
	}
	m.sandboxState[id] = cloneFSState(state)
	m.mu.Unlock()
	return m.persistCurrentState()
}

func changedKnownMountGeneration(original, next string) bool {
	return original != "" && original != next
}

func changedKnownMountGenerations(original, next []string) bool {
	if len(original) != len(next) {
		return true
	}
	for i := range original {
		if changedKnownMountGeneration(original[i], next[i]) {
			return true
		}
	}
	return false
}
func (m *fsManager) persistCurrentState() error {
	if m.store == nil {
		return nil
	}
	m.mu.Lock()
	stored := storedSandboxFSStates{SchemaVersion: fsJournalSchema, Items: make(map[string]sandboxFSState, len(m.sandboxState)), Completed: make(map[string]fsCompletion, len(m.completed))}
	for id, state := range m.sandboxState {
		stored.Items[id] = cloneFSState(state)
	}
	for key, receipt := range m.completed {
		stored.Completed[key] = receipt
	}
	m.mu.Unlock()
	if err := validateFSJournal(stored); err != nil {
		return err
	}
	integrity, err := fsJournalIntegrity(stored)
	if err != nil {
		return err
	}
	stored.IntegritySHA256 = integrity
	data, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	if err := m.store.StoreRaw(config.SandboxFSStateBucket, data); err != nil {
		return fmt.Errorf("persist filesystem ownership: %w", err)
	}
	return nil
}

func (m *fsManager) loadLocked() error {
	if m.loaded {
		return nil
	}
	if m.store == nil {
		m.loaded = true
		return nil
	}
	data, err := m.store.LoadRaw(config.SandboxFSStateBucket)
	if errord.IsNotFound(err) {
		m.loaded = true
		return nil
	}
	if err != nil {
		return err
	}
	stored, err := decodeFSJournal(data)
	if err != nil {
		return err
	}
	m.mu.Lock()
	for id, state := range stored.Items {
		m.sandboxState[id] = cloneFSState(state)
	}
	for key, receipt := range stored.Completed {
		m.completed[key] = receipt
	}
	m.mu.Unlock()
	m.loaded = true
	return nil
}

// Validate before ANY reconstruction or orphan cleanup. Otherwise a missing
// physical owner's journal could undercount a shared mount and release its
// source as if an unrelated orphan held the final reference.
func (m *fsManager) ValidatePhysicalOwners(owners []*runtime.SandboxMetadata) error {
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	if err := m.loadLocked(); err != nil {
		return err
	}
	for _, metadata := range owners {
		if metadata == nil || metadata.ID == "" {
			return fmt.Errorf("physical owner is incomplete")
		}
		generation := metadata.Labels[resourceGenerationLabel]
		m.mu.Lock()
		state, exists := m.sandboxState[metadata.ID]
		receipt, completed := m.completed[fsCompletionKey(metadata.ID, generation)]
		m.mu.Unlock()
		if generation != "" && metadata.PhysicalPhase == runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_INTENT && completed && receipt.SandboxID == metadata.ID && receipt.Generation == generation {
			continue
		}
		if !exists || state.Generation != generation {
			return fmt.Errorf("filesystem owner %s is missing or changed", metadata.ID)
		}
		if metadata.PhysicalPhase != runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_INTENT {
			if state.ReleaseRequested {
				return fmt.Errorf("published filesystem owner %s has unresolved cleanup", metadata.ID)
			}
			phases := append([]fsLeasePhase{state.RootfsPhase}, state.S3Phases...)
			phases = append(phases, state.OCIPhases...)
			for _, phase := range phases {
				if phase != fsAcquired {
					return fmt.Errorf("published filesystem owner %s has unresolved cleanup", metadata.ID)
				}
			}
		}
	}
	return nil
}

// Rebuild every surviving owner before allowing an orphan to release a shared
// source. An interrupted acquire/release re-acquires its OWN reference; it never
// decrements a neighbor's reconstructed reference or treats absence as success.
func (m *fsManager) Restore(sandboxExists func(string) bool) error {
	m.persistMu.Lock()
	defer m.persistMu.Unlock()
	if err := m.loadLocked(); err != nil {
		return err
	}
	if err := m.persistCurrentState(); err != nil {
		return err
	}
	orphans := make(map[string]bool)
	for _, id := range m.ownerIDs() {
		if sandboxExists != nil && !sandboxExists(id) {
			orphans[id] = true
			m.mu.Lock()
			state := cloneFSState(m.sandboxState[id])
			m.mu.Unlock()
			state.ReleaseRequested = true
			if err := m.saveStateLocked(id, state); err != nil {
				return err
			}
		}
	}
	if err := m.recoverAllLocked(); err != nil {
		return err
	}
	ids := m.ownerIDs()
	for _, id := range ids {
		if orphans[id] {
			m.mu.Lock()
			generation := m.sandboxState[id].Generation
			m.mu.Unlock()
			if err := m.releaseLocked(id, generation, generation != ""); err != nil {
				return fmt.Errorf("release orphan filesystem %s: %w", id, err)
			}
		}
	}
	return m.persistCurrentState()
}
func (m *fsManager) ownerIDs() []string {
	m.mu.Lock()
	ids := make([]string, 0, len(m.sandboxState))
	for id := range m.sandboxState {
		ids = append(ids, id)
	}
	m.mu.Unlock()
	sort.Strings(ids)
	return ids
}
func (m *fsManager) recoverAllLocked() error {
	// An unknown managed acquisition cannot be turned into a new mount by URL.
	// Check the entire inventory before reconstructing any shared reference.
	if err := m.persistCurrentState(); err != nil {
		return err
	}
	resolved := make(map[string]sandboxFSState)
	for _, id := range m.ownerIDs() {
		m.mu.Lock()
		state := cloneFSState(m.sandboxState[id])
		m.mu.Unlock()
		next, err := m.resolveFSOriginalOperationsLocked(state)
		if err != nil {
			return fmt.Errorf("resolve original filesystem %s: %w", id, err)
		}
		if state.RootfsPhase != next.RootfsPhase || !slices.Equal(state.S3Phases, next.S3Phases) || !slices.Equal(state.OCIPhases, next.OCIPhases) || state.RootfsMountGeneration != next.RootfsMountGeneration || !slices.Equal(state.S3MountGenerations, next.S3MountGenerations) || !slices.Equal(state.OCIMountGenerations, next.OCIMountGenerations) {
			resolved[id] = next
		}
	}
	for _, id := range m.ownerIDs() {
		if next, changed := resolved[id]; changed {
			if err := m.saveStateLocked(id, next); err != nil {
				return err
			}
		}
	}
	var failures []error
	for _, id := range m.ownerIDs() {
		if err := m.recoverSandboxLocked(id); err != nil {
			failures = append(failures, fmt.Errorf("recover filesystem %s: %w", id, err))
		}
	}
	return errors.Join(failures...)
}

func (m *fsManager) checkSourceAdmissionLocked(state sandboxFSState) error {
	rootfs := &runtime.RootfsConfig{}
	if err := proto.Unmarshal(state.Rootfs, rootfs); err != nil {
		return err
	}
	oci := append([]string(nil), state.OCI...)
	s3 := cloneS3Configs(state.S3)
	if rootfs.Type == runtime.RootfsSrcType_IMAGE {
		oci = append(oci, rootfs.GetImageUrl())
	}
	if rootfs.Type == runtime.RootfsSrcType_S3 {
		s3 = append(s3, rootfs.GetS3Config())
	}
	m.oci.mu.Lock()
	for _, source := range oci {
		if imageMountSourceBlocked(m.oci.entries, m.oci.generations, source) {
			m.oci.mu.Unlock()
			return fmt.Errorf("OCI source release is unconfirmed")
		}
	}
	m.oci.mu.Unlock()
	m.s3.mu.Lock()
	defer m.s3.mu.Unlock()
	for _, source := range s3 {
		if source == nil {
			return fmt.Errorf("S3 source is missing")
		}
		if imageMountSourceBlocked(m.s3.entries, m.s3.generations, s3MountKey(source)) {
			return fmt.Errorf("S3 source release is unconfirmed")
		}
	}
	return nil
}
func needsFSReference(phase fsLeasePhase) bool { return phase != fsReserved && phase != fsReleased }
func (m *fsManager) recoverSandboxLocked(id string) error {
	m.mu.Lock()
	state := cloneFSState(m.sandboxState[id])
	lr := m.sandboxRootfs[id]
	m.mu.Unlock()
	if needsFSReference(state.RootfsPhase) && lr == nil {
		rootfs := &runtime.RootfsConfig{}
		if err := proto.Unmarshal(state.Rootfs, rootfs); err != nil {
			return err
		}
		recovered, err := m.rootfs.AddLangRuntimeWithMountOperation(&runtime.StartRequest{SandboxID: id, Rootfs: rootfs}, true, state.RootfsMountGeneration, state.Generation != "", state.ReleaseRequested || state.RootfsPhase == fsReleasePending, fsMountOperationID(state, "rootfs", 0))
		if err != nil {
			return err
		}
		recovered.IncRef()
		m.mu.Lock()
		m.sandboxRootfs[id] = recovered
		m.mu.Unlock()
		if state.RootfsPhase == fsAcquiring {
			state.RootfsPhase = fsAcquired
		}
		state.RootfsMountGeneration = recovered.RootFS.PhysicalGeneration()
		if err := m.saveStateLocked(id, state); err != nil {
			return err
		}
	}
	for i, source := range state.S3 {
		if !needsFSReference(state.S3Phases[i]) {
			continue
		}
		m.mu.Lock()
		handles := m.sandboxS3Mount[id]
		known := i < len(handles) && handles[i] != nil
		m.mu.Unlock()
		if known {
			continue
		}
		entry, err := m.s3.mountS3Operation(source, state.S3MountGenerations[i], state.Generation != "", state.ReleaseRequested || state.S3Phases[i] == fsReleasePending, fsMountOperationID(state, "s3", i))
		if err != nil {
			return err
		}
		m.setS3Handle(id, i, len(state.S3), source)
		if state.S3Phases[i] == fsAcquiring {
			state.S3Phases[i] = fsAcquired
		}
		state.S3MountGenerations[i] = entry.physicalGeneration
		if err := m.saveStateLocked(id, state); err != nil {
			return err
		}
	}
	for i, source := range state.OCI {
		if !needsFSReference(state.OCIPhases[i]) {
			continue
		}
		m.mu.Lock()
		handles := m.sandboxOCIMount[id]
		known := i < len(handles) && handles[i] != ""
		m.mu.Unlock()
		if known {
			continue
		}
		entry, err := m.oci.mountOCIOperation(source, state.OCIMountGenerations[i], state.Generation != "", state.ReleaseRequested || state.OCIPhases[i] == fsReleasePending, fsMountOperationID(state, "oci", i))
		if err != nil {
			return err
		}
		m.setOCIHandle(id, i, len(state.OCI), source)
		if state.OCIPhases[i] == fsAcquiring {
			state.OCIPhases[i] = fsAcquired
		}
		state.OCIMountGenerations[i] = entry.physicalGeneration
		if err := m.saveStateLocked(id, state); err != nil {
			return err
		}
	}
	return nil
}
func (m *fsManager) setS3Handle(id string, index, count int, source *runtime.S3Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sandboxS3Mount[id] == nil {
		m.sandboxS3Mount[id] = make([]*runtime.S3Config, count)
	}
	m.sandboxS3Mount[id][index] = source
}
func (m *fsManager) setOCIHandle(id string, index, count int, source string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sandboxOCIMount[id] == nil {
		m.sandboxOCIMount[id] = make([]string, count)
	}
	m.sandboxOCIMount[id][index] = source
}
func (p *preparedFS) RootfsPath() string {
	if p == nil || p.rootfs == nil || p.rootfs.RootFS == nil {
		return ""
	}
	return p.rootfs.RootFS.Path()
}
func (p *preparedFS) Mounts() []*runtime.Mount {
	if p == nil {
		return nil
	}
	return p.mounts
}
func (p *preparedFS) Rollback() error {
	if p == nil {
		return nil
	}
	if p.generation != "" {
		return p.manager.ReleaseIfGeneration(p.sandboxID, p.generation)
	}
	return p.manager.Release(p.sandboxID)
}
func cloneMounts(mounts []*runtime.Mount) []*runtime.Mount {
	result := make([]*runtime.Mount, len(mounts))
	for i, mount := range mounts {
		if mount != nil {
			result[i] = proto.Clone(mount).(*runtime.Mount)
		}
	}
	return result
}
