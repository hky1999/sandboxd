// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package xpumanager

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	api "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/inclusionAI/sandboxd/pkg/store"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

const generationLeaseBucket = "scheduler-xpu-generation-leases"
const generationLeaseLimit = 65536
const generationJournalBytes = 64 * 1024 * 1024

type generationLeaseRecord struct {
	Generation  string      `json:"generation"`
	SandboxID   string      `json:"sandbox_id"`
	Request     []byte      `json:"request"`
	Fingerprint string      `json:"request_fingerprint"`
	State       string      `json:"state"`
	Allocated   bool        `json:"allocation_confirmed"`
	Lease       leaseRecord `json:"lease"`
}

type generationLeaseState struct {
	Version         int                              `json:"version"`
	JournalID       string                           `json:"journal_id"`
	DirectoryDevice uint64                           `json:"directory_device"`
	DirectoryInode  uint64                           `json:"directory_inode"`
	Records         map[string]generationLeaseRecord `json:"records"`
	IntegritySHA256 string                           `json:"integrity_sha256"`
}

type generationJournalOwner struct {
	path                    string
	directory, lock         *os.File
	directoryStat, lockStat unix.Stat_t
	initialization          deviceJournalInitialization
	createdNamespace        bool
}

type deviceJournalInitialization struct {
	JournalID       string `json:"journal_id"`
	DirectoryDevice uint64 `json:"directory_device"`
	DirectoryInode  uint64 `json:"directory_inode"`
	Phase           string `json:"phase"`
}

func (o *generationJournalOwner) loadInitialization() (bool, error) {
	fd, err := unix.Openat(int(o.directory.Fd()), "initialization.json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	f := os.NewFile(uintptr(fd), "initialization.json")
	defer f.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || stat.Size > 1024 {
		return false, errors.New("device journal initialization is not private bounded data")
	}
	data, err := io.ReadAll(io.LimitReader(f, 1025))
	if err != nil {
		return false, err
	}
	var record deviceJournalInitialization
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return false, err
	}
	canonical, _ := json.Marshal(record)
	if !bytes.Equal(data, canonical) {
		return false, errors.New("device journal initialization encoding differs")
	}
	if len(record.JournalID) != 64 || record.DirectoryDevice != uint64(o.directoryStat.Dev) || record.DirectoryInode != o.directoryStat.Ino || (record.Phase != "pending" && record.Phase != "complete") {
		return false, errors.New("original device journal initialization changed")
	}
	if _, err := hex.DecodeString(record.JournalID); err != nil {
		return false, err
	}
	o.initialization = record
	return true, nil
}

func (o *generationJournalOwner) publishInitialization(record deviceJournalInitialization) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(o.path, ".initialization-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
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
	if err := os.Rename(name, filepath.Join(o.path, "initialization.json")); err != nil {
		return err
	}
	if err := o.directory.Sync(); err != nil {
		return err
	}
	o.initialization = record
	return nil
}

func openGenerationJournalOwner(sandboxRoot string) (*generationJournalOwner, error) {
	if !filepath.IsAbs(sandboxRoot) || filepath.Clean(sandboxRoot) != sandboxRoot {
		return nil, errors.New("device journal requires its canonical absolute sandbox root")
	}
	path := filepath.Join(filepath.Dir(sandboxRoot), "scheduler-xpu-leases")
	created := true
	if err := os.Mkdir(path, 0700); errors.Is(err, os.ErrExist) {
		created = false
	} else if err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	o := &generationJournalOwner{path: path, directory: os.NewFile(uintptr(fd), path), createdNamespace: created}
	ok := false
	defer func() {
		if !ok {
			o.close()
		}
	}()
	if err := unix.Fstat(fd, &o.directoryStat); err != nil || o.directoryStat.Uid != uint32(os.Geteuid()) || o.directoryStat.Mode&07777 != 0700 {
		return nil, errors.New("device journal directory is not privately owned")
	}
	lockFD, err := unix.Openat(fd, ".lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	o.lock = os.NewFile(uintptr(lockFD), ".lock")
	if err := unix.Fstat(lockFD, &o.lockStat); err != nil || o.lockStat.Mode&unix.S_IFMT != unix.S_IFREG || o.lockStat.Mode&07777 != 0600 || o.lockStat.Uid != uint32(os.Geteuid()) || o.lockStat.Nlink != 1 || o.lockStat.Size != 0 {
		return nil, errors.New("device journal owner lock is invalid")
	}
	if err := unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("device journal already has an owner: %w", err)
	}
	if err := o.lock.Sync(); err != nil {
		return nil, err
	}
	if err := o.directory.Sync(); err != nil {
		return nil, err
	}
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	if err = parent.Sync(); err != nil {
		return nil, err
	}
	ok = true
	return o, nil
}

func (o *generationJournalOwner) check() error {
	if o == nil || o.directory == nil || o.lock == nil {
		return errors.New("device journal has no live owner")
	}
	var directory, lock unix.Stat_t
	if err := unix.Lstat(o.path, &directory); err != nil || directory.Dev != o.directoryStat.Dev || directory.Ino != o.directoryStat.Ino || directory.Mode != o.directoryStat.Mode || directory.Uid != o.directoryStat.Uid {
		return errors.New("original device journal directory changed")
	}
	if err := unix.Fstatat(int(o.directory.Fd()), ".lock", &lock, unix.AT_SYMLINK_NOFOLLOW); err != nil || lock.Dev != o.lockStat.Dev || lock.Ino != o.lockStat.Ino || lock.Mode != o.lockStat.Mode || lock.Uid != o.lockStat.Uid || lock.Nlink != 1 || lock.Size != 0 {
		return errors.New("original device journal owner lock changed")
	}
	if o.initialization.JournalID != "" {
		before := o.initialization
		probe := *o
		present, err := probe.loadInitialization()
		if err != nil || !present || probe.initialization != before {
			return errors.New("original device journal initialization is missing or changed")
		}
	}
	return nil
}

func (o *generationJournalOwner) close() {
	if o == nil {
		return
	}
	if o.lock != nil {
		o.lock.Close()
		o.lock = nil
	}
	if o.directory != nil {
		o.directory.Close()
		o.directory = nil
	}
}

// NewWithStore owns the device journal independently of accelerator discovery.
// CPU-only requests still have explicit durable empty ownership. Legacy GPU
// records remain unowned; no current generation is assigned to them.
func NewWithStore(runscBinary, sandboxRoot string, db store.DbStore) (*Manager, error) {
	m := newManager(runscBinary, sandboxRoot)
	if err := m.discoverNVIDIA(); err != nil {
		m.reason = err
	} else {
		m.healthy = true
	}
	if err := m.initializeGenerationJournal(db); err != nil {
		return nil, err
	}
	if m.healthy {
		if err := m.restoreLeases(); err != nil {
			m.Close()
			return nil, err
		}
	}
	return m, nil
}

func (m *Manager) initializeGenerationJournal(db store.DbStore) error {
	if db == nil {
		return errors.New("generation device store is required")
	}
	owner, err := openGenerationJournalOwner(m.sandboxRoot)
	if err != nil {
		return err
	}
	m.generationOwner, m.generationStore = owner, db
	ok := false
	defer func() {
		if !ok {
			owner.close()
		}
	}()
	initialized, err := owner.loadInitialization()
	if err != nil {
		return err
	}
	data, err := db.LoadRaw(generationLeaseBucket)
	if !initialized {
		if !owner.createdNamespace {
			return errors.New("existing device journal has no original initialization")
		}
		if !errors.Is(err, errord.ErrNotFound) {
			return errors.New("device journal has records without original initialization")
		}
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		record := deviceJournalInitialization{JournalID: hex.EncodeToString(nonce[:]), DirectoryDevice: uint64(owner.directoryStat.Dev), DirectoryInode: owner.directoryStat.Ino, Phase: "pending"}
		if err := owner.publishInitialization(record); err != nil {
			return err
		}
	}
	if errors.Is(err, errord.ErrNotFound) {
		if owner.initialization.Phase != "pending" {
			return errors.New("initialized original device journal is missing")
		}
		m.generationRecords = map[string]generationLeaseRecord{}
		if err = m.writeGenerationStateLocked(m.generationRecords); err != nil {
			return err
		}
	} else {
		if err != nil {
			return err
		}
		state, err := decodeGenerationState(data)
		if err != nil {
			return err
		}
		if state.JournalID != owner.initialization.JournalID || state.DirectoryDevice != uint64(owner.directoryStat.Dev) || state.DirectoryInode != owner.directoryStat.Ino {
			return errors.New("device records belong to another journal")
		}
		if owner.initialization.Phase == "pending" && len(state.Records) != 0 {
			return errors.New("uninitialized device journal contains allocations")
		}
		m.generationRecords, m.generationDigest = state.Records, deviceSHA(data)
	}
	if owner.initialization.Phase == "pending" {
		record := owner.initialization
		record.Phase = "complete"
		if err := owner.publishInitialization(record); err != nil {
			return err
		}
	}
	for _, record := range m.generationRecords {
		if record.State != "active" {
			continue
		}
		for i, uuid := range record.Lease.DeviceUUID {
			device, known := m.devices[record.Lease.DeviceIDs[i]]
			if !known || device.UUID != uuid {
				return errors.New("active original device inventory is unavailable or changed")
			}
			if _, duplicate := m.leases[uuid]; duplicate {
				return errors.New("active device lease has duplicate owners")
			}
			m.leases[uuid] = record.SandboxID
		}
	}
	ok = true
	return nil
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.generationOwner.close()
	return nil
}

func deviceSHA(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func boundedLeaseIdentity(s string) bool {
	return s != "" && len(s) <= 128 && strings.IndexFunc(s, func(r rune) bool { return r <= ' ' || r >= 127 }) == -1
}
func generationStateDigest(s generationLeaseState) string {
	s.IntegritySHA256 = ""
	data, _ := json.Marshal(s)
	return deviceSHA(data)
}

func decodeGenerationState(data []byte) (*generationLeaseState, error) {
	if len(data) == 0 || len(data) > generationJournalBytes {
		return nil, errors.New("device journal size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state generationLeaseState
	if err := decoder.Decode(&state); err != nil {
		return nil, err
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, errors.New("device journal has trailing data")
	}
	if err := rejectDeviceJournalDuplicates(json.NewDecoder(bytes.NewReader(data)), 0); err != nil {
		return nil, err
	}
	if state.Version != 1 || len(state.JournalID) != 64 || state.DirectoryInode == 0 || state.Records == nil || len(state.Records) > generationLeaseLimit || state.IntegritySHA256 != generationStateDigest(state) {
		return nil, errors.New("device journal schema, integrity or capacity is invalid")
	}
	canonical, _ := json.Marshal(state)
	if !bytes.Equal(canonical, data) {
		return nil, errors.New("device journal is missing fields or has a different encoding")
	}
	activeIDs, activeUUIDs := map[string]bool{}, map[string]bool{}
	for generation, r := range state.Records {
		if !boundedLeaseIdentity(generation) || generation != r.Generation || !boundedLeaseIdentity(r.SandboxID) || r.Lease.SandboxID != r.SandboxID || r.Lease.Generation != generation || len(r.Request) > 8192 || r.Fingerprint != deviceSHA(r.Request) || (r.State != "intent" && r.State != "active" && r.State != "released") {
			return nil, errors.New("original device record identity is invalid")
		}
		var request api.StartRequest
		if err := proto.Unmarshal(r.Request, &request); err != nil {
			return nil, err
		}
		if !proto.Equal(&request, &api.StartRequest{XpuAllocations: request.XpuAllocations}) {
			return nil, errors.New("device record contains unrelated request fields")
		}
		if len(r.Lease.DeviceIDs) != len(r.Lease.DeviceUUID) || len(r.Lease.DeviceUUID) > 256 {
			return nil, errors.New("original device lease shape is invalid")
		}
		if r.State == "intent" || r.State == "released" && !r.Allocated {
			if r.State == "intent" && r.Allocated {
				return nil, errors.New("device intent claims an allocation")
			}
			if len(r.Lease.DeviceIDs) != 0 || r.Lease.Type != "" {
				return nil, errors.New("device intent contains dispatched ownership")
			}
		} else if !r.Allocated {
			return nil, errors.New("active device allocation has no confirmation")
		} else if len(request.XpuAllocations) == 0 {
			if len(r.Lease.DeviceIDs) != 0 || r.Lease.Type != "" {
				return nil, errors.New("empty device request has nonempty ownership")
			}
		} else if len(request.XpuAllocations) != 1 || request.XpuAllocations[0] == nil || r.Lease.Type != TypeGPU || strings.ToLower(strings.TrimSpace(request.XpuAllocations[0].Type)) != TypeGPU || len(r.Lease.DeviceIDs) == 0 || !reflect.DeepEqual(r.Lease.DeviceIDs, request.XpuAllocations[0].DeviceIds) {
			return nil, errors.New("device lease differs from original request")
		}
		seenIDs, seenUUIDs := map[uint32]bool{}, map[string]bool{}
		for i, uuid := range r.Lease.DeviceUUID {
			id := r.Lease.DeviceIDs[i]
			if uuid == "" || len(uuid) > 256 || seenIDs[id] || seenUUIDs[uuid] {
				return nil, errors.New("original device identity is duplicated or invalid")
			}
			seenIDs[id], seenUUIDs[uuid] = true, true
			if r.State == "active" {
				if activeUUIDs[uuid] {
					return nil, errors.New("device UUID has multiple active owners")
				}
				activeUUIDs[uuid] = true
			}
		}
		if r.State != "released" {
			if activeIDs[r.SandboxID] {
				return nil, errors.New("sandbox has multiple active device generations")
			}
			activeIDs[r.SandboxID] = true
		}
	}
	return &state, nil
}

func rejectDeviceJournalDuplicates(d *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("device journal nesting is excessive")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delimiter == '{' {
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			s, ok := key.(string)
			if !ok || seen[s] {
				return errors.New("device journal has duplicate fields")
			}
			seen[s] = true
			if err := rejectDeviceJournalDuplicates(d, depth+1); err != nil {
				return err
			}
		}
	} else if delimiter == '[' {
		for d.More() {
			if err := rejectDeviceJournalDuplicates(d, depth+1); err != nil {
				return err
			}
		}
	} else {
		return errors.New("device journal delimiter is invalid")
	}
	_, err = d.Token()
	return err
}

func (m *Manager) checkGenerationJournalLocked() error {
	if err := m.generationOwner.check(); err != nil {
		return err
	}
	if m.generationStore == nil {
		return errors.New("device journal store is unavailable")
	}
	data, err := m.generationStore.LoadRaw(generationLeaseBucket)
	if err != nil {
		return err
	}
	if deviceSHA(data) != m.generationDigest {
		return errors.New("original device journal changed or a prior write remains unresolved")
	}
	return nil
}

func (m *Manager) writeGenerationStateLocked(records map[string]generationLeaseRecord) error {
	if err := m.generationOwner.check(); err != nil {
		return err
	}
	state := generationLeaseState{Version: 1, JournalID: m.generationOwner.initialization.JournalID, DirectoryDevice: uint64(m.generationOwner.directoryStat.Dev), DirectoryInode: m.generationOwner.directoryStat.Ino, Records: records}
	state.IntegritySHA256 = generationStateDigest(state)
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if _, err = decodeGenerationState(data); err != nil {
		return err
	}
	if err = m.generationStore.StoreRaw(generationLeaseBucket, data); err != nil {
		return err
	}
	readback, err := m.generationStore.LoadRaw(generationLeaseBucket)
	if err != nil {
		return err
	}
	if !bytes.Equal(readback, data) {
		return errors.New("original device journal write is unconfirmed")
	}
	m.generationRecords, m.generationDigest = records, deviceSHA(data)
	return nil
}

func (m *Manager) copyGenerationRecordsLocked() map[string]generationLeaseRecord {
	next := make(map[string]generationLeaseRecord, len(m.generationRecords)+1)
	for key, r := range m.generationRecords {
		next[key] = r
	}
	return next
}

func (m *Manager) AcquireForGeneration(id, generation string, allocations []*api.XpuAllocation) (*svc.SpecUpdates, error) {
	if !boundedLeaseIdentity(id) || !boundedLeaseIdentity(generation) {
		return nil, errors.New("original device allocation identity is required")
	}
	request, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&api.StartRequest{XpuAllocations: allocations})
	if err != nil || len(request) > 8192 {
		return nil, errors.New("device request exceeds its bound")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkGenerationJournalLocked(); err != nil {
		return nil, err
	}
	r, exists := m.generationRecords[generation]
	if exists {
		if r.SandboxID != id || r.Fingerprint != deviceSHA(request) || !bytes.Equal(r.Request, request) || r.State == "released" {
			return nil, errors.New("original device allocation identity changed or retired")
		}
	} else {
		if len(m.generationRecords) >= generationLeaseLimit {
			return nil, errors.New("device journal is full")
		}
		for _, current := range m.generationRecords {
			if current.SandboxID == id && current.State != "released" {
				return nil, errors.New("sandbox has another active device generation")
			}
		}
		r = generationLeaseRecord{Generation: generation, SandboxID: id, Request: request, Fingerprint: deviceSHA(request), State: "intent", Lease: leaseRecord{SandboxID: id, Generation: generation}}
		next := m.copyGenerationRecordsLocked()
		next[generation] = r
		if err := m.writeGenerationStateLocked(next); err != nil {
			return nil, err
		}
	}
	if r.State == "intent" {
		for _, owner := range m.leases {
			if owner == id {
				return nil, errors.New("legacy device ownership cannot be adopted")
			}
		}
		lease, err := m.resolveLeaseLocked(id, allocations)
		if err != nil {
			return nil, err
		}
		lease.Generation = generation
		r.Lease, r.State = lease, "active"
		r.Allocated = true
		next := m.copyGenerationRecordsLocked()
		next[generation] = r
		if err := m.writeGenerationStateLocked(next); err != nil {
			return nil, err
		}
		for _, uuid := range r.Lease.DeviceUUID {
			m.leases[uuid] = id
		}
	}
	for _, uuid := range r.Lease.DeviceUUID {
		if m.leases[uuid] != id {
			return nil, errors.New("original active device ownership is unconfirmed")
		}
	}
	if len(r.Lease.DeviceUUID) == 0 {
		return nil, nil
	}
	data, _ := json.Marshal(r.Lease)
	return nvidiaSpecUpdates(r.Lease.DeviceUUID, data), nil
}

// ReleaseIfGeneration retires allocator ownership, after the server has
// confirmed runtime absence. It does not destroy driver or runtime contexts.
func (m *Manager) ReleaseIfGeneration(id, generation string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.checkGenerationJournalLocked(); err != nil {
		return err
	}
	r, ok := m.generationRecords[generation]
	if !ok || r.SandboxID != id {
		return errors.New("original device lease is missing or changed")
	}
	if r.State == "released" {
		return nil
	}
	owned := map[string]bool{}
	for _, uuid := range r.Lease.DeviceUUID {
		owned[uuid] = true
		if m.leases[uuid] != id {
			return errors.New("original device lease is not independently confirmed")
		}
	}
	for uuid, owner := range m.leases {
		if owner == id && !owned[uuid] {
			return errors.New("unowned legacy device lease prevents completion")
		}
	}
	r.State = "released"
	next := m.copyGenerationRecordsLocked()
	next[generation] = r
	if err := m.writeGenerationStateLocked(next); err != nil {
		return err
	}
	for uuid := range owned {
		delete(m.leases, uuid)
	}
	return nil
}

// Independent read of the original completion; never infer it from absence or
// release a replacement owner merely because it has the same sandbox ID.
func (m *Manager) ConfirmReleasedForGeneration(id, generation string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if err := m.checkGenerationJournalLocked(); err != nil {
		return err
	}
	r, ok := m.generationRecords[generation]
	if !ok || r.SandboxID != id || r.State != "released" {
		return fmt.Errorf("original device release is not persistently confirmed")
	}
	return nil
}
