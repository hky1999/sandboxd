// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/uuid"
	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const historyBatchLimit = 32
const historyManifestFileLimit = 4096
const historyStateLimit = 8 * 1024 * 1024
const startOperationHistoryIndexHeader = "sandboxd-start-operations-v2\n"

type historyFile struct {
	DirectoryDevice uint64 `json:"directory_device"`
	DirectoryInode  uint64 `json:"directory_inode"`
	Path            string `json:"path"`
	Device          uint64 `json:"device"`
	Inode           uint64 `json:"inode"`
	Size            int64  `json:"size"`
	SHA256          string `json:"sha256"`
}
type historyPending struct {
	OperationIDs []string      `json:"operation_ids"`
	Files        []historyFile `json:"files"`
}
type historyState struct {
	Version   int                      `json:"version"`
	Boundary  *runtime.HistoryBoundary `json:"boundary"`
	Pending   *historyPending          `json:"pending,omitempty"`
	Integrity string                   `json:"integrity_sha256"`
}

func historyRuntimeRevision(identity *runtime.HistoryIdentity) (uint64, error) {
	if identity == nil || schedulerIdentityValue(identity.Authority) != identity.Authority || identity.Authority == "" ||
		schedulerIdentityValue(identity.EnvironmentID) != identity.EnvironmentID || identity.EnvironmentID == "" || identity.AssignmentGeneration == 0 {
		return 0, fmt.Errorf("complete history identity required")
	}
	base := identity.EnvironmentID + "-" + strconv.FormatUint(identity.AssignmentGeneration, 10)
	if identity.RuntimeID == base {
		return 0, nil
	}
	suffix, ok := strings.CutPrefix(identity.RuntimeID, base+"-r")
	revision, err := strconv.ParseUint(suffix, 10, 64)
	if !ok || err != nil || revision == 0 || strconv.FormatUint(revision, 10) != suffix {
		return 0, fmt.Errorf("runtime does not belong to the complete assignment")
	}
	return revision, nil
}

// This binding prevents a forgotten operation UUID from being reused with a
// different allocation. Length prefixes make the encoding unambiguous.
func historyOperationID(identity *runtime.HistoryIdentity, fingerprint string) (string, error) {
	if _, err := historyRuntimeRevision(identity); err != nil {
		return "", err
	}
	digest := sha256.New()
	for _, value := range []string{"sandboxd-history-start-v1", identity.Authority, identity.EnvironmentID, identity.RuntimeID, strconv.FormatUint(identity.AssignmentGeneration, 10), fingerprint} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		digest.Write(size[:])
		digest.Write([]byte(value))
	}
	data := digest.Sum(nil)[:16]
	data[6] = (data[6] & 0x0f) | 0x80
	data[8] = (data[8] & 0x3f) | 0x80
	id, err := uuid.FromBytes(data)
	return id.String(), err
}
func historyBoundaryValid(b *runtime.HistoryBoundary) error {
	if b == nil || b.Authority == "" || schedulerIdentityValue(b.Authority) != b.Authority || b.CoordinatorEpoch == 0 || len(b.Protected) > 65536 {
		return fmt.Errorf("invalid history authority or boundary")
	}
	seen := map[string]bool{}
	for _, p := range b.Protected {
		if p == nil || p.EnvironmentID == "" || schedulerIdentityValue(p.EnvironmentID) != p.EnvironmentID || seen[p.EnvironmentID] || p.AssignmentGeneration == 0 || p.AssignmentGeneration > b.AssignmentGeneration {
			return fmt.Errorf("invalid or duplicate protected assignment")
		}
		digest, err := hex.DecodeString(p.SpecificationSha256)
		if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != p.SpecificationSha256 {
			return fmt.Errorf("invalid protected specification")
		}
		seen[p.EnvironmentID] = true
	}
	return nil
}
func historyBoundaryAdvances(old, next *runtime.HistoryBoundary) error {
	if err := historyBoundaryValid(next); err != nil {
		return err
	}
	if old == nil {
		return nil
	}
	if old.Authority != next.Authority || next.CoordinatorEpoch < old.CoordinatorEpoch || next.AssignmentGeneration < old.AssignmentGeneration || next.CatalogRevision < old.CatalogRevision {
		return fmt.Errorf("history authority changed or boundary rolled back")
	}
	if old.CoordinatorEpoch == next.CoordinatorEpoch && old.CatalogRevision == next.CatalogRevision && !proto.Equal(old, next) {
		return fmt.Errorf("history boundary equivocated at one catalog revision")
	}
	previous := map[string]*runtime.HistoryProtection{}
	for _, p := range old.Protected {
		previous[p.EnvironmentID] = p
	}
	for _, p := range next.Protected {
		before := previous[p.EnvironmentID]
		if before != nil && before.AssignmentGeneration == p.AssignmentGeneration {
			if (before.SpecificationSha256 != p.SpecificationSha256 && p.EnvironmentRevision == before.EnvironmentRevision) || p.MinimumRuntimeRevision < before.MinimumRuntimeRevision || p.EnvironmentRevision < before.EnvironmentRevision {
				return fmt.Errorf("protected assignment rolled back or changed specification")
			}
		} else if p.AssignmentGeneration <= old.AssignmentGeneration {
			return fmt.Errorf("closed assignment cannot be reopened")
		}
	}
	return nil
}
func historyClosed(b *runtime.HistoryBoundary, identity *runtime.HistoryIdentity) (bool, error) {
	revision, err := historyRuntimeRevision(identity)
	if err != nil {
		return false, err
	}
	if b == nil {
		return false, nil
	}
	if identity.Authority != b.Authority {
		return false, fmt.Errorf("history authority differs")
	}
	if identity.AssignmentGeneration > b.AssignmentGeneration {
		return false, nil
	}
	for _, p := range b.Protected {
		if p.EnvironmentID == identity.EnvironmentID && p.AssignmentGeneration == identity.AssignmentGeneration {
			return revision < p.MinimumRuntimeRevision, nil
		}
	}
	return true, nil
}
func historyDigest(state historyState) string {
	state.Integrity = ""
	data, _ := json.Marshal(state)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
func historyReadPrivate(path string, limit int64) ([]byte, os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || info.Size() > limit {
		return nil, nil, fmt.Errorf("history file is not a private bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	return data, info, err
}
func (j *startOperationJournal) loadHistory() (*historyState, error) {
	data, _, err := historyReadPrivate(j.path+".history", historyStateLimit)
	if errors.Is(err, os.ErrNotExist) && j.header == startOperationIndexHeader {
		return nil, j.cleanupHistoryTemporaries()
	}
	if err != nil {
		return nil, err
	}
	var state historyState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return nil, err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || state.Version != 1 || state.Integrity != historyDigest(state) {
		return nil, fmt.Errorf("invalid history state integrity")
	}
	if err := historyBoundaryValid(state.Boundary); err != nil {
		return nil, err
	}
	if state.Pending != nil {
		if len(state.Pending.OperationIDs) > historyBatchLimit || len(state.Pending.Files) > historyManifestFileLimit {
			return nil, fmt.Errorf("history transaction exceeds bound")
		}
		for _, f := range state.Pending.Files {
			if !historyOwnedPath(f.Path) || f.Inode == 0 || f.Size < 0 || len(f.SHA256) != 64 {
				return nil, fmt.Errorf("invalid history deletion manifest")
			}
		}
	}
	if err := j.cleanupHistoryTemporaries(); err != nil {
		return nil, err
	}
	return &state, nil
}

// cleanupHistoryTemporaries discards only unpublished private files created by
// historyAtomic. It runs under the service start-operation mutex and the held
// journal flock, after validating the authoritative index and history sidecar.
// A temporary file never authorizes admission, retirement, or budget release.
func (j *startOperationJournal) cleanupHistoryTemporaries() (result error) {
	root := filepath.Dir(j.path)
	directory := j.root
	if directory == nil || j.directory == nil || j.index == nil || j.lock == nil {
		return fmt.Errorf("original history parent directory is not held")
	}
	parent, err := directory.Stat()
	if err != nil {
		return err
	}
	parentStat, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || !parent.IsDir() || parent.Mode().Perm()&0022 != 0 || parentStat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("history temporary directory is not daemon-owned")
	}
	changed := false
	defer func() {
		if changed {
			if err := directory.Sync(); result == nil {
				result = err
			}
		}
	}()
	fd := int(directory.Fd())
	checkScope := func() error {
		currentParent, err := os.Lstat(root)
		if err != nil || !os.SameFile(parent, currentParent) || !currentParent.IsDir() {
			return fmt.Errorf("history parent directory is not the original directory")
		}
		for _, binding := range []struct {
			file      *os.File
			parent    int
			name      string
			directory bool
		}{
			{j.directory, fd, filepath.Base(j.path), true},
			{j.index, fd, filepath.Base(j.path) + ".index", false},
			{j.lock, int(j.directory.Fd()), ".lock", false},
		} {
			var opened, named unix.Stat_t
			if err := unix.Fstat(int(binding.file.Fd()), &opened); err != nil {
				return err
			}
			if err := unix.Fstatat(binding.parent, binding.name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return err
			}
			mode := uint32(unix.S_IFREG | 0600)
			if binding.directory {
				mode = unix.S_IFDIR | 0700
			}
			if opened.Dev != named.Dev || opened.Ino != named.Ino || named.Mode != mode ||
				opened.Uid != uint32(os.Geteuid()) || named.Uid != opened.Uid ||
				(!binding.directory && (opened.Nlink != 1 || named.Nlink != 1)) {
				return fmt.Errorf("original history directory, admission index or flock path changed")
			}
		}
		return nil
	}
	if err := checkScope(); err != nil {
		return err
	}
	scan, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	entries := os.NewFile(uintptr(scan), root)
	defer entries.Close()
	for {
		names, err := entries.Readdirnames(128)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		for _, name := range names {
			if !strings.HasPrefix(name, ".history-") {
				continue
			}
			suffix := strings.TrimPrefix(name, ".history-")
			number, parseErr := strconv.ParseUint(suffix, 10, 32)
			if parseErr != nil || strconv.FormatUint(number, 10) != suffix {
				continue
			}
			if err := checkScope(); err != nil {
				return err
			}
			file, openErr := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if openErr != nil {
				return fmt.Errorf("history temporary could not be opened privately: %w", openErr)
			}
			var original, current unix.Stat_t
			statErr := unix.Fstat(file, &original)
			if statErr == nil {
				statErr = unix.Fstatat(fd, name, &current, unix.AT_SYMLINK_NOFOLLOW)
			}
			if statErr == nil && (original.Mode&unix.S_IFMT != unix.S_IFREG || original.Mode&07777 != 0600 ||
				original.Nlink != 1 || original.Uid != uint32(os.Geteuid()) || original.Size < 0 ||
				original.Size > historyStateLimit || original.Dev != current.Dev || original.Ino != current.Ino ||
				original.Mode != current.Mode || original.Uid != current.Uid || original.Nlink != current.Nlink ||
				original.Size != current.Size || original.Mtim != current.Mtim || original.Ctim != current.Ctim) {
				statErr = fmt.Errorf("history temporary is not an unchanged private bounded file")
			}
			if statErr == nil {
				statErr = checkScope()
			}
			if statErr == nil {
				statErr = unix.Unlinkat(fd, name, 0)
				if statErr == nil {
					changed = true
				}
			}
			unix.Close(file)
			if statErr != nil {
				return statErr
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}

func historyAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".history-*")
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
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncRetirementDirectory(dir)
}
func (j *startOperationJournal) saveHistory(state *historyState) error {
	if state == nil || state.Version != 1 {
		return fmt.Errorf("invalid history state version")
	}
	if err := historyBoundaryValid(state.Boundary); err != nil {
		return err
	}
	if state.Pending != nil && (len(state.Pending.OperationIDs) > historyBatchLimit || len(state.Pending.Files) > historyManifestFileLimit) {
		return fmt.Errorf("history manifest exceeds bounded transaction capacity")
	}
	state.Integrity = historyDigest(*state)
	data, err := json.Marshal(state)
	if err != nil || len(data) > historyStateLimit {
		return fmt.Errorf("history state exceeds capacity")
	}
	return historyAtomic(j.path+".history", data)
}
func historyOwnedPath(path string) bool {
	parts := strings.Split(path, "/")
	if len(parts) != 2 || parts[1] == "" || parts[1][0] == '.' || filepath.Base(parts[1]) != parts[1] || !strings.HasSuffix(parts[1], ".json") {
		return false
	}
	switch parts[0] {
	case "scheduler-start-operations", "scheduler-retirements", "scheduler-retirement-progress", "scheduler-resource-retirements":
		return true
	}
	return false
}
func historySnapshot(root, path string) (historyFile, error) {
	relative, err := filepath.Rel(root, path)
	if err != nil || !historyOwnedPath(relative) {
		return historyFile{}, fmt.Errorf("history path outside owned directories")
	}
	directory, err := os.Lstat(filepath.Dir(path))
	if err != nil || !directory.IsDir() || directory.Mode().Perm() != 0700 {
		return historyFile{}, fmt.Errorf("history directory is not private")
	}
	data, info, err := historyReadPrivate(path, retirementProgressBytes)
	if err != nil {
		return historyFile{}, err
	}
	stat := info.Sys().(*syscall.Stat_t)
	digest := sha256.Sum256(data)
	directoryStat := directory.Sys().(*syscall.Stat_t)
	return historyFile{DirectoryDevice: uint64(directoryStat.Dev), DirectoryInode: directoryStat.Ino, Path: relative, Device: uint64(stat.Dev), Inode: stat.Ino, Size: info.Size(), SHA256: hex.EncodeToString(digest[:])}, nil
}
func (j *startOperationJournal) rewriteHistoryIndex(remove map[string]bool) error {
	ids := make([]string, 0, len(j.admitted))
	for id := range j.admitted {
		if !remove[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	data := startOperationHistoryIndexHeader + strings.Join(ids, "\n")
	if len(ids) > 0 {
		data += "\n"
	}
	if err := historyAtomic(j.path+".index", []byte(data)); err != nil {
		return err
	}
	index, err := os.OpenFile(j.path+".index", os.O_RDWR|os.O_APPEND|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	j.index.Close()
	j.index = index
	j.header = startOperationHistoryIndexHeader
	j.admitted = map[string]struct{}{}
	for _, id := range ids {
		j.admitted[id] = struct{}{}
	}
	return j.checkDirectory()
}
func (h *sandboxService) finishHistory(j *startOperationJournal, state *historyState) (uint64, uint64, error) {
	if state.Pending == nil {
		return 0, 0, nil
	}
	// Version 2 is durably published before the first unlink; old daemons refuse it.
	if j.header != startOperationHistoryIndexHeader {
		if err := j.rewriteHistoryIndex(nil); err != nil {
			return 0, 0, err
		}
	}
	var count, size uint64
	for _, original := range state.Pending.Files {
		path := filepath.Join(h.config.RootDir, original.Path)
		current, err := historySnapshot(h.config.RootDir, path)
		if errors.Is(err, os.ErrNotExist) {
			if err := syncRetirementDirectory(filepath.Dir(path)); err != nil {
				return count, size, err
			}
			continue
		}
		if err != nil {
			return count, size, err
		}
		if !reflect.DeepEqual(original, current) {
			return count, size, fmt.Errorf("selected history file changed")
		}
		directory, err := os.OpenFile(filepath.Dir(path), os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return count, size, err
		}
		var stat unix.Stat_t
		if err := unix.Fstat(int(directory.Fd()), &stat); err != nil || uint64(stat.Dev) != original.DirectoryDevice || stat.Ino != original.DirectoryInode {
			directory.Close()
			return count, size, fmt.Errorf("original history directory changed")
		}
		if err := unix.Fstatat(int(directory.Fd()), filepath.Base(path), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil || uint64(stat.Dev) != original.Device || stat.Ino != original.Inode || stat.Mode&unix.S_IFMT != unix.S_IFREG {
			directory.Close()
			return count, size, fmt.Errorf("selected history inode changed")
		}
		if err := unix.Unlinkat(int(directory.Fd()), filepath.Base(path), 0); err != nil {
			directory.Close()
			return count, size, err
		}
		if err := directory.Sync(); err != nil {
			directory.Close()
			return count, size, err
		}
		directory.Close()
		if err := syncRetirementDirectory(filepath.Dir(path)); err != nil {
			return count, size, err
		}
		count++
		size += uint64(original.Size)
	}
	remove := map[string]bool{}
	for _, id := range state.Pending.OperationIDs {
		remove[id] = true
	}
	if err := j.rewriteHistoryIndex(remove); err != nil {
		return count, size, err
	}
	state.Pending = nil
	if err := j.saveHistory(state); err != nil {
		return count, size, err
	}
	return count, size, nil
}
func (h *sandboxService) historyCandidate(ctx context.Context, j *startOperationJournal, b *runtime.HistoryBoundary, c *runtime.HistoryCandidate) ([]historyFile, error) {
	if c == nil || validateStartOperationIdentity(c.OperationID, c.RequestFingerprint, c.DeadlineUnixMillis) != nil || c.SandboxID != "sbox-"+c.OperationID {
		return nil, fmt.Errorf("complete historical operation identity required")
	}
	closed, err := historyClosed(b, c.Identity)
	if err != nil || !closed {
		return nil, fmt.Errorf("historical runtime is still protected or foreign")
	}
	record, err := j.read(c.OperationID)
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, nil
	} // acknowledgment only, never retirement proof
	if record.RequestFingerprint != c.RequestFingerprint || record.DeadlineUnixMillis != c.DeadlineUnixMillis || (record.Generation != c.ResourceGeneration && !(record.State == runtime.StartOperationState_START_OPERATION_STATE_NOT_CREATED && c.ResourceGeneration == "")) || record.SandboxID != c.SandboxID {
		return nil, fmt.Errorf("original operation tuple differs")
	}
	if record.HistoryIdentity != nil && !proto.Equal(record.HistoryIdentity, c.Identity) {
		return nil, fmt.Errorf("original assignment differs")
	}
	unlock, err := h.resourceLocks.acquire(ctx, c.SandboxID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	paths := []string{filepath.Join(j.path, c.OperationID+".intent.json"), filepath.Join(j.path, c.OperationID+".json")}
	if record.State != runtime.StartOperationState_START_OPERATION_STATE_NOT_CREATED {
		if current, err := h.sandboxManager.Get(c.SandboxID); err == nil && current.Metadata.Labels[resourceGenerationLabel] == c.ResourceGeneration {
			return nil, fmt.Errorf("original physical generation is still live")
		}
		receipt, err := h.readRetirement(c.SandboxID, c.ResourceGeneration)
		if err != nil || receipt == nil || !receipt.Complete {
			return nil, fmt.Errorf("exact completed retirement required")
		}
		progress, err := h.readRetirementProgress(c.SandboxID, c.ResourceGeneration)
		if err != nil || progress == nil || len(progress.Steps) != len(retirementProgressSteps) {
			return nil, fmt.Errorf("complete original retirement progress required")
		}
		var original runtime.SandboxMetadata
		if proto.Unmarshal(progress.Original, &original) != nil || !historyLabels(c.Identity, original.Labels) {
			return nil, fmt.Errorf("original physical assignment differs")
		}
		_, receiptPath := h.retirementPath(c.SandboxID, c.ResourceGeneration)
		_, progressPath := h.retirementProgressPath(c.SandboxID, c.ResourceGeneration)
		paths = append(paths, receiptPath, progressPath)
		directory := filepath.Join(h.config.RootDir, "scheduler-resource-retirements")
		entries, err := os.ReadDir(directory)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			path := filepath.Join(directory, entry.Name())
			data, _, err := historyReadPrivate(path, 32*1024)
			if err != nil {
				return nil, err
			}
			var observation retirementResourceRecord
			if json.Unmarshal(data, &observation) != nil {
				return nil, fmt.Errorf("invalid retirement observation")
			}
			if observation.SandboxID == c.SandboxID && observation.ResourceGeneration == c.ResourceGeneration {
				paths = append(paths, path)
			}
		}
	}
	files := make([]historyFile, 0, len(paths))
	for _, path := range paths {
		file, err := historySnapshot(h.config.RootDir, path)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	return files, nil
}
func historyLabels(identity *runtime.HistoryIdentity, labels map[string]string) bool {
	return identity != nil && labels["adx.environment_id"] == identity.EnvironmentID && labels["adx.runtime_id"] == identity.RuntimeID && labels["adx.generation"] == strconv.FormatUint(identity.AssignmentGeneration, 10)
}

// Caller holds startOperationMu. Existing admitted operations remain resolvable;
// missing closed operations can never dispatch or manufacture non-creation proof.
func (j *startOperationJournal) admitHistory(id, fingerprint string, identity *runtime.HistoryIdentity, labels map[string]string) error {
	state, err := j.loadHistory()
	if err != nil {
		return err
	}
	if state == nil {
		if identity == nil {
			return nil
		}
	} else if identity == nil {
		return status.Error(codes.FailedPrecondition, "legacy operation admission is closed")
	}
	expected, err := historyOperationID(identity, fingerprint)
	if err != nil || expected != id {
		return status.Error(codes.FailedPrecondition, "operation is not bound to its complete allocation")
	}
	if labels != nil && !historyLabels(identity, labels) {
		return status.Error(codes.FailedPrecondition, "payload allocation differs")
	}
	if state != nil {
		closed, err := historyClosed(state.Boundary, identity)
		if err != nil || closed {
			return status.Error(codes.FailedPrecondition, "operation is covered by the durable history boundary")
		}
	}
	return nil
}

// CollectHistory only acknowledges log reclamation. It does not delete a runtime,
// report retirement, change resources, or authorize any budget release.
func (h *sandboxService) CollectHistory(ctx context.Context, request *runtime.CollectHistoryRequest) (*runtime.CollectHistoryResponse, error) {
	if request == nil || len(request.Candidates) > historyBatchLimit {
		return nil, status.Error(codes.InvalidArgument, "bounded history batch required")
	}
	h.startOperationMu.Lock()
	defer h.startOperationMu.Unlock()
	j, err := h.openStartOperationJournal()
	if err != nil {
		return nil, status.Error(codes.Unavailable, "history journal unavailable")
	}
	state, err := j.loadHistory()
	if err != nil {
		return nil, status.Error(codes.Unavailable, "history boundary unavailable")
	}
	var previous *runtime.HistoryBoundary
	if state != nil {
		previous = state.Boundary
	}
	if err := historyBoundaryAdvances(previous, request.Boundary); err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	if state == nil {
		state = &historyState{Version: 1}
	}
	response := &runtime.CollectHistoryResponse{}
	if state.Pending != nil {
		ids := append([]string(nil), state.Pending.OperationIDs...)
		count, size, err := h.finishHistory(j, state)
		if err != nil {
			return nil, status.Error(codes.Unavailable, "pending history transaction unresolved")
		}
		response.AcknowledgedOperationIds = ids
		response.RemovedFiles = count
		response.RemovedBytes = size
	}
	pending := &historyPending{}
	seen := map[string]bool{}
	for _, c := range request.Candidates {
		if c == nil || seen[c.OperationID] {
			return nil, status.Error(codes.InvalidArgument, "duplicate or missing history candidate")
		}
		seen[c.OperationID] = true
		files, err := h.historyCandidate(ctx, j, request.Boundary, c)
		if err != nil {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		pending.OperationIDs = append(pending.OperationIDs, c.OperationID)
		pending.Files = append(pending.Files, files...)
	}
	if len(pending.Files) > historyManifestFileLimit {
		return nil, status.Error(codes.ResourceExhausted, "history deletion manifest exceeds transaction capacity; reduce batch before retry")
	}
	state.Boundary = proto.Clone(request.Boundary).(*runtime.HistoryBoundary)
	state.Pending = pending
	if err := j.saveHistory(state); err != nil {
		return nil, status.Error(codes.Unavailable, "history intent publication failed")
	}
	count, size, err := h.finishHistory(j, state)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "history transaction unresolved")
	}
	for _, id := range pending.OperationIDs {
		found := false
		for _, old := range response.AcknowledgedOperationIds {
			if old == id {
				found = true
			}
		}
		if !found {
			response.AcknowledgedOperationIds = append(response.AcknowledgedOperationIds, id)
		}
	}
	response.RemovedFiles += count
	response.RemovedBytes += size
	response.RemainingStartOperations = uint64(len(j.admitted))
	return response, nil
}
