// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package server

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
	"syscall"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/sandbox"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

const retirementProgressBytes = 4 * 1024 * 1024

type retirementProgressJournal struct {
	path          string
	directory     *os.File
	lock          *os.File
	directoryStat unix.Stat_t
	lockStat      unix.Stat_t
}

// Caller holds retirementMu. The held flock prevents a second service from
// publishing histories in this namespace; every access rechecks original
// directory and lock inodes, even when a replacement has matching contents.
func (h *sandboxService) openRetirementProgressJournalLocked() (*retirementProgressJournal, error) {
	if current := h.retirementProgressJournal; current != nil {
		return current, current.check()
	}
	path := filepath.Join(h.config.RootDir, "scheduler-retirement-progress")
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	j := &retirementProgressJournal{path: path, directory: os.NewFile(uintptr(fd), path)}
	ok := false
	defer func() {
		if !ok {
			j.close()
		}
	}()
	if err := unix.Fstat(fd, &j.directoryStat); err != nil || j.directoryStat.Uid != uint32(os.Geteuid()) || j.directoryStat.Mode&0022 != 0 {
		return nil, fmt.Errorf("retirement journal directory is not privately owned")
	}
	lockFD, err := unix.Openat(fd, ".lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	j.lock = os.NewFile(uintptr(lockFD), ".lock")
	if err := unix.Fstat(lockFD, &j.lockStat); err != nil || j.lockStat.Mode&unix.S_IFMT != unix.S_IFREG || j.lockStat.Mode&07777 != 0600 || j.lockStat.Uid != uint32(os.Geteuid()) || j.lockStat.Nlink != 1 || j.lockStat.Size != 0 {
		return nil, fmt.Errorf("retirement journal lock is invalid")
	}
	if err := unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("retirement journal already has an owner: %w", err)
	}
	if err := j.check(); err != nil {
		return nil, err
	}
	if err := j.lock.Sync(); err != nil {
		return nil, err
	}
	if err := j.directory.Sync(); err != nil {
		return nil, err
	}
	if err := syncRetirementDirectory(h.config.RootDir); err != nil {
		return nil, err
	}
	h.retirementProgressJournal = j
	ok = true
	return j, nil
}

func (j *retirementProgressJournal) check() error {
	var directory, lock unix.Stat_t
	if err := unix.Lstat(j.path, &directory); err != nil || directory.Dev != j.directoryStat.Dev || directory.Ino != j.directoryStat.Ino || directory.Mode != j.directoryStat.Mode || directory.Uid != j.directoryStat.Uid {
		return fmt.Errorf("original retirement journal directory changed")
	}
	if err := unix.Fstatat(int(j.directory.Fd()), ".lock", &lock, unix.AT_SYMLINK_NOFOLLOW); err != nil || lock.Dev != j.lockStat.Dev || lock.Ino != j.lockStat.Ino || lock.Mode != j.lockStat.Mode || lock.Uid != j.lockStat.Uid || lock.Nlink != 1 || lock.Size != 0 {
		return fmt.Errorf("original retirement journal lock changed")
	}
	return nil
}

func (j *retirementProgressJournal) close() {
	if j.lock != nil {
		j.lock.Close()
	}
	if j.directory != nil {
		j.directory.Close()
	}
}

func (h *sandboxService) closeRetirementProgressJournal() {
	h.retirementMu.Lock()
	defer h.retirementMu.Unlock()
	if h.retirementProgressJournal != nil {
		h.retirementProgressJournal.close()
		h.retirementProgressJournal = nil
	}
}

var retirementProgressSteps = []string{"runtime", "network_disconnected", "filesystem", "acl", "devices", "dnat", "resources", "root"}

// Original is the immutable pre-delete snapshot, kept outside the removable
// sandbox directory. Steps acknowledge completed operations, never inferred
// absence. RootPending is durably saved before the original directory removal.
type retirementProgress struct {
	Version         int                      `json:"version"`
	SandboxID       string                   `json:"sandbox_id"`
	Generation      string                   `json:"generation"`
	Original        []byte                   `json:"original_metadata"`
	Resources       sandbox.OccupiedResource `json:"resources"`
	DirectoryDevice uint64                   `json:"directory_device"`
	DirectoryInode  uint64                   `json:"directory_inode"`
	ParentDevice    uint64                   `json:"parent_device"`
	ParentInode     uint64                   `json:"parent_inode"`
	Steps           []string                 `json:"completed_steps"`
	RootPending     bool                     `json:"root_pending"`
	IntegritySHA256 string                   `json:"integrity_sha256"`
}

func progressDigest(record retirementProgress) string {
	record.IntegritySHA256 = ""
	data, _ := json.Marshal(record)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func (h *sandboxService) retirementProgressPath(id, generation string) (string, string) {
	key, _ := json.Marshal([2]string{id, generation})
	digest := sha256.Sum256(key)
	directory := filepath.Join(h.config.RootDir, "scheduler-retirement-progress")
	return directory, filepath.Join(directory, hex.EncodeToString(digest[:])+".json")
}

func validateRetirementProgress(record *retirementProgress, id, generation string) error {
	if record.Version != 1 || record.SandboxID != id || record.Generation != generation || !validRetirementProgressKey(id) || !validRetirementProgressKey(generation) || record.DirectoryInode == 0 || record.ParentInode == 0 || record.Resources.ID != id || record.Resources.Generation != generation || len(record.Steps) > len(retirementProgressSteps) || record.IntegritySHA256 != progressDigest(*record) {
		return fmt.Errorf("original retirement progress identity or integrity differs")
	}
	var metadata runtime.SandboxMetadata
	if err := proto.Unmarshal(record.Original, &metadata); err != nil || metadata.ID != id || metadata.Labels[resourceGenerationLabel] != generation || metadata.RuntimeHandler == "" {
		return fmt.Errorf("original retirement metadata is incomplete")
	}
	for i, step := range record.Steps {
		if step != retirementProgressSteps[i] {
			return fmt.Errorf("retirement progress is not an ordered prefix")
		}
	}
	if record.RootPending && len(record.Steps) < len(retirementProgressSteps)-1 || len(record.Steps) == len(retirementProgressSteps) && !record.RootPending {
		return fmt.Errorf("root retirement intent does not follow complete resource cleanup")
	}
	return nil
}

func (h *sandboxService) readRetirementProgress(id, generation string) (*retirementProgress, error) {
	h.retirementMu.Lock()
	defer h.retirementMu.Unlock()
	j, err := h.openRetirementProgressJournalLocked()
	if err != nil {
		return nil, err
	}
	return h.readRetirementProgressLocked(j, id, generation)
}

func (h *sandboxService) readRetirementProgressLocked(j *retirementProgressJournal, id, generation string) (*retirementProgress, error) {
	_, path := h.retirementProgressPath(id, generation)
	record, err := h.readRetirementProgressFileLocked(j, filepath.Base(path))
	if err != nil || record == nil {
		return record, err
	}
	if err := validateRetirementProgress(record, id, generation); err != nil {
		return nil, err
	}
	return record, nil
}

func (h *sandboxService) readRetirementProgressFileLocked(j *retirementProgressJournal, name string) (*retirementProgress, error) {
	if filepath.Base(name) != name {
		return nil, fmt.Errorf("retirement progress name is not a filename")
	}
	fd, err := unix.Openat(int(j.directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || info.Size() > retirementProgressBytes {
		return nil, fmt.Errorf("retirement progress is not a private bounded record")
	}
	data, err := io.ReadAll(io.LimitReader(f, retirementProgressBytes+1))
	if err != nil || len(data) > retirementProgressBytes {
		return nil, fmt.Errorf("read bounded original retirement progress")
	}
	var record retirementProgress
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return nil, err
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, fmt.Errorf("retirement progress contains trailing data")
	}
	if err := rejectRetirementProgressDuplicates(json.NewDecoder(bytes.NewReader(data))); err != nil {
		return nil, err
	}
	if err := validateRetirementProgress(&record, record.SandboxID, record.Generation); err != nil {
		return nil, err
	}
	_, expected := h.retirementProgressPath(record.SandboxID, record.Generation)
	if filepath.Base(expected) != name {
		return nil, fmt.Errorf("retirement progress filename differs from original identity")
	}
	return &record, nil
}

func rejectRetirementProgressDuplicates(decoder *json.Decoder) error {
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return fmt.Errorf("retirement progress nesting exceeds limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		if delimiter == '{' {
			keys := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || keys[name] {
					return fmt.Errorf("duplicate retirement progress field")
				}
				keys[name] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		} else if delimiter == '[' {
			for decoder.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		} else {
			return fmt.Errorf("invalid retirement progress delimiter")
		}
		_, err = decoder.Token()
		return err
	}
	return walk(0)
}

func (h *sandboxService) writeRetirementProgress(record *retirementProgress) error {
	h.retirementMu.Lock()
	defer h.retirementMu.Unlock()
	record.IntegritySHA256 = progressDigest(*record)
	if err := validateRetirementProgress(record, record.SandboxID, record.Generation); err != nil {
		return err
	}
	j, err := h.openRetirementProgressJournalLocked()
	if err != nil {
		return err
	}
	directory, path := h.retirementProgressPath(record.SandboxID, record.Generation)
	current, err := h.readRetirementProgressLocked(j, record.SandboxID, record.Generation)
	if err != nil {
		return err
	}
	if current != nil {
		before, after := *current, *record
		before.Steps, after.Steps = nil, nil
		before.RootPending, after.RootPending = false, false
		before.IntegritySHA256, after.IntegritySHA256 = "", ""
		if !reflect.DeepEqual(before, after) || len(record.Steps) < len(current.Steps) || current.RootPending && !record.RootPending {
			return fmt.Errorf("original retirement snapshot or progress cannot be rewritten")
		}
	} else {
		entries, err := os.ReadDir(directory)
		if err != nil {
			return err
		}
		if len(entries) >= retirementReceiptLimit {
			return fmt.Errorf("retirement progress journal full")
		}
	}
	data, err := json.Marshal(record)
	if err != nil || len(data) > retirementProgressBytes {
		return fmt.Errorf("retirement progress exceeds byte limit")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	tempName := ".progress-" + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(int(j.directory.Fd()), tempName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), tempName)
	defer unix.Unlinkat(int(j.directory.Fd()), tempName, 0)
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
	if err := j.check(); err != nil {
		return err
	}
	if err := unix.Renameat(int(j.directory.Fd()), tempName, int(j.directory.Fd()), filepath.Base(path)); err != nil {
		return err
	}
	return j.directory.Sync()
}

func (h *sandboxService) verifyRetirementProgressSnapshot(record *retirementProgress) error {
	if record == nil {
		return nil
	}
	if _, err := h.verifyRetirementProgressRoot(record, false); err != nil {
		return err
	}
	root := filepath.Join(h.config.RootDir, "containers", record.SandboxID)
	f, err := os.OpenFile(filepath.Join(root, config.SandboxMetaFile), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > physicalIntentMetadataLimit {
		return fmt.Errorf("original retirement metadata is unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(f, physicalIntentMetadataLimit+1))
	if err != nil || len(data) > physicalIntentMetadataLimit {
		return fmt.Errorf("read bounded original retirement metadata")
	}
	var before, current runtime.SandboxMetadata
	if proto.Unmarshal(record.Original, &before) != nil || proto.Unmarshal(data, &current) != nil || !proto.Equal(&before, &current) {
		return fmt.Errorf("original retirement metadata changed")
	}
	return nil
}

func (h *sandboxService) beginRetirementProgress(metadata *runtime.SandboxMetadata, resources sandbox.OccupiedResource) (*retirementProgress, error) {
	generation := metadata.Labels[resourceGenerationLabel]
	record, err := h.readRetirementProgress(metadata.ID, generation)
	if err != nil {
		return nil, err
	}
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	if record != nil {
		if !bytes.Equal(record.Original, data) || !reflect.DeepEqual(record.Resources, resources) {
			return nil, fmt.Errorf("original retirement resources or metadata changed")
		}
		return record, nil
	}
	root := filepath.Join(h.config.RootDir, "containers", metadata.ID)
	var directory, parent unix.Stat_t
	if err := unix.Lstat(root, &directory); err != nil || directory.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, fmt.Errorf("original sandbox directory is unavailable")
	}
	if err := unix.Lstat(filepath.Dir(root), &parent); err != nil || parent.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, fmt.Errorf("original sandbox parent is unavailable")
	}
	record = &retirementProgress{Version: 1, SandboxID: metadata.ID, Generation: generation, Original: data, Resources: resources, DirectoryDevice: uint64(directory.Dev), DirectoryInode: directory.Ino, ParentDevice: uint64(parent.Dev), ParentInode: parent.Ino, Steps: []string{}}
	if err := h.writeRetirementProgress(record); err != nil {
		return nil, err
	}
	return record, nil
}

func (h *sandboxService) completeRetirementProgressStep(record *retirementProgress, step string) error {
	if record == nil {
		return nil
	}
	index := -1
	for i, name := range retirementProgressSteps {
		if name == step {
			index = i
			break
		}
	}
	if index < 0 {
		return fmt.Errorf("unknown retirement step")
	}
	if index < len(record.Steps) {
		return nil
	}
	if index != len(record.Steps) {
		return fmt.Errorf("retirement step would skip an unconfirmed operation")
	}
	record.Steps = append(record.Steps, step)
	return h.writeRetirementProgress(record)
}

func (h *sandboxService) verifyRetirementProgressRoot(record *retirementProgress, allowAbsent bool) (bool, error) {
	root := filepath.Join(h.config.RootDir, "containers", record.SandboxID)
	var parent, directory unix.Stat_t
	if err := unix.Lstat(filepath.Dir(root), &parent); err != nil || uint64(parent.Dev) != record.ParentDevice || parent.Ino != record.ParentInode || parent.Mode&unix.S_IFMT != unix.S_IFDIR {
		return false, fmt.Errorf("original sandbox parent changed")
	}
	err := unix.Lstat(root, &directory)
	if errors.Is(err, unix.ENOENT) && allowAbsent {
		return false, nil
	}
	if err != nil || uint64(directory.Dev) != record.DirectoryDevice || directory.Ino != record.DirectoryInode || directory.Mode&unix.S_IFMT != unix.S_IFDIR {
		return false, fmt.Errorf("original sandbox directory changed")
	}
	return true, nil
}

// Called before looking up a current sandbox. Only a complete resource history
// plus a durable root-removal intent may resolve absent original metadata. It
// never repeats cleanup or touches a replacement directory or instance.
func (h *sandboxService) resumeRetirementCompletion(id, generation string) (bool, error) {
	record, err := h.readRetirementProgress(id, generation)
	if err != nil || record == nil {
		return false, err
	}
	if !record.RootPending || len(record.Steps) < len(retirementProgressSteps)-1 {
		return false, nil
	}
	present, err := h.verifyRetirementProgressRoot(record, true)
	if err != nil {
		return false, err
	}
	if present {
		return false, nil
	}
	if err := syncRetirementDirectory(filepath.Join(h.config.RootDir, "containers")); err != nil {
		return false, err
	}
	if err := h.completeRetirementProgressStep(record, "root"); err != nil {
		return false, err
	}
	if err := h.writeRetirement(id, generation, true); err != nil {
		return false, err
	}
	return true, nil
}

// Reject path fragments in future operation keys; filenames themselves remain
// SHA256 keys and never use caller text as a path component.
func validRetirementProgressKey(value string) bool {
	return value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\x00\r\n")
}
