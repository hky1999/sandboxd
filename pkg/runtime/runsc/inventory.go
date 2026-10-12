// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package runsc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	"golang.org/x/sys/unix"
)

const runtimeInventoryEntries = 131072
const runtimeStateBytes = 8 * 1024 * 1024
const runtimeInventoryBytes = 16 * 1024 * 1024

type runtimeInventoryFile struct {
	Device    uint64
	Inode     uint64
	Size      int64
	Digest    string
	ID        string
	SandboxID string
	Bundle    string
	PID       int
	Status    string
}

type runtimeListedState struct {
	Version     string            `json:"ociVersion"`
	ID          string            `json:"id"`
	Status      string            `json:"status"`
	PID         int               `json:"pid"`
	Bundle      string            `json:"bundle"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type boundedRuntimeOutput struct{ buffer bytes.Buffer }

func (b *boundedRuntimeOutput) Len() int      { return b.buffer.Len() }
func (b *boundedRuntimeOutput) Bytes() []byte { return b.buffer.Bytes() }

func (b *boundedRuntimeOutput) Write(data []byte) (int, error) {
	if len(data) > runtimeInventoryBytes-b.Len() {
		return 0, errors.New("runtime inventory output exceeds its byte limit")
	}
	return b.buffer.Write(data)
}

func runtimeInventoryID(id string) bool {
	return id != "" && len(id) <= 256 && id != "." && id != ".." && strings.IndexFunc(id, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '+' || r == '.')
	}) == -1
}

func runtimeInventoryName(name string) (string, string, error) {
	stem, ok := strings.CutSuffix(name, ".state")
	if !ok {
		return "", "", errors.New("runtime state suffix differs")
	}
	id, sandboxID, ok := strings.Cut(stem, "_sandbox:")
	if !ok || !runtimeInventoryID(id) || !runtimeInventoryID(sandboxID) {
		return "", "", errors.New("runtime state filename is not an exact full identity")
	}
	return id, sandboxID, nil
}

// GVisor list skips files that fail to load. Independently enumerate through
// the held original root and require every bounded native state to be present
// in its result. This proves inventory completeness, not original process
// birth or the absence of an unrecorded initializer.
func readRuntimeInventory(ctx context.Context, directory *os.File) (map[string]runtimeInventoryFile, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(directory.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	copy := os.NewFile(uintptr(fd), "runtime-inventory")
	defer copy.Close()
	entries, err := copy.ReadDir(runtimeInventoryEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > runtimeInventoryEntries {
		return nil, errors.New("runtime directory exceeds its inventory limit")
	}
	result := map[string]runtimeInventoryFile{}
	ids := map[string]bool{}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !strings.HasSuffix(entry.Name(), ".state") {
			continue
		}
		id, sandboxID, err := runtimeInventoryName(entry.Name())
		if err != nil {
			return nil, err
		}
		if ids[id] {
			return nil, errors.New("runtime inventory has an ambiguous container identity")
		}
		ids[id] = true
		stateFD, err := unix.Openat(int(directory.Fd()), entry.Name(), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, fmt.Errorf("open original runtime state: %w", err)
		}
		f := os.NewFile(uintptr(stateFD), entry.Name())
		var before, after, current unix.Stat_t
		if err := unix.Fstat(stateFD, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&0022 != 0 || before.Uid != uint32(os.Geteuid()) || before.Nlink != 1 || before.Size <= 0 || before.Size > runtimeStateBytes {
			f.Close()
			return nil, errors.New("original runtime state is not private bounded regular data")
		}
		data, readErr := io.ReadAll(io.LimitReader(f, runtimeStateBytes+1))
		statErr := unix.Fstat(stateFD, &after)
		pathErr := unix.Fstatat(int(directory.Fd()), entry.Name(), &current, unix.AT_SYMLINK_NOFOLLOW)
		closeErr := f.Close()
		if readErr != nil || statErr != nil || pathErr != nil || closeErr != nil || len(data) > runtimeStateBytes || !sameRuntimeInventoryStat(before, after) || !sameRuntimeInventoryStat(after, current) {
			return nil, errors.New("original runtime state changed or could not be fully read")
		}
		if err := rejectRuntimeJSONDuplicates(json.NewDecoder(bytes.NewReader(data)), 0); err != nil {
			return nil, err
		}
		var raw struct {
			ID      string `json:"id"`
			Status  string `json:"status"`
			Bundle  string `json:"bundleDir"`
			Sandbox *struct {
				ID     string `json:"id"`
				PID    int    `json:"pid"`
				Socket string `json:"controlSocketPath"`
			} `json:"sandbox"`
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		if err := decoder.Decode(&raw); err != nil {
			return nil, errors.New("original runtime state is malformed")
		}
		var trailing any
		if decoder.Decode(&trailing) != io.EOF {
			return nil, errors.New("original runtime state has trailing data")
		}
		if raw.ID != id || raw.Sandbox == nil || raw.Sandbox.ID != sandboxID || raw.Sandbox.PID < 0 || !knownRuntimeInventoryStatus(raw.Status) {
			return nil, errors.New("native runtime identity differs from its state filename")
		}
		digest := sha256.Sum256(data)
		result[entry.Name()] = runtimeInventoryFile{Device: uint64(before.Dev), Inode: before.Ino, Size: before.Size, Digest: hex.EncodeToString(digest[:]), ID: id, SandboxID: sandboxID, Bundle: raw.Bundle, PID: raw.Sandbox.PID, Status: raw.Status}
	}
	return result, nil
}

func sameRuntimeInventoryStat(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Size == b.Size && a.Mode == b.Mode && a.Uid == b.Uid && a.Nlink == b.Nlink && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func verifyRuntimeInventory(before, after map[string]runtimeInventoryFile, data []byte) error {
	if !reflect.DeepEqual(before, after) {
		return errors.New("original runtime inventory changed during observation")
	}
	if len(data) > runtimeInventoryBytes {
		return errors.New("runtime inventory output exceeds its byte limit")
	}
	if err := rejectRuntimeJSONDuplicates(json.NewDecoder(bytes.NewReader(data)), 0); err != nil {
		return err
	}
	var states []*runtimeListedState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&states); err != nil {
		return errors.New("runtime list result is malformed")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return errors.New("runtime list result has trailing data")
	}
	if len(states) != len(before) {
		return errors.New("runtime list omitted or invented original state files")
	}
	native := map[string]runtimeInventoryFile{}
	for _, file := range before {
		native[file.ID] = file
	}
	seen := map[string]bool{}
	for _, state := range states {
		if state == nil || seen[state.ID] {
			return errors.New("runtime list has missing or duplicate identities")
		}
		seen[state.ID] = true
		file, ok := native[state.ID]
		if !ok || state.Bundle != file.Bundle {
			return errors.New("runtime list belongs to another state or bundle")
		}
		switch state.Status {
		case "created", "running", "paused":
			if state.Status != file.Status || state.PID <= 0 || state.PID != file.PID {
				return errors.New("live runtime list identity differs from its native state")
			}
		case "stopped":
			// Upstream CheckStopped may observe exit without rewriting the file.
			if state.PID != -1 && state.PID != 0 {
				return errors.New("stopped runtime list has a live PID")
			}
		default:
			return errors.New("runtime list has an unsupported or unknown state")
		}
	}
	return nil
}

func knownRuntimeInventoryStatus(status string) bool {
	switch status {
	case "creating", "created", "running", "paused", "stopped":
		return true
	default:
		return false
	}
}

func rejectRuntimeJSONDuplicates(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("runtime state nesting exceeds its limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return errors.New("runtime state JSON is incomplete")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delimiter == '{' {
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return errors.New("runtime state key is incomplete")
			}
			s, ok := key.(string)
			if !ok || seen[s] {
				return errors.New("runtime state has duplicate fields")
			}
			seen[s] = true
			if err := rejectRuntimeJSONDuplicates(decoder, depth+1); err != nil {
				return err
			}
		}
	} else if delimiter == '[' {
		for decoder.More() {
			if err := rejectRuntimeJSONDuplicates(decoder, depth+1); err != nil {
				return err
			}
		}
	} else {
		return errors.New("runtime state delimiter is invalid")
	}
	if _, err := decoder.Token(); err != nil {
		return errors.New("runtime state JSON is incomplete")
	}
	return nil
}
