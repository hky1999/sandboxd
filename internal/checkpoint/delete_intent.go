// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package checkpoint

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/inclusionAI/sandboxd/pkg/errord"
)

// The receipt lives outside the directory being unlinked. Only a fully synced
// receipt permits replay after RemoveAll has removed the original manifest.
// Corrupt receipts and changed directory incarnations fail closed.
type deleteIntent struct {
	Version  int            `json:"version"`
	Expected DeleteIdentity `json:"expected"`
	Device   uint64         `json:"device"`
	Inode    uint64         `json:"inode"`
}

func deleteIntentPath(trash string, expected DeleteIdentity) string {
	data, _ := json.Marshal(expected)
	sum := sha256.Sum256(data)
	return trash + ".intent-" + hex.EncodeToString(sum[:]) + ".json"
}

func directoryIdentity(path string) (uint64, uint64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, 0, err
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return 0, 0, fmt.Errorf("ordinary checkpoint directory required: %w", errord.ErrFailedPrecondition)
	}
	return uint64(native.Dev), native.Ino, nil
}

func readDeleteIntent(path string, expected DeleteIdentity) (*deleteIntent, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, classifyIOError(err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		return nil, fmt.Errorf("checkpoint delete receipt is not a bounded ordinary file: %w", errord.ErrFailedPrecondition)
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return nil, classifyIOError(err)
	}
	var value deleteIntent
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("checkpoint delete receipt is incomplete: %w", errord.ErrFailedPrecondition)
	}
	if decoder.Decode(new(any)) != io.EOF || value.Version != 1 || value.Expected != expected || value.Inode == 0 {
		return nil, fmt.Errorf("checkpoint delete receipt identity differs: %w", errord.ErrFailedPrecondition)
	}
	// A valid receipt may have been read after its writer died before fsync.
	// Make it durable again before permitting the first or a replayed unlink.
	if err := file.Sync(); err != nil {
		return nil, classifyIOError(err)
	}
	if err := syncPath(filepath.Dir(path)); err != nil {
		return nil, classifyIOError(err)
	}
	return &value, nil
}

func persistDeleteIntent(path string, value deleteIntent) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return classifyIOError(err)
	}
	// A partial/unsynced receipt never authorizes removal. Keep it for diagnosis.
	if _, err = file.Write(append(data, '\n')); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return classifyIOError(err)
	}
	return classifyIOError(syncPath(filepath.Dir(path)))
}

func deleteIsolatedAt(trash string, expected DeleteIdentity) error {
	path := deleteIntentPath(trash, expected)
	receipt, err := readDeleteIntent(path, expected)
	if err != nil {
		return err
	}
	device, inode, err := directoryIdentity(trash)
	if errors.Is(err, fs.ErrNotExist) {
		if receipt == nil {
			return nil
		}
		// Tree removal completed before its reply or receipt cleanup.
		return finishDeleteIntent(path)
	}
	if err != nil {
		return classifyIOError(err)
	}
	if receipt == nil {
		fact, err := InspectAt(trash, expected.CheckpointID)
		if err != nil || fact.Manifest.SourceID != expected.SourceID ||
			(expected.SourceGeneration != "" && fact.Manifest.SourceGeneration != expected.SourceGeneration) ||
			fact.Manifest.ImageSize != expected.ImageSize || !strings.EqualFold(fact.Manifest.ImageSHA256, expected.ImageSHA256) {
			return fmt.Errorf("isolated checkpoint delete identity differs from committed artifact: %w", errord.ErrFailedPrecondition)
		}
		receipt = &deleteIntent{Version: 1, Expected: expected, Device: device, Inode: inode}
		if err := persistDeleteIntent(path, *receipt); err != nil {
			return err
		}
	}
	if receipt.Device != device || receipt.Inode != inode {
		return fmt.Errorf("isolated checkpoint directory incarnation changed: %w", errord.ErrFailedPrecondition)
	}
	// An exact durable receipt is sufficient even if the manifest was already
	// unlinked. No unrelated or newly published directory can inherit it.
	if err := os.RemoveAll(trash); err != nil {
		return classifyIOError(fmt.Errorf("remove checkpoint artifact: %w", err))
	}
	if err := syncPath(filepath.Dir(trash)); err != nil {
		return classifyIOError(err)
	}
	return finishDeleteIntent(path)
}

func finishDeleteIntent(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return classifyIOError(err)
	}
	return classifyIOError(syncPath(filepath.Dir(path)))
}
