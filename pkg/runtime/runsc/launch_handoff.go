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
	"path/filepath"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const managedLaunchRecordBytes = 16 << 10

// This is the independent consumer of the daemon's completed retirement
// receipt. A launch intent or absent runtime never substitutes for this proof.
type completedLaunchRetirement struct {
	Version    int    `json:"version"`
	SandboxID  string `json:"sandbox_id"`
	Generation string `json:"generation"`
	Complete   bool   `json:"complete"`
}

type retiredManagedLaunch struct {
	Version       int                        `json:"version"`
	Launch        *managedLaunchRecord       `json:"launch"`
	LaunchSHA256  string                     `json:"launch_sha256"`
	Retirement    *completedLaunchRetirement `json:"retirement"`
	ReceiptSHA256 string                     `json:"receipt_sha256"`
}

func managedLaunchKey(id, generation string) string {
	raw, _ := json.Marshal([2]string{id, generation})
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func decodeManagedLaunchJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("managed launch journal has trailing content")
	}
	return nil
}

func privateManagedLaunchJSON(directory *os.File, name string, limit int64) ([]byte, error) {
	var source unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), name, &source, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	if source.Mode&unix.S_IFMT != unix.S_IFREG || source.Mode&07777 != 0600 ||
		source.Uid != uint32(os.Geteuid()) || source.Nlink != 1 || source.Size <= 0 || source.Size > limit {
		return nil, errors.New("managed launch journal is not private bounded regular data")
	}
	data, after, err := privateRuntimeSnapshot(directory, name)
	if err != nil {
		return nil, err
	}
	if !sameRuntimeInventoryStat(source, after) || int64(len(data)) > limit {
		return nil, errors.New("managed launch journal changed during observation")
	}
	return data, nil
}

// The source root is configured by the daemon constructor, never by a sandbox
// request. Its receipt namespace is opened through held private directories.
func (c *Client) readLaunchRetirement(ctx context.Context, id, generation string) (*completedLaunchRetirement, string, error) {
	path := c.Options.RetirementRoot
	if path == "" {
		return nil, "", nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, "", errors.New("managed launch retirement root is not exact and absolute")
	}
	root, original, err := openRuntimeIdentityDirectory(path)
	if err != nil {
		return nil, "", err
	}
	defer root.Close()
	fd, err := unix.Openat(int(root.Fd()), "scheduler-retirements", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, "", verifyRuntimeIdentityDirectory(path, original)
	}
	if err != nil {
		return nil, "", err
	}
	directory := os.NewFile(uintptr(fd), "scheduler-retirements")
	defer directory.Close()
	var source unix.Stat_t
	if err := unix.Fstat(fd, &source); err != nil || source.Mode&07777 != 0700 || source.Uid != uint32(os.Geteuid()) {
		return nil, "", errors.New("managed launch retirement directory is not privately owned")
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := verifyRuntimeIdentityDirectory(path, original); err != nil {
			return err
		}
		var current unix.Stat_t
		if err := unix.Fstatat(int(root.Fd()), "scheduler-retirements", &current, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
			current.Dev != source.Dev || current.Ino != source.Ino || current.Mode != source.Mode || current.Uid != source.Uid {
			return errors.New("managed launch retirement directory changed")
		}
		return nil
	}
	data, err := privateManagedLaunchJSON(directory, managedLaunchKey(id, generation)+".json", 4096)
	if errors.Is(err, unix.ENOENT) {
		return nil, "", check()
	}
	if err != nil {
		return nil, "", err
	}
	var receipt completedLaunchRetirement
	if err := decodeManagedLaunchJSON(data, &receipt); err != nil {
		return nil, "", err
	}
	if receipt.Version != 1 || receipt.SandboxID != id || receipt.Generation != generation {
		return nil, "", errors.New("managed launch retirement belongs to another execution")
	}
	if err := check(); err != nil {
		return nil, "", err
	}
	if receipt.Complete {
		// A visible completion from a previous failed directory sync must be
		// made durable before it authorizes a new physical launch.
		if err := c.syncLaunchJournal(directory); err != nil {
			return nil, "", err
		}
		if err := c.syncLaunchJournal(root); err != nil {
			return nil, "", err
		}
		if err := check(); err != nil {
			return nil, "", err
		}
	}
	digest := sha256.Sum256(data)
	return &receipt, hex.EncodeToString(digest[:]), nil
}

func (c *Client) syncLaunchJournal(file *os.File) error {
	if c.managedLaunchSync != nil {
		return c.managedLaunchSync(file)
	}
	return file.Sync()
}

// Caller holds the same private launch lock for archive and active handoff.
// The archive is immutable. Only a fully archived original can be replaced.
func (c *Client) writeManagedLaunchJSON(directory, root *os.File, name string, data []byte, replace bool, check func() error) error {
	if len(data) == 0 || len(data) > managedLaunchRecordBytes {
		return errors.New("managed launch publication exceeds its record bound")
	}
	fd := int(directory.Fd())
	temporary := ".pending-" + uuid.NewString()
	fileFD, err := unix.Openat(fd, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fileFD), temporary)
	defer file.Close()
	defer unix.Unlinkat(fd, temporary, 0)
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := c.syncLaunchJournal(file); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := check(); err != nil {
		return err
	}
	if replace {
		if err := unix.Renameat(fd, temporary, fd, name); err != nil {
			return err
		}
	} else {
		if err := unix.Linkat(fd, temporary, fd, name, 0); err != nil {
			return err
		}
		if err := unix.Unlinkat(fd, temporary, 0); err != nil {
			return err
		}
	}
	if err := c.syncLaunchJournal(directory); err != nil {
		return err
	}
	if err := c.syncLaunchJournal(root); err != nil {
		return err
	}
	return check()
}

func (c *Client) archiveRetiredManagedLaunch(ctx context.Context, directory, root *os.File, old *managedLaunchRecord, original []byte, check func() error) error {
	receipt, receiptDigest, err := c.readLaunchRetirement(ctx, old.SandboxID, old.ResourceGeneration)
	if err != nil {
		return err
	}
	if receipt == nil || !receipt.Complete {
		return errors.New("managed launch already has an unresolved original owner")
	}
	digest := sha256.Sum256(original)
	record := retiredManagedLaunch{Version: 1, Launch: old, LaunchSHA256: hex.EncodeToString(digest[:]), Retirement: receipt, ReceiptSHA256: receiptDigest}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	name := "retired-" + managedLaunchKey(old.SandboxID, old.ResourceGeneration) + ".json"
	saved, err := privateManagedLaunchJSON(directory, name, managedLaunchRecordBytes)
	if err == nil {
		if !bytes.Equal(saved, data) {
			return errors.New("managed launch retirement archive differs from its original")
		}
		if err := c.syncLaunchJournal(directory); err != nil {
			return err
		}
		if err := c.syncLaunchJournal(root); err != nil {
			return err
		}
		return check()
	}
	if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("read original launch archive: %w", err)
	}
	return c.writeManagedLaunchJSON(directory, root, name, data, false, check)
}
