// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package distillfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/inclusionAI/sandboxd/pkg/imagemanager/imageconfig"
	"golang.org/x/sys/unix"
)

const daemonMetadataLimit = 1 << 20

func metadataSHA(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func daemonMetadataDigest(meta DaemonMeta) (string, error) {
	meta.IntegritySHA256 = ""
	data, err := json.Marshal(meta)
	if err != nil {
		return "", fmt.Errorf("encode daemon metadata integrity")
	}
	return metadataSHA(data), nil
}

// The containing directory is daemon-owned. This compares the original bytes
// and refuses aliases; it is not a cross-process filesystem CAS or a signature.
func (d *Daemon) persistDaemonMetadata() error {
	d.metaPersistMu.Lock()
	defer d.metaPersistMu.Unlock()
	meta := d.meta
	meta.PhysicalIdentity = clonePhysicalIdentity(meta.PhysicalIdentity)
	meta.Preparation = clonePreparation(meta.Preparation)
	meta.Env = append([]string(nil), meta.Env...)
	meta.ImageProcess = imageconfig.Clone(meta.ImageProcess)
	meta.SchemaVersion = 1
	digest, err := daemonMetadataDigest(meta)
	if err != nil {
		return err
	}
	meta.IntegritySHA256 = digest
	data, err := json.Marshal(meta)
	if err != nil || len(data)+1 > daemonMetadataLimit {
		return fmt.Errorf("daemon metadata cannot be published within its byte limit")
	}
	data = append(data, '\n')
	current, err := readDaemonMetadataFile(d.savedPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect original daemon metadata: %w", err)
	}
	if err == nil {
		if d.savedMetaSHA256 == "" || metadataSHA(current) != d.savedMetaSHA256 {
			return fmt.Errorf("original daemon metadata changed before publication")
		}
	} else if d.savedMetaSHA256 != "" {
		return fmt.Errorf("original daemon metadata disappeared before publication")
	}
	dir := filepath.Dir(d.savedPath)
	temp, err := os.CreateTemp(dir, ".daemon-metadata-")
	if err != nil {
		return fmt.Errorf("prepare daemon metadata publication: %w", err)
	}
	name := temp.Name()
	defer os.Remove(name)
	defer temp.Close()
	if _, err := temp.Write(data); err != nil {
		return fmt.Errorf("write daemon metadata: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync daemon metadata: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close daemon metadata: %w", err)
	}
	if err := os.Rename(name, d.savedPath); err != nil {
		return fmt.Errorf("publish daemon metadata: %w", err)
	}
	// Rename may already be visible if the directory sync fails. Preserve the
	// matching in-process byte identity so a retry can sync the same owner.
	d.savedMetaSHA256 = metadataSHA(data)
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open daemon metadata directory: %w", err)
	}
	defer directory.Close()
	syncDirectory := directory.Sync
	if d.metadataDirectorySyncFunc != nil {
		syncDirectory = func() error { return d.metadataDirectorySyncFunc(directory) }
	}
	if err := syncDirectory(); err != nil {
		return fmt.Errorf("sync daemon metadata directory: %w", err)
	}
	return nil
}

func readDaemonMetadataFile(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > daemonMetadataLimit {
		return nil, fmt.Errorf("daemon metadata is not a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, daemonMetadataLimit+1))
	if err != nil || len(data) > daemonMetadataLimit {
		return nil, fmt.Errorf("read daemon metadata within byte limit")
	}
	return data, nil
}

func decodeDaemonMetadata(data []byte) (DaemonMeta, error) {
	var meta DaemonMeta
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&meta); err != nil {
		return meta, fmt.Errorf("invalid daemon metadata fields")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return meta, fmt.Errorf("daemon metadata contains trailing data")
	}
	if err := rejectDuplicateDaemonFields(json.NewDecoder(bytes.NewReader(data)), 0); err != nil {
		return meta, err
	}
	if meta.ID == "" || meta.ID == "." || meta.ID == ".." || strings.ContainsAny(meta.ID, "/\\\x00") {
		return meta, fmt.Errorf("invalid daemon metadata identity")
	}
	if meta.SourceType != "" && meta.SourceType != "oss" && meta.SourceType != "nydus" {
		return meta, fmt.Errorf("unknown daemon metadata source")
	}
	switch meta.SchemaVersion {
	case 0:
		if meta.IntegritySHA256 != "" || meta.PhysicalIdentity != nil || meta.Preparation != nil {
			return meta, fmt.Errorf("legacy daemon metadata contains unproven integrity")
		}
	case 1:
		digest, err := daemonMetadataDigest(meta)
		if err != nil || digest != meta.IntegritySHA256 {
			return meta, fmt.Errorf("daemon metadata integrity mismatch")
		}
	default:
		return meta, fmt.Errorf("unknown daemon metadata schema")
	}
	if err := validatePreparationMetadata(meta); err != nil {
		return meta, err
	}
	if err := validatePhysicalMetadata(meta); err != nil {
		return meta, err
	}
	return meta, nil
}

func rejectDuplicateDaemonFields(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return fmt.Errorf("daemon metadata nesting exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid daemon metadata JSON")
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		keys := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			text, ok := key.(string)
			if err != nil || !ok || keys[text] {
				return fmt.Errorf("duplicate or invalid daemon metadata field")
			}
			keys[text] = true
			if err := rejectDuplicateDaemonFields(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := rejectDuplicateDaemonFields(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("invalid daemon metadata delimiter")
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("invalid daemon metadata ending")
	}
	return nil
}

func (d *Daemon) loadDaemonMetadata(path string) error {
	data, err := readDaemonMetadataFile(path)
	if err != nil {
		return fmt.Errorf("read original daemon metadata: %w", err)
	}
	meta, err := decodeDaemonMetadata(data)
	if err != nil {
		return err
	}
	if meta.SourceType == "" {
		meta.SourceType = "oss"
	}
	d.meta = meta
	d.savedPath = path
	d.savedMetaSHA256 = metadataSHA(data)
	d.metadataLoaded = true
	if p := meta.PhysicalIdentity; p != nil {
		d.targetUnmountSucceeded = p.UnmountSucceeded
	}
	d.config = &BackendConfig{}
	d.publishPreparationObservationLocked() // Loading precedes admission and all goroutines.
	if meta.Preparation != nil && meta.PhysicalIdentity == nil {
		return nil // Preparation can precede any backend configuration file.
	}
	if p := meta.PhysicalIdentity; p != nil && p.Phase == "released" {
		return nil // Original release was persisted before removal of backend files.
	}
	return d.loadBackendConfig()
}
