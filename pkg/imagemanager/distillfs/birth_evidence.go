// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package distillfs

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"

	"golang.org/x/sys/unix"
)

const physicalBirthLimit = 8192

// These facts precede primary metadata publication. They are not launch
// acknowledgements or completed-retirement receipts, and never authorize a
// new process dispatch. Only explicit original-generation cleanup reads them.
type physicalBirthRecord struct {
	SchemaVersion   int                      `json:"schema_version"`
	DaemonID        string                   `json:"daemon_id"`
	Kind            string                   `json:"kind"`
	Original        *physicalIdentity        `json:"original"`
	Process         *physicalProcessIdentity `json:"process"`
	Mount           *physicalMountIdentity   `json:"mount,omitempty"`
	IntegritySHA256 string                   `json:"integrity_sha256"`
}

func physicalLaunchAnchor(p *physicalIdentity) *physicalIdentity {
	out := clonePhysicalIdentity(p)
	if out != nil {
		out.Phase = "launching"
		out.Process, out.Mount = nil, nil
		out.NoDispatchConfirmed, out.UnmountSucceeded = false, false
	}
	return out
}

func samePhysicalLaunch(a, b *physicalIdentity) bool {
	return reflect.DeepEqual(physicalLaunchAnchor(a), physicalLaunchAnchor(b))
}

func physicalBirthName(p *physicalIdentity, kind string) string {
	return "physical-birth-" + p.Generation + "-" + kind + ".json"
}

func physicalBirthDigest(record physicalBirthRecord) string {
	record.IntegritySHA256 = ""
	data, _ := json.Marshal(record)
	return metadataSHA(data)
}

// Open a directory handle and verify its original inode before any openat or
// linkat. All record operations stay relative to that handle, not a later path.
func (d *Daemon) openPhysicalBirthDirectory(p *physicalIdentity) (*os.File, error) {
	if p.BirthProtocol != 1 || p.BirthDirectory == nil {
		return nil, fmt.Errorf("independent physical birth protocol is unavailable")
	}
	fd, err := unix.Open(d.meta.DaemonDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open original birth directory: %w", err)
	}
	directory := os.NewFile(uintptr(fd), d.meta.DaemonDir)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0022 != 0 || stat.Ino != p.BirthDirectory.Inode || uint64(stat.Dev) != p.BirthDirectory.Device {
		directory.Close()
		return nil, fmt.Errorf("original birth directory ownership changed")
	}
	return directory, nil
}

func readPhysicalBirthFile(directory *os.File, name string) ([]byte, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&07777 != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || stat.Size > physicalBirthLimit {
		return nil, fmt.Errorf("physical birth is not a private bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, physicalBirthLimit+1))
	if err != nil || len(data) > physicalBirthLimit {
		return nil, fmt.Errorf("read physical birth within byte limit")
	}
	return data, nil
}

func (d *Daemon) readPhysicalBirth(directory *os.File, p *physicalIdentity, kind string) (*physicalBirthRecord, error) {
	data, err := readPhysicalBirthFile(directory, physicalBirthName(p, kind))
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var record physicalBirthRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return nil, fmt.Errorf("invalid independent physical birth fields")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("independent physical birth has trailing data")
	}
	if err := rejectDuplicateDaemonFields(json.NewDecoder(bytes.NewReader(data)), 0); err != nil {
		return nil, err
	}
	if record.SchemaVersion != 1 || record.DaemonID != d.meta.ID || record.Kind != kind || record.Original == nil || !reflect.DeepEqual(record.Original, physicalLaunchAnchor(p)) || record.IntegritySHA256 != physicalBirthDigest(record) || record.Process == nil || kind == "process" && record.Mount != nil || kind == "mount" && record.Mount == nil {
		return nil, fmt.Errorf("independent physical birth ownership or integrity differs")
	}
	meta := d.meta
	meta.PhysicalIdentity = clonePhysicalIdentity(record.Original)
	meta.PhysicalIdentity.Process, meta.PhysicalIdentity.Mount = record.Process, record.Mount
	if err := validatePhysicalMetadata(meta); err != nil {
		return nil, err
	}
	return &record, nil
}

// Caller holds physicalMu, including the immutable-generation compare and
// directory sync. No existing birth file is replaced, even after a failed sync.
func (d *Daemon) persistPhysicalBirthLocked(p *physicalIdentity, kind string) error {
	current := d.meta.PhysicalIdentity
	if current == nil || !samePhysicalLaunch(current, p) || current.NoDispatchConfirmed || current.Phase == "released" || current.Phase == "not_started" {
		return fmt.Errorf("original physical birth publication is no longer authorized")
	}
	if p.BirthProtocol == 0 {
		return nil // Old identities retain their existing contract without upgrading.
	}
	if current.Process != nil && (p.Process == nil || *p.Process != *current.Process) || current.Mount != nil && (p.Mount == nil || *p.Mount != *current.Mount) {
		return fmt.Errorf("original physical birth cannot be replaced")
	}
	scope, err := d.observeOriginalScope()
	if err != nil || scope != p.Scope {
		return fmt.Errorf("original scope changed before birth persistence")
	}
	source, err := d.sourceIdentitySHA()
	if err != nil || source != p.SourceSHA256 {
		return fmt.Errorf("original source changed before birth persistence")
	}
	record := physicalBirthRecord{SchemaVersion: 1, DaemonID: d.meta.ID, Kind: kind, Original: physicalLaunchAnchor(p), Process: p.Process}
	if kind == "mount" {
		record.Mount = p.Mount
	} else if kind != "process" {
		return fmt.Errorf("unknown physical birth kind")
	}
	meta := d.meta
	meta.PhysicalIdentity = p
	if err := validatePhysicalMetadata(meta); err != nil || record.Process == nil || kind == "mount" && record.Mount == nil {
		return fmt.Errorf("physical birth is incomplete")
	}
	directory, err := d.openPhysicalBirthDirectory(p)
	if err != nil {
		return err
	}
	defer directory.Close()
	if kind == "mount" {
		process, err := d.readPhysicalBirth(directory, p, "process")
		if err != nil || process == nil || *process.Process != *p.Process {
			return fmt.Errorf("mount birth lacks its independent original process")
		}
	}
	record.IntegritySHA256 = physicalBirthDigest(record)
	data, err := json.Marshal(record)
	if err != nil || len(data)+1 > physicalBirthLimit {
		return fmt.Errorf("physical birth exceeds byte limit")
	}
	data = append(data, '\n')
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("prepare physical birth temporary name")
	}
	tempName := ".physical-birth-" + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(int(directory.Fd()), tempName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return fmt.Errorf("prepare physical birth file: %w", err)
	}
	temp := os.NewFile(uintptr(fd), tempName)
	defer temp.Close()
	defer unix.Unlinkat(int(directory.Fd()), tempName, 0)
	if _, err := temp.Write(data); err != nil {
		return fmt.Errorf("write physical birth: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync physical birth: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close physical birth: %w", err)
	}
	name := physicalBirthName(p, kind)
	if err := unix.Linkat(int(directory.Fd()), tempName, int(directory.Fd()), name, 0); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("publish independent physical birth: %w", err)
		}
		existing, readErr := readPhysicalBirthFile(directory, name)
		if readErr != nil || !bytes.Equal(existing, data) {
			return fmt.Errorf("independent physical birth already differs")
		}
	}
	if err := unix.Unlinkat(int(directory.Fd()), tempName, 0); err != nil {
		return fmt.Errorf("unlink physical birth temporary name: %w", err)
	}
	if d.birthDirectorySyncFunc != nil {
		return d.birthDirectorySyncFunc(directory)
	}
	return directory.Sync()
}

func (d *Daemon) reconcilePhysicalBirthForRetirement() error {
	if p := d.originalPhysicalIdentity(); p != nil && p.ManagedLaunch != nil {
		return d.adoptManagedLaunchFacts(false, false)
	}
	d.physicalMu.Lock()
	defer d.physicalMu.Unlock()
	p := clonePhysicalIdentity(d.meta.PhysicalIdentity)
	if p == nil || p.BirthProtocol == 0 {
		return nil
	}
	if p.Phase != "releasing" {
		return fmt.Errorf("original release fence must precede birth reconciliation")
	}
	directory, err := d.openPhysicalBirthDirectory(p)
	if err != nil {
		return err
	}
	defer directory.Close()
	process, err := d.readPhysicalBirth(directory, p, "process")
	if err != nil {
		return err
	}
	mount, err := d.readPhysicalBirth(directory, p, "mount")
	if err != nil {
		return err
	}
	if process == nil {
		if p.Process != nil || mount != nil || p.Mount != nil {
			return fmt.Errorf("independent original process birth is missing")
		}
		return nil // Missing evidence never proves no dispatch; caller keeps unknown.
	}
	if p.NoDispatchConfirmed || p.Process != nil && *p.Process != *process.Process || mount != nil && *mount.Process != *process.Process || p.Mount != nil && (mount == nil || *p.Mount != *mount.Mount) {
		return fmt.Errorf("independent physical birth contradicts original metadata")
	}
	scope, err := d.observeOriginalScope()
	if err != nil || scope != p.Scope {
		return fmt.Errorf("original scope changed before birth reconciliation")
	}
	source, err := d.sourceIdentitySHA()
	if err != nil || source != p.SourceSHA256 {
		return fmt.Errorf("original source changed before birth reconciliation")
	}
	changed := p.Process == nil || p.Mount == nil && mount != nil
	p.Process = process.Process
	if mount != nil {
		p.Mount = mount.Mount
	}
	// A visible record from a failed publication is synced before adopting it.
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync original physical birth before reconciliation: %w", err)
	}
	if changed {
		return d.publishPhysicalIdentityLocked(p)
	}
	return nil
}

func (d *Daemon) physicalBirthPath(p *physicalIdentity, kind string) string {
	return filepath.Join(d.meta.DaemonDir, physicalBirthName(p, kind))
}
