// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package distillfs

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	"github.com/moby/sys/mountinfo"
)

// PreparationOwner identifies the original producer even if its upper journal
// binding fails. It contains hashes only, never backend credentials.
type PreparationOwner struct {
	OperationID        string `json:"operation_id"`
	RequestFingerprint string `json:"request_fingerprint"`
}

// PreparationManager is deliberately separate from the legacy interface.
// Managed requests require it before allocating any working directory.
type PreparationManager interface {
	PrepareDaemon(*DaemonCreateOpt, PreparationOwner, func(string, string) error) error
	FindPreparation(PreparationOwner) (*PreparationInfo, error)
}

// The additional capability confirms that the original producer has no native
// preparation, including unpublished in-memory intents and legacy inventory.
// It does not itself authorize dropping an upper intent: that producer must
// first be fenced by its durable operation journal under its operation lock.
type PreparationRetirementManager interface {
	PreparationManager
	ConfirmNoPreparation(PreparationOwner) error
}

type PreparationInfo struct {
	Owner      PreparationOwner
	Generation string
	DaemonID   string
	Target     string
	SourceType string
	ImageURL   string
}

type directoryBirth struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

type daemonPreparation struct {
	Generation string           `json:"generation"`
	Owner      PreparationOwner `json:"owner"`
	Scope      physicalScope    `json:"scope"`
	Directory  string           `json:"directory"`
	Parent     directoryBirth   `json:"parent_directory_birth"`
	Birth      *directoryBirth  `json:"directory_birth,omitempty"`
	Phase      string           `json:"phase"`
	OwnsTarget bool             `json:"owns_target"`
}

func clonePreparation(p *daemonPreparation) *daemonPreparation {
	if p == nil {
		return nil
	}
	copy := *p
	if p.Birth != nil {
		birth := *p.Birth
		copy.Birth = &birth
	}
	return &copy
}

func (d *Daemon) originalPreparation() *daemonPreparation {
	d.physicalMu.Lock()
	defer d.physicalMu.Unlock()
	return clonePreparation(d.meta.Preparation)
}

func readDirectoryBirth(path string) (*directoryBirth, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("preparation directory is not privately owned")
	}
	return &directoryBirth{Device: uint64(stat.Dev), Inode: stat.Ino}, nil
}

func syncPreparationDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (mgr *manager) planPreparation(d *Daemon, opts *DaemonCreateOpt) error {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("allocate preparation generation: %w", err)
	}
	generation := hex.EncodeToString(nonce[:])
	scope, err := d.observeOriginalScope()
	if err != nil {
		return err
	}
	dir := filepath.Join(mgr.root, "allocations", generation)
	parent, err := readDirectoryBirth(filepath.Dir(dir))
	if err != nil {
		return err
	}
	d.meta.Preparation = &daemonPreparation{Generation: generation, Scope: scope, Directory: dir, Parent: *parent, Phase: "preparing", OwnsTarget: opts.MountPoint == ""}
	d.meta.MountPoint = opts.MountPoint
	if opts.MountPoint == "" {
		d.meta.MountPoint = filepath.Join(dir, "mnt")
	}
	d.meta.DaemonDir = filepath.Join(dir, "daemon")
	d.meta.ImageMetaDir = filepath.Join(dir, "image_meta")
	d.meta.DaemonLogPath = filepath.Join(d.meta.DaemonDir, "daemon.log")
	d.meta.PidFilePath = filepath.Join(d.meta.DaemonDir, "pid-"+generation)
	d.meta.ChunkDBDir = filepath.Join(mgr.root, "chunk_db")
	d.meta.CfgPath = filepath.Join(d.meta.DaemonDir, "backend.cfg")
	if d.meta.SourceType == "nydus" {
		d.meta.CacheDir = filepath.Join(dir, "cache_dir")
	} else {
		d.meta.CachePath = filepath.Join(dir, "cache")
	}
	d.savedPath = filepath.Join(mgr.root, "daemon_configs", d.meta.ID+".json")
	d.updateExpired()
	return nil
}

// Caller holds the manager lock. Publication and the upper binding precede
// allocation. Even a failed publication/binding retains this original in memory.
func (d *Daemon) allocatePreparation(owner PreparationOwner, bind func(string, string) error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.physicalMu.Lock()
	defer d.physicalMu.Unlock()
	p := d.meta.Preparation
	p.Owner = owner
	if err := d.persistPreparationLocked(); err != nil {
		return err
	}
	d.publishPreparationObservationLocked()
	if bind != nil {
		if err := bind(p.Generation, d.meta.MountPoint); err != nil {
			return err
		}
	}
	if err := d.verifyPreparationParentLocked(); err != nil {
		return err
	}
	// Caller-specified targets are existing caller-owned directories. Never
	// create foreign ancestors or remove their contents as part of retirement.
	if !p.OwnsTarget {
		info, err := os.Lstat(d.meta.MountPoint)
		if err != nil || !info.IsDir() {
			return fmt.Errorf("caller mount target must be an existing directory")
		}
	}
	if err := os.Mkdir(p.Directory, 0700); err != nil {
		return fmt.Errorf("create original preparation directory: %w", err)
	}
	birth, err := readDirectoryBirth(p.Directory)
	if err != nil {
		return err
	}
	p.Birth = birth
	// No child effects before the directory birth is durably recorded.
	if err := syncPreparationDirectory(filepath.Dir(p.Directory)); err != nil {
		return err
	}
	if err := d.persistPreparationLocked(); err != nil {
		return err
	}
	paths := []string{d.meta.DaemonDir, d.meta.ImageMetaDir}
	if p.OwnsTarget {
		paths = append(paths, d.meta.MountPoint)
	}
	if d.meta.SourceType == "nydus" {
		paths = append(paths, d.meta.CacheDir)
	}
	for _, path := range paths {
		if err := os.Mkdir(path, 0700); err != nil {
			return fmt.Errorf("prepare original working directory: %w", err)
		}
	}
	if err := syncPreparationDirectory(p.Directory); err != nil {
		return err
	}
	p.Phase = "prepared"
	return d.persistPreparationLocked()
}

func (d *Daemon) publishPreparationObservationLocked() {
	p := d.meta.Preparation
	if p != nil {
		d.preparationObservation.Store(&PreparationInfo{Owner: p.Owner, Generation: p.Generation, DaemonID: d.meta.ID, Target: d.meta.MountPoint, SourceType: d.meta.SourceType, ImageURL: d.meta.ImageURL})
	}
}

func validPhysicalSHA(value string) bool {
	bytes, err := hex.DecodeString(value)
	return err == nil && len(bytes) == 32 && value == strings.ToLower(value)
}

func (d *Daemon) persistPreparationLocked() error {
	d.preparationPublicationPending = true
	if err := d.persistDaemonMetadata(); err != nil {
		return err
	}
	d.preparationPublicationPending = false
	return nil
}

func (d *Daemon) verifyPreparationParentLocked() error {
	p := d.meta.Preparation
	if p == nil {
		return nil
	}
	if d.ownership != nil && p.Directory != filepath.Join(d.ownership.root, "allocations", p.Generation) {
		return fmt.Errorf("preparation is outside the original manager root")
	}
	parent, err := readDirectoryBirth(filepath.Dir(p.Directory))
	if err != nil || *parent != p.Parent {
		return fmt.Errorf("original preparation parent was replaced")
	}
	return nil
}

func (d *Daemon) verifyPreparationForLaunch() error {
	d.physicalMu.Lock()
	defer d.physicalMu.Unlock()
	return d.verifyPreparationForLaunchLocked()
}

func (d *Daemon) verifyPreparationForLaunchLocked() error {
	p := d.meta.Preparation
	if p == nil {
		return nil // Legacy fixtures and recovered physical records have their own fence.
	}
	if d.metadataLoaded || d.preparationPublicationPending || p.Phase != "prepared" || p.Birth == nil {
		return fmt.Errorf("original preparation is not authorized for launch")
	}
	if err := d.verifyPreparationParentLocked(); err != nil {
		return err
	}
	scope, err := d.observeOriginalScope()
	if err != nil || scope != p.Scope {
		return fmt.Errorf("original preparation scope changed before launch")
	}
	birth, err := readDirectoryBirth(p.Directory)
	if err != nil || *birth != *p.Birth {
		return fmt.Errorf("original preparation directory changed before launch")
	}
	return nil
}

func validatePreparationMetadata(meta DaemonMeta) error {
	p := meta.Preparation
	if p == nil {
		return nil
	}
	root := filepath.Dir(filepath.Dir(p.Directory))
	if !validPhysicalSHA(p.Generation) || !filepath.IsAbs(p.Directory) || filepath.Clean(p.Directory) != p.Directory || p.Directory != filepath.Join(root, "allocations", p.Generation) || p.Parent.Inode == 0 || len(p.Scope.BootID) != 36 || p.Scope.MountNSInode == 0 || p.Scope.PIDNSInode == 0 {
		return fmt.Errorf("preparation ownership is incomplete")
	}
	if (p.Owner.OperationID == "") != (p.Owner.RequestFingerprint == "") || (p.Owner.OperationID != "" && (!validPhysicalSHA(p.Owner.OperationID) || !validPhysicalSHA(p.Owner.RequestFingerprint))) {
		return fmt.Errorf("preparation producer identity is incomplete")
	}
	if p.Birth != nil && p.Birth.Inode == 0 {
		return fmt.Errorf("preparation directory birth is incomplete")
	}
	switch p.Phase {
	case "preparing", "releasing", "released":
	case "prepared":
		if p.Birth == nil {
			return fmt.Errorf("prepared directory birth is missing")
		}
	default:
		return fmt.Errorf("unknown preparation phase")
	}
	if meta.DaemonDir != filepath.Join(p.Directory, "daemon") || meta.ImageMetaDir != filepath.Join(p.Directory, "image_meta") || meta.CfgPath != filepath.Join(meta.DaemonDir, "backend.cfg") || meta.DaemonLogPath != filepath.Join(meta.DaemonDir, "daemon.log") || meta.ChunkDBDir != filepath.Join(root, "chunk_db") || !filepath.IsAbs(meta.MountPoint) || (p.OwnsTarget && meta.MountPoint != filepath.Join(p.Directory, "mnt")) {
		return fmt.Errorf("preparation working paths changed")
	}
	if (meta.SourceType == "nydus" && meta.CacheDir != filepath.Join(p.Directory, "cache_dir")) || (meta.SourceType == "oss" && meta.CachePath != filepath.Join(p.Directory, "cache")) {
		return fmt.Errorf("preparation cache path changed")
	}
	if physical := meta.PhysicalIdentity; physical != nil && physical.Generation != p.Generation {
		return fmt.Errorf("preparation and physical generation differ")
	}
	return nil
}

// This cleanup is only for a preparation with no dispatched physical intent.
// Caller holds lifecycle and physical locks, fencing later preparation/launch.
func (d *Daemon) retirePreparationLocked() error {
	p := d.meta.Preparation
	if p == nil || d.meta.PhysicalIdentity != nil {
		return fmt.Errorf("original preparation cannot prove pre-launch retirement")
	}
	if p.Phase == "released" {
		if err := d.persistPreparationLocked(); err != nil {
			return err
		}
		d.releasePending = false
		return nil
	}
	p.Phase = "releasing"
	if err := d.persistPreparationLocked(); err != nil {
		return err
	}
	d.userStopped.Store(true)
	if d.getState() == DaemonStateMounting {
		return fmt.Errorf("original preparation still has an active initializer")
	}
	scope, err := d.observeOriginalScope()
	if err != nil || scope != p.Scope {
		return fmt.Errorf("original preparation scope is unknown")
	}
	if err := d.verifyPreparationParentLocked(); err != nil {
		return err
	}
	if p.Birth == nil {
		if _, err := os.Lstat(p.Directory); !os.IsNotExist(err) {
			return fmt.Errorf("original preparation directory birth is unknown")
		}
	} else {
		birth, err := readDirectoryBirth(p.Directory)
		if err == nil {
			if *birth != *p.Birth {
				return fmt.Errorf("original preparation directory was replaced")
			}
			// Even a pre-launch target can have a foreign mount. Never remove it.
			mount, err := d.observeOriginalMount()
			if err != nil || mount != nil {
				return fmt.Errorf("original preparation target is not confirmed unmounted")
			}
			if err := removePreparationDirectory(p.Directory); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if err := syncPreparationDirectory(filepath.Dir(p.Directory)); err != nil {
		return err
	}
	p.Phase = "released"
	if err := d.persistPreparationLocked(); err != nil {
		return err
	}
	d.releasePending = false
	d.setState(DaemonStateStopped)
	return nil
}

func removePreparationDirectory(path string) error {
	mounts, err := mountinfo.GetMounts(nil)
	if err != nil {
		return fmt.Errorf("inspect original preparation subtree mounts: %w", err)
	}
	for _, mount := range mounts {
		if mount.Mountpoint == path || strings.HasPrefix(mount.Mountpoint, path+string(os.PathSeparator)) {
			return fmt.Errorf("original preparation subtree has an unresolved mount")
		}
	}
	return os.RemoveAll(path)
}

// Called only after lifecycle cleanup. A released preparation remains in its
// metadata until the manager removes the original entry, so a crash during
// directory removal can be retried without reintroducing a process.
func (d *Daemon) cleanupPreparationResources() error {
	d.physicalMu.Lock()
	defer d.physicalMu.Unlock()
	p := d.meta.Preparation
	if d.preparationPublicationPending {
		return fmt.Errorf("original preparation publication is unresolved")
	}
	if d.meta.PhysicalIdentity == nil {
		if p.Phase != "released" {
			return fmt.Errorf("original preparation release is unresolved")
		}
	} else if d.meta.PhysicalIdentity.Phase != "released" {
		return fmt.Errorf("original physical release is unresolved")
	}
	if err := d.verifyPreparationParentLocked(); err != nil {
		return err
	}
	birth, err := readDirectoryBirth(p.Directory)
	if err == nil {
		if p.Birth == nil || *birth != *p.Birth {
			return fmt.Errorf("original preparation directory was replaced")
		}
		if err := removePreparationDirectory(p.Directory); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := syncPreparationDirectory(filepath.Dir(p.Directory)); err != nil {
		return err
	}
	p.Phase = "released"
	if err := d.persistPreparationLocked(); err != nil {
		return err
	}
	if err := os.Remove(d.savedPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncPreparationDirectory(filepath.Dir(d.savedPath))
}

func (mgr *manager) ConfirmNoPreparation(owner PreparationOwner) error {
	release, err := mgr.ownership.acquire()
	if err != nil {
		return err
	}
	defer release()
	if !validPhysicalSHA(owner.OperationID) || !validPhysicalSHA(owner.RequestFingerprint) {
		return fmt.Errorf("original preparation identity is invalid")
	}
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	known := make(map[string]bool)
	metadata := make(map[string]*daemonPreparation)
	for _, d := range mgr.daemons {
		if !d.physicalMu.TryLock() {
			return fmt.Errorf("native preparation inventory is currently active")
		}
		p := clonePreparation(d.meta.Preparation)
		d.physicalMu.Unlock()
		if p == nil || p.Owner.OperationID == "" {
			return fmt.Errorf("legacy native allocation has no original producer identity")
		}
		if p.Owner.OperationID == owner.OperationID {
			return fmt.Errorf("original native preparation exists or is unresolved")
		}
		known[filepath.Base(p.Directory)] = true
		metadata[d.meta.ID+".json"] = p
	}
	// Validate the disk inventory as well as the live map. An unindexed or
	// changed owner cannot disappear from an absence proof merely because it
	// was not loaded into memory. No temporary or damaged file is discarded.
	metadataDir := filepath.Join(mgr.root, "daemon_configs")
	if _, err := readDirectoryBirth(metadataDir); err != nil {
		return fmt.Errorf("native metadata inventory is unreadable")
	}
	entries, err := os.ReadDir(metadataDir)
	if err != nil {
		return err
	}
	if len(entries) != len(metadata) {
		return fmt.Errorf("native metadata inventory has an unindexed or missing owner")
	}
	for _, entry := range entries {
		original, known := metadata[entry.Name()]
		if !known || !entry.Type().IsRegular() {
			return fmt.Errorf("native metadata inventory has an unindexed owner")
		}
		raw, err := readDaemonMetadataFile(filepath.Join(metadataDir, entry.Name()))
		if err != nil {
			return err
		}
		meta, err := decodeDaemonMetadata(raw)
		if err != nil || meta.ID+".json" != entry.Name() || !reflect.DeepEqual(meta.Preparation, original) {
			return fmt.Errorf("native preparation ownership changed or is unreadable")
		}
	}
	// Legacy unindexed directories cannot become a no-allocation proof after
	// losing an upper journal. Inspect a single entry: any legacy effect blocks.
	for _, child := range []string{"daemons", "image_metas", "mnt"} {
		path := filepath.Join(mgr.root, child)
		_, err := readDirectoryBirth(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("legacy allocation inventory is unreadable")
		}
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("legacy allocation inventory is unreadable")
		}
		entries, readErr := f.ReadDir(1)
		f.Close()
		if len(entries) != 0 || readErr != io.EOF {
			return fmt.Errorf("legacy allocation inventory remains unresolved")
		}
	}
	allocationDir := filepath.Join(mgr.root, "allocations")
	if _, err := readDirectoryBirth(allocationDir); err != nil {
		return err
	}
	f, err := os.Open(allocationDir)
	if err != nil {
		return err
	}
	defer f.Close()
	for {
		entries, err := f.ReadDir(128)
		for _, entry := range entries {
			if !entry.IsDir() || !known[entry.Name()] {
				return fmt.Errorf("unindexed original allocation remains unresolved")
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}
