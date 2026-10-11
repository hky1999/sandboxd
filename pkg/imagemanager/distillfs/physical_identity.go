// Copyright (c) 2026 Ant Group Corporation.
// SPDX-License-Identifier: Apache-2.0

package distillfs

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/moby/sys/mountinfo"
	"golang.org/x/sys/unix"
)

type physicalScope struct {
	BootID        string `json:"boot_id"`
	MountNSDevice uint64 `json:"mount_namespace_device"`
	MountNSInode  uint64 `json:"mount_namespace_inode"`
	PIDNSDevice   uint64 `json:"pid_namespace_device"`
	PIDNSInode    uint64 `json:"pid_namespace_inode"`
}

type physicalProcessIdentity struct {
	PID              int    `json:"pid"`
	StartTicks       uint64 `json:"start_ticks"`
	ExecutableSHA256 string `json:"executable_sha256"`
	ArgumentsSHA256  string `json:"arguments_sha256"`
}

type physicalMountIdentity struct {
	MountID       int    `json:"mount_id"`
	UniqueMountID uint64 `json:"unique_mount_id"`
	Major         int    `json:"major"`
	Minor         int    `json:"minor"`
	Root          string `json:"root"`
	Filesystem    string `json:"filesystem"`
	Source        string `json:"source"`
}

type physicalIdentity struct {
	Generation          string                   `json:"generation"`
	Scope               physicalScope            `json:"scope"`
	Target              string                   `json:"target"`
	PIDFile             string                   `json:"pid_file"`
	ExecutableSHA256    string                   `json:"executable_sha256"`
	ArgumentsSHA256     string                   `json:"arguments_sha256"`
	SourceSHA256        string                   `json:"source_sha256"`
	Phase               string                   `json:"phase"`
	Process             *physicalProcessIdentity `json:"process,omitempty"`
	Mount               *physicalMountIdentity   `json:"mount,omitempty"`
	UnmountSucceeded    bool                     `json:"unmount_succeeded"`
	NoDispatchConfirmed bool                     `json:"no_dispatch_confirmed,omitempty"`
	BirthProtocol       uint8                    `json:"birth_protocol,omitempty"`
	BirthDirectory      *directoryBirth          `json:"birth_directory,omitempty"`
}

func clonePhysicalIdentity(p *physicalIdentity) *physicalIdentity {
	if p == nil {
		return nil
	}
	out := *p
	if p.BirthDirectory != nil {
		birth := *p.BirthDirectory
		out.BirthDirectory = &birth
	}
	if p.Process != nil {
		process := *p.Process
		out.Process = &process
	}
	if p.Mount != nil {
		mount := *p.Mount
		out.Mount = &mount
	}
	return &out
}

func (d *Daemon) originalPhysicalIdentity() *physicalIdentity {
	d.physicalMu.Lock()
	defer d.physicalMu.Unlock()
	return clonePhysicalIdentity(d.meta.PhysicalIdentity)
}

func (d *Daemon) publishPhysicalIdentity(p *physicalIdentity) error {
	d.physicalMu.Lock()
	defer d.physicalMu.Unlock()
	return d.publishPhysicalIdentityLocked(p)
}

// Caller holds physicalMu, shared with the final original process dispatch.
func (d *Daemon) publishPhysicalIdentityLocked(p *physicalIdentity) error {
	if p == nil {
		return fmt.Errorf("original physical identity cannot be removed")
	}
	next := clonePhysicalIdentity(p)
	current := d.meta.PhysicalIdentity
	if current == nil && d.metadataLoaded {
		return fmt.Errorf("loaded daemon cannot adopt a new physical identity")
	}
	if preparation := d.meta.Preparation; preparation != nil {
		if next.Generation != preparation.Generation || preparation.Phase != "prepared" && (next.Phase == "launching" || next.Phase == "running") {
			return fmt.Errorf("original preparation generation or phase changed")
		}
	}
	if current != nil {
		if next.Generation != current.Generation {
			if d.physicalPublicationPending || (current.Phase != "released" && current.Phase != "not_started") || next.Phase != "launching" || next.Process != nil || next.Mount != nil || next.UnmountSucceeded {
				return fmt.Errorf("original physical generation is not durably settled")
			}
		} else {
			if !samePhysicalLaunch(next, current) || d.meta.PidFilePath != current.PIDFile {
				return fmt.Errorf("original physical launch identity changed")
			}
			if current.Process != nil {
				if next.Process != nil && *next.Process != *current.Process {
					return fmt.Errorf("original process birth cannot be replaced")
				}
				next.Process = clonePhysicalIdentity(current).Process
			}
			if current.Mount != nil {
				if next.Mount != nil && *next.Mount != *current.Mount {
					return fmt.Errorf("original mount birth cannot be replaced")
				}
				next.Mount = clonePhysicalIdentity(current).Mount
			}
			next.UnmountSucceeded = next.UnmountSucceeded || current.UnmountSucceeded
			if next.NoDispatchConfirmed && !current.NoDispatchConfirmed && current.Phase != "not_started" && next.Phase != "not_started" {
				return fmt.Errorf("original unstarted proof cannot be invented")
			}
			next.NoDispatchConfirmed = next.NoDispatchConfirmed || current.NoDispatchConfirmed || current.Phase == "not_started"
			switch current.Phase {
			case "released":
				if next.Phase != "released" || (current.Process == nil && next.Process != nil) || (current.Mount == nil && next.Mount != nil) || next.UnmountSucceeded != current.UnmountSucceeded {
					return fmt.Errorf("completed original release cannot be rewritten")
				}
			case "releasing":
				if next.Phase == "launching" || next.Phase == "running" {
					next.Phase = "releasing" // Late birth facts cannot reopen the lifecycle.
				} else if next.Phase != "releasing" && next.Phase != "released" {
					return fmt.Errorf("original release phase cannot move backward")
				}
			case "running":
				if next.Phase == "launching" {
					next.Phase = "running"
				} else if next.Phase != "running" && next.Phase != "releasing" {
					return fmt.Errorf("running original phase cannot skip release")
				}
			case "launching":
				if next.Phase == "released" {
					return fmt.Errorf("original launch cannot skip release")
				}
			case "not_started":
				if next.Phase != "not_started" && next.Phase != "releasing" {
					return fmt.Errorf("unstarted original launch cannot acquire birth effects")
				}
			}
		}
	}
	meta := d.meta
	meta.PidFilePath = next.PIDFile
	meta.PhysicalIdentity = next
	if err := validatePhysicalMetadata(meta); err != nil {
		return err
	}
	d.meta.PidFilePath = next.PIDFile
	d.meta.PhysicalIdentity = next
	d.physicalPublicationPending = true
	if err := d.persistDaemonMetadata(); err != nil {
		return err
	}
	d.physicalPublicationPending = false
	return nil
}

func (d *Daemon) ensurePhysicalPublication() error {
	d.physicalMu.Lock()
	defer d.physicalMu.Unlock()
	if !d.physicalPublicationPending {
		return nil
	}
	if err := d.persistDaemonMetadata(); err != nil {
		return err
	}
	d.physicalPublicationPending = false
	return nil
}

func currentPhysicalScope() (physicalScope, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return physicalScope{}, fmt.Errorf("read original boot identity")
	}
	scope := physicalScope{BootID: strings.TrimSpace(string(data))}
	for path, fields := range map[string][2]*uint64{
		"/proc/thread-self/ns/mnt": {&scope.MountNSDevice, &scope.MountNSInode},
		"/proc/thread-self/ns/pid": {&scope.PIDNSDevice, &scope.PIDNSInode},
	} {
		var stat unix.Stat_t
		if err := unix.Stat(path, &stat); err != nil {
			return physicalScope{}, fmt.Errorf("read original namespace identity")
		}
		*fields[0], *fields[1] = uint64(stat.Dev), stat.Ino
	}
	return scope, nil
}

func readPhysicalFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, fmt.Errorf("physical identity input is unreadable or exceeds limit")
	}
	return data, nil
}

func parseProcessStart(data []byte, pid int) (uint64, error) {
	text := string(data)
	first, last := strings.IndexByte(text, '('), strings.LastIndexByte(text, ')')
	if first <= 0 || last <= first {
		return 0, fmt.Errorf("invalid original process stat")
	}
	parsedPID, err := strconv.Atoi(strings.TrimSpace(text[:first]))
	if err != nil || parsedPID != pid {
		return 0, fmt.Errorf("original process stat identity changed")
	}
	fields := strings.Fields(text[last+1:])
	if len(fields) < 20 {
		return 0, fmt.Errorf("original process stat is incomplete")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return 0, fmt.Errorf("original process start time is unknown")
	}
	return start, nil
}

func observePhysicalProcess(pid int) (*physicalProcessIdentity, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("original process PID is unknown")
	}
	root := filepath.Join("/proc", strconv.Itoa(pid))
	before, err := readPhysicalFile(filepath.Join(root, "stat"), 65536)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("observe original process stat: %w", err)
	}
	start, err := parseProcessStart(before, pid)
	if err != nil {
		return nil, err
	}
	exe, err := readPhysicalFile(filepath.Join(root, "exe"), 256<<20)
	if err != nil {
		return nil, fmt.Errorf("observe original process executable: %w", err)
	}
	args, err := readPhysicalFile(filepath.Join(root, "cmdline"), 65536)
	if err != nil || len(args) == 0 {
		return nil, fmt.Errorf("observe original process arguments")
	}
	after, err := readPhysicalFile(filepath.Join(root, "stat"), 65536)
	if err != nil {
		return nil, fmt.Errorf("recheck original process start")
	}
	end, err := parseProcessStart(after, pid)
	if err != nil || start != end {
		return nil, fmt.Errorf("original process changed during observation")
	}
	return &physicalProcessIdentity{PID: pid, StartTicks: start, ExecutableSHA256: metadataSHA(exe), ArgumentsSHA256: metadataSHA(args)}, nil
}

func observePhysicalMount(target string) (*physicalMountIdentity, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if !filepath.IsAbs(target) || filepath.Clean(target) != target {
		return nil, fmt.Errorf("invalid physical mount target")
	}
	for parent := target; ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("physical target cannot be inspected")
		}
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("physical target contains a symbolic link")
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	read := func() (*mountinfo.Info, error) {
		mounts, err := mountinfo.GetMounts(nil)
		if err != nil {
			return nil, fmt.Errorf("read original mount table")
		}
		var result *mountinfo.Info
		for _, mount := range mounts {
			if mount.Mountpoint != target {
				continue
			}
			if result != nil {
				return nil, fmt.Errorf("physical target has stacked mounts")
			}
			result = mount
		}
		return result, nil
	}
	before, err := read()
	if err != nil || before == nil {
		return nil, err
	}
	var stat unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, target, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID_UNIQUE, &stat); err != nil {
		return nil, fmt.Errorf("read original unique kernel mount identity: %w", err)
	}
	if stat.Mask&unix.STATX_MNT_ID_UNIQUE == 0 || stat.Mnt_id == 0 {
		return nil, fmt.Errorf("unique kernel mount identity is unavailable")
	}
	after, err := read()
	if err != nil || after == nil || *before != *after {
		return nil, fmt.Errorf("original mount changed during observation")
	}
	return &physicalMountIdentity{MountID: before.ID, UniqueMountID: stat.Mnt_id, Major: before.Major, Minor: before.Minor, Root: before.Root, Filesystem: before.FSType, Source: before.Source}, nil
}

func (d *Daemon) observeOriginalScope() (physicalScope, error) {
	if d.physicalScopeFunc != nil {
		return d.physicalScopeFunc()
	}
	return currentPhysicalScope()
}

func (d *Daemon) observeOriginalProcess(pid int) (*physicalProcessIdentity, error) {
	if d.physicalProcessFunc != nil {
		return d.physicalProcessFunc(pid)
	}
	return observePhysicalProcess(pid)
}

func (d *Daemon) observeOriginalMount() (*physicalMountIdentity, error) {
	if d.physicalMountFunc != nil {
		return d.physicalMountFunc(d.meta.MountPoint)
	}
	return observePhysicalMount(d.meta.MountPoint)
}

func (d *Daemon) sourceIdentitySHA() (string, error) {
	config, err := readPhysicalFile(d.meta.CfgPath, daemonMetadataLimit)
	if err != nil {
		return "", fmt.Errorf("read original backend configuration identity")
	}
	bootstrap := ""
	if d.meta.SourceType == "nydus" {
		data, err := readPhysicalFile(d.meta.BootstrapPath, 256<<20)
		if err != nil {
			return "", fmt.Errorf("read original Nydus bootstrap identity")
		}
		bootstrap = metadataSHA(data)
	}
	data, err := json.Marshal([]string{d.meta.ID, d.meta.SourceType, d.meta.ImageURL, d.meta.MountPoint, metadataSHA(config), bootstrap})
	if err != nil {
		return "", fmt.Errorf("encode original source identity")
	}
	return metadataSHA(data), nil
}

func (d *Daemon) preparePhysicalLaunch() error {
	if err := d.ensurePhysicalPublication(); err != nil {
		return err
	}
	if original := d.originalPhysicalIdentity(); original != nil && original.Phase != "released" && original.Phase != "not_started" {
		return fmt.Errorf("original physical daemon lifecycle is unresolved")
	}
	mount, err := d.observeOriginalMount()
	if err != nil || mount != nil {
		return fmt.Errorf("original launch target is not confirmed empty")
	}
	scope, err := d.observeOriginalScope()
	if err != nil {
		return err
	}
	exe, err := readPhysicalFile(d.binPath, 256<<20)
	if err != nil {
		return fmt.Errorf("read original daemon executable identity")
	}
	source, err := d.sourceIdentitySHA()
	if err != nil {
		return err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("allocate original physical generation")
	}
	generation := hex.EncodeToString(nonce[:])
	if preparation := d.originalPreparation(); preparation != nil {
		if err := d.verifyPreparationForLaunch(); err != nil {
			return err
		}
		generation = preparation.Generation
	}
	pidFile := filepath.Join(d.meta.DaemonDir, "pid-"+generation)
	birth, err := readDirectoryBirth(d.meta.DaemonDir)
	if err != nil {
		return fmt.Errorf("record original daemon directory identity: %w", err)
	}
	args := append([]string{d.binPath}, d.buildMountArgsForPIDFile(pidFile)...)
	p := &physicalIdentity{Generation: generation, Scope: scope, Target: d.meta.MountPoint, PIDFile: pidFile, ExecutableSHA256: metadataSHA(exe), ArgumentsSHA256: metadataSHA([]byte(strings.Join(args, "\x00") + "\x00")), SourceSHA256: source, Phase: "launching", BirthProtocol: 1, BirthDirectory: birth}
	return d.publishPhysicalIdentity(p) // Durable before process dispatch.
}

func (d *Daemon) captureOriginalProcess() error {
	p := d.originalPhysicalIdentity()
	if p == nil {
		return fmt.Errorf("original physical launch intent is missing")
	}
	scope, err := d.observeOriginalScope()
	if err != nil || scope != p.Scope {
		return fmt.Errorf("original physical scope changed")
	}
	source, err := d.sourceIdentitySHA()
	if err != nil || source != p.SourceSHA256 {
		return fmt.Errorf("original source changed before process publication")
	}
	current, err := d.observeOriginalProcess(d.getPid())
	if err != nil || current == nil || current.ExecutableSHA256 != p.ExecutableSHA256 || current.ArgumentsSHA256 != p.ArgumentsSHA256 {
		return fmt.Errorf("original daemon birth identity cannot be confirmed")
	}
	p.Process = current
	d.physicalMu.Lock()
	defer d.physicalMu.Unlock()
	if err := d.persistPhysicalBirthLocked(p, "process"); err != nil {
		return err
	}
	return d.publishPhysicalIdentityLocked(p)
}

func (d *Daemon) captureOriginalMount() error {
	p := d.originalPhysicalIdentity()
	if p == nil || p.Process == nil {
		return fmt.Errorf("original process birth is missing")
	}
	scope, err := d.observeOriginalScope()
	if err != nil || scope != p.Scope {
		return fmt.Errorf("original scope changed before mount publication")
	}
	source, err := d.sourceIdentitySHA()
	if err != nil || source != p.SourceSHA256 {
		return fmt.Errorf("original source changed before mount publication")
	}
	current, err := d.observeOriginalProcess(p.Process.PID)
	if err != nil || current == nil || *current != *p.Process {
		return fmt.Errorf("original process birth changed before mount publication")
	}
	mount, err := d.observeOriginalMount()
	if err != nil || mount == nil || !strings.HasPrefix(mount.Filesystem, "fuse") {
		return fmt.Errorf("original FUSE mount birth cannot be confirmed")
	}
	p.Mount = mount
	p.Phase = "running"
	d.physicalMu.Lock()
	defer d.physicalMu.Unlock()
	if err := d.persistPhysicalBirthLocked(p, "mount"); err != nil {
		return err
	}
	return d.publishPhysicalIdentityLocked(p)
}

func signalPhysicalProcess(expected *physicalProcessIdentity, sig syscall.Signal) error {
	before, err := observePhysicalProcess(expected.PID)
	if err != nil {
		return err
	}
	if before == nil {
		return nil
	}
	if *before != *expected {
		return fmt.Errorf("original process was replaced before signal")
	}
	fd, err := unix.PidfdOpen(expected.PID, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open original process handle: %w", err)
	}
	defer unix.Close(fd)
	after, err := observePhysicalProcess(expected.PID)
	if err != nil || after == nil || *after != *expected {
		return fmt.Errorf("original process changed while acquiring handle")
	}
	if err := unix.PidfdSendSignal(fd, unix.Signal(sig), nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("signal original process handle: %w", err)
	}
	return nil
}

func (d *Daemon) signalOriginalProcess(sig syscall.Signal) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	p := d.originalPhysicalIdentity()
	if p == nil || p.Process == nil {
		return fmt.Errorf("original process birth is unknown")
	}
	scope, err := d.observeOriginalScope()
	if err != nil || scope != p.Scope {
		return fmt.Errorf("original process scope changed before signal")
	}
	current, err := d.observeOriginalProcess(p.Process.PID)
	if err != nil {
		return err
	}
	if current == nil {
		return nil
	}
	if *current != *p.Process {
		return fmt.Errorf("original process birth changed before signal")
	}
	if d.physicalSignalFunc != nil {
		return d.physicalSignalFunc(p.Process, sig)
	}
	return signalPhysicalProcess(p.Process, sig)
}

func (d *Daemon) verifyOriginalMountForRemoval() error {
	p := d.originalPhysicalIdentity()
	if p == nil || p.Mount == nil {
		return fmt.Errorf("original mount birth is unknown")
	}
	source, err := d.sourceIdentitySHA()
	if err != nil || source != p.SourceSHA256 {
		return fmt.Errorf("original mounted source changed")
	}
	scope, err := d.observeOriginalScope()
	if err != nil || scope != p.Scope {
		return fmt.Errorf("original mount namespace changed")
	}
	current, err := d.observeOriginalMount()
	if err != nil || current == nil || *current != *p.Mount {
		return fmt.Errorf("original physical mount was replaced or is unknown")
	}
	return nil
}

func validatePhysicalMetadata(meta DaemonMeta) error {
	p := meta.PhysicalIdentity
	if p == nil {
		return nil
	}
	validSHA := func(s string) bool {
		decoded, err := hex.DecodeString(s)
		return err == nil && len(decoded) == 32 && s == strings.ToLower(s)
	}
	if !validSHA(p.Generation) || !validSHA(p.ExecutableSHA256) || !validSHA(p.ArgumentsSHA256) || !validSHA(p.SourceSHA256) {
		return fmt.Errorf("physical identity digest or generation is invalid")
	}
	if !filepath.IsAbs(p.Target) || filepath.Clean(p.Target) != p.Target || p.Target != meta.MountPoint || p.PIDFile != meta.PidFilePath || p.PIDFile != filepath.Join(meta.DaemonDir, "pid-"+p.Generation) {
		return fmt.Errorf("original physical target or launch record changed")
	}
	if len(p.Scope.BootID) != 36 || p.Scope.MountNSInode == 0 || p.Scope.PIDNSInode == 0 {
		return fmt.Errorf("original physical namespace identity is incomplete")
	}
	if p.BirthProtocol > 1 || p.BirthProtocol == 0 && p.BirthDirectory != nil || p.BirthProtocol == 1 && (p.BirthDirectory == nil || p.BirthDirectory.Inode == 0) {
		return fmt.Errorf("original physical birth protocol or directory is invalid")
	}
	if p.Process != nil && (p.Process.PID <= 0 || p.Process.StartTicks == 0 || p.Process.ExecutableSHA256 != p.ExecutableSHA256 || p.Process.ArgumentsSHA256 != p.ArgumentsSHA256) {
		return fmt.Errorf("original process birth identity is invalid")
	}
	if p.Mount != nil && (p.Mount.MountID <= 0 || p.Mount.UniqueMountID == 0 || !strings.HasPrefix(p.Mount.Filesystem, "fuse")) {
		return fmt.Errorf("original kernel mount birth identity is invalid")
	}
	if p.BirthProtocol == 1 && p.Mount != nil && (p.Mount.Major < 0 || p.Mount.Minor < 0 || !filepath.IsAbs(p.Mount.Root) || filepath.Clean(p.Mount.Root) != p.Mount.Root || p.Mount.Source == "" || p.Mount.Filesystem != "fuse" && !strings.HasPrefix(p.Mount.Filesystem, "fuse.")) {
		return fmt.Errorf("independent original mount birth identity is incomplete")
	}
	switch p.Phase {
	case "launching", "releasing", "released":
	case "running":
		if p.Process == nil || p.Mount == nil {
			return fmt.Errorf("running physical identity lacks original birth")
		}
	case "not_started":
		if p.Process != nil || p.Mount != nil || p.UnmountSucceeded {
			return fmt.Errorf("unstarted physical identity contains foreign effects")
		}
	default:
		return fmt.Errorf("unknown physical daemon phase")
	}
	if p.UnmountSucceeded && p.Mount == nil {
		return fmt.Errorf("physical unmount result lacks original mount identity")
	}
	if p.NoDispatchConfirmed && (p.Process != nil || p.Mount != nil || p.UnmountSucceeded || p.Phase != "not_started" && p.Phase != "releasing" && p.Phase != "released") {
		return fmt.Errorf("unstarted physical proof contains dispatch effects")
	}
	return nil
}
