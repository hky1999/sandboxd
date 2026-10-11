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
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// This is the exact producer manifest. No credentials or raw argv are stored.
// Its original serialized bytes, not a Rust/Go JSON reserialization, are hashed.
type managedLaunchManifest struct {
	SchemaVersion          int            `json:"schema_version"`
	DaemonID               string         `json:"daemon_id"`
	Generation             string         `json:"generation"`
	OperationID            string         `json:"operation_id"`
	RequestFingerprint     string         `json:"request_fingerprint"`
	Target                 string         `json:"target"`
	PIDFile                string         `json:"pid_file"`
	ExecutableSHA256       string         `json:"executable_sha256"`
	ArgumentsSHA256        string         `json:"arguments_sha256"`
	SourceSHA256           string         `json:"source_sha256"`
	ConfigSHA256           string         `json:"config_sha256"`
	BootstrapSHA256        string         `json:"bootstrap_sha256"`
	Scope                  physicalScope  `json:"scope"`
	InitializationDeadline uint64         `json:"initialization_deadline_boottime_ns"`
	JournalPath            string         `json:"journal_directory_path"`
	JournalDirectory       directoryBirth `json:"journal_directory"`
	OwnerPath              string         `json:"owner_directory_path"`
	OwnerDirectory         directoryBirth `json:"owner_directory"`
	OwnerLockName          string         `json:"owner_lock_name"`
	OwnerLock              directoryBirth `json:"owner_lock"`
	TargetDirectory        directoryBirth `json:"target_directory"`
}

type managedLaunchIntent struct {
	OwnerSession string                `json:"owner_session"`
	IntentSHA256 string                `json:"intent_sha256"`
	Manifest     managedLaunchManifest `json:"manifest"`
}

type managedLaunchEnvelope struct {
	SchemaVersion   int    `json:"schema_version"`
	Payload         string `json:"payload"`
	IntegritySHA256 string `json:"integrity_sha256"`
}

type managedLaunchFact struct {
	Kind               string                   `json:"kind"`
	DaemonID           string                   `json:"daemon_id"`
	Generation         string                   `json:"generation"`
	OperationID        string                   `json:"operation_id"`
	RequestFingerprint string                   `json:"request_fingerprint"`
	IntentSHA256       string                   `json:"intent_sha256"`
	MountToken         string                   `json:"mount_token"`
	Scope              physicalScope            `json:"scope"`
	Process            *physicalProcessIdentity `json:"process"`
	Mount              *physicalMountIdentity   `json:"mount,omitempty"`
}

// Assigned under physicalMu before Start's critical section ends. Wait runs
// exactly once, retains the native child handle, and never publishes metadata.
type managedLaunchChild struct {
	Generation string
	Command    *exec.Cmd
	Done       chan struct{}
	Err        error // Written before Done closes; read only after Done is received.
}

var errManagedProcessPending = errors.New("original producer process fact is missing")

func managedMountArgs(legacy []string) ([]string, error) {
	if len(legacy) < 2 || legacy[0] != "mount" || legacy[1] != "--daemon" {
		return nil, fmt.Errorf("original mount arguments are incomplete")
	}
	args := append([]string{legacy[0]}, legacy[2:]...)
	return append(args, "--scheduler-launch-manifest-fd", "3", "--scheduler-owner-lock-fd", "4", "--scheduler-owner-directory-fd", "5", "--scheduler-journal-directory-fd", "6"), nil
}

func launchBoottime() (uint64, error) {
	var clock unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &clock); err != nil || clock.Sec < 0 || clock.Nsec < 0 || clock.Nsec >= 1e9 {
		return 0, fmt.Errorf("original launch clock is unavailable")
	}
	if uint64(clock.Sec) > (^uint64(0)-uint64(clock.Nsec))/1e9 {
		return 0, fmt.Errorf("original launch clock overflow")
	}
	return uint64(clock.Sec)*1e9 + uint64(clock.Nsec), nil
}

func openLaunchDirectory(path string, birth *directoryBirth) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("original launch directory path is invalid")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if openErr != nil {
			return nil, fmt.Errorf("open original launch directory: %w", openErr)
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), path)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0022 != 0 || stat.Ino == 0 || birth != nil && (stat.Ino != birth.Inode || uint64(stat.Dev) != birth.Device) {
		f.Close()
		return nil, fmt.Errorf("original launch directory changed")
	}
	return f, nil
}

func (d *Daemon) prepareManagedLaunch(p *physicalIdentity, legacy []string) error {
	preparation := d.originalPreparation()
	if preparation == nil || preparation.Owner.OperationID == "" {
		return nil
	} // Legacy identity never upgrades.
	if d.ownership == nil {
		return fmt.Errorf("managed launch requires an original manager owner")
	}
	args, err := managedMountArgs(legacy)
	if err != nil {
		return err
	}
	p.ArgumentsSHA256 = metadataSHA([]byte(strings.Join(append([]string{d.binPath}, args...), "\x00") + "\x00"))
	now, err := launchBoottime()
	if err != nil {
		return err
	}
	duration := daemonMountTimeout
	if duration <= 0 || duration > 5*time.Minute {
		duration = time.Minute
	}
	manifest := managedLaunchManifest{SchemaVersion: 1, DaemonID: d.meta.ID, Generation: p.Generation, OperationID: preparation.Owner.OperationID, RequestFingerprint: preparation.Owner.RequestFingerprint, Target: p.Target, PIDFile: p.PIDFile, ExecutableSHA256: p.ExecutableSHA256, ArgumentsSHA256: p.ArgumentsSHA256, SourceSHA256: p.SourceSHA256, Scope: p.Scope, InitializationDeadline: now + uint64(duration), JournalPath: d.meta.DaemonDir, JournalDirectory: *p.BirthDirectory, OwnerPath: d.ownership.root, OwnerLockName: managerOwnerLockName}
	ownerRelease, err := d.ownership.acquire()
	if err != nil {
		return err
	}
	defer ownerRelease()
	d.ownership.mu.Lock()
	manifest.OwnerDirectory = directoryBirth{Device: uint64(d.ownership.directoryStat.Dev), Inode: d.ownership.directoryStat.Ino}
	manifest.OwnerLock = directoryBirth{Device: uint64(d.ownership.lockStat.Dev), Inode: d.ownership.lockStat.Ino}
	session := d.ownership.session
	d.ownership.mu.Unlock()
	target, err := readDirectoryBirth(p.Target)
	if err != nil {
		return err
	}
	manifest.TargetDirectory = *target
	for _, input := range []struct {
		path string
		hash *string
	}{{d.meta.CfgPath, &manifest.ConfigSHA256}, {d.meta.BootstrapPath, &manifest.BootstrapSHA256}} {
		if input.path == "" {
			continue
		}
		data, err := readPhysicalFile(input.path, 256<<20)
		if err != nil {
			return err
		}
		*input.hash = metadataSHA(data)
	}
	data, err := json.Marshal(manifest)
	if err != nil || len(data) > physicalBirthLimit {
		return fmt.Errorf("original launch manifest exceeds byte limit")
	}
	p.ManagedLaunch = &managedLaunchIntent{OwnerSession: session, IntentSHA256: metadataSHA(data), Manifest: manifest}
	// A manifest that fits its own envelope can still make the native original
	// anchor too large. Reject that layout before dispatch, rather than starting
	// a child whose original facts cannot subsequently be adopted or retired.
	probe := &physicalProcessIdentity{PID: 2147483647, StartTicks: ^uint64(0), ExecutableSHA256: p.ExecutableSHA256, ArgumentsSHA256: p.ArgumentsSHA256}
	for _, kind := range []string{"process", "mount"} {
		record := physicalBirthRecord{SchemaVersion: 1, DaemonID: d.meta.ID, Kind: kind, Original: physicalLaunchAnchor(p), Process: probe, IntegritySHA256: strings.Repeat("0", 64)}
		if kind == "mount" {
			record.Mount = &physicalMountIdentity{MountID: 2147483647, UniqueMountID: ^uint64(0), Major: 4294967295, Minor: 4294967295, Root: "/", Filesystem: "fuse.distill_fs", Source: "akernel-" + p.Generation}
		}
		bytes, err := json.Marshal(record)
		if err != nil || len(bytes)+1 > physicalBirthLimit {
			return fmt.Errorf("original managed birth anchor exceeds byte limit before dispatch")
		}
	}
	return nil
}

func validateManagedLaunch(meta DaemonMeta, p *physicalIdentity) error {
	if p.ManagedLaunch == nil {
		return nil
	}
	i := p.ManagedLaunch
	m := i.Manifest
	prep := meta.Preparation
	data, err := json.Marshal(m)
	if err != nil || len(data) > physicalBirthLimit || !validPhysicalSHA(i.IntentSHA256) || i.IntentSHA256 != metadataSHA(data) || !validPhysicalSHA(i.OwnerSession) || p.BirthProtocol != 1 || p.BirthDirectory == nil || prep == nil || prep.Owner.OperationID == "" || m.SchemaVersion != 1 || m.DaemonID != meta.ID || m.Generation != p.Generation || m.OperationID != prep.Owner.OperationID || m.RequestFingerprint != prep.Owner.RequestFingerprint || m.Target != p.Target || m.PIDFile != p.PIDFile || m.ExecutableSHA256 != p.ExecutableSHA256 || m.ArgumentsSHA256 != p.ArgumentsSHA256 || m.SourceSHA256 != p.SourceSHA256 || m.Scope != p.Scope || m.JournalPath != meta.DaemonDir || m.JournalDirectory != *p.BirthDirectory || m.InitializationDeadline == 0 || m.OwnerLockName != managerOwnerLockName || m.OwnerDirectory.Inode == 0 || m.OwnerLock.Inode == 0 || m.TargetDirectory.Inode == 0 || !filepath.IsAbs(m.OwnerPath) || filepath.Clean(m.OwnerPath) != m.OwnerPath || !strings.HasPrefix(m.JournalPath, m.OwnerPath+string(os.PathSeparator)) || m.ConfigSHA256 == "" && meta.CfgPath != "" || m.ConfigSHA256 != "" && !validPhysicalSHA(m.ConfigSHA256) || m.BootstrapSHA256 == "" && meta.BootstrapPath != "" || m.BootstrapSHA256 != "" && !validPhysicalSHA(m.BootstrapSHA256) {
		return fmt.Errorf("managed original launch identity is invalid")
	}
	if p.Mount != nil && (p.Mount.Source != "akernel-"+p.Generation || p.Mount.Filesystem != "fuse.distill_fs") {
		return fmt.Errorf("managed original kernel source differs")
	}
	return nil
}

func decodeManagedLaunch(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("invalid original producer fields")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("original producer record has trailing data")
	}
	return rejectDuplicateDaemonFields(json.NewDecoder(bytes.NewReader(data)), 0)
}

func publishLaunchManifest(directory *os.File, name string, data []byte) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	tempName := ".launch-intent-" + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(int(directory.Fd()), tempName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), tempName)
	defer f.Close()
	defer unix.Unlinkat(int(directory.Fd()), tempName, 0)
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := unix.Linkat(int(directory.Fd()), tempName, int(directory.Fd()), name, 0); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return err
		}
		existing, readErr := readPhysicalBirthFile(directory, name)
		if readErr != nil || !bytes.Equal(existing, data) {
			return fmt.Errorf("original launch manifest already differs")
		}
	}
	if err := unix.Unlinkat(int(directory.Fd()), tempName, 0); err != nil {
		return err
	}
	return directory.Sync()
}

// Caller holds physicalMu through dispatch. Each descriptor is a private dup,
// and all parent copies close after Start; the root flock's OFD stays shared.
func (d *Daemon) managedLaunchFiles(p *physicalIdentity) ([]*os.File, error) {
	if p.ManagedLaunch == nil {
		return nil, nil
	}
	i := p.ManagedLaunch
	m := i.Manifest
	if err := validateManagedLaunch(d.meta, p); err != nil {
		return nil, err
	}
	if d.ownership == nil || d.ownership.session != i.OwnerSession || d.ownership.root != m.OwnerPath {
		return nil, fmt.Errorf("original launch owner session changed")
	}
	now, err := launchBoottime()
	if err != nil || now >= m.InitializationDeadline || m.InitializationDeadline-now > uint64(5*time.Minute) {
		return nil, fmt.Errorf("original launch deadline expired")
	}
	root, err := openLaunchDirectory(m.OwnerPath, &m.OwnerDirectory)
	if err != nil {
		return nil, err
	}
	journal, err := openLaunchDirectory(m.JournalPath, &m.JournalDirectory)
	if err != nil {
		root.Close()
		return nil, err
	}
	files := []*os.File{root, journal}
	ok := false
	defer func() {
		if !ok {
			for _, f := range files {
				f.Close()
			}
		}
	}()
	target, err := openLaunchDirectory(m.Target, &m.TargetDirectory)
	if err != nil {
		return nil, err
	}
	target.Close()
	data, _ := json.Marshal(m)
	name := "launch-intent-" + p.Generation + ".json"
	if err := publishLaunchManifest(journal, name, data); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(journal.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	manifest := os.NewFile(uintptr(fd), name)
	files = append(files, manifest)
	actual, err := readPhysicalBirthFile(journal, name)
	if err != nil || metadataSHA(actual) != i.IntentSHA256 {
		return nil, fmt.Errorf("original launch manifest changed before dispatch")
	}
	d.ownership.mu.Lock()
	verifyErr := d.ownership.verifyPathsLocked()
	lockFD, dupErr := unix.FcntlInt(d.ownership.lock.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	d.ownership.mu.Unlock()
	if dupErr != nil {
		return nil, dupErr
	}
	lock := os.NewFile(uintptr(lockFD), managerOwnerLockName)
	files = append(files, lock)
	if verifyErr != nil {
		return nil, verifyErr
	}
	if m.OwnerLock != (directoryBirth{Device: uint64(d.ownership.lockStat.Dev), Inode: d.ownership.lockStat.Ino}) {
		return nil, fmt.Errorf("original launch owner lock differs")
	}
	ok = true
	return []*os.File{manifest, lock, root, journal}, nil
}

func (d *Daemon) readManagedLaunchFact(directory *os.File, p *physicalIdentity, kind string) (*managedLaunchFact, error) {
	data, err := readPhysicalBirthFile(directory, "launch-birth-"+p.Generation+"-"+kind+".json")
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var envelope managedLaunchEnvelope
	if err := decodeManagedLaunch(data, &envelope); err != nil {
		return nil, err
	}
	if envelope.SchemaVersion != 1 || envelope.IntegritySHA256 != metadataSHA([]byte(envelope.Payload)) {
		return nil, fmt.Errorf("original producer integrity differs")
	}
	var fact managedLaunchFact
	if err := decodeManagedLaunch([]byte(envelope.Payload), &fact); err != nil {
		return nil, err
	}
	m := p.ManagedLaunch.Manifest
	if fact.Kind != kind || fact.DaemonID != d.meta.ID || fact.Generation != p.Generation || fact.OperationID != m.OperationID || fact.RequestFingerprint != m.RequestFingerprint || fact.IntentSHA256 != p.ManagedLaunch.IntentSHA256 || fact.MountToken != "akernel-"+p.Generation || fact.Scope != p.Scope || fact.Process == nil || kind == "process" && fact.Mount != nil || kind == "mount" && fact.Mount == nil {
		return nil, fmt.Errorf("original producer ownership differs")
	}
	meta := d.meta
	meta.PhysicalIdentity = clonePhysicalIdentity(p)
	meta.PhysicalIdentity.Process = fact.Process
	meta.PhysicalIdentity.Mount = fact.Mount
	meta.PhysicalIdentity.Phase = "launching"
	if err := validatePhysicalMetadata(meta); err != nil {
		return nil, err
	}
	return &fact, nil
}

// This adoption never reads a PID file to manufacture original birth. The
// primary metadata must sync before any lifecycle effect uses the producer.
func (d *Daemon) adoptManagedLaunchFacts(requireMount, requireLive bool) error {
	release, err := d.ownership.acquire()
	if err != nil {
		return err
	}
	defer release()
	d.physicalMu.Lock()
	defer d.physicalMu.Unlock()
	p := clonePhysicalIdentity(d.meta.PhysicalIdentity)
	if p == nil || p.ManagedLaunch == nil {
		return fmt.Errorf("original managed launch is missing")
	}
	if requireLive && (p.Phase != "launching" && p.Phase != "running" || d.physicalPublicationPending) {
		return fmt.Errorf("original managed launch is fenced")
	}
	if p.Phase == "released" || p.NoDispatchConfirmed {
		return fmt.Errorf("original producer adoption is no longer authorized")
	}
	directory, err := openLaunchDirectory(p.ManagedLaunch.Manifest.JournalPath, &p.ManagedLaunch.Manifest.JournalDirectory)
	if err != nil {
		return err
	}
	defer directory.Close()
	process, err := d.readManagedLaunchFact(directory, p, "process")
	if err != nil {
		return err
	}
	if process == nil {
		return errManagedProcessPending
	}
	mount, err := d.readManagedLaunchFact(directory, p, "mount")
	if err != nil {
		return err
	}
	if mount == nil && p.Phase == "releasing" {
		native, err := d.readPhysicalBirth(directory, p, "mount")
		if err != nil {
			return err
		}
		if native != nil {
			mount = &managedLaunchFact{Process: native.Process, Mount: native.Mount}
		}
	}
	if p.Process != nil && *p.Process != *process.Process || mount != nil && *mount.Process != *process.Process || p.Mount != nil && (mount == nil || *p.Mount != *mount.Mount) {
		return fmt.Errorf("original producer birth contradicts metadata")
	}
	if child := d.managedChild; child != nil && (child.Generation != p.Generation || child.Command.Process.Pid != process.Process.PID) {
		return fmt.Errorf("producer does not belong to the original direct child")
	}
	scope, err := d.observeOriginalScope()
	if err != nil || scope != p.Scope {
		return fmt.Errorf("original producer scope changed")
	}
	source, err := d.sourceIdentitySHA()
	if err != nil || source != p.SourceSHA256 {
		return fmt.Errorf("original producer source changed")
	}
	if requireLive {
		current, err := d.observeOriginalProcess(process.Process.PID)
		if err != nil || current == nil || *current != *process.Process {
			return fmt.Errorf("original producer process is no longer live")
		}
	}
	if requireMount && mount == nil {
		return fmt.Errorf("original producer mount fact is missing")
	}
	p.Process = process.Process
	if mount != nil {
		if requireLive {
			current, err := d.observeOriginalMount()
			if err != nil || current == nil || *current != *mount.Mount {
				return fmt.Errorf("original producer mount changed")
			}
		}
		p.Mount = mount.Mount
		if requireLive {
			p.Phase = "running"
		}
	}
	if err := directory.Sync(); err != nil {
		return err
	}
	if err := d.persistPhysicalBirthLocked(p, "process"); err != nil {
		return err
	}
	if p.Mount != nil {
		if err := d.persistPhysicalBirthLocked(p, "mount"); err != nil {
			return err
		}
	}
	return d.publishPhysicalIdentityLocked(p)
}

func (d *Daemon) waitManagedLaunchProcess(child *managedLaunchChild) error {
	if child == nil {
		return fmt.Errorf("original direct child is missing")
	}
	deadline := time.NewTimer(daemonMountTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		// Avoid adopting a dead process as a successful initialization, while
		// still preserving its immutable facts for subsequent explicit cleanup.
		err := d.adoptManagedLaunchFacts(false, true)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errManagedProcessPending) {
			return err
		}
		select {
		case <-child.Done:
			_ = d.adoptManagedLaunchFacts(false, false)
			return fmt.Errorf("original managed child exited before initialization")
		case <-d.ownership.closingSignal():
			return fmt.Errorf("original owner closed during initialization")
		case <-deadline.C:
			return fmt.Errorf("original managed process confirmation timed out")
		case <-ticker.C:
		}
	}
}

// Caller has already durably published releasing. First adopt the original
// process fact, then stop only that process and wait for the owned child. If
// its first fact is missing, wait conservatively without sending any signal.
func (d *Daemon) stopManagedLaunchChild() error {
	d.physicalMu.Lock()
	p := clonePhysicalIdentity(d.meta.PhysicalIdentity)
	child := d.managedChild
	d.physicalMu.Unlock()
	if p == nil || p.ManagedLaunch == nil || child == nil {
		return nil
	}
	if p.Phase != "releasing" || child.Generation != p.Generation {
		return fmt.Errorf("original child release is not fenced")
	}
	select {
	case <-child.Done:
		if d.getState() == DaemonStateMounting {
			d.setState(DaemonStateStopped)
		}
		return nil
	default:
	}
	if err := d.adoptManagedLaunchFacts(false, false); err == nil {
		if err := d.signalOriginalProcess(syscall.SIGTERM); err != nil {
			return err
		}
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-child.Done:
		if d.getState() == DaemonStateMounting {
			d.setState(DaemonStateStopped)
		}
		return nil
	case <-timer.C:
		return fmt.Errorf("original managed child exit is still unknown")
	}
}

// A missing mount acknowledgement is reconciled only after original-process
// exit. The immutable producer process fact binds the kernel generation token,
// the held target at birth, the complete command and the original scope. This
// is a new managed-producer contract; legacy mounts never use this recovery.
func (d *Daemon) reconcileManagedMountAfterProcessExit() error {
	d.physicalMu.Lock()
	defer d.physicalMu.Unlock()
	p := clonePhysicalIdentity(d.meta.PhysicalIdentity)
	if p == nil || p.ManagedLaunch == nil || p.Mount != nil {
		return nil
	}
	if p.Phase != "releasing" || p.Process == nil {
		return fmt.Errorf("original managed process exit is not fenced")
	}
	scope, err := d.observeOriginalScope()
	if err != nil || scope != p.Scope {
		return fmt.Errorf("original managed scope changed during mount reconciliation")
	}
	current, err := d.observeOriginalProcess(p.Process.PID)
	if err != nil || current != nil {
		return fmt.Errorf("original managed process exit is unconfirmed")
	}
	directory, err := openLaunchDirectory(p.ManagedLaunch.Manifest.JournalPath, &p.ManagedLaunch.Manifest.JournalDirectory)
	if err != nil {
		return err
	}
	defer directory.Close()
	process, err := d.readManagedLaunchFact(directory, p, "process")
	if err != nil || process == nil || *process.Process != *p.Process {
		return fmt.Errorf("original kernel token lacks its immutable producer")
	}
	mount, err := d.observeOriginalMount()
	if err != nil {
		return err
	}
	if mount == nil {
		target, err := openLaunchDirectory(p.Target, &p.ManagedLaunch.Manifest.TargetDirectory)
		if err != nil {
			return err
		}
		target.Close()
		return nil
	}
	if mount.Source != process.MountToken || mount.Filesystem != "fuse.distill_fs" {
		return fmt.Errorf("current kernel mount does not belong to the original producer")
	}
	p.Mount = mount
	if err := d.persistPhysicalBirthLocked(p, "mount"); err != nil {
		return err
	}
	return d.publishPhysicalIdentityLocked(p)
}
