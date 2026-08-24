// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package firecracker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/firecrackerproto"
	"github.com/inclusionAI/sandboxd/internal/util"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	runtimecommon "github.com/inclusionAI/sandboxd/pkg/runtime/internal/common"
	"github.com/sirupsen/logrus"
)

const firecrackerBaseMemoryName = "base-memory"

// Checkpoint writes a v2 checkpoint directory owned by the caller and keeps
// the incremental lineage alive across generations:
//
//   - tier 1: a base from a previous checkpoint in the same Firecracker
//     process — reflink-clone it and let a SoftDirty snapshot patch the pages
//     of the current window into the clone;
//   - tier 2: a base from the last restore — clone it and use the pagemap
//     (Incremental) ledger, which is the baseline a restored process tracks;
//   - tier 3: no usable base — preallocate a zero memory file and take a
//     first SoftDirty window.
//
// The sandbox-owned base only advances to a memory image the running
// Firecracker actually produced (mirroring the fork's ack semantics), so a
// failed generation never leaves a stale base that a later window could be
// patched into incorrectly.
func (handler *Handler) Checkpoint(
	ctx context.Context,
	config runtimecore.CheckpointConfig,
) (retErr error) {
	sandboxID := config.ID
	instance, err := handler.lookupInstance(sandboxID)
	if err != nil {
		return err
	}
	instance.operationMu.Lock()
	defer instance.operationMu.Unlock()
	state := instance.snapshot()
	if state.Exited || !state.Configured ||
		!firecrackerProcessMatches(state.PID, handler.binary, state.APIPath, state.ID) {
		return fmt.Errorf("Firecracker sandbox %s is not running", sandboxID)
	}

	api := newFirecrackerAPI(state.APIPath)
	memorySize := int64(state.MemoryMiB) << 20
	base := state.BaseMemoryPath
	incremental := state.BaseMemoryIncremental
	if memorySize > 0 && base != "" && !firecrackerBaseMemoryUsable(base, memorySize) {
		// The base drifted (crash cleanup, operator interference): fall
		// through to a first window instead of failing outright.
		base = ""
		incremental = false
	}
	snapshotType := firecrackerSnapshotTypeFull
	if memorySize > 0 {
		snapshotType = firecrackerSnapshotTypeSoftDirty
		if base != "" && incremental {
			snapshotType = firecrackerSnapshotTypeIncremental
		}
	}

	// Layout happens before the pause: cloning the base is pure host-side
	// work the guest should not wait for. A tier-1/2 layout failure degrades
	// to a first window; anything else is unrecoverable.
	files, err := prepareFirecrackerCheckpointV2(config.Directory, base, memorySize)
	if err != nil {
		if base == "" || memorySize <= 0 {
			return fmt.Errorf("lay out Firecracker checkpoint for %s: %w", sandboxID, err)
		}
		logrus.Warnf(
			"firecracker: incremental layout for %s failed, rebuilding base: %v",
			sandboxID, err,
		)
		handler.disarmBaseMemory(instance, sandboxID)
		base, incremental = "", false
		snapshotType = firecrackerSnapshotTypeSoftDirty
		if files, err = prepareFirecrackerCheckpointV2(config.Directory, "", memorySize); err != nil {
			return fmt.Errorf("lay out Firecracker checkpoint for %s: %w", sandboxID, err)
		}
	}

	if err := api.pause(ctx); err != nil {
		discardUnsealedFirecrackerCheckpoint(files)
		return fmt.Errorf("pause Firecracker sandbox %s: %w", sandboxID, err)
	}
	if err := api.createSnapshot(ctx, files.State, files.Memory, snapshotType); err != nil {
		if base != "" && memorySize > 0 {
			// A failed snapshot request disarms the Firecracker ledger, so
			// the previous base is dead: rebuild from a first window while
			// the guest is still paused.
			handler.disarmBaseMemory(instance, sandboxID)
			discardUnsealedFirecrackerCheckpoint(files)
			base, incremental = "", false
			snapshotType = firecrackerSnapshotTypeSoftDirty
			if files, err = prepareFirecrackerCheckpointV2(config.Directory, "", memorySize); err == nil {
				err = api.createSnapshot(ctx, files.State, files.Memory, snapshotType)
			} else {
				files = firecrackerCheckpointFiles{}
			}
		}
		if err != nil {
			discardUnsealedFirecrackerCheckpoint(files)
			if config.LeaveRunning {
				err = errors.Join(err, fmt.Errorf(
					"resume Firecracker sandbox %s: %w", sandboxID, api.resume(ctx),
				))
			}
			return fmt.Errorf("create Firecracker %s snapshot for %s: %w",
				snapshotType, sandboxID, err)
		}
	}
	// The snapshot succeeded: files.Memory is now the complete guest memory
	// image and the baseline the Firecracker ledger tracks.
	if _, err := cloneFile(state.OverlayPath, files.Overlay); err != nil {
		// The window already reset, so keep the chain alive through the base
		// even though this artifact cannot be sealed.
		handler.adoptCheckpointMemory(instance, files.Memory, sandboxID, false)
		discardUnsealedFirecrackerCheckpoint(files)
		if config.LeaveRunning {
			err = errors.Join(err, fmt.Errorf(
				"resume Firecracker sandbox %s: %w", sandboxID, api.resume(ctx),
			))
		}
		return fmt.Errorf("snapshot Firecracker writable layer for %s: %w", sandboxID, err)
	}

	resumeErr := error(nil)
	if config.LeaveRunning {
		if err := api.resume(ctx); err != nil {
			resumeErr = fmt.Errorf("resume Firecracker sandbox %s: %w", sandboxID, err)
		}
	}

	// Post-resume tail: sealing digests and adopting the base cost seconds per
	// GiB on hashing and copying and must not extend the pause window.
	memoryInfo, err := os.Lstat(files.Memory)
	if err != nil {
		handler.adoptCheckpointMemory(instance, files.Memory, sandboxID, false)
		discardUnsealedFirecrackerCheckpoint(files)
		return errors.Join(resumeErr, fmt.Errorf(
			"inspect Firecracker checkpoint memory for %s: %w", sandboxID, err,
		))
	}
	manifest := &firecrackerCheckpointManifest{
		SnapshotType: snapshotType,
		MemorySize:   memoryInfo.Size(),
	}
	if base != "" {
		manifest.BaseMemory = firecrackerBaseMemoryName
	}
	if err := finalizeFirecrackerCheckpointV2(ctx, files, manifest); err != nil {
		handler.adoptCheckpointMemory(instance, files.Memory, sandboxID, false)
		discardUnsealedFirecrackerCheckpoint(files)
		return errors.Join(resumeErr, fmt.Errorf(
			"seal Firecracker checkpoint for %s: %w", sandboxID, err,
		))
	}
	handler.adoptCheckpointMemory(instance, files.Memory, sandboxID, false)

	if !config.LeaveRunning {
		return handler.finishCheckpointedSandbox(instance, state, sandboxID)
	}
	if resumeErr != nil {
		// The artifact is sealed and the base adopted; only the guest is
		// still paused, which the caller must see as a failure.
		return resumeErr
	}
	logrus.Infof(
		"firecracker: checkpointed sandbox %s type=%s memory=%dMiB dir=%s",
		sandboxID, snapshotType, memoryInfo.Size()>>20, config.Directory,
	)
	return nil
}

func (handler *Handler) finishCheckpointedSandbox(
	instance *firecrackerInstance,
	state firecrackerPersistedState,
	sandboxID string,
) error {
	handler.stopInstance(instance, true)
	if firecrackerProcessMatches(state.PID, handler.binary, state.APIPath, state.ID) {
		return fmt.Errorf("stop Firecracker sandbox %s after checkpoint", sandboxID)
	}
	if instance.finish(runtimecore.Exit{ExitedAt: time.Now(), ExitCode: 0}) && instance.shouldPersist() {
		if err := handler.persistInstance(instance); err != nil {
			logrus.Warnf("firecracker: persist checkpoint exit state for %s: %v", sandboxID, err)
		}
	}
	return nil
}

// firecrackerBaseMemoryUsable reports whether the recorded base can still be
// patched by an incremental snapshot of a guest with the given memory size.
func firecrackerBaseMemoryUsable(path string, memorySize int64) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() &&
		info.Mode()&os.ModeSymlink == 0 && info.Size() == memorySize
}

// discardUnsealedFirecrackerCheckpoint removes the components of a checkpoint
// directory that never reached a manifest; sealed artifacts are left alone.
func discardUnsealedFirecrackerCheckpoint(files firecrackerCheckpointFiles) {
	for _, path := range []string{files.State, files.Memory, files.Overlay} {
		if path != "" {
			_ = os.Remove(path)
		}
	}
}

// adoptCheckpointMemory advances the sandbox-owned base to a memory image a
// Firecracker process produced (a checkpoint the running VMM just wrote, or
// the file a restore just loaded), keeping the incremental chain consistent
// with the in-process ledger. When the adoption itself fails the lineage is
// dropped: the next checkpoint rebuilds a first window.
func (handler *Handler) adoptCheckpointMemory(
	instance *firecrackerInstance,
	memoryPath,
	sandboxID string,
	incremental bool,
) {
	if memoryPath == "" {
		return
	}
	if err := handler.cloneBaseMemory(memoryPath, sandboxID); err != nil {
		logrus.Warnf(
			"firecracker: adopt checkpoint base for %s: %v", sandboxID, err,
		)
		instance.clearBaseMemory()
		return
	}
	instance.setBaseMemory(handler.baseMemoryPath(sandboxID), incremental)
}

func (handler *Handler) cloneBaseMemory(memoryPath, sandboxID string) error {
	base := handler.baseMemoryPath(sandboxID)
	if base == "" {
		return errors.New("sandbox ID is rejected by the storage root")
	}
	staging := base + ".staging"
	if err := os.Remove(staging); err != nil && !os.IsNotExist(err) {
		return err
	}
	if _, err := cloneFile(memoryPath, staging); err != nil {
		_ = os.Remove(staging)
		return err
	}
	if err := os.Rename(staging, base); err != nil {
		_ = os.Remove(staging)
		return err
	}
	return nil
}

// disarmBaseMemory drops the incremental lineage and removes the orphaned
// base file so it cannot be mistaken for a live baseline later.
func (handler *Handler) disarmBaseMemory(instance *firecrackerInstance, sandboxID string) {
	if instance.clearBaseMemory() {
		if base := handler.baseMemoryPath(sandboxID); base != "" {
			_ = os.Remove(base)
		}
	}
}

func (handler *Handler) baseMemoryPath(sandboxID string) string {
	directory, err := util.JoinWithinRoot(handler.storageRoot, sandboxID)
	if err != nil {
		return ""
	}
	return filepath.Join(directory, firecrackerBaseMemoryName)
}

func (handler *Handler) Restore(
	ctx context.Context,
	startConfig runtimecore.StartConfig,
) (retErr error) {
	imagePath := filepath.Join(startConfig.CheckpointDir, checkpointImageName)
	if startConfig.DisableCgroup || startConfig.CgroupPath == "" {
		return errors.New("Firecracker requires a managed cgroup")
	}
	if startConfig.EnableKVM {
		return errors.New("Firecracker does not expose nested KVM to the guest")
	}
	if startConfig.SpecUpdates != nil {
		return errors.New("Firecracker does not support host device-provider OCI updates")
	}
	if startConfig.Network == nil || startConfig.Network.Interface == nil {
		return errors.New("Firecracker requires a cached TAP network")
	}
	handler.mu.RLock()
	_, alreadyRunning := handler.instances[startConfig.ID]
	handler.mu.RUnlock()
	if alreadyRunning {
		return fmt.Errorf("Firecracker sandbox %s already exists", startConfig.ID)
	}

	bundlePath, spec, err := handler.ociLoader.GenerateOci(runtimecore.OciLoadOptions{
		SandboxID:  startConfig.ID,
		Config:     startConfig,
		CgroupPath: startConfig.CgroupPath,
	})
	if err != nil {
		return fmt.Errorf("generate Firecracker restore OCI metadata: %w", err)
	}
	plan, err := prepareFirecrackerStorage(spec, startConfig)
	if err != nil {
		return err
	}
	storageDir, err := createFirecrackerStorageDirectory(handler.storageRoot, startConfig.ID)
	if err != nil {
		return err
	}
	keepStorage := false
	defer func() {
		if !keepStorage {
			retErr = errors.Join(
				retErr,
				cleanupFirecrackerOverlay(handler.storageRoot, startConfig.ID),
			)
		}
	}()

	stateDir := filepath.Join(bundlePath, firecrackerArtifactsDir)
	if err := os.Mkdir(stateDir, 0700); err != nil {
		return fmt.Errorf("create Firecracker restore state directory: %w", err)
	}
	runtimeDir := handler.runtimeDirectory(startConfig.ID)
	runtimeCreated := false
	keepRuntimeArtifacts := false
	defer func() {
		if keepRuntimeArtifacts {
			return
		}
		retErr = errors.Join(retErr, os.RemoveAll(stateDir))
		if runtimeCreated {
			retErr = errors.Join(
				retErr,
				handler.cleanupRuntimeDirectory(startConfig.ID, filepath.Join(
					runtimeDir, firecrackerAPISocket,
				)),
			)
		}
	}()
	if err := os.Mkdir(runtimeDir, 0700); err != nil {
		return fmt.Errorf("create Firecracker socket directory %s: %w", runtimeDir, err)
	}
	runtimeCreated = true
	apiPath := filepath.Join(runtimeDir, firecrackerAPISocket)
	vsockPath := filepath.Join(runtimeDir, firecrackerVsock)
	if len(apiPath) >= 100 || len(vsockPath) >= 100 {
		return fmt.Errorf("Firecracker Unix socket path is too long under %s", runtimeDir)
	}
	if err := removeFirecrackerSocket(apiPath); err != nil {
		return err
	}
	if err := removeFirecrackerSocket(vsockPath); err != nil {
		return err
	}

	checkpointFiles := firecrackerCheckpointFiles{
		State:   filepath.Join(stateDir, firecrackerCheckpointStateName),
		Memory:  filepath.Join(stateDir, firecrackerCheckpointMemoryName),
		Overlay: filepath.Join(storageDir, "overlay.ext4"),
	}
	if err := extractFirecrackerCheckpointArchive(
		ctx,
		imagePath,
		checkpointFiles,
	); err != nil {
		return err
	}
	memoryInfo, err := os.Lstat(checkpointFiles.Memory)
	if err != nil {
		return fmt.Errorf("inspect restored Firecracker memory: %w", err)
	}
	if err := os.Symlink(checkpointFiles.Overlay, filepath.Join(
		stateDir, firecrackerCheckpointOverlayName,
	)); err != nil {
		return fmt.Errorf("link restored Firecracker writable layer: %w", err)
	}

	stdout, err := openFirecrackerOutput(startConfig.Stdout)
	if err != nil {
		return err
	}
	defer stdout.Close()
	stderr, err := openFirecrackerOutput(startConfig.Stderr)
	if err != nil {
		return err
	}
	defer stderr.Close()
	command := exec.Command(
		handler.binary,
		"--api-sock", apiPath,
		"--id", startConfig.ID,
	)
	command.Dir = stateDir
	command.Stdout = stdout
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return fmt.Errorf("start Firecracker restore VMM: %w", err)
	}
	instance := &firecrackerInstance{
		state: firecrackerPersistedState{
			ID:          startConfig.ID,
			PID:         command.Process.Pid,
			BundlePath:  bundlePath,
			APIPath:     apiPath,
			VsockPath:   vsockPath,
			OverlayPath: checkpointFiles.Overlay,
			MemoryMiB:   uint32(memoryInfo.Size() >> 20),
			CreatedAt:   time.Now().Format(time.RFC3339Nano),
		},
		done: make(chan struct{}),
	}
	handler.mu.Lock()
	handler.instances[startConfig.ID] = instance
	handler.mu.Unlock()
	go handler.waitCommand(instance, command)

	restoreSucceeded := false
	defer func() {
		if restoreSucceeded {
			return
		}
		instance.markDeleting()
		handler.stopInstance(instance, true)
		handler.mu.Lock()
		delete(handler.instances, startConfig.ID)
		handler.mu.Unlock()
	}()
	if err := attachFirecrackerProcess(startConfig.CgroupPath, command.Process.Pid); err != nil {
		return fmt.Errorf("attach restored Firecracker to cgroup: %w", err)
	}
	if err := handler.persistInstance(instance); err != nil {
		return err
	}

	readyCtx, readyCancel := context.WithTimeout(ctx, firecrackerAgentTimeout)
	api := newFirecrackerAPI(apiPath)
	if err := api.waitReady(readyCtx); err != nil {
		readyCancel()
		return err
	}
	readyCancel()
	if err := api.loadSnapshot(
		ctx,
		checkpointFiles.State,
		checkpointFiles.Memory,
		startConfig.Network.Interface.Name,
		vsockPath,
	); err != nil {
		return fmt.Errorf("load Firecracker checkpoint for %s: %w", startConfig.ID, err)
	}
	agentCtx, agentCancel := context.WithTimeout(ctx, firecrackerAgentTimeout)
	defer agentCancel()
	if err := waitForFirecrackerAgent(agentCtx, vsockPath); err != nil {
		return err
	}
	if err := requestFirecrackerAgent(
		agentCtx,
		vsockPath,
		firecrackerproto.MessageSetNetwork,
		plan.configure.Network,
	); err != nil {
		return fmt.Errorf("configure restored Firecracker network: %w", err)
	}
	instance.markConfigured()
	// A restored Firecracker diffs against the memory file it loaded, so the
	// sandbox-owned base adopts that image and the next checkpoint runs as a
	// pagemap (Incremental) generation.
	handler.adoptCheckpointMemory(
		instance,
		checkpointFiles.Memory,
		startConfig.ID,
		true,
	)
	if err := handler.persistInstance(instance); err != nil {
		return err
	}
	go handler.waitGuest(instance)
	if err := runtimecommon.WriteSandboxRuntimeMarker(bundlePath, config.RuntimeNameFirecracker); err != nil {
		return fmt.Errorf("persist Firecracker restore runtime marker: %w", err)
	}
	restoreSucceeded = true
	keepStorage = true
	keepRuntimeArtifacts = true
	logrus.Infof(
		"firecracker: restored sandbox %s pid=%d",
		startConfig.ID,
		command.Process.Pid,
	)
	return nil
}
