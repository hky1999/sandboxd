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

package runsc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	runtimeapi "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/assert"
)

func TestNewRunscHandlerUsesSharedLogFile(t *testing.T) {
	baseDir := t.TempDir()
	rootDir := filepath.Join(baseDir, "sandboxd", "root")
	cfg := config.Config{RootDir: rootDir}
	cfg.RuntimeConfig.FilestoreDir = filepath.Join(baseDir, "filestore")
	handler, err := NewHandler(cfg, "/usr/local/bin/runsc", nil)
	assert.NoError(t, err)

	client, ok := handler.runsc.(*Client)
	if !ok {
		t.Fatalf("runsc client has unexpected type %T", handler.runsc)
	}
	assert.Equal(t, filepath.Join(baseDir, "logs", config.RuntimeNameRunsc, "runsc.log"), client.Options.DebugLogPath)
	assert.Equal(t, config.RunscPlatformSystrap, client.Options.Platform)
}

func TestNewRunscHandlerPropagatesIgnoreCgroups(t *testing.T) {
	rootDir := filepath.Join(t.TempDir(), "sandboxd", "root")
	cfg := config.Config{RootDir: rootDir}
	cfg.DisableCgroup = true
	cfg.RuntimeConfig.FilestoreDir = filepath.Join(t.TempDir(), "filestore")
	handler, err := NewHandler(cfg, "/usr/local/bin/runsc", nil)
	assert.NoError(t, err)

	client := handler.runsc.(*Client)
	assert.True(t, client.Options.IgnoreCgroups)
}

func TestNewRunscHandlerPropagatesKVMPlatform(t *testing.T) {
	rootDir := filepath.Join(t.TempDir(), "sandboxd", "root")
	cfg := config.Config{RootDir: rootDir}
	cfg.RuntimeConfig.FilestoreDir = filepath.Join(t.TempDir(), "filestore")
	cfg.RuntimeConfig.Runsc.Platform = config.RunscPlatformKVM
	handler, err := NewHandler(cfg, "/usr/local/bin/runsc", nil)
	assert.NoError(t, err)

	client := handler.runsc.(*Client)
	assert.Equal(t, config.RunscPlatformKVM, client.Options.Platform)
}

func TestNewRunscHandlerRejectsInvalidPlatform(t *testing.T) {
	rootDir := filepath.Join(t.TempDir(), "sandboxd", "root")
	cfg := config.Config{RootDir: rootDir}
	cfg.RuntimeConfig.FilestoreDir = filepath.Join(t.TempDir(), "filestore")
	cfg.RuntimeConfig.Runsc.Platform = "ptrace"
	_, err := NewHandler(cfg, "/usr/local/bin/runsc", nil)
	assert.ErrorContains(t, err, "runsc platform must be")
}

func TestNewRunscHandlerRejectsMissingFilestore(t *testing.T) {
	rootDir := filepath.Join(t.TempDir(), "sandboxd", "root")
	_, err := NewHandler(config.Config{RootDir: rootDir}, "/usr/local/bin/runsc", nil)
	assert.ErrorContains(t, err, "plugin.runtime.filestore_dir")
}

func TestRunscHandlerDoesNotPrepareNVProxyRootfsForGenericSpecUpdates(t *testing.T) {
	bundleRoot := t.TempDir()
	bundlePath := filepath.Join(bundleRoot, "sbox-generic-updates")
	assert.NoError(t, os.MkdirAll(bundlePath, 0755))

	originalMount := mountRunscNVProxyOverlay
	t.Cleanup(func() { mountRunscNVProxyOverlay = originalMount })
	mountRunscNVProxyOverlay = func(_, _, _, _ string) error {
		return errors.New("unexpected nvproxy overlay")
	}

	handler := &Handler{
		runsc:                  successfulRunscClient{},
		ociLoader:              staticOciLoader{bundlePath: bundlePath, spec: &runtimecore.Spec{Root: &runtimecore.Root{Path: t.TempDir()}}},
		rootfsOverlayTmpfsSize: "10G",
		filestoreDir:           t.TempDir(),
		sandboxRoot:            bundleRoot,
		mountEROFS:             mountRunscNVProxyEROFSImage,
	}
	err := handler.Start(context.Background(), runtimecore.StartConfig{
		ID:          "sbox-generic-updates",
		Network:     &networkmanager.NetResource{},
		SpecUpdates: &runtimecore.SpecUpdates{Annotations: map[string]string{"example": "value"}},
	})
	assert.NoError(t, err)
}

func TestRunscHandlerMountsRootfsImageForNVProxy(t *testing.T) {
	bundleRoot := t.TempDir()
	rootfsImage := filepath.Join(t.TempDir(), "rootfs.img")
	assert.NoError(t, os.WriteFile(rootfsImage, []byte("erofs-placeholder"), 0644))

	loader, err := runtimecore.NewBundleLoader("", bundleRoot)
	assert.NoError(t, err)

	originalMount := mountRunscNVProxyOverlay
	originalImageMount := mountRunscNVProxyEROFSImage
	originalUnmount := unmountRunscNVProxyPath
	t.Cleanup(func() {
		mountRunscNVProxyOverlay = originalMount
		mountRunscNVProxyEROFSImage = originalImageMount
		unmountRunscNVProxyPath = originalUnmount
	})
	var lowerDir string
	mountRunscNVProxyOverlay = func(lower, _, _, _ string) error {
		lowerDir = lower
		return nil
	}
	var mountedImage, mountedImageTarget string
	mountRunscNVProxyEROFSImage = func(source, target string) error {
		mountedImage, mountedImageTarget = source, target
		return nil
	}
	unmountRunscNVProxyPath = func(string, int) error { return syscall.EINVAL }

	handler := &Handler{
		runsc:                  successfulRunscClient{},
		ociLoader:              loader,
		rootfsOverlayTmpfsSize: "10G",
		filestoreDir:           t.TempDir(),
		sandboxRoot:            bundleRoot,
		mountEROFS:             mountRunscNVProxyEROFSImage,
	}
	err = handler.Start(context.Background(), runtimecore.StartConfig{
		ID:         "sbox-rootfs-image",
		Rootfs:     rootfsImage,
		CgroupPath: "/akernel/sbox-rootfs-image",
		Network:    &networkmanager.NetResource{},
		Resources:  &runtimeapi.LinuxSandboxResources{},
		SpecUpdates: &runtimecore.SpecUpdates{
			RequiresHostWritableRootfs: true,
		},
	})
	assert.NoError(t, err)
	expectedLower := filepath.Join(bundleRoot, "sbox-rootfs-image", runscNVProxyLowerDir)
	assert.Equal(t, rootfsImage, mountedImage)
	assert.Equal(t, expectedLower, mountedImageTarget)
	assert.Equal(t, expectedLower, lowerDir)
}

type staticOciLoader struct {
	bundlePath string
	spec       *runtimecore.Spec
}

func (l staticOciLoader) GenerateOci(runtimecore.OciLoadOptions) (string, *runtimecore.Spec, error) {
	return l.bundlePath, l.spec, nil
}

type successfulRunscClient struct{}

func (successfulRunscClient) Create(context.Context, StartArgs) error                  { return nil }
func (successfulRunscClient) FsCheckpoint(context.Context, string, string, bool) error { return nil }
func (successfulRunscClient) Pause(context.Context, string) error                      { return nil }
func (successfulRunscClient) Resume(context.Context, string) error                     { return nil }
func (successfulRunscClient) Start(context.Context, StartArgs) error                   { return nil }
func (successfulRunscClient) Checkpoint(context.Context, string, string, bool, bool, ...string) error {
	return nil
}
func (successfulRunscClient) Restore(context.Context, StartArgs, string) error {
	return nil
}
func (successfulRunscClient) Wait(context.Context, string) (int, error)  { return 0, nil }
func (successfulRunscClient) Delete(context.Context, string, bool) error { return nil }
func (successfulRunscClient) ListJSON(context.Context) ([]byte, error)   { return []byte("[]"), nil }

func TestRunscHandlerResolvesWritableLayerOverlay(t *testing.T) {
	rootDir := filepath.Join(t.TempDir(), "sandboxd", "root")
	cfg := config.Config{RootDir: rootDir}
	cfg.RuntimeConfig.FilestoreDir = "/home/akernel/xfs"
	cfg.RuntimeConfig.OverlayTmpfsSize = "10G"
	handler, err := NewHandler(cfg, "/usr/local/bin/runsc", nil)
	assert.NoError(t, err)

	overlay, size, err := handler.resolveRootOverlay(2 << 30)
	assert.NoError(t, err)
	assert.Equal(t, "root:dir=/home/akernel/xfs,size=2147483648", overlay)
	assert.Equal(t, "2147483648", size)

	overlay, size, err = handler.resolveRootOverlay(0)
	assert.NoError(t, err)
	assert.Equal(t, "root:dir=/home/akernel/xfs,size=10G", overlay)
	assert.Equal(t, "10G", size)
}

type recordingCheckpointClient struct {
	successfulRunscClient
	pauseCount, resumeCount, fsCheckpointCount, checkpointCount int
	checkpointPaths                                             []string
	leaveRunning                                                bool
	checkpointErr                                               error
	pauseErr                                                    error
	cancelDuringCheckpoint                                      func()
	resumeCtx                                                   context.Context
	resumeEntryErr                                              error
	resumeEntryRemaining                                        time.Duration
	postReturnErr                                               error
	order                                                       []string
}

func (c *recordingCheckpointClient) FsCheckpoint(context.Context, string, string, bool) error {
	c.fsCheckpointCount++
	return nil
}

func (c *recordingCheckpointClient) Pause(_ context.Context, _ string) error {
	c.pauseCount++
	c.order = append(c.order, "pause")
	return c.pauseErr
}

func (c *recordingCheckpointClient) Resume(ctx context.Context, _ string) error {
	c.resumeCount++
	// Capture the context state AT ENTRY: resumeSource's deferred cancel runs
	// before Handler returns, so post-return reads would always see Canceled.
	c.resumeCtx = ctx
	c.resumeEntryErr = ctx.Err()
	if deadline, ok := ctx.Deadline(); ok {
		c.resumeEntryRemaining = time.Until(deadline)
	}
	c.order = append(c.order, "resume")
	return nil
}

func (c *recordingCheckpointClient) recordPostReturnState() {
	if c.resumeCtx != nil {
		c.postReturnErr = c.resumeCtx.Err()
	}
}

func (c *recordingCheckpointClient) Checkpoint(
	ctx context.Context, _, _ string, _, leaveRunning bool, paths ...string,
) error {
	c.checkpointCount++
	c.order = append(c.order, "checkpoint")
	c.checkpointPaths = paths
	c.leaveRunning = leaveRunning
	if c.cancelDuringCheckpoint != nil {
		c.cancelDuringCheckpoint()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.checkpointErr
}

func newCheckpointTestHandler(t *testing.T, client *recordingCheckpointClient) *Handler {
	t.Helper()
	cfg := config.Config{RootDir: filepath.Join(t.TempDir(), "sandboxd", "root")}
	cfg.RuntimeConfig.FilestoreDir = "/home/akernel/xfs"
	handler, err := NewHandler(cfg, "/usr/local/bin/runsc", staticOciLoader{bundlePath: t.TempDir(), spec: &runtimecore.Spec{}})
	assert.NoError(t, err)
	handler.runsc = client
	return handler
}

func TestCheckpointIncludeFilesystemUsesSingleCombinedCall(t *testing.T) {
	client := &recordingCheckpointClient{}
	handler := newCheckpointTestHandler(t, client)

	err := handler.Checkpoint(context.Background(), "sbox", "/images/cp", runtimecore.CheckpointOptions{
		IncludeFilesystem: true,
	})
	assert.NoError(t, err)
	// Exactly ONE runsc checkpoint carrying the root path; NO separate
	// fscheckpoint subcommand may run anymore.
	assert.Equal(t, 1, client.checkpointCount)
	assert.Equal(t, 0, client.fsCheckpointCount)
	assert.Equal(t, []string{"/"}, client.checkpointPaths)
	// LeaveRunning=false stops the source: the combined call runs WITHOUT
	// --leave-running and no sandboxd-side Resume happens.
	assert.False(t, client.leaveRunning)
	assert.Equal(t, 1, client.pauseCount)
	assert.Equal(t, 0, client.resumeCount)
}

func TestCheckpointIncludeFilesystemLeaveRunningResumes(t *testing.T) {
	client := &recordingCheckpointClient{}
	handler := newCheckpointTestHandler(t, client)

	err := handler.Checkpoint(context.Background(), "sbox", "/images/cp", runtimecore.CheckpointOptions{
		IncludeFilesystem: true,
		LeaveRunning:      true,
	})
	assert.NoError(t, err)
	assert.Equal(t, 1, client.pauseCount)
	assert.Equal(t, 1, client.resumeCount)
	assert.Equal(t, 1, client.checkpointCount)
	assert.True(t, client.leaveRunning)
}

func TestCheckpointIncludeFilesystemFailureStillResumes(t *testing.T) {
	client := &recordingCheckpointClient{checkpointErr: errors.New("checkpoint boom")}
	handler := newCheckpointTestHandler(t, client)

	err := handler.Checkpoint(context.Background(), "sbox", "/images/cp", runtimecore.CheckpointOptions{
		IncludeFilesystem: true,
	})
	assert.Error(t, err)
	assert.Equal(t, 1, client.resumeCount, "failed combined checkpoint must still resume the source")
}

func TestCheckpointIncludeFilesystemCancelledRequestStillResumes(t *testing.T) {
	client := &recordingCheckpointClient{}
	handler := newCheckpointTestHandler(t, client)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The mock cancels the REQUEST after Pause succeeded, then Checkpoint
	// observes the cancellation — exactly the mid-flight cancellation shape.
	client.cancelDuringCheckpoint = cancel
	err := handler.Checkpoint(ctx, "sbox", "/images/cp", runtimecore.CheckpointOptions{
		IncludeFilesystem: true,
	})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled), "original cancellation error must survive: %v", err)
	assert.Equal(t, 1, client.resumeCount, "cancelled request must still unfreeze the source")
	// At Resume ENTRY the cleanup context is live (not the cancelled request)
	// and bounded: remaining deadline within (0, 10s] plus a tiny slack.
	assert.NotNil(t, client.resumeCtx)
	assert.NoError(t, client.resumeEntryErr, "resume context must be live at entry")
	assert.Greater(t, client.resumeEntryRemaining, time.Duration(0))
	assert.LessOrEqual(t, client.resumeEntryRemaining, 10*time.Second+50*time.Millisecond)
	// Execution order proves the unfreeze happened after the failed checkpoint.
	assert.Equal(t, []string{"pause", "checkpoint", "resume"}, client.order)
	// After Handler returns, the deferred cancel HAS fired — the cleanup
	// timer is released.
	client.recordPostReturnState()
	assert.ErrorIs(t, client.postReturnErr, context.Canceled)
}

func TestCheckpointPlainCompatSkipsPauseAndPaths(t *testing.T) {
	client := &recordingCheckpointClient{}
	handler := newCheckpointTestHandler(t, client)

	err := handler.Checkpoint(context.Background(), "sbox", "/images/cp", runtimecore.CheckpointOptions{})
	assert.NoError(t, err)
	assert.Equal(t, 0, client.pauseCount)
	assert.Equal(t, 0, client.resumeCount)
	assert.Equal(t, 1, client.checkpointCount)
	assert.Empty(t, client.checkpointPaths)
}
