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

package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/pkg/errord"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type checkpointTestHandler struct {
	*svc.FakeRuntimeHandler

	mu           sync.Mutex
	checkpointFn func(context.Context, string, string, svc.CheckpointOptions) error
	restoreFn    func(context.Context, svc.StartConfig, string) error
	checkpoints  []string
	checkpointOptions []svc.CheckpointOptions
	restores     []svc.StartConfig
	restoreDirs  []string
	starts       []svc.StartConfig
	deleteCalls  int
}

func newCheckpointTestHandler() *checkpointTestHandler {
	return &checkpointTestHandler{FakeRuntimeHandler: svc.NewFakeRuntimeHandler()}
}

func (h *checkpointTestHandler) Start(ctx context.Context, config svc.StartConfig) error {
	h.mu.Lock()
	h.starts = append(h.starts, config)
	h.mu.Unlock()
	return nil
}

func (h *checkpointTestHandler) Delete(_ context.Context, _ string) error {
	h.mu.Lock()
	h.deleteCalls++
	h.mu.Unlock()
	return nil
}

func (h *checkpointTestHandler) Checkpoint(
	ctx context.Context, sandboxID, dir string, options svc.CheckpointOptions,
) error {
	h.mu.Lock()
	h.checkpoints = append(h.checkpoints, dir)
	h.checkpointOptions = append(h.checkpointOptions, options)
	fn := h.checkpointFn
	h.mu.Unlock()
	if fn != nil {
		return fn(ctx, sandboxID, dir, options)
	}
	return os.WriteFile(filepath.Join(dir, "checkpoint.img"), []byte("image"), 0600)
}

func (h *checkpointTestHandler) Restore(
	ctx context.Context,
	config svc.StartConfig,
	imagePath string,
) error {
	h.mu.Lock()
	h.restores = append(h.restores, config)
	h.restoreDirs = append(h.restoreDirs, imagePath)
	fn := h.restoreFn
	h.mu.Unlock()
	if fn != nil {
		return fn(ctx, config, imagePath)
	}
	return nil
}

func storeRunningSandbox(t *testing.T, service *sandboxService, id, runtimeName string) {
	t.Helper()
	require.NoError(t, service.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID:             id,
		RuntimeHandler: runtimeName,
	}))
}

func TestCheckpointValidatesRequestAndRuntime(t *testing.T) {
	service := newTestService(t, map[string]svc.Handler{
		"runsc": svc.NewFakeRuntimeHandler(),
	})
	const id = "sbox-validate"
	stageCheckpointSource(t, service, id, "gen-validate")
	dir := filepath.Join(service.config.RootDir, "checkpoints", "ckpt-validate")

	// The scheduler line requires an explicit checkpoint identity.
	_, err := service.Checkpoint(context.Background(), &runtime.CheckpointRequest{
		ID: id, CheckpointDir: dir,
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	// A stale expectation is rejected before any runtime work (the
	// managed-capability and rootfs stages that follow are covered by the
	// executeCheckpoint-level tests).
	_, err = service.CheckpointIfGeneration(context.Background(), &runtime.CheckpointIfGenerationRequest{
		Checkpoint:        &runtime.CheckpointRequest{ID: id, CheckpointDir: dir, CheckpointID: "ckpt-validate"},
		ExpectedGeneration: "gen-other",
	})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}


// stageCheckpointSource stages a RUNNING sandbox with a generation label and
// an OCI bundle so the shared checkpoint path can validate the source.
func stageCheckpointSource(t *testing.T, service *sandboxService, id, generation string) string {
	t.Helper()
	require.NoError(t, service.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID:             id,
		RuntimeHandler: "runsc",
		Labels:         map[string]string{resourceGenerationLabel: generation},
	}))
	bundleDir := filepath.Join(service.config.RootDir, "containers", id)
	require.NoError(t, os.MkdirAll(bundleDir, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(bundleDir, config.SandboxSpecFile),
		[]byte(`{"ociVersion":"1.0.2","process":{"cwd":"/"},"root":{"path":"rootfs"},"linux":{"cgroupsPath":""},"annotations":{}}`),
		0o600,
	))
	return generation
}

// stageDir registers a managed checkpoint directory under the daemon root.
func stageDir(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(strings.TrimRight(t.TempDir(), "/"), name)
}

func TestCheckpointDirectoryValidation(t *testing.T) {
	root := t.TempDir()
	t.Run("missing leaf is created and removed on cleanup", func(t *testing.T) {
		path := filepath.Join(root, "created")
		directory, err := prepareCheckpointOutputDirectory(path)
		require.NoError(t, err)
		assert.True(t, directory.created)
		require.NoError(t, directory.cleanup())
		assert.NoDirExists(t, path)
	})

	t.Run("existing empty directory is preserved on cleanup", func(t *testing.T) {
		path := filepath.Join(root, "existing")
		require.NoError(t, os.Mkdir(path, 0700))
		directory, err := prepareCheckpointOutputDirectory(path)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(path, "partial"), []byte("x"), 0600))
		require.NoError(t, directory.cleanup())
		assert.DirExists(t, path)
		entries, readErr := os.ReadDir(path)
		require.NoError(t, readErr)
		assert.Empty(t, entries)
	})

	t.Run("nonempty output is rejected", func(t *testing.T) {
		path := filepath.Join(root, "nonempty")
		require.NoError(t, os.Mkdir(path, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(path, "owned"), []byte("x"), 0600))
		_, err := prepareCheckpointOutputDirectory(path)
		assert.ErrorIs(t, err, errord.ErrFailedPrecondition)
	})

	t.Run("relative path is rejected", func(t *testing.T) {
		_, err := prepareCheckpointOutputDirectory("relative/checkpoint")
		assert.ErrorIs(t, err, errord.ErrInvalidArgument)
	})

	t.Run("symbolic link component is rejected", func(t *testing.T) {
		target := filepath.Join(root, "target")
		link := filepath.Join(root, "link")
		require.NoError(t, os.Mkdir(target, 0700))
		require.NoError(t, os.Symlink(target, link))
		_, err := prepareCheckpointOutputDirectory(filepath.Join(link, "checkpoint"))
		assert.ErrorIs(t, err, errord.ErrInvalidArgument)
	})
}

func TestCheckpointInputDirectoryValidation(t *testing.T) {
	directory := t.TempDir()
	_, err := validateCheckpointInputDirectory(directory)
	assert.ErrorIs(t, err, errord.ErrFailedPrecondition)

	require.NoError(t, os.WriteFile(filepath.Join(directory, "checkpoint.img"), []byte("image"), 0600))
	got, err := validateCheckpointInputDirectory(directory)
	require.NoError(t, err)
	assert.Equal(t, directory, got)
}

func TestCheckpointGuestMemoryResources(t *testing.T) {
	limit := int64(256 << 20)
	swap := int64(512 << 20)
	got := checkpointGuestMemoryResources(&specs.Spec{
		Linux: &specs.Linux{
			Resources: &specs.LinuxResources{
				Memory: &specs.LinuxMemory{
					Limit: &limit,
					Swap:  &swap,
				},
			},
		},
	})
	require.NotNil(t, got)
	assert.Equal(t, limit, got.MemoryLimitInBytes)
	assert.Equal(t, swap, got.MemorySwapLimitInBytes)

	assert.Nil(t, checkpointGuestMemoryResources(nil))
	assert.Nil(t, checkpointGuestMemoryResources(&specs.Spec{
		Linux: &specs.Linux{
			Resources: &specs.LinuxResources{
				Memory: &specs.LinuxMemory{},
			},
		},
	}))
}

func TestStartSandboxRuntimeDispatchesRestore(t *testing.T) {
	handler := newCheckpointTestHandler()
	service := buildServiceWithOptions(AddHandler("runsc", handler))
	config := svc.StartConfig{
		ID:            "sbox-restored",
		CheckpointDir: "/checkpoints/one",
	}

	require.NoError(t, service.startSandboxRuntime(context.Background(), "runsc", config, nil))
	require.Len(t, handler.restores, 1)
	assert.Equal(t, config, handler.restores[0])
	assert.Equal(t, filepath.Join("/checkpoints/one", "checkpoint.img"), handler.restoreDirs[0])
	assert.Empty(t, handler.starts)
}

func TestStartSandboxRuntimeUsesStartWithoutCheckpoint(t *testing.T) {
	handler := newCheckpointTestHandler()
	service := buildServiceWithOptions(AddHandler("runsc", handler))
	config := svc.StartConfig{ID: "sbox-started"}

	require.NoError(t, service.startSandboxRuntime(context.Background(), "runsc", config, nil))
	require.Len(t, handler.starts, 1)
	assert.Equal(t, config, handler.starts[0])
	assert.Empty(t, handler.restores)
}

func TestStartSandboxRuntimeRejectsUnsupportedRestore(t *testing.T) {
	service := buildServiceWithOptions(AddHandler("runc", svc.NewFakeRuntimeHandler()))
	err := service.startSandboxRuntime(context.Background(), "runc", svc.StartConfig{
		ID:            "sbox-restored",
		CheckpointDir: "/checkpoints/one",
	}, nil)
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}
