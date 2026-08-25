package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	runtime "github.com/inclusionAI/sandboxd/api/runtime/v1"
	svc "github.com/inclusionAI/sandboxd/pkg/runtime"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

// W7-P1.1: the resource-limits sidecar overrides the restore request's
// memory booking; missing/corrupt sidecar keeps legacy behavior.
func TestApplyCheckpointResourceLimits(t *testing.T) {
	dir := t.TempDir()
	req := &runtime.StartRequest{Resources: map[string]float64{"Memory": 32768}}

	// no sidecar: unchanged
	applyCheckpointResourceLimits(req, dir)
	assert.Equal(t, float64(32768), req.Resources["Memory"])

	// sidecar with 6GiB
	assert.NoError(t, os.WriteFile(filepath.Join(dir, resourceLimitsFile),
		[]byte(`{"memory_limit_bytes":6442450944}`), 0o600))
	applyCheckpointResourceLimits(req, dir)
	assert.Equal(t, float64(6144), req.Resources["Memory"])

	// corrupt sidecar: no-op, no panic
	assert.NoError(t, os.WriteFile(filepath.Join(dir, resourceLimitsFile),
		[]byte("not json"), 0o600))
	req.Resources["Memory"] = 32768
	applyCheckpointResourceLimits(req, dir)
	assert.Equal(t, float64(32768), req.Resources["Memory"])

	// sub-MiB value: no-op
	assert.NoError(t, os.WriteFile(filepath.Join(dir, resourceLimitsFile),
		[]byte(`{"memory_limit_bytes":512}`), 0o600))
	applyCheckpointResourceLimits(req, dir)
	assert.Equal(t, float64(32768), req.Resources["Memory"])

	// nil resources map is created on demand
	req2 := &runtime.StartRequest{}
	assert.NoError(t, os.WriteFile(filepath.Join(dir, resourceLimitsFile),
		[]byte(`{"memory_limit_bytes":6442450944}`), 0o600))
	applyCheckpointResourceLimits(req2, dir)
	assert.Equal(t, float64(6144), req2.Resources["Memory"])
}

// W7-P1.2: a park leftover (exited sandbox with a never-restored record) is
// dropped instead of failing the restore with a replay conflict.
func TestExistingRestorePhysicalFact_ParkLeftoverDropped(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	const id = "sbox-park-leftover"
	assert.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID:             id,
		RuntimeHandler: "runsc",
		PhysicalPhase:  runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED,
	}))
	assert.NoError(t, s.sandboxManager.SetExit(id, 0, time.Now().Format(time.RFC3339Nano), false))
	// the synchronous cleanup reads the sandbox's OCI spec; stage a minimal one
	specDir := filepath.Join(s.config.RootDir, "containers", id)
	assert.NoError(t, os.MkdirAll(specDir, 0o755))
	assert.NoError(t, os.WriteFile(filepath.Join(specDir, "config.json"),
		[]byte(`{"ociVersion":"1.0.2","process":{"args":["/init"]},"root":{"path":"rootfs"},"linux":{}}`), 0o644))

	identity := &runtime.RestoreIdentity{CheckpointID: "ckpt-1", RequestSha256: "abc"}
	_, found, err := s.existingRestorePhysicalFact(context.Background(), &runtime.StartRequest{SandboxID: id}, identity)
	assert.NoError(t, err)
	assert.False(t, found, "park leftover must not be treated as a replay")
	_, gerr := s.sandboxManager.Get(id)
	assert.Error(t, gerr, "stale record should be deleted")
}

// W7-P1.2: an idempotent replay (same restore identity) still returns the
// existing physical fact.
func TestExistingRestorePhysicalFact_IdempotentReplay(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	const id = "sbox-restored"
	identity := &runtime.RestoreIdentity{CheckpointID: "ckpt-1", RequestSha256: "abc"}
	assert.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID:              id,
		RuntimeHandler:  "runsc",
		PhysicalPhase:   runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED,
		RestoreIdentity: identity,
	}))
	resp, found, err := s.existingRestorePhysicalFact(
		context.Background(), &runtime.StartRequest{SandboxID: id, Runtime: "runsc"},
		proto.Clone(identity).(*runtime.RestoreIdentity))
	assert.NoError(t, err)
	assert.True(t, found)
	assert.NotNil(t, resp)
}

// W7-P1.2: a live sandbox with a never-restored record refuses the restore
// with a clear error instead of the old opaque replay-conflict message.
func TestExistingRestorePhysicalFact_LiveSandboxRefused(t *testing.T) {
	s := newTestService(t, map[string]svc.Handler{"runsc": svc.NewFakeRuntimeHandler()})
	const id = "sbox-live"
	assert.NoError(t, s.sandboxManager.StoreMetadata(id, &runtime.SandboxMetadata{
		ID:             id,
		RuntimeHandler: "runsc",
		PhysicalPhase:  runtime.SandboxPhysicalPhase_SANDBOX_PHYSICAL_PHASE_COMMITTED,
	}))
	identity := &runtime.RestoreIdentity{CheckpointID: "ckpt-1", RequestSha256: "abc"}
	_, found, err := s.existingRestorePhysicalFact(context.Background(), &runtime.StartRequest{SandboxID: id}, identity)
	assert.Error(t, err)
	assert.True(t, found)
}
